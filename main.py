# -*- coding: utf-8 -*-
"""
switchlog 服务入口

    python main.py                        起服务，监听 UDP 收设备日志
    python main.py --selftest             连库自检，打印规则条数和一台设备的信息后退出
    python main.py --replay <file> [--ip] 回放一个日志文件，打到 stdout
    python main.py --workers 8 --port 5514  覆盖配置里的默认值

三个线程角色：

    receiver      recvfrom -> hash(ip) % N -> worker 队列。只做这两件事
    worker x N    从队列取报文，跑 L0 ~ L2.5
    maintenance   定时刷新规则表、清理缓存、打一行统计

收包和解析必须分开：解析是 CPU 密集，跑在收包线程里会让 recvfrom 迟滞、
内核 socket buffer 溢出丢包，那是无声丢包。

按 IP hash 分区是硬要求，不是优化：L4 聚合和 L5 状态机依赖同设备事件的
先后顺序，随机分配会让 IF_UP 先于 IF_DOWN 被处理，告警关不掉。
"""
import os
import sys
import time
import socket
import argparse
import logging
import threading
import queue

from config.config import Config
from utils.logger import setup_logger
from utils.stats import stats
from pipeline.runner import Runner

logger = logging.getLogger(__name__)


# ============================================================
# 收包
# ============================================================

class UdpReceiver(object):
    """
    UDP 收包线程

    内核 socket 缓冲调大是吸收突发最有效的手段，比在应用层加队列
    更靠前。实际生效值受 /proc/sys/net/core/rmem_max 限制，
    起服务时把真实值打出来，免得以为调大了其实没生效。
    """

    def __init__(self, ip, port, max_packet_size, rcvbuf, queues, stop_event):
        self.ip = ip
        self.port = port
        self.max_packet_size = int(max_packet_size)
        self.rcvbuf = int(rcvbuf)
        self.queues = queues
        self.stop_event = stop_event
        self._sock = None
        self._thread = None
        self._workers = len(queues)

    def start(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.rcvbuf)
            actual = self._sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
            if actual < self.rcvbuf:
                logger.warning("socket 接收缓冲只拿到 %s 字节（配置 %s），"
                               "受内核心 rmem_max 限制，需要时调大 "
                               "/proc/sys/net/core/rmem_max", actual, self.rcvbuf)
            else:
                logger.info("socket 接收缓冲 %s 字节", actual)
        except OSError as err:
            logger.warning("设置 socket 接收缓冲失败，用系统默认值：%s", err)

        self._sock.bind((self.ip, self.port))
        self._sock.settimeout(1.0)
        logger.info("UDP 收包已启动 %s:%s", self.ip, self.port)

        self._thread = threading.Thread(target=self._loop, name="receiver", daemon=True)
        self._thread.start()

    def _loop(self):
        while not self.stop_event.is_set():
            try:
                data, addr = self._sock.recvfrom(self.max_packet_size)
            except socket.timeout:
                # 超时是为了让 stop_event 能及时生效
                continue
            except OSError as err:
                if not self.stop_event.is_set():
                    logger.error("recvfrom 失败：%s", err)
                continue

            if not data:
                continue
            source_ip = addr[0]
            raw = {
                "ip": source_ip,
                "message": data.decode("utf-8", "replace").strip(),
                "timestamp": int(time.time()),
            }
            # 同一设备的日志必须落到同一个 worker，顺序是聚合和状态机的前提
            index = hash(source_ip) % self._workers
            try:
                self.queues[index].put_nowait(raw)
            except queue.Full:
                # 主动丢弃并计数。阻塞收包线程会让内核 buffer 溢出，
                # 那是无声丢包，比这里丢更难查
                stats.incr("dropped")

    def stop(self):
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass


# ============================================================
# worker
# ============================================================

class Worker(threading.Thread):
    """一个 worker 从自己的队列取报文，跑管线"""

    def __init__(self, index, work_queue, runner, stop_event):
        super(Worker, self).__init__(name="worker-{}".format(index), daemon=True)
        self.index = index
        self.work_queue = work_queue
        self.runner = runner
        self.stop_event = stop_event

    def run(self):
        logger.info("worker-%s 已启动", self.index)
        while not self.stop_event.is_set():
            try:
                raw = self.work_queue.get(timeout=1.0)
            except queue.Empty:
                continue

            try:
                event = self.runner.handle(raw)
            except Exception as err:
                # 单条报文出错不能拖垮 worker
                stats.incr("errors")
                logger.exception("处理报文失败 ip=%s：%s", raw.get("ip"), err)
                continue

            if event is not None:
                self._on_event(event)

        logger.info("worker-%s 已停止", self.index)

    @staticmethod
    def _on_event(event):
        """
        每条日志的解析结果 + 告警动作

        落库和通知都在 L6 里做完了，这里只是打日志。解析那行是 debug，
        日志量大的时候不该刷屏；真产生了告警动作的打 warning。
        """
        logger.debug(
            "%s %s %s %s severity=%s object=%s if=%s alias=%s",
            event.get("ip"), event.get("hostname"),
            event.get("event_code"), event.get("vendor"),
            event.get("severity_name", "-"), event.get("alarm_object"),
            event.get("if_name") or "-", event.get("if_alias") or "-")
        log_decision(event.get("decision"))


def log_decision(decision):
    """
    把告警动作打一行到 switchlog.log

    这是给人看的那份，机器读的在 logs/notify.log（一行一条 JSON）。
    被静默的也打，但标出来 —— 割接期间得能看出"告警产生了，只是没通知"，
    否则看着像管线漏了。
    """
    if not decision or not decision.get("notify"):
        return
    tail = ""
    if decision.get("muted"):
        tail = "  [静默 rule {}，不通知]".format(decision.get("mute_rule_id"))
    if decision.get("flapping"):
        tail += "  [闪断，需人工确认]"
    if decision.get("reason") == "mute_expired":
        tail += "  [静默窗口已结束，故障仍未恢复]"
    logger.warning(
        "告警 %s  %s  %s %s  %s  count=%s%s",
        decision.get("action"), decision.get("severity_name", "-"),
        decision.get("ip"), decision.get("alarm_object", "-"),
        decision.get("event_code"), decision.get("counter", 0), tail)


# ============================================================
# 维护
# ============================================================

class Maintenance(threading.Thread):
    """定时刷新规则、清理缓存、打统计"""

    # alarm_log 清理间隔。删的是 7 天前的数据，一小时跑一次足够，
    # 和规则刷新分开 —— 那个 300s 一次，带上删表会把刷新也拖慢
    PURGE_INTERVAL = 3600

    # 到期扫描间隔。两件事等不了 5 分钟：stateless 事件静默恢复、
    # 静默窗口过了但故障还在要恢复通知
    SWEEP_INTERVAL = 60

    # 落库间隔。和规则刷新（300s）分开：
    #   alarm_log 攒着的原子记录
    #   syslog_alarm_state 变动过的告警状态 —— 隔得越久，崩了丢得越多
    #   alarm_list.counter 累加出来的值 —— 隔得越久，看板滞后越久
    # 10s 是个折中：看板看着是实时的，写入量又不跟日志量涨
    # （dirty 是 set，一个指纹一轮最多写一次）
    PERSIST_INTERVAL = 10

    def __init__(self, runner, queues, stop_event,
                 refresh_interval, stats_interval):
        super(Maintenance, self).__init__(name="maintenance", daemon=True)
        self.runner = runner
        self.queues = queues
        self.stop_event = stop_event
        self.refresh_interval = int(refresh_interval)
        self.stats_interval = int(stats_interval)

    def run(self):
        next_refresh = time.time() + self.refresh_interval
        next_stats = time.time() + self.stats_interval
        next_sweep = time.time() + self.SWEEP_INTERVAL
        next_persist = time.time() + self.PERSIST_INTERVAL
        # 启动时不立刻删表，等一个间隔 —— 刚起来的时候让收包先稳住
        next_purge = time.time() + self.PURGE_INTERVAL
        while not self.stop_event.is_set():
            if self.stop_event.wait(1):
                break
            now = time.time()
            if now >= next_persist:
                next_persist = now + self.PERSIST_INTERVAL
                try:
                    self.runner.persist(now=now)
                except Exception as err:
                    logger.error("落库失败：%s", err)
            if now >= next_refresh:
                next_refresh = now + self.refresh_interval
                try:
                    self.runner.tick()
                except Exception as err:
                    logger.error("规则刷新失败：%s", err)
            if now >= next_sweep:
                next_sweep = now + self.SWEEP_INTERVAL
                try:
                    for decision in self.runner.sweep(now=now):
                        log_decision(decision)
                except Exception as err:
                    logger.error("到期扫描失败：%s", err)
            if now >= next_stats:
                next_stats = now + self.stats_interval
                try:
                    stats.log_interval([q.qsize() for q in self.queues])
                except Exception as err:
                    logger.error("统计输出失败：%s", err)
            if now >= next_purge:
                next_purge = now + self.PURGE_INTERVAL
                try:
                    self.runner.purge_logs(now=now)
                except Exception as err:
                    logger.error("alarm_log 清理失败：%s", err)


# ============================================================
# 各运行模式
# ============================================================

def run_service(args):
    """收包 + worker + 维护线程，主线程等信号"""
    queues = [queue.Queue(maxsize=Config.queue_size) for _ in range(args.workers)]
    stop_event = threading.Event()
    runner = Runner()

    # 先把规则加载一遍，起服务时就知道规则表和事件表读没读到；
    # 加载失败的话，收进来的日志会全线落 UNKNOWN_MNEMONIC
    logger.info("规则表：黑名单 %s 条，匹配规则 %s 条，事件属性 %s 个，定级规则 %s 条",
                runner.blacklist.size(), runner.parser.size(),
                runner.attrs.size(), runner.attrs.severity_size())

    logger.info("静默规则 %s 条", runner.mute.size())
    # 两个开关都该是 True，关掉任一个都会让告警看不见或者推不出去，
    # 起服务时打出来，免得配错了找半天
    logger.info("告警出口：落 alarm_list=%s，推通知=%s（通道 %s）",
                Config.alarm_write_db, Config.alarm_notify, Config.notify_channel)

    # 回放未恢复的告警。不放的话重启后同一个还没好的故障会重新开告警，
    # 等于重复通知一次。两层各回放自己的：L4 回放窗口、L5 回放告警状态
    restored = runner.aggregator.restore()
    if restored:
        logger.info("回放 %s 个指纹的聚合窗口", restored)
    restored = runner.state_machine.restore()
    if restored:
        logger.info("回放 %s 条未恢复告警", restored)

    workers = [Worker(i, queues[i], runner, stop_event) for i in range(args.workers)]
    for worker in workers:
        worker.start()

    maintenance = Maintenance(
        runner, queues, stop_event,
        Config.rule_refresh_interval, Config.stats_interval)
    maintenance.start()

    receiver = UdpReceiver(
        args.listen_ip or Config.listen_ip,
        args.port or Config.listen_port,
        Config.max_packet_size, Config.socket_rcvbuf, queues, stop_event)
    try:
        receiver.start()
    except PermissionError:
        logger.error("监听 %s:%s 失败：端口 <1024 需要 root 或 CAP_NET_BIND_SERVICE。"
                     "容器里加 --cap-add=NET_BIND_SERVICE，或用 --port 指定非特权端口"
                     "并在设备侧配 logging port",
                     args.listen_ip or Config.listen_ip, args.port or Config.listen_port)
        stop_event.set()
        return 1

    logger.info("switchlog 已启动，worker %s 个，按下 Ctrl+C 停止", args.workers)
    try:
        while not stop_event.is_set():
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("收到停止信号")
    finally:
        stop_event.set()
        receiver.stop()
        runner.stop()
        for worker in workers:
            worker.join(timeout=3)
        logger.info("switchlog 已停止（累计收 %s，丢弃 %s，异常 %s）",
                    stats.snapshot()["received"], stats.snapshot()["dropped"],
                    stats.snapshot()["errors"])
    return 0


def run_replay(args):
    """回放日志文件，一行一条"""
    if not args.replay or not os.path.isfile(args.replay):
        print("文件不存在：{}".format(args.replay))
        return 2

    runner = Runner()
    source_ip = args.ip or "0.0.0.0"
    total = handled = blocked = 0
    codes = {}

    with open(args.replay, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            total += 1
            event = runner.handle({"ip": source_ip, "message": line})
            if event is None:
                blocked += 1
                continue
            handled += 1
            code = event.get("event_code", "")
            codes[code] = codes.get(code, 0) + 1
            print("{:<14}{:<22}{:<18}{:<24}{}".format(
                event.get("ip", "-"), event.get("hostname", "-"), code,
                event.get("severity_name", "-"),
                event.get("alarm_object", "-")))

    print("\n读 {} 条，黑名单拦 {} 条，进管线 {} 条".format(total, blocked, handled))
    print("\n事件码分布（UNKNOWN_MNEMONIC 就是下一批该补的规则）：")
    for code, count in sorted(codes.items(), key=lambda kv: -kv[1]):
        print("  {:<26}{}".format(code, count))
    return 0


def run_selftest(args):
    """连库自检：规则表、事件表、设备表各读一次"""
    ok = True
    runner = Runner()
    try:
        rules = runner.parser.size()
        events = runner.attrs.size()
        blacklist = runner.blacklist.size()
        logger.info("自检：黑名单 %s 条，匹配规则 %s 条，事件属性 %s 个",
                    blacklist, rules, events)
        if rules == 0:
            logger.error("匹配规则为 0 —— syslog_rule 表是空的，"
                         "所有日志都会落 UNKNOWN_MNEMONIC")
            ok = False
        if events == 0:
            logger.error("事件属性为 0 —— syslog_event 表是空的")
            ok = False

        if args.ip:
            info, ports = runner.enricher.get(args.ip)
            if info is None:
                logger.error("查设备 %s 失败：数据库不可用", args.ip)
                ok = False
            else:
                logger.info("设备 %s：sysname=%s vendor=%s hardware=%s 资产号=%s "
                            "接口 %s 个 src_state=%s",
                            args.ip, info["sysname"], info["vendor"] or "-",
                            info["hardware"], info["syscontact"],
                            ports.total, info["src_state"])
    finally:
        runner.stop()
    return 0 if ok else 1


# ============================================================
# 入口
# ============================================================

def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="switchlog 交换机日志告警服务")
    parser.add_argument("--selftest", action="store_true", help="连库自检后退出")
    parser.add_argument("--replay", metavar="FILE", help="回放一个日志文件")
    parser.add_argument("--ip", default="", help="回放/自检用的源 IP")
    parser.add_argument("--workers", type=int, default=Config.workers,
                        help="worker 线程数（默认 %(default)s）")
    parser.add_argument("--port", type=int, default=0, help="覆盖监听端口")
    parser.add_argument("--listen-ip", default="", help="覆盖监听地址")
    parser.add_argument("--log-level", default="", help="覆盖日志级别")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    setup_logger(args.log_level or None)

    logger.info("=" * 60)
    logger.info("switchlog 启动，数据源 %s",
                "mock（config.use_mock_db=True）" if Config.use_mock_db else "MySQL")
    logger.info("=" * 60)

    if args.selftest:
        return run_selftest(args)
    if args.replay:
        return run_replay(args)
    return run_service(args)


if __name__ == "__main__":
    sys.exit(main())
