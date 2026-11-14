# -*- coding: utf-8 -*-
"""
switchlog 服务入口

    python main.py                        起服务，监听 UDP 收设备日志
    python main.py --selftest             连库自检，打印规则条数和一台设备的信息后退出
    python main.py --replay <file> [--ip] 回放一个日志文件，打到 stdout
    python main.py --workers 8 --port 5514  覆盖配置里的默认值

三个线程角色：

    receiver      recvfrom -> hash(ip) % N -> worker 队列。只做这两件事
    worker x N    从队列取报文，跑 L1 ~ L5
    maintenance   定时刷新规则表、清理缓存、打一行统计

收包和解析必须分开：解析是 CPU 密集，跑在收包线程里会让 recvfrom 迟滞、
内核 socket buffer 溢出丢包，那是无声丢包。

按 IP hash 分区是硬要求，不是优化：L6 聚合和 L7 状态机依赖同设备事件的
先后顺序，随机分配会让 IF_UP 先于 IF_DOWN 被处理，告警关不掉。

经中转站转发的日志，UDP 包的源地址是中转站自己的 IP，不是交换机的
真实 IP。中转站用 rsyslog 的模板把整条日志包成一行 JSON 转发过来，见
parse_relay_payload()。没走中转、设备直连的仍然是原始 syslog 文本，
两种格式自动识别，不需要分别配置。
"""
import os
import sys
import json
import time
import socket
import argparse
import logging
import threading
import queue
import datetime
from logging.handlers import TimedRotatingFileHandler

from config.config import Config
from utils.logger import setup_logger, LOG_DIR
from utils.stats import stats
from pipeline.runner import Runner

logger = logging.getLogger(__name__)

# 中转站 rsyslog 的转发模板：
#
#   template(name="fwd-json" type="list") {
#       constant(value="{")
#         constant(value="\"time\":\"")        property(name="timegenerated" dateFormat="rfc3339")
#         constant(value="\",\"src_ip\":\"")   property(name="fromhost-ip")
#         constant(value="\",\"severity\":\"") property(name="syslogseverity-text")
#         constant(value="\",\"facility\":\"") property(name="syslogfacility-text")
#         constant(value="\",\"message\":\"")  property(name="rawmsg-after-pri" format="json")
#       constant(value="\"}")
#   }
#
# 中转站收到交换机原始报文后，包成一行 JSON 转发给 switchlog——不这么做的话，
# switchlog 这边 socket.recvfrom() 拿到的 addr[0] 会是中转站自己的 IP
# （比如 172.25.40.11），不是交换机的真实 IP。按 ip 查 devices 表、
# 按 ip hash 分 worker 全部会查到中转站身上。
#
# time 字段是 rfc3339，取的是中转站 rsyslog 收到这条日志的时刻
# （timegenerated），不是交换机自己写在报文正文里的时间——这正是
# l1_prepare.py 一直要的"采集时间"，比 switchlog 收到 UDP 包的时刻
# 更接近设备实际发出日志的那一刻，网络转发的几毫秒延迟可以忽略。


def parse_rfc3339(text):
    """
    rfc3339 时间串转 epoch 秒。转不动返回 None，不往上抛——
    上一条日志的时间格式异常不该让整个 UDP 收包线程挂掉
    """
    try:
        text = str(text or "").strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        return int(datetime.datetime.fromisoformat(text).timestamp())
    except (ValueError, TypeError):
        return None


def parse_relay_payload(text):
    """
    自动识别中转站的 JSON 转发格式，解不出来就当原始 syslog 文本处理

    :return: (ip 或 None, message, timestamp 或 None)
             ip/timestamp 为 None 表示没取到，调用方退回各自的默认值
             （UDP 包的 addr[0] / 本机当前时间）
    """
    text = text.strip()
    if not text.startswith("{"):
        return None, text, None

    try:
        payload = json.loads(text)
    except (ValueError, TypeError):
        # 开头是 { 但不是合法 JSON，大概率是设备正文本身凑巧带了个花括号，
        # 当原始文本处理，不要因为解析失败丢整条日志
        return None, text, None

    if not isinstance(payload, dict) or "message" not in payload:
        # 合法 JSON 但不是预期的转发格式（没有 message 字段），同样退回
        # 原始文本 —— 整个 JSON 字符串当 message 正文，至少不丢日志
        return None, text, None

    ip = str(payload.get("src_ip") or "").strip() or None
    message = str(payload.get("message") or "")
    ts = parse_rfc3339(payload.get("time"))
    return ip, message, ts


# ============================================================
# 原始报文留档
# ============================================================

RAW_PACKET_LOG_FILE = os.path.join(LOG_DIR, "raw_packets.log")


def build_raw_packet_logger():
    """
    建一个独立的 logger 专门记收到的原始 UDP 报文，不走根 logger

    和 switchlog.log 分开是因为用途、量级都不一样：switchlog.log 记的是
    应用事件（启动、错误、告警动作），这里记的是每一个收到的包，日志
    风暴时一分钟几万行，混在一起会把应用日志冲没，排查反而更难。

    只记 addr[0]（UDP 包的真实来源，可能是中转站）+ 原始 message，不做
    任何解析 —— 解析可能失败、可能抛异常，记录这一步必须比解析更可靠，
    否则这份档案本身就不可信。真正的 ip 识别结果（剥没剥出 src_ip、
    走没走中转）该看 switchlog.log 里 L3 产出的 event，这里只保证
    "设备确实发了这条、长什么样"这件事能查到。

    按天切割，和 switchlog.log 用同一套 TimedRotatingFileHandler，
    保留天数单独配置 —— 这份文件写入量比应用日志大得多，留的天数
    短一些更合适，不和 log_backup_days 共用一个值。
    """
    raw_logger = logging.getLogger("switchlog.raw_packets")
    raw_logger.setLevel(logging.INFO)
    raw_logger.propagate = False  # 不往根 logger 冒泡，不进 switchlog.log

    for handler in raw_logger.handlers[:]:
        raw_logger.removeHandler(handler)

    handler = TimedRotatingFileHandler(
        RAW_PACKET_LOG_FILE, when="midnight", interval=1,
        backupCount=Config.raw_packet_log_backup_days, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(message)s",
                                           datefmt="%Y-%m-%d %H:%M:%S"))
    raw_logger.addHandler(handler)
    return raw_logger


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

    def __init__(self, ip, port, max_packet_size, rcvbuf, queues, stop_event,
                 raw_logger=None):
        self.ip = ip
        self.port = port
        self.max_packet_size = int(max_packet_size)
        self.rcvbuf = int(rcvbuf)
        self.queues = queues
        self.stop_event = stop_event
        self._sock = None
        self._thread = None
        self._workers = len(queues)
        self._raw_logger = raw_logger
        # 来源 IP 黑名单，配置里的固定集合，收包线程只做一次 in 判断
        self._drop_sources = frozenset(Config.drop_source_ips or ())
        if self._drop_sources:
            logger.info("来源IP黑名单已启用：%s", ", ".join(sorted(self._drop_sources)))

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
            text = data.decode("utf-8", "replace").strip()

            # 原始留档，排在任何解析之前：只记"收到了什么"，不依赖后面
            # 解析成不成功。addr[0] 是 UDP 包的真实来源，走中转时就是
            # 中转站自己的 IP，不是设备 IP ——要看最终识别到的设备 IP，
            # 去 switchlog.log 里对应时刻的 L3 解析结果
            if self._raw_logger is not None:
                try:
                    self._raw_logger.info("%s %s", addr[0], text)
                except Exception:
                    pass  # 留档失败不能影响正常收包，静默跳过

            # 中转站转发的是一行 JSON，剥出真实设备 IP / 正文 / 采集时间；
            # 不是 JSON 说明设备直连，三者都退回现有行为
            relay_ip, message, relay_ts = parse_relay_payload(text)
            source_ip = relay_ip or addr[0]

            # 来源 IP 黑名单：本机回环转发的日志（rsyslog 把本机日志也
            # 转过来）不是任何一台纳管设备，进管线只会变成 UNMANAGED_SRC
            # 噪声。拦在入队之前，连 worker 都不占
            if source_ip in self._drop_sources:
                stats.incr("dropped_source")
                continue

            raw = {
                "ip": source_ip,
                "message": message,
                "timestamp": relay_ts if relay_ts is not None else int(time.time()),
            }
            # 同一设备的日志必须落到同一个 worker，顺序是聚合和状态机的前提。
            # 这里的 source_ip 已经是剥过中转前缀的真实设备 IP ——
            # 如果漏剥，走中转站的所有设备会被 addr[0]（中转站自己的 IP）
            # 统一哈希到一个 worker，等于失去了按设备分区的意义
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

        落库和通知都在 L9 里做完了，这里只是打日志。解析那行是 debug，
        日志量大的时候不该刷屏；真产生了告警动作的打 warning。
        """
        logger.debug(
            "%s %s %s %s severity=%s object=%s object_name=%s object_alias=%s",
            event.get("ip"), event.get("hostname"),
            event.get("event_code"), event.get("vendor"),
            event.get("severity_name", "-"), event.get("alarm_object"),
            event.get("object_name") or "-", event.get("object_alias") or "-")
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
    # 落库没有开关（alarm_list 是看板唯一数据源）。通知有，关掉的话
    # 看板上有告警但不推出去，起服务时打出来免得配错了找半天
    logger.info("告警出口：推通知=%s（通道 %s）",
                Config.alarm_notify, Config.notify_channel)

    # 回放未恢复的告警。不放的话重启后同一个还没好的故障会重新开告警，
    # 等于重复通知一次。两层各回放自己的：L6 回放窗口、L7 回放告警状态
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

    raw_logger = None
    if Config.raw_packet_log_enable:
        raw_logger = build_raw_packet_logger()
        logger.info("原始报文留档已开启：%s（保留 %s 天）",
                    RAW_PACKET_LOG_FILE, Config.raw_packet_log_backup_days)

    receiver = UdpReceiver(
        args.listen_ip or Config.listen_ip,
        args.port or Config.listen_port,
        Config.max_packet_size, Config.socket_rcvbuf, queues, stop_event,
        raw_logger=raw_logger)
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
    logger.info("switchlog 启动，数据源 MySQL %s:%s/%s",
                Config.mysql_config["db_host"], Config.mysql_config["db_port"],
                Config.mysql_config["db_name"])
    logger.info("=" * 60)

    if args.selftest:
        return run_selftest(args)
    if args.replay:
        return run_replay(args)
    return run_service(args)


if __name__ == "__main__":
    sys.exit(main())
