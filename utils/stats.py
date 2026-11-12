# -*- coding: utf-8 -*-
"""
运行计数器

管线上每一层都往这里记数，维护线程定时打一行汇总。
日志量大的时候这是唯一能看出"哪一层在丢东西"的地方。

计数用普通 int 自增，不加锁：GIL 下单条 += 不会撕裂，
偶尔少记一两次不影响判断趋势，加锁反而拖慢热路径。
"""
import time
import logging
import threading

logger = logging.getLogger(__name__)


class Stats(object):
    """
    一组计数器 + 上次输出的快照，用来算区间速率

    计数项：
        received      收到的 UDP 报文数
        dropped       队列满丢弃（收包线程快于 worker）
        blocked       L0.5 黑名单拦掉
        parsed        走完 L1 的
        parse_fail    报文不可读
        unmanaged     devices 表里查不到源 IP
        unknown       规则表没命中，规则缺口
        ignored       L2.5 定级规则判定不开告警（state=ignore）
        alarms        L5 产生的告警动作（开/升级/恢复）
        muted         其中被 L3 静默的，不发通知
        errors        管线里抛异常的
    """

    KEYS = ("received", "dropped", "blocked", "parsed",
            "parse_fail", "unmanaged", "unknown", "ignored",
            "alarms", "muted", "errors")

    def __init__(self):
        self._counters = dict.fromkeys(self.KEYS, 0)
        self._last = dict.fromkeys(self.KEYS, 0)
        self._last_ts = time.time()
        self._start_ts = time.time()
        self._lock = threading.Lock()

    def incr(self, key, delta=1):
        """计数。未知 key 直接忽略，不为了打点把管线搞崩"""
        if key in self._counters:
            self._counters[key] += delta

    def snapshot(self):
        """当前累计值"""
        return dict(self._counters)

    def interval(self):
        """
        距上次调用的区间增量与速率，并重置基线。

        :return: {"seconds", "delta": {...}, "rate": {...}, "total": {...}}
        """
        now = time.time()
        with self._lock:
            seconds = max(now - self._last_ts, 0.001)
            current = dict(self._counters)
            delta = {key: current[key] - self._last[key] for key in self.KEYS}
            self._last = current
            self._last_ts = now
        return {
            "seconds": seconds,
            "delta": delta,
            "rate": {key: delta[key] / seconds for key in self.KEYS},
            "total": current,
        }

    def uptime(self):
        return time.time() - self._start_ts

    def log_interval(self, queue_sizes=None):
        """
        打一行区间汇总。dropped 非零时单独再打一条 warning ——
        丢包是必须被看到的，混在 info 里容易被忽略

        :param queue_sizes: [int]，各 worker 队列当前积压
        """
        data = self.interval()
        delta = data["delta"]
        rate = data["rate"]

        parts = ["收 {}（{:.0f}/s）".format(delta["received"], rate["received"])]
        if delta["blocked"]:
            parts.append("黑名单拦 {}".format(delta["blocked"]))
        parts.append("解析 {}".format(delta["parsed"]))
        if delta["alarms"]:
            muted = "（静默 {}）".format(delta["muted"]) if delta["muted"] else ""
            parts.append("告警 {}{}".format(delta["alarms"], muted))
        for key, label in (("unknown", "规则缺口"), ("unmanaged", "未纳管"),
                           ("parse_fail", "不可读"), ("ignored", "不告警"),
                           ("errors", "异常")):
            if delta[key]:
                parts.append("{} {}".format(label, delta[key]))
        if queue_sizes:
            parts.append("队列积压 {}".format("/".join(str(size) for size in queue_sizes)))
        logger.info("统计 %.0fs：%s", data["seconds"], "，".join(parts))

        if delta["dropped"]:
            logger.warning(
                "队列满丢弃 %s 条（%.0f/s）：worker 跟不上收包速度，"
                "调大 config.workers 或 queue_size",
                delta["dropped"], rate["dropped"])
        return data


# 进程内共用一份
stats = Stats()
