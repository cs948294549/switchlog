# -*- coding: utf-8 -*-
"""
L4 聚合

这一级不做任何正则匹配。进来的是 L2.5 产出的原子告警，event_code 和
归一化后的 object 都已算好，这里只剩拼 key：

    fingerprint = md5(ip | event_code | alarm_object)

恢复事件（IF_UP）要落到对应故障事件（IF_DOWN）的指纹上才关得掉告警，
所以用 L2.5 补的 clear_code 换算：IF_UP 的指纹按 IF_DOWN 算。

窗口用真滑动，不靠分桶继承：

    now - first_seen > max_life    -> 强制开新段（解决无限继承）
    now - last_seen  > window      -> 新段，count = 1
    否则                            -> 同一段，count += 1，刷新 last_seen

window 取 syslog_event.window_sec，比的是**相邻两条日志的间隔**，不是
固定分桶的边界。所以"5 分钟窗口 + 日志持续 10 分钟"是一段不是两段 ——
只要中间没有超过 5 分钟的空档。要分成两段，间隔得大于窗口。

max_life 默认 1800s：持续闪断的接口每 30 分钟重新开一段，不会永久静默。
判断顺序是 max_life 在前 —— 反过来写的话日志不断时永远满足窗口条件，
max_life 那条分支根本到不了，无限继承就没解决（设计文档 §4.4 的伪代码
是窗口在前，那里是笔误）。

======================= 写 alarm_log =======================

本层把原子告警写进 alarm_log（一条日志一行，带指纹，只留 7 天）。
过了 L0.5 的日志条条都写，包括噪声码和没到阈值没产生告警的 ——
指纹在 alarm_list 里查不到说明这组日志没到告警阈值，这本身是有用的信息。

写入量就是收到的日志量，日志风暴时一分钟几万行，所以必须攒批：
攒到 batch_size 或者隔 flush_interval 秒刷一次，由维护线程兜底调 flush()。

alarm_list 不在这里写。阈值判断是 L5 的事 —— MAC_FLAP 配 600/3，
第一条日志进来时 alarm_list 里不该有行，攒到第 3 条才算告警。本层只管
数清楚 count 交给 L5。

======================= 输出给 L5 =======================

    {"fingerprint", "group_label", "is_first", "count", "first_seen", "last_seen"}

count 是**日志条数**，不是事故次数。一次端口 down 在 Cisco 上可能同时落到
IF_DOWN、IF_DOWN_LINK_FAILURE、LINEPROTO down 三条日志，指纹相同 count 就是 3，
但这是一次端口 down。所以任何按"次数"做的判断（闪断识别）都不能直接读
count，必须数 L5 里"无活跃告警 -> 开告警"这一跳。

is_first 只表示"本段窗口内第一条"。**L5 不要拿它决定开不开告警** ——
max_life 切新段时它也是 True，而一个口持续 down 一小时应该是一条告警
不是两条。L5 的判据是"有没有活跃告警"。

状态放内存，不引入 Redis：worker 按 IP hash 分区，同一设备的日志固定
落到同一个 worker，所以同一指纹不会跨 worker。但 Runner 是各 worker
共享的，所以状态字典仍要加锁。重启靠 syslog_alarm_state 表回放
（restore()），多实例部署时再上 Redis。
"""
import time
import hashlib
import logging
import threading

logger = logging.getLogger(__name__)

DEFAULT_WINDOW = 300            # syslog_event.window_sec 缺省值
DEFAULT_MAX_LIFETIME = 1800     # 一段最长活多久，防无限继承

# alarm_log 保留天数，维护线程按 ingest_ts 删
DEFAULT_LOG_RETENTION_DAYS = 7

# 攒批写 alarm_log
DEFAULT_BATCH_SIZE = 200        # 攒够这么多条刷一次
DEFAULT_FLUSH_INTERVAL = 5      # 或者隔这么多秒刷一次
DEFAULT_BUFFER_LIMIT = 20000    # 缓冲上限，数据库写不动时丢最老的，不吃爆内存

NO_OBJECT = "-"


def fingerprint_of(ip, event_code, alarm_object):
    """
    md5(ip | event_code | alarm_object)

    分隔符用 | 并且各段都给默认值，避免 ("a", "bc") 和 ("ab", "c")
    拼出同一个指纹
    """
    key = "{}|{}|{}".format(ip or NO_OBJECT, event_code or NO_OBJECT,
                            alarm_object or NO_OBJECT)
    return hashlib.md5(key.encode("utf-8")).hexdigest()


class Window(object):
    """
    一个指纹的滑动窗口状态

    segments 只为排查用：这个指纹一共切过几段，能看出是不是在反复闪断。
    """

    __slots__ = ("fingerprint", "label", "first_seen", "last_seen", "count", "segments")

    def __init__(self, fingerprint, now, label=None, count=1, first_seen=None):
        self.fingerprint = fingerprint
        self.first_seen = int(first_seen if first_seen is not None else now)
        self.last_seen = int(now)
        self.count = int(count)
        self.segments = 1
        self.label = label or self._make_label(fingerprint, self.first_seen)

    @staticmethod
    def _make_label(fingerprint, first_seen):
        """
        段标签。同一指纹 max_life 切段后要换一个，所以带上段起点。

        注意和 alarm_list.group_label 不是一回事 —— 那一列沿用
        central-server 的老结构存裸指纹，现有分组页面按它分组。
        """
        return "{}:{}".format(fingerprint, first_seen)

    def renew(self, now):
        """开新段：重置计数和起点，换标签"""
        self.first_seen = int(now)
        self.last_seen = int(now)
        self.count = 1
        self.segments += 1
        self.label = self._make_label(self.fingerprint, self.first_seen)

    def touch(self, now):
        """同一段内又来一条"""
        self.count += 1
        # 时钟回拨时不让 last_seen 往回走，否则窗口判断会乱
        self.last_seen = max(self.last_seen, int(now))


class Aggregator(object):
    """
    L4 聚合器

    handle() 热路径：算指纹、滑窗口、攒 alarm_log 的批。
    flush() / purge() 由维护线程定期调。
    """

    def __init__(self, max_lifetime=DEFAULT_MAX_LIFETIME, batch_size=DEFAULT_BATCH_SIZE,
                 flush_interval=DEFAULT_FLUSH_INTERVAL, buffer_limit=DEFAULT_BUFFER_LIMIT,
                 retention_days=DEFAULT_LOG_RETENTION_DAYS, db=None):
        """
        :param max_lifetime:   一段最长活多久（秒）
        :param batch_size:     alarm_log 攒够多少条刷一次
        :param flush_interval: 或者隔多少秒刷一次
        :param buffer_limit:   缓冲上限，超了丢最老的
        :param retention_days: alarm_log 保留天数
        :param db:             数据源，由 db.get_alarm_db() 注入
        """
        self._max_lifetime = int(max_lifetime)
        self._batch_size = int(batch_size)
        self._flush_interval = int(flush_interval)
        self._buffer_limit = int(buffer_limit)
        self._retention_days = int(retention_days)
        self._db = db

        self._windows = {}          # fingerprint -> Window
        self._buffer = []           # 待写 alarm_log 的行
        self._last_flush = int(time.time())
        self._lock = threading.RLock()
        self._dropped = 0           # 缓冲溢出丢掉的条数

    @property
    def db(self):
        if self._db is None:
            from db import get_alarm_db
            self._db = get_alarm_db()
        return self._db

    # ---------------- 热路径 ----------------

    def handle(self, event, now=None):
        """
        聚合一条原子告警，原地往 event 上补指纹和窗口字段

        :param event: L2.5 的输出
        :param now:   采集时间，不传取 event 的 ingest_ts
        :return: event
        """
        clock = int(now if now is not None else (event.get("ingest_ts") or time.time()))

        fingerprint = self._fingerprint(event)
        window = self._slide(fingerprint, event, clock)

        event["fingerprint"] = fingerprint
        event["group_label"] = window.label
        event["is_first"] = (window.count == 1)
        event["count"] = window.count
        event["first_seen"] = window.first_seen
        event["last_seen"] = window.last_seen

        self._buffer_log(event, clock)
        return event

    def _fingerprint(self, event):
        """
        算指纹。恢复事件按它对应的故障事件算，否则关不掉告警。

        IF_UP 的 clear_code 是空的，raise 类事件（IF_DOWN）才配 clear_code，
        所以这里要反过来查：谁的 clear_code 是我，我就按谁算。
        这张反查表由 attrs 层维护（clear_code -> 故障码），本层只用结果。
        """
        code = event.get("event_code", "")
        # L2.5 补的 raise_code：本事件是谁的恢复事件。没有就是它自己
        code = event.get("raise_code") or code
        return fingerprint_of(event.get("ip"), code, event.get("alarm_object"))

    def _slide(self, fingerprint, event, now):
        """滑动窗口。返回更新后的 Window"""
        window_sec = self._window_sec(event)
        with self._lock:
            window = self._windows.get(fingerprint)
            if window is None:
                window = Window(fingerprint, now)
                self._windows[fingerprint] = window
                return window

            # 顺序重要：max_life 必须判在窗口之前。反过来写的话日志不断时
            # 永远满足窗口条件，这条分支到不了，无限继承就没解决
            if now - window.first_seen > self._max_lifetime:
                window.renew(now)
            elif now - window.last_seen > window_sec:
                window.renew(now)
            else:
                window.touch(now)
            return window

    @staticmethod
    def _window_sec(event):
        """窗口取 syslog_event.window_sec，不同事件码不一样"""
        try:
            value = int(event.get("window_sec") or DEFAULT_WINDOW)
        except (TypeError, ValueError):
            return DEFAULT_WINDOW
        return value if value > 0 else DEFAULT_WINDOW

    # ---------------- alarm_log 攒批 ----------------

    def _buffer_log(self, event, now):
        """
        攒一条原子记录。攒够一批或者隔够时间就刷

        缓冲满了丢最老的并计数：这张表是排查用的，丢几条比把内存吃爆好。
        丢弃必须可观测，所以 stats() 里带 dropped
        """
        row = {
            "fingerprint": event.get("fingerprint", ""),
            "ip": event.get("ip", ""),
            "hostname": event.get("hostname", ""),
            "event_code": event.get("event_code", ""),
            "alarm_object": event.get("alarm_object", ""),
            "severity": event.get("severity", 3),
            "mnemonic": event.get("mnemonic", ""),
            "rule_id": event.get("rule_id", 0),
            "severity_rule_id": event.get("severity_rule_id", 0),
            "msg": event.get("message", ""),
            "ingest_ts": str(event.get("ingest_ts") or now),
        }

        with self._lock:
            if len(self._buffer) >= self._buffer_limit:
                # 丢最老的。切片比 pop(0) 快，一次丢一批免得每条都搬数组
                drop = len(self._buffer) - self._buffer_limit + 1
                self._buffer = self._buffer[drop:]
                self._dropped += drop
            self._buffer.append(row)
            due = (len(self._buffer) >= self._batch_size
                   or now - self._last_flush >= self._flush_interval)

        if due:
            self.flush(now=now)

    def flush(self, now=None):
        """
        把缓冲写进 alarm_log。维护线程也要调，否则低流量时最后几条压在内存里

        写失败不把这批塞回缓冲：数据库持续不可用的话塞回去只会越积越多，
        最后把内存吃爆。这张表是排查用的，丢了比拖垮管线好，但要记 error
        """
        now = int(now if now is not None else time.time())
        with self._lock:
            if not self._buffer:
                self._last_flush = now
                return 0
            rows = self._buffer
            self._buffer = []
            self._last_flush = now

        try:
            written = self.db.addAlarmLogs(rows)
        except Exception as err:
            logger.error("======Aggregator flush error========\n%s", err)
            with self._lock:
                self._dropped += len(rows)
            return 0
        if not written:
            with self._lock:
                self._dropped += len(rows)
            logger.error("======Aggregator flush 写入 0 行========\n丢弃 %s 条原子记录",
                         len(rows))
        return written

    # ---------------- 周期维护 ----------------

    def purge(self, now=None):
        """
        清理过期窗口。一个指纹静默超过 max_life 就没必要再占内存 ——
        下次再来会重新建段，结果一样

        :return: 清掉的窗口数
        """
        now = int(now if now is not None else time.time())
        with self._lock:
            expired = [key for key, window in self._windows.items()
                       if now - window.last_seen > self._max_lifetime]
            for key in expired:
                self._windows.pop(key, None)
        return len(expired)

    def purge_logs(self, now=None):
        """
        删过期的 alarm_log。分批删到删不动为止 ——
        一次删几十万行会长时间持锁

        :return: 删掉的总行数
        """
        now = int(now if now is not None else time.time())
        before = now - self._retention_days * 86400
        total = 0
        # 有上限，别在数据库卡住时无限循环
        for _ in range(100):
            try:
                removed = self.db.delOldAlarmLogs(before)
            except Exception as err:
                logger.error("======Aggregator purge_logs error========\n%s", err)
                break
            if removed == "failed" or not removed:
                break
            total += removed
        if total:
            logger.info("alarm_log 清理 %s 行（早于 %s）", total,
                        time.strftime("%Y-%m-%d %H:%M", time.localtime(before)))
        return total

    def restore(self, limit=5000):
        """
        重启后回放未恢复告警的窗口状态，避免重启后同一故障重新开段

        只回放 first_seen / last_seen / counter 三样，够算窗口了。
        告警本身的状态由 L5 自己回放。

        :return: 回放的窗口数
        """
        try:
            rows = self.db.getOpenAlarmStates(limit=limit)
        except Exception as err:
            logger.error("======Aggregator restore error========\n%s", err)
            return 0

        restored = 0
        with self._lock:
            for row in rows or []:
                fingerprint = row.get("fingerprint")
                if not fingerprint or fingerprint in self._windows:
                    continue
                try:
                    first_seen = int(row.get("first_seen") or 0)
                    last_seen = int(row.get("last_seen") or 0)
                    count = int(row.get("counter") or 1)
                except (TypeError, ValueError):
                    continue
                if not last_seen:
                    continue
                window = Window(fingerprint, last_seen, count=max(count, 1),
                                first_seen=first_seen or last_seen)
                self._windows[fingerprint] = window
                restored += 1
        if restored:
            logger.info("Aggregator 回放 %s 个指纹的窗口状态", restored)
        return restored

    def stats(self):
        """dropped 非零说明数据库写不动或者缓冲溢出，要能看出来"""
        with self._lock:
            return {
                "windows": len(self._windows),
                "buffered": len(self._buffer),
                "dropped": self._dropped,
            }

    def size(self):
        """当前跟踪的指纹数"""
        return len(self._windows)
