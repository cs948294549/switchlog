# -*- coding: utf-8 -*-
"""
L6 聚合

这一级不做任何正则匹配。进来的是 L5 产出的原子告警，event_code 和
归一化后的 object 都已算好，这里只剩拼 key：

    fingerprint = md5(ip | event_code | alarm_object)

恢复事件（IF_UP）要落到对应故障事件（IF_DOWN）的指纹上才关得掉告警，
所以用 L5 补的 clear_code 换算：IF_UP 的指纹按 IF_DOWN 算。

窗口用真滑动，不靠分桶继承：

    now - first_seen > max_life    -> 强制开新段（一段不能无限长）
    now - last_seen  > window      -> 新段，count = 1
    否则                            -> 同一段，count += 1，刷新 last_seen

window 比的是**相邻两条日志的间隔**，不是固定分桶的边界。所以"5 分钟窗口
+ 日志持续 10 分钟"是一段不是两段 —— 只要中间没有超过 5 分钟的空档。
要分成两段，间隔得大于窗口。

window 取**故障码**那一行的 syslog_event.window_sec（L5 补的
segment_window_sec），不是进来这条事件自己的：段是故障码的段，指纹也是
按 raise_code 算的，IF_UP 判在不在同一段自然该用 IF_DOWN 的窗口。
所以 IF_UP 那一行的 window_sec 填多少都不影响聚合。

**本层算出来的段就是一条告警。** L7 拿 (fingerprint, first_seen) 当段的
身份，一个段对应 alarm_list 的一行：同段内不管来多少条日志、raise 还是
clear，只有一行。所以这里切不切段直接决定看板上是一行还是两行。

max_life 实际用的是 max(配置值, window_sec) —— 配得比窗口小的话，段活
不到窗口该有的长度就被强制切断，两个配置互相打架（TEMP_ALARM 窗口 3600、
老的 max_life 写死 1800，一段 1800 秒就断）。闪断升级去掉之后 max_life
的唯一作用是"别让一行告警的 first_seen 停在三周前"，所以配置默认值放到
86400，不再是原来那个"每 30 分钟重新开一段"的 1800。

判断顺序是 max_life 在前 —— 反过来写的话日志不断时永远满足窗口条件，
max_life 那条分支根本到不了，一段就能活到无限长（设计文档 §4.4 的伪代码
是窗口在前，那里是笔误）。

======================= 写 alarm_log =======================

本层把原子告警写进 alarm_log（一条日志一行，带指纹，只留 7 天）。
过了 L2 的日志条条都写，包括噪声码和没到阈值没产生告警的 ——
指纹在 alarm_list 里查不到说明这组日志没到告警阈值，这本身是有用的信息。

写入量就是收到的日志量，日志风暴时一分钟几万行，所以必须攒批：
攒到 batch_size 或者隔 flush_interval 秒刷一次，由维护线程兜底调 flush()。

alarm_list 不在这里写。阈值判断是 L7 的事 —— MAC_FLAP 配 600/3，
第一条日志进来时 alarm_list 里不该有行，攒到第 3 条才算告警。本层只管
数清楚 count 交给 L7。

======================= 输出给 L7 =======================

    {"fingerprint", "group_label", "is_first", "count", "first_seen", "last_seen"}

count 是**日志条数**，不是事故次数。一次端口 down 在 Cisco 上可能同时落到
IF_DOWN、IF_DOWN_LINK_FAILURE、LINEPROTO down 三条日志，指纹相同 count 就是 3，
但这是一次端口 down。L7 的 threshold 判的就是这个条数（MAC_FLAP 配 3），
别拿它当"故障发生了几次"。

is_first 只表示"本段窗口内第一条"。L7 不读它 —— 它的判据是 first_seen
变没变（段的身份）加上"本段在 alarm_list 里有没有行"，threshold 大于 1
的事件码插行的时机不是第一条。

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
# 一段最长活多久。实际用 max(这个值, window_sec)，见 _slide()。
# 一段就是 alarm_list 的一行，所以这个值只是"别让一行的 first_seen 停在
# 三周前"的上限，不是"多久重新告警一次"
DEFAULT_MAX_LIFETIME = 86400

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

    segments 只为排查用：这个指纹一共切过几段，能看出是不是在反复抖。

    life 是这个指纹实际用的段上限 max(配置值, window_sec)。存下来是给
    purge() 用的 —— 它要知道"静默多久才算这段肯定断了"，而 window_sec
    只在 handle() 的事件里带着，purge() 那会儿拿不到。
    """

    __slots__ = ("fingerprint", "label", "first_seen", "last_seen", "count",
                 "segments", "life")

    def __init__(self, fingerprint, now, label=None, count=1, first_seen=None,
                 life=0):
        self.fingerprint = fingerprint
        self.first_seen = int(first_seen if first_seen is not None else now)
        self.last_seen = int(now)
        self.count = int(count)
        self.segments = 1
        self.life = int(life)
        self.label = label or self._make_label(fingerprint, self.first_seen)

    @staticmethod
    def _make_label(fingerprint, first_seen):
        """
        段标签。同一指纹切段之后要换一个，所以带上段起点。

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
    L6 聚合器

    handle() 热路径：算指纹、滑窗口、攒 alarm_log 的批。
    flush() / purge() 由维护线程定期调。
    """

    def __init__(self, max_lifetime=DEFAULT_MAX_LIFETIME, batch_size=DEFAULT_BATCH_SIZE,
                 flush_interval=DEFAULT_FLUSH_INTERVAL, buffer_limit=DEFAULT_BUFFER_LIMIT,
                 retention_days=DEFAULT_LOG_RETENTION_DAYS, db=None,
                 write_db=True):
        """
        :param max_lifetime:   一段最长活多久（秒）
        :param batch_size:     alarm_log 攒够多少条刷一次
        :param flush_interval: 或者隔多少秒刷一次
        :param buffer_limit:   缓冲上限，超了丢最老的
        :param retention_days: alarm_log 保留天数
        :param db:             数据源，由 db.get_alarm_db() 注入
        :param write_db:       False=只读不写。flush() 不写 alarm_log、
                               purge() 不删老数据。滑动窗口和指纹计算
                               照常跑（那是纯内存的），只是不落库 ——
                               给 test.py 这类调试脚本用
        """
        self._max_lifetime = int(max_lifetime)
        self._write_db = bool(write_db)
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

        :param event: L5 的输出
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
        # L5 补的 raise_code：本事件是谁的恢复事件。没有就是它自己
        code = event.get("raise_code") or code
        return fingerprint_of(event.get("ip"), code, event.get("alarm_object"))

    def _slide(self, fingerprint, event, now):
        """滑动窗口。返回更新后的 Window"""
        window_sec = self._window_sec(event)
        # max_life 不能小于窗口，否则段活不到窗口该有的长度就被强制切断，
        # 两个配置互相打架。TEMP_ALARM 的窗口是 3600，老的 max_life 写死
        # 1800，一段 1800 秒就断，而窗口的意思是"间隔 3600 秒内算同一段"
        max_lifetime = max(self._max_lifetime, window_sec)
        with self._lock:
            window = self._windows.get(fingerprint)
            if window is None:
                window = Window(fingerprint, now, life=max_lifetime)
                self._windows[fingerprint] = window
                return window

            window.life = max_lifetime
            # 顺序重要：max_life 必须判在窗口之前。反过来写的话日志不断时
            # 永远满足窗口条件，这条分支到不了，一段就能活到无限长
            if now - window.first_seen > max_lifetime:
                window.renew(now)
            elif now - window.last_seen > window_sec:
                window.renew(now)
            else:
                window.touch(now)
            return window

    @staticmethod
    def _window_sec(event):
        """
        窗口取 syslog_event.window_sec，不同事件码不一样

        用 L5 补的 segment_window_sec，不是事件自己的 window_sec：
        **段是故障码的段**，指纹按 raise_code 算（IF_UP 落到 IF_DOWN 的
        指纹上），所以"这条日志算不算同一段"也该按故障码的窗口判。
        按恢复码自己的窗口判的话，两个码配得不一样就会让一次故障在看板上
        变成两行。L5 的 _fill_segment_attrs() 负责算这个值
        """
        try:
            value = int(event.get("segment_window_sec")
                        or event.get("window_sec") or DEFAULT_WINDOW)
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

        write_db=False 时把缓冲清空但不写库 —— 清空是必须的，否则
        调试跑长了缓冲会一直涨到 buffer_limit 开始丢数据、还报 dropped
        """
        now = int(now if now is not None else time.time())
        with self._lock:
            if not self._buffer:
                self._last_flush = now
                return 0
            rows = self._buffer
            self._buffer = []
            self._last_flush = now

        if not self._write_db:
            return 0

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
        静默这么久的话下一条日志无论如何都会开新段（max_life 实际用的是
        max(配置值, window_sec)，而窗口判断用的也是同一个上界），
        清掉和留着结果一样

        :return: 清掉的窗口数
        """
        now = int(now if now is not None else time.time())
        with self._lock:
            expired = [key for key, window in self._windows.items()
                       if now - window.last_seen > max(self._max_lifetime,
                                                       window.life)]
            for key in expired:
                self._windows.pop(key, None)
        return len(expired)

    def purge_logs(self, now=None):
        """
        删过期的 alarm_log。分批删到删不动为止 ——
        一次删几十万行会长时间持锁

        write_db=False 时直接返回 0：调试脚本不该删生产数据，这是
        这个开关最该挡住的一类操作

        :return: 删掉的总行数
        """
        if not self._write_db:
            return 0

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

    def restore(self, since_ts, limit=5000):
        """
        重启后回放窗口状态，避免重启后同一个段被当成新段

        只回放 first_seen / last_seen / counter 三样，够算窗口了。
        段对应的那一行告警由 L7 自己回放。

        **不只回放未恢复的。** 段就是 alarm_list 的一行，已经盖过恢复标签
        的段同样要接上 —— 不接的话重启后段内再来一条重复的恢复日志，
        first_seen 会变成新值，L7 认不出是同一段，又会多插一行。

        :param since_ts: 只回放 last_seen 在这之后的段，由调用方按最长的
                         window_sec 算
        :return: 回放的窗口数
        """
        try:
            rows = self.db.getAlarmStatesSince(since_ts, limit=limit)
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
                # life 先给 max_lifetime，第一条事件进来时 _slide() 会按
                # 真实的 window_sec 改过来。window_sec 不在状态表里（它来自
                # syslog_event），而 purge() 要靠 life 判"静默多久算这段
                # 肯定断了"——给小了会把还在进行中的段清掉
                window = Window(fingerprint, last_seen, count=max(count, 1),
                                first_seen=first_seen or last_seen,
                                life=self._max_lifetime)
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
