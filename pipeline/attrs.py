# -*- coding: utf-8 -*-
"""
L2.5 事件属性

L1 只负责"这是哪个事件、对象是谁"。severity / state / object_type / 窗口 /
clear_code 描述的是**事件**，不是匹配规则，所以单独一张 syslog_event 表：

    IF_DOWN 在三家厂商下共 9 行匹配规则，属性只有一份。
    改一次 P2→P1 只改一行，不会出现"华为的端口 down 是 P1、
    Cisco 的同一个事件还是 P2"这种谁都发现不了的错。

放在 L2 之后：富化查库失败时事件照样要能往下走，属性本身不依赖富化结果，
但它之后紧接着就是 L3 抑制，两条查询串在一起反而拖慢热路径时的可观测性 ——
先让富化把设备身份补全，属性补齐之后日志里就能直接打出"哪台设备的哪个事件"。

severity 用 P 级整数：
    1 = P1  最高，需要立刻处理（BGP 全断、LAG 断）
    2 = P2  需要处理（端口 down、电源故障）
    3 = P3  记录、观察（端口 up、配置变更）
不用 syslog 自带的 emergency..debug 八级：%BGP-5-ADJCHANGE 是 level 5
（notice），但 BGP 邻居掉了对我们是 P1，两者没有对应关系。

查不到事件码时给默认值并记 warning —— 规则表配了 event_code 但
syslog_event 里没建行，是配置漏项。
"""
import logging
import threading

logger = logging.getLogger(__name__)

DEFAULT_REFRESH = 300          # syslog_event 刷新间隔

# 属性默认值：查不到事件码时用
DEFAULT_SEVERITY = 3
DEFAULT_STATE = "stateless"
DEFAULT_OBJECT_TYPE = "none"
DEFAULT_WINDOW = 300
DEFAULT_THRESHOLD = 1

SEVERITY_NAMES = {1: "P1", 2: "P2", 3: "P3"}

STATE_RAISE = "raise"
STATE_CLEAR = "clear"
STATE_STATELESS = "stateless"
STATES = (STATE_RAISE, STATE_CLEAR, STATE_STATELESS)


def severity_name(severity):
    """1/2/3 -> P1/P2/P3，看板和日志里用"""
    try:
        return SEVERITY_NAMES.get(int(severity), "P3")
    except (TypeError, ValueError):
        return "P3"


def escalate(severity, levels=1):
    """
    抖动升级：P3 -> P2 -> P1，封顶 P1。

    升级是往小数字走，容易写反；收在这里一处，别在各层里各写一遍。
    """
    try:
        base = int(severity)
    except (TypeError, ValueError):
        base = DEFAULT_SEVERITY
    return max(1, base - max(int(levels or 0), 0))


class EventAttr(object):
    """syslog_event 的一行"""

    __slots__ = ("event_code", "severity", "state", "object_type", "window_sec",
                 "threshold", "clear_code", "descr")

    def __init__(self, row):
        self.event_code = str(row.get("event_code", "") or "").strip()
        self.severity = self._to_int(row.get("severity"), DEFAULT_SEVERITY)
        if self.severity not in SEVERITY_NAMES:
            # 表里塞了 0 或 5 这类越界值，按最低级处理并喊一声
            logger.warning("syslog_event.severity 越界：%s=%s，按 P3 处理",
                           self.event_code, self.severity)
            self.severity = DEFAULT_SEVERITY
        state = str(row.get("state", "") or "").strip().lower()
        self.state = state if state in STATES else DEFAULT_STATE
        self.object_type = str(row.get("object_type", "") or "").strip().lower() \
            or DEFAULT_OBJECT_TYPE
        self.window_sec = self._to_int(row.get("window_sec"), DEFAULT_WINDOW)
        self.threshold = self._to_int(row.get("threshold"), DEFAULT_THRESHOLD)
        self.clear_code = str(row.get("clear_code", "") or "").strip()
        self.descr = str(row.get("descr", "") or "")

    @staticmethod
    def _to_int(value, default):
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    def as_dict(self):
        return {
            "severity": self.severity,
            "state": self.state,
            "object_type": self.object_type,
            "window_sec": self.window_sec,
            "threshold": self.threshold,
            "clear_code": self.clear_code,
        }


class EventAttrIndex(object):
    """syslog_event 全量索引，dict[event_code] -> EventAttr"""

    __slots__ = ("attrs", "total", "version")

    def __init__(self, rows, version=0):
        self.attrs = {}
        self.total = 0
        self.version = version
        for row in rows or []:
            attr = EventAttr(row)
            if not attr.event_code:
                continue
            self.attrs[attr.event_code] = attr
            self.total += 1


class EventAttrs(object):
    """
    L2.5：按 event_code 补事件属性

    和 parser 一样定时刷新，索引整体替换。查不到时给默认值，
    并按事件码记一次 warning（同一事件码只在首次加载时报，不是每条日志都喊）。
    """

    def __init__(self, refresh_interval=DEFAULT_REFRESH, db=None):
        """
        :param refresh_interval: syslog_event 刷新间隔（秒），0 表示只加载一次
        :param db: 数据源，由 db.get_rule_db() 注入
        """
        self._refresh_interval = int(refresh_interval)
        self._db = db
        self._index = EventAttrIndex([])
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._refresh_thread = None

        self.refresh()

        if self._refresh_interval > 0:
            self._refresh_thread = threading.Thread(
                target=self._refresh_loop, name="attrs-refresh", daemon=True)
            self._refresh_thread.start()

    @property
    def db(self):
        if self._db is None:
            from db import get_rule_db
            self._db = get_rule_db()
        return self._db

    def refresh(self):
        """重新加载 syslog_event。加载失败保留旧索引"""
        try:
            rows = self.db.getSyslogEvents()
        except Exception as err:
            logger.error("======EventAttrs refresh error========\n%s", err)
            return self._index.total
        if not rows and self._index.total:
            logger.warning("EventAttrs got empty event set, keep %s loaded events",
                           self._index.total)
            return self._index.total

        index = EventAttrIndex(rows)
        with self._lock:
            self._index = index
        logger.info("EventAttrs loaded %s events", index.total)
        self._warn_missing_codes()
        return index.total

    def _warn_missing_codes(self):
        """
        报一下规则表引用了但事件表里没有的事件码。一次加载只报一轮，
        不是每条日志都喊
        """
        try:
            codes = {row.get("event_code", "") for row in self.db.getSyslogRules()}
        except Exception:
            return
        missing = sorted(code for code in codes
                         if code and code not in self._index.attrs)
        if missing:
            logger.warning("syslog_rule 引用了 %s 个 syslog_event 里不存在的事件码，"
                           "这些事件按 P3/stateless 处理：%s",
                           len(missing), ", ".join(missing))

    def _refresh_loop(self):
        while not self._stop_event.is_set():
            if self._stop_event.wait(self._refresh_interval):
                break
            try:
                self.refresh()
            except Exception as err:
                logger.error("======EventAttrs refresh loop error========\n%s", err)

    def stop(self):
        self._stop_event.set()

    def attrs_of(self, event_code):
        """取事件属性，查不到返回 None"""
        index = self._index
        return index.attrs.get(str(event_code or ""))

    def size(self):
        """当前加载的事件属性条数"""
        return self._index.total

    # ---------------- 流水线入口 ----------------

    def fill(self, event):
        """
        给事件补属性字段，原地修改并返回

        clear_code 单独拿出来：L5 配对恢复事件时要用，
        但 raise 类事件才需要，clear 和 stateless 一律留空。
        """
        attr = self.attrs_of(event.get("event_code"))
        if attr is None:
            # 兜底：UNKNOWN_MNEMONIC / PARSE_FAIL / UNMANAGED_SRC 在
            # syslog_event 里应该都有行，没有就按默认值走
            event.update({
                "severity": DEFAULT_SEVERITY,
                "state": DEFAULT_STATE,
                "object_type": DEFAULT_OBJECT_TYPE,
                "window_sec": DEFAULT_WINDOW,
                "threshold": DEFAULT_THRESHOLD,
                "clear_code": "",
            })
            event["severity_name"] = severity_name(DEFAULT_SEVERITY)
            return event

        event.update(attr.as_dict())
        event["severity_name"] = severity_name(attr.severity)
        return event
