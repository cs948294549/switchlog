# -*- coding: utf-8 -*-
"""
L5 事件属性 + 事件定级

分两步，读两张表：

    第一步  syslog_event         state / object_type / window_sec /
                                 threshold / clear_code
    第二步  syslog_severity_rule  severity，以及 action=ignore 时把
                                  state 改成 ignore

第一步那些字段描述的是**事件**，不是匹配规则，所以单独一张表：
IF_DOWN 在三家厂商下共 9 行匹配规则，属性只有一份，改窗口改一行、
全厂商同时生效，不会出现"华为的端口 down 窗口 300s、Cisco 的同一个
事件还是 600s"这种谁都发现不了的错。

第二步单独一张表是另一个原因：**级别不是事件的固有属性**。同一个
IF_DOWN，csw 掉口是核心网段断了（P1），rsw 掉口是一个机柜的接入（P3），
corp 职场的 rsw 掉口压根不用看。一个事件码一行存不下"哪个事件 + 哪台
设备"两个维度，所以定级按规则表走，priority 小的先判、首条命中即停。

定级必须跑在 L4 富化之后：那时 sysname 已经从 devices 表补好，可以按
设备名判角色（csw/pcs/rsw/asw/bbs，见 docs/network/设备命名规范.md）。
富化失败时 sysname 退成 "-"，sysname_reg 的规则匹配不上，ip_reg 的
照样生效，最终落到全局兜底那条，不会因为查不到设备就没级别。

severity 用 P 级整数：
    1 = P1  最高，需要立刻处理（BGP 全断、LAG 断）
    2 = P2  需要处理（端口 down、电源故障）
    3 = P3  记录、观察（端口 up、配置变更）
不用 syslog 自带的 emergency..debug 八级：%BGP-5-ADJCHANGE 是 level 5
（notice），但 BGP 邻居掉了对我们是 P1，两者没有对应关系。

action='ignore' 产出 state=ignore，事件照样走完 L8~L9 并落 ES，只是 L7
不开告警 —— 割接或事后回看时这段日志还查得到。要彻底不解析的噪声配
syslog_black_list，要按变更窗口静默的配 L8 的 mute。

两张表查不到都给默认值并记 warning，都属于配置漏项。
"""
import re
import logging
import threading

logger = logging.getLogger(__name__)

DEFAULT_REFRESH = 300          # 两张表共用的刷新间隔

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

# 定级规则产出的第四种 state，不在 STATES 里 —— 它只能由定级规则产生，
# 不允许在 syslog_event.state 里直接配。L7 的 MODE_IGNORE 对应这个值
STATE_IGNORE = "ignore"

ANY_EVENT = "*"                # event_code='*' 表示所有事件
ACTION_NORMAL = ""
ACTION_IGNORE = "ignore"
ACTIONS = (ACTION_NORMAL, ACTION_IGNORE)


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


def _to_int(value, default):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


class EventAttr(object):
    """syslog_event 的一行。不含 severity，级别由 SeverityRule 定"""

    __slots__ = ("event_code", "state", "object_type", "window_sec",
                 "threshold", "clear_code", "descr")

    def __init__(self, row):
        self.event_code = str(row.get("event_code", "") or "").strip()
        state = str(row.get("state", "") or "").strip().lower()
        if state == STATE_IGNORE:
            # ignore 只能由定级规则产生。配在这里会让整个事件码无条件
            # 不告警，而且在定级表里查不到原因
            logger.error("======syslog_event.state 不允许配 ignore========\n"
                         "%s 按 %s 处理，要不告警请在 syslog_severity_rule "
                         "配 action=ignore", self.event_code, DEFAULT_STATE)
            state = DEFAULT_STATE
        self.state = state if state in STATES else DEFAULT_STATE
        self.object_type = str(row.get("object_type", "") or "").strip().lower() \
            or DEFAULT_OBJECT_TYPE
        self.window_sec = _to_int(row.get("window_sec"), DEFAULT_WINDOW)
        self.threshold = _to_int(row.get("threshold"), DEFAULT_THRESHOLD)
        self.clear_code = str(row.get("clear_code", "") or "").strip()
        self.descr = str(row.get("descr", "") or "")

    def as_dict(self):
        return {
            "state": self.state,
            "object_type": self.object_type,
            "window_sec": self.window_sec,
            "threshold": self.threshold,
            "clear_code": self.clear_code,
        }


class EventAttrIndex(object):
    """
    syslog_event 全量索引

        attrs       dict[event_code] -> EventAttr
        raise_codes dict[clear_code] -> 拥有这个恢复码的故障码

    raise_codes 是 clear_code 的反查表，L6 算指纹要用：IF_UP 必须落到
    IF_DOWN 的指纹上才关得掉告警，但 clear_code 配在 IF_DOWN 那一行
    （IF_DOWN -> IF_UP），所以得反过来查"谁的 clear_code 是我"。
    加载时建一次，热路径上 dict 查一次。
    """

    __slots__ = ("attrs", "raise_codes", "total", "version")

    def __init__(self, rows, version=0):
        self.attrs = {}
        self.raise_codes = {}
        self.total = 0
        self.version = version
        for row in rows or []:
            attr = EventAttr(row)
            if not attr.event_code:
                continue
            self.attrs[attr.event_code] = attr
            self.total += 1

        for attr in self.attrs.values():
            if not attr.clear_code:
                continue
            owner = self.raise_codes.get(attr.clear_code)
            if owner is not None:
                # 两个故障码配了同一个恢复码，那条恢复日志不知道该关谁的告警。
                # 保留先到的并喊一声，不能悄悄吞掉配置问题
                logger.error("======syslog_event.clear_code 冲突========\n"
                             "%s 同时是 %s 和 %s 的恢复码，恢复事件只会关 %s 的告警",
                             attr.clear_code, owner, attr.event_code, owner)
                continue
            self.raise_codes[attr.clear_code] = attr.event_code


class SeverityRule(object):
    """
    syslog_severity_rule 的一行，正则在加载时编译一次

    三个判据都空（event_code='*' + 两个正则都空）的那行是全局兜底，
    唯一允许匹配全网所有事件的规则。其余规则至少要有一个判据，
    否则一个笔误就把全网级别改了 —— valid() 负责挡这件事。
    """

    __slots__ = ("rule_id", "event_code", "ip_reg", "sysname_reg", "ip_pattern",
                 "sysname_pattern", "severity", "action", "priority", "descr")

    def __init__(self, row):
        self.rule_id = row.get("rule_id", 0)
        self.event_code = str(row.get("event_code", "") or ANY_EVENT).strip() or ANY_EVENT
        self.ip_pattern = str(row.get("ip_reg", "") or "").strip()
        self.sysname_pattern = str(row.get("sysname_reg", "") or "").strip()
        self.priority = _to_int(row.get("priority"), 100)
        self.descr = str(row.get("descr", "") or "")

        self.severity = _to_int(row.get("severity"), DEFAULT_SEVERITY)
        if self.severity not in SEVERITY_NAMES:
            # 表里塞了 0 或 5 这类越界值，按最低级处理并喊一声
            logger.warning("syslog_severity_rule.severity 越界：rule_id=%s %s=%s，按 P3 处理",
                           self.rule_id, self.event_code, self.severity)
            self.severity = DEFAULT_SEVERITY

        action = str(row.get("action", "") or "").strip().lower()
        if action not in ACTIONS:
            logger.warning("syslog_severity_rule.action 不认识：rule_id=%s action=%s，"
                           "按正常告警处理", self.rule_id, action)
            action = ACTION_NORMAL
        self.action = action

        self.ip_reg = self._compile(self.ip_pattern, self.rule_id, "ip_reg")
        self.sysname_reg = self._compile(self.sysname_pattern, self.rule_id, "sysname_reg")

    @staticmethod
    def _compile(expression, rule_id, field):
        if not expression:
            return None
        try:
            return re.compile(expression)
        except re.error as err:
            # 正则写错了只废掉这一条，不能让整张表加载不上。
            # 返回 "编译失败" 的标记，由 valid() 把这行滤掉
            logger.error("======SeverityRule %s compile error rule_id=%s========\n%s",
                         field, rule_id, err)
            return False

    def valid(self):
        """正则编译失败的行作废，不能让它变成"无判据"的兜底规则"""
        if self.ip_reg is False or self.sysname_reg is False:
            return False
        return True

    def is_catch_all(self):
        """三个判据都空，匹配全网所有事件"""
        return (self.event_code == ANY_EVENT and not self.ip_pattern
                and not self.sysname_pattern)

    def matches(self, ip, sysname):
        """
        事件码由索引负责（候选列表已经按 event_code 取好），这里只判设备。

        两个正则是与的关系，空=不限。富化失败时 sysname 是 "-"，
        sysname_reg 的规则自然匹配不上，ip_reg 的照样生效。
        """
        if self.ip_reg is not None and not self.ip_reg.search(ip):
            return False
        if self.sysname_reg is not None and not self.sysname_reg.search(sysname):
            return False
        return True


class SeverityIndex(object):
    """
    syslog_severity_rule 的内存索引

        by_code  dict[event_code] -> [rule, ...]  按 (priority, rule_id) 升序
        shared   event_code='*' 的规则，加载时已并进 by_code 的每个列表

    '*' 的规则在加载时就并进每个具体事件码的列表里，热路径上一次 dict
    取到的就是完整有序候选集 —— 不在运行时拼列表，拼一次就是一次内存
    分配，每条日志都要付。

    代价是新事件码（by_code 里没有的）要走 shared 列表，这由 candidates()
    兜住。syslog_event 里有的码在加载时都会建键。
    """

    __slots__ = ("by_code", "shared", "total", "version", "has_catch_all")

    def __init__(self, rows, version=0, known_codes=None):
        self.version = version
        self.by_code = {}
        self.shared = []
        self.total = 0
        self.has_catch_all = False

        invalid = 0
        own = {}
        for row in rows or []:
            rule = SeverityRule(row)
            if not rule.valid():
                invalid += 1
                continue
            self.total += 1
            if rule.is_catch_all():
                self.has_catch_all = True
            if rule.event_code == ANY_EVENT:
                self.shared.append(rule)
            else:
                own.setdefault(rule.event_code, []).append(rule)

        self.shared.sort(key=lambda item: (item.priority, item.rule_id))
        # 把 '*' 的规则并进每个具体码的列表。syslog_event 里有行但定级表里
        # 没专门规则的码也要建键，否则它们每条日志都走 shared 的线性扫
        for code in set(own) | set(known_codes or ()):
            rules = own.get(code, []) + self.shared
            rules.sort(key=lambda item: (item.priority, item.rule_id))
            self.by_code[code] = rules

        if invalid:
            logger.warning("SeverityIndex ignored %s rules with bad regex", invalid)

    def candidates(self, event_code):
        """按事件码取候选，已排好序。没建键的新事件码退 shared"""
        rules = self.by_code.get(event_code)
        return rules if rules is not None else self.shared

    def match(self, event_code, ip, sysname):
        """首条命中即停，没有命中返回 None"""
        for rule in self.candidates(event_code):
            if rule.matches(ip, sysname):
                return rule
        return None


class EventAttrs(object):
    """
    L5：补事件属性 + 定级

    两张表共用一个刷新线程，一起刷、版本号一起递增 —— 它们在同一层
    用掉，错开刷新时间点没有意义，集中在一处好排查。

    和 parser 一样索引整体替换，读路径不加锁。查不到时给默认值并记
    warning（一次加载只报一轮，不是每条日志都喊）。
    """

    def __init__(self, refresh_interval=DEFAULT_REFRESH, db=None):
        """
        :param refresh_interval: 两张表的刷新间隔（秒），0 表示只加载一次
        :param db: 数据源，由 db.get_rule_db() 注入
        """
        self._refresh_interval = int(refresh_interval)
        self._db = db
        self._index = EventAttrIndex([])
        self._severity = SeverityIndex([])
        self._version = 0
        # (version, event_code, ip, sysname) -> SeverityRule 或 None。
        # sysname 进键是因为富化失败时它退成 "-" 而 ip 不变，
        # 两种情况命中的规则可能不同，不能共用一条缓存
        self._match_cache = {}
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
        """
        重新加载两张表。单张加载失败各自保留旧索引，不互相牵连

        :return: (事件属性条数, 定级规则条数)
        """
        events = self._refresh_events()
        rules = self._refresh_severity()
        return events, rules

    def _refresh_events(self):
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

    def _refresh_severity(self):
        """
        重新加载 syslog_severity_rule。加载失败或查询返回空都保留旧索引 ——
        定级表空了全线落 P3，比留着旧规则更糟
        """
        try:
            rows = self.db.getSeverityRules()
        except Exception as err:
            logger.error("======EventAttrs severity refresh error========\n%s", err)
            return self._severity.total
        if not rows and self._severity.total:
            logger.warning("EventAttrs got empty severity rule set, "
                           "keep %s loaded rules", self._severity.total)
            return self._severity.total

        with self._lock:
            self._version += 1
            index = SeverityIndex(rows, version=self._version,
                                  known_codes=self._index.attrs.keys())
            self._severity = index
            self._match_cache = {}
        logger.info("EventAttrs loaded %s severity rules (version %s)",
                    index.total, index.version)
        if not index.has_catch_all:
            # 没有兜底规则，未配规则的事件码会落到代码里的 P3 默认值，
            # 在表里看不出来。这是配置漏项，不是代码问题
            logger.error("======syslog_severity_rule 缺全局兜底规则========\n"
                         "没有 event_code='*' 且 ip_reg/sysname_reg 都空的行，"
                         "未配规则的事件码按 P3 处理。补一行：\n"
                         "INSERT INTO syslog_severity_rule"
                         "(event_code, severity, priority, descr) "
                         "VALUES('*', 3, 999, '全局兜底');")
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
                           "这些事件按 stateless/300s 处理：%s",
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

    def raise_code_of(self, event_code):
        """
        本事件是谁的恢复事件。不是恢复事件就返回空串

        L6 算指纹时用它换算：IF_UP 按 IF_DOWN 算指纹，否则恢复事件
        落到自己的指纹上，故障告警永远关不掉
        """
        index = self._index
        return index.raise_codes.get(str(event_code or ""), "")

    def grade_of(self, event_code, ip, sysname):
        """
        取命中的定级规则，查不到返回 None。带缓存

        设备数 × 事件码数有限（2000 台 × 30 码），刷新时整体清空，
        和 parser._match_cache 一个规格
        """
        index = self._severity
        event_code = str(event_code or "")
        ip = str(ip or "-")
        sysname = str(sysname or "-")

        key = (index.version, event_code, ip, sysname)
        if key in self._match_cache:
            return self._match_cache[key]

        rule = index.match(event_code, ip, sysname)
        with self._lock:
            if self._severity.version == index.version:
                self._match_cache[key] = rule
        return rule

    def size(self):
        """当前加载的事件属性条数"""
        return self._index.total

    def severity_size(self):
        """当前加载的定级规则条数"""
        return self._severity.total

    # ---------------- 流水线入口 ----------------

    def fill(self, event):
        """
        补事件属性 + 定级，原地修改并返回

        两步：syslog_event 给 state/object_type/窗口/clear_code，
        syslog_severity_rule 给 severity。级别按设备判，所以必须在 L4
        富化之后跑 —— 那时 sysname 已经补好。

        clear_code 单独拿出来：L7 配对恢复事件时要用，
        但 raise 类事件才需要，clear 和 stateless 一律留空。
        """
        # 恢复事件要落到故障事件的指纹上，L6 据此算指纹。
        # 自己就是故障码时留空，L6 按 event_code 算
        event["raise_code"] = self.raise_code_of(event.get("event_code"))

        # 第一步：事件属性
        attr = self.attrs_of(event.get("event_code"))
        if attr is None:
            # 兜底：UNKNOWN_MNEMONIC / PARSE_FAIL / UNMANAGED_SRC 在
            # syslog_event 里应该都有行，没有就按默认值走
            event.update({
                "state": DEFAULT_STATE,
                "object_type": DEFAULT_OBJECT_TYPE,
                "window_sec": DEFAULT_WINDOW,
                "threshold": DEFAULT_THRESHOLD,
                "clear_code": "",
            })
        else:
            event.update(attr.as_dict())

        self._grade(event)
        return event

    def _grade(self, event):
        """
        第二步：按 (event_code, ip, sysname) 定级

        没命中任何规则时按 P3 处理。正常情况下不该发生 —— 定级表里有
        event_code='*' 的全局兜底行，加载时查不到那行已经打过 error，
        这里不再逐条喊，否则日志风暴时每条都刷一行
        """
        rule = self.grade_of(event.get("event_code"),
                             event.get("ip"), event.get("sysname"))
        if rule is None:
            event["severity"] = DEFAULT_SEVERITY
            event["severity_rule_id"] = 0
            event["severity_name"] = severity_name(DEFAULT_SEVERITY)
            self._inherit_ignore(event)
            return event

        event["severity"] = rule.severity
        event["severity_rule_id"] = rule.rule_id
        event["severity_name"] = severity_name(rule.severity)
        if rule.action == ACTION_IGNORE:
            # 事件照样往下走并落 ES，只是 L7 不开告警
            event["state"] = STATE_IGNORE
            return event

        self._inherit_ignore(event)
        return event

    def _inherit_ignore(self, event):
        """
        恢复事件跟着故障事件一起 ignore

        定级规则是按 event_code 配的，一条 ('IF_DOWN', '^rsw.*corp',
        ignore) 只盖住 IF_DOWN。但"corp 职场接入口 down 不告警"说的是
        整个 down/up 周期都不用看 —— 配对的 IF_UP 匹配不到那条规则，
        会落全局兜底（正常告警），然后在 L7 发现没有活跃告警可关，
        漏出一条 clear_orphan。规则的意图没实现，噪声还是全量进来。

        所以恢复事件额外按它的故障码（raise_code，L6 算指纹也用它）
        再查一次规则：故障码被 ignore，恢复事件跟着 ignore。

        只继承 ignore，不继承 severity —— 级别本来就该各自判，
        IF_UP 自己有行就用自己的。
        """
        raise_code = event.get("raise_code") or ""
        if not raise_code:
            # 自己就是故障码，没有要继承的
            return
        rule = self.grade_of(raise_code, event.get("ip"), event.get("sysname"))
        if rule is not None and rule.action == ACTION_IGNORE:
            event["state"] = STATE_IGNORE
            # rule_id 记故障码那条 —— 排查时要能看出是哪条规则让它不告警
            event["severity_rule_id"] = rule.rule_id
