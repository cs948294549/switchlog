# -*- coding: utf-8 -*-
"""
L3 解析归一

输入是 L1 prepare 的输出，信封和 mnemonic 已经剥好。本层只剩两步：

    1. 按源 IP 查 devices.vendor。厂商只认 devices 表，不猜文本
    2. syslog_rule 查 (vendor, mnemonic)，没命中退 ('*', mnemonic)。
       同一 mnemonic 多行时用 body_match 消歧（PHY_UPDOWN 的 up/down
       共用一条 mnemonic）。命中后按该行的 object_regex 抽对象

这两步分别查两张不同的表，所以本层接两个 db：构造时的 db 参数只管
syslog_rule（由 get_rule_db() 注入），device_db 参数单独查
devices.vendor（由 get_device_db() 注入）。SyslogRuleDB 不实现
getDeviceVendor，两者不能共用一个 db 实例。

只产出 event_code 和 object 两样东西。severity / state / object_type /
窗口 / clear_code 是事件属性，按 event_code 查 syslog_event，在 L5 确定。

一切按表来，代码里不内置任何厂商正则或关键字：
报文不可读 -> PARSE_FAIL，查不到厂商 -> UNMANAGED_SRC，
规则表没命中 -> UNKNOWN_MNEMONIC；object_regex 没配或没抽到，object 就是 "-"。
三个兜底码在 syslog_event 里有行，级别和窗口照样可调，UNKNOWN_MNEMONIC
同时就是规则缺口清单（按 vendor + mnemonic 分组计数）。
"""
import re
import time
import logging
import threading

logger = logging.getLogger(__name__)

DEFAULT_REFRESH = 300          # syslog_rule 刷新间隔
DEFAULT_VENDOR_TTL = 600       # devices.vendor 缓存，含负缓存

# 解析器自己产生的三个事件码，syslog_event 里有行，级别和窗口照样可调
CODE_UNKNOWN = "UNKNOWN_MNEMONIC"
CODE_PARSE_FAIL = "PARSE_FAIL"
CODE_UNMANAGED = "UNMANAGED_SRC"

NO_OBJECT = "-"
ANY_VENDOR = "*"

MATCH_EXACT = "exact"
MATCH_CONTAINS = "contains"
MATCH_REGEX = "regex"

# 抽出来的对象去掉首尾标点，Interface Eth1/1, 这类尾逗号不能进指纹
OBJECT_TRIM = " \t\r\n,.;:\"'()[]<>"


class SyslogRule(object):
    """syslog_rule 的一行，正则在加载时编译一次"""

    __slots__ = ("rule_id", "vendor", "mnemonic", "match_type", "pattern", "pattern_reg",
                 "body_match", "event_code", "object_reg", "priority", "descr")

    def __init__(self, row):
        self.rule_id = row.get("rule_id", 0)
        self.vendor = str(row.get("vendor", "") or ANY_VENDOR).strip().lower() or ANY_VENDOR
        self.mnemonic = str(row.get("mnemonic", "") or "").strip()
        self.match_type = str(row.get("match_type", "") or MATCH_EXACT).strip().lower()
        if self.match_type not in (MATCH_EXACT, MATCH_CONTAINS, MATCH_REGEX):
            self.match_type = MATCH_EXACT
        self.pattern = str(row.get("pattern", "") or "")
        self.body_match = str(row.get("body_match", "") or "")
        self.event_code = str(row.get("event_code", "") or "").strip()
        self.priority = self._to_int(row.get("priority"), 100)
        self.descr = str(row.get("descr", "") or "")
        self.pattern_reg = None
        self.object_reg = None
        if self.match_type == MATCH_REGEX and self.pattern:
            self.pattern_reg = self._compile(self.pattern, self.rule_id, "pattern")
        object_regex = str(row.get("object_regex", "") or "")
        if object_regex:
            self.object_reg = self._compile(object_regex, self.rule_id, "object_regex")

    @staticmethod
    def _to_int(value, default):
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _compile(expression, rule_id, field):
        try:
            return re.compile(expression)
        except re.error as err:
            # 规则写错了只废掉这一条，不能让整张表加载不上
            logger.error("======SyslogRule %s compile error rule_id=%s========\n%s",
                         field, rule_id, err)
            return None

    def match_body(self, body):
        """
        正文判据。exact 时 mnemonic 已经是全部判据，只剩 body_match 消歧；
        contains/regex 再按 pattern 判一次
        """
        if self.body_match and self.body_match not in body:
            return False
        if self.match_type == MATCH_CONTAINS:
            return bool(self.pattern) and self.pattern in body
        if self.match_type == MATCH_REGEX:
            return self.pattern_reg is not None and bool(self.pattern_reg.search(body))
        return True

    def extract_object(self, body):
        """
        按本行的 object_regex 抽对象。同一事件码下不同 mnemonic 正文格式不同，
        所以正则逐行配，不按事件配一份。

        :return: (object, object_raw)，没配或没抽到都返回 ("-", "")
        """
        if self.object_reg is None:
            return NO_OBJECT, ""
        match = self.object_reg.search(body)
        if not match:
            return NO_OBJECT, ""
        raw = match.group(1) if match.groups() else match.group(0)
        value = str(raw or "").strip(OBJECT_TRIM)
        return (value or NO_OBJECT), str(raw or "")


class RuleIndex(object):
    """
    syslog_rule 的内存索引，一次加载对应一个 version，缓存挂在 version 上，
    规则一改整体失效。

        exact  dict[(vendor, mnemonic)] -> [rule, ...]   按 priority, rule_id 排
        fuzzy  mnemonic 为空的规则，按 priority 升序，只对剥不出 mnemonic 的报文跑
    """

    __slots__ = ("exact", "fuzzy", "version", "total")

    def __init__(self, rows, version):
        self.version = version
        self.exact = {}
        self.fuzzy = []
        self.total = 0
        for row in rows or []:
            rule = SyslogRule(row)
            if not rule.event_code:
                # 没给事件码的规则没有意义，跳过
                continue
            if rule.match_type == MATCH_REGEX and rule.pattern_reg is None:
                continue
            self.total += 1
            if rule.mnemonic:
                self.exact.setdefault((rule.vendor, rule.mnemonic), []).append(rule)
            else:
                self.fuzzy.append(rule)
        for rules in self.exact.values():
            rules.sort(key=lambda item: (item.priority, item.rule_id))
        self.fuzzy.sort(key=lambda item: (item.priority, item.rule_id))

    def candidates(self, vendor, mnemonic):
        """
        先按厂商精确查，未命中退 vendor='*'。
        两边都有时合并：厂商专属规则优先（priority 相同时先到的在前）
        """
        rules = self.exact.get((vendor, mnemonic), [])
        shared = self.exact.get((ANY_VENDOR, mnemonic), []) if vendor != ANY_VENDOR else []
        if rules and shared:
            return rules + shared
        return rules or shared

    def fuzzy_candidates(self, vendor):
        return [rule for rule in self.fuzzy if rule.vendor in (ANY_VENDOR, vendor)]


class SyslogParser(object):
    """
    L3 解析器

    规则表定时刷新，devices.vendor 带 TTL 缓存（含负缓存）。
    线程安全：索引整体替换，读的时候拿一次引用，不在读路径上加锁。
    """

    def __init__(self, refresh_interval=DEFAULT_REFRESH, vendor_ttl=DEFAULT_VENDOR_TTL,
                 db=None, device_db=None):
        """
        :param refresh_interval: syslog_rule 刷新间隔（秒），0 表示只加载一次
        :param vendor_ttl: devices.vendor 缓存秒数
        :param db: 规则表数据源，由 db.get_rule_db() 注入，只管 syslog_rule
        :param device_db: 设备表数据源，由 db.get_device_db() 注入，
                          vendor_of() 用它查 devices.vendor。规则表和
                          设备表是两张不同的库表，不能共用一个 db ——
                          SyslogRuleDB 不实现 getDeviceVendor，那是
                          DeviceDB 的职责
        """
        self._refresh_interval = int(refresh_interval)
        self._vendor_ttl = int(vendor_ttl)
        self._db = db
        self._device_db = device_db
        self._index = RuleIndex([], 0)
        self._version = 0
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._refresh_thread = None
        self._vendor_cache = {}     # ip -> (expire_ts, vendor)
        # (version, vendor, mnemonic) -> [rule, ...]，含未命中（空列表）
        self._match_cache = {}

        self.refresh()

        if self._refresh_interval > 0:
            self._refresh_thread = threading.Thread(
                target=self._refresh_loop, name="parser-refresh", daemon=True)
            self._refresh_thread.start()

    # ---------------- 规则加载 ----------------

    @property
    def db(self):
        if self._db is None:
            from db import get_rule_db
            self._db = get_rule_db()
        return self._db

    @property
    def device_db(self):
        if self._device_db is None:
            from db import get_device_db
            self._device_db = get_device_db()
        return self._device_db

    def refresh(self):
        """重新加载 syslog_rule。加载失败保留旧索引，不把管线打空"""
        try:
            rows = self.db.getSyslogRules()
        except Exception as err:
            logger.error("======SyslogParser refresh error========\n%s", err)
            return self._index.total
        if not rows and self._index.total:
            # 查询返回空但之前有规则，按失败处理，避免瞬时故障把规则清空。
            # 这里和黑名单相反：规则空了会全线落 UNKNOWN_MNEMONIC，比留着旧规则更糟
            logger.warning("SyslogParser got empty rule set, keep %s loaded rules",
                           self._index.total)
            return self._index.total
        with self._lock:
            self._version += 1
            index = RuleIndex(rows, self._version)
            self._index = index
            self._match_cache = {}
        logger.info("SyslogParser loaded %s rules (version %s)", index.total, index.version)
        return index.total

    def _refresh_loop(self):
        while not self._stop_event.is_set():
            if self._stop_event.wait(self._refresh_interval):
                break
            try:
                self.refresh()
            except Exception as err:
                logger.error("======SyslogParser refresh loop error========\n%s", err)

    def stop(self):
        self._stop_event.set()

    def size(self):
        """当前加载的规则条数"""
        return self._index.total

    # ---------------- 厂商判定 ----------------

    def vendor_of(self, ip, now=None):
        """
        源 IP -> devices.vendor 原值。查不到返回空串，由调用方打 UNMANAGED_SRC。

        不做任何文本猜测：设备换版本后正文格式会变，猜出来的结果会漂且没人知道。
        """
        ip = str(ip or "").strip()
        if not ip:
            return ""
        now = int(now if now is not None else time.time())
        with self._lock:
            cached = self._vendor_cache.get(ip)
            if cached and cached[0] > now:
                return cached[1]

        try:
            vendor = self.device_db.getDeviceVendor(ip)
        except Exception as err:
            logger.error("======SyslogParser vendor lookup error========\n%s", err)
            return ""
        if vendor == "failed":
            # 查询本身失败，不写负缓存，下一条重新查
            return ""

        vendor = str(vendor or "").strip().lower()
        with self._lock:
            self._vendor_cache[ip] = (now + self._vendor_ttl, vendor)
        return vendor

    def purge_vendor_cache(self, now=None):
        now = int(now if now is not None else time.time())
        with self._lock:
            expired = [ip for ip, (expire, _) in self._vendor_cache.items() if expire <= now]
            for ip in expired:
                self._vendor_cache.pop(ip, None)
        return len(expired)

    # ---------------- 规则匹配 ----------------

    def _candidates(self, index, vendor, mnemonic):
        """
        候选规则列表，带缓存（含未命中的空列表）。
        同一台设备会反复发同一类日志，其中很多根本没配规则，
        不缓存失败结果这些日志每次都要重新查一遍表。
        缓存键带 version，规则一改整体失效。
        """
        key = (index.version, vendor, mnemonic)
        cached = self._match_cache.get(key)
        if cached is not None:
            return cached
        rules = index.candidates(vendor, mnemonic)
        with self._lock:
            if self._index.version == index.version:
                self._match_cache[key] = rules
        return rules

    def _pick(self, index, vendor, mnemonic, body):
        """
        选出命中的规则。

        候选只有一条且没配 body_match / pattern 时直接返回，不碰正文；
        多条时按 priority 升序逐条判 body_match，命中即停
        （Comware 的 PHY_UPDOWN：同一 mnemonic，up 和 down 只差在正文）。
        mnemonic 剥不出来时才走 fuzzy，对真没见过的报文做兜底匹配。
        """
        if mnemonic:
            rules = self._candidates(index, vendor, mnemonic)
            if len(rules) == 1 and rules[0].match_type == MATCH_EXACT \
                    and not rules[0].body_match:
                return rules[0]
        else:
            rules = index.fuzzy_candidates(vendor)
        for rule in rules:
            if rule.match_body(body):
                return rule
        return None

    # ---------------- 解析入口 ----------------

    def parse(self, prepared, now=None):
        """
        解析一条已预处理的报文

        :param prepared: L1 prepare 的输出
        :param now: 采集时间，prepared 里没有 ingest_ts 时用
        :return: L3 输出契约，见 pipeline/__init__.py
        """
        ip = prepared.get("ip") or "-"
        body = prepared.get("body") or ""
        mnemonic = prepared.get("mnemonic") or ""
        ingest_ts = prepared.get("ingest_ts") or int(now if now is not None else time.time())

        event = {
            "ingest_ts": ingest_ts,
            "ip": ip,
            "hostname": prepared.get("hostname") or "-",
            "message": prepared.get("message") or "",
            "body": body,
            "mnemonic": mnemonic,
            "vendor": "",
            "event_code": "",
            "alarm_object": NO_OBJECT,
            "object_raw": "",
            "rule_id": 0,
        }

        # 信封都剥不动，报文不可读。一台设备持续发垃圾日志本身就是配置错误
        if not prepared.get("readable"):
            event["event_code"] = CODE_PARSE_FAIL
            return event

        # 厂商只认 devices 表。查不到不解析，但事件照样往下走，
        # 它在发日志而表里没有，这本身就是该补纳管的事件
        vendor = self.vendor_of(ip, now=ingest_ts)
        event["vendor"] = vendor
        if not vendor:
            event["event_code"] = CODE_UNMANAGED
            return event

        rule = self._pick(self._index, vendor, mnemonic, body)
        if rule is None:
            # 规则缺口。按 (vendor, mnemonic) 分组计数就是下一条该补的规则
            event["event_code"] = CODE_UNKNOWN
            return event

        event["event_code"] = rule.event_code
        event["rule_id"] = rule.rule_id
        event["alarm_object"], event["object_raw"] = rule.extract_object(body)
        return event
