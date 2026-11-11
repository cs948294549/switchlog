# -*- coding: utf-8 -*-
"""
L0.5 黑名单拦截

放在 parser 之前，命中就把报文丢掉，不进后面任何一层。

为什么放在解析前：确定是噪声的日志（登录过程、调试输出、心跳），
解析它纯属浪费 —— 既要查 devices 表，又要跑一遍规则匹配，最后还是丢。
日志风暴时这一层就是挡在前面的闸门。

匹配分两级，mnemonic 由 L0 的 prepare 剥好透传进来：

    一级  dict[mnemonic] -> rule          O(1)，绝大多数规则走这里
          再查 dict[(ip, mnemonic)]，设备专属规则不参与全量流量
    二级  全文子串，一小串规则线性扫        只给不带 mnemonic 的噪声用

为什么这么分：实测 162 字节报文逐条 str.find，20 条规则就和剥一次
mnemonic 一样贵，100 条是 4 倍，500 条是 21 倍。而 mnemonic 既然
已经在手上，dict 查一次只要 0.036us，等于白拿。

判据只有 mnemonic/子串 + ip 两样，因为这一层还没解析，手上只有
(src_ip, message, mnemonic)。需要正则、需要变更窗口期 mute、
需要按机房限定的，配到 L3 抑制去。

拦掉的日志照常落 ES 归档（旁路独立消费原始日志，不受本层影响），
所以这里丢得起。但丢掉就查不到了，所以每条规则带命中计数，
stats() 能看出哪条规则在吃量、有没有误拦。
"""
import logging
import threading

logger = logging.getLogger(__name__)

DEFAULT_REFRESH = 300          # 规则刷新间隔

# syslog_black_list.scope：这条规则按什么匹配
SCOPE_MNEMONIC = "mnemonic"    # pattern 是 mnemonic 全名，进 dict
SCOPE_MESSAGE = "message"      # pattern 是全文子串，线性扫
SCOPES = (SCOPE_MNEMONIC, SCOPE_MESSAGE)


class BlacklistRule(object):
    """
    syslog_black_list 的一行

    pattern     scope=mnemonic 时是 mnemonic 全名；scope=message 时是全文子串
    scope       mnemonic=进 dict O(1)；message=进线性扫列表
    ip          限定设备，空=不限
    ignore_case 只对 scope=message 生效。mnemonic 是设备给的固定字面量，
                大小写不会变，进 dict 的键不做大小写处理

    没有 priority：这一层只有"丢"一个动作，命中哪条结果都一样，
    同一个键配多条是数据错误，加载时直接报出来（见 BlacklistIndex）。
    """

    __slots__ = ("rule_id", "pattern", "needle", "scope", "ip", "ignore_case",
                 "descr", "hits")

    def __init__(self, row):
        self.rule_id = row.get("rule_id", 0)
        self.pattern = str(row.get("pattern", "") or "").strip()
        self.scope = str(row.get("scope", "") or SCOPE_MNEMONIC).strip().lower()
        if self.scope not in SCOPES:
            self.scope = SCOPE_MNEMONIC
        self.ip = str(row.get("ip", "") or "").strip()
        self.ignore_case = bool(row.get("ignore_case", 0)) and self.scope == SCOPE_MESSAGE
        self.descr = str(row.get("descr", "") or "")
        # 预先算好用于比较的那一份，热路径上不再做 lower()
        self.needle = self.pattern.lower() if self.ignore_case else self.pattern
        self.hits = 0

    def valid(self):
        """pattern 为空的规则会命中一切，必须挡掉"""
        return bool(self.pattern)

    def match_message(self, message, message_lower):
        """
        二级：全文子串。ip 已经由调用方按桶分好，这里不再判

        :param message_lower: 调用方算一次传进来，避免每条规则都 lower 一遍
        """
        return self.needle in (message_lower if self.ignore_case else message)

    def info(self):
        return {
            "rule_id": self.rule_id,
            "pattern": self.pattern,
            "scope": self.scope,
            "ip": self.ip or "*",
            "ignore_case": self.ignore_case,
            "descr": self.descr,
            "hits": self.hits,
        }


class BlacklistIndex(object):
    """
    规则索引，一次加载对应一个不可变快照

        by_mnemonic       dict[mnemonic] -> rule       全设备生效
        by_ip_mnemonic    dict[(ip, mnemonic)] -> rule 设备专属，不参与全量流量
        message_rules     全文子串规则，只给不带 mnemonic 的报文扫
        ip_message_rules  dict[ip] -> [rule]           设备专属的全文规则

    同一个键配了多条是数据错误，直接报 error 并按 rule_id 小的留一条 ——
    这一层只有"丢"一个动作，留哪条结果都一样，但不能悄悄吞掉配置问题。
    """

    __slots__ = ("by_mnemonic", "by_ip_mnemonic", "message_rules", "ip_message_rules",
                 "needs_lower", "total", "rules", "duplicates")

    def __init__(self, rows):
        self.by_mnemonic = {}
        self.by_ip_mnemonic = {}
        self.message_rules = []
        self.ip_message_rules = {}
        self.rules = []
        self.total = 0
        self.duplicates = []

        invalid = 0
        for row in rows or []:
            rule = BlacklistRule(row)
            if not rule.valid():
                invalid += 1
                logger.error("======BlacklistIndex empty pattern, rule_id=%s========",
                             rule.rule_id)
                continue
            self.rules.append(rule)
            self.total += 1
            if rule.scope == SCOPE_MNEMONIC:
                table = self.by_ip_mnemonic if rule.ip else self.by_mnemonic
                key = (rule.ip, rule.pattern) if rule.ip else rule.pattern
                if key in table:
                    self.duplicates.append((rule, table[key]))
                    logger.error(
                        "======BlacklistIndex duplicate key========\n"
                        "scope=mnemonic ip=%s pattern=%s rule_id=%s 与 rule_id=%s 重复，保留前者",
                        rule.ip or "*", rule.pattern, rule.rule_id, table[key].rule_id)
                    continue
                table[key] = rule
            elif rule.ip:
                self.ip_message_rules.setdefault(rule.ip, []).append(rule)
            else:
                self.message_rules.append(rule)

        # 同一设备下全文规则也有重复的可能，按 (ip, needle) 查一遍
        seen = {(rule.ip, rule.needle): rule for rule in self.message_rules}
        for ip, rules in self.ip_message_rules.items():
            for rule in rules:
                key = (rule.ip, rule.needle)
                if key in seen:
                    self.duplicates.append((rule, seen[key]))
                    logger.error(
                        "======BlacklistIndex duplicate key========\n"
                        "scope=message ip=%s pattern=%s rule_id=%s 与 rule_id=%s 重复",
                        ip, rule.pattern, rule.rule_id, seen[key].rule_id)
                seen[key] = rule

        # 全文规则没有先后之分，排序只为让输出稳定
        self.message_rules.sort(key=lambda item: item.rule_id)
        for rules in self.ip_message_rules.values():
            rules.sort(key=lambda item: item.rule_id)
        # 有没有大小写不敏感的规则，加载时定下来，热路径上不再 any() 扫一遍
        self.needs_lower = any(rule.ignore_case for rule in self.rules)
        if invalid:
            logger.warning("BlacklistIndex ignored %s rules with empty pattern", invalid)
        if self.duplicates:
            logger.warning("BlacklistIndex found %s duplicate keys, 去重后再用",
                           len(self.duplicates))

    def lookup(self, ip, mnemonic, message):
        """
        查命中的规则，没有返回 None

        先两次 dict；没中再扫全文规则。全文那串是故意保持小的
        （只放报文头的噪声），所以每条日志都扫它也只是几条 str.find。
        带 mnemonic 的报文同样要扫 —— 全文规则匹配的位置可能在
        mnemonic 之外，不能因为有 mnemonic 就跳过。
        """
        if mnemonic:
            rule = self.by_mnemonic.get(mnemonic)
            if rule is not None:
                return rule
            if self.by_ip_mnemonic:
                rule = self.by_ip_mnemonic.get((ip, mnemonic))
                if rule is not None:
                    return rule

        own = self.ip_message_rules.get(ip) if self.ip_message_rules else None
        if not self.message_rules and not own:
            return None

        message_lower = message.lower() if self.needs_lower else message
        # 全局和设备专属分别扫，不拼列表 —— 拼一次就是一次内存分配，
        # 热路径上每条日志都要付
        for rule in self.message_rules:
            if rule.match_message(message, message_lower):
                return rule
        for rule in own or ():
            if rule.match_message(message, message_lower):
                return rule
        return None


class BlacklistFilter(object):
    """
    黑名单过滤器

    规则定时刷新，命中计数常驻。线程安全：索引整体替换，
    读路径只拿一次引用；计数是 int 自增，GIL 下不会丢（不要求精确）。
    """

    def __init__(self, refresh_interval=DEFAULT_REFRESH, db=None):
        """
        :param refresh_interval: 刷新间隔（秒），0 表示只加载一次
        :param db: 数据源，由 db.get_rule_db() 注入
        """
        self._refresh_interval = int(refresh_interval)
        self._db = db
        self._index = BlacklistIndex([])
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._refresh_thread = None
        # 总量统计：进来多少条、拦了多少条
        self._total = 0
        self._blocked = 0

        self.refresh()

        if self._refresh_interval > 0:
            self._refresh_thread = threading.Thread(
                target=self._refresh_loop, name="blacklist-refresh", daemon=True)
            self._refresh_thread.start()

    # ---------------- 规则加载 ----------------

    @property
    def db(self):
        if self._db is None:
            from db import get_rule_db
            self._db = get_rule_db()
        return self._db

    def refresh(self):
        """
        重新加载规则。

        查询异常时保留旧索引；查出空集就按空集生效。
        这和 parser 的处理相反：黑名单空了只是少拦一些噪声，
        而误留旧规则会继续丢日志，后者更危险。
        """
        try:
            rows = self.db.getBlacklistRules()
        except Exception as err:
            logger.error("======BlacklistFilter refresh error========\n%s", err)
            return self._index.total

        index = BlacklistIndex(rows)
        # 命中计数跨刷新保留，否则页面上的量每 5 分钟清零
        with self._lock:
            previous = {rule.rule_id: rule.hits for rule in self._index.rules}
            for rule in index.rules:
                rule.hits = previous.get(rule.rule_id, 0)
            self._index = index
        logger.info("BlacklistFilter loaded %s rules（mnemonic %s / message %s）",
                    index.total,
                    len(index.by_mnemonic) + len(index.by_ip_mnemonic),
                    len(index.message_rules) +
                    sum(len(v) for v in index.ip_message_rules.values()))
        return index.total

    def _refresh_loop(self):
        while not self._stop_event.is_set():
            if self._stop_event.wait(self._refresh_interval):
                break
            try:
                self.refresh()
            except Exception as err:
                logger.error("======BlacklistFilter refresh loop error========\n%s", err)

    def stop(self):
        self._stop_event.set()

    # ---------------- 热路径 ----------------

    def match(self, prepared):
        """
        查哪条规则命中，不计数、不改状态，排查用

        :param prepared: prepare 的输出，mnemonic 已剥好
        :return: 命中的 BlacklistRule，没命中返回 None
        """
        prepared = prepared if isinstance(prepared, dict) else {}
        message = prepared.get("message") or ""
        if not message:
            return None
        return self._index.lookup(
            prepared.get("ip") or "-",
            prepared.get("mnemonic") or "",
            message)

    def blocked(self, prepared):
        """
        是否该拦掉。命中即计数。

        这是管线上的调用入口：返回 True 就不要再往 parser 送。
        """
        self._total += 1
        rule = self.match(prepared)
        if rule is None:
            return False
        rule.hits += 1
        self._blocked += 1
        logger.debug("blacklist drop %s by rule %s (%s=%s)",
                     prepared.get("ip", "-"), rule.rule_id, rule.scope, rule.pattern)
        return True

    # ---------------- 统计 ----------------

    def stats(self):
        """
        看哪条规则在吃量。hits 为 0 的规则要么没用上，要么 pattern 写错了
        """
        index = self._index
        rules = sorted(index.rules, key=lambda rule: -rule.hits)
        return {
            "total": self._total,
            "blocked": self._blocked,
            "passed": self._total - self._blocked,
            "mnemonic_rules": len(index.by_mnemonic) + len(index.by_ip_mnemonic),
            "message_rules": len(index.message_rules) + sum(
                len(v) for v in index.ip_message_rules.values()),
            "rules": [rule.info() for rule in rules],
        }

    def reset_stats(self):
        with self._lock:
            self._total = 0
            self._blocked = 0
            for rule in self._index.rules:
                rule.hits = 0

    def size(self):
        return self._index.total
