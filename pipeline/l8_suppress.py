# -*- coding: utf-8 -*-
"""
L8 告警静默

只有 mute 一档，判据 ip_reg / event_code_reg / object_reg + 时间窗。

原来设计的三档收窄成一档：

    drop    确定是噪声的日志改用 syslog_black_list 在 L2 截掉。
            越早丢越省资源，那一层按 mnemonic 走 dict，比解析完再丢便宜
    depend  拓扑抑制依赖运行时的上游可达状态，不是静态规则能表达的，
            本轮不做
    mute    留下，就是本层

跑在 L7 之后，不在 L5 之后，三个原因：

    1. 判据凑不齐。object 要等 L3 抽、L6 聚合，告警状态要等 L7
    2. 冷路径。只有 L7 判定"需要告警"的聚合告警才过这一层 ——
       一次端口 down 是 3 条日志、1 个指纹、1 次 mute 判断，量级从
       日志条数掉到告警条数，差几个数量级。所以四个判据全用正则也不心疼
    3. 被静默的告警照样进聚合、进状态机、照样写 alarm_list，只是不发
       通知。割接完要能回看那段时间发生了什么

所以本层不丢事件、不拦记录。muted 是记录上的一个状态，不是"要不要入库"
的开关 —— 被静默的告警照样入库，只是 L9 不发通知。

这和 L5 的 action=ignore 是同一个模式（都不丢事件，只标记），区别是
ignore 是静态配置、长期生效，mute 是时间窗驱动、窗口过了自动恢复。

======================= 写入时序 =======================

新开的告警：本层判完 mute，muted 和 mute_rule_id 跟着其余字段一次
INSERT 进去（AlarmDB.addAlarm 的入参里就有这两个）。不要先 INSERT
muted=0 再 UPDATE 成 1 —— 中间那一瞬间看板轮询到会显示成"割接期间有条
没静默的告警"。

======================= 判一次就定了，没有定时扫描 =======================

静默是**告警产生那一刻**判一次的事，判完就定了，不回头改：

    L6 聚合出一条告警
    -> L8 拿这条告警的发生时间（decision["ingest_ts"]）比规则的时间窗
    -> 在窗口内且判据命中  -> 打屏蔽标签（muted=1 status='4'）
    -> 否则                -> 正常往 L9 走

本层**没有 sweep()**。以前有一个定时扫描，把"窗口过了但告警还没恢复"的
放出来补发通知，已经删掉 —— 窗口过了而这期间没有新告警产生，就说明没有
新的事情发生，不需要把旧告警翻回待处理。真有新日志进来，自然会重新走一
遍上面的判定，那时候窗口已经过了，这条新告警就不会被静默。

handle() 里原来还有一道 `if not notify: return` 的门槛（L7 判
ACTION_NONE 就不判 mute），也去掉了：原始日志进来就按流程判。那道门槛
的后果是同一窗口段内的重复 raise 全部跳过正则，人在前端新加的规则对已
经开着的告警永远不生效（hit_count 一直是 0）。

muted 和 alarm_list.status 两列**同步变**，不是分开的两套语义 ——
人工屏蔽就是 mute，不区分"人点的4"和"规则设的4"：

    命中规则  muted=1  status='4'（看板显示已屏蔽）
    不命中    muted=0  status 交给 L9 定（ignore段='5'，其余='0'）

两列都留着是因为用途不同：muted 是 L9 判断发不发通知用的开关，
status 是看板上的处理状态标签。

注意这是**每条告警各判一次**，不是给某条告警反复改状态：窗口过了之后
新产生的告警判出来就是 muted=0，窗口内产生的那条保持 muted=1 不动。

三个字段各管一件事，别混：
    state   open/clear，**只影响展示标签**（告警中/已恢复的事实记录），
            不参与"该不该静默"的判断
    status  处理状态，0待处理 1已确认 2已处理 3忽略 4已屏蔽 5系统忽略
    muted   发不发通知的开关

段和 mute 的交互：割接期间同一个窗口段内反复 down/up，L7 只有一行告警，
但每次翻回告警中（action=reopen）都会重新过一遍本层。所以割接窗口一开，
这些 reopen 全被压住；窗口一过还在抖的话，下一次 reopen 就会漏出来。
不需要在本层记"这一行压过没有"——mute 判的是这一刻该不该通知。

实现前置条件：
    1. syslog_mute_rule 表定稿（已建，见 sql/schema.sql）
    2. 变更工单的查询接口确定 —— 规则的数据来源是 central-server 的
       AlterationManageDB，人工配规则只是兜底
    3. L6 / L7 先落地，本层的输入是它们产出的聚合告警

======================= 接口 =======================

    handle(decision, now) -> 原地往 decision 上填 muted / mute_rule_id / status

入参是 L7 的决策（带 fingerprint / ip / event_code / alarm_object），
不是原始 event —— 本层在 L7 之后，拿到的已经是告警不是日志。
"""
import re
import time
import logging
import threading


logger = logging.getLogger(__name__)

ACTION_PASS = "pass"
ACTION_MUTE = "mute"

# alarm_list.status 的取值。命中 mute 规则写 '4'（已屏蔽）——
# 人工屏蔽就是 mute，不区分"人点的4"和"规则设的4"，统一这一个值。
# 不命中时本层不写 status，交给 L9 定（ignore段='5'，其余='0'）
STATUS_MUTED = "4"

# syslog_mute_rule 刷新间隔。比其他规则表短（那几张是 300s）：
# 变更窗口是分钟级的，工单一开就得尽快生效，等 5 分钟割接都开始了
DEFAULT_REFRESH = 60


class MuteRule(object):
    """
    syslog_mute_rule 的一行，正则在加载时编译一次

    三个判据都空的规则匹配所有告警。这是合法用法（整站静默，比如全局
    演练），但危险，所以加载时打 warning —— 一个笔误就把全网告警静默了。
    """

    __slots__ = ("rule_id", "ip_reg", "event_code_reg", "object_reg",
                 "ip_pattern", "event_pattern", "object_pattern",
                 "start_time", "end_time", "descr", "hits", "persisted_hits")

    def __init__(self, row):
        self.rule_id = row.get("rule_id", 0)
        self.ip_pattern = str(row.get("ip_reg", "") or "").strip()
        self.event_pattern = str(row.get("event_code_reg", "") or "").strip()
        self.object_pattern = str(row.get("object_reg", "") or "").strip()
        self.start_time = self._to_int(row.get("start_time"), 0)
        # 空 end_time = 永久静默
        self.end_time = self._to_int(row.get("end_time"), 0)
        self.descr = str(row.get("descr", "") or "")
        # 命中数：告警被这条规则压住的次数，不是日志条数（L8 只过聚合后
        # 的告警）。persisted_hits 是 persist() 上次刷进数据库时的值，
        # 算增量用，跨刷新保留见 MuteFilter.refresh()
        self.hits = 0
        self.persisted_hits = 0

        self.ip_reg = self._compile(self.ip_pattern, self.rule_id, "ip_reg")
        self.event_code_reg = self._compile(self.event_pattern, self.rule_id,
                                            "event_code_reg")
        self.object_reg = self._compile(self.object_pattern, self.rule_id, "object_reg")

    @staticmethod
    def _to_int(value, default):
        try:
            text = str(value or "").strip()
            return int(text) if text else default
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _compile(expression, rule_id, field):
        if not expression:
            return None
        try:
            return re.compile(expression)
        except re.error as err:
            # 正则写错了只废掉这一条，不能让整张表加载不上。
            # 返回 False 由 valid() 滤掉 —— 不能让它变成"无判据"的全站静默
            logger.error("======MuteRule %s compile error rule_id=%s========\n%s",
                         field, rule_id, err)
            return False

    def valid(self):
        """正则编译失败的行作废"""
        return not (self.ip_reg is False or self.event_code_reg is False
                    or self.object_reg is False)

    def is_catch_all(self):
        """三个判据都空，匹配所有告警"""
        return not (self.ip_pattern or self.event_pattern or self.object_pattern)

    def in_window(self, now):
        """
        当前时刻在窗口内。start_time 空=立即生效，end_time 空=永久

        数据库那边 getMuteRules() 已经按时间过滤过一遍，这里还要再判一次：
        规则是最多 60s 前加载到内存的，这期间窗口可能已经过了。而判窗口
        用的是**这条告警的发生时间**（decision["ingest_ts"]），不是当前
        时刻 —— 告警什么时候发生的，就按那一刻在不在窗口内算
        """
        if self.start_time and now < self.start_time:
            return False
        if self.end_time and now > self.end_time:
            return False
        return True

    def matches(self, ip, event_code, alarm_object):
        """三个判据取与，空=不限"""
        if self.ip_reg is not None and not self.ip_reg.search(ip):
            return False
        if self.event_code_reg is not None and not self.event_code_reg.search(event_code):
            return False
        if self.object_reg is not None and not self.object_reg.search(alarm_object):
            return False
        return True


class MuteIndex(object):
    """
    syslog_mute_rule 的内存快照

    规则数量少（变更窗口是稀疏事件，同时进行的割接不会有几百个），
    所以直接线性扫，不建索引。判据是三个正则，没有能做 dict 命中的键。
    """

    __slots__ = ("rules", "total", "version")

    def __init__(self, rows, version=0):
        self.version = version
        self.rules = []
        self.total = 0

        invalid = 0
        for row in rows or []:
            rule = MuteRule(row)
            if not rule.valid():
                invalid += 1
                continue
            self.rules.append(rule)
            self.total += 1
            if rule.is_catch_all():
                logger.warning("syslog_mute_rule rule_id=%s 三个判据都空，"
                               "会静默所有告警。确认这是整站静默而不是笔误：%s",
                               rule.rule_id, rule.descr)

        self.rules.sort(key=lambda item: item.rule_id)
        if invalid:
            logger.warning("MuteIndex ignored %s rules with bad regex", invalid)

    def match(self, ip, event_code, alarm_object, now):
        """首条命中即返回。静默只有一个动作，命中哪条结果都一样"""
        for rule in self.rules:
            if rule.in_window(now) and rule.matches(ip, event_code, alarm_object):
                return rule
        return None


class MuteFilter(object):
    """
    L8 静默

    handle() 判一条决策要不要静默。判一次就定了，没有回头修改的机制。
    和其他规则层一样定时刷新，索引整体替换，读路径不加锁。
    """

    def __init__(self, refresh_interval=DEFAULT_REFRESH, db=None, write_db=True):
        """
        :param refresh_interval: syslog_mute_rule 刷新间隔（秒），0=只加载一次
        :param db: 数据源，由 db.get_alarm_db() 注入
        :param write_db: False=只读不写，persist() 不回写 hit_count。
                         规则照常加载、静默照常判，只是不往库里留痕
        """
        self._refresh_interval = int(refresh_interval)
        self._db = db
        self._write_db = bool(write_db)
        self._index = MuteIndex([])
        self._version = 0
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._refresh_thread = None
        self._muted_count = 0

        self.refresh()

        if self._refresh_interval > 0:
            self._refresh_thread = threading.Thread(
                target=self._refresh_loop, name="mute-refresh", daemon=True)
            self._refresh_thread.start()

    @property
    def db(self):
        if self._db is None:
            from db import get_alarm_db
            self._db = get_alarm_db()
        return self._db

    def refresh(self):
        """
        重新加载 syslog_mute_rule

        和其他规则表相反：这里空结果是正常状态（没有进行中的割接），
        直接接受，不保留旧索引。保留的话窗口过了的规则会一直生效 ——
        那是最糟的结果，故障永远静默
        """
        try:
            rows = self.db.getMuteRules()
        except Exception as err:
            # 查询失败才保留旧索引：宁可多静默一会儿，也不要因为数据库抖动
            # 把割接期间的告警全放出来
            logger.error("======MuteFilter refresh error========\n%s", err)
            return self._index.total

        index = MuteIndex(rows, version=self._version + 1)
        with self._lock:
            self._version += 1
            # 命中计数跨刷新保留（规则还在窗口内、还在列表里的情况）。
            # persisted_hits 也要带过去，否则下次 persist() 把 hits 全量
            # 当增量重刷一遍。窗口过期后规则从列表消失，hits 跟着丢没
            # 关系——数据库那边 hit_count 在过期前已经持久化过了
            previous = {rule.rule_id: (rule.hits, rule.persisted_hits)
                       for rule in self._index.rules}
            for rule in index.rules:
                rule.hits, rule.persisted_hits = previous.get(rule.rule_id, (0, 0))
            self._index = index
        return self._index.total

    def _refresh_loop(self):
        while not self._stop_event.is_set():
            if self._stop_event.wait(self._refresh_interval):
                break
            try:
                self.refresh()
            except Exception as err:
                logger.error("======MuteFilter refresh loop error========\n%s", err)

    def stop(self):
        self._stop_event.set()

    def size(self):
        """当前生效的静默规则数"""
        return self._index.total

    def persist(self, now=None):
        """
        把内存里累加的 hits 刷进 syslog_mute_rule.hit_count

        和 BlacklistFilter.persist() 同一个模式：维护线程按固定间隔调，
        不在热路径上写库；增量 = 当前 hits - 上次刷过的值。

        write_db=False 时直接返回 0 —— 内存里的 hits 照常累加
        （stats() 还能看到命中了几次），只是不回写库

        :return: 更新的行数
        """
        if not self._write_db:
            return 0

        with self._lock:
            deltas = {}
            rules = []
            for rule in self._index.rules:
                delta = rule.hits - rule.persisted_hits
                if delta > 0:
                    deltas[rule.rule_id] = delta
                    rules.append(rule)
            for rule in rules:
                rule.persisted_hits = rule.hits

        if not deltas:
            return 0
        try:
            return self.db.updateMuteHits(deltas, now=now)
        except Exception as err:
            logger.error("======MuteFilter persist error========\n%s", err)
            return 0

    def rule_of(self, ip, event_code, alarm_object, now=None):
        """查命中的规则，没有返回 None。不带缓存 —— 判据含时间，缓存会过期"""
        now = int(now if now is not None else time.time())
        return self._index.match(str(ip or ""), str(event_code or ""),
                                 str(alarm_object or ""), now)

    # ---------------- 流水线入口 ----------------

    def handle(self, decision, now=None):
        """
        判一条 L7 决策要不要静默，原地填 muted / mute_rule_id / status

        不丢决策、不拦记录：muted 是记录上的状态，不是"要不要入库"的开关。
        被静默的告警照样入库，只是 L9 不发通知。

        **不看 L7 的 action/notify**：原始日志进来后按流程判断，遇到 mute
        匹配就打上 mute 状态。以前这里有一道 `if not notify: return` 的
        门槛，后果是同一个窗口段内重复的 raise（L7 判 ACTION_NONE，
        notify=False）压根不过正则 —— 人在前端新加一条规则，对已经开着
        的告警永远不生效（hit_count 一直是 0）。PSU_FAIL 窗口 7 天的
        场景下尤其明显：一次风扇故障后续所有日志都落在同一段里。

        命中后同时写三个字段：
            muted=1         L9 据此不发通知
            mute_rule_id    命中了哪条规则，排查时能追到源头
            status='4'      看板上的"已屏蔽"。人工屏蔽就是 mute，不区分
                            "人设的4"和"规则设的4"，统一这一个值

        判窗口用的是**这条告警的发生时间**（decision["ingest_ts"]），
        不是当前时刻：告警什么时候发生的，就按那一刻在不在窗口内算。
        判完就定了，窗口过了也不回头改这条告警 —— 窗口之后新产生的
        告警自然判出来 muted=0。

        state（open/clear）不参与判断 —— 它只影响展示标签，是"告警中/
        已恢复"的事实记录，和该不该通知无关。

        :return: decision
        """
        if not decision:
            return decision
        # 三个字段一定有值，不管走哪条分支 —— L9 不用判 key 在不在
        decision.setdefault("muted", False)
        decision.setdefault("mute_rule_id", 0)
        decision.setdefault("status", "")

        clock = int(now if now is not None else (decision.get("ingest_ts") or time.time()))
        rule = self.rule_of(decision.get("ip"), decision.get("event_code"),
                            decision.get("alarm_object"), now=clock)
        if rule is None:
            decision["muted"] = False
            decision["mute_rule_id"] = 0
            # 不命中时不写 status，让 L9 按自己的逻辑定（ignore 段='5'、
            # 其余='0'）。写成 '0' 会把 ignore 段的 '5' 冲掉
            return decision

        decision["muted"] = True
        decision["mute_rule_id"] = rule.rule_id
        decision["status"] = STATUS_MUTED
        # rule 是 self._index 里的同一个实例，直接累加
        rule.hits += 1
        with self._lock:
            self._muted_count += 1
        logger.info("静默 %s %s %s：命中 rule %s（%s）",
                    decision.get("ip"), decision.get("event_code"),
                    decision.get("alarm_object"), rule.rule_id, rule.descr)
        return decision

    def stats(self):
        with self._lock:
            return {"rules": self._index.total, "muted": self._muted_count}
