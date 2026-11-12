# -*- coding: utf-8 -*-
"""
L3 告警静默  [未实现]

只有 mute 一档，判据 ip_reg / event_code_reg / object_reg + 时间窗。

原来设计的三档收窄成一档：

    drop    确定是噪声的日志改用 syslog_black_list 在 L0.5 截掉。
            越早丢越省资源，那一层按 mnemonic 走 dict，比解析完再丢便宜
    depend  拓扑抑制依赖运行时的上游可达状态，不是静态规则能表达的，
            本轮不做
    mute    留下，就是本层

跑在 L5 之后，不在 L2.5 之后，三个原因：

    1. 判据凑不齐。object 要等 L1 抽、L4 聚合，告警状态要等 L5
    2. 冷路径。只有 L5 判定"需要告警"的聚合告警才过这一层 ——
       一次端口 down 是 3 条日志、1 个指纹、1 次 mute 判断，量级从
       日志条数掉到告警条数，差几个数量级。所以四个判据全用正则也不心疼
    3. 被静默的告警照样进聚合、进状态机、照样写 alarm_list，只是不发
       通知。割接完要能回看那段时间发生了什么

所以本层不丢事件、不拦记录。muted 是记录上的一个状态，不是"要不要入库"
的开关 —— 被静默的告警照样入库，只是 L6 不发通知。

这和 L2.5 的 action=ignore 是同一个模式（都不丢事件，只标记），区别是
ignore 是静态配置、长期生效，mute 是时间窗驱动、窗口过了自动恢复。

======================= 写入时序 =======================

新开的告警：本层判完 mute，muted 和 mute_rule_id 跟着其余字段一次
INSERT 进去（AlarmDB.addAlarm 的入参里就有这两个）。不要先 INSERT
muted=0 再 UPDATE 成 1 —— 中间那一瞬间看板轮询到会显示成"割接期间有条
没静默的告警"。

已经开着的告警：静默状态后来变了才用 AlarmDB.setAlarmMute()，两个方向
都要管：

    窗口开始  已开着的告警进了割接窗口     -> setAlarmMute(id, True, rule_id)
    窗口结束  窗口过了但告警还没好         -> setAlarmMute(id, False)

======================= 到期扫描 =======================

第二个方向必须靠定时扫描，不能等日志驱动：窗口到期是时间到了，不是来了
新日志。一个口在割接窗口里 down 了一直没好，窗口结束之后不会再有新日志
进管线（L5 看到已有活跃告警只累加，也不会重新判 mute），这条告警就会
永远 muted —— 割接结束了、故障还在，但没人收到通知。

所以本层除了 handle() 还要有个 sweep()：

    AlarmDB.getMutedOpenAlarms()  取还在告警中且被静默的
    -> 逐条重新判当前时刻还命不命中规则
    -> 不命中的 setAlarmMute(id, False)，并交给 L6 补发一次通知

补不补发通知要定：窗口结束时故障还在，值班应该被叫醒；但如果窗口里这条
告警已经恢复过又重开，补发的内容要以当前状态为准。实现时按"扫描时
state 仍是 open 就补发"处理。

muted 和 alarm_list.status=4（人工屏蔽）分开两个字段存，到期这一刻就是
原因：窗口过了只需要把 muted 改回 0，人工屏蔽该留着。塞进同一个字段，
这时候就得判断"这个 4 是人设的还是规则设的"，判不出来。

闪断和 mute 的交互：割接期间的 raise 照样进 L5 的闪断计数（L5 不反查
mute 规则，两层之间不加反向依赖），窗口内连续 3 次会升出一条 P1 的
IF_FLAP。那条 IF_FLAP 同样要过本层，命中同一条 mute 规则就一起被静默 ——
前提是规则的 event_code_reg 能盖住 IF_FLAP。只写了 ^IF_DOWN$ 的规则会
让它漏出来，schema.sql 的规则示例里写了这一点。

实现前置条件：
    1. syslog_mute_rule 表定稿（已建，见 sql/schema.sql）
    2. 变更工单的查询接口确定 —— 规则的数据来源是 central-server 的
       AlterationManageDB，人工配规则只是兜底
    3. L4 / L5 先落地，本层的输入是它们产出的聚合告警

======================= 接口 =======================

    handle(decision, now) -> 原地往 decision 上填 muted / mute_rule_id
    sweep(now)            -> [放出的告警]，维护线程定期调

入参是 L5 的决策（带 fingerprint / ip / event_code / alarm_object），
不是原始 event —— 本层在 L5 之后，拿到的已经是告警不是日志。
"""
import re
import time
import logging
import threading

from pipeline.attrs import severity_name

logger = logging.getLogger(__name__)

ACTION_PASS = "pass"
ACTION_MUTE = "mute"

# sweep() 放出来的决策用这个动作：告警早就在 alarm_list 里了，
# muted 这一列本层也改过了，L6 只需要补一条通知，不要再写库
ACTION_NOTIFY_ONLY = "notify_only"

# syslog_mute_rule 刷新间隔。比其他规则表短（那几张是 300s）：
# 变更窗口是分钟级的，工单一开就得尽快生效，等 5 分钟割接都开始了
DEFAULT_REFRESH = 60

# 到期扫描间隔。窗口结束要尽快恢复通知 —— 割接完了故障还在，
# 晚一分钟就是晚一分钟没人知道
DEFAULT_SWEEP_INTERVAL = 60


class MuteRule(object):
    """
    syslog_mute_rule 的一行，正则在加载时编译一次

    三个判据都空的规则匹配所有告警。这是合法用法（整站静默，比如全局
    演练），但危险，所以加载时打 warning —— 一个笔误就把全网告警静默了。
    """

    __slots__ = ("rule_id", "ip_reg", "event_code_reg", "object_reg",
                 "ip_pattern", "event_pattern", "object_pattern",
                 "start_time", "end_time", "descr")

    def __init__(self, row):
        self.rule_id = row.get("rule_id", 0)
        self.ip_pattern = str(row.get("ip_reg", "") or "").strip()
        self.event_pattern = str(row.get("event_code_reg", "") or "").strip()
        self.object_pattern = str(row.get("object_reg", "") or "").strip()
        self.start_time = self._to_int(row.get("start_time"), 0)
        # 空 end_time = 永久静默
        self.end_time = self._to_int(row.get("end_time"), 0)
        self.descr = str(row.get("descr", "") or "")

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

        数据库那边 getMuteRules() 已经按时间过滤过一遍，这里再判一次是为了
        sweep() —— 它要用内存里的规则判"现在还命不命中"，而规则是 60s 前
        加载的，窗口可能已经过了
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
    L3 静默

    handle() 判一条决策要不要静默，sweep() 把窗口过了的放出来。
    和其他规则层一样定时刷新，索引整体替换，读路径不加锁。
    """

    def __init__(self, refresh_interval=DEFAULT_REFRESH, db=None):
        """
        :param refresh_interval: syslog_mute_rule 刷新间隔（秒），0=只加载一次
        :param db: 数据源，由 db.get_alarm_db() 注入
        """
        self._refresh_interval = int(refresh_interval)
        self._db = db
        self._index = MuteIndex([])
        self._version = 0
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._refresh_thread = None
        self._muted_count = 0
        self._released_count = 0

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

        with self._lock:
            self._version += 1
            self._index = MuteIndex(rows, version=self._version)
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

    def rule_of(self, ip, event_code, alarm_object, now=None):
        """查命中的规则，没有返回 None。不带缓存 —— 判据含时间，缓存会过期"""
        now = int(now if now is not None else time.time())
        return self._index.match(str(ip or ""), str(event_code or ""),
                                 str(alarm_object or ""), now)

    # ---------------- 流水线入口 ----------------

    def handle(self, decision, now=None):
        """
        判一条 L5 决策要不要静默，原地填 muted / mute_rule_id

        不丢决策、不拦记录：muted 是记录上的状态，不是"要不要入库"的开关。
        被静默的告警照样入库，只是 L6 不发通知。

        L5 说不用通知的（action=none/ignore）直接跳过，不白跑正则

        :return: decision
        """
        if not decision:
            return decision
        # 两个字段一定有值，不管走哪条分支 —— L6 不用判 key 在不在
        decision.setdefault("muted", False)
        decision.setdefault("mute_rule_id", 0)
        if not decision.get("notify"):
            return decision

        clock = int(now if now is not None else (decision.get("ingest_ts") or time.time()))
        rule = self.rule_of(decision.get("ip"), decision.get("event_code"),
                            decision.get("alarm_object"), now=clock)
        if rule is None:
            decision["muted"] = False
            decision["mute_rule_id"] = 0
            return decision

        decision["muted"] = True
        decision["mute_rule_id"] = rule.rule_id
        with self._lock:
            self._muted_count += 1
        logger.info("静默 %s %s %s：命中 rule %s（%s）",
                    decision.get("ip"), decision.get("event_code"),
                    decision.get("alarm_object"), rule.rule_id, rule.descr)
        return decision

    def sweep(self, now=None):
        """
        窗口到期：把还在告警中但已经不命中任何规则的放出来

        必须定时扫，不能等日志驱动。窗口到期是时间到了，不是来了新日志 ——
        一个口在割接窗口里 down 了一直没好，窗口结束之后不会再有新日志进
        管线（L5 看到已有活跃告警只累加，也不会重新判 mute），这条告警就
        永远 muted，割接结束了、故障还在，但没人收到通知。

        扫描时 state 仍是 open 就补发通知：窗口结束故障还在，值班应该被叫醒。

        :return: [{alarm_id, fingerprint, ip, event_code, alarm_object,
                   severity, notify}]，交给 L6 补发通知
        """
        now = int(now if now is not None else time.time())
        try:
            rows = self.db.getMutedOpenAlarms()
        except Exception as err:
            logger.error("======MuteFilter sweep error========\n%s", err)
            return []

        released = []
        for row in rows or []:
            # keyword 列存的是 event_code，沿用 central-server 的老结构
            rule = self.rule_of(row.get("ip"), row.get("keyword"),
                                row.get("alarm_object"), now=now)
            if rule is not None:
                # 还在窗口内（或命中了另一条规则），继续静默
                continue

            alarm_id = row.get("alarm_id")
            try:
                result = self.db.setAlarmMute(alarm_id, False)
            except Exception as err:
                logger.error("======MuteFilter setAlarmMute error========\n%s", err)
                continue
            if result == "failed":
                continue

            released.append({
                # 只补通知，不再动 alarm_list —— muted 这一列上面
                # 已经改过了，别让 L6 拿默认值把 last_seen/counter 冲掉
                "action": ACTION_NOTIFY_ONLY,
                "alarm_id": alarm_id,
                "fingerprint": row.get("fingerprint", ""),
                "ip": row.get("ip", ""),
                "hostname": "",
                "event_code": row.get("keyword", ""),
                "alarm_object": row.get("alarm_object", ""),
                "severity": row.get("severity", 3),
                "severity_name": severity_name(row.get("severity", 3)),
                "counter": row.get("counter", 0),
                "first_seen": row.get("first_seen", ""),
                "last_seen": row.get("last_seen", ""),
                "flapping": row.get("flapping", 0),
                "message": "",
                "ingest_ts": now,
                "muted": False,
                "mute_rule_id": 0,
                "notify": True,
                "reason": "mute_expired",
            })

        if released:
            with self._lock:
                self._released_count += len(released)
            logger.warning("静默窗口到期，%s 条告警恢复通知（故障仍未恢复）",
                           len(released))
        return released

    def stats(self):
        with self._lock:
            return {"rules": self._index.total, "muted": self._muted_count,
                    "released": self._released_count}
