# -*- coding: utf-8 -*-
"""
L7 段状态机

**一个窗口段 = alarm_list 的一行。** 本层只做一件事：把 L6 算好的段
映射到一行告警上，决定这一条事件是"插新行"、"改这一行"还是"什么都不做"。

======================= 段就是告警 =======================

L6 给的 (fingerprint, first_seen) 就是段的身份。本层给每个指纹记住
当前段的起点和它对应的 alarm_id：

    first_seen 和记住的不一样  ->  新段，alarm_id 清零，下一条够格的插新行
    一样                        ->  同段，改那一行

同一段内不管来多少条日志、raise 还是 clear，alarm_list 永远只有一行。
clear **不再判断"有没有活跃告警"**，它只是在这一行上盖恢复标签。

这是和老版本最大的区别。老版本的判据是"有没有活跃告警"，于是一条恢复
日志被设备发两遍时，第二条找不到活跃告警，被当成"视野外恢复"另插一行；
华为一次口 up 打 hwPortUp + linkDown_clear 两条、都归 IF_UP，同样多插
一行。新模型下这两种都是"同一段内的重复 clear"，返回 ACTION_NONE。

窗口是**纯时间窗，不跟着故障状态延长**。一个口 down 了两小时才 up，
那条 IF_UP 落在新段里，自己是一行"生而恢复"的记录，上一段那一行保持
open —— 它的时间范围已经定稿，不回头去改。

======================= 动作 =======================

    本段还没插行（alarm_id = 0）
        count < threshold       ACTION_NONE    只有 alarm_log，看板上没有
        count >= threshold      ACTION_RAISE   插一行。clear 事件插出来的
                                               行生而恢复（state=clear）
    本段已有行
        clear 且行是 open       ACTION_CLEAR   盖恢复标签
        clear 且行已经 clear    ACTION_NONE    重复恢复在这里被吃掉
        raise 且行是 clear      ACTION_REOPEN  翻回 open，清掉恢复时间
        raise 且级别变了        ACTION_UPDATE
        raise 且什么都没变      ACTION_NONE    counter 靠 L9 定期同步

一段内 down/up/down/up 反复抖：始终是那一行，counter 一路涨，行的状态
跟着最后一条事件走。闪断判定（窗口内 N 次新开告警 -> 升级成 IF_FLAP、
禁止自动恢复、需人工确认）整套去掉了 —— 反复抖动现在靠段本身合并，
不升级级别、不换事件码。syslog_alarm_state 的 flapping / raise_count
两列保留但恒写 0。

======================= 阈值 =======================

threshold 留着，判的是**段内日志条数**（L6 的 count），不自己数：
MAC_FLAP 配 600/3，攒到第 3 条才在 alarm_list 里出现，虚机迁移造成的
偶发单次 MAC 迁移不报。绝大多数事件码 threshold=1，等于命中指纹就开。

和窗口一样取**故障码**那一行的值（L5 补的 segment_threshold）：段是故障码
的段，插不插行该按故障码的阈值判，不按恢复码自己配的值。

======================= stateless =======================

MAC 漂移、配置变更、登录失败没有恢复日志，靠 sweep() 定时扫：段静默
超过 silence 就把那一行盖成恢复。必须定时扫，不能等日志驱动 —— 没有
日志来正是恢复的条件。

raise 类不在 sweep() 里关，它们等显式的恢复事件。一个口 down 了两小时
没好，那一行就该一直 open。

======================= ignore =======================

L5 的定级规则配 action=ignore 产生 mode=ignore：照样按段落 alarm_list
（status='5'，人工操作选不到这个值），但不发通知、不进开/关的生命周期。
落库是为了避免"alarm_log 有记录但看板查不到"的孤儿数据。

ignore 和非 ignore 之间切换（定级规则改过）按**开新段**处理：同一段内
不会一半 ignore 一半不 ignore，省掉"status 5 怎么翻回 0"这类判断。
正常情况下也切不起来 —— L5 的 _inherit_ignore 保证恢复事件跟着故障
事件一起 ignore。

======================= 状态存哪 =======================

内存，不引入 Redis：worker 按 IP hash 分区，同一设备的日志固定落到同一个
worker，所以同一指纹不会跨 worker。但 Runner 是各 worker 共享的，所以
状态字典仍要加锁。

重启靠 syslog_alarm_state 回放（restore()）。**已经盖过恢复标签的段也要
回放** —— 不回放的话重启后段内再来一条重复的恢复日志，本层认不出"本段
已经有行了"，又会另插一行。多实例部署时再上 Redis。
"""
import time
import logging
import threading

from pipeline.l5_attrs import severity_name

logger = logging.getLogger(__name__)

# syslog_event.state 的四个取值。raise 和 stateless 在本层走同一条路径，
# 区别只在怎么恢复：raise 等显式的 clear 事件，stateless 等 sweep() 静默到期
MODE_RAISE = "raise"
MODE_CLEAR = "clear"
MODE_STATELESS = "stateless"
MODE_IGNORE = "ignore"

# 本层产出的动作
ACTION_NONE = "none"            # 什么都不用做（没到阈值、累加、重复恢复）
ACTION_RAISE = "raise"          # 本段第一行，insert
ACTION_REOPEN = "reopen"        # 同段内恢复之后又来故障，翻回 open
ACTION_UPDATE = "update"        # 同段内级别变了
ACTION_CLEAR = "clear"          # 盖恢复标签

# 要通知的动作。ignore 段不在这里判——它的 notify 由 _decide() 直接压成
# False（不是被 mute 压住，是这类事件本来就不该发通知）
NOTIFY_ACTIONS = (ACTION_RAISE, ACTION_REOPEN, ACTION_UPDATE, ACTION_CLEAR)
# 要落库的动作。ACTION_NONE 不落库——它就是"这一行没有新信息"，
# L6 已经写了 alarm_log
WRITE_ACTIONS = NOTIFY_ACTIONS

# alarm_list.state 的三个取值。idle 是 ignore 段专用：它不是活跃告警，
# 也没有恢复的那一刻
ROW_OPEN = "open"
ROW_CLEAR = "clear"
ROW_IDLE = "idle"

DEFAULT_SILENCE = 600           # stateless 段静默多久自动盖恢复
# 段状态在内存里留多久没动静就清掉。实际用的是
# max(这个值, 段的 window_sec) —— 清早了段的身份就断了，同一段会被
# 当成新段再插一行，而 window_sec 最长的 CERT_EXPIRED 是 86400
DEFAULT_STATE_TTL = 7200
# restore() 往回捞多久的段。比最长的 window_sec（86400）留一点余量，
# 更早的段无论如何都已经切掉了，回放它只会让内存里多一批死状态
DEFAULT_RESTORE_LOOKBACK = 90000
# 回放时给段的 window_sec 兜底值。表里没有这一列（它来自 syslog_event，
# 由 L5 带在事件上），而 purge() 的 TTL 要用它。
#
# 必须取现网最大的 window_sec（CERT_EXPIRED / TCAM_THRESHOLD 是 86400），
# 不能用 0 —— 那样 TTL 退回 state_ttl（7200），一个 86400 窗口的段重启后
# 静默两小时就被清掉，下一条日志会被当成新段再插一行。
# 宁可多占一会儿内存：L6 那边一段最长也就活到 max_life，超过这个值的段
# 无论如何都已经切了
RESTORED_WINDOW_FALLBACK = 86400


class Segment(object):
    """
    一个指纹的当前窗口段，对应 syslog_alarm_state 的一行

    start 就是段的身份（L6 的 first_seen）。alarm_id 是这个段在
    alarm_list 里那一行；为 0 表示本段还没插行（没到阈值，或者上次
    insert 失败了）。

    severity 不再分 severity / base_severity 两个值 —— 那是闪断临时提档
    留下的，闪断去掉之后两者恒等。表里两列都保留，落库时写同一个值。
    """

    __slots__ = ("fingerprint", "ip", "event_code", "alarm_object", "mode",
                 "start", "last_seen", "counter", "clear_count", "severity",
                 "row_severity", "alarm_id", "row_state", "window_sec")

    def __init__(self, fingerprint, ip="", event_code="", alarm_object="",
                 mode=MODE_RAISE, severity=3, start=0, window_sec=0):
        self.fingerprint = fingerprint
        self.ip = ip
        self.event_code = event_code
        self.alarm_object = alarm_object
        self.mode = mode
        self.severity = int(severity)
        # alarm_list 那一行当前写着的级别。和 severity 分开存才能判出
        # "级别变了"——severity 每条事件都会被刷成最新值，拿它和自己比
        # 永远相等，于是定级规则改过也不会让 L9 去改那一行
        self.row_severity = 0
        self.start = int(start)
        self.last_seen = int(start)
        self.counter = 0
        self.clear_count = 0
        self.alarm_id = 0
        self.row_state = ""        # 空=本段还没插行
        self.window_sec = int(window_sec)

    def has_row(self):
        """本段在 alarm_list 里有行没有。判的是 alarm_id 不是 row_state"""
        return self.alarm_id > 0

    def renew(self, start):
        """换到新段：身份、计数、行的归属全部归位"""
        self.start = int(start)
        self.last_seen = int(start)
        self.counter = 0
        self.clear_count = 0
        self.alarm_id = 0
        self.row_state = ""
        self.row_severity = 0

    def as_row(self, now):
        """
        落 syslog_alarm_state 的一行

        raise_count / flapping / ignore_* 五列是闪断判定和 ignore 独立
        计数留下的，功能去掉了但列保留（NOT NULL，现网不 ALTER），
        恒写 0 和空串。别在这几列上做判断
        """
        return {
            "fingerprint": self.fingerprint,
            "ip": self.ip,
            "event_code": self.event_code,
            "alarm_object": self.alarm_object,
            "mode": self.mode,
            # 存行的状态（open/clear/idle），不是"段还在不在" ——
            # 段的身份是 first_seen，它自己就在下一列里
            "state": self.row_state or ROW_IDLE,
            "severity": self.severity,
            # base_severity 这一列原来存"闪断前的原始级别"，闪断去掉之后
            # 借它存 row_severity（alarm_list 那一行写着的级别）——
            # 不然重启回放之后判不出级别变没变，会白更新一次
            "base_severity": self.row_severity,
            "first_seen": str(self.start or ""),
            "last_seen": str(self.last_seen or ""),
            "counter": self.counter,
            "clear_count": self.clear_count,
            "alarm_id": self.alarm_id,
            "raise_count": 0,
            "flapping": 0,
            "ignore_counter": 0,
            "ignore_first_seen": "",
            "ignore_alarm_id": 0,
            "updated_time": str(int(now)),
        }

    @classmethod
    def from_row(cls, row):
        """
        启动回放用。查不出来的字段给默认值，不让一行坏数据挡住回放

        window_sec 不在表里（它来自 syslog_event），先给
        RESTORED_WINDOW_FALLBACK，下一条事件进来时 _locate() 会按真值改掉
        """
        def to_int(value, default=0):
            try:
                return int(value)
            except (TypeError, ValueError):
                return default

        segment = cls(row.get("fingerprint", ""), ip=row.get("ip", ""),
                      event_code=row.get("event_code", ""),
                      alarm_object=row.get("alarm_object", ""),
                      mode=row.get("mode") or MODE_RAISE,
                      severity=to_int(row.get("severity"), 3),
                      start=to_int(row.get("first_seen")),
                      window_sec=RESTORED_WINDOW_FALLBACK)
        segment.last_seen = to_int(row.get("last_seen"), segment.start)
        segment.counter = to_int(row.get("counter"))
        segment.clear_count = to_int(row.get("clear_count"))
        segment.alarm_id = to_int(row.get("alarm_id"))
        segment.row_severity = to_int(row.get("base_severity"), segment.severity)
        state = row.get("state") or ""
        # alarm_id=0 的段在 alarm_list 里没有行，row_state 必须跟着空 ——
        # 留个 idle 在那里会让 has_row() 和 row_state 对不上
        segment.row_state = state if segment.alarm_id > 0 else ""
        return segment


class StateMachine(object):
    """
    L7 段状态机

    handle() 热路径，sweep() / persist() / purge() 由维护线程调。
    worker 共享同一个实例，状态字典加锁。
    """

    def __init__(self, silence=DEFAULT_SILENCE, state_ttl=DEFAULT_STATE_TTL,
                 restore_lookback=DEFAULT_RESTORE_LOOKBACK, db=None,
                 write_db=True):
        """
        :param silence:          stateless 段静默多久算恢复
        :param state_ttl:        内存里的段状态保留多久
        :param restore_lookback: 启动回放往回捞多久的段
        :param db:               数据源，由 db.get_alarm_db() 注入
        :param write_db:         False=只读不写，persist() 不回写
                                 syslog_alarm_state。段状态照常在内存里
                                 维护（动作判定、阈值、恢复全都正常），
                                 只是进程退出就丢 —— 调试脚本本来就是
                                 单次跑完就退，不需要持久化
        """
        self._silence = int(silence)
        self._state_ttl = int(state_ttl)
        self._restore_lookback = int(restore_lookback)
        self._db = db
        self._write_db = bool(write_db)

        self._segments = {}        # fingerprint -> Segment
        self._dirty = set()        # 待落库的指纹
        self._lock = threading.RLock()

    @property
    def db(self):
        if self._db is None:
            from db import get_alarm_db
            self._db = get_alarm_db()
        return self._db

    # ---------------- 热路径 ----------------

    def handle(self, event, now=None):
        """
        处理一条聚合后的事件，返回决策

        :param event: L6 的输出（带 fingerprint / first_seen / count）
        :return: 决策 dict。action=none 时 L8 和 L9 都不用管它
        """
        clock = int(now if now is not None else (event.get("ingest_ts") or time.time()))
        fingerprint = event.get("fingerprint") or ""
        if not fingerprint:
            # L6 没算出指纹，本层没法定位段。L6 那边已经打过 error
            return self._decide(event, ACTION_NONE, None, clock)

        with self._lock:
            segment = self._locate(event, clock)
            action = self._advance(segment, event, clock)
            # ACTION_NONE 也要标 dirty：它多半是"同一行只累加"，counter 和
            # last_seen 都变了。不标的话这些变化只留在内存里，重启后
            # counter 回到上次落库的值。dirty 是 set，一个指纹刷一万条日志
            # 也只有一个条目，persist 一轮写一次
            self._dirty.add(fingerprint)
            return self._decide(event, action, segment, clock)

    def _locate(self, event, now):
        """
        找到这条事件所属的段，必要时开新段

        段的身份是 L6 的 first_seen。L6 没给（异常路径）就退回用 now，
        那样每条都是新段，至少不会把两次故障算成一段
        """
        fingerprint = event["fingerprint"]
        mode = str(event.get("state") or MODE_STATELESS).lower()
        start = self._int(event.get("first_seen"), now)

        segment = self._segments.get(fingerprint)
        if segment is None:
            segment = Segment(
                fingerprint, ip=event.get("ip", ""),
                # event_code 取 raise_code：恢复事件的指纹是 L6 按 raise_code
                # 换算的（IF_UP 落到 IF_DOWN 的指纹上），存 IF_UP 就出现
                # "指纹是 IF_DOWN 的、event_code 却是 IF_UP"的自相矛盾行
                event_code=event.get("raise_code") or event.get("event_code", ""),
                alarm_object=event.get("alarm_object", ""),
                mode=mode, severity=self._int(event.get("severity"), 3),
                start=start, window_sec=self._int(event.get("window_sec"), 0))
            self._segments[fingerprint] = segment
            return segment

        # ignore 和非 ignore 之间切换（定级规则改过）按开新段处理：
        # 同一行既是 status=5 又要发通知说不清，分成两行各自干净
        ignore_switched = (segment.mode == MODE_IGNORE) != (mode == MODE_IGNORE)
        if segment.start != start or ignore_switched:
            segment.renew(start)
        segment.window_sec = self._int(event.get("window_sec"), segment.window_sec)
        return segment

    def _advance(self, segment, event, now):
        """按模式推进这一段，返回动作"""
        mode = str(event.get("state") or MODE_STATELESS).lower()
        segment.mode = mode
        segment.last_seen = max(segment.last_seen, now)
        segment.severity = self._int(event.get("severity"), segment.severity)
        # counter 直接用 L6 的段内条数，不自己数：段和告警现在是一对一，
        # 两边各数一份只会出现对不上的情况
        segment.counter = self._int(event.get("count"), segment.counter + 1)

        threshold = self._threshold(event)
        if mode == MODE_IGNORE:
            return self._on_ignore(segment, threshold)
        if mode == MODE_CLEAR:
            return self._on_clear(segment, threshold)
        return self._on_raise(segment, threshold)

    # ---------------- 三条路径 ----------------

    def _on_raise(self, segment, threshold):
        """
        故障事件（raise / stateless）

        判据是"本段有没有行"，不是"有没有活跃告警"。同段内恢复之后又来
        故障，翻回 open 就行 —— 不插新行，所以一段内反复抖只有一行
        """
        if not segment.has_row():
            if segment.counter < threshold:
                # 阈值兼做降噪：MAC_FLAP 配 3，虚机迁移造成的偶发单次不报
                return ACTION_NONE
            segment.row_state = ROW_OPEN
            segment.row_severity = segment.severity
            return ACTION_RAISE

        if segment.row_state == ROW_CLEAR:
            segment.row_state = ROW_OPEN
            segment.row_severity = segment.severity
            return ACTION_REOPEN

        # 已经 open。级别变了（定级规则改过）要让 L9 更新一下，
        # 否则什么都没变，counter 靠 L9 的 sync_counters 定期刷
        if segment.severity != segment.row_severity:
            segment.row_severity = segment.severity
            return ACTION_UPDATE
        return ACTION_NONE

    def _on_clear(self, segment, threshold):
        """
        恢复事件

        **不判断有没有活跃告警。** 本段有行就盖恢复标签，没行就插一行
        "生而恢复"的记录 —— 后者是故障发生在监控视野之外（初次上线 /
        重建库 / 进程停机期间，或者 down 了两小时才 up，那条 down 在
        上一段里）。syslog 只在状态变化时发，设备不会为了我们重发一遍
        down，所以这条 up 就是唯一的线索。

        同段内重复的恢复（设备把一条 TEMP_OK 发两遍、华为一次口 up 打
        hwPortUp + linkDown_clear 两条）在这里被吃掉：行已经是 clear 了，
        只累加 counter，不插行、不重复通知
        """
        if not segment.has_row():
            if segment.counter < threshold:
                return ACTION_NONE
            segment.row_state = ROW_CLEAR
            segment.row_severity = segment.severity
            segment.clear_count += 1
            return ACTION_RAISE

        if segment.row_state == ROW_CLEAR:
            return ACTION_NONE

        segment.row_state = ROW_CLEAR
        segment.row_severity = segment.severity
        segment.clear_count += 1
        return ACTION_CLEAR

    def _on_ignore(self, segment, threshold):
        """
        L5 定级规则判定不告警

        照样按段落 alarm_list（status='5'），但不发通知、不进开/关的
        生命周期。row_state 一直是 idle —— 它不是活跃告警，没有要恢复的
        那一刻，sweep() 也不会碰它（只扫 stateless 且 open 的）
        """
        if not segment.has_row():
            if segment.counter < threshold:
                return ACTION_NONE
            segment.row_state = ROW_IDLE
            segment.row_severity = segment.severity
            return ACTION_RAISE
        return ACTION_NONE

    @staticmethod
    def _threshold(event):
        """
        段内攒够这么多条才在 alarm_list 里出现。syslog_event.threshold

        和窗口一样用 L5 补的 segment_threshold：段是故障码的段，
        插不插行该按故障码那一行的阈值判，不按恢复码自己配的值
        """
        try:
            value = int(event.get("segment_threshold")
                        or event.get("threshold") or 1)
        except (TypeError, ValueError):
            return 1
        return value if value > 0 else 1

    @staticmethod
    def _int(value, default):
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    # ---------------- 决策 ----------------

    def _decide(self, event, action, segment, now):
        """
        拼决策 dict 交给 L8

        muted / mute_rule_id 留空位，L8 填。L9 据此一次写 alarm_list，
        不是先写再改 —— 先写 muted=0 再 UPDATE 成 1 的话，中间那一瞬间
        看板轮询到会显示成"割接期间有条没静默的告警"
        """
        ignored = str(event.get("state") or "").lower() == MODE_IGNORE
        decision = {
            "action": action,
            # ignore 段永远不通知：不是被 mute 压住，是这类事件本来就不该
            # 发通知。但它照样落库（见 WRITE_ACTIONS），所以这两个判断
            # 不能共用一个字段
            "notify": action in NOTIFY_ACTIONS and not ignored,
            "write": action in WRITE_ACTIONS,
            "ignored": ignored,
            "fingerprint": event.get("fingerprint", ""),
            "ip": event.get("ip", ""),
            "hostname": event.get("hostname", ""),
            # L4 富化的结果，L9 落 alarm_list 要用，排查时能直接看出
            # 设备厂商/型号，不用现查 devices 表
            "vendor": event.get("vendor", ""),
            "hardware": event.get("hardware", ""),
            "alarm_object": event.get("alarm_object", ""),
            # 同样是 L4 富化结果：接口对象才会有值，其它对象类型是空串
            "object_name": event.get("object_name", ""),
            "object_alias": event.get("object_alias", ""),
            "message": event.get("message", ""),
            "ingest_ts": now,
            # L8 填
            "muted": False,
            "mute_rule_id": 0,
        }

        if segment is None:
            decision.update({
                "event_code": event.get("event_code", ""),
                "severity": event.get("severity", 3),
                "severity_name": severity_name(event.get("severity", 3)),
                "state": ROW_IDLE,
                "counter": event.get("count", 1),
                "first_seen": now,
                "last_seen": now,
                "clear_time": 0,
                "alarm_id": 0,
            })
            return decision

        row_state = segment.row_state or ROW_IDLE
        decision.update({
            # 恢复事件也写故障码（IF_UP 的行写 IF_DOWN）：这一行代表的是
            # 那条故障告警，不是那条恢复日志
            "event_code": segment.event_code,
            "severity": segment.severity,
            "severity_name": severity_name(segment.severity),
            "state": row_state,
            "counter": segment.counter,
            "first_seen": segment.start or now,
            "last_seen": segment.last_seen or now,
            # 盖了恢复标签就有恢复时间；reopen 要把它清空（L9 写空串，
            # 看板按"空=未恢复"判）
            "clear_time": now if row_state == ROW_CLEAR else 0,
            "clear_count": segment.clear_count,
            "alarm_id": segment.alarm_id,
        })
        return decision

    def bind_alarm(self, fingerprint, alarm_id):
        """
        L9 insert 之后把 alarm_id 回填进段状态，本段后面的事件要用它定位行

        :return: True=绑上了
        """
        with self._lock:
            segment = self._segments.get(fingerprint)
            if segment is None:
                return False
            segment.alarm_id = int(alarm_id)
            self._dirty.add(fingerprint)
        return True

    # ---------------- 周期维护 ----------------

    def sweep(self, now=None):
        """
        stateless 段的自动恢复：静默超过 silence 就把那一行盖成恢复

        必须定时扫，不能等日志驱动 —— 没有日志来正是恢复的条件。
        raise 类不在这里关，它们等显式的恢复事件：一个口 down 了两小时
        没好，那一行就该一直 open。

        :return: [决策]，L8/L9 照常处理
        """
        now = int(now if now is not None else time.time())
        decisions = []
        with self._lock:
            for segment in self._segments.values():
                if segment.mode != MODE_STATELESS or segment.row_state != ROW_OPEN:
                    continue
                if now - segment.last_seen <= self._silence:
                    continue
                segment.row_state = ROW_CLEAR
                segment.clear_count += 1
                self._dirty.add(segment.fingerprint)
                if not segment.has_row():
                    # 这一段的 insert 失败过，alarm_list 里没有行可盖。
                    # 内存状态照样推进，但没有决策可发
                    continue
                decisions.append({
                    "action": ACTION_CLEAR,
                    "notify": True,
                    "write": True,
                    "ignored": False,
                    "fingerprint": segment.fingerprint,
                    "ip": segment.ip,
                    "hostname": "",
                    "event_code": segment.event_code,
                    "alarm_object": segment.alarm_object,
                    "message": "",
                    "severity": segment.severity,
                    "severity_name": severity_name(segment.severity),
                    "state": ROW_CLEAR,
                    # 传 segment.counter，不是 0 —— 它是这一行最终"有几条
                    # 日志支撑"，写死 0 的话 L9 会拿这个 0 把 alarm_list
                    # 的 counter 冲掉，看板上变成"0 条"
                    "counter": segment.counter,
                    "first_seen": segment.start,
                    "last_seen": segment.last_seen,
                    "clear_time": now,
                    "clear_count": segment.clear_count,
                    "alarm_id": segment.alarm_id,
                    "ingest_ts": now,
                    "muted": False,
                    "mute_rule_id": 0,
                })
        if decisions:
            logger.info("stateless 静默恢复 %s 条", len(decisions))
        return decisions

    def persist(self, now=None):
        """
        把变动过的段状态落 syslog_alarm_state。进程重启后靠它接着算

        只落 dirty 的 —— 全量 upsert 在指纹多的时候是白写。
        落库失败的留在 dirty 里，下一轮再试

        write_db=False 时直接返回 0，dirty 集合也不清：留着不影响内存
        判定（dirty 只是"该落库的清单"），而且万一调试中途想改成写库
        也不会丢掉之前的变更

        :return: 落库成功的条数
        """
        if not self._write_db:
            return 0

        now = int(now if now is not None else time.time())
        with self._lock:
            if not self._dirty:
                return 0
            pending = [(fp, self._segments[fp].as_row(now))
                       for fp in self._dirty if fp in self._segments]
            self._dirty = set()

        failed = 0
        for fingerprint, row in pending:
            try:
                result = self.db.upsertAlarmState(row)
            except Exception as err:
                logger.error("======StateMachine persist error========\n%s", err)
                result = "failed"
            if result == "failed":
                failed += 1
                with self._lock:
                    self._dirty.add(fingerprint)
        return len(pending) - failed

    def restore(self, limit=5000, now=None):
        """
        启动回放最近的窗口段

        **不只回放 open 的。** 段的身份就是行的身份，已经盖过恢复标签的
        段同样要回放 —— 不回放的话重启后段内再来一条重复的恢复日志，
        本层认不出"本段已经有行了"，又会另插一行。

        :return: 回放的段数
        """
        now = int(now if now is not None else time.time())
        since = now - self._restore_lookback
        try:
            rows = self.db.getAlarmStatesSince(since, limit=limit)
        except Exception as err:
            logger.error("======StateMachine restore error========\n%s", err)
            return 0

        restored = 0
        with self._lock:
            for row in rows or []:
                fingerprint = row.get("fingerprint")
                if not fingerprint or fingerprint in self._segments:
                    continue
                segment = Segment.from_row(row)
                if not segment.start:
                    # 没有段起点就没有身份，回放它只会让下一条事件
                    # 误判成同一段
                    continue
                self._segments[fingerprint] = segment
                restored += 1
        if restored:
            logger.info("StateMachine 回放 %s 个窗口段", restored)
        return restored

    def purge(self, now=None):
        """
        清理长期没动静的段状态

        TTL 取 max(state_ttl, 段的 window_sec)：清早了段的身份就断了，
        同一段的下一条日志会被当成新段再插一行。window_sec 最长的
        CERT_EXPIRED 是 86400，比默认的 state_ttl 大一个量级。

        活跃告警（row_state=open）不清 —— 清了之后这个段再来恢复事件
        就找不到行，会另插一行"生而恢复"的记录

        :return: 清掉的段数
        """
        now = int(now if now is not None else time.time())
        with self._lock:
            expired = [key for key, segment in self._segments.items()
                       if segment.row_state != ROW_OPEN
                       and key not in self._dirty
                       and now - segment.last_seen > max(self._state_ttl,
                                                         segment.window_sec)]
            for key in expired:
                self._segments.pop(key, None)
        return len(expired)

    def current_snapshots(self):
        """
        所有已经有行的段的 (fingerprint, alarm_id, counter, last_seen,
        severity, state)

        给 L9 同步 alarm_list.counter 用。段内的后续日志多半是 ACTION_NONE
        （不重复通知，这是对的），所以 alarm_list 的 counter 会停在插行
        那一刻的值 —— 一次端口 down 三条日志，看板上显示 1。靠维护线程
        定期把这里的值刷过去补齐。

        已恢复的段也给：它可能在恢复之后又收到重复的恢复日志，counter
        还在涨。L9 按 state 决定要不要把"已处理"翻回"待处理"
        """
        with self._lock:
            return [{
                "fingerprint": segment.fingerprint,
                "alarm_id": segment.alarm_id,
                "counter": segment.counter,
                "last_seen": segment.last_seen,
                "severity": segment.severity,
                "state": segment.row_state,
            } for segment in self._segments.values() if segment.has_row()]

    def stats(self):
        with self._lock:
            opened = sum(1 for s in self._segments.values()
                         if s.row_state == ROW_OPEN)
            rows = sum(1 for s in self._segments.values() if s.has_row())
            return {"segments": len(self._segments), "open": opened,
                    "rows": rows, "dirty": len(self._dirty)}

    def size(self):
        return len(self._segments)
