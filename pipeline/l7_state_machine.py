# -*- coding: utf-8 -*-
"""
L7 状态机

现有链路完全缺失的一级，也是日志告警能不能用起来的关键。

本层决定"要不要产生一条告警动作"，不决定"要不要通知"（那是 L8）、
也不落 alarm_list（那是 L9 一次写）。产出一个决策 dict，L8 往上盖 mute
标记，L9 据此落库发通知。

状态的唯一来源是 syslog_alarm_state（内存 + 启动回放），不读 alarm_list ——
重启那一瞬间两者可能不一致（状态表回放了，alarm_list 的行是上次进程写的），
以状态表为准。

======================= 有状态事件 =======================

state 取 raise / clear：

    raise 且无活跃告警   -> 攒到 threshold 就开告警
    raise 且已有活跃告警 -> 只累加 count
    clear                -> 按同一指纹关掉活跃告警

指纹含 object，所以 BGP_UP peer=A 只会关 A 的告警，不会误关同台设备上
B 邻居的告警。恢复事件的指纹由 L6 按 raise_code 算好，这里拿到的已经是
故障事件的指纹。

不要读 L6 的 is_first 来决定开不开告警。max_life 切新段时它是 True，
但一个口持续 down 一小时应该是一条告警不是两条 —— 判据是"有没有活跃告警"。

======================= 无状态事件 =======================

MAC 漂移、配置变更、登录失败没有恢复日志，用窗口计数触发，窗口内不再
出现即自动恢复：

    MAC_FLAP: 同指纹 10 分钟内 >= 3 次 -> 告警

这个门槛同时起降噪作用，虚机漂移造成的偶发单次 MAC 迁移不报。

"窗口内不再出现即恢复"必须靠定时扫描，不能等日志驱动 —— 没有日志来
正是恢复的条件。sweep() 负责这件事，维护线程定期调。

======================= 闪断识别 =======================

同指纹 flap_window（默认 1800s）内 >= flap_threshold（默认 3）次
「新开告警」-> 升级，severity 提一档，event_code 换成 IF_FLAP。

计数点在"无活跃告警 -> 开告警"这一跳，不在 L6 的日志条数上。一次端口
down 会产生 2~3 条同指纹日志，按日志条数计的话一次 down 就能凑满 3 次，
当场误报成闪断。

升级在原指纹上做，不换指纹：指纹是 md5(ip|event_code|object)，换了就是
另一条告警，原来那条还挂着关不掉。所以 flapping 置位 + 提级别 + 显示用
的 event_code 改成 IF_FLAP，指纹不动。

闪断禁止自动恢复，需人工确认才关闭（flapping=1 时 clear 不关告警，
只记一次 clear_count）。

**闪断计数不看 mute。** 割接期间的 raise 照样进计数，窗口内连续 3 次
照样升出 IF_FLAP —— 本层不反查 L8 的静默规则，两层之间不加反向依赖
（L8 在本层之后，反查就成了循环）。割接自己造成的闪断由 L8 兜住：
那条升级动作同样要过 L8，命中同一条 mute 规则就一起被静默。

======================= ignore =======================

L5 的定级规则配 action=ignore 产生 state=ignore，表示这台设备的这个
事件不开告警。本层直接返回 ACTION_IGNORE，不写状态、不往 L8 交。
事件已经在 L6 写进 alarm_log，事后回看查得到。

ignore 和 mute 都是"不告警"，区别在生效方式：ignore 是静态配置（哪类
设备的哪个事件码永久不看），mute 是时间窗（割接期间临时不看，窗口过了
自动恢复）。前者在本层截住，后者要等本层维护完状态再交给 L8 判。
"""
import time
import logging
import threading

from pipeline.l5_attrs import escalate, severity_name

logger = logging.getLogger(__name__)

# syslog_event.state 的四个取值，对应到状态机的处理模式
MODE_RAISE = "raise"
MODE_CLEAR = "clear"
MODE_STATELESS = "stateless"
MODE_IGNORE = "ignore"

# 本层产出的动作
ACTION_NONE = "none"            # 什么都不用做（累加、未到阈值、重复恢复）
ACTION_RAISE = "raise"          # 开告警
ACTION_UPDATE = "update"        # 已开着的告警有新进展（级别变了）
ACTION_ESCALATE = "escalate"    # 闪断升级
ACTION_CLEAR = "clear"          # 关告警
ACTION_IGNORE = "ignore"        # L5 判定不告警，不往 L8 交

# 要通知的动作。ACTION_NONE / ACTION_IGNORE 不往 L8 交
NOTIFY_ACTIONS = (ACTION_RAISE, ACTION_UPDATE, ACTION_ESCALATE, ACTION_CLEAR)

STATE_OPEN = "open"
STATE_IDLE = "idle"

DEFAULT_SILENCE = 600           # stateless 静默多久自动恢复
DEFAULT_FLAP_WINDOW = 1800      # 闪断统计窗口 30 分钟
DEFAULT_FLAP_THRESHOLD = 3      # 窗口内新开告警次数达到即判闪断

FLAP_CODE = "IF_FLAP"           # 升级后的事件码，syslog_event 里有行

# 状态在内存里留多久没动静就清掉。比闪断窗口长一截 ——
# 清早了闪断计数就断了
DEFAULT_STATE_TTL = 7200


class AlarmState(object):
    """
    一个指纹的告警状态，对应 syslog_alarm_state 的一行

    severity 和 base_severity 分开存：闪断把级别临时提一档，稳定后要落回
    base_severity，所以原始级别不能丢。

    raise_times 只在内存里，不入库 —— 它是闪断计数用的时间戳列表，重启后
    从零开始数。持久化的 flapping 标记保证已经判定闪断的告警重启后仍然
    不自动恢复，所以丢掉这个列表不影响正确性。
    """

    __slots__ = ("fingerprint", "ip", "event_code", "alarm_object", "mode", "state",
                 "severity", "base_severity", "first_seen", "last_seen", "counter",
                 "raise_count", "clear_count", "flapping", "alarm_id", "raise_times")

    def __init__(self, fingerprint, ip="", event_code="", alarm_object="",
                 mode=MODE_RAISE, severity=3):
        self.fingerprint = fingerprint
        self.ip = ip
        self.event_code = event_code
        self.alarm_object = alarm_object
        self.mode = mode
        self.state = STATE_IDLE
        self.severity = int(severity)
        self.base_severity = int(severity)
        self.first_seen = 0
        self.last_seen = 0
        self.counter = 0
        self.raise_count = 0
        self.clear_count = 0
        self.flapping = 0
        self.alarm_id = 0
        self.raise_times = []

    def is_open(self):
        return self.state == STATE_OPEN

    def as_row(self, now):
        """落 syslog_alarm_state 的一行。raise_times 不入库"""
        return {
            "fingerprint": self.fingerprint,
            "ip": self.ip,
            "event_code": self.event_code,
            "alarm_object": self.alarm_object,
            "mode": self.mode,
            "state": self.state,
            "severity": self.severity,
            "base_severity": self.base_severity,
            "first_seen": str(self.first_seen or ""),
            "last_seen": str(self.last_seen or ""),
            "counter": self.counter,
            "raise_count": self.raise_count,
            "clear_count": self.clear_count,
            "flapping": self.flapping,
            "alarm_id": self.alarm_id,
            "updated_time": str(int(now)),
        }

    @classmethod
    def from_row(cls, row):
        """启动回放用。查不出来的字段给默认值，不让一行坏数据挡住回放"""
        def to_int(value, default=0):
            try:
                return int(value)
            except (TypeError, ValueError):
                return default

        state = cls(row.get("fingerprint", ""), ip=row.get("ip", ""),
                    event_code=row.get("event_code", ""),
                    alarm_object=row.get("alarm_object", ""),
                    mode=row.get("mode") or MODE_RAISE,
                    severity=to_int(row.get("base_severity"), 3))
        state.state = row.get("state") or STATE_IDLE
        state.severity = to_int(row.get("severity"), state.base_severity)
        state.first_seen = to_int(row.get("first_seen"))
        state.last_seen = to_int(row.get("last_seen"))
        state.counter = to_int(row.get("counter"))
        state.raise_count = to_int(row.get("raise_count"))
        state.clear_count = to_int(row.get("clear_count"))
        state.flapping = to_int(row.get("flapping"))
        state.alarm_id = to_int(row.get("alarm_id"))
        return state


class StateMachine(object):
    """
    L7 状态机

    handle() 热路径，sweep() / persist() / purge() 由维护线程调。
    worker 共享同一个实例，状态字典加锁。
    """

    def __init__(self, silence=DEFAULT_SILENCE, flap_window=DEFAULT_FLAP_WINDOW,
                 flap_threshold=DEFAULT_FLAP_THRESHOLD, state_ttl=DEFAULT_STATE_TTL,
                 db=None):
        """
        :param silence:        stateless 事件静默多久算恢复
        :param flap_window:    闪断统计窗口
        :param flap_threshold: 窗口内新开告警次数达到即判闪断
        :param state_ttl:      内存状态保留多久
        :param db:             数据源，由 db.get_alarm_db() 注入
        """
        self._silence = int(silence)
        self._flap_window = int(flap_window)
        self._flap_threshold = int(flap_threshold)
        self._state_ttl = int(state_ttl)
        self._db = db

        self._states = {}           # fingerprint -> AlarmState
        self._dirty = set()          # 待落库的指纹
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

        :param event: L6 的输出（带 fingerprint / count / state / severity）
        :return: 决策 dict。action=none/ignore 时 L8 和 L9 都不用管它
        """
        clock = int(now if now is not None else (event.get("ingest_ts") or time.time()))
        mode = str(event.get("state") or MODE_STATELESS).lower()

        # L5 判定不告警。不写状态 —— 写了反而会让后面真要告警时
        # 误以为"已有活跃告警"
        if mode == MODE_IGNORE:
            return self._decide(event, ACTION_IGNORE, None, clock)

        fingerprint = event.get("fingerprint") or ""
        if not fingerprint:
            # L6 没算出指纹，状态机没法做事。L6 那边已经打过 error
            return self._decide(event, ACTION_NONE, None, clock)

        with self._lock:
            state = self._states.get(fingerprint)
            if state is None:
                state = AlarmState(
                    fingerprint, ip=event.get("ip", ""),
                    event_code=event.get("event_code", ""),
                    alarm_object=event.get("alarm_object", ""),
                    mode=mode, severity=event.get("severity", 3))
                self._states[fingerprint] = state

            if mode == MODE_CLEAR:
                action = self._on_clear(state, event, clock)
            elif mode == MODE_RAISE:
                action = self._on_raise(state, event, clock)
            else:
                action = self._on_stateless(state, event, clock)

            # ACTION_NONE 也要标 dirty：它多半是"已有活跃告警，只累加"，
            # counter 和 last_seen 都变了。不标的话这些变化只留在内存里，
            # persist 的时机一变就丢，重启后 counter 回到上次落库的值。
            # dirty 是 set，一个指纹刷一万条日志也只有一个条目，
            # persist 一轮写一次，写入量不会跟着日志量涨
            self._dirty.add(fingerprint)
            return self._decide(event, action, state, clock)

    # ---------------- 三种模式 ----------------

    def _on_raise(self, state, event, now):
        """
        raise：无活跃告警就攒到阈值开告警，已有活跃告警只累加

        判据是"有没有活跃告警"，不是 L6 的 is_first —— 一个口持续 down
        一小时，L6 按 max_life 切两段、两次给 is_first=True，但那是一条告警

        counter 自己数，不借用 L6 的 count：那个值会在 L6 的窗口过期或
        max_life 到期时重置为 1，这和本层"告警开着没有"是两套完全独立
        的生命周期 —— L6 的窗口可能在告警还没恢复时就先断了（比如
        down 了 17 分钟，窗口 300s 早过期，但故障没好、告警还开着），
        借它的值反推 counter 会算出负数或错误的差值
        """
        state.mode = MODE_RAISE
        state.last_seen = now
        base = int(event.get("severity", state.base_severity))
        state.base_severity = base

        state.counter += 1
        if state.is_open():
            # 已经开着。级别变了（定级规则改过）要让 L9 更新一下，
            # 但闪断提过级的不往回降 —— 那是 flapping 的结果不是定级的
            if not state.flapping and state.severity != base:
                state.severity = base
                return ACTION_UPDATE
            return ACTION_NONE

        # 没开着：阈值由 syslog_event.threshold 定，IF_DOWN 是 1 当场开，
        # PARSE_FAIL 是 5 要攒 —— 没开的时候 counter 就是"攒了几条"，
        # 每条都加一，攒够才开告警
        threshold = self._threshold(event)
        if state.counter < threshold:
            return ACTION_NONE

        return self._open(state, now, base)

    def _on_clear(self, state, event, now):
        """clear：关掉同指纹的活跃告警。闪断中的不自动关"""
        state.last_seen = now
        if not state.is_open():
            # 没有活跃告警，这条恢复事件没东西可关。设备重启后会补发一批
            # up 日志，属正常现象，不记 error
            return ACTION_NONE

        state.clear_count += 1

        if state.flapping:
            # 闪断禁止自动恢复：一个口反复 down/up，每次 up 都关告警的话
            # 值班永远看不到它在闪。必须人工确认
            logger.info("闪断中不自动恢复：%s %s %s，需人工确认",
                        state.ip, state.event_code, state.alarm_object)
            return ACTION_NONE

        state.state = STATE_IDLE
        # counter 不清零、不改动 —— 它是这条告警最终的"几条日志支撑"，
        # 要落进 alarm_list 留着。下一次 raise 会在 _on_raise 里判到
        # state 不是 open，重新从 1 开始数，不用在这里预先处理
        state.severity = state.base_severity
        return ACTION_CLEAR

    def _on_stateless(self, state, event, now):
        """
        stateless：窗口内累计到阈值就告警，窗口内不再出现即自动恢复

        没有恢复日志的事件走这里（MAC 漂移、配置变更、登录失败）。
        自动恢复由 sweep() 负责 —— 没有日志来正是恢复的条件，等不到事件驱动

        这里的"窗口"是本层自己的概念（threshold 条日志内算一轮），
        不是 L6 的滑动窗口，两者无关也不该混用
        """
        state.mode = MODE_STATELESS
        state.last_seen = now
        base = int(event.get("severity", state.base_severity))
        state.base_severity = base

        # counter 和 _on_raise 一样无条件先加：alarm_list.counter 的字段
        # 语义是"窗口内日志条数"，开了告警之后同指纹日志照样要计入，
        # 否则 sync_counters 同步过去的永远是 threshold 那个老值，看板上
        # 看不出这条告警后面还在持续发生
        state.counter += 1
        if state.is_open():
            return ACTION_NONE

        threshold = self._threshold(event)
        if state.counter < threshold:
            # 阈值兼做降噪：MAC_FLAP 配 3，虚机迁移造成的偶发单次不报
            return ACTION_NONE

        return self._open(state, now, base)

    # ---------------- 开告警与闪断 ----------------

    def _open(self, state, now, base_severity):
        """
        开告警，并数一次闪断

        计数点就在这里 —— "无活跃告警 -> 开告警"这一跳。不在 L6 的日志
        条数上：一次端口 down 产生 2~3 条同指纹日志，按日志条数计的话
        一次 down 就能凑满 3 次，当场误报成闪断
        """
        state.state = STATE_OPEN
        state.first_seen = now
        state.raise_count += 1
        state.severity = base_severity
        state.base_severity = base_severity
        # 开告警这一刻把 counter 定为 1：_on_raise/_on_stateless 在没开着
        # 的时候会一直累加（攒阈值用），到这里之前它存的是"攒了几条"，
        # 不是"这次故障几条"——上一轮恢复后 counter 没清零（要留给
        # alarm_list 当历史值），这里必须显式归位，否则第二次开告警会把
        # 上一轮的条数也算进来
        state.counter = 1

        # 闪断窗口内的开告警次数
        state.raise_times.append(now)
        cutoff = now - self._flap_window
        state.raise_times = [ts for ts in state.raise_times if ts > cutoff]

        if len(state.raise_times) >= self._flap_threshold:
            return self._escalate(state, now)
        return ACTION_RAISE

    def _escalate(self, state, now):
        """
        闪断升级：提一档级别，换显示用的事件码，指纹不动

        指纹不动是硬要求：指纹是 md5(ip|event_code|object)，换了就是另一条
        告警，原来那条还挂着关不掉。所以只改级别和 event_code
        """
        was_flapping = state.flapping
        state.flapping = 1
        state.severity = escalate(state.base_severity, 1)
        state.event_code = FLAP_CODE

        if not was_flapping:
            logger.warning("闪断升级：%s %s 在 %s 秒内开告警 %s 次，升为 %s（%s），"
                           "禁止自动恢复",
                           state.ip, state.alarm_object, self._flap_window,
                           len(state.raise_times), FLAP_CODE,
                           severity_name(state.severity))
        return ACTION_ESCALATE

    @staticmethod
    def _threshold(event):
        """窗口内攒够这么多条才告警。syslog_event.threshold"""
        try:
            value = int(event.get("threshold") or 1)
        except (TypeError, ValueError):
            return 1
        return value if value > 0 else 1

    # ---------------- 决策 ----------------

    def _decide(self, event, action, state, now):
        """
        拼决策 dict 交给 L8

        muted / mute_rule_id 留空位，L8 填。L9 据此一次写 alarm_list，
        不是先写再改 —— 先写 muted=0 再 UPDATE 成 1 的话，中间那一瞬间
        看板轮询到会显示成"割接期间有条没静默的告警"
        """
        decision = {
            "action": action,
            "notify": action in NOTIFY_ACTIONS,
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

        if state is None:
            decision.update({
                "event_code": event.get("event_code", ""),
                "severity": event.get("severity", 3),
                "severity_name": severity_name(event.get("severity", 3)),
                "state": STATE_IDLE,
                "counter": event.get("count", 1),
                "first_seen": now,
                "last_seen": now,
                "flapping": 0,
                "alarm_id": 0,
            })
            return decision

        decision.update({
            # 升级之后这里是 IF_FLAP，不是原来的 IF_DOWN
            "event_code": state.event_code,
            "severity": state.severity,
            "severity_name": severity_name(state.severity),
            "base_severity": state.base_severity,
            "state": state.state,
            "counter": state.counter,
            "first_seen": state.first_seen or now,
            "last_seen": state.last_seen or now,
            "clear_time": now if action == ACTION_CLEAR else 0,
            "flapping": state.flapping,
            "raise_count": state.raise_count,
            "alarm_id": state.alarm_id,
        })
        return decision

    def bind_alarm(self, fingerprint, alarm_id):
        """
        L9 落库之后把 alarm_id 回填进状态，下次更新同一条告警要用

        :return: True=绑上了
        """
        with self._lock:
            state = self._states.get(fingerprint)
            if state is None:
                return False
            state.alarm_id = int(alarm_id)
            self._dirty.add(fingerprint)
        return True

    def confirm_flap(self, fingerprint):
        """
        人工确认闪断，解除"禁止自动恢复"

        闪断不自动关，必须有人看过。确认之后下一条恢复事件才能关掉它。
        看板上那个"确认"按钮最终调到这里

        :return: True=解除了
        """
        with self._lock:
            state = self._states.get(fingerprint)
            if state is None or not state.flapping:
                return False
            state.flapping = 0
            state.severity = state.base_severity
            state.raise_times = []
            self._dirty.add(fingerprint)
        logger.info("闪断已人工确认，恢复自动关闭：%s", fingerprint)
        return True

    # ---------------- 周期维护 ----------------

    def sweep(self, now=None):
        """
        stateless 事件的自动恢复：静默超过窗口就关

        必须定时扫，不能等日志驱动 —— 没有日志来正是恢复的条件。
        raise/clear 类不在这里关，它们等显式的恢复事件。

        :return: [决策]，L8/L9 照常处理
        """
        now = int(now if now is not None else time.time())
        decisions = []
        with self._lock:
            for state in self._states.values():
                if state.mode != MODE_STATELESS or not state.is_open():
                    continue
                if now - state.last_seen <= self._silence:
                    continue
                if state.flapping:
                    # 闪断中的不自动关，等人工确认
                    continue
                state.state = STATE_IDLE
                # 和 _on_clear 一样：counter 不清零、不改动，留着给
                # alarm_list 展示"这条告警最终有几条日志支撑"
                state.clear_count += 1
                state.severity = state.base_severity
                self._dirty.add(state.fingerprint)
                decisions.append({
                    "action": ACTION_CLEAR,
                    "notify": True,
                    "fingerprint": state.fingerprint,
                    "ip": state.ip,
                    "hostname": "",
                    "event_code": state.event_code,
                    "alarm_object": state.alarm_object,
                    "message": "",
                    "severity": state.severity,
                    "severity_name": severity_name(state.severity),
                    "base_severity": state.base_severity,
                    "state": state.state,
                    "counter": 0,
                    "first_seen": state.first_seen,
                    "last_seen": state.last_seen,
                    "clear_time": now,
                    "flapping": state.flapping,
                    "raise_count": state.raise_count,
                    "alarm_id": state.alarm_id,
                    "ingest_ts": now,
                    "muted": False,
                    "mute_rule_id": 0,
                })
        if decisions:
            logger.info("stateless 静默恢复 %s 条", len(decisions))
        return decisions

    def persist(self, now=None):
        """
        把变动过的状态落 syslog_alarm_state。进程重启后靠它接着算

        只落 dirty 的 —— 全量 upsert 在指纹多的时候是白写。
        落库失败的留在 dirty 里，下一轮再试

        :return: 落库成功的条数
        """
        now = int(now if now is not None else time.time())
        with self._lock:
            if not self._dirty:
                return 0
            pending = [(fp, self._states[fp].as_row(now))
                       for fp in self._dirty if fp in self._states]
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

    def restore(self, limit=5000):
        """
        启动回放未恢复的告警。不回放的话重启后同一个还没好的故障会重新
        开告警，等于重复通知一次

        raise_times 不回放，闪断计数从零开始数。持久化的 flapping 标记
        保证已经判定闪断的告警重启后仍然不自动恢复

        :return: 回放的状态数
        """
        try:
            rows = self.db.getOpenAlarmStates(limit=limit)
        except Exception as err:
            logger.error("======StateMachine restore error========\n%s", err)
            return 0

        restored = 0
        with self._lock:
            for row in rows or []:
                fingerprint = row.get("fingerprint")
                if not fingerprint or fingerprint in self._states:
                    continue
                self._states[fingerprint] = AlarmState.from_row(row)
                restored += 1
        if restored:
            logger.info("StateMachine 回放 %s 条未恢复告警", restored)
        return restored

    def purge(self, now=None):
        """
        清理长期没动静的状态。活跃告警和闪断中的永不清 ——
        清了就等于悄悄关了一条还没好的告警

        :return: 清掉的状态数
        """
        now = int(now if now is not None else time.time())
        with self._lock:
            expired = [key for key, state in self._states.items()
                       if not state.is_open() and not state.flapping
                       and key not in self._dirty
                       and now - state.last_seen > self._state_ttl]
            for key in expired:
                self._states.pop(key, None)
        return len(expired)

    def open_snapshots(self):
        """
        还开着的告警的 (fingerprint, counter, last_seen, severity, alarm_id)

        给 L9 同步 alarm_list.counter 用。累加（ACTION_NONE）不触发 L9，
        所以 alarm_list 的 counter 会停在开告警那一刻的值 —— 一次端口 down
        三条日志，看板上显示 1。靠维护线程定期把这里的值刷过去补齐。

        只给还开着的：已恢复的那些 counter 已经定稿了，不用再同步
        """
        with self._lock:
            return [{
                "fingerprint": state.fingerprint,
                "counter": state.counter,
                "last_seen": state.last_seen,
                "severity": state.severity,
                "alarm_id": state.alarm_id,
            } for state in self._states.values() if state.is_open()]

    def stats(self):
        with self._lock:
            opened = sum(1 for s in self._states.values() if s.is_open())
            flapping = sum(1 for s in self._states.values() if s.flapping)
            return {"states": len(self._states), "open": opened,
                    "flapping": flapping, "dirty": len(self._dirty)}

    def size(self):
        return len(self._states)
