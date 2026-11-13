# -*- coding: utf-8 -*-
"""
管线串联

worker 拿到一条原始报文，调 runner.handle() 走完 L1 ~ L9。

    raw {"ip", "message", "timestamp"}
      │
      ├─ L1 prepare       剥信封 + 剥 mnemonic
      │      ↓ 不可读也往下走，落 PARSE_FAIL
      ├─ L2 blacklist     命中即返回 None，整条终止
      ├─ L3 parser        (vendor, mnemonic) -> event_code / object
      ├─ L4 enrich        sysname / hardware / syscontact / 接口描述
      ├─ L5 attrs         state / 窗口 / clear_code，再按设备定 severity
      │      ↓ 原子告警
      ├─ L6 aggregate     指纹 + 滑动窗口，攒批写 alarm_log
      ├─ L7 state_machine raise / clear / stateless + 闪断升级
      │      ↓ 告警决策
      ├─ L8 suppress      时间窗静默，填 muted
      └─ L9 emit          写 alarm_list + 发通知

层号就是执行顺序，文件名带前缀（l1_prepare.py ... l9_emit.py）。
L8 静默排在状态机之后是有原因的，见 pipeline/l8_suppress.py：
判据里的 object 要等 L6、告警状态要等 L7，而且挪到这里之后它从热路径
（每条日志）变成冷路径（只有待通知的告警）。

三个周期动作，间隔各不相同，别混在一起：
    tick()        刷规则、清内存缓存，不写库
    persist()     落库，比 tick 频繁得多
    purge_logs()  删过期 alarm_log，按小时

性能相关的一点：各层各自持有规则的快照，读路径不加锁，
刷新线程整体替换索引。worker 之间共享这些实例是安全的。
"""
import logging
import time

from pipeline.l1_prepare import prepare
from pipeline.l2_blacklist import BlacklistFilter
from pipeline.l3_parser import SyslogParser
from pipeline.l4_enrich import DeviceEnricher
from pipeline import l5_attrs as attrs_mod
from pipeline.l5_attrs import EventAttrs
from pipeline.l6_aggregate import Aggregator
from pipeline.l7_state_machine import StateMachine
from pipeline.l8_suppress import MuteFilter
from pipeline.l9_emit import AlarmEmitter
from utils import stats as stats_mod

logger = logging.getLogger(__name__)


class Runner(object):
    """把各层串起来，worker 只需要调 handle()"""

    def __init__(self, prepare_fn=prepare, blacklist=None, parser=None,
                 enricher=None, attrs=None, aggregator=None, state_machine=None,
                 mute=None, emitter=None, stats=None):
        """
        :param blacklist:     BlacklistFilter，默认懒建
        :param parser:        SyslogParser，默认懒建
        :param enricher:      DeviceEnricher，默认懒建
        :param attrs:         EventAttrs，默认懒建
        :param aggregator:    Aggregator，默认懒建
        :param state_machine: StateMachine，默认懒建
        :param mute:          MuteFilter，默认懒建
        :param emitter:       AlarmEmitter，默认懒建
        :param stats:         utils.stats.Stats，默认用进程内单例
        """
        self._prepare = prepare_fn
        self._blacklist = blacklist
        self._parser = parser
        self._enricher = enricher
        self._attrs = attrs
        self._aggregator = aggregator
        self._state_machine = state_machine
        self._mute = mute
        self._emitter = emitter
        self._stats = stats or stats_mod.stats

    # ---------------- 组件懒建 ----------------

    @property
    def blacklist(self):
        if self._blacklist is None:
            self._blacklist = BlacklistFilter()
        return self._blacklist

    @property
    def parser(self):
        if self._parser is None:
            self._parser = SyslogParser()
        return self._parser

    @property
    def enricher(self):
        if self._enricher is None:
            self._enricher = DeviceEnricher()
        return self._enricher

    @property
    def attrs(self):
        if self._attrs is None:
            self._attrs = EventAttrs()
        return self._attrs

    @property
    def aggregator(self):
        if self._aggregator is None:
            self._aggregator = Aggregator()
        return self._aggregator

    @property
    def state_machine(self):
        if self._state_machine is None:
            self._state_machine = StateMachine()
        return self._state_machine

    @property
    def mute(self):
        if self._mute is None:
            self._mute = MuteFilter()
        return self._mute

    @property
    def emitter(self):
        if self._emitter is None:
            # 带上状态机：insert 之后要把 alarm_id 回填进状态
            self._emitter = AlarmEmitter(state_machine=self.state_machine)
        return self._emitter

    # ---------------- 热路径 ----------------

    def handle(self, raw, now=None):
        """
        处理一条原始报文

        :param raw: {"ip", "message", "timestamp"}
        :param now: 采集时间，不传就用 raw 里的 timestamp，都没有取本机时间
        :return: event dict；被黑名单拦掉返回 None
        """
        clock = int(now if now is not None else time.time())

        # L1 预处理。mnemonic 在这里剥一次，后面各层共用
        prepared = self._prepare(raw, now=clock)
        self._stats.incr("received")

        # 时间统一用 prepare 定下来的 ingest_ts：raw 里带 timestamp 时它就是
        # 那个值。后面各层都用它，否则回放历史日志时窗口按今天的时钟算，
        # 聚合、状态机、恢复时间全是错的
        clock = int(prepared.get("ingest_ts") or clock)

        # L2 黑名单。命中即丢，不进任何后续层
        if self.blacklist.blocked(prepared):
            self._stats.incr("blocked")
            return None

        # L3 解析
        event = self.parser.parse(prepared)

        # L4 富化。失败不影响主流程，只标记 src_state
        try:
            self.enricher.enrich(event, now=clock)
        except Exception as err:
            logger.error("======Runner enrich error========\n%s", err)
            event.setdefault("src_state", "SRC_LOOKUP_FAILED")

        # L5 事件属性 + 定级
        try:
            self.attrs.fill(event)
        except Exception as err:
            logger.error("======Runner attrs error========\n%s", err)

        self._count_codes(event)

        # L6 聚合。算不出指纹后面各层都没法做，但事件本身不丢 ——
        # 原子告警已经成形，至少能落日志
        try:
            self.aggregator.handle(event, now=clock)
        except Exception as err:
            logger.error("======Runner aggregate error========\n%s", err)
            return event

        # L7 状态机。出错就不往下走了 —— 状态不可信的话 L8/L9 做的决定
        # 也不可信，宁可这条不告警，也不要开一条关不掉的
        try:
            decision = self.state_machine.handle(event, now=clock)
        except Exception as err:
            logger.error("======Runner state_machine error========\n%s", err)
            return event

        # L8 静默。出错按"不静默"处理 —— 漏静默是多发一条通知，
        # 误静默是真故障没人知道，前者代价小得多
        try:
            self.mute.handle(decision, now=clock)
        except Exception as err:
            logger.error("======Runner mute error========\n%s", err)
            decision.setdefault("muted", False)
            decision.setdefault("mute_rule_id", 0)

        self._count_decision(decision)

        # L9 落库 + 通知
        try:
            self.emitter.handle(decision, now=clock)
        except Exception as err:
            logger.error("======Runner emit error========\n%s", err)

        event["decision"] = decision
        return event

    def _count_decision(self, decision):
        """开了几条告警、静默了几条"""
        if not decision.get("notify"):
            return
        self._stats.incr("alarms")
        if decision.get("muted"):
            self._stats.incr("muted")

    def _count_codes(self, event):
        """按事件码记数。UNKNOWN_MNEMONIC 的计数就是规则缺口清单的来源"""
        self._stats.incr("parsed")
        code = event.get("event_code", "")
        if code == "PARSE_FAIL":
            self._stats.incr("parse_fail")
        elif code == "UNMANAGED_SRC":
            self._stats.incr("unmanaged")
        elif code == "UNKNOWN_MNEMONIC":
            self._stats.incr("unknown")
        # 定级规则判定不开告警的。和 blocked 分开记：那个是解析前就丢了，
        # 这个走完了整条管线、日志照样归档，只是不告警
        if event.get("state") == attrs_mod.STATE_IGNORE:
            self._stats.incr("ignored")

    # ---------------- 周期维护 ----------------

    def tick(self, now=None):
        """
        维护线程定期调这个：刷新规则、清理缓存

        刷新放在同一个线程串行做，不各自起 refresh 线程 ——
        几张表的刷新时间点错开没有意义，集中在一处好排查

        不含落库。规则刷新 300s 一次合理（规则很少改），但告警状态和
        counter 跟着 300s 才落一次就太慢了 —— 看板上 counter 最多滞后
        5 分钟，进程崩了丢 5 分钟的状态。落库在 persist()，自己一个间隔
        """
        now = int(now if now is not None else time.time())
        for name, component in (("blacklist", self._blacklist), ("parser", self._parser),
                                ("attrs", self._attrs), ("mute", self._mute)):
            if component is None:
                continue
            try:
                component.refresh()
            except Exception as err:
                logger.error("======Runner refresh %s error========\n%s", name, err)

        if self._enricher is not None:
            try:
                self._enricher.purge(now=now)
            except Exception as err:
                logger.error("======Runner enrich purge error========\n%s", err)
        if self._parser is not None:
            try:
                self._parser.purge_vendor_cache(now=now)
            except Exception as err:
                logger.error("======Runner vendor purge error========\n%s", err)

        # 只清内存，不落库 —— 落库在 persist()
        if self._aggregator is not None:
            try:
                self._aggregator.purge(now=now)
            except Exception as err:
                logger.error("======Runner aggregate purge error========\n%s", err)

        if self._state_machine is not None:
            try:
                self._state_machine.purge(now=now)
            except Exception as err:
                logger.error("======Runner state purge error========\n%s", err)

    def persist(self, now=None):
        """
        落库。维护线程按自己的间隔调，比 tick() 频繁得多

        五件事：
            L2  persist        黑名单规则的命中数刷进 syslog_black_list
            L6  flush          攒着的原子记录写 alarm_log
            L7  persist        变动过的告警状态写 syslog_alarm_state
            L8  persist        静默规则的命中数刷进 syslog_mute_rule
            L9  sync_counters  累加出来的 counter 刷进 alarm_list

        为什么不跟 tick() 一起：规则刷新 300s 一次合理，但这几件 300s
        才做一次的后果是看板上的数滞后 5 分钟、进程崩了丢 5 分钟状态。

        为什么不在热路径上做：日志风暴时一条规则一秒能命中几千次，
        热路径上每次都 UPDATE 就是几千次写。这里一轮一条规则最多一次。

        :return: {"logs", "states", "counters", "blacklist_hits", "mute_hits"} 各写了多少
        """
        now = int(now if now is not None else time.time())
        result = {"logs": 0, "states": 0, "counters": 0,
                  "blacklist_hits": 0, "mute_hits": 0}

        if self._blacklist is not None:
            try:
                result["blacklist_hits"] = self._blacklist.persist(now=now)
            except Exception as err:
                logger.error("======Runner blacklist persist error========\n%s", err)

        if self._aggregator is not None:
            try:
                result["logs"] = self._aggregator.flush(now=now)
            except Exception as err:
                logger.error("======Runner persist flush error========\n%s", err)

        if self._mute is not None:
            try:
                result["mute_hits"] = self._mute.persist(now=now)
            except Exception as err:
                logger.error("======Runner mute persist error========\n%s", err)

        if self._state_machine is None:
            return result

        try:
            result["states"] = self._state_machine.persist(now=now)
        except Exception as err:
            logger.error("======Runner state persist error========\n%s", err)

        # L7 对已有活跃告警的后续日志返回 ACTION_NONE，L9 不跑，所以
        # alarm_list.counter 会停在开告警那一刻 —— 一次端口 down 三条日志，
        # 看板上显示 1。这里把内存里累加的值刷过去补齐
        if self._emitter is not None:
            try:
                result["counters"] = self._emitter.sync_counters(
                    self._state_machine.open_snapshots())
            except Exception as err:
                logger.error("======Runner sync_counters error========\n%s", err)
        return result

    def sweep(self, now=None):
        """
        两个到期扫描，都不能等日志驱动 —— 它们的触发条件就是"没有新日志"
        或者"时间到了"：

            L7  stateless 静默超过窗口 -> 自动恢复
            L8  静默窗口过了但故障还在 -> 恢复通知

        返回待通知的决策，L9 落地后由它发出去。现在 L9 还没实现，
        调用方拿到的就是列表本身

        :return: [决策]
        """
        now = int(now if now is not None else time.time())
        pending = []

        if self._state_machine is not None:
            try:
                for decision in self._state_machine.sweep(now=now):
                    # 自动恢复的也要过 L8：割接窗口内的恢复通知同样该压住
                    if self._mute is not None:
                        self._mute.handle(decision, now=now)
                    pending.append(decision)
            except Exception as err:
                logger.error("======Runner state sweep error========\n%s", err)

        if self._mute is not None:
            try:
                # 静默到期放出来的已经在 L8 里改过库了，这里只补通知
                pending.extend(self._mute.sweep(now=now))
            except Exception as err:
                logger.error("======Runner mute sweep error========\n%s", err)

        for decision in pending:
            self._count_decision(decision)
            try:
                self.emitter.handle(decision, now=now)
            except Exception as err:
                logger.error("======Runner sweep emit error========\n%s", err)

        return pending

    def purge_logs(self, now=None):
        """
        删过期的 alarm_log。比 tick() 慢得多，维护线程单独按天调，
        不跟规则刷新挤在一起
        """
        if self._aggregator is None:
            return 0
        try:
            return self._aggregator.purge_logs(now=now)
        except Exception as err:
            logger.error("======Runner purge_logs error========\n%s", err)
            return 0

    def stop(self):
        # 退出前最后落一次库，这是最后的机会。状态丢了重启后会重复告警一轮
        try:
            result = self.persist()
            if any(result.values()):
                logger.info("退出前落库：alarm_log %s 条，状态 %s 条，counter %s 条，"
                            "黑名单命中 %s 条，静默命中 %s 条",
                            result["logs"], result["states"], result["counters"],
                            result["blacklist_hits"], result["mute_hits"])
        except Exception as err:
            logger.error("======Runner stop persist error========\n%s", err)

        for component in (self._blacklist, self._parser, self._attrs, self._mute,
                          self._emitter):
            if component is None:
                continue
            try:
                component.stop()
            except Exception:
                pass
