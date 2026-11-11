# -*- coding: utf-8 -*-
"""
管线串联

worker 拿到一条原始报文，调 runner.handle() 走完 L0 ~ L2.5。
L3 之后还没实现，跑到 attrs 就返回。

    raw {"ip", "message", "timestamp"}
      │
      ├─ L0   prepare    剥信封 + 剥 mnemonic
      │        ↓ 不可读也往下走，落 PARSE_FAIL
      ├─ L0.5 blacklist  命中即返回 None，整条终止
      ├─ L1   parser     (vendor, mnemonic) -> event_code / object
      ├─ L2   enrich     sysname / hardware / syscontact / 接口描述
      └─ L2.5 attrs      severity / state / window / clear_code

性能相关的一点：四层各自持有规则的快照，读路径不加锁，
刷新线程整体替换索引。worker 之间共享这些实例是安全的。
"""
import logging
import time

from pipeline.prepare import prepare
from pipeline.blacklist import BlacklistFilter
from pipeline.parser import SyslogParser
from pipeline.enrich import DeviceEnricher
from pipeline.attrs import EventAttrs
from utils import stats as stats_mod

logger = logging.getLogger(__name__)


class Runner(object):
    """把各层串起来，worker 只需要调 handle()"""

    def __init__(self, prepare_fn=prepare, blacklist=None, parser=None,
                 enricher=None, attrs=None, stats=None):
        """
        :param blacklist: BlacklistFilter，默认懒建
        :param parser:    SyslogParser，默认懒建
        :param enricher:  DeviceEnricher，默认懒建
        :param attrs:     EventAttrs，默认懒建
        :param stats:     utils.stats.Stats，默认用进程内单例
        """
        self._prepare = prepare_fn
        self._blacklist = blacklist
        self._parser = parser
        self._enricher = enricher
        self._attrs = attrs
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

    # ---------------- 热路径 ----------------

    def handle(self, raw, now=None):
        """
        处理一条原始报文

        :param raw: {"ip", "message", "timestamp"}
        :param now: 采集时间，不传取本机时间
        :return: event dict；被黑名单拦掉返回 None
        """
        clock = int(now if now is not None else time.time())

        # L0 预处理。mnemonic 在这里剥一次，后面各层共用
        prepared = self._prepare(raw, now=clock)
        self._stats.incr("received")

        # L0.5 黑名单。命中即丢，不进任何后续层
        if self.blacklist.blocked(prepared):
            self._stats.incr("blocked")
            return None

        # L1 解析
        event = self.parser.parse(prepared)

        # L2 富化。失败不影响主流程，只标记 src_state
        try:
            self.enricher.enrich(event, now=clock)
        except Exception as err:
            logger.error("======Runner enrich error========\n%s", err)
            event.setdefault("src_state", "SRC_LOOKUP_FAILED")

        # L2.5 事件属性
        try:
            self.attrs.fill(event)
        except Exception as err:
            logger.error("======Runner attrs error========\n%s", err)

        self._count_codes(event)
        return event

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

    # ---------------- 周期维护 ----------------

    def tick(self, now=None):
        """
        维护线程定期调这个：刷新规则、清理缓存

        刷新放在同一个线程串行做，不各自起 refresh 线程 ——
        四张表的刷新时间点错开没有意义，集中在一处好排查
        """
        now = int(now if now is not None else time.time())
        for name, component in (("blacklist", self._blacklist), ("parser", self._parser),
                                ("attrs", self._attrs)):
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

    def stop(self):
        for component in (self._blacklist, self._parser, self._attrs):
            if component is None:
                continue
            try:
                component.stop()
            except Exception:
                pass
