# -*- coding: utf-8 -*-
"""
贴一条报文，看它在管线每一层被改成什么样

改下面的 a 然后跑：
    cd projects/switchlog
    python test.py

链路 L1 prepare -> L2 黑名单 -> L3 解析 -> L4 富化 -> L5 属性 + 定级，
每层打一次完整记录，新增或变化的字段前面标 +。

L5 分两步打：syslog_event 给 state/窗口/clear_code，
syslog_severity_rule 按 (event_code, ip, sysname) 定 severity。
定级那段会打出命中的规则和它为什么命中。

数据全部连真实 MySQL（config.py 的 mysql_config），不再有内存 mock。
WRITE_DB=False（默认）时跑完 L1~L8 但不执行 L9 的实际落库，只打印
"本该写进哪条记录"；改成 True 才会真的往 alarm_log/alarm_list 插入数据。

回放真实日志文件走 main.py --replay。
"""
import logging

from pipeline.l1_prepare import prepare
from pipeline.l2_blacklist import BlacklistFilter
from pipeline.l3_parser import SyslogParser
from pipeline.l4_enrich import DeviceEnricher
from pipeline.l5_attrs import EventAttrs, severity_name, STATE_IGNORE
from pipeline.l6_aggregate import Aggregator
from pipeline.l7_state_machine import StateMachine
from pipeline.l8_suppress import MuteFilter
from pipeline.l9_emit import AlarmEmitter, FileNotifier
from db import get_rule_db, get_device_db, get_alarm_db

logger = logging.getLogger(__name__)

# 值打多宽，超了截断
VAL_WIDTH = 110

# 第一步打表时挡掉的字段：定级那三个归第二步，raise_code 是给 L6 用的
GRADE_FIELDS = ("severity", "severity_name", "severity_rule_id", "raise_code")

# 默认不落库：跑完整条链路只是为了看每层改了什么字段，不该顺手污染
# alarm_log/alarm_list。确认过没问题、真要测落库效果时改成 True
WRITE_DB = False

# ============================================================
# 要跑的报文：ip 是源 IP，message 是原始报文，timestamp 是采集时间
# ============================================================
a = {
    "ip": "10.16.249.5",
    "message": '''2026 Sep 22 15:15:25.144 bbs1_dc05_m01_new %ETHPORT-5-IF_DOWN_LINK_FAILURE: Interface Ethernet1/1 (description:pT:bbs1_dc07_m01:100G1/4) is down (Link failure)''',
    "timestamp": 1762800000,
}

# 换着试的几条（取消注释即可）：
# a = {"ip": "10.19.7.1", "message": "<189>2026 Oct  9 05:18:56.565 pcs1_dc07_m01 "
#      "%ETH_PORT_CHANNEL-5-FOP_CHANGED: port-channel38: first operational port "
#      "changed from Ethernet1/38 to none"}                      # LAG_DOWN
# a = {"ip": "10.19.8.11", "message": "<189>Nov 11 09:12:33 asw1_dc08_m02 "
#      "%%10IFNET/3/PHY_UPDOWN: Physical state on the interface "
#      "GigabitEthernet1/0/1 changed to down."}                  # H3C IF_DOWN
# a = {"ip": "10.16.249.5", "message": "2026 Nov  4 09:00:01.100 bbs1_dc05_m01_new "
#      "%SSHD-6-SESSION_CONNECTED: ssh session connected from 10.1.2.3"}  # 黑名单拦掉
# a = {"ip": "10.19.250.8", "message": "<189>Oct 11 14:03:08.109 some_dev "
#      "%ETHPORT-5-IF_DOWN: Interface Ethernet1/1, changed state to down"}  # 未纳管


def build():
    """一条完整的 L1 ~ L9 链路，各层共用真实数据源

    refresh_interval=0：不起刷新线程，规则只加载一次（跑一条报文用不上
    定时刷新，起了线程进程退出还要等它）
    """
    rule_db = get_rule_db()
    device_db = get_device_db()
    alarm_db = get_alarm_db()

    sm = StateMachine(db=alarm_db)
    return (
        BlacklistFilter(refresh_interval=0, db=rule_db),
        SyslogParser(refresh_interval=0, db=rule_db, device_db=device_db),
        DeviceEnricher(db=device_db),
        EventAttrs(refresh_interval=0, db=rule_db),
        Aggregator(db=alarm_db),
        sm,
        MuteFilter(refresh_interval=0, db=alarm_db),
        AlarmEmitter(notifier=FileNotifier(), state_machine=sm, db=alarm_db),
    )


def shorten(value):
    text = str(value).replace("\n", " ").replace("\r", " ")
    return text if len(text) <= VAL_WIDTH else text[:VAL_WIDTH - 3] + "..."


def show(layer, record, before=None, skip=()):
    """
    打一层的结果，新增或变化的字段标 +

    :param skip: 不打的字段。L5 两步都在 fill() 里做完，
                 第一步要把第二步的字段挡掉，否则看不出是哪步补的
    """
    before = before if before is not None else {}
    print("\n--- {} ---".format(layer))
    for key, value in record.items():
        if key in skip:
            continue
        mark = "+" if key not in before or before[key] != value else " "
        print(" {} {:<18}{}".format(mark, key, shorten(value)))


def main():
    blacklist, parser, enricher, attrs, aggregator, machine, mute, emitter = build()

    print("== 原始报文 ==")
    print("  ip      {}".format(a.get("ip", "-")))
    print("  message {}".format(shorten(a.get("message", ""))))

    # L1 剥信封 + 剥 mnemonic。不可读也往下走，由 L3 落 PARSE_FAIL
    prepared = prepare(a)
    show("L1 prepare 剥信封 + 剥 mnemonic", prepared)
    if not prepared["readable"]:
        print("\n  readable=False，报文不可读，L3 会落 PARSE_FAIL")

    # L2 黑名单，命中即终止，不进后面任何一层
    rule = blacklist.match(prepared)
    print("\n--- L2 blacklist 命中即丢 ---")
    if rule is not None:
        print("   命中 rule {}  scope={}  pattern={}".format(
            rule.rule_id, rule.scope, rule.pattern))
        print("   {}".format(rule.descr))
        print("\n整条终止，runner.handle() 返回 None")
        return 0
    print("   没命中，放行")

    # L3 (vendor, mnemonic) -> event_code / alarm_object
    event = parser.parse(prepared)
    show("L3 parser -> event_code / alarm_object", event, prepared)

    # L4 按源 IP 查 devices 补 sysname/hardware/syscontact，查 ports 补接口描述
    before = dict(event)
    enricher.enrich(event)
    show("L4 enrich devices + ports", event, before)

    # L5 两步走。fill() 一次做完两步，打的时候拆开 ——
    # 第一步先把定级的字段挡掉，否则看不出是哪步补的
    before = dict(event)
    attrs.fill(event)
    show("L5 第一步 syslog_event 事件属性", event, before, skip=GRADE_FIELDS)
    show_grade(attrs, event)

    # L6 算指纹 + 滑动窗口，顺便把原子记录攒进 alarm_log 的批
    before = dict(event)
    aggregator.handle(event)
    show("L6 aggregate 指纹 + 滑动窗口", event, before)
    show_window(aggregator, event)

    # L7 状态机 -> 决策，L8 在决策上盖静默标记
    decision = machine.handle(event)
    show_decision(machine, decision)
    mute.handle(decision)
    show_mute(mute, decision)

    # L9 落库 + 推通知。WRITE_DB=False 时只打印本该落的内容，不真的写
    show_emit(emitter, decision)

    print("\n最终 {}  {}  {}  {}".format(
        event.get("sysname", "-"), decision.get("event_code", "-"),
        event.get("alarm_object", "-"), decision.get("severity_name", "-")))
    if decision.get("action") == "ignore":
        print("     定级规则判定不开告警（state=ignore），不往 L8 交")
    elif not decision.get("notify"):
        print("     action={} —— 不产生告警动作（累加或未到阈值）".format(
            decision.get("action")))
    elif decision.get("muted"):
        print("     告警会入库，但命中静默规则 {} 不发通知".format(
            decision.get("mute_rule_id")))
    else:
        print("     告警入库并发通知")
    return 0


def show_emit(emitter, decision):
    """
    L9：落库 + 通知

    WRITE_DB=False 时不调 emitter.handle()——那会真的执行
    addAlarm/addAlarmLogs，往生产的 alarm_log/alarm_list 插数据。
    只打印这条决策本该落成什么样，不产生副作用。
    """
    print("\n--- L9 emit 落库 + 通知 ---")
    if not decision.get("notify"):
        print("   action={} —— L7 判定不用处理，L9 没有动作".format(
            decision.get("action")))
        return 0

    if not WRITE_DB:
        print("   WRITE_DB=False，不执行真实落库。本该写入：")
        print("     action={}  severity={}  muted={}".format(
            decision.get("action"), decision.get("severity_name"),
            decision.get("muted")))
        print("   把文件顶部 WRITE_DB 改成 True 才会真的写 alarm_log/alarm_list")
        return 0

    result = emitter.handle(decision)
    print(" + {:<18}{}".format("alarm_id", result.get("alarm_id")))
    print(" + {:<18}{}".format("notified", result.get("notified")))
    print(" + {:<18}{}".format("muted", result.get("muted")))
    print("\n   WRITE_DB=True，已经真的写进 MySQL 的 alarm_log/alarm_list 了。")
    print("   emitter stats:", emitter.stats())
    return 0


def show_decision(machine, decision):
    """L7 的决策，以及同一条日志反复来会怎样"""
    print("\n--- L7 state_machine 状态机 ---")
    for key in ("action", "notify", "state", "counter", "severity_name",
                "flapping", "raise_count"):
        if key in decision:
            print(" + {:<18}{}".format(key, decision[key]))

    if decision.get("action") == "ignore":
        print("\n   state=ignore 在这一层就截住，不写状态、不往 L8 交")
        return 0

    print("\n   判据是\"有没有活跃告警\"，不是 L6 的 is_first ——")
    print("   一个口持续 down 一小时，L6 切两段都给 is_first=True，但那是一条告警")
    print("   stats:", machine.stats())
    return 0


def show_mute(mute, decision):
    """L8 的静默判定"""
    print("\n--- L8 mute 告警静默 ---")
    if not decision.get("notify"):
        print("   L7 说不用通知，跳过（不白跑正则）")
        return 0

    print("   判据 ip={}  event_code={}  object={}".format(
        decision.get("ip"), decision.get("event_code"),
        decision.get("alarm_object")))
    rule = mute.rule_of(decision.get("ip"), decision.get("event_code"),
                        decision.get("alarm_object"))
    if rule is None:
        print("   没命中静默规则，正常通知")
    else:
        judge = []
        if rule.ip_pattern:
            judge.append("ip_reg=" + rule.ip_pattern)
        if rule.event_pattern:
            judge.append("event_code_reg=" + rule.event_pattern)
        if rule.object_pattern:
            judge.append("object_reg=" + rule.object_pattern)
        window = "{} ~ {}".format(rule.start_time or "立即",
                                  rule.end_time or "永久")
        print("   命中 rule {}  判据 {}  窗口 {}".format(
            rule.rule_id, "  ".join(judge) or "无（所有告警）", window))
        print("   {}".format(rule.descr))
    print(" + {:<18}{}".format("muted", decision.get("muted")))
    print(" + {:<18}{}".format("mute_rule_id", decision.get("mute_rule_id")))
    print("\n   muted 是记录上的状态，不是入库开关 —— 被静默的告警照样入库")
    print("   窗口过了靠 mute.sweep() 把还没好的放出来，不能等日志驱动")
    return 0


def show_window(aggregator, event):
    """L6 的窗口怎么算的，以及恢复事件落到了谁的指纹上"""
    code = event.get("event_code", "")
    raise_code = event.get("raise_code") or ""
    window_sec = event.get("window_sec", "-")

    print("\n   指纹 = md5(ip | {} | alarm_object)".format(raise_code or code))
    if raise_code:
        print("   {} 是 {} 的恢复事件，所以按 {} 算指纹 —— "
              "否则关不掉故障告警".format(code, raise_code, raise_code))

    print("   窗口 {}s，比的是相邻两条日志的间隔，不是固定分桶的边界".format(window_sec))
    print("   同一段内再来一条就 count+1；间隔超过 {}s 开新段；"
          "一段最长活 1800s".format(window_sec))
    print("   （不再演示\"隔多久切新段\"——那需要一个干净的内存聚合器，"
          "现在这份 aggregator 连的是真库，不拿它做探测性调用）")

    print("\n   alarm_log 的攒批还在内存里，没调 flush()/persist() 不会真的落库")
    print("   alarm_list 本层不写 —— 阈值 {} 的判断是 L7 的事".format(
        event.get("threshold", "-")))
    return 0


def show_grade(attrs, event):
    """
    L5 第二步：定级。打出命中的规则和它凭什么命中

    级别按 (event_code, ip, sysname) 判，所以必须排在 L4 富化之后 ——
    sysname 是富化补的
    """
    event_code = event.get("event_code", "")
    ip = event.get("ip", "-")
    sysname = event.get("sysname", "-")

    print("\n--- L5 第二步 syslog_severity_rule 定级 ---")
    print("   判据 event_code={}  ip={}  sysname={}".format(event_code, ip, sysname))

    rule = attrs.grade_of(event_code, ip, sysname)
    if rule is None:
        print("   没命中任何规则，按 P3 兜底")
        print("   定级表缺 event_code='*' 的全局兜底行，补一条")
    else:
        judge = []
        if rule.event_code != "*":
            judge.append("event_code={}".format(rule.event_code))
        if rule.ip_pattern:
            judge.append("ip_reg={}".format(rule.ip_pattern))
        if rule.sysname_pattern:
            judge.append("sysname_reg={}".format(rule.sysname_pattern))
        print("   命中 rule {}  priority={}  判据 {}".format(
            rule.rule_id, rule.priority, "  ".join(judge) or "无（全局兜底）"))
        print("   {}".format(rule.descr))

    print(" + {:<18}{}（{}）".format("severity", event.get("severity"),
                                     event.get("severity_name", "-")))
    print(" + {:<18}{}".format("severity_rule_id", event.get("severity_rule_id", 0)))
    if event.get("state") == STATE_IGNORE:
        print(" + {:<18}{}".format(
            "state", "ignore —— 走完管线并落 ES，但 L7 不开告警"))
    return 0


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s %(message)s")
    raise SystemExit(main())
