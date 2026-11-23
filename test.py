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

WRITE_DB=False（默认）时**整条 L1~L9 都照常跑**，包括 L9 的 handle()，
只是各层内部的写库那一句被跳过（靠各层的 write_db 开关）。所以走的是
和线上一样的代码路径，能看到真实的动作判定和通知内容，不会污染生产库。
改成 True 才会真的往 alarm_log/alarm_list/syslog_alarm_state 写数据。

被 write_db 挡住的七个写库点：
    L2  syslog_black_list.hit_count      黑名单命中数
    L6  alarm_log 批量插入                原子日志
    L6  删 7 天前的 alarm_log             数据清理
    L7  syslog_alarm_state upsert         段状态持久化
    L8  syslog_mute_rule.hit_count        静默规则命中数
    L9  alarm_list insert                 新开告警
    L9  alarm_list update                 更新/恢复告警
规则表和设备表的**读取**不受影响 —— 不读就没规则可判。

回放真实日志文件走 main.py --replay。
"""
import logging

from pipeline.l1_prepare import prepare
from pipeline.l2_blacklist import BlacklistFilter
from pipeline.l3_parser import SyslogParser
from pipeline.l4_enrich import DeviceEnricher
from pipeline.l5_attrs import EventAttrs, severity_name, STATE_IGNORE
from pipeline import l6_aggregate
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
# alarm_log/alarm_list。确认过没问题、真要测落库效果时改成 True。
# 这个值在 build() 里传给有写库操作的五层（L2/L6/L7/L8/L9）的
# write_db 参数，不是在 test.py 里判断要不要调用那些层
WRITE_DB = False

# ============================================================
# 要跑的报文：ip 是源 IP，message 是原始报文，timestamp 是采集时间
# ============================================================
a = {
    "ip": "10.39.240.32",
    "message": '''Nov 20 16:25:24 2026 oob2_mdu11_prod_dc07_m01 %%10DEV/1/FAN STATE CHANGES TO FAILURE(t):-DevIP=10.39.240.32; Trap 1.3.6.1.4.1.25506.8.35.12.1.6<hh3cfanfailure>: fan ID is 1''',
    "timestamp": 1795163044,
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

    write_db=WRITE_DB 传给有写库操作的五层（L2/L6/L7/L8/L9）：
        WRITE_DB=False  规则照常从真库加载、判定照常跑，只是七个写库点
                        全部跳过（黑名单hit_count、alarm_log、删老日志、
                        syslog_alarm_state、静默hit_count、alarm_list的
                        insert/update）
        WRITE_DB=True   真的写进 MySQL
    L3/L4/L5 只读规则表和设备表，没有写库操作，不需要这个参数
    """
    rule_db = get_rule_db()
    device_db = get_device_db()
    alarm_db = get_alarm_db()

    sm = StateMachine(db=alarm_db, write_db=WRITE_DB)
    return (
        BlacklistFilter(refresh_interval=0, db=rule_db, write_db=WRITE_DB),
        SyslogParser(refresh_interval=0, db=rule_db, device_db=device_db),
        DeviceEnricher(db=device_db),
        EventAttrs(refresh_interval=0, db=rule_db),
        Aggregator(db=alarm_db, write_db=WRITE_DB),
        sm,
        MuteFilter(refresh_interval=0, db=alarm_db, write_db=WRITE_DB),
        AlarmEmitter(notifier=FileNotifier(), state_machine=sm, db=alarm_db,
                     write_db=WRITE_DB),
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
    if decision.get("ignored"):
        print("     定级规则判定不开告警（state=ignore）：落 alarm_list 留痕，不通知")
    elif not decision.get("notify"):
        print("     action={} —— 这一行没有新信息（段内累加、未到阈值、"
              "或重复的恢复）".format(decision.get("action")))
    elif decision.get("muted"):
        print("     告警会入库，但命中静默规则 {} 不发通知".format(
            decision.get("mute_rule_id")))
    else:
        print("     告警入库并发通知")
    return 0


def show_emit(emitter, decision):
    """
    L9：落库 + 通知

    不管 WRITE_DB 是什么都**真的调 emitter.handle()** —— 落不落库由
    AlarmEmitter 内部的 write_db 开关决定（build() 里传的）。这样走的是
    和线上完全一样的代码路径，能看到真实的动作判定、通知内容、统计计数，
    只是 WRITE_DB=False 时跳过那两句 SQL。

    以前这里是"WRITE_DB=False 就不调 handle()"，等于 L9 整层没被测到。
    """
    print("\n--- L9 emit 落库 + 通知 ---")
    if not decision.get("notify"):
        print("   action={} —— L7 判定不用处理，L9 没有动作".format(
            decision.get("action")))
        return 0

    result = emitter.handle(decision)
    print(" + {:<18}{}".format("alarm_id", result.get("alarm_id")))
    print(" + {:<18}{}".format("notified", result.get("notified")))
    print(" + {:<18}{}".format("muted", result.get("muted")))
    if WRITE_DB:
        print("\n   WRITE_DB=True，已经真的写进 MySQL 的 alarm_log/alarm_list 了。")
    else:
        print("\n   WRITE_DB=False，没有写库（alarm_id 是负数假 id）。")
        print("   通知照常输出到 logs/notify.log —— 对规则就看那个文件。")
        print("   把文件顶部 WRITE_DB 改成 True 才会真的写 alarm_log/alarm_list")
    print("   emitter stats:", emitter.stats())
    return 0


def show_decision(machine, decision):
    """L7 的决策：这条事件在本段那一行上做了什么"""
    print("\n--- L7 state_machine 段状态机 ---")
    for key in ("action", "notify", "write", "ignored", "state", "counter",
                "severity_name", "alarm_id"):
        if key in decision:
            print(" + {:<18}{}".format(key, decision[key]))

    if decision.get("ignored"):
        print("\n   定级规则判定不告警：照样按段落 alarm_list（status=5），不发通知")

    print("\n   一个窗口段 = alarm_list 的一行。判据是段的身份（L6 的")
    print("   first_seen）变没变，加上本段在 alarm_list 里有没有行 ——")
    print("   同段内不管来多少条日志、raise 还是 clear，都只有那一行")
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
    print("   status 跟着写 4（已屏蔽）—— 人工屏蔽就是 mute，不区分谁设的")
    print("   判窗口用的是这条告警的发生时间(ingest_ts)，判一次就定了，")
    print("   没有定时扫描回头改：窗口过了之后新产生的告警自然判出 muted=0")
    return 0


def show_window(aggregator, event):
    """L6 的窗口怎么算的，以及恢复事件落到了谁的指纹上"""
    code = event.get("event_code", "")
    raise_code = event.get("raise_code") or ""
    own_window = event.get("window_sec", "-")
    window_sec = event.get("segment_window_sec", own_window)

    print("\n   指纹 = md5(ip | {} | alarm_object)".format(raise_code or code))
    if raise_code:
        print("   {} 是 {} 的恢复事件，所以按 {} 算指纹 —— "
              "否则盖不到故障告警那一行上".format(code, raise_code, raise_code))

    print("   窗口 {}s，比的是相邻两条日志的间隔，不是固定分桶的边界".format(window_sec))
    if raise_code and own_window != window_sec:
        print("   （{} 自己配的是 {}s，但段是 {} 的段，按 {}s 算）".format(
            code, own_window, raise_code, window_sec))
    print("   同一段内再来一条就 count+1；间隔超过 {}s 开新段；"
          "一段最长活 max({}, {})s".format(
              window_sec, l6_aggregate.DEFAULT_MAX_LIFETIME, window_sec))
    print("   （不再演示\"隔多久切新段\"——那需要一个干净的内存聚合器，"
          "现在这份 aggregator 连的是真库，不拿它做探测性调用）")

    print("\n   first_seen={} 就是段的身份，L7 拿它定位 alarm_list 的行".format(
        event.get("first_seen", "-")))
    print("   alarm_log 的攒批还在内存里，没调 flush() 不会落库；")
    print("   而且 WRITE_DB={} —— flush() 里那句 SQL 也被 write_db 开关挡着".format(WRITE_DB))
    print("   alarm_list 本层不写 —— 阈值 {} 的判断是 L7 的事".format(
        event.get("segment_threshold", event.get("threshold", "-"))))
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
