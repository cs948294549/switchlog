# -*- coding: utf-8 -*-
"""
拿样本报文跑一遍管线，逐条对 (event_code, object)

链路是 L0 prepare -> L0.5 黑名单 -> L1 解析 -> L2 富化 -> L2.5 事件属性：
mnemonic 在 prepare 里剥一次，黑名单和 parser 共用；黑名单命中的直接丢，不进 parser。
L2 按源 IP 查 devices 补 sysname/hardware/syscontact(资产号)，查 ports 补接口描述。
L2.5 按 event_code 查 syslog_event 补 severity/state/窗口/clear_code。

数据全部来自 tests/fixtures.py 的内存表，不连 MySQL，也不看 config.use_mock_db。

跑：
    cd projects/switchlog
    python test.py                   # 全部样本
    python test.py -v                # 多打 L2 富化 / L2.5 属性 / 指纹收敛 / 黑名单四张表
    python test.py dc05              # 只跑 bbs1_dc05_m01_new 那段现场日志
    python test.py black             # 只跑黑名单的拦/放判定
    python test.py 10.16.249.5       # 位置参数当源 IP 过滤
    python test.py -i "2026 Nov  4 00:13:08.109 sw %ETHPORT-5-IF_UP: ..."

样本带期望值，对不上打 FAIL，退出码非 0，规则表改动后可以直接当回归用。
自己贴的报文没有期望值，判定列是 "-"，只看解析结果。

回放真实日志文件走 main.py：
    python main.py --replay syslog/xxx.txt --ip 10.16.249.5
"""
import sys
import hashlib
import logging

from pipeline.prepare import prepare
from pipeline.blacklist import BlacklistFilter
from pipeline.parser import SyslogParser
from pipeline.enrich import DeviceEnricher
from pipeline.attrs import EventAttrs
from pipeline.runner import Runner
from tests.mock_db import MockSyslogDB
from tests.fixtures import (
    MOCK_MESSAGES_ALL, MOCK_MESSAGES_DC05, MOCK_MESSAGES_BLACK
)

logger = logging.getLogger(__name__)

MSG_WIDTH = 96

# 黑名单拦掉的日志不进 parser，event_code 列显示这个
BLOCKED = "(blacklist)"


def build(**kwargs):
    """
    建一条完整的 L0 ~ L2.5 链路，各层共用同一个 mock 库。

    refresh_interval=0：不起刷新线程，规则只加载一次
    enricher 用默认 TTL：同一台设备只查一次库，和线上行为一致
    """
    db = MockSyslogDB(**kwargs)
    blacklist = BlacklistFilter(refresh_interval=0, db=db)
    parser = SyslogParser(refresh_interval=0, db=db)
    enricher = DeviceEnricher(db=db)
    attrs = EventAttrs(refresh_interval=0, db=db)
    runner = Runner(blacklist=blacklist, parser=parser, enricher=enricher, attrs=attrs)
    return blacklist, runner, db


def fingerprint_of(ip, event_code, alarm_object):
    """L4 指纹，这里只为看收敛效果，真实计算在 aggregate.py"""
    key = "{}|{}|{}".format(ip or "-", event_code or "-", alarm_object or "-")
    return hashlib.md5(key.encode("utf-8")).hexdigest()


def shorten(text, width=MSG_WIDTH):
    text = str(text or "").replace("\n", " ").replace("\r", " ")
    return text if len(text) <= width else text[:width - 3] + "..."


def run(messages=None, verbose=False, blacklist=None, runner=None):
    """
    逐条走链路并打表

    :param messages: [(ip, msg)] 或 [(ip, msg, want_code, want_object)]
    :return: {"total", "failed", "blocked", "rows"}
    """
    if blacklist is None or runner is None:
        blacklist, runner, _ = build()
    messages = messages if messages is not None else MOCK_MESSAGES_ALL
    rows = []
    failed = 0
    blocked_count = 0

    for item in messages:
        ip, message = item[0], item[1]
        want_code = item[2] if len(item) > 2 else None
        want_object = item[3] if len(item) > 3 else None

        event = runner.handle({"ip": ip, "message": message, "timestamp": 1762800000})
        if event is None:
            blocked_count += 1
            row = _blocked_row(ip, message, blacklist)
        else:
            row = _event_row(ip, message, event)

        # 没给期望值就只看结果，不判定
        if want_code is None:
            row["ok"] = None
        else:
            row["ok"] = (row["event_code"] == want_code and row["object"] == want_object)
            if not row["ok"]:
                failed += 1
        row["want_code"] = want_code
        row["want_object"] = want_object
        # 行号跟着行走，收敛表过滤掉被拦的行之后编号仍对得上主表
        row["line"] = len(rows) + 1
        rows.append(row)

    _print_rows(rows, verbose=verbose)
    if verbose:
        # 被拦的不参与指纹收敛，它们根本没进告警链路
        _print_groups([row for row in rows if not row["blocked"]])
        _print_l2(rows)
        _print_attrs(rows)
        _print_blacklist(blacklist)

    checked = len([row for row in rows if row["ok"] is not None])
    print("\n样本 {} 条，黑名单拦 {} 条，判定 {} 条，FAIL {} 条".format(
        len(rows), blocked_count, checked, failed))
    return {"total": len(rows), "failed": failed, "blocked": blocked_count, "rows": rows}


def _blocked_row(ip, message, blacklist):
    """被拦的日志：从黑名单规则里取命中的那一条，没有上下文可补"""
    rule = blacklist.match({"ip": ip, "message": message})
    return {
        "ip": ip, "msg": message, "object": "-", "event_code": BLOCKED,
        "vendor": "-", "rule_id": rule.rule_id if rule else 0,
        "blocked": True,
        "black_pattern": "{}={}".format(rule.scope, rule.pattern) if rule else "",
        "sysname": "-", "hardware": "-", "syscontact": "-",
        "if_name": "", "if_alias": "", "src_state": "",
        "severity": "", "severity_name": "", "state": "", "object_type": "",
        "clear_code": "",
    }


def _event_row(ip, message, event):
    return {
        "ip": ip, "msg": message,
        "object": event.get("alarm_object", "-"),
        "event_code": event.get("event_code", ""),
        "vendor": event.get("vendor", ""),
        "rule_id": event.get("rule_id", 0),
        "blocked": False,
        "black_pattern": "",
        # L2 补的
        "sysname": event.get("sysname", "-"),
        "hardware": event.get("hardware", "-"),
        "syscontact": event.get("syscontact", "-"),
        "if_name": event.get("if_name", ""),
        "if_alias": event.get("if_alias", ""),
        "src_state": event.get("src_state", ""),
        # L2.5 补的
        "severity": event.get("severity", ""),
        "severity_name": event.get("severity_name", ""),
        "state": event.get("state", ""),
        "object_type": event.get("object_type", ""),
        "clear_code": event.get("clear_code", ""),
        "window_sec": event.get("window_sec", ""),
        "threshold": event.get("threshold", ""),
    }


def _print_rows(rows, verbose=False):
    """主表：ip / msg / object / event_code，-v 多给 severity 和命中的规则"""
    print("\n== 管线解析结果 ==")
    if verbose:
        header = "{:<4}{:<14}{:<8}{:<22}{:<26}{:<18}{:<6}{}".format(
            "#", "ip", "vendor", "event_code", "object", "severity", "rule", "判定")
    else:
        header = "{:<4}{:<14}{:<" + str(MSG_WIDTH + 2) + "}{:<18}{:<22}{}"
        header = header.format("#", "ip", "msg", "object", "event_code", "判定")
    print(header)
    print("-" * len(header))

    for num, row in enumerate(rows, 1):
        if row["ok"] is None:
            mark = "-"
        elif row["ok"]:
            mark = "ok"
        else:
            mark = "FAIL 期望 {} / {}".format(row["want_code"], row["want_object"])
        if row["blocked"]:
            mark = "拦截 " + mark if mark != "-" else "拦截"

        if verbose:
            code = row["event_code"]
            if row["black_pattern"]:
                code = "{}[{}]".format(code, row["black_pattern"])
            print("{:<4}{:<14}{:<8}{:<22}{:<26}{:<18}{:<6}{}".format(
                num, row["ip"], row["vendor"] or "-", shorten(code, 20),
                shorten(row["object"], 24), row["severity_name"] or "-",
                row["rule_id"], mark))
        else:
            fmt = "{:<4}{:<14}{:<" + str(MSG_WIDTH + 2) + "}{:<18}{:<22}{}"
            print(fmt.format(num, row["ip"], shorten(row["msg"]),
                             shorten(row["object"], 16), row["event_code"], mark))


def _print_groups(rows):
    """按 md5(ip|event_code|object) 收敛，看同一故障的几条日志是否落到一个桶"""
    groups = {}
    for row in rows:
        fingerprint = fingerprint_of(row["ip"], row["event_code"], row["object"])
        key = "{}|{}|{}".format(row["ip"], row["event_code"], row["object"])
        bucket = groups.setdefault(fingerprint, {"key": key, "lines": []})
        bucket["lines"].append(row.get("line", 0))

    print("\n== L4 指纹收敛 md5(ip|event_code|object) ==")
    print("{:<20}{:<56}{:<7}{}".format("fingerprint", "ip|event_code|object", "count", "命中行"))
    for fingerprint, bucket in sorted(groups.items(), key=lambda kv: -len(kv[1]["lines"])):
        print("{:<20}{:<56}{:<7}{}".format(
            fingerprint[:18], shorten(bucket["key"], 54), len(bucket["lines"]),
            ",".join(str(i) for i in bucket["lines"])))
    print("\n共 {} 个指纹".format(len(groups)))


def _print_l2(rows):
    """L2 富化结果：哪台设备、什么硬件、资产号、接口描述"""
    enriched = [row for row in rows if not row["blocked"]]
    if not enriched:
        return

    print("\n== L2 富化 devices + ports ==")
    print("{:<4}{:<14}{:<22}{:<18}{:<14}{:<10}{:<18}{:<26}".format(
        "#", "ip", "sysname", "hardware", "syscontact", "src_state",
        "object", "if_name / if_alias"))
    for row in enriched:
        port_text = "-"
        if row["if_name"]:
            port_text = row["if_name"]
            if row["if_alias"]:
                port_text += " / " + row["if_alias"]
        elif row["object"] not in ("-", ""):
            port_text = "(接口表里没有)"
        print("{:<4}{:<14}{:<22}{:<18}{:<14}{:<10}{:<18}{:<26}".format(
            row["line"], row["ip"], shorten(row["sysname"], 20),
            shorten(row["hardware"], 16), shorten(row["syscontact"], 12),
            row["src_state"] or "-", shorten(row["object"], 16),
            shorten(port_text, 24)))

    # 设备维度的汇总：一条日志一个设备，重复的行只算一次
    devices = {}
    for row in enriched:
        devices.setdefault(row["ip"], row)
    unmanaged = [ip for ip, row in devices.items() if row["src_state"] != "MANAGED"]
    # 对象是接口但接口表里查不到的，要么表没采到，要么短名展开没覆盖这种写法
    missed = [row for row in enriched
              if row["object"] not in ("-", "") and not row["if_name"]]
    print("\n涉及设备 {} 台，其中未纳管 {} 台{}".format(
        len(devices), len(unmanaged),
        "：" + ", ".join(sorted(unmanaged)) if unmanaged else ""))
    if missed:
        print("接口表里对不上的对象 {} 条（peer IP 这类非接口对象属正常）：{}".format(
            len(missed),
            ", ".join(sorted({row["object"] for row in missed}))))


def _print_attrs(rows):
    """L2.5 事件属性：有没有事件码在 syslog_event 里是空的"""
    enriched = [row for row in rows if not row["blocked"]]
    if not enriched:
        return

    codes = {}
    for row in enriched:
        code = row["event_code"]
        if code not in codes:
            codes[code] = row

    print("\n== L2.5 事件属性 syslog_event ==")
    print("{:<24}{:<8}{:<12}{:<14}{:<8}{:<10}{}".format(
        "event_code", "级别", "state", "object_type", "窗口", "阈值", "恢复码"))
    for code, row in sorted(codes.items()):
        print("{:<24}{:<8}{:<12}{:<14}{:<8}{:<10}{}".format(
            shorten(code, 22), row["severity_name"] or "-",
            row["state"] or "-", row["object_type"] or "-",
            row.get("window_sec", "-"), row.get("threshold", "-"),
            row["clear_code"] or "-"))


def _print_blacklist(blacklist):
    """哪条黑名单在吃量。hits=0 的要么没用上，要么 pattern 写错了"""
    stats = blacklist.stats()
    print("\n== L0.5 黑名单命中 ==")
    print("{:<6}{:<10}{:<16}{:<40}{:<7}{}".format(
        "rule", "scope", "ip", "pattern", "hits", "说明"))
    for rule in stats["rules"]:
        print("{:<6}{:<10}{:<16}{:<40}{:<7}{}".format(
            rule["rule_id"], rule["scope"], rule["ip"], shorten(rule["pattern"], 38),
            rule["hits"], shorten(rule["descr"], 40)))
    print("\n进 {} 条，拦 {} 条，放行 {} 条；索引 mnemonic {} 条 / 全文扫 {} 条".format(
        stats["total"], stats["blocked"], stats["passed"],
        stats["mnemonic_rules"], stats["message_rules"]))


def run_blacklist(messages=None, verbose=True):
    """
    单测黑名单：样本的第三个字段是"该不该被拦"的布尔值

    误拦比漏拦更要紧，所以两个方向都判：该拦的没拦住是漏，
    不该拦的拦了是误拦，后者会把真告警吃掉。
    """
    blacklist, runner, _ = build()
    del runner  # 只跑黑名单，不需要后续层
    messages = messages if messages is not None else MOCK_MESSAGES_BLACK
    rows = []
    failed = 0

    for ip, message, want_blocked in messages:
        prepared = prepare({"ip": ip, "message": message})
        rule = blacklist.match(prepared)
        is_blocked = rule is not None
        if is_blocked:
            blacklist.blocked(prepared)
        ok = (is_blocked == bool(want_blocked))
        if not ok:
            failed += 1
        rows.append({
            "ip": ip, "msg": message, "blocked": is_blocked,
            "mnemonic": prepared["mnemonic"],
            "rule_id": rule.rule_id if rule else 0,
            "scope": rule.scope if rule else "",
            "pattern": rule.pattern if rule else "",
            "want_blocked": bool(want_blocked), "ok": ok,
        })

    print("\n== L0.5 黑名单判定 ==")
    print("{:<4}{:<14}{:<44}{:<6}{:<10}{:<34}{}".format(
        "#", "ip", "mnemonic", "rule", "scope", "命中 pattern", "判定"))
    for num, row in enumerate(rows, 1):
        if row["ok"]:
            mark = "ok 拦截" if row["blocked"] else "ok 放行"
        else:
            mark = "FAIL 误拦" if row["blocked"] else "FAIL 漏拦"
        print("{:<4}{:<14}{:<44}{:<6}{:<10}{:<34}{}".format(
            num, row["ip"], shorten(row["mnemonic"] or "(无)", 42),
            row["rule_id"] or "-", row["scope"] or "-",
            shorten(row["pattern"] or "-", 32), mark))

    if verbose:
        _print_blacklist(blacklist)

    print("\n样本 {} 条，FAIL {} 条".format(len(rows), failed))
    return {"total": len(rows), "failed": failed, "rows": rows}


def main(argv=None):
    argv = list(argv if argv is not None else sys.argv[1:])
    verbose = False
    for flag in ("-v", "--verbose"):
        if flag in argv:
            verbose = True
            argv.remove(flag)

    # -i 自己贴一条报文，第二个参数给源 IP（默认用样本里的 cisco_nx 设备）
    if argv and argv[0] in ("-i", "--input"):
        message = argv[1] if len(argv) > 1 else ""
        ip = argv[2] if len(argv) > 2 else "10.16.249.5"
        run([(ip, message)], verbose=True)
        return 0

    # dc05 只跑那段现场日志
    if argv and argv[0] == "dc05":
        result = run(MOCK_MESSAGES_DC05, verbose=True)
        return 1 if result["failed"] else 0

    # black 只跑黑名单的拦/放判定
    if argv and argv[0] == "black":
        result = run_blacklist(verbose=True)
        return 1 if result["failed"] else 0

    # 位置参数当 IP 过滤
    if argv:
        wanted = set(argv)
        messages = [item for item in MOCK_MESSAGES_ALL if item[0] in wanted]
        if not messages:
            print("没有匹配 {} 的样本，样本里的源 IP：{}".format(
                ", ".join(sorted(wanted)),
                ", ".join(sorted({item[0] for item in MOCK_MESSAGES_ALL}))))
            return 2
        result = run(messages, verbose=verbose)
    else:
        result = run(verbose=verbose)

    return 1 if result["failed"] else 0


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s %(message)s")
    raise SystemExit(main())
