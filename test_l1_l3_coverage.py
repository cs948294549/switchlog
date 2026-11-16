# -*- coding: utf-8 -*-
"""
L1-L3 解析覆盖率测试

把 logs/raw_packets.log* 逐条跑 L1(剥信封/mnemonic) -> L2(黑名单) ->
L3(匹配规则)，数据库走真实连接（db.get_rule_db() / db.get_device_db()，
和线上管线用的是同一个数据源），不做任何绕过或模拟。

跑完按结果分类计数，并对每条输出做字段契约检查（pipeline/__init__.py
里定义的 L1/L3 产出字段，缺字段或类型不对的打出来）。

用法：
    python3 test_l1_l3_coverage.py [日志文件 ...]
    不给参数时默认跑 logs/raw_packets.log 和 logs/raw_packets.log.2026-11-14
"""
import json
import os
import sys
import collections

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pipeline.l1_prepare import prepare
from pipeline.l2_blacklist import BlacklistFilter
from pipeline.l3_parser import SyslogParser
from db import get_rule_db, get_device_db


HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_LOG_FILES = [
    os.path.join(HERE, "logs", "raw_packets.log"),
    os.path.join(HERE, "logs", "raw_packets.log.2026-11-14"),
]

# L1 产出字段契约（pipeline/__init__.py）
L1_FIELDS = {
    "ingest_ts": int,
    "ip": str,
    "message": str,
    "hostname": str,
    "body": str,
    "mnemonic": str,
    "readable": bool,
}

# L3 产出字段契约，在 L1 基础上增量补
L3_FIELDS = {
    "vendor": str,
    "event_code": str,
    "alarm_object": str,
    "object_raw": str,
    "rule_id": int,
}

BOOTSTRAP_CODES = ("PARSE_FAIL", "UNMANAGED_SRC", "UNKNOWN_MNEMONIC")


def iter_raw_messages(paths):
    """
    逐行读取 raw_packets.log 格式：
        2026-11-15 00:00:00 10.32.98.16 {"...json..."}
    跳过 127.0.0.1（本机环回，不是网络设备，和 Config.drop_source_ips 的
    默认值一致，但这里在 L1 之前就跳过，不进统计——它不是"解析不了"，
    是"不该统计"）。
    """
    for path in paths:
        if not os.path.exists(path):
            print("!! 文件不存在，跳过: %s" % path, file=sys.stderr)
            continue
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                idx = line.find("{")
                if idx < 0:
                    continue
                try:
                    data = json.loads(line[idx:])
                except Exception:
                    continue
                ip = data.get("src_ip") or ""
                if ip == "127.0.0.1" or not ip:
                    continue
                message = data.get("message") or ""
                if not message:
                    continue
                yield ip, message


def check_fields(prepared, stage_name, field_spec, field_errors):
    """字段契约检查：缺字段 or 类型不对，记一条错误（按阶段+字段名去重计数）"""
    for field, expect_type in field_spec.items():
        if field not in prepared:
            field_errors[(stage_name, field, "缺字段")] += 1
            continue
        val = prepared[field]
        if not isinstance(val, expect_type):
            field_errors[(stage_name, field, "类型错: 期望%s实际%s" %
                           (expect_type.__name__, type(val).__name__))] += 1


def run(log_paths, top_n=100):
    rule_db = get_rule_db()
    device_db = get_device_db()

    blacklist = BlacklistFilter(refresh_interval=0, db=rule_db)
    parser = SyslogParser(refresh_interval=0, db=rule_db, device_db=device_db)

    print("已加载黑名单规则: %d 条" % blacklist.size())
    print("已加载匹配规则: %d 条" % parser.size())
    print()

    total = 0
    blocked = 0
    by_outcome = collections.Counter()
    field_errors = collections.Counter()

    unknown_by_vm = collections.Counter()
    unknown_sample = {}
    unmanaged_by_ip = collections.Counter()
    unmanaged_sample = {}
    parse_fail_samples = []

    for ip, message in iter_raw_messages(log_paths):
        total += 1
        prepared = prepare({"ip": ip, "message": message, "timestamp": 0})
        check_fields(prepared, "L1", L1_FIELDS, field_errors)

        if blacklist.blocked(prepared):
            blocked += 1
            by_outcome["L2_黑名单拦截"] += 1
            continue

        event = parser.parse(prepared)
        check_fields(event, "L3", L3_FIELDS, field_errors)

        code = event.get("event_code", "")

        if code == "PARSE_FAIL":
            by_outcome["PARSE_FAIL(信封都剥不出)"] += 1
            if len(parse_fail_samples) < 20:
                parse_fail_samples.append(message[:200])
            continue

        if code == "UNMANAGED_SRC":
            by_outcome["UNMANAGED_SRC(查不到vendor)"] += 1
            unmanaged_by_ip[ip] += 1
            unmanaged_sample.setdefault(ip, message[:200])
            continue

        if code == "UNKNOWN_MNEMONIC":
            by_outcome["UNKNOWN_MNEMONIC(有vendor但没规则)"] += 1
            mn = prepared.get("mnemonic") or "(剥不出mnemonic，走fuzzy也没命中)"
            key = (event.get("vendor") or "?", mn)
            unknown_by_vm[key] += 1
            unknown_sample.setdefault(key, message[:220])
            continue

        by_outcome["已匹配到规则(%s)" % code] += 1

    print("=" * 70)
    print("样本总量: %d 条（已跳过 127.0.0.1）" % total)
    if total == 0:
        print("没有样本，检查日志路径")
        return
    print("L2 黑名单拦截: %d 条 (%.1f%%)" % (blocked, 100.0 * blocked / total))
    print()
    print("-- 解析结果分布 --")
    matched = sum(v for k, v in by_outcome.items() if k.startswith("已匹配到规则"))
    unresolved = sum(v for k in BOOTSTRAP_CODES for kk, v in by_outcome.items()
                      if kk.startswith(k))
    for k, v in by_outcome.most_common():
        print("  %-42s %6d  (%.2f%%)" % (k, v, 100.0 * v / total))
    print()
    print("解析不了的合计（PARSE_FAIL + UNMANAGED_SRC + UNKNOWN_MNEMONIC）: "
          "%d 条 (%.1f%%)" % (unresolved, 100.0 * unresolved / total))

    print()
    print("=" * 70)
    print("字段契约检查（L1/L3 产出字段缺失或类型不对）：")
    print("=" * 70)
    if not field_errors:
        print("  全部通过，没有缺字段/类型错误")
    else:
        for (stage, field, reason), cnt in field_errors.most_common():
            print("  %-4s %-16s %-30s x%d" % (stage, field, reason, cnt))

    print()
    print("=" * 70)
    print("UNKNOWN_MNEMONIC 缺口清单（vendor, mnemonic）按量排序，前 %d：" % top_n)
    print("=" * 70)
    for (vendor, mn), cnt in unknown_by_vm.most_common(top_n):
        print("  %6d  vendor=%-10s mnemonic=%s" % (cnt, vendor, mn))
        sample = unknown_sample.get((vendor, mn))
        if sample:
            print("          样例: %s" % sample)

    if unmanaged_by_ip:
        print()
        print("=" * 70)
        print("UNMANAGED_SRC 的源 IP（devices 表查不到厂商）：")
        print("=" * 70)
        for ip, cnt in unmanaged_by_ip.most_common(30):
            print("  %6d  ip=%-16s 样例: %s" % (cnt, ip, unmanaged_sample.get(ip, "")[:120]))

    if parse_fail_samples:
        print()
        print("=" * 70)
        print("PARSE_FAIL 样例（信封都剥不出，最多列20条）：")
        print("=" * 70)
        for s in parse_fail_samples:
            print("  " + s)

    print()
    print("=" * 70)
    print("黑名单命中统计（哪条规则在吃量，hits=0 的要么没用上要么 pattern 写错）：")
    print("=" * 70)
    stats = blacklist.stats()
    for rule in stats.get("rules", []):
        if rule.get("hits", 0) > 0:
            print("  %6d  scope=%-9s pattern=%s" % (rule["hits"], rule["scope"], rule["pattern"]))


if __name__ == "__main__":
    paths = sys.argv[1:] if len(sys.argv) > 1 else DEFAULT_LOG_FILES
    run(paths)
