# -*- coding: utf-8 -*-
"""
schema.sql 种子数据 vs 线上库一致性校对

schema.sql 对四张规则表都是 DROP TABLE + CREATE + INSERT IGNORE 种子数据，
设计前提是"库由本文件重建"。本脚本反过来验证这个前提：把 schema.sql 里
的种子行解析出来，和线上实际数据逐表按唯一键比对，分三类报告：
    only_in_schema  schema 写了，线上没有（可能是本次改动忘了执行补丁）
    only_in_db      线上有，schema 没写（可能是手工改过库、没有回填成文件）
    diff            唯一键能对上，但其余字段的值不一样

只读，不改线上库任何数据。

用法：
    python3 test_schema_sync.py [schema.sql路径]
    不给参数时默认用 sql/schema.sql
"""
import os
import re
import sys
import collections

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from db.database import MySQLConnection

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_SCHEMA = os.path.join(HERE, "sql", "schema.sql")

# 表名 -> (INSERT 语句里的列名顺序由文件里实际写的决定，这里只声明
#          唯一键 和 要忽略的运行态字段)
TABLE_SPECS = {
    "syslog_black_list": {
        "unique_key": ("scope", "ip", "pattern"),
        "ignore_cols": ("rule_id", "hit_count", "last_hit_time", "update_time"),
        "query": "select * from syslog_black_list",
    },
    "syslog_rule": {
        "unique_key": ("vendor", "mnemonic", "match_type", "pattern", "body_match"),
        "ignore_cols": ("rule_id", "update_time"),
        "query": "select * from syslog_rule",
    },
    "syslog_event": {
        "unique_key": ("event_code",),
        "ignore_cols": ("update_time",),
        "query": "select * from syslog_event",
    },
    "syslog_severity_rule": {
        "unique_key": ("event_code", "ip_reg", "sysname_reg"),
        "ignore_cols": ("rule_id", "update_time"),
        "query": "select * from syslog_severity_rule",
    },
}


def strip_comments_keep_strings(sql_text):
    """去掉 `--` 行注释，但不破坏字符串内容（字符串里的 -- 不是注释）"""
    out = []
    i, n = 0, len(sql_text)
    in_str, str_char = False, ""
    while i < n:
        c = sql_text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(sql_text[i + 1])
                i += 2
                continue
            if c == str_char:
                in_str = False
            i += 1
            continue
        if c in ("'", '"'):
            in_str = True
            str_char = c
            out.append(c)
            i += 1
            continue
        if c == "-" and i + 1 < n and sql_text[i + 1] == "-":
            j = sql_text.find("\n", i)
            j = n if j == -1 else j
            out.append("\n")
            i = j
            continue
        out.append(c)
        i += 1
    return "".join(out)


def find_statement_end(s, start):
    """从 start 开始找语句真正结束的分号，忽略字符串/括号内的分号"""
    i, n = start, len(s)
    in_str, str_char, depth = False, "", 0
    while i < n:
        c = s[i]
        if in_str:
            if c == "\\" and i + 1 < n:
                i += 2
                continue
            if c == str_char:
                in_str = False
            i += 1
            continue
        if c in ("'", '"'):
            in_str = True
            str_char = c
            i += 1
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        elif c == ";" and depth == 0:
            return i
        i += 1
    return -1


def extract_tuples(block):
    """从 VALUES 之后的文本里切出每个 (...) 元组，忽略字符串内的括号"""
    tuples = []
    depth, start = 0, None
    in_str, str_char = False, ""
    i, n = 0, len(block)
    while i < n:
        c = block[i]
        if in_str:
            if c == "\\" and i + 1 < n:
                i += 2
                continue
            if c == str_char:
                in_str = False
            i += 1
            continue
        if c in ("'", '"'):
            in_str = True
            str_char = c
            i += 1
            continue
        if c == "(":
            if depth == 0:
                start = i
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0 and start is not None:
                tuples.append(block[start:i + 1])
                start = None
        i += 1
    return tuples


_FIELD_RE = re.compile(r"""\s*(?:'((?:[^'\\]|\\.)*)'|([^,()]+))\s*(?:,|$)""")


def parse_tuple(tuple_str):
    """把 '(a, b, c)' 拆成字段值列表，字符串字段去掉引号并反转义"""
    inner = tuple_str[1:-1]
    fields = []
    pos, n = 0, len(inner)
    while pos < n:
        m = _FIELD_RE.match(inner, pos)
        if not m:
            break
        if m.group(1) is not None:
            fields.append(m.group(1).replace("\\'", "'").replace('\\"', '"'))
        else:
            fields.append(m.group(2).strip())
        pos = m.end()
    return fields


def parse_schema_seed_rows(schema_path):
    """
    解析 schema.sql 里针对 TABLE_SPECS 四张表的 INSERT 种子数据。

    返回 {table_name: [dict, ...]}，dict 的 key 是该条 INSERT 语句显式写的
    列名（即 INSERT INTO table (col1, col2, ...) 里的那几列），没写的列
    （比如 rule_id 靠自增、update_time 靠触发器/代码补）不会出现在 dict 里。
    """
    raw = open(schema_path, "r", encoding="utf-8").read()
    clean = strip_comments_keep_strings(raw)

    tables = collections.defaultdict(list)
    pattern = re.compile(
        r"INSERT\s+(?:IGNORE\s+)?INTO\s+(\w+)\s*\(([^)]*)\)\s*VALUES\s*",
        re.IGNORECASE,
    )
    for m in pattern.finditer(clean):
        table = m.group(1)
        if table not in TABLE_SPECS:
            continue
        cols = [c.strip() for c in m.group(2).split(",")]
        end = find_statement_end(clean, m.end())
        if end < 0:
            raise ValueError("%s 的 INSERT 语句没找到结尾分号" % table)
        body = clean[m.end():end]
        for t in extract_tuples(body):
            fields = parse_tuple(t)
            if len(fields) != len(cols):
                raise ValueError(
                    "%s 一行字段数(%d)和列数(%d)不匹配: %s"
                    % (table, len(fields), len(cols), t[:120])
                )
            tables[table].append(dict(zip(cols, fields)))
    return tables


def normalize(value):
    """DB 驱动把数字类列读成 int，schema.sql 解析出来是字符串，统一转字符串比较"""
    if value is None:
        return ""
    return str(value)


def fetch_db_rows(table):
    with MySQLConnection() as conn:
        sql = TABLE_SPECS[table]["query"]
        conn.cursor.execute(sql)
        cols = [d[0] for d in conn.cursor.description]
        rows = conn.cursor.fetchall()
        return [dict(zip(cols, row)) for row in rows]


def row_key(row, unique_key):
    return tuple(normalize(row.get(k, "")) for k in unique_key)


def diff_table(table, schema_rows, db_rows):
    spec = TABLE_SPECS[table]
    unique_key = spec["unique_key"]
    ignore_cols = set(spec["ignore_cols"])

    schema_by_key = {}
    for row in schema_rows:
        key = row_key(row, unique_key)
        if key in schema_by_key:
            print("  !! schema.sql 内部唯一键重复: %s" % (key,))
        schema_by_key[key] = row

    db_by_key = {row_key(row, unique_key): row for row in db_rows}

    schema_keys = set(schema_by_key)
    db_keys = set(db_by_key)

    only_in_schema = schema_keys - db_keys
    only_in_db = db_keys - schema_keys
    common = schema_keys & db_keys

    field_diffs = []
    for key in common:
        srow, drow = schema_by_key[key], db_by_key[key]
        # 只比较 schema.sql 这条语句里显式写了的列，且不是忽略列
        cols_to_check = [c for c in srow.keys() if c not in ignore_cols and c not in unique_key]
        for col in cols_to_check:
            sval = normalize(srow.get(col, ""))
            dval = normalize(drow.get(col, ""))
            if sval != dval:
                field_diffs.append((key, col, sval, dval))

    return only_in_schema, only_in_db, field_diffs, schema_by_key, db_by_key


def run(schema_path):
    print("解析 schema.sql 种子数据: %s" % schema_path)
    schema_tables = parse_schema_seed_rows(schema_path)
    for table in TABLE_SPECS:
        print("  %-24s schema.sql 中 %d 行" % (table, len(schema_tables.get(table, []))))
    print()

    any_diff = False

    for table in TABLE_SPECS:
        print("=" * 70)
        print("表: %s" % table)
        print("=" * 70)

        schema_rows = schema_tables.get(table, [])
        db_rows = fetch_db_rows(table)
        print("  schema.sql: %d 行    线上库: %d 行" % (len(schema_rows), len(db_rows)))

        only_in_schema, only_in_db, field_diffs, schema_by_key, db_by_key = diff_table(
            table, schema_rows, db_rows
        )

        unique_key = TABLE_SPECS[table]["unique_key"]

        if only_in_schema:
            any_diff = True
            print("\n  -- schema.sql 有、线上库没有 (%d 条，补丁没执行？) --" % len(only_in_schema))
            for key in sorted(only_in_schema):
                print("    %s -> %s" % (dict(zip(unique_key, key)), schema_by_key[key]))

        if only_in_db:
            any_diff = True
            print("\n  -- 线上库有、schema.sql 没写 (%d 条，手工改过库？) --" % len(only_in_db))
            for key in sorted(only_in_db):
                row = db_by_key[key]
                print("    %s -> %s" % (dict(zip(unique_key, key)), row))

        if field_diffs:
            any_diff = True
            print("\n  -- 唯一键一致但字段值不同 (%d 处) --" % len(field_diffs))
            for key, col, sval, dval in field_diffs:
                print("    %s  字段=%-14s schema=%r  线上=%r" %
                      (dict(zip(unique_key, key)), col, sval, dval))

        if not only_in_schema and not only_in_db and not field_diffs:
            print("  一致，没有差异")
        print()

    print("=" * 70)
    if any_diff:
        print("结论: schema.sql 和线上库不一致，看上面各表的差异明细")
    else:
        print("结论: schema.sql 和线上库完全一致")
    print("=" * 70)
    return any_diff


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_SCHEMA
    has_diff = run(path)
    sys.exit(1 if has_diff else 0)
