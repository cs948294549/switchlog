---
name: triage-syslog-gap
description: "处理用户贴来的 switchlog 原始日志（PARSE_FAIL / UNKNOWN_MNEMONIC，或已知事件码但 object 提取错误）。判断该拉黑、并入已有 event_code，还是新建 event_code，并在 sql/schema.sql 落地改动、生成对应 patch_*.sql。适用于用户贴一段原始 syslog 行、说"处理一下"/"加规则"/"屏蔽"/"合并到 XXX"之类请求的场景。"
---

# 处理 switchlog 日志缺口

用户会贴一段或几段原始 syslog（人工巡检/脚本扫描发现的 PARSE_FAIL、
UNKNOWN_MNEMONIC，或者已经有规则但告警对象提取错了），要求屏蔽、配
规则、合并到某个事件码，或者只是问"这条怎么处理"。这是本仓库里反复
出现的高频任务，流程已经走过很多轮，本技能把套路固化下来。

## 第一步：判断日志性质

不要看到日志就假设它该被拉黑或该被定级为告警。先分类：

1. **设备标准行为/操作留痕** —— 重启自检（风扇/电源OK、板卡上线）、
   配置操作记录（退出配置模式、命令执行留痕）、协议标准生命周期行为
   （OSPF LSA MaxAge、SSH登录成功）。这类拉黑。
2. **已有 event_code 的新写法** —— 同一类故障（端口down/up、MAC漂移、
   电源故障）在不同厂商/不同固件版本下的另一种 mnemonic。这类并入
   已有 event_code，不新建。
3. **全新的故障/风险信号** —— 认证服务器无响应、VLAN被挂起、丢包超
   阈值、设备主动重启。这类新建 event_code。
4. **已有规则但提取错了对象** —— 常见原因是 object_regex 依赖了不稳
   定的锚点（比如用冒号定位，被信封里的裸冒号或 mnemonic 自己的冒
   号抢先命中）。这类修 object_regex，不是新建规则。

拿不准该分到哪一类、或者要推翻之前记录过的"故意保留"决定时，用
AskUserQuestion 问，不要自己替用户决定。参考本仓库里发生过的真实案例：
- `SHELL/4/SHELL_CMD_MATCHFAIL` 曾被明确列为"故意不拦的安全审计信号"，
  后来用户要求连它也屏蔽——这种推翻已有决定的操作要先确认，不要因为
  用户说了"其余屏蔽"就默认包含进去。
- MAC_FLAP 和 MAC_FLAP_SUPPRESS 的合并：两者 object_type 不同（mac vs
  interface），"合并"有好几种做法（改 event_code / 废弃其中一个 /
  先讨论对象类型怎么处理），要问清楚具体怎么合并，不要自己选一种。

## 第二步：排查前先确认是否重复

```bash
grep -n "候选mnemonic或event_code" sql/schema.sql
```

同一类日志可能已经配过规则但配错了（比如 mnemonic 应该非空却填了
空串走fuzzy），或者已经被拉黑过。改之前先搜一遍，不要重复造规则。

## 第三步：验证 mnemonic 剥取结果，不要凭读日志猜

`pipeline/l1_prepare.py` 的 `strip_mnemonic()` 有几个已知坑：
- FAC/模块段带中划线（如 `FWM-ETH`、`TAHUSD-SLOT1`）在不同正则分支
  下表现不同，有的能剥出来有的不能，必须实测，不能凭字面判断。
- 斜杠最后一段碰到空格会截断（如 `DEV/1/FAN STATE CHANGES TO
  FAILURE` 实际剥出来是 `DEV/1/FAN`，要靠 `body_match` 消歧）。
- 时间戳格式认不出时 `readable=False`，直接判 PARSE_FAIL，根本进不
  到 L2/L3，配了规则也没用。

验证方法：把 `MNEMONIC_REGS`/`TS_REGS` 的正则复制到一次性 Python 脚本
里，拿真实样本跑一遍，不要用 Read 工具读代码之后口头推理。例如：

```python
import re
MNEMONIC_REGS = (
    re.compile(r"%{1,2}([A-Za-z][A-Za-z0-9_]*(?:-[A-Za-z][A-Za-z0-9_]*)?-\d+-[A-Za-z0-9_\-]+)\s*:"),
    re.compile(r"%{1,2}\d{0,2}([A-Za-z][A-Za-z0-9_\-]*(?:/\d+)?/[A-Za-z0-9_\-]+)"),
    re.compile(r"\blogid=\"?(\d+)\"?"),
)
def strip_mnemonic(body):
    for reg in MNEMONIC_REGS:
        m = reg.search(body)
        if m:
            return m.group(1)
    return ""
print(strip_mnemonic("用户贴的那条日志原文"))
```

如果剥出来是空串，配 `match_type='contains'` 的 fuzzy 规则（`mnemonic`
留空）。如果剥出来非空，必须配 `match_type='exact'` 并填完整 mnemonic——
**配成 `mnemonic=''` 但实际剥取结果非空是一个真实发生过的 bug**
（`l3_parser.py` 的 `_pick()` 逻辑是 mnemonic 非空就只查 exact 表，完全
不碰 fuzzy 表，配错了规则会直接哑火、从未生效过）。

修 `l1_prepare.py` 正则本身（改字符集收中划线、加时间戳格式分支）属于
全量热路径改动，必须用现存 `logs/raw_packets.log*` 全量回归，确认
**零退化**（没有任何已有 mnemonic 的剥取结果被改变）才能改，参见本
仓库 `TS_REGS` 和 `MNEMONIC_REGS` 两次改动的验证方式（统计旧/新结果
`readable`/mnemonic 不一致的条数，逐条人工看差异是否合理）。

## 第四步：设计 object_regex 时用真实样本验证，不要只读一眼就写正则

正则容易在以下场景出错，写完必须拿真实样本跑一遍 `re.search`：
- 依赖冒号/逗号等不稳定锚点定位，而正文里 mnemonic 本身或信封杂质
  也带同样的分隔符，会被提前命中（真实案例：`ETH_PORT_CHANNEL-5-
  FOP_CHANGED` 原来用 `':\s+(\S+?):'`抽 LAG 名，遇到带前导裸冒号的
  报文时把 alarm_object 抽成了 mnemonic 自己）。
- 优先考虑直接匹配固定词形（如 `port-channel\d+`、`Interface\s+
  ([^\s,(]+)`），比"数第N个分隔符"更稳。

## 第五步：落地到 sql/schema.sql

- 新建 event_code 放 `syslog_event` 的 INSERT 块里，参考现有同类事件
  的 `state`/`object_type`/`window_sec` 设计（有稳定恢复日志配
  raise/clear 对；没有就配 stateless）。
- 需要单独定级就加 `syslog_severity_rule` 一行；不需要就让它走全局
  兜底 P3，不用专门配。
- L3 匹配规则加进 `syslog_rule` 对应 INSERT 块，靠近同厂商/同族规则
  放，并写注释说明判断依据（为什么归这个 event_code、为什么这样提
  对象）。
- 黑名单加进 `syslog_black_list`，`scope='mnemonic'` 优先（dict 精确
  命中，便宜），只有 mnemonic 剥不出来时才用 `scope='message'`（全
  文子串线性扫，这一串要保持小，参考文件里"这一串要保持小"的注释）。
- 改动前后都记一下是否推翻了已有决定，推翻的话把原注释里的描述一起
  改掉（比如"故意不拦的13条"要改成"12条"并写明为什么撤销）。

## 第六步：语法 + 唯一键校验（本地没有数据库连接，必须用脚本模拟）

项目用 `pymysql`，但本机环境通常没装这个包，不能直接连库跑
`test_schema_sync.py`。改完 `sql/schema.sql` 后用下面这段脚本（已经
在本仓库多次验证可用，处理好了字符串内的括号/引号/中文括号/`--` 行
注释，不要用简单的 `str.count('(')` 之类的朴素统计，会被正文里的英文
括号干扰）校验：

```python
import re, collections

def strip_comments_keep_strings(sql_text):
    out = []
    i, n = 0, len(sql_text)
    in_str, str_char = False, ""
    while i < n:
        c = sql_text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(sql_text[i + 1]); i += 2; continue
            if c == str_char: in_str = False
            i += 1; continue
        if c in ("'", '"'):
            in_str = True; str_char = c; out.append(c); i += 1; continue
        if c == "-" and i + 1 < n and sql_text[i + 1] == "-":
            j = sql_text.find("\n", i); j = n if j == -1 else j
            out.append("\n"); i = j; continue
        out.append(c); i += 1
    return "".join(out)

def find_statement_end(s, start):
    i, n = start, len(s)
    in_str, str_char, depth = False, "", 0
    while i < n:
        c = s[i]
        if in_str:
            if c == "\\" and i + 1 < n: i += 2; continue
            if c == str_char: in_str = False
            i += 1; continue
        if c in ("'", '"'): in_str = True; str_char = c; i += 1; continue
        if c == "(": depth += 1
        elif c == ")": depth -= 1
        elif c == ";" and depth == 0: return i
        i += 1
    return -1

def extract_tuples(block):
    tuples = []
    depth, start = 0, None
    in_str, str_char = False, ""
    i, n = 0, len(block)
    while i < n:
        c = block[i]
        if in_str:
            if c == "\\" and i + 1 < n: i += 2; continue
            if c == str_char: in_str = False
            i += 1; continue
        if c in ("'", '"'): in_str = True; str_char = c; i += 1; continue
        if c == "(":
            if depth == 0: start = i
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0 and start is not None:
                tuples.append(block[start:i+1]); start = None
        i += 1
    return tuples

_FIELD_RE = re.compile(r"""\s*(?:'((?:[^'\\]|\\.)*)'|([^,()]+))\s*(?:,|$)""")
def parse_tuple(tuple_str):
    inner = tuple_str[1:-1]
    fields = []
    pos, n = 0, len(inner)
    while pos < n:
        m = _FIELD_RE.match(inner, pos)
        if not m: break
        if m.group(1) is not None:
            fields.append(m.group(1).replace("\\'", "'").replace('\\"', '"'))
        else:
            fields.append(m.group(2).strip())
        pos = m.end()
    return fields

TABLES = {"syslog_black_list", "syslog_rule", "syslog_event", "syslog_severity_rule"}
raw = open("sql/schema.sql", encoding="utf-8").read()
clean = strip_comments_keep_strings(raw)
tables = collections.defaultdict(list)
pattern = re.compile(r"INSERT\s+(?:IGNORE\s+)?INTO\s+(\w+)\s*\(([^)]*)\)\s*VALUES\s*", re.IGNORECASE)
for m in pattern.finditer(clean):
    table = m.group(1)
    if table not in TABLES: continue
    cols = [c.strip() for c in m.group(2).split(",")]
    end = find_statement_end(clean, m.end())
    body = clean[m.end():end]
    for t in extract_tuples(body):
        fields = parse_tuple(t)
        if len(fields) != len(cols):
            print("!! 字段数不匹配", table, len(fields), len(cols), t[:100]); continue
        tables[table].append(dict(zip(cols, fields)))

for t, rows in tables.items():
    print(t, len(rows))

# 各表唯一键按需替换检查：
# syslog_black_list: (scope, ip, pattern)
# syslog_rule:        (vendor, mnemonic, match_type, pattern, body_match)
# syslog_event:       (event_code,)
# syslog_severity_rule: (event_code, ip_reg, sysname_reg)
black = tables["syslog_black_list"]
bkeys = [(r["scope"], r["ip"], r["pattern"]) for r in black]
print("黑名单唯一键冲突:", {k: v for k, v in collections.Counter(bkeys).items() if v > 1} or "无")

rules = tables["syslog_rule"]
rkeys = [(r["vendor"], r["mnemonic"], r["match_type"], r["pattern"], r["body_match"]) for r in rules]
print("syslog_rule唯一键冲突:", {k: v for k, v in collections.Counter(rkeys).items() if v > 1} or "无")
```

跑完确认：新增的规则/黑名单条目都能在对应表里查到，没有唯一键冲突，
行数变化符合预期（改 UPDATE 类的不增行数，INSERT 类的按条数增加）。

## 第七步：生成独立 patch 文件

`sql/schema.sql` 是整库重建脚本（`DROP TABLE` + `CREATE` + 种子数据），
已部署的线上库不能重新跑它，要生成一个独立的 `sql/patch_<日期>_<简述>.sql`
给线上库用增量方式应用。命名规律：`patch_YYYYMMDD_主题.sql`。

模板结构（抄本仓库任意一个现有 `patch_*.sql` 的头部注释风格）：

```sql
-- ============================================================
-- 补丁：<一句话描述改了什么>
--
-- 现网样例：
--   <贴用户给的原始日志，带时间戳和设备名>
--
-- <为什么这么处理：判断依据、和哪条已有规则同族、有没有推翻过去的决定>
--
--     mysql -h <host> -P <port> -u netops -p netops < sql/patch_xxx.sql
--
-- 和 schema.sql 的关系：内容已折进 schema.sql。
--   * 库是用 schema.sql 重建的 -> 不用执行本补丁
--   * 库里有数据要保留、不能重建 -> 执行本补丁
-- ============================================================
USE netops;

-- INSERT IGNORE / UPDATE / DELETE 语句，和 schema.sql 里的改动完全对应

-- ============================================================
-- 执行后自查
-- ============================================================
-- 对应的 SELECT 语句，验证改动生效
-- 规则表由各层定时刷新，默认 300 秒一轮，等一轮或重启进程
```

**代码+SQL联动的改动**（比如改了 `l1_prepare.py` 的正则，同时也要改
`syslog_rule` 从 fuzzy 改成 exact）必须在 patch 注释里写清楚部署顺序，
并解释反过来执行会造成什么后果（本仓库真实案例：先执行 SQL 补丁再部
署代码的话，中间会有一段时间两边都查不到规则，比改之前更差）。

## 第八步：记录遗留问题，不要顺手处理超出范围的发现

排查过程中经常会连带发现其他问题（本仓库真实案例：发现
`TAHUSD-SLOT1`/`ACLQOS-SLOT1` 那两条 fuzzy 规则因为 mnemonic 实际非空
从未生效过，这和当次要处理的 `FWM-ETH` 问题无关）。遇到这种情况：
1. 停下来，不要混在当次改动里一起改。
2. 用 AskUserQuestion 或直接说明的方式告诉用户这个新发现。
3. 在 `schema.sql` 对应位置写注释记录下来，供以后处理，但不要代替
   用户决定修不修。

## 不要做的事

- 不要在本地启动/导入 switchlog 的任何模块去验证管线行为（没有数据
  库连接，`pymysql` 通常没装，会直接报错浪费时间）。纯文本/正则验证
  用一次性脚本即可，不要 import 项目代码。
- 不要假设"改了 schema.sql 就等于线上生效"，必须同时给出 patch 文件。
- 不要因为用户说"其余的/剩下的都处理"就扩大处理范围到明显需要用户
  确认定级/是否推翻已有决定的条目，该问的还是要问。
