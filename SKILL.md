---
name: triage-syslog-gap
description: "处理用户贴来的 switchlog 原始日志（PARSE_FAIL / UNKNOWN_MNEMONIC，或已知事件码但 object 提取错误）。判断该拉黑、并入已有 event_code，还是新建 event_code，并在 sql/schema.sql 落地改动、生成对应 patch_*.sql。适用于用户贴一段原始 syslog 行、说"处理一下"/"加规则"/"屏蔽"/"合并到 XXX"之类请求的场景。"
---

# 处理 switchlog 日志缺口

用户贴一段原始 syslog（PARSE_FAIL、UNKNOWN_MNEMONIC，或已有规则但对象
抽错），要求屏蔽、配规则、并入某个事件码，或只是问"这条怎么处理"。

## 第一步：判断日志性质

先分类，不要看到日志就假设该拉黑或该告警：

1. **设备标准行为/操作留痕** —— 重启自检、配置操作记录、协议正常生命
   周期（OSPF LSA MaxAge、SSH 登录成功）。拉黑。
2. **已有 event_code 的新写法** —— 同一类故障换厂商/换固件后的另一个
   mnemonic。并入已有码，不新建。
3. **全新故障/风险信号** —— 认证服务器无响应、VLAN 被挂起、设备主动重启。
   新建 event_code。
4. **已有规则但对象抽错** —— object_regex 锚点不稳（用冒号定位，被信封
   里的裸冒号或 mnemonic 自己的冒号抢先命中）。修正则，不新建规则。

判断要点：

- **看正文有没有真实检测结果，不看严重度数字。** 正文一个可变字段都没有
  = 抽不出告警对象 = 没有告警价值。`VPC-2-L3_VPC_UNEQUAL_WEIGHT` 严重度
  写的是 2，正文却是句固定的操作提醒，设备并没真去比对两边配置。
- **用户说"这条归 XXX 码"也要先看样本。** 同一个 mnemonic 可能有两个相反
  方向，整条归一个码会让反向那半变误报：`ETHPORT-5-IF_HARDWARE` 现网 14 条
  = 7 条拔模块 + 7 条插回去。条数是偶数、正文尾部能分两组就是这个信号。
  反向那半归哪个码**问用户**，别自己选 —— 归 IF_UP 看着对称但有坑，"插上
  模块"不等于"链路起来"，会误关还没恢复的告警。
- **正文会自相矛盾，能登设备就别只读日志。** 只读的 display 命令（MCP 的
  `run_cmd`）不是变更，可以直接查。`OPTICAL_WARNING_OCCUR` 说 "voltage was
  too high: CurrentValue = 3.39 V, Threshold =3.53 V" —— 当前值比门限还低，
  这种写法就是该登设备的信号。回显显示预警门限是 3.47V（正文填的是告警档
  门限），实测 3.39V 连预警都没到，`display transceiver alarm` 回 None，
  50 秒后 CLEAR 的读数和 OCCUR 一字不差。有这组回显才敢配 ignore。
- **容器型 mnemonic 按 ErrorCode 分成好几件事。** 上面那条既有误报的电压/
  温度，也有真有价值的收光低。规则层只能做字符串匹配、比不了数值大小，
  body_match 区分不开真假越限 —— 这种别拉黑整个 mnemonic，正常解析归档 +
  定级表配 `action='ignore'`，真故障留给另一档（那次是严重度 2 的
  `OPTMOD/2/OPTICAL_ALARM`）。
- 拿不准分类、或要推翻已记录的"故意保留"决定，用 AskUserQuestion 问。真实
  案例：`SHELL/4/SHELL_CMD_MATCHFAIL` 原是"故意不拦的审计信号"，后来用户
  要求拉黑；MAC_FLAP 和 MAC_FLAP_SUPPRESS 的"合并"有好几种做法。

## 第二步：确认是否重复

```bash
grep -n "候选mnemonic或event_code" sql/schema.sql
grep -rn "候选mnemonic" sql/log_config.txt sql/log_ignore.txt
```

同一类日志可能已配过规则但配错了（mnemonic 该非空却填了空串走 fuzzy），
或已被拉黑。`sql/` 下那两份上一套系统的清单整份都不导入，但每次值得查：
`log_ignore.txt` 命中说明之前已判过是噪声；`log_config.txt` 命中能看到老
系统的等级和一句话描述，判断一致就在注释写"txt第N行判断一致"。

**老系统的描述不能照抄。** `VPC-2-L3_VPC_UNEQUAL_WEIGHT` 在
`log_config.txt` 第 558 行写的"思科nxosvpc路由配置不一致"是误读。等级可以
参考，描述自己按正文重写。

## 第三步：验证 mnemonic 剥取，不要凭读代码推理

`pipeline/l1_prepare.py` 的 `strip_mnemonic()` 已知坑：

- FAC 段带中划线（`FWM-ETH`、`TAHUSD-SLOT1`）在不同正则分支下表现不同。
- 斜杠最后一段碰空格会截断（`DEV/1/FAN STATE CHANGES TO FAILURE` 实际剥出
  `DEV/1/FAN`，要靠 `body_match` 消歧）。
- 时间戳认不出就 `readable=False` → PARSE_FAIL，进不到 L2/L3，配了也没用。

把 `MNEMONIC_REGS`/`TS_REGS` 复制到一次性脚本跑真实样本，不要用 Read 读完
代码口头推理。**注意用户贴的往往是 `display logbuffer` 回显，不是管线收到
的线上格式** —— 回显有前导 `%`、没有 `%%NN` 版本号、没有 `-DevIP=`，拿回显
验会得出"剥不出来"的错误结论，要按线上格式验。

剥出空串 → 配 `match_type='contains'`（`mnemonic` 留空）。剥出非空 → 必须
`match_type='exact'` 并填完整 mnemonic。**配成 `mnemonic=''` 但实际剥取非空
是真实发生过的 bug**：`_pick()` 在 mnemonic 非空时只查 exact 表，完全不碰
fuzzy 表，规则直接哑火、从未生效。

改 `l1_prepare.py` 正则本身属全量热路径改动，必须用 `logs/raw_packets.log*`
全量回归确认**零退化**（统计旧/新 `readable`、mnemonic 不一致的条数，逐条
人工看差异）。

## 第四步：捞全正文变体再写 object_regex

```bash
grep -ho "候选mnemonic: .*" logs/raw_packets.log* | sed 's/\\"}$//' \
  | sort | uniq -c | sort -rn
```

**`logs/` 捞不到不等于现网没发生。** 两个失效原因：日志文件 mtime 可能早于
事件时间（`ls -la logs/` 看一眼，`OPTICAL_WARNING_OCCUR` 的 0 条就是这么来
的 —— 事件 21:54、文件停在 11:46）；`logs/` 只覆盖最近十来天。能登设备的话
`display logbuffer | include 关键字` 更全，还能顺带捞到配对的 CLEAR 侧写法
和同族 mnemonic。

正则写完必须拿真实样本跑 `re.search`：

- 别依赖冒号/逗号等不稳定锚点（`ETH_PORT_CHANNEL-5-FOP_CHANGED` 原来用
  `':\s+(\S+?):'`，遇到带前导裸冒号的报文把对象抽成了 mnemonic 自己）。
  优先匹配固定词形（`port-channel\d+`、`Interface\s+([^\s,(]+)`）。
- **同一对象在一条正文里可能有两种写法。** `OPTICAL_WARNING_OCCUR` 里
  `PhysicalName=FourHundredGigE1/0/57` 和 `interface:400GE1/0/57` 是同一个
  口，混用会生成两个指纹。选和 display 回显一致的那种。
- **raise/clear 成对的要拿两侧样本都跑**，确认抽出的对象字符串完全相同，
  否则 clear 关不掉 raise。CLEAR 侧可能多带字段（`channel:N` 这种），确认
  不影响抽取结果 —— 口级对象不变的话多通道回关同一指纹，L7 判重走
  `ACTION_NONE`，不会重复清。

## 第五步：落地到 sql/schema.sql

- 新建 event_code 进 `syslog_event`，参考同类事件的
  `state`/`object_type`/`window_sec`（有稳定恢复日志配 raise/clear 对，
  没有配 stateless）。
- 需要单独定级才加 `syslog_severity_rule`，否则走全局兜底 P3。
- 匹配规则进 `syslog_rule`，靠同厂商/同族规则放。
- 黑名单进 `syslog_black_list`，`scope='mnemonic'` 优先（dict 精确命中）；
  只有 mnemonic 剥不出来才用 `scope='message'`（全文线性扫，要保持小）。
- **注释写判断依据，不要复述正文。** 两三行说清"为什么归这个码""代价是
  什么"就够，不要把一条黑名单写成二十行论证。
- 推翻了已有决定，把原注释一起改掉（"故意不拦的13条"要改成"12条"并写明
  为什么撤销）。
- **文件末尾"死码清单"要跟着改。** 给某个死码新加一条没被黑名单拦住的
  规则，它就不再是死码（`IF_ATTR_CHG` 加了 `ETHPORT-5-IF_HARDWARE` 兜底行
  之后就活了，副作用是重新开始出告警，要在 patch 注释写明）。
- **末尾自查注释里的种子条数会过期，不要在旧数字上做加减法。** 真实踩过：
  注释写 193/98，实测是改动前 194/103，按注释推出来的全是错的。用脚本实测。

## 第六步：脚本校验（本地没有数据库连接）

本机通常没装 `pymysql`，不能连库跑 `test_schema_sync.py`。改完用下面这段
校验**列名、字段数、行数、唯一键**。不能用朴素的 `str.count('(')` —— 必须
跳过字符串内容和 `--` 行注释，否则正文里的英文括号会干扰。

```python
import re, collections

def scan(s, i, n, on):          # 统一的跳字符串/跳注释扫描器
    in_str = False
    while i < n:
        c = s[i]
        if in_str:
            if c == "\\": i += 2; continue
            if c == "'": in_str = False
        else:
            if s[i:i+2] == "--":
                j = s.find("\n", i); i = n if j < 0 else j; continue
            if c == "'": in_str = True
            else:
                r = on(c, i)
                if r is not None: return r
        i += 1
    return None

raw = open("sql/schema.sql", encoding="utf-8").read()

# 1. 从 CREATE TABLE 取真实列名
ddl = {}
for m in re.finditer(r"CREATE TABLE (\w+)\((.*?)\n\) ENGINE", raw, re.S):
    ddl[m.group(1)] = [g.group(1) for g in
        (re.match(r"(\w+)\s+(?:VARCHAR|INT|BIGINT|TINYINT|TEXT|DATETIME)",
                  l.strip()) for l in m.group(2).split("\n")) if g]

# 2. 逐个 INSERT 块取列清单和元组
UNIQ = {"syslog_black_list": ("scope", "ip", "pattern"),
        "syslog_rule": ("vendor", "mnemonic", "match_type", "pattern", "body_match"),
        "syslog_event": ("event_code",),
        "syslog_severity_rule": ("event_code", "ip_reg", "sysname_reg")}
rows = collections.defaultdict(list)
for m in re.finditer(r"INSERT\s+(?:IGNORE\s+)?INTO\s+(\w+)\s*\n?\s*\(([^)]*)\)"
                     r"\s*\nVALUES\s*\n", raw):
    tbl = m.group(1)
    if tbl not in UNIQ: continue
    cols = [c.strip() for c in m.group(2).replace("\n", " ").split(",")]
    bad = [c for c in cols if c not in ddl.get(tbl, [])]
    if bad: print(f"!! {tbl} 列名不存在: {bad}")
    depth = [0]; start = [None]; tuples = []
    def on(c, i):
        if c == "(":
            if depth[0] == 0: start[0] = i
            depth[0] += 1
        elif c == ")":
            depth[0] -= 1
            if depth[0] == 0 and start[0] is not None:
                tuples.append(raw[start[0]+1:i]); start[0] = None
        elif c == ";" and depth[0] == 0: return i
        return None
    scan(raw, m.end(), len(raw), on)
    for t in tuples:
        vals, d, cur, in_s, i = [], 0, 0, False, 0
        while i < len(t):                      # 按顶层逗号切字段
            ch = t[i]
            if in_s:
                if ch == "\\": i += 2; continue
                if ch == "'": in_s = False
            elif ch == "'": in_s = True
            elif ch == "(": d += 1
            elif ch == ")": d -= 1
            elif ch == "," and d == 0: vals.append(t[cur:i].strip()); cur = i+1
            i += 1
        vals.append(t[cur:].strip())
        if len(vals) != len(cols):
            print(f"!! {tbl} 字段数 {len(vals)} != 列数 {len(cols)}: {t[:80]}")
        rows[tbl].append(dict(zip(cols, [v.strip("'") for v in vals])))

# 3. 行数 + 唯一键
for tbl, rs in rows.items():
    keys = [tuple(r.get(k, "") for k in UNIQ[tbl]) for r in rs]
    dup = {k: v for k, v in collections.Counter(keys).items() if v > 1}
    print(f"{tbl:22} {len(rs):4} 行   唯一键冲突: {dup or '无'}")
```

确认：新增条目都在对应表里、无唯一键冲突、行数变化符合预期（UPDATE 类不
增行数）。实测出来的行数直接拿去更新第五步那些自查注释。

## 第七步：生成独立 patch 文件

`sql/schema.sql` 是整库重建脚本（`DROP` + `CREATE` + 种子数据），线上库不
能重跑，必须另给 `sql/patch_YYYYMMDD_主题.sql` 走增量。

```sql
-- ============================================================
-- 补丁：<一句话描述>
--
-- 现网样例：<用户给的原始日志，带时间戳和设备名>
-- 判断依据：<为什么这么处理、和哪条已有规则同族、有没有推翻过去的决定>
--
--     mysql -h <host> -P <port> -u netops -p netops < sql/patch_xxx.sql
--
-- 和 schema.sql 的关系：内容已折进 schema.sql。
--   * 库用 schema.sql 重建的 -> 不用执行本补丁
--   * 库里有数据要保留 -> 执行本补丁
-- ============================================================
USE netops;

-- INSERT IGNORE / UPDATE / DELETE，和 schema.sql 的改动完全对应

-- 执行后自查：对应的 SELECT 语句
-- 规则表各层定时刷新，默认 300 秒一轮，等一轮或重启进程
```

- **patch 的列清单必须照着 DDL 抄，不要凭记忆写。** 真实踩过：手写成
  `state_type`（实际是 `state`）、第 5 列写 `enabled`（实际是 `threshold`）、
  `sample`（实际是 `descr`），线上执行直接报 ERROR 1054。第六步的脚本能查
  出来，patch 文件也要过一遍同样的列名校验。
- **patch 是一次性的，用户执行完就删。** `sql/` 下只有待执行的 patch，
  看不到某次改动的 patch 文件是正常的（已经执行并删掉了），不要当成"写丢了"
  或"漏生成"报给用户。总表 `schema.sql` 才是全量状态的唯一依据，核对改动
  在不在以它为准。
- **多段 patch 要写明执行顺序和"不能只执行一半"的后果**（只删旧事件码不改
  规则指向，规则会指向一个不存在的码）。
- **代码+SQL 联动的改动**必须在注释写清部署顺序和反序的后果（真实案例：先
  执行 SQL 再部署代码，中间有一段时间两边都查不到规则，比改之前更差）。

## 第八步：记录遗留，不要顺手扩大范围

排查常会连带发现别的问题（真实案例：发现 `TAHUSD-SLOT1`/`ACLQOS-SLOT1` 两条
fuzzy 规则因 mnemonic 实际非空从未生效过，和当次要处理的问题无关）。做法：
不要混在当次改动里改；告诉用户这个发现；在 `schema.sql` 或 patch 的"遗留"
注释里记下来，但不要代替用户决定修不修。

## 不要做的事

- 不要在本地启动/导入 switchlog 的任何模块验证管线行为（没有数据库连接，
  `pymysql` 通常没装）。纯文本/正则验证用一次性脚本，不要 import 项目代码。
- 不要假设"改了 schema.sql 就等于线上生效"，必须同时给出 patch 文件。
- 不要因为用户说"其余的都处理"就扩大到明显需要用户确认定级/是否推翻已有
  决定的条目，该问的还是要问。



