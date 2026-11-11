# Syslog 日志告警设计

> 状态:L0~L2.5 已实现(switchlog 项目),L3~L6 待开发
> 最后更新:2026-11-11

本文是设计依据,记录"为什么这么做"。实现状态和跑法看 `README.md`。
设计与实现有两处不一致,已经按实现为准:

| 设计原文 | 实际实现 | 原因 |
|---|---|---|
| L0 收日志入 Kafka,管线消费 topic | switchlog 直接监听 UDP 514,内存队列分发 | 少一跳、少一个故障点,不依赖 central-server 常驻 |
| severity 用 emergency..debug 八级 | 用 P1/P2/P3 整数 | syslog level 和告警级别没有对应关系(§4.1.9 自己也提到 `%BGP-5-ADJCHANGE` 是 level 5 但对我们是 P1) |

另外 §4.1.2 的"语法族"没有落地成代码里的分派:三种 mnemonic 写法
(Cisco / Comware / FortiGate)对每条报文一起试,厂商只用来查规则表。
报文长什么样由报文自己说,不需要先按 vendor 选解析器。

## 1. 背景与目标

### 1.1 为什么要做

当前告警全部接在 Zabbix,靠 SNMP 轮询 + 触发器产生。这个方式原理上会漏两类事件:

| 漏的类型 | 原因 | 典型事件 |
|---|---|---|
| 轮询间隔内发生又恢复 | 60s 轮一次,两次轮询之间 down 了又 up,两次读到的都是 up | 端口闪断、BGP/OSPF 邻居闪断、链路 flap |
| 没有对应的 SNMP 指标 | 设备只在日志里报,MIB 里不暴露,或者没人配 item | MAC 漂移、STP 拓扑变化、环路检测、ARP/IP 冲突、风暴抑制、光模块告警、板卡/电源硬件错误、配置变更、登录失败 |

第一类最危险:一条上行链路每天闪断十几次,业务已经在报超时,Zabbix 上却一直是绿的。

### 1.2 目标

把设备 syslog 变成和 Zabbix 告警同等地位的告警源,统一进平台的 `alarm_list`,统一分级、去重、恢复、通知,看板只接一处。

### 1.3 前提:平台必须成为唯一告警出口

走全后端方案意味着平台成为唯一告警出口,因此 **Zabbix 的触发器告警也必须回流进 `alarm_list`**(Zabbix webhook → 平台接口)。

这一条如果不做,就会出现两个告警出口、两套分级,值班要看两处、看板要接两处,正是本设计想避免的局面。**这是落地的硬前提,不是可选项。**

## 2. 现有链路的问题

现有链路:`readDataFromSyslog` → 黑名单屏蔽 → 规则聚合 → `sendDataToCollector`,共三级。

相关文件(都在 central-server,本项目不动它们,新旧链路并行):
- `central-server/services/syslog_main.py` — 管线主流程
- `central-server/services/syslog/filter_blacklist.py` — 黑名单屏蔽
- `central-server/services/syslog/log_merge.py` — 规则聚合
- `central-server/services/syslog/__init__.py` — `BlacklistEntry` / `MergeRule` 规则对象
- `central-server/tables/SyslogDB.py` — `syslog_black_list` / `syslog_merge_list` 两张表

以下问题是结构性的,不是调参能解决的。

### 2.1 聚合把状态信息吃掉了(最关键)

`syslog_merge_list` 里一条规则 `PHY_UPDOWN|LINK_UPDOWN` → group_name `up/down状态`,down 和 up 被归进**同一个** `group_label`。

下游拿到一个 tag,不知道接口现在是通还是断,无法用 up 事件关闭 down 告警。聚合的目的是降噪,但这里降掉的是状态,而状态恰恰是告警的核心。

### 2.2 没有分级,也没有统一事件码

`mergeLog` 的返回只有 `group_name`(人读的分组名),没有 severity。下游无从判断 P1/P2/P3,看板也排不了序。

这和 `alarm_list` 缺 severity 是同一个坑,应该一次解决。

### 2.3 屏蔽的维度不够,抑制只有"丢"

全量日志已归档在 ES,复盘和补规则有数据基础,这一层不是问题。

问题在屏蔽本身:`syslog_black_list` 只有 `pattern` 一个维度,**没法按设备、按时间段屏蔽**,变更窗口期做不到"记录但不告警"。

而且 `syslog_main.py:38` 命中即 `continue`,屏蔽只有"丢"这一档,没有"进管线但不出告警"这一档。

### 2.4 窗口是固定分桶 + 无限继承

`log_merge.py:104` 的 `int(time.time()/timeWindow)` 是 tumbling window,靠 `log_merge.py:178-191` 继承上一桶的 label 来模拟滑动。

问题是只要事件不断,label 会一直继承下去:**一个持续闪断的接口永远是同一个 label,永远只有第一次告警**,之后彻底静默。缺一个最大寿命(max_life)。

### 2.5 Redis 里只存了 label,没存计数

`log_merge.py:193` 的 `set(key, key, ex=window*2)` 只有 label。下游不知道这个 tag 里有几条日志、从什么时候开始、是不是第一条。导致两件事做不了:

- "第一条产生告警、后续只累加"(现在每条都往下发)
- "30 分钟闪断 3 次"这类阈值判断

### 2.6 规则优先级由字母序决定

`SyslogDB.py:250` 是 `order by group_name,rule_id`,而 `log_merge.py:144-150` 命中第一条就 `break`。

等于规则优先级取决于 group_name 的字母顺序,不可控。需要显式 priority 字段。

### 2.7 单线程 + 异常吞掉

`syslog_main.py:35` 单线程 for 循环,每条日志都要线性遍历全部黑名单和合并规则做正则匹配,日志风暴时会堵在这里。

`syslog_main.py:50` 的 `except Exception` 把解析失败和 `sendDataToCollector` 发送失败一起吞了,发送失败的日志直接丢,没有重试和死信。

### 2.8 设备身份靠日志文本提取

`log_merge.py:117` 用 `(\S+)\s+%{1,2}` 从日志里抠 hostname。很多设备日志不带 hostname,带的也是设备本地名,和 CMDB 不一定一致。

应该以源 IP 查 CMDB 为准,查不到的单独报"未纳管设备在发日志"。

### 2.9 alarm_object 抽取方式偏粗

`log_merge.py:126-140` 一串接口正则,每次调用都重新 `re.compile`(可提到模块级)。

更重要的是第一条 `\S+(?:\d+/)+\d+` 会误匹配 IP、时间戳、版本号。而且不是所有事件的对象都是接口:BGP 事件的对象是 peer IP,MAC 漂移的对象是 MAC+VLAN,板卡事件的对象是槽位。

**抽什么应该由事件码决定**,不是统一一套接口正则。

## 3. 新数据流向

> 全量归档已在 ES 落地,是既有能力。图上标出它是为了说明位置和关系 —— 它是一条独立旁路,不被本次改造影响。本设计只改主链路(L1~L6)。

```
设备 syslog (Cisco / H3C / 华为 / FortiGate)
  │ UDP/TCP 514
  ▼
┌─ L0 接收 ──────────────────────────────────────────────┐
│ rsyslog / 现有 receiver                                │
│ → Kafka topic: syslog.raw,原样入 topic,不做任何判断    │
└───────────────────────────┬────────────────────────────┘
                            │
            ┌───────────────┴───────────────┐
            │                               │
            │ 主链路                        │ 旁路:全量归档
            │ (本次设计,下文 L1~L6)         │ (既有能力,ES)
            ▼                               ▼
┌─ L1 解析归一 ──────────────────────────┐  ┌─ 归档 ───────────────────┐
│ parser.py                              │  │ 原始日志,不过滤、不聚合、│
│ → event_code / severity / object       │  │ 不告警,与主链路完全解耦  │
└──────────┬─────────────────────────────┘  └──────────────────────────┘
           ▼
┌─ L2 富化 ──────────────────────────────┐
│ enrich.py                              │
│ 源 IP → CMDB: host / dc / role / 厂商  │
│ 本地缓存 10min,查不到 → UNMANAGED_SRC  │
└──────────┬─────────────────────────────┘
           ▼
┌─ L3 抑制 ──────────────────────────────┐
│ suppress.py   三档,不再是一刀切丢弃    │
│  drop     噪声日志,不进告警链路        │
│  mute     变更窗口/维护期,进管线不告警 │
│  depend   上游设备已 down,下游事件挂起 │
└──────────┬─────────────────────────────┘
           ▼
┌─ L4 聚合 ──────────────────────────────┐
│ aggregate.py                           │
│ fingerprint = ip + event_code + object │
│ 真滑动窗口 + 计数 + 最大寿命           │
│ 输出 is_first / count / first_seen     │
└──────────┬─────────────────────────────┘
           ▼
┌─ L5 状态机 ────────────────────────────┐
│ state_machine.py                       │
│ raise      → 开/累加告警               │
│ clear      → 按指纹关对应告警          │
│ stateless  → 窗口计数,静默即恢复       │
│ 长窗口计数 → 识别闪断,升级             │
└──────────┬─────────────────────────────┘
           ▼
┌─ L6 告警出口 ──────────────────────────┐
│ alarm_emit.py                          │
│ 写 alarm_list(带 severity + 指纹)      │
│ Kafka topic: alarm.event → 通知 / 看板 │
└────────────────────────────────────────┘
```

相对现有链路,改动集中在三点:

1. **屏蔽从第一级后移到第三级,并扩成三档** —— 先解析归一,再决定丢掉、静默还是挂起
2. **聚合后面补一级状态机** —— 现在完全缺失
3. **出口从 collector 改为 alarm_list** —— 平台成为唯一告警出口

## 4. 各级职责

### 4.1 L1 解析归一(parser.py)

**核心原则:不给每个厂商写一个解析器,按"语法族"写。** 现网设备再多,日志语法也就三四种;厂商内部的型号、版本差异全部下沉到规则表(数据),不进代码。

#### 4.1.1 一条日志分三段解析

```
<134>Oct 11 14:03:22.412 switch-a %ETHPORT-5-IF_DOWN: Interface Ethernet1/1 is down
└PRI┘└────── timestamp ─────┘└hostname┘ └──────────── body ────────────────┘

① envelope   与厂商无关。RFC3164 / RFC5424 都在这段消化,输出 ts / hostname / body
② header     按语法族。从 body 抽出 (facility, sev_hint, mnemonic)
③ body       按规则表。按 object_type 抽对象,再由 mnemonic 映射到 event_code
```

> 时间戳有三种写法都要吃:无年份 `Oct 11 14:03:22.412`、带年份且日期空格补位 `2026 Oct  9 05:18:56.565`、RFC5424 的 ISO8601。NX-OS 用哪种取决于 `logging timestamp` 配置,现网多半两种并存,envelope 解析器必须同时支持,否则整批日志落 `PARSE_FAIL`。

第一段和第三段全厂商共用,**只有第二段跟厂商相关**,而且它只输出三个字段,不做任何业务判断。这样 N 个厂商 ≠ N 套解析代码。

#### 4.1.2 语法族:按 `devices.vendor` 映射,不按型号

`devices` 表已经采集好了,`vendor` 字段的取值就是 `cisco_nx` / `h3c` / `huawei` / `unknown` 这几种。**header 语法只跟 vendor 走,和型号、版本无关** —— N9K 和 N3K 的 syslog header 一模一样,没必要为型号再分一层。

| 族 | `devices.vendor` | header 特征 | 输出 |
|---|---|---|---|
| `f_cisco` | `cisco_nx` / `cisco_ios` / `cisco_xr` | `%FACILITY-SEV-MNEMONIC:` | facility, sev, mnemonic |
| `f_comware` | `h3c` / `huawei` | `%%NNMOD/SEV/MNEMONIC` | mod, sev, mnemonic(`NN` 丢弃) |
| `f_forti` | `fortinet`(需先补采集侧,见 4.1.3) | `key=value` | `logid` → mnemonic,`level`,`subtype` |

型号 / 版本只影响**规则表里有哪些 mnemonic**,不影响解析方式 —— 这是数据层面的差异,补一条规则即可,不用动代码。

> Comware 的 `%%` 后面两位是**日志版本号**,不同版本不一样(常见 `%%10`)。解析时必须剥掉,否则同一个事件在 V5 和 V7 上会落到两个不同 mnemonic,规则表要重复配两遍。这是版本差异唯一会漏到代码里的地方,必须在 header 解析器里消化掉。

#### 4.1.3 厂商判定:只查 `devices` 表,查不到就是未命中

不做任何文本猜测。设备升级或换配置后正文格式会变,猜出来的结果会漂,而且漂了没人知道。判定就一步:

```
src_ip → devices.vendor → 语法族
        └ 查不到 → 未命中,不解析,打 UNMANAGED_SRC
```

未命中的日志仍然进 L2,打成 `UNMANAGED_SRC` 告警 —— 它在发日志但表里没有,这本身就是该补纳管或该查配置的事件。这样"漏解析"永远是可观测的,而不是安静地走进兜底分支假装解析过了。

> **飞塔的 vendor 识别**:采集侧已补 `fortinet`。存量设备需要重采一次,`devices.vendor` 才会从 `unknown` 刷成 `fortinet`;刷完之前飞塔日志会落 `UNMANAGED_SRC`,这是预期行为,正好用它确认还有哪些没重采。

#### 4.1.4 匹配:三级,正则只在最后一步

现在(问题 2.6)是每条日志线性跑一遍全部规则的正则,规则一多就堵。根因不是"正则慢",而是**把解析和聚合揉在一个函数里**(`log_merge.py:109-157` 的 `mergeLog` 同时干抠字段、判规则、算 key 三件事),所以每条日志都得全表遍历。分层之后这里只负责"找规则",分三级:

```
一级  dict[(vendor, mnemonic)] → [rule, ...]        O(1),覆盖 90% 以上
      精确未命中时再试 dict[('*', mnemonic)]
二级  mnemonic → rule_id 的缓存(含未命中)           O(1),同一 mnemonic 只算一次
三级  contains / regex 按 priority 升序短路         只对真没见过的 residue
```

一级查出来可能是**多条**规则,不是一条。绝大多数 mnemonic 只对应一个 event_code,`len == 1` 直接返回;少数 mnemonic 对应多个事件,需要再做一次正文判定来消歧——**Comware 的 `IFNET/3/PHY_UPDOWN` 就是典型:同一个 mnemonic,up 和 down 只差在正文里**。这类规则在行上再挂一个 `body_match`(走 `contains`,如 `state changed to down`),列表按 priority 排,命中即停。

代价是这类规则多一次 `str.find`,但只在候选列表长度 > 1 时发生,占比很小。

规则表里 `mnemonic` 非空就走一级;只有需要模糊匹配的才留空,进三级。`vendor` 填 `*` 表示该规则对所有厂商通用,建 dict 时展开成每个已采集到的 vendor 各一条,不额外多一次查找。规则加到几百条也不影响热路径。

三级里还有两个必须做的细节:

- **未命中也要缓存。** 同一台设备会反复发同一类日志,其中很多根本没人配规则。不缓存失败结果,这些日志每次都要重新全表扫。缓存挂在规则表版本号上,规则一改整体失效。
- **能写成子串就别写成正则。** 兜底规则里大量是"正文包含某个关键字",`"STATE_CHANGE" in body` 比 `re.search` 快一个数量级。规则表用 `match_type` 区分:

  | match_type | 实现 | 用在哪 |
  |---|---|---|
  | `exact` | dict 一级命中,mnemonic 即全部判据 | 绝大多数 |
  | `contains` | `str.find`,可用于 `body_match` 消歧 | `%STP-.*TOPOLOGY_CHANGE`、Comware 的 up/down |
  | `regex` | 模块级预编译,按 priority 短路 | 真需要模式的少数 |

  正则必须在模块加载时 `re.compile` 一次。`log_merge.py:126-140` 每次调用都重新编译,是纯浪费。

精确匹配顺带解决了问题 2.1 —— up 和 down 本来就是两个不同的 mnemonic,规则表里分别映射到 `IF_UP` / `IF_DOWN`,不存在"归进同一个 tag"的可能。对 Comware 这类 mnemonic 重合的,靠 `body_match` 分开,同样不会混。

> 如果某天 residue 大到三级也扛不住(yak 系单机每秒上千条),再考虑 Hyperscan 多模式单遍扫描。以现网日志量,几百条规则的规模用不上这个依赖。

#### 4.1.5 对象抽取:按 object_type 分派,与厂商无关

| object_type | 适用事件 | 抽取目标 | 归一化 |
|---|---|---|---|
| `interface` | 端口 up/down、聚合口、光模块 | 接口名 | 短名展开成全名(见 4.1.6) |
| `peer` | BGP / OSPF 邻居 | 邻居 IP | 统一小写,去掉 `%zone` 后缀 |
| `mac` | MAC 漂移 | MAC + VLAN | `xxxx.xxxx.xxxx` / `xx-xx-xx-xx-xx-xx` / `xxxx:xxxx:xxxx` 统一成 12 位十六进制小写 |
| `slot` | 板卡、电源、风扇 | 槽位号 | 统一成 `slot/subslot` |
| `none` | 配置变更、登录 | — | 固定 `-` |

**归一化是硬要求,不是美化。** `object` 参与 L4 指纹:同一个电口,down 日志里写成 `Eth1/1`、up 日志里写成 `Ethernet1/1`,就会落到两个不同指纹上,恢复事件永远关不掉对应的告警。

**同一事件码下的多个 mnemonic,必须抽出同一个对象。** 事件码的合并在规则表里完成(多个 mnemonic 指向同一个 `event_code`),但那只解决了一半 —— 下游只认 `md5(ip|event_code|object)`,对象不同照样分桶。以一个 NX-OS 物理口 down 为例:

| mnemonic | 正文 | 抽取锚点 |
|---|---|---|
| `ETHPORT-5-IF_DOWN` | `Interface Ethernet1/38, changed state to down` | `Interface\s+([^,\s]+),` |
| `ETHPORT-5-IF_DOWN_LINK_FAILURE` | `Interface Ethernet1/38 (description:...) is down (Link failure)` | `Interface\s+([^\s(]+)\s` |
| `LINEPROTO-5-UPDOWN` | `Line protocol on Interface Ethernet1/38, changed state to down` | `on Interface\s+([^,\s]+),` |

三行三种正文格式,所以 `object_regex` 是**逐 mnemonic** 配的,不能按事件配一份(§6.1.1 里把 `object_regex` 挂在事件上是不对的,只有 `object_type` 属于事件)。三行抽出来归一到 `Ethernet1/38`,才落到同一个指纹、`count=3`、一条告警。

三个前提缺一个,这一串就散成多条告警:规则少配一行、`object_regex` 抽歪、§4.1.6 的短名没展开。测试时按这三点分别构造用例。

#### 4.1.6 接口名归一:用设备自报的接口表,不硬编码

写死一张 `Eth → Ethernet` 对照表迟早跟不上(新的 400G 口类型、堆叠改名、华为的 `XGigabitEthernet`)。更稳的做法是用 netops collector **已有的配置采集**:

- 定期取每台设备的接口全集(`show interface` / `display interface brief`)
- 在 L1 建 `简称 → 全名` 映射并缓存,和规则表一起定时刷新
- 日志里的接口名先查映射;查不到再走兜底正则,并打 `UNKNOWN_OBJECT` 标记

设备出现新命名时只需重新采集一次,不用发版。

#### 4.1.7 未命中不丢:UNKNOWN_MNEMONIC

解析不出规则的日志不进 L3 抑制,但也不丢弃:

- 记为 `UNKNOWN_MNEMONIC`,severity=P3,在 L4 按"设备 + mnemonic"聚合
- 它同时是规则表的缺口清单:`select vendor, mnemonic, count(*) from ... group by 1,2 order by 3 desc`,高频未命中的就是下一条该补的规则。补规则时 `vendor` 直接抄这一行的值,不用再猜是哪家设备

这比人工翻日志文件找规则靠得住,也是阶段二能收敛的前提。

#### 4.1.8 envelope 解析失败也要告警

连 `PRI / 时间戳` 都解析不了的报文(端口配错、被错误转发的二进制、固件 bug),按设备聚合成 `PARSE_FAIL`(P3,窗口内累计 N 条才报)。一台设备持续发垃圾日志本身就是配置错误,应该让值班看到,而不是安静地躺在归档里。

#### 4.1.9 L1 的输出契约

下游只认这个结构,缺字段直接视为解析失败:

```python
{
  "ingest_ts": 1762...,        # 入库时间:窗口、排序、去重一律用它
  "ts": 1762...,               # 设备时间,只用于展示,可能不准
  "src_ip": "10.x.x.x",
  "vendor": "cisco_nx",        # devices.vendor 原值
  "family": "f_cisco",
  "mnemonic": "IF_DOWN",       # 原文里的关键字,规则表按它匹配
  "event_code": "IF_DOWN",
  "severity": 2,
  "state": "raise",
  "object_type": "interface",
  "object": "Ethernet1/1",     # 归一化后,参与指纹
  "object_raw": "Eth1/1",      # 原文,排查用
  "msg": "..."                 # body 原文,截断 1KB
}
```

两个细节:

- **窗口用 `ingest_ts` 不用 `ts`**。设备时钟没同步时日志时间是乱的,用它算窗口会错判顺序(§9 里提过 NTP 的影响)。
- **`severity` 由规则表定义,不用 syslog 自带的 level**。Cisco 的 `%BGP-5-ADJCHANGE` 是 level 5 (notice),但 BGP 邻居掉了对我们是 P1。

#### 4.1.10 规则表怎么填、怎么测

规则表按 `(vendor, mnemonic)` 落库,`vendor` 取 `devices.vendor` 的原值。只填现网设备实际会发的事件,不要照抄厂商手册全表 —— 抄进去的规则既不背测试也没人维护。几家设备的 mnemonic 完全相同时(比如 `IF_DOWN`),用 `vendor='*'` 一行覆盖,不用抄三行。

阶段一的离线验证顺带做成可回归的单测:拿 `syslog/义桥S125完整日志记录.txt` 当 fixture,输入一行、断言输出的 `(event_code, object)`,规则表改动时跑一遍。

### 4.2 L2 富化(enrich.py)

源 IP 查 CMDB 拿 host / dc / role / 厂商,本地缓存 10 分钟。

查不到的**不能丢**,统一打成 `UNMANAGED_SRC` 事件告警。这正好是"设备在发日志但没纳管"的发现渠道,和看板上"纳管 812/826"是一套逻辑。

设备侧要统一配 `logging source-interface`,否则源 IP 不稳定,映射会漂。

### 4.3 L3 抑制(suppress.py)

从一档扩成三档,这是最大的改动:

| 档位 | 行为 | 用途 |
|---|---|---|
| `drop` | 不进告警链路,原始日志照常落 ES | 确定是噪声:登录过程、日志自身的调试输出。沿用现有 `syslog_black_list` |
| `mute` | 进管线、进聚合、进状态机,**但不产生通知** | 变更窗口期。从 `AlterationManageDB` 读进行中工单的影响范围和时间窗 |
| `depend` | 上游设备整机不可达时,挂起其下游设备的事件 | 依赖 `TopologyDB` 已有拓扑数据。可后置,先留接口 |

`mute` 和 `drop` 的区别很重要:割接期间不该被电话轰炸,但割接完要能回看那段时间发生了什么,所以变更窗口必须用 `mute` 而不是 `drop`。

抑制结果记在日志记录的 `suppressed_by` 字段里,不是简单丢弃。规则表要加 `scope` 维度(全局 / 指定设备 / 指定机房)和生效时间段。

### 4.4 L4 聚合(aggregate.py)

**这一级不做任何正则匹配。** 现在每条日志过一遍聚合规则,是因为 `mergeLog` 把抠字段、判规则、算 key 揉在一起。分成 L1/L4 之后,进来的是结构化记录,`event_code` 和归一化后的 `object` 都已在 L1 算好,这里只剩拼 key:

```python
fingerprint = md5(f"{ip}|{event_code}|{object}")
```

唯一需要模式匹配的场景是 `UNKNOWN_MNEMONIC` —— 它没有 `event_code`,指纹退化成 `md5(ip + UNKNOWN + mnemonic)`,按原样字符串拼,同样不跑正则。

指纹统一成 `md5(ip + event_code + object)`。

不再像现在 `log_merge.py:153-157` 那样有两套 key 格式(取决于有没有命中规则),下游很难处理。

Redis 用 hash 存状态,而不是只存 label:

```
agg:{fingerprint}  →  hash {label, first_seen, last_seen, count}   ttl = window * 2
```

滑动靠 `last_seen` 判断,不靠分桶继承:

```python
now - last_seen <= window    →  同一个 label,count += 1,刷新 last_seen
now - first_seen > max_life  →  强制开新 label(解决无限继承)
否则                          →  新 label,count = 1
```

`max_life` 默认 1800s。持续闪断的接口每 30 分钟重新告警一次,不会永久静默。

返回值加字段,下游据此决定动作:

```python
{
  "fingerprint": "...",
  "group_label": "...",
  "is_first": True,      # 窗口内第一条 → 产生告警;否则只累加
  "count": 1,            # 落到这个桶里的**日志条数**,不是事件次数
  "first_seen": 1762...,
  "event_code": "IF_DOWN",
  "severity": 2,
  "state": "raise",
  ...
}
```

**`count` 是日志条数,不是事故次数。** 一个 `IF_DOWN` 在 Cisco 上可能同时落到 `IF_DOWN`、`IF_DOWN_LINK_FAILURE`、`LINEPROTO down` 三条日志,指纹相同,`count` 就是 3,但这是**一次**端口 down。所以:

- `count` 只用于"这个事件这一刻有多少条日志支撑它",展示和排查用
- **任何按"次数"做的判断都不能直接读 `count`**,必须数事件次数。闪断识别就踩这个坑,见 §4.5

想数事件次数,看 L5 的开告警动作,不是看 L4 的 `count`。

### 4.5 L5 状态机(state_machine.py)

**这一级是现有链路完全缺失的,也是日志告警能不能用起来的关键。**

#### 有状态事件

`state` 字段取 `raise` / `clear`:

```
alarm:active:{fingerprint}  →  hash {alarm_id, event_code, severity, first_seen, count}
```

| 输入 | 动作 |
|---|---|
| `raise` 且无活跃告警 | 开告警并写入 |
| `raise` 且已有活跃告警 | 只累加 count |
| `clear` | 按同一指纹找到活跃告警并关闭 |

因为指纹含 object,`BGP_UP peer=A` 只会关 A 的告警,不会误关同台设备上 B 邻居的告警。

#### 无状态事件

MAC 漂移、配置变更、登录失败没有恢复日志,用窗口计数触发,窗口内不再出现即自动恢复:

```
MAC_FLAP:同指纹 10 分钟内 ≥ 3 次 → 告警
```

这个 ≥3 的门槛同时起降噪作用,虚机漂移造成的偶发单次 MAC 迁移不报。

#### 闪断识别

单独一条长窗口,用 zset 做精确滑动窗口:

```
flap:{fingerprint}  →  zset  score = 开告警时刻
ZREMRANGEBYSCORE 清理窗口外 → ZCARD 取计数
同指纹 30 分钟内 ≥ 3 次「新开告警」→ 升级为 IF_FLAP,severity 提一档
```

**计数点在 L5 的开告警动作上,不在 L4 的日志条数上。** 一次端口 down 会产生 2~3 条同指纹日志(§4.4),按日志条数计的话一次 down 就能凑满 3 次,当场误报成闪断。所以只在"无活跃告警 → 开告警"这一跳 `ZADD` 一次,`raise` 累加和 `clear` 都不写。

闪断是轮询监控最容易漏、又最常导致业务抖动的一类。单次 down/up 间隔几秒,告警刚出就恢复,值班根本看不到,所以必须单独成一类,并且**禁止自动恢复,需人工确认才关闭**。

### 4.6 L6 告警出口(alarm_emit.py)

写 `alarm_list` 并发 Kafka topic `alarm.event`。

`alarm_list` 需要补的字段:

| 字段 | 用途 |
|---|---|
| `severity` | P1/P2/P3,看板排序和通知分级的依据 |
| `fingerprint` | 关联恢复事件、去重 |
| `event_code` | 统一事件码 |
| `alarm_state` | firing / resolved / acked |
| `count` | 聚合条数 |
| `first_seen` / `last_seen` / `resolved_at` | 持续时长、MTTR |
| `source` | syslog / zabbix / flow,区分来源 |
| `suppressed_by` | 被哪条规则 mute 的 |
| `incident_id` | 同一根因的告警归到同一张事件单,对外只发一次通知 |

> 具体改动要对着 `tables/AlarmDB.py` 现有结构核一遍再定,此处仅为字段需求清单。

### 4.7 实例:一次 port-channel 掉线,五条日志怎么收敛

现网真实样本(已脱敏,保留原格式):

```
2026 Oct  9 05:18:56.565 pcs1_dc07_m01 %ETH_PORT_CHANNEL-5-FOP_CHANGED: port-channel38: first operational port changed from Ethernet1/38 to none
2026 Oct  9 05:18:56.576 pcs1_dc07_m01 %ETH_PORT_CHANNEL-5-PORT_DOWN: port-channel38: Ethernet1/38 is down
2026 Oct  9 05:18:56.585 pcs1_dc07_m01 %ETHPORT-5-IF_DOWN_PORT_CHANNEL_MEMBERS_DOWN: Interface port-channel38 is down (No operational members)
2026 Oct  9 05:18:56.612 pcs1_dc07_m01 %ETHPORT-5-IF_DOWN_LINK_FAILURE: Interface Ethernet1/38 (description:vpn2.net.dc07::eth0) is down (Link failure)
2026 Oct  9 05:18:56.615 pcs1_dc07_m01 %ETHPORT-5-IF_DOWN_PORT_CHANNEL_MEMBERS_DOWN: Interface port-channel38 is down (No operational members)
```

#### 先看对象:这五条不是一个对象

| # | mnemonic | object | 说明 |
|---|---|---|---|
| 1 | `FOP_CHANGED` | `port-channel38` | `to none` = 最后一个可用成员没了 |
| 2 | `PORT_DOWN` | `Ethernet1/38` | 行首的 `port-channel38:` 是上下文,不是对象 |
| 3 | `IF_DOWN_PORT_CHANNEL_MEMBERS_DOWN` | `port-channel38` | |
| 4 | `IF_DOWN_LINK_FAILURE` | `Ethernet1/38` | 括号里是 description,不是接口名 |
| 5 | 同 3 | `port-channel38` | **与 #3 完全重复**,隔 30ms |

#### 收敛结果:两个指纹

| event_code | object | 命中 | 指纹 | count |
|---|---|---|---|---|
| `LAG_DOWN` | `port-channel38` | 1、3、5 | `md5(ip\|LAG_DOWN\|port-channel38)` | 3 |
| `IF_DOWN` | `Ethernet1/38` | 2、4 | `md5(ip\|IF_DOWN\|Ethernet1/38)` | 2 |

对应规则行:

| vendor | mnemonic | body_match | event_code | 备注 |
|---|---|---|---|---|
| `cisco_nx` | `ETH_PORT_CHANNEL-5-FOP_CHANGED` | `to none` | `LAG_DOWN` | |
| `cisco_nx` | `ETH_PORT_CHANNEL-5-FOP_CHANGED` | (其余) | `LAG_MEMBER_CHG` | P3,还有成员时是正常冗余切换 |
| `cisco_nx` | `ETH_PORT_CHANNEL-5-PORT_DOWN` | | `IF_DOWN` | |
| `cisco_nx` | `ETHPORT-5-IF_DOWN_PORT_CHANNEL_MEMBERS_DOWN` | | `LAG_DOWN` | |
| `cisco_nx` | `ETHPORT-5-IF_DOWN_LINK_FAILURE` | | `IF_DOWN` | |

`FOP_CHANGED` 必须用 `body_match` 分开:`to none` 才是 LAG 全断;变成 `to Ethernet1/39` 是成员切换,有冗余的 LAG 每天都会发生,报出来就是噪声。

#### 为什么不能把两个指纹合成一个

如果五条都归到 `port-channel38`,那么 `Ethernet1/38` 单独 up 回来(LAG 还断着)会把整条告警关掉。一个对象一个告警是状态机的底线,合并只能发生在通知层。

#### 通知层合并:事件单

**前提是 §6.2 的 `port_lag_member` 已经落地。** 没有成员关系表就没有可信的 `(ip, lag)` 键,这一段不启用。

```
inc:{ip}:{lag}  →  hash {incident_id, created, root_cause, alarms:[...]}   ttl = 30
```

- LAG 告警到达,按 `(ip, lag_if)` 建单
- 成员口告警到达,用 `(ip, member_if)` 查 `port_lag_member` 得到 `lag_if`,挂进同一张单
- 同一张单 30 秒内产生的告警都挂在里面
- 对外只发**一条**通知:`port-channel38 down,根因 Ethernet1/38 link failure`
- 底层两条告警各自独立 raise / clear,互不干扰

**合的是通知,不是状态。**

#### 三个坑

1. **因果关系是反的。** LAG down(.585)在前,成员 down(.612)在后,差 27ms。§4.3 的 `depend`(上游先 down → 下游挂起)在这里用不上,因为根因后到。所以事件单必须事后回捞:LAG 告警先建单,30 秒内成员告警进来再补 `root_cause`。反方向也成立,谁先到谁建单。

   注意回捞靠的是 `port_lag_member` 查出来的归属,时序只用来确定"谁先到",不用来推断"谁属于谁"。先到的是不是根因,同样要看 `event_code` 的层级关系(`IF_DOWN` 在成员口上 → `LAG_DOWN` 在 LAG 上),不是看时间戳先后。

2. **#3 和 #5 是重复日志。** mnemonic、正文、对象全同,隔 30ms。在现有设计下不会多一条告警 —— L5 的 `raise` 遇到已有活跃告警只累加 `count`;闪断计数又只数"新开告警"这一跳,所以不会被刷爆。`count` 会多 1,但 `count` 不参与任何次数判断。

3. **描述字段里藏着假接口名。** `Interface Ethernet1/38 (description:vpn2.net.dc07::eth0) is down` 里,抽取正则必须锚定 `Interface\s+([\w/.\-]+)` 且不跨越 `(`,否则 description 内容会被误抽。这一行直接做 fixture。

#### LAG 名和成员口的对应关系,日志里拿不到

先说清楚:这五条日志**不能**反推出 `Ethernet1/38` 属于 `port-channel38`。

| 行 | 带 LAG 名 | 带成员名 |
|---|---|---|
| 1 `FOP_CHANGED` | ✅ `port-channel38` | ✅ 正文里的 `changed from Ethernet1/38` |
| 2 `PORT_DOWN` | ✅ 行首 `port-channel38:` 是上下文 | ✅ |
| 3 / 5 `MEMBERS_DOWN` | ✅ | ❌ |
| 4 `IF_DOWN_LINK_FAILURE` | ❌ | ✅ |

只有 `PORT_DOWN` 和 `FOP_CHANGED` 这两种刚好把 LAG 名写进正文,是这两种报文格式的巧合,不是约定。`IF_DOWN_LINK_FAILURE` 才是最典型的成员口 down 日志,里面一个字都没提 LAG。换到 H3C/华为、换到别的 down 原因、换到成员口是在 LAG 已 down 之后才掉的,对应关系就断了。

**"同一台设备同一毫秒一起出现"不能当归属依据**,尤其不能拿它去关告警 —— 一次重启、一次批量插拔,同毫秒的无关日志多得是。

成员关系必须单独采,和 §4.1.6 的接口简称→全名映射合并到同一趟:

| 来源 | 说明 |
|---|---|
| NX-OS `show port-channel summary` | 接口清单采集时顺带收,可控可解析 |
| H3C / 华为 `display link-aggregation verbose` | 同上 |
| SNMP `IEEE8023-LAG-MIB::dot3adAggPortListPorts` | 位图,按 ifIndex 表示成员;不想多登一次设备时用 |
| SNMP `IF-MIB::ifStackTable` | 各家都支持,但 LAG 的父子关系要看厂商实际 walk 结果 |

`ports` 表目前只有 `ip, port_id, if_name, mac_address, speed, admin_statu, oper_statu, alias, timestamp`,没有成员关系字段。加一张:

```sql
create table port_lag_member (
  ip         varchar(32) not null,
  lag_if     varchar(64) not null,   -- port-channel38 / Bridge-Aggregation1 / Eth-Trunk1
  member_if  varchar(64) not null,   -- Ethernet1/38
  active     tinyint     not null default 1,
  updated_at datetime    not null,
  primary key (ip, lag_if, member_if),
  key idx_ip_lag (ip, lag_if)
);
```

采集周期跟接口清单一致。注意**增删成员不产生 syslog**,变更窗口结束后要强制刷一次,否则这张表会在割接后一直停在旧状态。

有了这张表,§4.7 的通知层才谈得上 `inc:{ip}:{lag}` 这个键:成员口告警到达时用 `(ip, member_if)` 反查 `lag_if`,挂到已有事件单上。

**这张表落地之前,两条告警分开发,不做合并。** 宁可多发一条通知,也不要靠猜出来的归属去压一条告警或关一条告警 —— 猜错一个成员口,代价是一张 P1 被误清。

#### 4.8
```
一、逐条投影                                                                                                                                                                                    
    ┌───────┬───────────┬───────────────────────────────────────────────────────┬────────────┬──────────────┬──────────────┐                                                                       
    │   #   │   时间    │                       mnemonic                        │ body_match │ → event_code │    object    │                                                                       
    ├───────┼───────────┼───────────────────────────────────────────────────────┼────────────┼──────────────┼──────────────┤                                                                       
    │ 1     │ 08.109    │ ETHPORT-5-IF_DOWN_LINK_FAILURE                        │            │ IF_DOWN      │ Ethernet1/6  │                                                                       
    ├───────┼───────────┼───────────────────────────────────────────────────────┼────────────┼──────────────┼──────────────┤                                                                       
    │ 2     │ 08.111    │ BGP-5-ADJCHANGE                                       │ Down       │ BGP_DOWN     │ 172.28.2.133 │                                                                       
    ├───────┼───────────┼───────────────────────────────────────────────────────┼────────────┼──────────────┼──────────────┤                                                                       
    │ 3     │ 08.111    │ BFD-5-SESSION_STATE_DOWN                              │            │ BGP_DOWN     │ 172.28.2.133 │                                                                       
    ├───────┼───────────┼───────────────────────────────────────────────────────┼────────────┼──────────────┼──────────────┤                                                                       
    │ 4     │ 08.160    │ BGP-5-ADJCHANGE                                       │ Down       │ BGP_DOWN     │ 172.28.2.113 │                                                                       
    ├───────┼───────────┼───────────────────────────────────────────────────────┼────────────┼──────────────┼──────────────┤                                                                       
    │ 5     │ 08.161    │ BFD-5-SESSION_STATE_DOWN                              │            │ BGP_DOWN     │ 172.28.2.113 │                                                                       
    ├───────┼───────────┼───────────────────────────────────────────────────────┼────────────┼──────────────┼──────────────┤                                                                       
    │ 6     │ 09.144    │ BFD-5-SESSION_REMOVED                                 │            │ drop         │ —            │                                                                       
    ├───────┼───────────┼───────────────────────────────────────────────────────┼────────────┼──────────────┼──────────────┤                                                                       
    │ 7     │ 09.178    │ BFD-5-SESSION_REMOVED                                 │            │ drop         │ —            │                                                                       
    ├───────┼───────────┼───────────────────────────────────────────────────────┼────────────┼──────────────┼──────────────┤                                                                       
    │ 8     │ 11.925    │ BGP-5-ADJCHANGE                                       │ Down       │ BGP_DOWN     │ 172.28.1.193 │                                                                       
    ├───────┼───────────┼───────────────────────────────────────────────────────┼────────────┼──────────────┼──────────────┤                                                                       
    │ 9     │ 11.925    │ BFD-5-SESSION_STATE_DOWN                              │            │ BGP_DOWN     │ 172.28.1.193 │                                                                       
    ├───────┼───────────┼───────────────────────────────────────────────────────┼────────────┼──────────────┼──────────────┤                                                                       
    │ 10    │ 11.949    │ BGP-5-ADJCHANGE                                       │ Down       │ BGP_DOWN     │ 172.28.2.125 │                                                                       
    ├───────┼───────────┼───────────────────────────────────────────────────────┼────────────┼──────────────┼──────────────┤                                                                       
    │ 11    │ 11.950    │ BFD-5-SESSION_STATE_DOWN                              │            │ BGP_DOWN     │ 172.28.2.125 │                                                                       
    ├───────┼───────────┼───────────────────────────────────────────────────────┼────────────┼──────────────┼──────────────┤                                                                       
    │ 12    │ 12.929    │ ETHPORT-5-IF_DOWN_LINK_FAILURE                        │            │ IF_DOWN      │ Ethernet1/1  │                                                                       
    ├───────┼───────────┼───────────────────────────────────────────────────────┼────────────┼──────────────┼──────────────┤                                                                       
    │ 13    │ 13.002    │ ETHPORT-5-IF_DOWN_LINK_FAILURE                        │            │ IF_DOWN      │ Ethernet1/2  │                                                                       
    ├───────┼───────────┼───────────────────────────────────────────────────────┼────────────┼──────────────┼──────────────┤                                                                       
    │ 14-15 │ 13.0xx    │ BFD-5-SESSION_REMOVED                                 │            │ drop         │ —            │                                                                       
    ├───────┼───────────┼───────────────────────────────────────────────────────┼────────────┼──────────────┼──────────────┤                                                                       
    │ 16-19 │ 38:32.709 │ SPEED/IF_DUPLEX/IF_RX_FLOW_CONTROL/IF_TX_FLOW_CONTROL │            │ drop         │ —            │                                                                       
    ├───────┼───────────┼───────────────────────────────────────────────────────┼────────────┼──────────────┼──────────────┤                                                                       
    │ 20    │ 32.725    │ ETHPORT-5-IF_UP                                       │            │ IF_UP        │ Ethernet1/6  │                                                                       
    ├───────┼───────────┼───────────────────────────────────────────────────────┼────────────┼──────────────┼──────────────┤                                                                       
    │ 21    │ 32.731    │ BGP-5-ADJCHANGE                                       │ Up         │ BGP_UP       │ 172.28.2.113 │                                                                       
    ├───────┼───────────┼───────────────────────────────────────────────────────┼────────────┼──────────────┼──────────────┤                                                                       
    │ 22    │ 33.232    │ BGP-5-ADJCHANGE                                       │ Up         │ BGP_UP       │ 172.28.2.133 │                                                                       
    ├───────┼───────────┼───────────────────────────────────────────────────────┼────────────┼──────────────┼──────────────┤                                                                       
    │ 23-24 │ 33.739    │ BFD-5-SESSION_MOVED                                   │            │ drop         │ —            │                                                                       
    └───────┴───────────┴───────────────────────────────────────────────────────┴────────────┴──────────────┴──────────────┘                                                                       
                                                                                                                                                                                                   
    对应要补的规则行:                                                                                                                                                                              
                                                                                                                                                                                                   
    ┌──────────┬────────────────────────────────┬────────────┬────────────┬─────────────┬─────────────────────────────────┐                                                                        
    │  vendor  │            mnemonic            │ body_match │ event_code │ object_type │          object_regex           │                                                                        
    ├──────────┼────────────────────────────────┼────────────┼────────────┼─────────────┼─────────────────────────────────┤                                                                        
    │ cisco_nx │ ETHPORT-5-IF_DOWN_LINK_FAILURE │            │ IF_DOWN    │ interface   │ Interface\s+([^\s(]+)           │                                                                        
    ├──────────┼────────────────────────────────┼────────────┼────────────┼─────────────┼─────────────────────────────────┤                                                                        
    │ cisco_nx │ ETHPORT-5-IF_UP                │            │ IF_UP      │ interface   │ Interface\s+([^\s(]+)           │                                                                        
    ├──────────┼────────────────────────────────┼────────────┼────────────┼─────────────┼─────────────────────────────────┤                                                                        
    │ cisco_nx │ BGP-5-ADJCHANGE                │ Down       │ BGP_DOWN   │ peer        │ neighbor\s+(\d+\.\d+\.\d+\.\d+) │                                                                        
    ├──────────┼────────────────────────────────┼────────────┼────────────┼─────────────┼─────────────────────────────────┤                                                                        
    │ cisco_nx │ BGP-5-ADJCHANGE                │ Up         │ BGP_UP     │ peer        │ neighbor\s+(\d+\.\d+\.\d+\.\d+) │                                                                        
    ├──────────┼────────────────────────────────┼────────────┼────────────┼─────────────┼─────────────────────────────────┤                                                                        
    │ cisco_nx │ BFD-5-SESSION_STATE_DOWN       │            │ BGP_DOWN   │ peer        │ neighbor\s+(\d+\.\d+\.\d+\.\d+) │                                                                        
    └──────────┴────────────────────────────────┴────────────┴────────────┴─────────────┴─────────────────────────────────┘                                                                        
                                                                                                                                                                                                   
    二、收敛成 7 个指纹                                                                                                                                                                            
                                                                                                                                                                                                   
    ┌────────────┬──────────────┬────────┬───────┬───────────────────────────────┐                                                                                                                 
    │ event_code │    object    │ 命中行 │ count │             指纹              │                                                                                                                 
    ├────────────┼──────────────┼────────┼───────┼───────────────────────────────┤                                                                                                                 
    │ IF_DOWN    │ Ethernet1/6  │ 1      │ 1     │ md5(ip|IF_DOWN|Ethernet1/6)   │                                                                                                                 
    ├────────────┼──────────────┼────────┼───────┼───────────────────────────────┤                                                                                                                 
    │ IF_DOWN    │ Ethernet1/1  │ 12     │ 1     │ md5(ip|IF_DOWN|Ethernet1/1)   │                                                                                                                 
    ├────────────┼──────────────┼────────┼───────┼───────────────────────────────┤                                                                                                                 
    │ IF_DOWN    │ Ethernet1/2  │ 13     │ 1     │ md5(ip|IF_DOWN|Ethernet1/2)   │                                                                                                                 
    ├────────────┼──────────────┼────────┼───────┼───────────────────────────────┤                                                                                                                 
    │ BGP_DOWN   │ 172.28.2.133 │ 2、3   │ 2     │ md5(ip|BGP_DOWN|172.28.2.133) │                                                                                                                 
    ├────────────┼──────────────┼────────┼───────┼───────────────────────────────┤                                                                                                                 
    │ BGP_DOWN   │ 172.28.2.113 │ 4、5   │ 2     │ md5(ip|BGP_DOWN|172.28.2.113) │                                                                                                                 
    ├────────────┼──────────────┼────────┼───────┼───────────────────────────────┤                                                                                                                 
    │ BGP_DOWN   │ 172.28.1.193 │ 8、9   │ 2     │ md5(ip|BGP_DOWN|172.28.1.193) │                                                                                                                 
    ├────────────┼──────────────┼────────┼───────┼───────────────────────────────┤                                                                                                                 
    │ BGP_DOWN   │ 172.28.2.125 │ 10、11 │ 2     │ md5(ip|BGP_DOWN|172.28.2.125) │                                                                                                                 
    └────────────┴──────────────┴────────┴───────┴───────────────────────────────┘                                                                                                                 
                                                                                                                                                                                                   
    三条恢复关掉其中三个:IF_UP Ethernet1/6(关 Eth1/6)、BGP_UP 172.28.2.113、BGP_UP 172.28.2.133。                                                                                                  
    │        仍活跃         │            原因             │                                                                                                                                        
    ├───────────────────────┼─────────────────────────────┤                                                                                                                                        
    │ IF_DOWN Ethernet1/1   │ 没见到 IF_UP,口还down着     │                                                                                                                                        
    ├───────────────────────┼─────────────────────────────┤                                                                                                                                        
    │ IF_DOWN Ethernet1/2   │ 同上                        │                                                                                                                                        
    ├───────────────────────┼─────────────────────────────┤                                                                                                                                        
    │ BGP_DOWN 172.28.1.193 │ 没见到 Up(对应 Eth1/1 没起) │                                                                                                                                        
    ├───────────────────────┼─────────────────────────────┤                                                                                                                                        
    │ BGP_DOWN 172.28.2.125 │ 同上(对应 Eth1/2 没起)      │                                                                                                                                        
    └───────────────────────┴─────────────────────────────┘ 
```
/
## 5. 事件码规则表(示意)

> 下表的日志关键字**仅作示意,必须用现网实际日志核对**。不同厂商、不同版本写法差异很大。
> 阶段一跑出真实日志分布之后,这张表要按实际出现的事件重写。

| event_code | severity | state | object_type | Cisco NX-OS | H3C | 华为 | 恢复事件 |
|---|---|---|---|---|---|---|---|
| `IF_DOWN` | P2 | raise | interface | `%ETHPORT-5-IF_DOWN`、`...IF_DOWN_LINK_FAILURE`、`%LINEPROTO-5-UPDOWN ... down`、`%ETH_PORT_CHANNEL-5-PORT_DOWN` | `IFNET/3/PHY_UPDOWN`、`IFNET/5/LINK_UPDOWN` | `IFNET/3/PHY_UPDOWN`、`IFNET/5/LINK_UPDOWN` | `IF_UP` |
| `IF_UP` | P3 | clear | interface | `%ETHPORT-5-IF_UP`、`%LINEPROTO-5-UPDOWN ... up` | `IFNET/3/PHY_UPDOWN`、`IFNET/5/LINK_UPDOWN` | `IFNET/3/PHY_UPDOWN`、`IFNET/5/LINK_UPDOWN` | — |
| `LAG_DOWN` | P1 | raise | interface | `%ETHPORT-5-IF_DOWN_PORT_CHANNEL_MEMBERS_DOWN`、`%ETH_PORT_CHANNEL-5-FOP_CHANGED` + `to none` | `LAGG/.../LAG_STATE` | `Eth-Trunk/.../TRUNK_STATE` | `LAG_UP` |
| `LAG_MEMBER_CHG` | P3 | stateless | interface | `%ETH_PORT_CHANNEL-5-FOP_CHANGED`(非 `to none`) | — | — | 窗口自动恢复 |
| `BGP_DOWN` | P1 | raise | peer | `%BGP-5-ADJCHANGE ... Down` | `BGP/5/BGP_STATE_CHANGED ... Established to` | `BGP/2/hwBgpPeerBackwardTransition` | `BGP_UP` |
| `OSPF_DOWN` | P1 | raise | peer | `%OSPF-5-ADJCHANGE ... to DOWN` | `OSPF/5/OSPF_NBR_CHG ... to Down` | `OSPF/.../NBR_CHANGE ... Down` | `OSPF_UP` |
| `MAC_FLAP` | P2 | stateless | mac | `MAC_MOVE` / `MACFLAP` | `MAC/4/MAC_FLAPPING` | `MAC/.../MACFLAPPING` | 窗口自动恢复 |
| `STP_TC` | P3 | stateless | interface | `%STP-.*TOPOLOGY_CHANGE` | `STP/.../STP_NOTIFIED_TC` | `MSTP/.../TC` | 窗口自动恢复 |
| `PSU_FAIL` | P2 | raise | slot | `%PLATFORM-.*PS_FAIL` | `DEV/.../POWER_FAILED` | `.../POWER_.*FAIL` | `PSU_OK` |
| `CONFIG_CHG` | P3 | stateless | none | `%VSHD-5-VSHD_SYSLOG_CONFIG_I` | `SHELL/.../CFG_CHANGED` | `CFG/.../CFG_CHANGE` | 窗口自动恢复 |
| `LOGIN_FAIL` | P3 | stateless | none | `AUTHPRIV.*fail` | `SSHS/.../AUTH_FAILURE` | `SSH/.../LOGIN_FAIL` | 窗口自动恢复 |
| `IF_FLAP` | P1 | raise | interface | 由 L5 长窗口计数升级产生 | — | — | 人工确认 |
| `UNMANAGED_SRC` | P3 | stateless | none | 由 L2 富化失败产生 | — | — | 窗口自动恢复 |

表里各厂商列填的是 **mnemonic**,也就是 §4.1.2 中 header 段剥出来的关键字,不是整条日志的匹配正则。规则表按 `(vendor, mnemonic)` 落库,`vendor` 取 `devices.vendor` 原值(`cisco_nx` / `h3c` / `huawei` / `fortinet`),同一个事件在几家设备上通常就是几行,`event_code` 相同;mnemonic 完全一致时用 `vendor='*'` 一行覆盖。

**一个 event_code 对应多条 mnemonic,这是刻意的。** 端口 down 会连着发好几条日志(物理层 up/down、链路协议 up/down、OSPF/STP 跟随变化),它们全部映射到同一个 `IF_DOWN`,而不是各打各的标签。这样 L4 的指纹 `md5(ip + event_code + object)` 会把这一串日志收敛成**一个**聚合桶,`count` 记下发生了几条,但对外只出**一条**告警。这正是"原子粒度是单条日志,但按事件告警"的落点 —— 原始日志一条不丢,告警量按事件收敛。

反过来,同一个 mnemonic 也可能对应多个 event_code(Comware 的 `IFNET/3/PHY_UPDOWN` up/down 共用一条 mnemonic),靠 `body_match` 区分,见 §4.1.4。

填表时的判断标准:**同一故障同一时刻产生、用户会当成一件事看待的日志,归到同一个 event_code;先后有意义、需要单独确认的,拆开。**

FortiGate 走 `f_forti` 族:解析 header 时把 key=value 转成同样三字段,mnemonic 取 `logid`(如 `type=event subtype=vpn level=alert logid="0101039426"`),下游与 Cisco/H3C 完全一致。MCP vendor 不支持飞塔不影响 syslog 接入。

## 6. 表结构变更

### 6.1 syslog_merge_list → 规则主表

现在只有 `group_name / pattern / descr`,需要扩成规则主表:

```sql
alter table syslog_merge_list
  add column vendor       varchar(30)  not null default '*' comment '取 devices.vendor 原值:cisco_nx/h3c/huawei/fortinet,* 表示不限',
  add column mnemonic     varchar(80)  not null default ''  comment '精确匹配用,空则走 pattern',
  add column match_type   varchar(10)  not null default 'exact' comment 'exact/contains/regex,见 4.1.4;复用现有 pattern 列',
  add column body_match   varchar(200) not null default ''  comment '同一 mnemonic 对应多个事件时的消歧子串,空=不参与',
  add column event_code   varchar(50)  not null default ''  comment '统一事件码,多行可重复',
  add column severity     tinyint      not null default 3   comment '1=P1 2=P2 3=P3',
  add column state        varchar(10)  not null default 'stateless' comment 'raise/clear/stateless',
  add column object_type  varchar(20)  not null default 'none' comment 'interface/peer/mac/slot/none',
  add column object_regex varchar(300) not null default ''  comment '对象抽取正则,空则按 object_type 默认',
  add column priority     int          not null default 100 comment '越小越先匹配,只对 contains/regex 生效',
  add column window_sec   int          not null default 300 comment '聚合窗口',
  add column threshold    int          not null default 1   comment '窗口内触发阈值',
  add column enabled      tinyint      not null default 1,
  add index idx_vendor_mnemonic (vendor, mnemonic),
  add index idx_event_code (event_code),
  add index idx_priority (priority);
```

**`event_code` 上不能建唯一索引**,这是设计上要接受的一点:一个事件码天然对应多行(多厂商、多 mnemonic),单条 mnemonic 也可能对应多个事件码。唯一性只存在于"同一 mnemonic 在某个 vendor 下指回同一个事件"这一层,而那层还带着 `body_match` 消歧,建唯一索引会互相打架。所以 `(vendor, mnemonic)` 用普通索引,内存里建 dict 时查出列表再按 `priority, rule_id` 排序,一级命中列表长度为 1 就直接返回,大于 1 才跑 `body_match`。

`mnemonic` 精确命中这一层就是 §4.1.4 的第一级;`match_type='exact'` 的规则不需要 `pattern`,`contains` 时 `pattern` 存关键字、走 `str.find`,`regex` 时存正则、模块加载时预编译一次。后两者按 `order by priority, rule_id` 短路(对应问题 2.6)。

#### 6.1.1 事件属性应该单独一张表

上面那张表里 `severity / state / object_type / window_sec / threshold` 这些字段,**描述的是事件,不是匹配规则**。现在挂在匹配行上,意味着 `IF_DOWN` 有几行(3 家厂商 × 3 条 mnemonic = 9 行)就有 9 份副本。改一次 P2→P1 要改 9 行,漏一行就出现"华为的端口 down 是 P1、Cisco 的同一个事件还是 P2"这种谁都发现不了的错。

`object_regex` 不在此列,它必须留在匹配行上 —— 同一个事件码下的不同 mnemonic 正文格式不同,正则没法共用(§4.1.5 里有三条 mnemonic 三种锚点的例子)。

既然处理是按事件走的,就按事件建表:

```sql
create table syslog_event (
  event_code   varchar(50) primary key,
  severity     tinyint     not null default 3,
  state        varchar(10) not null default 'stateless',   -- raise/clear/stateless
  object_type  varchar(20) not null default 'none',
  window_sec   int         not null default 300,
  threshold    int         not null default 1,
  clear_code   varchar(50) not null default '',            -- 恢复事件,如 IF_UP
  descr        varchar(200) not null default '',
  enabled      tinyint     not null default 1
);
```

上面那张表只留**匹配**相关的列:`vendor / mnemonic / match_type / pattern / body_match / event_code / priority / object_regex`。

对应的物化形式,也是你说的"一系列日志打一个标签":

| vendor | mnemonic | body_match | → event_code |
|---|---|---|---|
| `cisco_nx` | `ETHPORT-5-IF_DOWN` | | `IF_DOWN` |
| `cisco_nx` | `ETHPORT-5-IF_DOWN_LINK_FAILURE` | | `IF_DOWN` |
| `cisco_nx` | `LINEPROTO-5-UPDOWN` | `state down` | `IF_DOWN` |
| `h3c` | `IFNET/3/PHY_UPDOWN` | `state to down` | `IF_DOWN` |
| `h3c` | `IFNET/3/PHY_UPDOWN` | `state to up` | `IF_UP` |
| `huawei` | `IFNET/3/PHY_UPDOWN` | `state to DOWN` | `IF_DOWN` |

六行匹配,两个事件。改 `IF_DOWN` 的严重级别就改 `syslog_event` 里的一行,所有厂商同时生效。

### 6.2 新增 port_lag_member(LAG 成员关系)

见 §4.7。日志里拿不到"哪个物理口属于哪个 LAG",而 LAG 告警和成员口告警的通知合并依赖这个对应关系,所以必须单独建表并单独采集。

```sql
create table port_lag_member (
  ip         varchar(32) not null,
  lag_if     varchar(64) not null comment 'port-channel38 / Bridge-Aggregation1 / Eth-Trunk1',
  member_if  varchar(64) not null comment 'Ethernet1/38',
  active     tinyint     not null default 1,
  updated_at datetime    not null,
  primary key (ip, lag_if, member_if),
  key idx_ip_lag (ip, lag_if)
);
```

采集来源按厂商:NX-OS `show port-channel summary`、H3C/华为 `display link-aggregation verbose`;不想多登一次设备时走 SNMP `IEEE8023-LAG-MIB::dot3adAggPortListPorts` 或 `IF-MIB::ifStackTable`。采集周期与接口清单一致。

两点必须注意:

- **`active` 用软删,不要物理删行。** 成员被摘除后仍然要能查出"它曾经属于谁",否则故障复盘时关联不上。
- **增删成员不产生 syslog。** 变更窗口结束后要强制刷一次,不然这张表会停在割接前的状态。

这张表没落地之前,LAG 告警和成员口告警分开发,不做通知合并(依据是 §4.7 最后一条:宁可多发一条,也不要靠猜的归属去压告警)。

### 6.3 syslog_black_list → 抑制表

```sql
alter table syslog_black_list
  add column action     varchar(10)  not null default 'drop' comment 'drop/mute',
  add column scope_type varchar(20)  not null default 'global' comment 'global/device/dc',
  add column scope_val  varchar(200) not null default ''  comment '设备IP或机房编码',
  add column start_time varchar(10)  not null default ''  comment '生效起,空=长期',
  add column end_time   varchar(10)  not null default '',
  add column enabled    tinyint      not null default 1;
```

### 6.4 顺手修掉的 SQL 拼接

`SyslogDB.py:194` 和 `:199` 的查询条件是字符串拼接 SQL(`" regexp '" + str(...) + "'"`)。虽然前面过了 `waf()`,但既然这几个方法都要改,顺手换成参数化比较稳妥。

## 7. syslog_main.py 结构改造

从单线程 for 循环改成管线 + worker 池:

```python
class SyslogService:
    def __init__(self, workers=4, refresh_interval=300):
        self.pipeline = [
            Parser(refresh_interval),       # L1
            Enricher(cache_ttl=600),        # L2
            Suppressor(refresh_interval),   # L3
            Aggregator(),                   # L4
            StateMachine(),                 # L5
        ]
        self.emitter = AlarmEmitter()       # L6

    def _worker(self):
        for message in self.messages:
            if not self._running:
                break
            record = None
            try:
                record = self.pipeline[0].parse(message.value)
                for stage in self.pipeline[1:]:
                    record = stage.handle(record)
                    if record is None:              # drop,管线终止
                        break
                if record and record.get("emit"):
                    self.emitter.emit(record)       # 失败走重试 + 死信
            except Exception as e:
                self.dead_letter.put(message.value, str(e))
                logger.error(...)
```

两点和现在不同:

- **管线短路** —— `stage.handle()` 返回 `None` 即终止,不像现在 `syslog_main.py:38` 的黑名单判断写死在入口,后续环节只能被动接受
- **发送失败进死信队列** —— 而不是像 `syslog_main.py:50` 那样吞掉(对应问题 2.7)

归档不在这条管线里:旁路直接消费同一个 `syslog.raw` topic,本管线丢掉的日志它照样收得到。所以主链路上加抑制规则,不会削弱"事后查原始日志"的能力。

### 7.1 并发模型

正则匹配是 CPU 密集的,Python GIL 下多线程收益有限。如果单机日志量大(每秒上千条),两个选项:

1. worker 用多进程
2. 在 L1 之后按 `ip` 做 hash 分区到多个消费实例

> 注意:同一台设备的日志必须落到同一个实例。聚合和状态机都依赖同设备事件的顺序性,不能随机分配,否则 `IF_UP` 可能先于 `IF_DOWN` 被处理。

### 7.2 与现有代码的关系

`filter_blacklist.py` 和 `log_merge.py` **只作为逻辑参考,实现重写**。现有代码里"把 up/down 聚成一个 tag""分桶继承 label""Redis 只存 label"这几件事是设计层面的问题,不是加字段能救的;但两份文件里有三样东西值得照抄或复用:

| 现有 | 处理 |
|---|---|
| `MergelistManager.mergeLog` 的 `keyword`/`hostname` 正则(`log_merge.py:109`、`:117`) | 抄进 `parser.py` 的 `f_cisco` 族做参考,再补 Comware / FortiGate |
| 规则与黑名单的**定时刷新线程** | 复用这套机制,`Parser` 和 `Suppressor` 都靠它热更新规则,不重启 |
| `tables/SyslogDB.py` 的读写封装 | 复用连接和事务处理,查询条件换成参数化(§6.3) |
| `BlacklistManager` / `MergelistManager` 的类结构 | 不复用。`Suppressor` 是三档 action + scope,`Parser` 是族分派 + 两级匹配,和现在的单层循环对不上 |

`log_merge.py:126-140` 那串接口正则整段丢掉:它既会误匹配(问题 2.9),也不区分事件类型,统一重写不如按 §4.1.5 的 `object_type` 分派。

## 8. 落地顺序

| 阶段 | 内容 | 能验证什么 |
|---|---|---|
| 一 | L0 + L1,**不告警** | 日志接入覆盖率;事件码命中率;各类日志量 Top 50 |
| 二 | 按阶段一的真实统计写规则表,上 L4 新聚合(替换现有 `mergeLog`) | 聚合压缩比;对比新旧 label 分布 |
| 三 | 上 L5 状态机 + L6 出口,先只写 `alarm_list` 不发通知,跑一周 | 告警量、误报率,规则再收一轮 |
| 四 | 开通知;Zabbix webhook 回流进 `alarm_list` | 平台成为唯一出口,看板接一处 |
| 五 | 补 L3 的 mute(变更窗口)和 depend(拓扑抑制) | 割接期间不再误报 |

**阶段一必须先只收不报。** 直接上规则的话,第一周告警量通常会把值班淹没,而且规则是凭印象写的,不是基于真实日志分布。

现有的 `syslog/义桥S125完整日志记录.txt` 正好可以用来跑阶段一的离线验证,`syslog_main.py:71-90` 那段 main 里的离线跑法可以直接改造成回归测试。

## 9. 接入覆盖率

这和看板设计里的"纳管 812/826"是同一个问题:**没配 syslog 的设备永远不会出日志告警,看起来就是正常的**。

两项检查:

- **配置侧** —— 用 netops collector 已有的配置采集,检查每台设备是否配置了 `logging host`(指向采集层)、`logging source-interface`、日志级别是否够(至少 informational)、NTP 是否同步
- **数据侧** —— 规则层统计每台设备最近 24 小时有没有收到过任何日志,超过 24 小时没有日志的设备列入缺口清单

> NTP 不同步的影响容易被忽略:时间不准的话日志顺序是乱的,恢复事件可能排在故障事件前面,状态机会误判。

这两项可以直接接到值班看板的"设备与链路健康"面板,在"纳管设备"旁边加一个"日志接入 N / 826"。

## 10. 待确认事项

| # | 问题 | 影响 |
|---|---|---|
| 1 | `alarm_list` 现有字段结构 | 需对着 `tables/AlarmDB.py` 核一遍再给准确的 alter 语句 |
| 2 | 现有归档链路的 index / 保留期 / 查询入口 | 只是要知道去哪查原始日志,不影响本设计 |
| 3 | 日志量级(峰值每秒条数) | 决定 worker 用多线程还是按 IP 分区多实例 |
| 4 | Zabbix 回流进平台这一步做不做 | 不做的话,看板和值班仍要看两处(见 1.3) |
| 5 | 现有 syslog 服务器是否已在用 | 有的话 L0 可以直接在上面扩展 |

## 11. 可选补充:SNMP Trap

syslog 走 UDP 有丢包风险。后期可补 SNMP Trap(`linkDown`/`linkUp`、`bgpBackwardTransition`)作为第二通道,用 snmptrapd 接入同一管线,和 syslog 互为备份。

Trap 和 syslog 会产生重复事件,靠 L4 的指纹聚合天然去重 —— 这也是指纹设计成 `ip + event_code + object` 而不含日志原文的原因之一。

## 12. 相关文档

本项目:
- `README.md` — 目录结构、怎么跑、规则怎么配
- `sql/schema.sql` — 六张表的建表语句与种子数据,字段注释里写了配规则的坑
- `pipeline/__init__.py` — event 字段契约(§4.1.9 的落地版)

其他项目:
- `central-server/docs/change_management_design.md` — 变更管理,L3 的 mute 档依赖其工单数据
- `central-server/docs/MESSAGE_QUEUE.md` — Kafka / Redis 队列适配层(本项目改走 UDP 直收,不再经队列)
- `chen_vue/src/view/pages/dashboard/` — 值班与领导看板,告警数据的消费方

