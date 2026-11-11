# switchlog

交换机 syslog 告警服务。收设备日志，解析成统一事件码，聚合去重后产生告警。

从 `central-server/lib_syslog/` 独立出来：那边是 Flask API + 定时任务，
这边是常驻的流式管线，两者的并发模型和重启频率都不一样，日志风暴时
管线会把 API 进程拖慢。

设计文档在 `docs/syslog_alarm_design.md`。

## 它解决什么

现有告警全接在 Zabbix，靠 SNMP 轮询，原理上漏两类事件：

- **轮询间隔内发生又恢复**：60s 轮一次，两次轮询之间 down 了又 up，
  两次读到的都是 up。一条上行链路每天闪断十几次，业务已经在报超时，
  Zabbix 上却一直是绿的
- **没有对应的 SNMP 指标**：MAC 漂移、STP 拓扑变化、环路检测、
  光模块告警、板卡电源错误，设备只在日志里报

## 管线

```
设备 --UDP 514--> receiver --hash(ip)--> worker x N
                                          │
   L0    prepare      剥信封 + 剥 mnemonic
   L0.5  blacklist    黑名单，命中即丢
   L1    parser       (vendor, mnemonic) -> event_code / object
   L2    enrich       sysname / hardware / 资产号 / 接口描述
   L2.5  attrs        severity / state / 窗口 / clear_code
   L3    suppress     drop / mute / depend          [未实现]
   L4    aggregate    指纹滑动窗口 + 计数            [未实现]
   L5    state_machine raise / clear + 闪断升级      [未实现]
   L6    emit         写 alarm_list                 [未实现]
```

现在跑到 L2.5，解析结果打到日志里。L3~L6 逐层补。

**一切按表来**，代码里不内置任何厂商正则或关键字。设备型号、版本差异
全部下沉到规则表，加一条规则就能支持新事件，不用发版。

## 目录

```
main.py          启动入口，带 --selftest / --replay
config/          config_example.py 是模板，config.py 不进 git
pipeline/        L0~L6，一层一个文件
db/              数据源，get_db() 工厂决定真库还是 mock
utils/           日志、统计、接口名归一
sql/schema.sql   建表 + 种子数据
docker/          构建与启动脚本
tests/           样本数据 + 回放工具
docs/            设计文档
```

## 跑起来

```bash
cp config/config_example.py config/config.py    # 填 MySQL 口令

# 1. 不连库，用内存样本跑回归
python test.py                      # 全部样本，带 (event_code, object) 判定
python test.py -v                   # 多打 L2 富化 / L2.5 属性 / 指纹收敛 / 黑名单四张表
python test.py dc05                 # 只跑那段 bbs1_dc05 现场日志
python test.py black                # 黑名单拦/放判定，误拦和漏拦分开标

# 2. 建表
mysql -h <host> -P <port> -u netops -p netops < sql/schema.sql

# 3. 连库自检：规则表、事件表、设备表各读一次
python main.py --selftest --ip 10.16.249.5

# 4. 起服务
python main.py                      # 监听 UDP 514
python main.py --port 5514          # 非特权端口，设备侧要配 logging port

# 5. 回放历史日志，统计规则命中率
python main.py --replay syslog/xxx.txt --ip 10.16.249.5
```

514 是特权端口，直接跑需要 root；容器里靠 `--cap-add=NET_BIND_SERVICE`
（启动脚本已带）。

## 容器

```bash
./docker/app_build.sh               # 构建
./docker/app_start.sh               # 启动，映射宿主机 514/udp
./docker/app_start.sh v1 5514       # 换非特权端口

./docker/logs.sh                    # 跟踪日志
./docker/logs.sh stats              # 收包与丢弃统计
./docker/logs.sh gap                # 规则缺口 Top 20
./docker/logs.sh selftest           # 容器内连库自检
```

## 规则怎么配

三张表，职责分开：

| 表 | 管什么 | 谁读 |
|---|---|---|
| `syslog_black_list` | 解析前拦掉的噪声 | L0.5 |
| `syslog_rule` | `(vendor, mnemonic)` → `event_code`，对象抽取正则 | L1 |
| `syslog_event` | 事件属性：级别、状态、窗口、恢复码 | L2.5 |

**事件属性单独一张表**是有原因的：`IF_DOWN` 在三家厂商下共十几行匹配规则，
属性挂在匹配行上就有十几份副本，改一次 P2→P1 要改十几行，漏一行就出现
"华为的端口 down 是 P1、Cisco 的同一个事件还是 P2"这种谁都发现不了的错。

**补规则的依据是 `UNKNOWN_MNEMONIC` 的计数**，不是厂商手册。
`./docker/logs.sh gap` 打出的高频未命中就是下一批该补的，
`vendor` 直接抄那一行的值。照抄手册全表的规则既不背测试也没人维护。

两个配规则时容易踩的坑，写在 `sql/schema.sql` 的注释里：

- `object_regex` 跑在整段正文上（含 `%MNEMONIC:` 前缀），不能用 `^` 锚定，
  否则抓到的是 mnemonic 自己
- `body_match` 必须抄现网正文的原字符串。H3C 是 `changed to down.`，
  华为是 `turned into DOWN state.`，按手册写法臆造会整条规则不命中

## 几个刻意的设计

**同一设备的日志固定落到同一个 worker**（按 IP hash 分区）。这不是优化，
是硬要求：L4 聚合和 L5 状态机依赖同设备事件的先后顺序，随机分配会让
`IF_UP` 先于 `IF_DOWN` 被处理，告警关不掉。

**队列满时丢弃而不是阻塞**。阻塞收包线程会让内核 socket buffer 溢出，
那是无声丢包；主动丢弃能计数、能在统计里看到。

**mnemonic 只剥一次**。黑名单和 parser 都要用，L0 剥好往下透传。
实测 162 字节报文剥一次 0.44us，剥好后 dict 查一次 0.036us —— 这也是
黑名单用 dict 而不是逐条 `str.find` 的原因（20 条规则以上就比剥 mnemonic 还贵）。

**时间统一用采集时间，不用报文自带时间**。设备时钟没同步时日志时间是乱的，
用它算滑动窗口会错判顺序，恢复事件可能排在故障事件前面。

**级别用 P1/P2/P3，不用 syslog 的八级**。`%BGP-5-ADJCHANGE` 是 level 5
（notice），但 BGP 邻居掉了对我们是 P1，两者没有对应关系。

**解析不出来的日志不丢**，记成 `UNKNOWN_MNEMONIC`。这样"漏解析"永远是
可观测的，而不是安静地走进兜底分支假装解析过了。

## 数据库

共用 netops 库。`devices` / `ports` 由 central-server 采集侧维护，这边只读；
`syslog_*` 四张表归 switchlog；`alarm_list` 两边都用（switchlog 写，看板读）。

规则表的增删改查仍在 `central-server/api/api_alarm.py`，switchlog 不带 API。

## 接入覆盖率

没配 syslog 的设备永远不会出日志告警，看起来就是正常的。两项检查：

- **配置侧**：每台设备是否配了 `logging host`、`logging source-interface`、
  日志级别够不够（至少 informational）、NTP 是否同步
- **数据侧**：每台设备最近 24 小时有没有收到过日志，超过的列入缺口清单

设备侧必须配 `logging source-interface`，否则源 IP 不稳定，
按 IP 查 devices 表会漂。
