# -*- coding: utf-8 -*-
"""
switchlog 告警管线

层号就是执行顺序，文件名带前缀，`ls pipeline/` 出来就是管线的样子：

    l1_prepare.py        剥信封 + 剥 mnemonic，全链路只做一次
    l2_blacklist.py      子串/mnemonic 黑名单，命中即丢，不进后面任何一层
    l3_parser.py         (vendor, mnemonic) -> event_code，按 object_regex 抽 object
    l4_enrich.py         devices 补 sysname/hardware/syscontact，ports 补接口描述
    l5_attrs.py          syslog_event 补 state/窗口/clear_code，
                         syslog_severity_rule 按设备定 severity
                         ↓ 到这里是一条原子告警
    l6_aggregate.py      指纹 + 滑动窗口，写 alarm_log
    l7_state_machine.py  raise / clear / stateless + 闪断升级
                         ↓ 到这里是一条告警决策
    l8_suppress.py       按 ip/event_code/object + 时间窗静默，填 muted
    l9_emit.py           写 alarm_list + 发通知

runner.py 不是层，它是串联器；本文件是包契约，所以都不带前缀。

L8 静默排在状态机之后不是随手放的：判据里的 object 要等 L6 聚合、
级别和状态要等 L7，而且放在这里它从热路径（每条日志）变成冷路径
（只有待通知的告警），判据用正则也不心疼。

各层之间传的是 dict，每层往里增量补字段。热路径上 dict 比 dataclass 快，
而且哪一层补了哪些字段一目了然 —— 契约就写在下面。

======================= event 字段契约 =======================

    # L1 prepare 产出
    ingest_ts     int     采集时间。窗口、排序、去重一律用它
    ip            str     源 IP
    message       str     原始报文，截断 1KB
    hostname      str     报文自报的设备名，没有是 "-"
    body          str     剥掉信封后的正文，含 %MNEMONIC: 段
    mnemonic      str     header 段剥出的关键字
    readable      bool    False=报文不可读 -> PARSE_FAIL

    # L3 parser 产出
    vendor        str     devices.vendor 原值
    event_code    str     统一事件码，兜底三值见下
    alarm_object  str     归一化后的告警对象，参与 L6 指纹
    object_raw    str     报文里的原始写法，排查用
    rule_id       int     命中的规则行

    # L4 enrich 产出
    sysname       str     devices.sysname
    hardware      str     devices.hardware
    syscontact    str     devices.syscontact（现网存资产号）
    sysdesc       str     devices.sysdesc
    sys_type      str     devices.sys_type
    managed       bool    设备是否在 devices 表里
    src_state     str     MANAGED / UNMANAGED_SRC / SRC_LOOKUP_FAILED
    object_name   str     归一化后的对象识别名，查到了就填（目前只有
                          接口会填，是 ports.if_name 的全名写法）
    object_alias  str     对象的人类可读描述，目前只接了一种来源：
                              interface  查 ports.alias（接口描述）
                              peer/mac/slot  暂未实现，留空
                          L4 跑在 L5 之前，这里还没有 object_type，
                          所以不是"按类型分支查"，是对 alarm_object
                          直接尝试查 ports 表，查不到就留空 ——
                          查到了就说明它是接口，查不到不代表它一定
                          不是别的可识别对象，只是那条数据源还没接

    # L5 attrs 第一步：syslog_event 按 event_code 查
    state         str     raise / clear / stateless，被定级规则改成 ignore 时见下
    object_type   str     interface / peer / mac / slot / none
    window_sec    int     聚合窗口
    threshold     int     窗口内达到该条数才告警
    clear_code    str     恢复事件码，L7 据此配对

    # L5 attrs 第二步：syslog_severity_rule 按 (event_code, ip, sysname) 查
    severity      int     1=P1 2=P2 3=P3
    severity_name str     P1 / P2 / P3，看板和日志里用
    severity_rule_id int  命中的定级规则行，0=没命中（按 P3 兜底）

级别不是事件的固有属性，所以不在 syslog_event 里：同一个 IF_DOWN，
csw 掉口是核心网段断了（P1），rsw 掉口是一个机柜的接入（P3），
corp 职场的 rsw 掉口压根不用看（action=ignore）。定级必须排在 L4
富化之后 —— 要按 sysname 判设备角色。

命中 action=ignore 的规则时 state 变成第四个值：

    ignore        不开告警。事件照样走完后面各层并写 alarm_log，
                  只是 L7 不开告警，事后回看时这条日志还查得到。
                  L7 的 MODE_IGNORE 对应这个值

到这里一条原子告警就齐了。后面各层的产出：

    # L5 顺带给 L6 的
    raise_code    str     本事件是谁的恢复事件，自己是故障码时为空。
                          L6 据此算指纹：IF_UP 按 IF_DOWN 算，否则恢复
                          事件落到自己的指纹上，故障告警永远关不掉

    # L6 aggregate 产出
    fingerprint   str     md5(ip|raise_code or event_code|alarm_object)
    group_label   str     本段的标签 "指纹:段起点"，max_life 到了会换。
                          和 alarm_list.group_label 不是一回事 —— 那一列
                          沿用老结构存裸指纹
    is_first      bool    本段窗口内第一条。**L7 不要拿它决定开不开告警**，
                          max_life 切新段时它也是 True
    count         int     落到这个指纹的**日志条数**，不是事故次数
    first_seen    int     本段起点
    last_seen     int     本段最近一条

    L6 只写 alarm_log（一条日志一行，带指纹，只留 7 天）。alarm_list 不在
    L6 写 —— 阈值判断是 L7 的事：MAC_FLAP 配 600/3，第一条日志进来时
    alarm_list 里不该有行，攒到第 3 条才算告警

**指纹不含时间**，所以它只能回答"哪个口的哪类故障"，回答不了"哪一次"。
同一个口上周那次 down 和今天这次是同一个指纹。下钻查日志必须
指纹 + 时间范围两个条件一起用，范围取 alarm_list 那一行的 first_seen
到 clear_time（已恢复）或 last_seen（告警中）。
封装在 AlarmDB.getAlarmLogsByAlarm(alarm_id)，看板直接调它，别自己拼
"where fingerprint=?" —— 那样会把这个口所有历史故障的日志混在一起。

不拿 L6 的 group_label 当下钻条件：一条告警可能跨多个段（持续 down 一
小时会被 max_life 切两段，但 L7 只累加，仍是一条告警），按段标签查只
能查到其中一段。

    # L7 state_machine 产出
    L7 不往 event 上加字段，它产出一个独立的决策 dict，挂在
    event["decision"] 上：

    action        str     none / raise / update / escalate / clear / ignore
    notify        bool    要不要往下交。none 和 ignore 都是 False
    state         str     open / idle，告警自身还成不成立
    severity      int     闪断升级后是提过档的
    event_code    str     闪断升级后是 IF_FLAP，不是原来的 IF_DOWN
    counter       int     窗口内日志条数
    flapping      int     1=闪断中，禁止自动恢复，需人工确认
    raise_count   int     累计开告警次数，闪断判定数这个

    状态的唯一来源是 syslog_alarm_state（内存 + 启动回放），不读
    alarm_list —— 重启那一瞬间两者可能不一致，以状态表为准。

    阈值判断在 L7：MAC_FLAP 配 600/3，攒到第 3 条才算告警。
    闪断升级在原指纹上做，不换指纹 —— 换了就是另一条告警，
    原来那条还挂着关不掉。

    # L8 mute 产出
    L8 在同一个决策 dict 上填两个字段：

    muted         bool    被静默规则压住，L9 不发通知
    mute_rule_id  int     命中的 syslog_mute_rule 行，0=没命中

    muted 是记录上的状态，不是"要不要入库"的开关 —— 被静默的告警照样
    入库，只是不发通知。新开的告警在 L9 落库时一次写进去（addAlarm 的
    入参里就有这两个），不要先 INSERT muted=0 再 UPDATE。

    muted 和 status（人工屏蔽）分开两个字段：人工屏蔽要等人去改，
    muted 是时间窗一过自动恢复通知。窗口到期靠 L8 的 sweep() 定时扫，
    不能等日志驱动 —— 窗口结束之后不会再有新日志进管线

三个兜底事件码同样走过整条管线，窗口可在 syslog_event 里调、
级别可在 syslog_severity_rule 里调：

    PARSE_FAIL        报文不可读（无 PRI/时间戳，也剥不出 mnemonic）
    UNMANAGED_SRC     源 IP 在 devices 表里查不到厂商
    UNKNOWN_MNEMONIC  规则表没命中 —— 按 (vendor, mnemonic) 分组计数
                      就是下一批该补的规则清单
"""
