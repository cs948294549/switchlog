# -*- coding: utf-8 -*-
"""
switchlog 告警管线

    L0    prepare      剥信封 + 剥 mnemonic，全链路只做一次
    L0.5  blacklist    子串/mnemonic 黑名单，命中即丢，不进后面任何一层
    L1    parser       (vendor, mnemonic) -> event_code，按 object_regex 抽 object
    L2    enrich       devices 补 sysname/hardware/syscontact，ports 补接口描述
    L2.5  attrs        按 event_code 查 syslog_event，补 severity/state/窗口/clear_code
    L3    suppress     drop / mute / depend 三档抑制                  [未实现]
    L4    aggregate    md5(ip|event_code|object) 滑动窗口 + 计数      [未实现]
    L5    state_machine raise / clear / stateless + 闪断升级          [未实现]
    L6    emit         写 alarm_list                                  [未实现]

各层之间传的是 dict，每层往里增量补字段。热路径上 dict 比 dataclass 快，
而且哪一层补了哪些字段一目了然 —— 契约就写在下面。

======================= event 字段契约 =======================

    # L0 prepare 产出
    ingest_ts     int     采集时间。窗口、排序、去重一律用它
    ip            str     源 IP
    message       str     原始报文，截断 1KB
    hostname      str     报文自报的设备名，没有是 "-"
    body          str     剥掉信封后的正文，含 %MNEMONIC: 段
    mnemonic      str     header 段剥出的关键字
    readable      bool    False=报文不可读 -> PARSE_FAIL

    # L1 parser 产出
    vendor        str     devices.vendor 原值
    event_code    str     统一事件码，兜底三值见下
    alarm_object  str     归一化后的告警对象，参与 L4 指纹
    object_raw    str     报文里的原始写法，排查用
    rule_id       int     命中的规则行

    # L2 enrich 产出
    sysname       str     devices.sysname
    hardware      str     devices.hardware
    syscontact    str     devices.syscontact（现网存资产号）
    sysdesc       str     devices.sysdesc
    sys_type      str     devices.sys_type
    managed       bool    设备是否在 devices 表里
    src_state     str     MANAGED / UNMANAGED_SRC / SRC_LOOKUP_FAILED
    if_name       str     接口全名，非接口对象为空
    if_alias      str     接口描述，非接口对象为空

    # L2.5 attrs 产出
    severity      int     1=P1 2=P2 3=P3
    state         str     raise / clear / stateless
    object_type   str     interface / peer / mac / slot / none
    window_sec    int     聚合窗口
    threshold     int     窗口内达到该条数才告警
    clear_code    str     恢复事件码，L5 据此配对

三个兜底事件码同样走过整条管线，级别和窗口可在 syslog_event 里调：

    PARSE_FAIL        报文不可读（无 PRI/时间戳，也剥不出 mnemonic）
    UNMANAGED_SRC     源 IP 在 devices 表里查不到厂商
    UNKNOWN_MNEMONIC  规则表没命中 —— 按 (vendor, mnemonic) 分组计数
                      就是下一批该补的规则清单
"""
