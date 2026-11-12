# -*- coding: utf-8 -*-
"""
测试样本：mock 表数据 + 现场报文

五张表的数据字段名和 sql/schema.sql 一字不差，表定稿后整段搬进 insert 即可。
报文样本取自现网日志（已脱敏），覆盖三种兜底路径：
未纳管 IP、报文不可读、mnemonic 没配规则。

数据在这里，替身在 mock_db.py，跑法在 ../test.py。
"""
import logging

logger = logging.getLogger(__name__)

# ============================================================
# devices 表：ip -> 一行
#
# vendor 原值供 L1 匹配规则；sysname/hardware/syscontact 供 L2 富化。
# syscontact 在现网存的是资产号。
# ============================================================
MOCK_DEVICES = {
    # test.py 里那段 bbs1_dc05_m01_new 现场日志的源设备
    "10.16.249.5": {"vendor": "cisco_nx", "sysname": "bbs1_dc05_m01_new",
                    "hardware": "N9K-C9336C-FX2", "syscontact": "ZC2024001382",
                    "sysdesc": "Cisco Nexus Operating System (NX-OS) Software",
                    "sys_type": "switch"},
    "10.19.7.1":  {"vendor": "cisco_nx", "sysname": "pcs1_dc07_m01",
                   "hardware": "N9K-C93180YC-FX", "syscontact": "ZC2024002011",
                   "sysdesc": "Cisco Nexus Operating System (NX-OS) Software",
                   "sys_type": "switch"},
    "10.19.7.2":  {"vendor": "cisco_nx", "sysname": "pcs2_dc07_m01",
                   "hardware": "N9K-C93180YC-FX", "syscontact": "ZC2024002012",
                   "sysdesc": "Cisco Nexus Operating System (NX-OS) Software",
                   "sys_type": "switch"},
    "10.19.8.11": {"vendor": "h3c",      "sysname": "asw1_dc08_m02",
                   "hardware": "S5560X-30C-EI", "syscontact": "ZC2023008877",
                   "sysdesc": "H3C Comware Software, Version 7.1.070",
                   "sys_type": "switch"},
    "10.19.8.12": {"vendor": "huawei",   "sysname": "asw2_dc08_m02",
                   "hardware": "S5735-L24T4X", "syscontact": "ZC2023008891",
                   "sysdesc": "Huawei Versatile Routing Platform Software VRP V200R022",
                   "sys_type": "switch"},
    "10.19.9.21": {"vendor": "fortinet", "sysname": "fw1_corp_ts_m21",
                   "hardware": "FortiGate-600E", "syscontact": "ZC2022004510",
                   "sysdesc": "FortiGate-600E v7.0.12",
                   "sys_type": "firewall"},
    # 下面三台专门给定级规则用：同一条 IF_DOWN 日志，三台设备三个结果。
    # 命名前缀的含义见 docs/network/设备命名规范.md，csw=内网核心、rsw=接入
    "10.19.19.1":  {"vendor": "cisco_nx", "sysname": "csw1_dc19_m01",
                    "hardware": "N9K-C9336C-FX2", "syscontact": "ZC2024003001",
                    "sysdesc": "Cisco Nexus Operating System (NX-OS) Software",
                    "sys_type": "switch"},
    "10.19.19.11": {"vendor": "cisco_nx", "sysname": "rsw1_dc19_m05",
                    "hardware": "N9K-C93180YC-FX", "syscontact": "ZC2024003011",
                    "sysdesc": "Cisco Nexus Operating System (NX-OS) Software",
                    "sys_type": "switch"},
    "10.19.9.31":  {"vendor": "cisco_nx", "sysname": "rsw1_corp_ts_m21",
                    "hardware": "N9K-C93180YC-FX", "syscontact": "ZC2022004531",
                    "sysdesc": "Cisco Nexus Operating System (NX-OS) Software",
                    "sys_type": "switch"},
    # 纳管了但 vendor 还没采到，走 UNMANAGED_SRC 的另一条路径
    "10.19.9.99": {"vendor": "",         "sysname": "unknown_dev",
                   "hardware": "", "syscontact": "", "sysdesc": "",
                   "sys_type": ""},
}

# ports 表：ip -> 接口清单
#
# if_name 是全名，alias 是设备上配的描述（L2 补全用）。
# BFD 日志里写的是 Eth1/6，ETHPORT 日志里写的是 Ethernet1/6，
# 同一个口两种写法 —— L2 靠短名展开把它们对到同一行。
MOCK_PORTS = {
    "10.16.249.5": [
        {"if_name": "Ethernet1/1", "alias": "pT:bbs1_dc07_m01:100G1/4"},
        {"if_name": "Ethernet1/2", "alias": "pT:bbs1_dc07_m01:100G1/7"},
        {"if_name": "Ethernet1/5", "alias": "pT:bbs1_dc09_m01:100G1/5"},
        {"if_name": "Ethernet1/6", "alias": "pT:bbs1_dc09_m01:100G1/8:ZX"},
        {"if_name": "mgmt0", "alias": "oob-mgmt"},
    ],
    "10.19.7.1": [
        {"if_name": "Ethernet1/1", "alias": "pT:bbs1_dc07_m01:100G1/1"},
        {"if_name": "Ethernet1/2", "alias": "pT:bbs1_dc07_m01:100G1/2"},
        {"if_name": "Ethernet1/6", "alias": "pT:bbs1_dc09_m01:100G1/8:ZX"},
        {"if_name": "Ethernet1/38", "alias": "vpn2.net.dc07::eth0"},
        {"if_name": "Ethernet1/39", "alias": "vpn2.net.dc07::eth1"},
        {"if_name": "port-channel38", "alias": "vpn2-lag"},
        {"if_name": "mgmt0", "alias": "oob-mgmt"},
    ],
    "10.19.8.11": [
        {"if_name": "GigabitEthernet1/0/1", "alias": "to asw2_dc08_m02"},
        {"if_name": "GigabitEthernet1/0/2", "alias": "to bbs1_dc08_m01"},
        {"if_name": "Bridge-Aggregation1", "alias": "uplink-lag"},
    ],
    "10.19.8.12": [
        {"if_name": "GigabitEthernet0/0/1", "alias": "to asw1_dc08_m02"},
        {"if_name": "XGigabitEthernet0/0/1", "alias": "to bbs1_dc08_m02"},
        {"if_name": "Eth-Trunk1", "alias": "uplink-lag"},
    ],
    # 定级用的三台
    "10.19.19.1": [
        {"if_name": "Ethernet1/10", "alias": "pT:rsw1_dc19_m05:100G1/49"},
    ],
    "10.19.19.11": [
        {"if_name": "Ethernet1/10", "alias": "srv:dc19-m05-rack03"},
    ],
    "10.19.9.31": [
        {"if_name": "Ethernet1/10", "alias": "office:ts-m21-3F-ap07"},
    ],
}

# ============================================================
# syslog_rule：(vendor, mnemonic) -> event_code，object_regex 逐行配
#
# 字段与 scripts/db_syslog_pipeline.sql 的 syslog_rule 一致：
#   rule_id vendor mnemonic match_type pattern body_match
#   event_code object_regex priority descr
#
# 几条刻意保留的用法：
#   * 同一 event_code 多条 mnemonic（IF_DOWN 有三条），正文格式不同所以正则分别配
#   * 同一 mnemonic 多个 event_code（PHY_UPDOWN / BGP-5-ADJCHANGE），靠 body_match 分
#   * vendor='*' 覆盖各家写法一致的事件
#   * FOP_CHANGED 的 'to none' 必须排在兜底行前面，靠 priority 控制
# ============================================================
# syslog_black_list：解析前拦截（L0.5）
#
# 字段：rule_id pattern scope ip ignore_case enabled descr
#   scope=mnemonic  pattern 是 mnemonic 全名，进 dict，O(1) 命中
#   scope=message   pattern 是全文子串，线性扫
#   ip              限定设备，空=所有设备
#   ignore_case     1=大小写不敏感，只对 scope=message 生效
#                   （mnemonic 是设备给的固定字面量，大小写不会变）
#
# 没有 priority：黑名单只有"丢"一个动作，命中哪条结果都一样。
# 同一个键配多条是数据错误，加载时会报 error 并按 rule_id 留一条。
#
# 能按 mnemonic 配的一律用 mnemonic：实测 162 字节报文逐条 str.find，
# 20 条规则就和剥一次 mnemonic 一样贵，500 条是 21 倍；而 mnemonic
# 已由 prepare 剥好透传进来，dict 查一次只要 0.036us。
# message 那一串要保持小，每条日志都会扫它。
#
# 只放"确定是噪声、解析它纯属浪费"的日志。需要正则、需要变更窗口期
# mute、需要按机房限定的，配到 syslog_suppress_rule（L3）去。
# ============================================================
MOCK_BLACKLIST = [
    # ---- scope=mnemonic：进 dict，O(1) 命中，绝大多数规则都该是这一类 ----
    {"rule_id": 1, "pattern": "SSHD-6-SESSION_CONNECTED", "scope": "mnemonic",
     "ip": "", "ignore_case": 0, "enabled": 1,
     "descr": "SSH 建连过程，登录成功与否看 LOGIN_FAIL"},
    {"rule_id": 2, "pattern": "VSHD-5-VSHD_SYSLOG_CONFIG_I", "scope": "mnemonic",
     "ip": "", "ignore_case": 0, "enabled": 1,
     "descr": "配置变更的逐条回显，量大且无告警价值"},
    # 只拦某台设备：进 (ip, mnemonic) 那张 dict，不参与全量流量
    {"rule_id": 5, "pattern": "ETHPORT-5-IF_DOWN_CHANNEL_ADMIN_DOWN", "scope": "mnemonic",
     "ip": "10.16.249.5", "ignore_case": 0, "enabled": 1,
     "descr": "该设备成员口人工 shutdown 后持续刷，确认过无影响"},
    # 停用的规则：加载时被 enabled 过滤掉，验证开关
    {"rule_id": 6, "pattern": "BFD-5-SESSION_MOVED", "scope": "mnemonic",
     "ip": "", "ignore_case": 0, "enabled": 0,
     "descr": "停用示例：这条已改为走 L1 的 BFD_SESSION_CHG + L3 drop"},

    # ---- scope=message：线性扫，只给不带 mnemonic 的报文头噪声用 ----
    # 这一串必须保持小。能写成 mnemonic 的别往这里放，每条日志都要扫它
    {"rule_id": 3, "pattern": "last message repeated", "scope": "message",
     "ip": "", "ignore_case": 1, "enabled": 1,
     "descr": "syslog 自身的折叠提示，不带 mnemonic，只能按全文拦"},
    {"rule_id": 4, "pattern": "Configuration update aborted", "scope": "message",
     "ip": "", "ignore_case": 0, "enabled": 1,
     "descr": "配置回滚的调试输出，不带 mnemonic"},
]

MOCK_RULES = [
    # ---- NX-OS 物理口 down：三种正文格式，抽出来必须都是 Ethernet1/38 ----
    # 接口名后面跟什么由正文决定：IF_DOWN 跟逗号，LINK_FAILURE 跟空格再跟
    # (description:...)。字符类同时排掉空格/逗号/左括号，两种正文一套正则吃下，
    # 且绝不会把 description 里的内容当接口名
    {"rule_id": 1, "vendor": "cisco_nx", "mnemonic": "ETHPORT-5-IF_DOWN",
     "match_type": "exact", "pattern": "", "body_match": "",
     "event_code": "IF_DOWN", "object_regex": r"Interface\s+([^\s,(]+)",
     "priority": 100, "descr": "Interface Ethernet1/38, changed state to down"},
    {"rule_id": 2, "vendor": "cisco_nx", "mnemonic": "ETHPORT-5-IF_DOWN_LINK_FAILURE",
     "match_type": "exact", "pattern": "", "body_match": "",
     "event_code": "IF_DOWN", "object_regex": r"Interface\s+([^\s,(]+)",
     "priority": 100, "descr": "Interface Eth1/38 (description:..) is down (Link failure)"},
    {"rule_id": 3, "vendor": "cisco_nx", "mnemonic": "LINEPROTO-5-UPDOWN",
     "match_type": "exact", "pattern": "", "body_match": "changed state to down",
     "event_code": "IF_DOWN", "object_regex": r"on Interface\s+([^,\s]+),",
     "priority": 100, "descr": "Line protocol on Interface Eth1/38, changed state to down"},
    {"rule_id": 4, "vendor": "cisco_nx", "mnemonic": "LINEPROTO-5-UPDOWN",
     "match_type": "exact", "pattern": "", "body_match": "changed state to up",
     "event_code": "IF_UP", "object_regex": r"on Interface\s+([^,\s]+),",
     "priority": 100, "descr": "Line protocol up"},
    {"rule_id": 5, "vendor": "cisco_nx", "mnemonic": "ETH_PORT_CHANNEL-5-PORT_DOWN",
     "match_type": "exact", "pattern": "", "body_match": "",
     "event_code": "IF_DOWN", "object_regex": r":\s+(\S+)\s+is\s+down",
     "priority": 100, "descr": "port-channel38: Ethernet1/38 is down，对象是成员口不是 LAG"},

    # ---- LAG：FOP_CHANGED 的 'to none' 才是全断，priority 小的先判 ----
    # object_regex 跑在整段正文上（含 %MNEMONIC: 前缀），所以不能用 ^ 锚定，
    # 否则抓到的是 mnemonic 自己。靠 "冒号+空格+名字+冒号" 定位行首的 LAG 名
    {"rule_id": 6, "vendor": "cisco_nx", "mnemonic": "ETH_PORT_CHANNEL-5-FOP_CHANGED",
     "match_type": "exact", "pattern": "", "body_match": "to none",
     "event_code": "LAG_DOWN", "object_regex": r":\s+(\S+?):",
     "priority": 10, "descr": "最后一个可用成员没了，LAG 全断"},
    {"rule_id": 7, "vendor": "cisco_nx", "mnemonic": "ETH_PORT_CHANNEL-5-FOP_CHANGED",
     "match_type": "exact", "pattern": "", "body_match": "",
     "event_code": "LAG_MEMBER_CHG", "object_regex": r":\s+(\S+?):",
     "priority": 200, "descr": "还有成员时是正常冗余切换，噪声"},
    {"rule_id": 8, "vendor": "cisco_nx",
     "mnemonic": "ETHPORT-5-IF_DOWN_PORT_CHANNEL_MEMBERS_DOWN",
     "match_type": "exact", "pattern": "", "body_match": "",
     "event_code": "LAG_DOWN", "object_regex": r"Interface\s+([^\s,(]+)",
     "priority": 100, "descr": "Interface port-channel38 is down (No operational members)"},

    # ---- Comware / 华为：同一 mnemonic，up/down 只差正文 ----
    # body_match 必须抄现网正文的原字符串，不能按手册写法臆造：
    # H3C 是 "changed to down."，华为是 "turned into DOWN state."
    {"rule_id": 9, "vendor": "h3c", "mnemonic": "IFNET/3/PHY_UPDOWN",
     "match_type": "exact", "pattern": "", "body_match": "changed to down",
     "event_code": "IF_DOWN", "object_regex": r"interface (\S+?) changed",
     "priority": 100, "descr": "Physical state on the interface GE1/0/1 changed to down."},
    {"rule_id": 10, "vendor": "h3c", "mnemonic": "IFNET/3/PHY_UPDOWN",
     "match_type": "exact", "pattern": "", "body_match": "changed to up",
     "event_code": "IF_UP", "object_regex": r"interface (\S+?) changed",
     "priority": 100, "descr": "H3C 物理口 up"},
    {"rule_id": 11, "vendor": "huawei", "mnemonic": "IFNET/3/PHY_UPDOWN",
     "match_type": "exact", "pattern": "", "body_match": "turned into DOWN",
     "event_code": "IF_DOWN", "object_regex": r"interface (\S+?) has",
     "priority": 100, "descr": "The interface XGE0/0/1 has turned into DOWN state."},
    {"rule_id": 12, "vendor": "huawei", "mnemonic": "IFNET/3/PHY_UPDOWN",
     "match_type": "exact", "pattern": "", "body_match": "turned into UP",
     "event_code": "IF_UP", "object_regex": r"interface (\S+?) has",
     "priority": 100, "descr": "华为物理口 up"},

    # ---- 各家写法一致的用 vendor='*' 一行覆盖 ----
    # 两种正文都有：Interface Eth1/6, operational state... 和
    # Interface Eth1/6 (description:...) is up in Layer3
    {"rule_id": 13, "vendor": "*", "mnemonic": "ETHPORT-5-IF_UP",
     "match_type": "exact", "pattern": "", "body_match": "",
     "event_code": "IF_UP", "object_regex": r"Interface\s+([^\s,(]+)",
     "priority": 100, "descr": "NX-OS 端口 up"},
    {"rule_id": 14, "vendor": "*", "mnemonic": "BGP-5-ADJCHANGE",
     "match_type": "exact", "pattern": "", "body_match": "Down",
     "event_code": "BGP_DOWN", "object_regex": r"neighbor\s+(\d+\.\d+\.\d+\.\d+)",
     "priority": 100, "descr": "BGP 邻居 down"},
    {"rule_id": 15, "vendor": "*", "mnemonic": "BGP-5-ADJCHANGE",
     "match_type": "exact", "pattern": "", "body_match": "Up",
     "event_code": "BGP_UP", "object_regex": r"neighbor\s+(\d+\.\d+\.\d+\.\d+)",
     "priority": 100, "descr": "BGP 邻居 up"},
    # BFD 掉了就是 BGP 掉了，归到同一个 event_code，同一指纹只出一条告警
    {"rule_id": 16, "vendor": "*", "mnemonic": "BFD-5-SESSION_STATE_DOWN",
     "match_type": "exact", "pattern": "", "body_match": "",
     "event_code": "BGP_DOWN", "object_regex": r"neighbor\s+(\d+\.\d+\.\d+\.\d+)",
     "priority": 100, "descr": "BFD 会话 down，和 BGP_DOWN 同指纹"},

    # ---- FortiGate：mnemonic 取 logid ----
    {"rule_id": 17, "vendor": "fortinet", "mnemonic": "0100032003",
     "match_type": "exact", "pattern": "", "body_match": "",
     "event_code": "LOGIN_FAIL", "object_regex": "",
     "priority": 100, "descr": "管理员登录失败"},
    {"rule_id": 18, "vendor": "fortinet", "mnemonic": "0101037129",
     "match_type": "exact", "pattern": "", "body_match": "",
     "event_code": "BGP_DOWN", "object_regex": r"remote_ip=(\d+\.\d+\.\d+\.\d+)",
     "priority": 100, "descr": "IPSec 隧道 down 当邻居 down 处理"},

    # ---- 噪声类：设计 §4.8 标的 "drop" ----
    # L1 不做 drop，那是 L3 的事。这里照常给事件码，L3 配一条 drop 规则把
    # BFD_SESSION_CHG / IF_ATTR_CHG 拦掉即可。好处是它们不再混进
    # UNKNOWN_MNEMONIC 的规则缺口清单，缺口清单才有参考价值。
    {"rule_id": 19, "vendor": "*", "mnemonic": "BFD-5-SESSION_REMOVED",
     "match_type": "exact", "pattern": "", "body_match": "",
     "event_code": "BFD_SESSION_CHG", "object_regex": r"neighbor\s+(\d+\.\d+\.\d+\.\d+)",
     "priority": 100, "descr": "BFD 会话删除，down 之后的必然结果，噪声"},
    {"rule_id": 20, "vendor": "*", "mnemonic": "BFD-5-SESSION_MOVED",
     "match_type": "exact", "pattern": "", "body_match": "",
     "event_code": "BFD_SESSION_CHG", "object_regex": "",
     "priority": 100, "descr": "BFD 会话在板卡间迁移，噪声"},
    # 端口 up 之后必然跟着这四条属性日志，一次 up 刷四条，全归一个码
    {"rule_id": 21, "vendor": "*", "mnemonic": "ETHPORT-5-SPEED",
     "match_type": "exact", "pattern": "", "body_match": "",
     "event_code": "IF_ATTR_CHG", "object_regex": r"Interface\s+([^\s,(]+)",
     "priority": 100, "descr": "协商速率变化，端口 up 的伴生日志"},
    {"rule_id": 22, "vendor": "*", "mnemonic": "ETHPORT-5-IF_DUPLEX",
     "match_type": "exact", "pattern": "", "body_match": "",
     "event_code": "IF_ATTR_CHG", "object_regex": r"Interface\s+([^\s,(]+)",
     "priority": 100, "descr": "双工模式变化，伴生日志"},
    {"rule_id": 23, "vendor": "*", "mnemonic": "ETHPORT-5-IF_RX_FLOW_CONTROL",
     "match_type": "exact", "pattern": "", "body_match": "",
     "event_code": "IF_ATTR_CHG", "object_regex": r"Interface\s+([^\s,(]+)",
     "priority": 100, "descr": "收向流控变化，伴生日志"},
    {"rule_id": 24, "vendor": "*", "mnemonic": "ETHPORT-5-IF_TX_FLOW_CONTROL",
     "match_type": "exact", "pattern": "", "body_match": "",
     "event_code": "IF_ATTR_CHG", "object_regex": r"Interface\s+([^\s,(]+)",
     "priority": 100, "descr": "发向流控变化，伴生日志"},

    # ---- mnemonic 留空：剥不出 mnemonic 的报文才走这里（三级模糊匹配）----
    {"rule_id": 25, "vendor": "*", "mnemonic": "",
     "match_type": "contains", "pattern": "authentication failure", "body_match": "",
     "event_code": "LOGIN_FAIL", "object_regex": "",
     "priority": 300, "descr": "无 mnemonic 的 sshd 日志兜底"},
    {"rule_id": 26, "vendor": "*", "mnemonic": "",
     "match_type": "regex", "pattern": r"[Cc]onfigured from (console|vty)", "body_match": "",
     "event_code": "CONFIG_CHG", "object_regex": "",
     "priority": 300, "descr": "无 mnemonic 的配置变更兜底"},
]

# ============================================================
# syslog_event：事件属性，按 event_code 一行
#
# state / object_type / window_sec / threshold / clear_code 都在这里，
# 不在匹配行上 —— IF_DOWN 有三条 mnemonic × 几家厂商，属性存一份，
# 改窗口改一行、全厂商同时生效。
#
# 没有 severity：级别取决于"哪个事件 + 哪台设备"，在下面那张
# MOCK_SEVERITY_RULES 里定。
#
# L1 不读这张表：它在 L2 富化之后才查。
# 前三行是解析器自己产生的兜底码，必须存在，否则窗口没地方调。
# ============================================================
MOCK_EVENTS = [
    {"event_code": "UNKNOWN_MNEMONIC", "state": "stateless", "object_type": "none",
     "window_sec": 600, "threshold": 1, "clear_code": "",
     "descr": "mnemonic 在规则表里没有对应规则，同时是规则缺口清单"},
    {"event_code": "PARSE_FAIL", "state": "stateless", "object_type": "none",
     "window_sec": 600, "threshold": 5, "clear_code": "",
     "descr": "信封解析失败，单台设备持续发垃圾日志即配置错误"},
    {"event_code": "UNMANAGED_SRC", "state": "stateless", "object_type": "none",
     "window_sec": 600, "threshold": 1, "clear_code": "",
     "descr": "src_ip 在 devices 表里查不到厂商，用于发现未纳管设备"},

    {"event_code": "IF_DOWN", "state": "raise", "object_type": "interface",
     "window_sec": 300, "threshold": 1, "clear_code": "IF_UP", "descr": "端口 down"},
    {"event_code": "IF_UP", "state": "clear", "object_type": "interface",
     "window_sec": 300, "threshold": 1, "clear_code": "", "descr": "端口 up"},
    {"event_code": "LAG_DOWN", "state": "raise", "object_type": "interface",
     "window_sec": 300, "threshold": 1, "clear_code": "LAG_UP", "descr": "聚合口 down"},
    {"event_code": "LAG_UP", "state": "clear", "object_type": "interface",
     "window_sec": 300, "threshold": 1, "clear_code": "", "descr": "聚合口 up"},
    {"event_code": "LAG_MEMBER_CHG", "state": "stateless", "object_type": "interface",
     "window_sec": 600, "threshold": 1, "clear_code": "", "descr": "聚合口成员变化"},
    {"event_code": "BGP_DOWN", "state": "raise", "object_type": "peer",
     "window_sec": 300, "threshold": 1, "clear_code": "BGP_UP", "descr": "BGP 邻居 down"},
    {"event_code": "BGP_UP", "state": "clear", "object_type": "peer",
     "window_sec": 300, "threshold": 1, "clear_code": "", "descr": "BGP 邻居 up"},
    {"event_code": "MAC_FLAP", "state": "stateless", "object_type": "mac",
     "window_sec": 600, "threshold": 3, "clear_code": "", "descr": "MAC 漂移，到阈值才告警"},
    # 下面两个是噪声码：enabled=1 让 L1 认得它们、不落进规则缺口清单，
    # 真正的拦截在 L3 配 drop 规则，不在这里靠 enabled=0 关
    {"event_code": "BFD_SESSION_CHG", "state": "stateless", "object_type": "peer",
     "window_sec": 600, "threshold": 1, "clear_code": "",
     "descr": "BFD 会话删除/迁移，BGP_DOWN 的伴生日志，L3 drop"},
    {"event_code": "IF_ATTR_CHG", "state": "stateless", "object_type": "interface",
     "window_sec": 600, "threshold": 1, "clear_code": "",
     "descr": "速率/双工/流控变化，端口 up 的伴生日志，建议配黑名单"},
    # L5 自己产生的码，没有对应 mnemonic，不在 MOCK_RULES 里。
    # clear_code 留空是故意的：闪断禁止自动恢复，必须人工确认
    {"event_code": "IF_FLAP", "state": "raise", "object_type": "interface",
     "window_sec": 1800, "threshold": 3, "clear_code": "",
     "descr": "端口闪断，L5 长窗口计数升级产生，禁止自动恢复"},
    {"event_code": "CONFIG_CHG", "state": "stateless", "object_type": "none",
     "window_sec": 600, "threshold": 1, "clear_code": "", "descr": "配置变更"},
    {"event_code": "LOGIN_FAIL", "state": "stateless", "object_type": "none",
     "window_sec": 600, "threshold": 1, "clear_code": "", "descr": "登录失败"},
]

# ============================================================
# syslog_severity_rule：(event_code, ip, sysname) -> severity
#
# 字段与 sql/schema.sql 的 syslog_severity_rule 一致：
#   rule_id event_code ip_reg sysname_reg severity action priority descr
#
# 级别不是事件的固有属性 —— 同一个 IF_DOWN，csw 掉口是核心网段断了，
# rsw 掉口是一个机柜的接入，corp 职场的 rsw 掉口压根不用看。
#
# IF_DOWN 的候选链（priority 升序，首条命中即停）：
#     corp rsw -> csw -> rsw -> IF_DOWN 默认 -> *
# 其余事件码没写专门行，直接落最后那条 '*'。
#
# 几条刻意保留的用法：
#   * priority 控顺序：corp 那条必须小于通用 rsw，否则 rsw1_corp_ts_m21
#     会先命中 ^rsw 被降成 P3，而不是被忽略
#   * action=ignore：不开告警，但事件照样走完管线、日志照样归档
#   * event_code='*' 的全局兜底，缺了加载时会打 error
#   * rule 7 用 ip_reg 而不是 sysname_reg，验证两种判据都能走
# ============================================================
MOCK_SEVERITY_RULES = [
    # 判据最窄的排最前。severity 填 3 只是占位，action=ignore 时级别不参与告警
    {"rule_id": 1, "event_code": "IF_DOWN", "ip_reg": "", "sysname_reg": r"^rsw.*corp",
     "severity": 3, "action": "ignore", "priority": 10, "enabled": 1,
     "descr": "corp 职场接入口 down 不告警，单机柜接入无冗余且有人值守"},
    # 同一个 IF_DOWN，核心和接入不是一个量级
    {"rule_id": 2, "event_code": "IF_DOWN", "ip_reg": "", "sysname_reg": r"^csw",
     "severity": 1, "action": "", "priority": 50, "enabled": 1,
     "descr": "核心口 down 升 P1，csw 是内网网段网关"},
    {"rule_id": 3, "event_code": "IF_DOWN", "ip_reg": "", "sysname_reg": r"^rsw",
     "severity": 3, "action": "", "priority": 50, "enabled": 1,
     "descr": "接入口 down 降 P3，rsw 是 ToR，影响一个机柜"},
    # 各事件码的默认级别，没有设备判据
    {"rule_id": 4, "event_code": "IF_DOWN", "ip_reg": "", "sysname_reg": "",
     "severity": 2, "action": "", "priority": 100, "enabled": 1,
     "descr": "端口 down 的默认级别"},
    {"rule_id": 5, "event_code": "LAG_DOWN", "ip_reg": "", "sysname_reg": "",
     "severity": 1, "action": "", "priority": 100, "enabled": 1,
     "descr": "聚合口全断，不分角色都是 P1"},
    {"rule_id": 6, "event_code": "BGP_DOWN", "ip_reg": "", "sysname_reg": "",
     "severity": 1, "action": "", "priority": 100, "enabled": 1,
     "descr": "BGP 邻居 down"},
    # 按网段定级：10.19.9.x 是测试环境，级别压一档
    {"rule_id": 7, "event_code": "MAC_FLAP", "ip_reg": r"^10[.]19[.]9[.]",
     "sysname_reg": "", "severity": 3, "action": "", "priority": 50, "enabled": 1,
     "descr": "测试网段的 MAC 漂移降 P3，验证 ip_reg 判据"},
    {"rule_id": 8, "event_code": "MAC_FLAP", "ip_reg": "", "sysname_reg": "",
     "severity": 2, "action": "", "priority": 100, "enabled": 1,
     "descr": "MAC 漂移"},
    # 闪断不分角色都是 P1。注意它不继承 IF_DOWN 的定级：corp rsw 的
    # IF_DOWN 配了 ignore，但同一个口真闪起来照样升出 IF_FLAP 按 P1 告警
    {"rule_id": 11, "event_code": "IF_FLAP", "ip_reg": "", "sysname_reg": "",
     "severity": 1, "action": "", "priority": 100, "enabled": 1,
     "descr": "端口闪断，L5 升级产生"},
    # 停用的规则：加载时被 enabled 过滤掉，验证开关
    {"rule_id": 9, "event_code": "BGP_UP", "ip_reg": "", "sysname_reg": "",
     "severity": 1, "action": "", "priority": 50, "enabled": 0,
     "descr": "停用示例：恢复事件没有升 P1 的道理，留着验证 enabled"},
    # 全局兜底。唯一允许匹配全网所有事件的规则，删了会打 error
    {"rule_id": 10, "event_code": "*", "ip_reg": "", "sysname_reg": "",
     "severity": 3, "action": "", "priority": 999, "enabled": 1,
     "descr": "全局兜底，没写专门规则的事件码都是 P3"},
]
MOCK_MESSAGES = [
    # ---- §4.7 一次 port-channel 掉线 ----
    ("10.19.7.1",
     "<189>2026 Oct  9 05:18:56.565 pcs1_dc07_m01 %ETH_PORT_CHANNEL-5-FOP_CHANGED: "
     "port-channel38: first operational port changed from Ethernet1/38 to none",
     "LAG_DOWN", "port-channel38"),
    ("10.19.7.1",
     "<189>2026 Oct  9 05:18:56.576 pcs1_dc07_m01 %ETH_PORT_CHANNEL-5-PORT_DOWN: "
     "port-channel38: Ethernet1/38 is down",
     "IF_DOWN", "Ethernet1/38"),
    ("10.19.7.1",
     "<189>2026 Oct  9 05:18:56.585 pcs1_dc07_m01 "
     "%ETHPORT-5-IF_DOWN_PORT_CHANNEL_MEMBERS_DOWN: Interface port-channel38 is down "
     "(No operational members)",
     "LAG_DOWN", "port-channel38"),
    # description 里藏着假接口名，正则不能跨越左括号
    ("10.19.7.1",
     "<189>2026 Oct  9 05:18:56.612 pcs1_dc07_m01 %ETHPORT-5-IF_DOWN_LINK_FAILURE: "
     "Interface Ethernet1/38 (description:vpn2.net.dc07::eth0) is down (Link failure)",
     "IF_DOWN", "Ethernet1/38"),
    # 和上面第 3 条完全重复，隔 30ms，指纹相同只累加 count
    ("10.19.7.1",
     "<189>2026 Oct  9 05:18:56.615 pcs1_dc07_m01 "
     "%ETHPORT-5-IF_DOWN_PORT_CHANNEL_MEMBERS_DOWN: Interface port-channel38 is down "
     "(No operational members)",
     "LAG_DOWN", "port-channel38"),

    # ---- FOP_CHANGED 不是 'to none'：有冗余的正常切换，低级别 ----
    ("10.19.7.1",
     "<189>2026 Oct  9 05:19:01.100 pcs1_dc07_m01 %ETH_PORT_CHANNEL-5-FOP_CHANGED: "
     "port-channel38: first operational port changed from Ethernet1/38 to Ethernet1/39",
     "LAG_MEMBER_CHG", "port-channel38"),

    # ---- §4.8 BGP + BFD 归同一事件码、同一对象 ----
    ("10.19.7.2",
     "<189>Oct 11 14:03:08.111 pcs2_dc07_m01 %BGP-5-ADJCHANGE: neighbor 172.28.2.133 "
     "Down - BGP Notification sent",
     "BGP_DOWN", "172.28.2.133"),
    ("10.19.7.2",
     "<189>Oct 11 14:03:08.111 pcs2_dc07_m01 %BFD-5-SESSION_STATE_DOWN: "
     "BFD session to neighbor 172.28.2.133 on interface Ethernet1/6 has gone down",
     "BGP_DOWN", "172.28.2.133"),
    ("10.19.7.2",
     "<189>Oct 11 14:03:32.731 pcs2_dc07_m01 %BGP-5-ADJCHANGE: neighbor 172.28.2.133 Up",
     "BGP_UP", "172.28.2.133"),

    # ---- 时间戳三种写法：无年份 / 带年份 / ISO8601 都要吃掉 ----
    ("10.19.7.1",
     "<189>Oct 11 14:03:08.109 pcs1_dc07_m01 %ETHPORT-5-IF_DOWN_LINK_FAILURE: "
     "Interface Ethernet1/6 is down (Link failure)",
     "IF_DOWN", "Ethernet1/6"),
    ("10.19.7.1",
     "<189>2026-11-11T05:18:56.565+08:00 pcs1_dc07_m01 %ETHPORT-5-IF_UP: "
     "Interface Ethernet1/6, operational state changed to up",
     "IF_UP", "Ethernet1/6"),

    # ---- Comware：同一 mnemonic，up/down 靠 body_match 分 ----
    ("10.19.8.11",
     "<189>Nov 11 09:12:33 asw1_dc08_m02 %%10IFNET/3/PHY_UPDOWN: "
     "Physical state on the interface GigabitEthernet1/0/1 changed to down.",
     "IF_DOWN", "GigabitEthernet1/0/1"),
    ("10.19.8.11",
     "<189>Nov 11 09:12:48 asw1_dc08_m02 %%10IFNET/3/PHY_UPDOWN: "
     "Physical state on the interface GigabitEthernet1/0/1 changed to up.",
     "IF_UP", "GigabitEthernet1/0/1"),
    # 华为同 mnemonic，大写 DOWN，vendor 不同所以命中的是另一行规则
    ("10.19.8.12",
     "<189>Nov 11 09:13:01 asw2_dc08_m02 %%01IFNET/3/PHY_UPDOWN: "
     "The interface XGigabitEthernet0/0/1 has turned into DOWN state.",
     "IF_DOWN", "XGigabitEthernet0/0/1"),

    # ---- FortiGate：mnemonic 取 logid ----
    ("10.19.9.21",
     'date=2026-11-11 time=09:20:11 devname="fw1_corp_ts_m21" type=event subtype=system '
     'level=alert logid="0100032003" msg="Administrator admin login failed from ssh(10.1.2.3)"',
     "LOGIN_FAIL", "-"),

    # ---- 三条兜底路径 ----
    # 规则表没这条 mnemonic -> 规则缺口清单
    ("10.19.7.1",
     "<189>Oct 11 14:38:32.709 pcs1_dc07_m01 %ETHPORT-5-IF_SFP_WARNING: "
     "Interface Ethernet1/9, Failed due to SFP validation failure",
     "UNKNOWN_MNEMONIC", "-"),
    # devices 表里没这个 IP -> 该补纳管
    ("10.19.250.8",
     "<189>Oct 11 14:03:08.109 some_dev %ETHPORT-5-IF_DOWN: "
     "Interface Ethernet1/1, changed state to down",
     "UNMANAGED_SRC", "-"),
    # 纳管了但 vendor 还没采到，同样走 UNMANAGED_SRC
    ("10.19.9.99",
     "<189>Oct 11 14:03:08.109 unknown_dev %ETHPORT-5-IF_DOWN: "
     "Interface Ethernet1/1, changed state to down",
     "UNMANAGED_SRC", "-"),
    # 连 PRI 和时间戳都没有 -> 报文不可读
    ("10.19.7.1", "garbage binary payload \x01\x02", "PARSE_FAIL", "-"),

    # ---- 剥不出 mnemonic，走 mnemonic='' 的模糊规则 ----
    ("10.19.7.1",
     "<38>Nov 11 09:30:02 pcs1_dc07_m01 sshd[1234]: authentication failure for admin "
     "from 10.1.2.3",
     "LOGIN_FAIL", "-"),
    ("10.19.7.1",
     "<189>Nov 11 09:31:40 pcs1_dc07_m01 Configured from vty by admin on 10.1.2.3",
     "CONFIG_CHG", "-"),

    # ---- L2.5 定级：同一条 IF_DOWN，三台设备三个结果 ----
    # 报文除了设备名一模一样，event_code 和 object 也一样，
    # 差别只在 severity —— 期望值这两列对不出区别，看 test.py 的定级那段
    ("10.19.19.1",
     "<189>Nov 11 10:00:01 csw1_dc19_m01 %ETHPORT-5-IF_DOWN: "
     "Interface Ethernet1/10, changed state to down",
     "IF_DOWN", "Ethernet1/10"),              # csw  -> P1，rule 2
    ("10.19.19.11",
     "<189>Nov 11 10:00:02 rsw1_dc19_m05 %ETHPORT-5-IF_DOWN: "
     "Interface Ethernet1/10, changed state to down",
     "IF_DOWN", "Ethernet1/10"),              # rsw  -> P3，rule 3
    ("10.19.9.31",
     "<189>Nov 11 10:00:03 rsw1_corp_ts_m21 %ETHPORT-5-IF_DOWN: "
     "Interface Ethernet1/10, changed state to down",
     "IF_DOWN", "Ethernet1/10"),              # corp rsw -> ignore，rule 1
    # 同一台 csw 的 LAG_DOWN 没有专门规则，落 LAG_DOWN 的默认行 P1
    ("10.19.19.1",
     "<189>Nov 11 10:00:04 csw1_dc19_m01 "
     "%ETHPORT-5-IF_DOWN_PORT_CHANNEL_MEMBERS_DOWN: Interface port-channel10 is down "
     "(No operational members)",
     "LAG_DOWN", "port-channel10"),
    # csw 的 IF_UP 没有专门规则，落全局兜底 '*' 的 P3
    ("10.19.19.1",
     "<189>Nov 11 10:05:01 csw1_dc19_m01 %ETHPORT-5-IF_UP: "
     "Interface Ethernet1/10, operational state changed to up",
     "IF_UP", "Ethernet1/10"),
]

# ============================================================
# bbs1_dc05_m01_new 2026-11-04 00:13 现场：Eth1/6 光路闪断
#
# 24 条日志，一个故障。没有 <PRI>，设备直接以 "2026 Nov  4" 开头，
# 信封解析靠带年份那条时间戳正则吃下。
#
# 收敛后的样子（object 已按正文抽取，未做短名展开）：
#   IF_DOWN  Eth1/1 Eth1/2 Ethernet1/6      3 个指纹，各 1 条
#   BGP_DOWN 四个邻居                        4 个指纹，各 2 条（BGP + BFD）
#   IF_UP / BGP_UP                           回关上面三个
#   BFD_SESSION_CHG / IF_ATTR_CHG            噪声，L3 配 drop
#
# 注意 BFD 日志写 Eth1/6、ETHPORT 日志写 Ethernet1/6，是同一个口两种写法。
# 这里 object 只按正文抽，所以不会混；等 §4.1.6 的短名展开落地后，
# 要确认它不会把 BFD 的 peer 对象也一起改掉。
# ============================================================
MOCK_MESSAGES_DC05 = [
    ("10.16.249.5",
     "2026 Nov  4 00:13:08.109 bbs1_dc05_m01_new %ETHPORT-5-IF_DOWN_LINK_FAILURE: "
     "Interface Ethernet1/6 (description:pT:bbs1_dc09_m01:100G1/8:ZX) is down (Link failure)",
     "IF_DOWN", "Ethernet1/6"),
    ("10.16.249.5",
     "2026 Nov  4 00:13:08.111 bbs1_dc05_m01_new %BGP-5-ADJCHANGE:  bgp- [25358] (default) "
     "neighbor 172.28.2.133 Down - sent:  bfd session down",
     "BGP_DOWN", "172.28.2.133"),
    ("10.16.249.5",
     "2026 Nov  4 00:13:08.111 bbs1_dc05_m01_new %BFD-5-SESSION_STATE_DOWN: "
     "BFD session 1090519198 to neighbor 172.28.2.133 on interface Eth1/6 has gone down. "
     "Reason: Path Down.",
     "BGP_DOWN", "172.28.2.133"),
    ("10.16.249.5",
     "2026 Nov  4 00:13:08.160 bbs1_dc05_m01_new %BGP-5-ADJCHANGE:  bgp- [25358] (default) "
     "neighbor 172.28.2.113 Down - sent:  bfd session down",
     "BGP_DOWN", "172.28.2.113"),
    ("10.16.249.5",
     "2026 Nov  4 00:13:08.161 bbs1_dc05_m01_new %BFD-5-SESSION_STATE_DOWN: "
     "BFD session 1090519197 to neighbor 172.28.2.113 on interface Eth1/5 has gone down. "
     "Reason: Control Detection Time Expired.",
     "BGP_DOWN", "172.28.2.113"),
    # 会话删除是 down 之后的必然结果，归噪声码，不进规则缺口清单
    ("10.16.249.5",
     "2026 Nov  4 00:13:09.144 bbs1_dc05_m01_new %BFD-5-SESSION_REMOVED: "
     "BFD session to neighbor 172.28.2.133 on interface Eth1/6 has been removed",
     "BFD_SESSION_CHG", "172.28.2.133"),
    ("10.16.249.5",
     "2026 Nov  4 00:13:09.178 bbs1_dc05_m01_new %BFD-5-SESSION_REMOVED: "
     "BFD session to neighbor 172.28.2.113 on interface Eth1/5 has been removed",
     "BFD_SESSION_CHG", "172.28.2.113"),
    ("10.16.249.5",
     "2026 Nov  4 00:13:11.925 bbs1_dc05_m01_new %BGP-5-ADJCHANGE:  bgp- [25358] (default) "
     "neighbor 172.28.1.193 Down - sent:  bfd session down",
     "BGP_DOWN", "172.28.1.193"),
    ("10.16.249.5",
     "2026 Nov  4 00:13:11.925 bbs1_dc05_m01_new %BFD-5-SESSION_STATE_DOWN: "
     "BFD session 1090519246 to neighbor 172.28.1.193 on interface Eth1/1 has gone down. "
     "Reason: Echo Function Failed.",
     "BGP_DOWN", "172.28.1.193"),
    ("10.16.249.5",
     "2026 Nov  4 00:13:11.949 bbs1_dc05_m01_new %BGP-5-ADJCHANGE:  bgp- [25358] (default) "
     "neighbor 172.28.2.125 Down - sent:  bfd session down",
     "BGP_DOWN", "172.28.2.125"),
    ("10.16.249.5",
     "2026 Nov  4 00:13:11.950 bbs1_dc05_m01_new %BFD-5-SESSION_STATE_DOWN: "
     "BFD session 1090519245 to neighbor 172.28.2.125 on interface Eth1/2 has gone down. "
     "Reason: Echo Function Failed.",
     "BGP_DOWN", "172.28.2.125"),
    ("10.16.249.5",
     "2026 Nov  4 00:13:12.929 bbs1_dc05_m01_new %ETHPORT-5-IF_DOWN_LINK_FAILURE: "
     "Interface Ethernet1/1 (description:pT:bbs1_dc07_m01:100G1/4) is down (Link failure)",
     "IF_DOWN", "Ethernet1/1"),
    ("10.16.249.5",
     "2026 Nov  4 00:13:13.002 bbs1_dc05_m01_new %ETHPORT-5-IF_DOWN_LINK_FAILURE: "
     "Interface Ethernet1/2 (description:pT:bbs1_dc07_m01:100G1/7) is down (Link failure)",
     "IF_DOWN", "Ethernet1/2"),
    ("10.16.249.5",
     "2026 Nov  4 00:13:13.068 bbs1_dc05_m01_new %BFD-5-SESSION_REMOVED: "
     "BFD session to neighbor 172.28.1.193 on interface Eth1/1 has been removed",
     "BFD_SESSION_CHG", "172.28.1.193"),
    ("10.16.249.5",
     "2026 Nov  4 00:13:13.102 bbs1_dc05_m01_new %BFD-5-SESSION_REMOVED: "
     "BFD session to neighbor 172.28.2.125 on interface Eth1/2 has been removed",
     "BFD_SESSION_CHG", "172.28.2.125"),
    # 一次端口 up 刷四条属性日志，全归 IF_ATTR_CHG，同指纹 count=4
    ("10.16.249.5",
     "2026 Nov  4 00:38:32.709 bbs1_dc05_m01_new %ETHPORT-5-SPEED: "
     "Interface Ethernet1/6, operational speed changed to 100 Gbps",
     "IF_ATTR_CHG", "Ethernet1/6"),
    ("10.16.249.5",
     "2026 Nov  4 00:38:32.709 bbs1_dc05_m01_new %ETHPORT-5-IF_DUPLEX: "
     "Interface Ethernet1/6, operational duplex mode changed to Full",
     "IF_ATTR_CHG", "Ethernet1/6"),
    ("10.16.249.5",
     "2026 Nov  4 00:38:32.709 bbs1_dc05_m01_new %ETHPORT-5-IF_RX_FLOW_CONTROL: "
     "Interface Ethernet1/6, operational Receive Flow Control state changed to off",
     "IF_ATTR_CHG", "Ethernet1/6"),
    ("10.16.249.5",
     "2026 Nov  4 00:38:32.709 bbs1_dc05_m01_new %ETHPORT-5-IF_TX_FLOW_CONTROL: "
     "Interface Ethernet1/6, operational Transmit Flow Control state changed to off",
     "IF_ATTR_CHG", "Ethernet1/6"),
    # 恢复：这条 IF_UP 正文是 "Eth1/6 (description:...) is up"，没有逗号，
    # 和 down 日志共用一套 object_regex，抽出来必须也是 Ethernet1/6
    ("10.16.249.5",
     "2026 Nov  4 00:38:32.725 bbs1_dc05_m01_new %ETHPORT-5-IF_UP: "
     "Interface Ethernet1/6 (description:pT:bbs1_dc09_m01:100G1/8:ZX) is up in Layer3",
     "IF_UP", "Ethernet1/6"),
    ("10.16.249.5",
     "2026 Nov  4 00:38:32.731 bbs1_dc05_m01_new %BGP-5-ADJCHANGE:  bgp- [25358] (default) "
     "neighbor 172.28.2.113 Up ",
     "BGP_UP", "172.28.2.113"),
    ("10.16.249.5",
     "2026 Nov  4 00:38:33.232 bbs1_dc05_m01_new %BGP-5-ADJCHANGE:  bgp- [25358] (default) "
     "neighbor 172.28.2.133 Up ",
     "BGP_UP", "172.28.2.133"),
    # 这两条正文里没有邻居 IP，object_regex 抽不到，object 退成 "-"
    ("10.16.249.5",
     "2026 Nov  4 00:38:33.739 bbs1_dc05_m01_new %BFD-5-SESSION_MOVED: "
     "BFD session 0x410000cf: Installed on LC 1",
     "BFD_SESSION_CHG", "-"),
    ("10.16.249.5",
     "2026 Nov  4 00:38:33.739 bbs1_dc05_m01_new %BFD-5-SESSION_MOVED: "
     "BFD session 0x410000d0: Installed on LC 1",
     "BFD_SESSION_CHG", "-"),
]

MOCK_MESSAGES_ALL = MOCK_MESSAGES + MOCK_MESSAGES_DC05

# ============================================================
# 黑名单样本：(源IP, 原始报文, 是否该被拦)
# ============================================================
MOCK_MESSAGES_BLACK = [
    # ---- scope=mnemonic，走 dict ----
    ("10.16.249.5",
     "2026 Nov  4 09:00:01.100 bbs1_dc05_m01_new %SSHD-6-SESSION_CONNECTED: "
     "ssh session connected from 10.1.2.3", True),
    ("10.19.7.1",
     "<189>Nov 11 09:31:40 pcs1_dc07_m01 %VSHD-5-VSHD_SYSLOG_CONFIG_I: "
     "Configuring console from pts/0", True),
    # rule 5 限定设备，走 (ip, mnemonic) 那张 dict
    ("10.16.249.5",
     "2026 Nov  4 09:05:00.000 bbs1_dc05_m01_new "
     "%ETHPORT-5-IF_DOWN_CHANNEL_ADMIN_DOWN: Interface Ethernet1/9 is down", True),
    # 同一个 mnemonic 换一台设备，ip 不匹配，不该拦
    ("10.19.7.1",
     "<189>Nov 11 09:05:00 pcs1_dc07_m01 "
     "%ETHPORT-5-IF_DOWN_CHANNEL_ADMIN_DOWN: Interface Ethernet1/9 is down", False),
    # rule 6 已停用，不该拦
    ("10.16.249.5",
     "2026 Nov  4 00:38:33.739 bbs1_dc05_m01_new %BFD-5-SESSION_MOVED: "
     "BFD session 0x410000cf: Installed on LC 1", False),

    # ---- scope=message，走线性扫 ----
    # rule 3 配的是小写，报文是大写，验证 ignore_case
    ("10.19.7.1", "<189>Nov 11 09:32:00 pcs1_dc07_m01 Last Message Repeated 5 times", True),
    ("10.19.7.1",
     "<189>Nov 11 09:33:00 pcs1_dc07_m01 Configuration update aborted: no such file", True),
    # rule 4 大小写敏感，原文小写 c 不该命中
    ("10.19.7.1",
     "<189>Nov 11 09:33:10 pcs1_dc07_m01 configuration update aborted: no such file", False),

    # ---- 正常告警日志，一条都不能误拦 ----
    ("10.16.249.5",
     "2026 Nov  4 00:13:08.109 bbs1_dc05_m01_new %ETHPORT-5-IF_DOWN_LINK_FAILURE: "
     "Interface Ethernet1/6 (description:pT:bbs1_dc09_m01:100G1/8:ZX) is down (Link failure)",
     False),
    ("10.16.249.5",
     "2026 Nov  4 00:13:08.111 bbs1_dc05_m01_new %BGP-5-ADJCHANGE:  bgp- [25358] (default) "
     "neighbor 172.28.2.133 Down - sent:  bfd session down", False),
]

