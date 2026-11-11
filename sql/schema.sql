-- ============================================================
-- switchlog 数据表
--
-- 共用 netops 库。devices / ports 由 central-server 采集侧维护，
-- switchlog 只读，不在本文件里建。
--
--     mysql -h <host> -P <port> -u netops -p netops < sql/schema.sql
--
-- 本文件可重复执行：建表用 CREATE TABLE IF NOT EXISTS，
-- 种子数据用 INSERT IGNORE，不会覆盖已改过的级别。
-- ============================================================

USE netops;

-- ============================================================
-- L0.5 黑名单：解析前拦截
--
-- 和 L3 抑制表的区别：这层只有 mnemonic/子串 + ip 两个判据，解析前就执行，
-- 命中即丢。要正则、要 mute、要时间窗的规则配到 syslog_suppress_rule 去。
--
--   scope=mnemonic  pattern 是 mnemonic 全名，进 dict，O(1) 命中
--   scope=message   pattern 是全文子串，线性扫
--
-- 能按 mnemonic 配的一律用 mnemonic：实测 162 字节报文逐条 str.find，
-- 20 条规则就和剥一次 mnemonic 一样贵，500 条是 21 倍；而 mnemonic 由
-- L0 剥好透传进来，dict 查一次只要 0.036us。scope=message 那一串要保持小，
-- 每条日志都会扫它。
--
-- 没有 priority：黑名单只有"丢"一个动作，命中哪条结果都一样。
-- (scope, ip, pattern) 建唯一索引，重复配置在入库时就挡住。
-- ============================================================
CREATE TABLE IF NOT EXISTS syslog_black_list(
    rule_id BIGINT NOT NULL AUTO_INCREMENT COMMENT '规则ID',
    pattern VARCHAR(300) NOT NULL DEFAULT '' COMMENT 'scope=mnemonic时为mnemonic全名，scope=message时为全文子串',
    scope VARCHAR(10) NOT NULL DEFAULT 'mnemonic' COMMENT 'mnemonic=进dict精确命中 / message=全文子串线性扫',
    ip VARCHAR(64) NOT NULL DEFAULT '' COMMENT '限定设备IP，空=所有设备',
    ignore_case TINYINT NOT NULL DEFAULT 0 COMMENT '1=大小写不敏感，只对scope=message生效',
    enabled TINYINT NOT NULL DEFAULT 1 COMMENT '1=启用 0=停用',
    descr VARCHAR(300) NOT NULL DEFAULT '' COMMENT '为什么拦这条，便于日后判断能不能放开',
    update_time VARCHAR(10) NOT NULL DEFAULT '' COMMENT '最近更新时间(epoch秒)',
    PRIMARY KEY(rule_id),
    UNIQUE KEY uniq_scope_ip_pattern (scope, ip, pattern),
    INDEX idx_enabled (enabled)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Syslog解析前黑名单';

-- ============================================================
-- L1 匹配规则：(vendor, mnemonic) -> event_code
--
-- 按 (vendor, mnemonic) 定位，一级 dict 命中；vendor='*' 表示不限，
-- 取 devices.vendor 原值：cisco_nx / cisco_ios / cisco_xr / h3c / huawei / fortinet。
--
--   mnemonic     header 段剥出来的关键字，不含厂商前缀格式差异：
--                Cisco     FAC-SEV-MNEMONIC（%ETHPORT-5-IF_DOWN）
--                Comware   MOD/SEV/MNEMONIC（IFNET/3/PHY_UPDOWN，日志版本号已剥掉）
--                FortiGate logid（0100032003）
--                留空的只对"剥不出 mnemonic 的报文"生效，走模糊匹配
--   match_type   exact=mnemonic 即全部判据；contains=正文含 pattern；regex=正文匹配 pattern
--   body_match   同一 mnemonic 对应多个事件时的消歧子串（Comware 的 up/down
--                共用一条 mnemonic），走 contains，空=不参与
--   object_regex 对象抽取正则，逐 mnemonic 配 —— 同一事件码下不同 mnemonic
--                的正文格式不同，正则没法共用
--   priority     越小越先匹配。同 mnemonic 多规则时靠它控顺序
--                （FOP_CHANGED 的 'to none' 必须排在兜底行前面）
--
-- event_code 上不能建唯一索引：一个事件码天然对应多行（多厂商、多 mnemonic），
-- 同一 mnemonic 也可能对应多个事件码（靠 body_match 分开）。
-- ============================================================
CREATE TABLE IF NOT EXISTS syslog_rule(
    rule_id BIGINT NOT NULL AUTO_INCREMENT COMMENT '规则ID',
    vendor VARCHAR(30) NOT NULL DEFAULT '*' COMMENT 'devices.vendor原值，*=不限厂商',
    mnemonic VARCHAR(80) NOT NULL DEFAULT '' COMMENT 'header段关键字，空=只对剥不出mnemonic的报文走模糊匹配',
    match_type VARCHAR(10) NOT NULL DEFAULT 'exact' COMMENT 'exact/contains/regex',
    pattern VARCHAR(300) NOT NULL DEFAULT '' COMMENT 'contains关键字 / regex正则',
    body_match VARCHAR(200) NOT NULL DEFAULT '' COMMENT '同mnemonic多事件时的消歧子串，须抄现网正文原字符串',
    event_code VARCHAR(50) NOT NULL DEFAULT '' COMMENT '统一事件码，多行可重复',
    object_regex VARCHAR(300) NOT NULL DEFAULT '' COMMENT '对象抽取正则，第一个捕获组即对象',
    priority INT NOT NULL DEFAULT 100 COMMENT '越小越先匹配',
    enabled TINYINT NOT NULL DEFAULT 1 COMMENT '1=启用 0=停用',
    descr VARCHAR(300) NOT NULL DEFAULT '' COMMENT '建议填现网正文样例，便于核对正则',
    update_time VARCHAR(10) NOT NULL DEFAULT '' COMMENT '最近更新时间(epoch秒)',
    PRIMARY KEY(rule_id),
    INDEX idx_vendor_mnemonic (vendor, mnemonic),
    INDEX idx_event_code (event_code),
    INDEX idx_priority (priority),
    INDEX idx_enabled (enabled)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Syslog解析匹配规则';

-- ============================================================
-- L2.5 事件属性
--
-- 描述的是"事件"，不是"匹配规则"。IF_DOWN 在现网有 3 家厂商 × 若干条
-- mnemonic 共十几行匹配规则，属性只在这里存一份 —— 改级别改一行、
-- 全厂商同时生效，不会出现"华为的端口 down 是 P1、Cisco 的同一个事件
-- 还是 P2"这种谁都发现不了的错。
--
--   severity    1=P1 2=P2 3=P3。由这里定，不看 syslog 自带 level
--               （%BGP-5-ADJCHANGE 是 level 5，但 BGP 邻居掉了对我们是 P1）
--   state       raise=开告警 / clear=关告警 / stateless=窗口计数，静默即恢复
--   object_type interface / peer / mac / slot / none，决定对象怎么归一
--   window_sec  聚合窗口；threshold 窗口内达到该条数才告警
--   clear_code  本事件的恢复事件码，如 IF_DOWN -> IF_UP。
--               L5 据此让恢复事件落到故障事件的指纹上，否则告警关不掉
-- ============================================================
CREATE TABLE IF NOT EXISTS syslog_event(
    event_code VARCHAR(50) NOT NULL COMMENT '统一事件码',
    severity TINYINT NOT NULL DEFAULT 3 COMMENT '1=P1 2=P2 3=P3',
    state VARCHAR(10) NOT NULL DEFAULT 'stateless' COMMENT 'raise/clear/stateless',
    object_type VARCHAR(20) NOT NULL DEFAULT 'none' COMMENT 'interface/peer/mac/slot/none',
    window_sec INT NOT NULL DEFAULT 300 COMMENT '聚合窗口(秒)',
    threshold INT NOT NULL DEFAULT 1 COMMENT '窗口内达到该条数才告警',
    clear_code VARCHAR(50) NOT NULL DEFAULT '' COMMENT '恢复事件码，空=无显式恢复',
    descr VARCHAR(200) NOT NULL DEFAULT '' COMMENT '事件描述',
    enabled TINYINT NOT NULL DEFAULT 1 COMMENT '1=启用 0=停用',
    update_time VARCHAR(10) NOT NULL DEFAULT '' COMMENT '最近更新时间(epoch秒)',
    PRIMARY KEY(event_code),
    INDEX idx_enabled (enabled)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Syslog事件属性';

-- ============================================================
-- L3 抑制规则  [L3 未实现，表先建好]
--
--   drop   噪声，永不进入告警路径
--   mute   变更/维护窗口，事件留在管道里但不告警
--   depend 上游设备宕机时，下游事件挂起；上游恢复后放行
--
-- mute 和 drop 的区别很重要：割接期间不该被电话轰炸，但割接完要能回看
-- 那段时间发生了什么，所以变更窗口必须用 mute 而不是 drop。
--
-- 匹配字段为空表示"不限"，多个字段同时填写时取与。
-- ============================================================
CREATE TABLE IF NOT EXISTS syslog_suppress_rule(
    rule_id BIGINT NOT NULL AUTO_INCREMENT COMMENT '规则ID',
    rule_type VARCHAR(10) NOT NULL DEFAULT 'drop' COMMENT 'drop/mute/depend',
    enabled TINYINT NOT NULL DEFAULT 1 COMMENT '1=启用 0=停用',
    ip_reg VARCHAR(300) NOT NULL DEFAULT '' COMMENT '源IP正则，空=不限',
    vendor VARCHAR(40) NOT NULL DEFAULT '' COMMENT '厂商，空=不限',
    event_code_reg VARCHAR(300) NOT NULL DEFAULT '' COMMENT '事件码正则，空=不限',
    object_reg VARCHAR(300) NOT NULL DEFAULT '' COMMENT '告警对象正则，空=不限',
    msg_reg VARCHAR(300) NOT NULL DEFAULT '' COMMENT '原始报文正则，空=不限',
    depend_ip VARCHAR(64) NOT NULL DEFAULT '' COMMENT 'depend类型：上游设备IP',
    depend_event_reg VARCHAR(300) NOT NULL DEFAULT '' COMMENT 'depend类型：触发挂起的上游事件正则',
    hold_seconds INT NOT NULL DEFAULT 600 COMMENT 'depend类型：上游未恢复时挂起多久(秒)',
    start_time VARCHAR(10) NOT NULL DEFAULT '' COMMENT 'mute类型：窗口开始(epoch秒)，空=立即生效',
    end_time VARCHAR(10) NOT NULL DEFAULT '' COMMENT 'mute类型：窗口结束(epoch秒)，空=永久',
    descr VARCHAR(300) NOT NULL DEFAULT '' COMMENT '规则描述',
    update_time VARCHAR(10) NOT NULL DEFAULT '' COMMENT '最近更新时间(epoch秒)',
    PRIMARY KEY(rule_id),
    INDEX idx_type_enabled (rule_type, enabled)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Syslog抑制规则';

-- ============================================================
-- L5 告警状态  [L5 未实现，表先建好]
--
-- 保存未恢复的告警状态，进程重启后接着算，不会重复告警。
-- 同一指纹只保留一行。
--
-- severity 和 base_severity 分开存：闪断会把级别临时提一档
-- （P3->P2->P1），稳定后要落回 base_severity，所以原始级别不能丢。
-- ============================================================
CREATE TABLE IF NOT EXISTS syslog_alarm_state(
    fingerprint VARCHAR(64) NOT NULL COMMENT '告警指纹 md5(ip|event_code|alarm_object)',
    ip VARCHAR(64) NOT NULL DEFAULT '' COMMENT '设备IP',
    event_code VARCHAR(100) NOT NULL DEFAULT '' COMMENT '事件码',
    alarm_object VARCHAR(100) NOT NULL DEFAULT '' COMMENT '告警对象',
    mode VARCHAR(20) NOT NULL DEFAULT 'raise' COMMENT 'raise/clear/stateless/ignore',
    state VARCHAR(10) NOT NULL DEFAULT 'idle' COMMENT 'open=告警中 idle=已恢复',
    severity TINYINT NOT NULL DEFAULT 3 COMMENT '当前级别(可能因闪断升级)',
    base_severity TINYINT NOT NULL DEFAULT 3 COMMENT '事件原始级别，闪断平息后落回这个值',
    first_seen VARCHAR(10) NOT NULL DEFAULT '' COMMENT '首次出现(epoch秒)',
    last_seen VARCHAR(10) NOT NULL DEFAULT '' COMMENT '最近出现(epoch秒)',
    counter INT NOT NULL DEFAULT 0 COMMENT '当前窗口内日志条数',
    raise_count INT NOT NULL DEFAULT 0 COMMENT '累计开告警次数，闪断判定数这个',
    clear_count INT NOT NULL DEFAULT 0 COMMENT '累计恢复次数',
    flapping TINYINT NOT NULL DEFAULT 0 COMMENT '1=闪断中，禁止自动恢复',
    alarm_id BIGINT NOT NULL DEFAULT 0 COMMENT '对应的 alarm_list 记录',
    updated_time VARCHAR(10) NOT NULL DEFAULT '' COMMENT '最近写入时间(epoch秒)',
    PRIMARY KEY(fingerprint),
    INDEX idx_state (state),
    INDEX idx_last_seen (last_seen)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Syslog告警状态';

-- ============================================================
-- L6 告警列表  [L6 未实现，表先建好]
--
-- 看板和 central-server/api/api_alarm.py 都读这张表。
--
-- 两个字段名沿用 central-server 的老结构，现有分组页面不用改：
--   keyword      存 event_code
--   group_label  存 fingerprint
--
-- status 是人工处理状态（0待处理/1已确认/2已处理/3忽略/4屏蔽），
-- state 是告警自身是否还成立，两者独立，不要混用：
-- 一条告警可以是 status=已确认 + state=open（知道了但还没好）。
-- ============================================================
CREATE TABLE IF NOT EXISTS alarm_list(
    alarm_id BIGINT NOT NULL AUTO_INCREMENT COMMENT '告警ID',
    ip VARCHAR(300) NOT NULL DEFAULT '' COMMENT '设备IP',
    hostname VARCHAR(300) NOT NULL DEFAULT '' COMMENT '设备名称',
    alarm_type VARCHAR(40) NOT NULL DEFAULT 'syslog' COMMENT '告警来源：syslog/zabbix/flow',
    group_label VARCHAR(100) NOT NULL DEFAULT '' COMMENT '分组标签，存fingerprint',
    msg VARCHAR(500) NOT NULL DEFAULT '' COMMENT '原始报文',
    group_name VARCHAR(100) NOT NULL DEFAULT '' COMMENT '分组名称',
    alarm_object VARCHAR(100) NOT NULL DEFAULT '' COMMENT '告警对象',
    keyword VARCHAR(100) NOT NULL DEFAULT '' COMMENT '关键字，存event_code',
    fingerprint VARCHAR(64) NOT NULL DEFAULT '' COMMENT '告警指纹 md5(ip|event_code|alarm_object)',
    severity TINYINT NOT NULL DEFAULT 3 COMMENT '1=P1 2=P2 3=P3',
    state VARCHAR(10) NOT NULL DEFAULT 'open' COMMENT 'open=告警中 clear=已恢复',
    status VARCHAR(1) NOT NULL DEFAULT '0' COMMENT '人工处理状态 0待处理1已确认2已处理3忽略4屏蔽',
    counter INT NOT NULL DEFAULT 1 COMMENT '窗口内日志条数，不是事故次数',
    first_seen VARCHAR(10) NOT NULL DEFAULT '' COMMENT '本段首次出现(epoch秒)',
    last_seen VARCHAR(10) NOT NULL DEFAULT '' COMMENT '最近一次出现(epoch秒)',
    clear_time VARCHAR(10) NOT NULL DEFAULT '' COMMENT '恢复时间(epoch秒)，空=未恢复',
    create_time VARCHAR(10) NOT NULL DEFAULT '' COMMENT '创建时间(epoch秒)',
    PRIMARY KEY(alarm_id),
    INDEX idx_ip (ip),
    INDEX idx_group_label (group_label),
    INDEX idx_fingerprint (fingerprint),
    INDEX idx_state (state),
    INDEX idx_status (status),
    INDEX idx_create_time (create_time)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='告警列表';

-- ============================================================
-- 种子数据：兜底事件码
--
-- 这三个码是管线自己产生的，必须存在，否则走代码里的 P3/stateless 默认值，
-- 表里看不到它们、也没法调级别。
--
-- UNKNOWN_MNEMONIC 同时是规则缺口清单的来源：
--     select vendor, mnemonic, count(*) from <日志归档>
--     where event_code='UNKNOWN_MNEMONIC' group by 1,2 order by 3 desc;
-- 高频未命中的就是下一条该补的规则，补规则时 vendor 直接抄这一行的值。
-- ============================================================
INSERT IGNORE INTO syslog_event
    (event_code, severity, state, object_type, window_sec, threshold, clear_code, descr)
VALUES
('UNKNOWN_MNEMONIC', 3, 'stateless', 'none', 600, 1, '',
 'mnemonic 在规则表里没有对应规则，同时是规则缺口清单'),
('PARSE_FAIL',       3, 'stateless', 'none', 600, 5, '',
 '信封解析失败，单台设备持续发垃圾日志即配置错误，窗口内累计5条才报'),
('UNMANAGED_SRC',    3, 'stateless', 'none', 600, 1, '',
 '源IP在devices表里查不到厂商，用于发现未纳管设备');

-- ============================================================
-- 种子数据：事件属性
--
-- 按现网实际会发的事件填，不要照抄厂商手册全表 —— 抄进去的事件
-- 既不背测试也没人维护。
--
-- 判断标准：同一故障同一时刻产生、用户会当成一件事看待的日志，
-- 归到同一个 event_code；先后有意义、需要单独确认的，拆开。
-- ============================================================
INSERT IGNORE INTO syslog_event
    (event_code, severity, state, object_type, window_sec, threshold, clear_code, descr)
VALUES
-- 端口与聚合口
('IF_DOWN',        2, 'raise',     'interface', 300, 1, 'IF_UP',
 '端口down。物理层/链路协议/成员口同时刻产生的几条日志收敛成一条告警'),
('IF_UP',          3, 'clear',     'interface', 300, 1, '',
 '端口up，按IF_DOWN的指纹回关告警'),
('LAG_DOWN',       1, 'raise',     'interface', 300, 1, 'LAG_UP',
 '聚合口全断，最后一个可用成员也没了'),
('LAG_UP',         3, 'clear',     'interface', 300, 1, '',
 '聚合口恢复'),
('LAG_MEMBER_CHG', 3, 'stateless', 'interface', 600, 1, '',
 '聚合口成员切换。有冗余的LAG每天都会发生，报出来就是噪声'),
-- 路由邻居
('BGP_DOWN',       1, 'raise',     'peer',      300, 1, 'BGP_UP',
 'BGP邻居down。BFD会话down归到同一个码，同一指纹只出一条告警'),
('BGP_UP',         3, 'clear',     'peer',      300, 1, '',
 'BGP邻居up'),
('OSPF_DOWN',      1, 'raise',     'peer',      300, 1, 'OSPF_UP',
 'OSPF邻居down'),
('OSPF_UP',        3, 'clear',     'peer',      300, 1, '',
 'OSPF邻居up'),
-- 二层
('MAC_FLAP',       2, 'stateless', 'mac',       600, 3, '',
 'MAC漂移。阈值3兼做降噪，虚机迁移造成的偶发单次不报'),
('STP_TC',         3, 'stateless', 'interface', 600, 1, '',
 'STP拓扑变更'),
-- 硬件
('PSU_FAIL',       2, 'raise',     'slot',      300, 1, 'PSU_OK',
 '电源/风扇/板卡故障'),
('PSU_OK',         3, 'clear',     'slot',      300, 1, '',
 '电源/风扇/板卡恢复'),
-- 管理面
('CONFIG_CHG',     3, 'stateless', 'none',      600, 1, '',
 '配置变更'),
('LOGIN_FAIL',     3, 'stateless', 'none',      600, 1, '',
 '登录失败，暴力破解类'),
-- 噪声码：给它们事件码是为了不混进 UNKNOWN_MNEMONIC 的规则缺口清单，
-- 真正的拦截在 syslog_suppress_rule 配 drop，不靠这里 enabled=0 关
('BFD_SESSION_CHG', 3, 'stateless', 'peer',      600, 1, '',
 'BFD会话删除/迁移，BGP_DOWN的伴生日志，建议L3配drop'),
('IF_ATTR_CHG',     3, 'stateless', 'interface', 600, 1, '',
 '速率/双工/流控变化，端口up的伴生日志（一次up刷四条），建议L3配drop');

-- ============================================================
-- 种子数据：L1 匹配规则
--
-- 只放已经对着现网日志核对过的几条，用来验证三件事：
--   1. 多条 mnemonic 归一个 event_code，且抽出同一个对象
--   2. 同一 mnemonic 多个 event_code，靠 body_match 分开
--   3. vendor='*' 覆盖各家写法一致的事件
--
-- 现网规则按 UNKNOWN_MNEMONIC 的缺口清单逐批补。
--
-- 两个坑写在这里，补规则时照着避：
--   * object_regex 跑在整段正文上（含 %MNEMONIC: 前缀），不能用 ^ 锚定，
--     否则抓到的是 mnemonic 自己
--   * body_match 必须抄现网正文的原字符串，不能按手册写法臆造。
--     H3C 是 "changed to down."，华为是 "turned into DOWN state."，
--     两家写法不同，配错了整条规则不命中
-- ============================================================
INSERT IGNORE INTO syslog_rule
    (rule_id, vendor, mnemonic, match_type, pattern, body_match,
     event_code, object_regex, priority, descr)
VALUES
-- NX-OS 物理口 down：两种正文格式。IF_DOWN 的接口名后面跟逗号，
-- LINK_FAILURE 跟空格再跟 (description:...)。字符类同时排掉空格/逗号/左括号，
-- 一套正则吃下两种正文，且绝不会把 description 里的内容当接口名
(1, 'cisco_nx', 'ETHPORT-5-IF_DOWN', 'exact', '', '',
 'IF_DOWN', 'Interface\\s+([^\\s,(]+)', 100,
 'Interface Ethernet1/38, changed state to down'),
(2, 'cisco_nx', 'ETHPORT-5-IF_DOWN_LINK_FAILURE', 'exact', '', '',
 'IF_DOWN', 'Interface\\s+([^\\s,(]+)', 100,
 'Interface Ethernet1/6 (description:pT:xxx) is down (Link failure)'),
(3, 'cisco_nx', 'LINEPROTO-5-UPDOWN', 'exact', '', 'changed state to down',
 'IF_DOWN', 'on Interface\\s+([^,\\s]+),', 100,
 'Line protocol on Interface Ethernet1/38, changed state to down'),
(4, 'cisco_nx', 'LINEPROTO-5-UPDOWN', 'exact', '', 'changed state to up',
 'IF_UP', 'on Interface\\s+([^,\\s]+),', 100,
 'Line protocol up'),
(5, 'cisco_nx', 'ETH_PORT_CHANNEL-5-PORT_DOWN', 'exact', '', '',
 'IF_DOWN', ':\\s+(\\S+)\\s+is\\s+down', 100,
 'port-channel38: Ethernet1/38 is down。对象是成员口，不是LAG'),
-- 聚合口：FOP_CHANGED 的 'to none' 才是全断，priority 小的先判。
-- 靠"冒号+空格+名字+冒号"定位行首的 LAG 名
(6, 'cisco_nx', 'ETH_PORT_CHANNEL-5-FOP_CHANGED', 'exact', '', 'to none',
 'LAG_DOWN', ':\\s+(\\S+?):', 10,
 'first operational port changed from Ethernet1/38 to none，最后一个成员没了'),
(7, 'cisco_nx', 'ETH_PORT_CHANNEL-5-FOP_CHANGED', 'exact', '', '',
 'LAG_MEMBER_CHG', ':\\s+(\\S+?):', 200,
 'changed from Ethernet1/38 to Ethernet1/39，还有成员时是正常冗余切换'),
(8, 'cisco_nx', 'ETHPORT-5-IF_DOWN_PORT_CHANNEL_MEMBERS_DOWN', 'exact', '', '',
 'LAG_DOWN', 'Interface\\s+([^\\s,(]+)', 100,
 'Interface port-channel38 is down (No operational members)'),
-- Comware / 华为：同一 mnemonic，up/down 只差正文
(9, 'h3c', 'IFNET/3/PHY_UPDOWN', 'exact', '', 'changed to down',
 'IF_DOWN', 'interface (\\S+?) changed', 100,
 'Physical state on the interface GigabitEthernet1/0/1 changed to down.'),
(10, 'h3c', 'IFNET/3/PHY_UPDOWN', 'exact', '', 'changed to up',
 'IF_UP', 'interface (\\S+?) changed', 100,
 'H3C 物理口 up'),
(11, 'huawei', 'IFNET/3/PHY_UPDOWN', 'exact', '', 'turned into DOWN',
 'IF_DOWN', 'interface (\\S+?) has', 100,
 'The interface XGigabitEthernet0/0/1 has turned into DOWN state.'),
(12, 'huawei', 'IFNET/3/PHY_UPDOWN', 'exact', '', 'turned into UP',
 'IF_UP', 'interface (\\S+?) has', 100,
 '华为物理口 up'),
-- 各家写法一致的用 vendor='*' 一行覆盖
(13, '*', 'ETHPORT-5-IF_UP', 'exact', '', '',
 'IF_UP', 'Interface\\s+([^\\s,(]+)', 100,
 '两种正文都有：Interface Eth1/6, operational... 和 Eth1/6 (description:...) is up'),
(14, '*', 'BGP-5-ADJCHANGE', 'exact', '', 'Down',
 'BGP_DOWN', 'neighbor\\s+(\\d+\\.\\d+\\.\\d+\\.\\d+)', 100,
 'neighbor 172.28.2.133 Down - sent: bfd session down'),
(15, '*', 'BGP-5-ADJCHANGE', 'exact', '', 'Up',
 'BGP_UP', 'neighbor\\s+(\\d+\\.\\d+\\.\\d+\\.\\d+)', 100,
 'neighbor 172.28.2.133 Up'),
-- BFD 掉了就是 BGP 掉了，归到同一个 event_code，同一指纹只出一条告警
(16, '*', 'BFD-5-SESSION_STATE_DOWN', 'exact', '', '',
 'BGP_DOWN', 'neighbor\\s+(\\d+\\.\\d+\\.\\d+\\.\\d+)', 100,
 'BFD session to neighbor 172.28.2.133 on interface Eth1/6 has gone down'),
-- 噪声类：照常给事件码，L3 配 drop 拦掉
(17, '*', 'BFD-5-SESSION_REMOVED', 'exact', '', '',
 'BFD_SESSION_CHG', 'neighbor\\s+(\\d+\\.\\d+\\.\\d+\\.\\d+)', 100,
 'BFD 会话删除，down 之后的必然结果'),
(18, '*', 'BFD-5-SESSION_MOVED', 'exact', '', '',
 'BFD_SESSION_CHG', '', 100,
 'BFD 会话在板卡间迁移，正文里没有邻居IP'),
(19, '*', 'ETHPORT-5-SPEED', 'exact', '', '',
 'IF_ATTR_CHG', 'Interface\\s+([^\\s,(]+)', 100,
 '协商速率变化，端口up的伴生日志'),
(20, '*', 'ETHPORT-5-IF_DUPLEX', 'exact', '', '',
 'IF_ATTR_CHG', 'Interface\\s+([^\\s,(]+)', 100,
 '双工模式变化，伴生日志'),
(21, '*', 'ETHPORT-5-IF_RX_FLOW_CONTROL', 'exact', '', '',
 'IF_ATTR_CHG', 'Interface\\s+([^\\s,(]+)', 100,
 '收向流控变化，伴生日志'),
(22, '*', 'ETHPORT-5-IF_TX_FLOW_CONTROL', 'exact', '', '',
 'IF_ATTR_CHG', 'Interface\\s+([^\\s,(]+)', 100,
 '发向流控变化，伴生日志'),
-- FortiGate：mnemonic 取 logid
(23, 'fortinet', '0100032003', 'exact', '', '',
 'LOGIN_FAIL', '', 100,
 'Administrator admin login failed from ssh'),
-- mnemonic 留空：只对剥不出 mnemonic 的报文生效，走模糊匹配
(24, '*', '', 'contains', 'authentication failure', '',
 'LOGIN_FAIL', '', 300,
 'sshd[1234]: authentication failure for admin，无mnemonic'),
(25, '*', '', 'regex', '[Cc]onfigured from (console|vty)', '',
 'CONFIG_CHG', '', 300,
 'Configured from vty by admin，无mnemonic');

-- rule_id 显式给值，AUTO_INCREMENT 从 26 继续，后续手工加规则可以不带 rule_id

-- ============================================================
-- 种子数据：L0.5 黑名单
--
-- 只放"确定是噪声、解析它纯属浪费"的日志。
-- 能按 mnemonic 配的一律用 scope=mnemonic，走 dict 命中；
-- scope=message 那一串每条日志都会扫，要保持小。
-- ============================================================
INSERT IGNORE INTO syslog_black_list
    (rule_id, pattern, scope, ip, ignore_case, descr)
VALUES
(1, 'SSHD-6-SESSION_CONNECTED', 'mnemonic', '', 0,
 'SSH 建连过程，登录成功与否看 LOGIN_FAIL'),
(2, 'VSHD-5-VSHD_SYSLOG_CONFIG_I', 'mnemonic', '', 0,
 '配置变更的逐条回显，量大且无告警价值'),
(3, 'last message repeated', 'message', '', 1,
 'syslog 自身的折叠提示，不是设备事件，且不带 mnemonic'),
(4, 'Configuration update aborted', 'message', '', 0,
 '配置回滚的调试输出，不带 mnemonic');

-- ============================================================
-- L3 抑制规则示例（默认不插入，按需手工执行）
-- ============================================================
-- 1) drop：把 L1 归好的噪声码拦在告警之外
-- INSERT INTO syslog_suppress_rule(rule_type, event_code_reg, descr)
-- VALUES('drop', '^(BFD_SESSION_CHG|IF_ATTR_CHG)$', '伴生日志，不进告警');
--
-- 2) mute：某设备变更窗口内不告警（时间用 epoch 秒）
-- INSERT INTO syslog_suppress_rule(rule_type, ip_reg, start_time, end_time, descr)
-- VALUES('mute', '^10[.]16[.]249[.]5$', '1763000000', '1763007200', '端口割接窗口');
--
-- 3) depend：10.16.249.5 宕机时，挂起 10.16.250.x 的端口事件
-- INSERT INTO syslog_suppress_rule(rule_type, ip_reg, depend_ip, hold_seconds, descr)
-- VALUES('depend', '^10[.]16[.]250[.]', '10.16.249.5', 900, '上联宕机挂起下联');
