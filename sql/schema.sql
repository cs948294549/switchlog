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
--   state       raise=开告警 / clear=关告警 / stateless=窗口计数，静默即恢复
--   object_type interface / peer / mac / slot / none，决定对象怎么归一
--   window_sec  聚合窗口；threshold 窗口内达到该条数才告警
--   clear_code  本事件的恢复事件码，如 IF_DOWN -> IF_UP。
--               L5 据此让恢复事件落到故障事件的指纹上，否则告警关不掉
--
-- severity 不在这张表里，在 syslog_severity_rule —— 同一个事件码在不同
-- 角色的设备上不是一个级别（csw 的 IF_DOWN 比 rsw 的要紧），一个事件码
-- 一行存不下这件事。详见下面那张表的注释。
-- ============================================================
CREATE TABLE IF NOT EXISTS syslog_event(
    event_code VARCHAR(50) NOT NULL COMMENT '统一事件码',
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
-- L2.5 事件定级：event_code + 设备 -> severity
--
-- 为什么不把 severity 放在 syslog_event 里：那张表一个事件码一行，
-- 只能表达"全网统一"。但同一个 IF_DOWN，csw 掉口是核心网段断了（P1），
-- rsw 掉口是一个机柜的接入（P3），corp 职场的 rsw 掉口压根不用看。
-- 级别取决于"哪个事件 + 哪台设备"两个维度，一个事件码一行存不下。
--
-- 定级跑在 L2 富化之后：那时 sysname 已经从 devices 表补好，可以按设备名
-- 判角色。只按 ip 判也行，但网段和角色不是一一对应的，sysname 更直接。
--
--   event_code  精确事件码，'*'=所有事件
--   ip_reg      源 IP 正则，空=不限
--   sysname_reg sysname 正则，空=不限（设备命名规范见 docs/network/）
--   severity    1=P1 2=P2 3=P3。不看 syslog 自带 level
--               （%BGP-5-ADJCHANGE 是 level 5，但 BGP 邻居掉了对我们是 P1）
--   action      ''=正常告警 / 'ignore'=不开告警
--   priority    越小越先匹配，首条命中即停
--
-- action='ignore' 的事件照样走完管线并落 ES，只是 L5 不开告警。
-- 要彻底不解析的噪声配 syslog_black_list，要按变更窗口静默的配
-- syslog_suppress_rule 的 mute —— 这里管的是"级别"，不是"抑制"。
--
-- priority 的用法，和 syslog_rule 里 FOP_CHANGED 的 'to none' 一个套路：
-- 判据越窄的排越前。corp rsw 那条必须小于通用 rsw 那条，否则
-- rsw1_corp_ts_m21 会先命中 ^rsw 被降成 P3，而不是被忽略。
--
-- event_code='*' 且两个正则都空的那行是全局兜底，唯一允许匹配全网所有
-- 事件的规则。没有它，未配规则的事件码会落到代码里的 P3 默认值，
-- 表里看不出来，所以加载时查不到这行会打 error。
-- 其余规则至少要有一个判据，不然一个笔误就把全网级别改了。
-- ============================================================
CREATE TABLE IF NOT EXISTS syslog_severity_rule(
    rule_id BIGINT NOT NULL AUTO_INCREMENT COMMENT '规则ID',
    event_code VARCHAR(50) NOT NULL DEFAULT '*' COMMENT '精确事件码，*=所有事件',
    ip_reg VARCHAR(300) NOT NULL DEFAULT '' COMMENT '源IP正则，空=不限',
    sysname_reg VARCHAR(300) NOT NULL DEFAULT '' COMMENT 'sysname正则，空=不限',
    severity TINYINT NOT NULL DEFAULT 3 COMMENT '1=P1 2=P2 3=P3',
    action VARCHAR(10) NOT NULL DEFAULT '' COMMENT '空=正常告警 / ignore=不开告警',
    priority INT NOT NULL DEFAULT 100 COMMENT '越小越先匹配，首条命中即停',
    enabled TINYINT NOT NULL DEFAULT 1 COMMENT '1=启用 0=停用',
    descr VARCHAR(300) NOT NULL DEFAULT '' COMMENT '为什么这个级别，便于日后判断能不能调',
    update_time VARCHAR(10) NOT NULL DEFAULT '' COMMENT '最近更新时间(epoch秒)',
    PRIMARY KEY(rule_id),
    UNIQUE KEY uniq_code_ip_sysname (event_code, ip_reg, sysname_reg),
    INDEX idx_priority (priority),
    INDEX idx_enabled (enabled)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Syslog事件定级规则';

-- ============================================================
-- L3 告警静默  [L3 未实现，表先建好]
--
-- 只有 mute 一档，判据 ip_reg / event_code_reg / object_reg + 时间窗。
--
-- 原来设计的 drop 和 depend 两档都取消了：
--   drop   确定是噪声的日志用 syslog_black_list 在 L0.5 截掉。越早丢
--          越省资源，而且那一层按 mnemonic 走 dict，比解析完再丢便宜
--   depend 拓扑抑制依赖运行时的上游可达状态，不是静态规则能表达的，
--          本轮不做
--
-- 跑在 L5 之后，不在 L2.5 之后：
--   1. 判据里的 object 要等 L1 抽、L4 聚合，级别和状态要等 L2.5/L5
--   2. 冷路径。只有 L5 判定"需要告警"的聚合告警才过这一层 ——
--      一次端口 down 是 3 条日志、1 个指纹、1 次 mute 判断，
--      量级从日志条数掉到告警条数。所以四个判据全用正则也不心疼
--   3. 被静默的告警照样进聚合、进状态机、照样写 alarm_list，
--      只是不发通知。割接完要能回看那段时间发生了什么
--
-- 匹配字段为空表示"不限"，多个字段同时填写时取与。
-- start_time 必填（空=立即生效），end_time 空=永久静默。
--
-- 闪断升级产生的 IF_FLAP 同样要过这一层：割接期间的 raise 照样进闪断
-- 计数，窗口内连续 3 次会升出 IF_FLAP，靠 event_code_reg 一并盖住它，
-- 否则割接自己造成的闪断会在窗口内炸出一条 P1。配规则时注意把 IF_FLAP
-- 写进 event_code_reg，或者干脆留空（不限事件码）。
-- ============================================================
CREATE TABLE IF NOT EXISTS syslog_mute_rule(
    rule_id BIGINT NOT NULL AUTO_INCREMENT COMMENT '规则ID',
    ip_reg VARCHAR(300) NOT NULL DEFAULT '' COMMENT '设备IP正则，空=不限',
    event_code_reg VARCHAR(300) NOT NULL DEFAULT '' COMMENT '事件码正则，空=不限。注意盖住IF_FLAP',
    object_reg VARCHAR(300) NOT NULL DEFAULT '' COMMENT '告警对象正则，空=不限',
    start_time VARCHAR(10) NOT NULL DEFAULT '' COMMENT '窗口开始(epoch秒)，空=立即生效',
    end_time VARCHAR(10) NOT NULL DEFAULT '' COMMENT '窗口结束(epoch秒)，空=永久静默',
    enabled TINYINT NOT NULL DEFAULT 1 COMMENT '1=启用 0=停用',
    descr VARCHAR(300) NOT NULL DEFAULT '' COMMENT '为什么静默，建议写上变更工单号',
    update_time VARCHAR(10) NOT NULL DEFAULT '' COMMENT '最近更新时间(epoch秒)',
    PRIMARY KEY(rule_id),
    INDEX idx_enabled (enabled),
    INDEX idx_end_time (end_time)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Syslog告警静默规则';

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
-- L4 聚合告警列表  [L4 未实现，表先建好]
--
-- 一个指纹一行，存聚合后的告警。L4 写这张表，L5 更新状态，L3 回写静默
-- 标记，L6 只管发通知。原子记录在 alarm_log，靠 fingerprint 关联。
--
-- 看板和 central-server/api/api_alarm.py 都读这张表。
--
-- 两个字段名沿用 central-server 的老结构，现有分组页面不用改：
--   keyword      存 event_code
--   group_label  存 fingerprint
--
-- 三组状态字段互相独立，不要混用：
--   state   告警自身还成不成立（open/clear），由 L5 状态机维护
--   status  人工处理到哪一步（0待处理/1已确认/2已处理/3忽略/4屏蔽），
--           只有人点才会变
--   muted   有没有被 L3 的静默规则压住，窗口一过自动恢复通知
--
-- muted 和 status=4（人工屏蔽）看起来像，但生命周期完全不同，所以分开存：
-- 人工屏蔽要一直屏蔽到有人去改；muted 是割接窗口结束就该自动恢复告警。
-- 塞进同一个字段，窗口结束时就得判断"这个 4 是人设的还是规则设的"。
--
-- 三者可以同时成立：割接期间被静默（muted=1），值班也点了已确认
-- （status=1），而故障还没好（state=open）。
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
    status VARCHAR(1) NOT NULL DEFAULT '0' COMMENT '人工处理状态 0待处理1已确认2已处理3忽略4屏蔽，只有人点才变',
    muted TINYINT NOT NULL DEFAULT 0 COMMENT '1=被L3静默规则压住，不发通知。窗口过了自动恢复',
    mute_rule_id BIGINT NOT NULL DEFAULT 0 COMMENT '命中的syslog_mute_rule行，0=没被静默',
    counter INT NOT NULL DEFAULT 1 COMMENT '窗口内日志条数，不是事故次数',
    first_seen VARCHAR(10) NOT NULL DEFAULT '' COMMENT '本段首次出现(epoch秒)',
    last_seen VARCHAR(10) NOT NULL DEFAULT '' COMMENT '最近一次出现(epoch秒)',
    clear_time VARCHAR(10) NOT NULL DEFAULT '' COMMENT '恢复时间(epoch秒)，空=未恢复',
    create_time VARCHAR(10) NOT NULL DEFAULT '' COMMENT '创建时间(epoch秒)',
    PRIMARY KEY(alarm_id),
    INDEX idx_ip (ip),
    INDEX idx_group_label (group_label),
    INDEX idx_fingerprint (fingerprint),
    INDEX idx_muted (muted),
    INDEX idx_state (state),
    INDEX idx_status (status),
    INDEX idx_create_time (create_time)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='聚合告警列表';

-- ============================================================
-- L4 原子告警  [L4 未实现，表先建好]
--
-- 一条日志一行，带指纹。alarm_list 里一条聚合告警是由这里的 N 行支撑的，
-- 看板点一条告警就能下钻到具体是哪几条日志。
--
-- **下钻必须带时间范围。** 指纹是 md5(ip|event_code|alarm_object)，不含
-- 时间 —— 同一个口上周那次 down 和今天这次是同一个指纹。只按指纹查会把
-- 这个口所有历史故障的日志混在一起。指纹定位"哪个口的哪类故障"，时间
-- 范围定位"哪一次"，两个一起才唯一：
--
--     select l.* from alarm_log l
--     join alarm_list a on a.fingerprint = l.fingerprint
--     where a.alarm_id = ?
--       and l.ingest_ts >= a.first_seen - 2
--       and l.ingest_ts <= coalesce(nullif(a.clear_time,''), a.last_seen) + 2
--     order by l.ingest_ts;
--
-- 上界取 clear_time（已恢复）或 last_seen（还在告警中）。两头各放宽 2 秒：
-- 写 alarm_log 是攒批的，日志的 ingest_ts 和 L5 更新 last_seen 的时刻之间
-- 有几秒差，卡死边界会漏掉最后一两条。放宽不会串到上一次故障去 ——
-- 相邻两次之间有一个大于窗口（至少 300s）的空档。
--
-- 代码里封装成了 AlarmDB.getAlarmLogsByAlarm(alarm_id)，看板直接调它。
--
-- 一条告警可能跨 L4 的多个段：一个口持续 down 一小时，L4 按 max_life 切
-- 两段，但 L5 看到已有活跃告警只累加，仍是一条告警。所以下钻的边界用
-- alarm_list 那一行的时间范围，不是 L4 的段标签 —— 用段标签只能查到其中一段。
--
-- 过了 L0.5 黑名单的日志条条都写，包括噪声码（BFD_SESSION_CHG /
-- IF_ATTR_CHG）和没产生告警的，所以和 alarm_list 对得上 ——
-- 指纹在 alarm_list 里查不到说明这组日志没到告警阈值，这本身是有用的信息。
--
-- 写入量就是收到的日志量，日志风暴时一分钟几万行，所以：
--   1. 只留 7 天，维护线程按 ingest_ts 批量删。排查基本只看近几小时，
--      再往前的靠 ES 归档
--   2. 字段只放排查必需的。设备型号、资产号这些查 devices 表，
--      不在这里存第二份
--
-- ingest_ts 单独建一个索引给清理用。idx_fingerprint_ts 是复合索引、
-- fingerprint 在前，按 ingest_ts 单独做范围扫用不上它。
-- 存的是定长 10 位的 epoch 字符串，字符串比较和数值比较等价
-- （到 2286 年才会多一位）。
--
-- is_read 给排查流程用：下钻看过的日志标一下，下次只看未读的。
-- 和 alarm_list.status（人工处理到哪一步）不是一回事 —— 那个是针对
-- 一条聚合告警的处理状态，这个是针对单条原始日志的阅读标记。
--
-- 和 ES 归档重复是故意的：ES 那条是旁路，原始报文全量进；这张表只留
-- 近 7 天且带指纹，为的是能和告警关联查询。ES 挂了不影响这张表。
-- ============================================================
CREATE TABLE IF NOT EXISTS alarm_log(
    log_id BIGINT NOT NULL AUTO_INCREMENT COMMENT '原子告警ID',
    fingerprint VARCHAR(64) NOT NULL DEFAULT '' COMMENT '告警指纹，关联alarm_list',
    ip VARCHAR(64) NOT NULL DEFAULT '' COMMENT '设备IP',
    hostname VARCHAR(300) NOT NULL DEFAULT '' COMMENT '设备名称',
    event_code VARCHAR(50) NOT NULL DEFAULT '' COMMENT '事件码',
    alarm_object VARCHAR(100) NOT NULL DEFAULT '' COMMENT '告警对象',
    severity TINYINT NOT NULL DEFAULT 3 COMMENT '1=P1 2=P2 3=P3，L2.5定级的结果',
    mnemonic VARCHAR(80) NOT NULL DEFAULT '' COMMENT 'header段关键字，排查规则命中用',
    rule_id BIGINT NOT NULL DEFAULT 0 COMMENT '命中的syslog_rule行',
    severity_rule_id BIGINT NOT NULL DEFAULT 0 COMMENT '命中的syslog_severity_rule行',
    msg VARCHAR(1024) NOT NULL DEFAULT '' COMMENT '原始报文',
    is_read TINYINT NOT NULL DEFAULT 0 COMMENT '1=已读，排查时标记看过的日志',
    ingest_ts VARCHAR(10) NOT NULL DEFAULT '' COMMENT '采集时间(epoch秒)，不是设备自报时间',
    PRIMARY KEY(log_id),
    INDEX idx_fingerprint_ts (fingerprint, ingest_ts),
    INDEX idx_ip (ip),
    INDEX idx_ingest_ts (ingest_ts)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Syslog原子告警，只留7天';

-- ============================================================
-- 种子数据：兜底事件码
--
-- 这三个码是管线自己产生的，必须存在，否则走代码里的 stateless 默认值，
-- 表里看不到它们、窗口也没法调。
--
-- UNKNOWN_MNEMONIC 同时是规则缺口清单的来源：
--     select vendor, mnemonic, count(*) from <日志归档>
--     where event_code='UNKNOWN_MNEMONIC' group by 1,2 order by 3 desc;
-- 高频未命中的就是下一条该补的规则，补规则时 vendor 直接抄这一行的值。
-- ============================================================
INSERT IGNORE INTO syslog_event
    (event_code, state, object_type, window_sec, threshold, clear_code, descr)
VALUES
('UNKNOWN_MNEMONIC', 'stateless', 'none', 600, 1, '',
 'mnemonic 在规则表里没有对应规则，同时是规则缺口清单'),
('PARSE_FAIL',       'stateless', 'none', 600, 5, '',
 '信封解析失败，单台设备持续发垃圾日志即配置错误，窗口内累计5条才报'),
('UNMANAGED_SRC',    'stateless', 'none', 600, 1, '',
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
    (event_code, state, object_type, window_sec, threshold, clear_code, descr)
VALUES
-- 端口与聚合口
('IF_DOWN',        'raise',     'interface', 300, 1, 'IF_UP',
 '端口down。物理层/链路协议/成员口同时刻产生的几条日志收敛成一条告警'),
('IF_UP',          'clear',     'interface', 300, 1, '',
 '端口up，按IF_DOWN的指纹回关告警'),
('LAG_DOWN',       'raise',     'interface', 300, 1, 'LAG_UP',
 '聚合口全断，最后一个可用成员也没了'),
('LAG_UP',         'clear',     'interface', 300, 1, '',
 '聚合口恢复'),
('LAG_MEMBER_CHG', 'stateless', 'interface', 600, 1, '',
 '聚合口成员切换。有冗余的LAG每天都会发生，报出来就是噪声'),
-- 路由邻居
('BGP_DOWN',       'raise',     'peer',      300, 1, 'BGP_UP',
 'BGP邻居down。BFD会话down归到同一个码，同一指纹只出一条告警'),
('BGP_UP',         'clear',     'peer',      300, 1, '',
 'BGP邻居up'),
('OSPF_DOWN',      'raise',     'peer',      300, 1, 'OSPF_UP',
 'OSPF邻居down'),
('OSPF_UP',        'clear',     'peer',      300, 1, '',
 'OSPF邻居up'),
-- 二层
('MAC_FLAP',       'stateless', 'mac',       600, 3, '',
 'MAC漂移。阈值3兼做降噪，虚机迁移造成的偶发单次不报'),
('STP_TC',         'stateless', 'interface', 600, 1, '',
 'STP拓扑变更'),
-- 硬件
('PSU_FAIL',       'raise',     'slot',      300, 1, 'PSU_OK',
 '电源/风扇/板卡故障'),
('PSU_OK',         'clear',     'slot',      300, 1, '',
 '电源/风扇/板卡恢复'),
-- 管理面
('CONFIG_CHG',     'stateless', 'none',      600, 1, '',
 '配置变更'),
('LOGIN_FAIL',     'stateless', 'none',      600, 1, '',
 '登录失败，暴力破解类'),
-- 噪声码：给它们事件码是为了不混进 UNKNOWN_MNEMONIC 的规则缺口清单，
-- 真正的拦截在 syslog_suppress_rule 配 drop，不靠这里 enabled=0 关
('BFD_SESSION_CHG', 'stateless', 'peer',      600, 1, '',
 'BFD会话删除/迁移，BGP_DOWN的伴生日志，建议配黑名单在L0.5截掉'),
('IF_ATTR_CHG',     'stateless', 'interface', 600, 1, '',
 '速率/双工/流控变化，端口up的伴生日志（一次up刷四条），建议配黑名单'),
-- L5 自己产生的码：没有对应的 mnemonic，不在 syslog_rule 里
-- clear_code 留空是故意的 —— 闪断禁止自动恢复，必须人工确认才关闭
('IF_FLAP',         'raise',     'interface', 1800, 3, '',
 '端口闪断。L5长窗口计数升级产生：同指纹30分钟内3次新开告警。禁止自动恢复');

-- ============================================================
-- 种子数据：事件定级
--
-- 现网 20 个事件码里 14 个是 P3，所以用"一条全局兜底 + 只给非 P3 的码
-- 写行"的写法，10 行覆盖全部，而不是一码一行写 20 行。
-- 新增事件码不写行就是 P3 —— 方向是安全的，宁可级别偏低也不要误报 P1。
--
-- IF_DOWN 的候选链（priority 升序，首条命中即停）：
--     corp rsw -> csw -> rsw -> IF_DOWN 默认 -> *
-- IF_UP 这类没写专门行的，直接落最后那条 '*'。
--
-- 调级别就在这张表加一行，不用动 syslog_event。
-- ============================================================
INSERT IGNORE INTO syslog_severity_rule
    (event_code, ip_reg, sysname_reg, severity, action, priority, descr)
VALUES
-- 判据最窄的排最前：corp 职场接入口 down 不开告警。
-- severity 填 3 只是占位，action=ignore 时级别不参与告警
('IF_DOWN',  '', '^rsw.*corp', 3, 'ignore', 10,
 'corp职场接入口down不告警。单机柜接入无冗余设计，掉口影响面已知且有人值守'),
-- 同一个 IF_DOWN，核心和接入不是一个量级
('IF_DOWN',  '', '^csw',       1, '',       50,
 '核心口down升P1。csw是内网网段网关，掉口等于整个网段断'),
('IF_DOWN',  '', '^rsw',       3, '',       50,
 '接入口down降P3。rsw是ToR，掉口影响一个机柜，有冗余时业务无感'),
-- 各事件码的默认级别，没有设备判据
('IF_DOWN',  '', '',           2, '',       100, '端口down的默认级别'),
('LAG_DOWN', '', '',           1, '',       100, '聚合口全断，不分角色都是P1'),
('BGP_DOWN', '', '',           1, '',       100, 'BGP邻居down'),
('OSPF_DOWN','', '',           1, '',       100, 'OSPF邻居down'),
('MAC_FLAP', '', '',           2, '',       100, 'MAC漂移'),
('PSU_FAIL', '', '',           2, '',       100, '电源/风扇/板卡故障'),
-- 闪断是轮询监控最容易漏、又最常导致业务抖动的一类，不分角色都是P1。
-- 注意它不继承 IF_DOWN 的定级：corp rsw 的 IF_DOWN 配了 ignore，但同一个口
-- 真闪起来照样会升出 IF_FLAP 并按 P1 告警。要连闪断一起不看，
-- 得在这里补一行 sysname_reg='^rsw.*corp' 的 ignore
('IF_FLAP',  '', '',           1, '',       100, '端口闪断，L5升级产生'),
-- 全局兜底。唯一允许匹配全网所有事件的规则，删了会打 error
('*',        '', '',           3, '',       999,
 '全局兜底。没写专门规则的事件码都是P3，加载时查不到这行会打error');

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
-- L3 静默规则示例（默认不插入，按需手工执行）
--
-- 时间用 epoch 秒。end_time 留空=永久静默。
-- 判据为空=不限，多个字段取与。
-- ============================================================
-- 1) 整机静默：某台设备割接窗口内所有事件都不通知
-- INSERT INTO syslog_mute_rule(ip_reg, start_time, end_time, descr)
-- VALUES('^10[.]16[.]249[.]5$', '1763000000', '1763007200',
--        '端口割接窗口，工单 CHG-20261113-007');
--
-- 2) 只静默某个口：割接只动一个接口，别把整机的告警都盖住
-- INSERT INTO syslog_mute_rule(ip_reg, event_code_reg, object_reg,
--                              start_time, end_time, descr)
-- VALUES('^10[.]16[.]249[.]5$', '^(IF_DOWN|IF_UP|IF_FLAP)$', '^Ethernet1/6$',
--        '1763000000', '1763007200', 'Eth1/6 换光模块，工单 CHG-20261113-008');
--
-- 3) 按机房静默：整个机房断电演练，IP 段用正则盖
-- INSERT INTO syslog_mute_rule(ip_reg, start_time, end_time, descr)
-- VALUES('^10[.]19[.]19[.]', '1763000000', '1763014400', 'dc19 断电演练');
--
-- 4) 永久静默：实验环境的设备不参与告警，但日志要留着
-- INSERT INTO syslog_mute_rule(ip_reg, start_time, end_time, descr)
-- VALUES('^10[.]19[.]9[.]99$', '', '', '实验设备，日志留档但永不通知');
--
-- 配规则时注意 IF_FLAP：割接期间的 raise 照样进 L5 的闪断计数，窗口内
-- 连续 3 次会升出一条 P1 的 IF_FLAP。event_code_reg 留空（不限）就能一并
-- 盖住；要是只写了 ^IF_DOWN$，那条 IF_FLAP 会漏出来。

-- ============================================================
-- 升级：alarm_log 去掉 log_date，加 is_read
--
-- 已经建过 alarm_log 的环境手工执行：
--
-- ALTER TABLE alarm_log
--     ADD COLUMN is_read TINYINT NOT NULL DEFAULT 0
--         COMMENT '1=已读，排查时标记看过的日志',
--     ADD INDEX idx_ingest_ts (ingest_ts),
--     DROP INDEX idx_log_date,
--     DROP COLUMN log_date;
--
-- 清理改成按 ingest_ts 删，所以 idx_ingest_ts 必须先建起来 ——
-- idx_fingerprint_ts 是复合索引、fingerprint 在前，
-- 按 ingest_ts 单独做范围扫用不上它，少这个索引清理会扫全表。
-- ============================================================

-- ============================================================
-- 升级：L3 从三档抑制收窄成只有 mute
--
-- syslog_suppress_rule 换成了 syslog_mute_rule：drop 改用
-- syslog_black_list 在 L0.5 截，depend 本轮不做。L3 还没实现过，
-- 旧表里应该是空的，确认之后手工删掉：
--
-- SELECT count(*) FROM syslog_suppress_rule;   -- 先确认是 0
-- DROP TABLE syslog_suppress_rule;
--
-- 已经建过 alarm_list 的环境，上面的 CREATE 不会改已存在的表，
-- 两个静默标记字段要手工加：
--
-- ALTER TABLE alarm_list
--     ADD COLUMN muted TINYINT NOT NULL DEFAULT 0
--         COMMENT '1=被L3静默规则压住，不发通知。窗口过了自动恢复',
--     ADD COLUMN mute_rule_id BIGINT NOT NULL DEFAULT 0
--         COMMENT '命中的syslog_mute_rule行，0=没被静默',
--     ADD INDEX idx_muted (muted);
-- ============================================================

-- ============================================================
-- 升级：severity 从 syslog_event 搬到 syslog_severity_rule
--
-- 本文件可重复执行靠的是 CREATE TABLE IF NOT EXISTS 和 INSERT IGNORE，
-- 但 DROP COLUMN 没有 IF EXISTS，重复执行会报错，所以留在这里手工执行。
--
-- 已经建过 syslog_event 的环境，上面的 CREATE 不会改已存在的表，
-- severity 列还在。确认 syslog_severity_rule 里的定级规则符合预期之后，
-- 手工执行这一句把旧列删掉：
--
-- ALTER TABLE syslog_event DROP COLUMN severity;
--
-- 不删也能跑：代码不再读这一列，只是留着会让人以为还在用。
-- 删之前可以先对一遍两边是否一致，有出入的说明定级规则漏配了：
--
-- SELECT e.event_code, e.severity AS 旧级别, r.severity AS 新级别
-- FROM syslog_event e
-- LEFT JOIN syslog_severity_rule r
--        ON r.event_code = e.event_code AND r.ip_reg = '' AND r.sysname_reg = ''
-- WHERE r.severity IS NULL OR r.severity <> e.severity;
--
-- 查出来的行分两类：新级别为空且旧级别是 3 的，由 '*' 兜底，正常；
-- 其余的要在 syslog_severity_rule 里补一行。
-- ============================================================
