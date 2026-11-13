-- ============================================================
-- switchlog 数据表
--
-- 共用 netops 库。devices / ports 由 central-server 采集侧维护，
-- switchlog 只读，不在本文件里建。
--
--     mysql -h <host> -P <port> -u netops -p netops < sql/schema.sql
--
-- ############################################################
-- #  本文件会先 DROP 再 CREATE，执行即清空这 8 张表的全部数据。  #
-- #  测试阶段专用，不要对生产库执行。                            #
-- ############################################################
--
-- 被清掉的不只是规则，还有历史数据：
--   alarm_list         聚合告警，看板和 central-server/api/api_alarm.py 在读
--   alarm_log          原子告警（本来留 7 天）
--   syslog_alarm_state 未恢复告警的状态，清掉等于所有活跃告警丢失，
--                      进程重启后已经 down 的口不会再报（日志不会重发）
-- 以及人工改过的东西：定级调整、黑名单、静默窗口、alarm_list.status
-- 的处理状态，全部回到本文件的种子值。
--
-- 生产库要加表或改字段，用 sql/patch_*.sql 走 ALTER / INSERT IGNORE，
-- 不要执行本文件。
--
-- 为什么改成先删再建：CREATE TABLE IF NOT EXISTS 对已存在的表什么都不做，
-- 改了列定义、加了索引都不生效，还会出现"文件里写着、库里没有"的偏差 ——
-- 之前 alarm_list 的 muted 和 syslog_rule 的 uniq_match 都得靠文件末尾的
-- 升级注释手工补。测试阶段直接重建，库的结构永远等于本文件。
--
-- 建表顺序无依赖：8 张表之间没有外键，DROP 的先后无所谓。
--
-- 种子数据一律不写自增主键（rule_id 那几个），交给 AUTO_INCREMENT。
-- 重建之后表是空的，去重本不需要，但 INSERT IGNORE / WHERE NOT EXISTS
-- 都保留着 —— 单独重跑某一节种子数据时还得靠它们。各表的唯一键：
--
--   syslog_black_list     uniq_scope_ip_pattern (scope, ip, pattern)
--   syslog_rule           uniq_match (vendor, mnemonic, match_type,
--                                     pattern, body_match)
--   syslog_event          主键 event_code
--   syslog_severity_rule  uniq_code_ip_sysname (event_code, ip_reg, sysname_reg)
--   syslog_mute_rule      没有唯一键，用 WHERE NOT EXISTS 去重（见该节注释）
--
-- 原来 syslog_rule 的去重靠显式 rule_id，有两个毛病：补丁之间要人工对号
-- （34 被占了就得翻文件找空号），而且同一条规则换个号就能重复插进去。
-- uniq_match 按"匹配身份"去重之后这两个问题都没了。
-- ============================================================

USE netops;

-- ============================================================
-- L2 黑名单：解析前拦截
--
-- 和 L8 抑制表的区别：这层只有 mnemonic/子串 + ip 两个判据，解析前就执行，
-- 命中即丢。要正则、要 mute、要时间窗的规则配到 syslog_suppress_rule 去。
--
--   scope=mnemonic  pattern 是 mnemonic 全名，进 dict，O(1) 命中
--   scope=message   pattern 是全文子串，线性扫
--
-- 能按 mnemonic 配的一律用 mnemonic：实测 162 字节报文逐条 str.find，
-- 20 条规则就和剥一次 mnemonic 一样贵，500 条是 21 倍；而 mnemonic 由
-- L1 剥好透传进来，dict 查一次只要 0.036us。scope=message 那一串要保持小，
-- 每条日志都会扫它。
--
-- 没有 priority：黑名单只有"丢"一个动作，命中哪条结果都一样。
-- (scope, ip, pattern) 建唯一索引，重复配置在入库时就挡住。
-- ============================================================
DROP TABLE IF EXISTS syslog_black_list;
CREATE TABLE syslog_black_list(
    rule_id BIGINT NOT NULL AUTO_INCREMENT COMMENT '规则ID',
    pattern VARCHAR(300) NOT NULL DEFAULT '' COMMENT 'scope=mnemonic时为mnemonic全名，scope=message时为全文子串',
    scope VARCHAR(10) NOT NULL DEFAULT 'mnemonic' COMMENT 'mnemonic=进dict精确命中 / message=全文子串线性扫',
    ip VARCHAR(64) NOT NULL DEFAULT '' COMMENT '限定设备IP，空=所有设备',
    ignore_case TINYINT NOT NULL DEFAULT 0 COMMENT '1=大小写不敏感，只对scope=message生效',
    enabled TINYINT NOT NULL DEFAULT 1 COMMENT '1=启用 0=停用',
    descr VARCHAR(300) NOT NULL DEFAULT '' COMMENT '为什么拦这条，便于日后判断能不能放开',
    hit_count BIGINT NOT NULL DEFAULT 0 COMMENT '累计命中次数，维护线程定期从内存计数器刷过来，不是热路径实时写',
    last_hit_time VARCHAR(10) NOT NULL DEFAULT '' COMMENT '最近一次命中时间(epoch秒)，空=从未命中',
    update_time VARCHAR(10) NOT NULL DEFAULT '' COMMENT '最近更新时间(epoch秒)',
    PRIMARY KEY(rule_id),
    UNIQUE KEY uniq_scope_ip_pattern (scope, ip, pattern),
    INDEX idx_enabled (enabled)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Syslog解析前黑名单';

-- ============================================================
-- L3 匹配规则：(vendor, mnemonic) -> event_code
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
--
-- 唯一键建在"匹配身份"上：(vendor, mnemonic, match_type, pattern, body_match)
-- 这五列决定一条报文会不会命中这行，五列都相同就是同一条规则，rule_id 是几
-- 无关。有了它，种子数据和补丁都不用再显式写 rule_id ——
-- 交给 AUTO_INCREMENT，INSERT IGNORE 照样去重，本文件照样可重复执行。
--
-- object_regex / priority / descr 不进唯一键：它们是同一条规则的属性，
-- 改正则不该算成一条新规则（否则改一次正则就多出一行，旧行还在生效，
-- 而且 priority 相同时谁先命中取决于 rule_id，排查起来很难看出来）。
-- 要改这三列用 UPDATE 或 REPLACE，不要 INSERT。
--
-- 索引长度 30+80+10+300+200=620 字符 × 4 字节 = 2480 字节，
-- 在 InnoDB DYNAMIC 行格式的 3072 字节上限内，不用加前缀长度。
-- ============================================================
DROP TABLE IF EXISTS syslog_rule;
CREATE TABLE syslog_rule(
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
    UNIQUE KEY uniq_match (vendor, mnemonic, match_type, pattern, body_match),
    INDEX idx_vendor_mnemonic (vendor, mnemonic),
    INDEX idx_event_code (event_code),
    INDEX idx_priority (priority),
    INDEX idx_enabled (enabled)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Syslog解析匹配规则';

-- ============================================================
-- L5 事件属性
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
--               L7 据此让恢复事件落到故障事件的指纹上，否则告警关不掉
--
-- severity 不在这张表里，在 syslog_severity_rule —— 同一个事件码在不同
-- 角色的设备上不是一个级别（csw 的 IF_DOWN 比 rsw 的要紧），一个事件码
-- 一行存不下这件事。详见下面那张表的注释。
-- ============================================================
DROP TABLE IF EXISTS syslog_event;
CREATE TABLE syslog_event(
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
-- L5 事件定级：event_code + 设备 -> severity
--
-- 为什么不把 severity 放在 syslog_event 里：那张表一个事件码一行，
-- 只能表达"全网统一"。但同一个 IF_DOWN，csw 掉口是核心网段断了（P1），
-- rsw 掉口是一个机柜的接入（P3），corp 职场的 rsw 掉口压根不用看。
-- 级别取决于"哪个事件 + 哪台设备"两个维度，一个事件码一行存不下。
--
-- 定级跑在 L4 富化之后：那时 sysname 已经从 devices 表补好，可以按设备名
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
-- action='ignore' 的事件照样走完管线并落 ES，只是 L7 不开告警。
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
DROP TABLE IF EXISTS syslog_severity_rule;
CREATE TABLE syslog_severity_rule(
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
-- L8 告警静默
--
-- 只有 mute 一档，判据 ip_reg / event_code_reg / object_reg + 时间窗。
--
-- 原来设计的 drop 和 depend 两档都取消了：
--   drop   确定是噪声的日志用 syslog_black_list 在 L2 截掉。越早丢
--          越省资源，而且那一层按 mnemonic 走 dict，比解析完再丢便宜
--   depend 拓扑抑制依赖运行时的上游可达状态，不是静态规则能表达的，
--          本轮不做
--
-- 跑在 L7 之后，不在 L5 之后：
--   1. 判据里的 object 要等 L3 抽、L6 聚合，级别和状态要等 L5/L7
--   2. 冷路径。只有 L7 判定"需要告警"的聚合告警才过这一层 ——
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
DROP TABLE IF EXISTS syslog_mute_rule;
CREATE TABLE syslog_mute_rule(
    rule_id BIGINT NOT NULL AUTO_INCREMENT COMMENT '规则ID',
    ip_reg VARCHAR(300) NOT NULL DEFAULT '' COMMENT '设备IP正则，空=不限',
    event_code_reg VARCHAR(300) NOT NULL DEFAULT '' COMMENT '事件码正则，空=不限。注意盖住IF_FLAP',
    object_reg VARCHAR(300) NOT NULL DEFAULT '' COMMENT '告警对象正则，空=不限',
    start_time VARCHAR(10) NOT NULL DEFAULT '' COMMENT '窗口开始(epoch秒)，空=立即生效',
    end_time VARCHAR(10) NOT NULL DEFAULT '' COMMENT '窗口结束(epoch秒)，空=永久静默',
    enabled TINYINT NOT NULL DEFAULT 1 COMMENT '1=启用 0=停用',
    descr VARCHAR(300) NOT NULL DEFAULT '' COMMENT '为什么静默，建议写上变更工单号',
    hit_count BIGINT NOT NULL DEFAULT 0 COMMENT '累计命中次数（告警被压住的次数，不是日志条数），维护线程定期从内存计数器刷过来',
    last_hit_time VARCHAR(10) NOT NULL DEFAULT '' COMMENT '最近一次命中时间(epoch秒)，空=从未命中',
    update_time VARCHAR(10) NOT NULL DEFAULT '' COMMENT '最近更新时间(epoch秒)',
    PRIMARY KEY(rule_id),
    INDEX idx_enabled (enabled),
    INDEX idx_end_time (end_time)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Syslog告警静默规则';

-- ============================================================
-- L7 告警状态
--
-- 保存未恢复的告警状态，进程重启后接着算，不会重复告警。
-- 同一指纹只保留一行。
--
-- severity 和 base_severity 分开存：闪断会把级别临时提一档
-- （P3->P2->P1），稳定后要落回 base_severity，所以原始级别不能丢。
-- ============================================================
-- 注意：清掉这张表等于丢掉所有未恢复告警的状态。日志不会重发，
-- 所以重建后已经 down 的口不会再产生告警，要等它下次翻动才会重新被发现
DROP TABLE IF EXISTS syslog_alarm_state;
CREATE TABLE syslog_alarm_state(
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
    ignore_counter INT NOT NULL DEFAULT 0 COMMENT 'ignore行的日志条数，和counter分开：同一指纹下ignore行和clear_orphan行是两条独立记录',
    ignore_first_seen VARCHAR(10) NOT NULL DEFAULT '' COMMENT 'ignore行的首次出现(epoch秒)',
    ignore_alarm_id BIGINT NOT NULL DEFAULT 0 COMMENT 'ignore行对应的alarm_list记录，和alarm_id分开存',
    updated_time VARCHAR(10) NOT NULL DEFAULT '' COMMENT '最近写入时间(epoch秒)',
    PRIMARY KEY(fingerprint),
    INDEX idx_state (state),
    INDEX idx_last_seen (last_seen)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Syslog告警状态';

-- ============================================================
-- 聚合告警列表（L9 写）
--
-- 一个指纹一行，存聚合后的告警。L6 算指纹、L7 定告警动作、L8 判静默，
-- 最后由 L9 一次写进来 —— muted 跟着其余字段一起 insert，不是先写
-- 再改。原子记录在 alarm_log，靠 fingerprint 关联。
--
-- counter 由维护线程定期同步（Runner.persist）：L7 对已有活跃告警的
-- 后续日志只累加不产生动作，L9 不跑，所以这一列会停在开告警那一刻。
--
-- 看板和 central-server/api/api_alarm.py 都读这张表。
--
-- 两个字段名沿用 central-server 的老结构，现有分组页面不用改：
--   keyword      存 event_code
--   group_label  存 fingerprint
--
-- 三组状态字段互相独立，不要混用：
--   state   告警自身还成不成立（open/clear），由 L7 状态机维护
--   status  处理状态（0待处理/1已确认/2已处理/3忽略/4屏蔽/5系统判定忽略），
--           0~4 只有人点才会变，5 是 L9 写入的，人工操作不会选到这个值
--   muted   有没有被 L8 的静默规则压住，窗口一过自动恢复通知
--
-- status=5 和 status=3（人工忽略）、muted（L8静默）看起来都是"不告警"，
-- 但触发源不一样：3 是人点出来的，5 是 L5 定级规则 action=ignore 判定的
-- （哪类设备的哪个事件码永久不告警），muted 是 L8 时间窗临时压住。
-- 分开存是为了不把"系统自动判定"和"人工操作"混进同一份统计里。
--
-- muted 和 status=4（人工屏蔽）看起来像，但生命周期完全不同，所以分开存：
-- 人工屏蔽要一直屏蔽到有人去改；muted 是割接窗口结束就该自动恢复告警。
-- 塞进同一个字段，窗口结束时就得判断"这个 4 是人设的还是规则设的"。
--
-- 三者可以同时成立：割接期间被静默（muted=1），值班也点了已确认
-- （status=1），而故障还没好（state=open）。
-- ============================================================
-- 注意：看板和 central-server/api/api_alarm.py 都在读这张表，
-- 清掉等于告警历史和人工处理状态（status）全部归零
DROP TABLE IF EXISTS alarm_list;
CREATE TABLE alarm_list(
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
    vendor VARCHAR(30) NOT NULL DEFAULT '' COMMENT '设备厂商，L4富化时按devices.vendor原值写入，排查用',
    hardware VARCHAR(100) NOT NULL DEFAULT '' COMMENT '设备型号，L4富化时按devices.hardware写入，排查用',
    object_name VARCHAR(100) NOT NULL DEFAULT '' COMMENT '对象归一化识别名，目前只有接口会填（ports.if_name全名），其它对象类型留空',
    object_alias VARCHAR(200) NOT NULL DEFAULT '' COMMENT '对象人类可读描述，目前只有接口会填（ports.alias接口描述），其它对象类型留空',
    severity TINYINT NOT NULL DEFAULT 3 COMMENT '1=P1 2=P2 3=P3',
    state VARCHAR(10) NOT NULL DEFAULT 'open' COMMENT 'open=告警中 clear=已恢复 idle=ignore判定不告警，没有活跃状态',
    status VARCHAR(1) NOT NULL DEFAULT '0' COMMENT '处理状态 0待处理1已确认2已处理3忽略4屏蔽5系统判定忽略，5由L9写入非人工操作',
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
-- L6 原子告警
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
-- 写 alarm_log 是攒批的，日志的 ingest_ts 和 L7 更新 last_seen 的时刻之间
-- 有几秒差，卡死边界会漏掉最后一两条。放宽不会串到上一次故障去 ——
-- 相邻两次之间有一个大于窗口（至少 300s）的空档。
--
-- 代码里封装成了 AlarmDB.getAlarmLogsByAlarm(alarm_id)，看板直接调它。
--
-- 一条告警可能跨 L6 的多个段：一个口持续 down 一小时，L6 按 max_life 切
-- 两段，但 L7 看到已有活跃告警只累加，仍是一条告警。所以下钻的边界用
-- alarm_list 那一行的时间范围，不是 L6 的段标签 —— 用段标签只能查到其中一段。
--
-- 过了 L2 黑名单的日志条条都写，包括噪声码（BFD_SESSION_CHG /
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
-- 注意：清掉之后告警下钻就没有原始日志可看了，ES 里还有（旁路全量）
DROP TABLE IF EXISTS alarm_log;
CREATE TABLE alarm_log(
    log_id BIGINT NOT NULL AUTO_INCREMENT COMMENT '原子告警ID',
    fingerprint VARCHAR(64) NOT NULL DEFAULT '' COMMENT '告警指纹，关联alarm_list',
    ip VARCHAR(64) NOT NULL DEFAULT '' COMMENT '设备IP',
    hostname VARCHAR(300) NOT NULL DEFAULT '' COMMENT '设备名称',
    event_code VARCHAR(50) NOT NULL DEFAULT '' COMMENT '事件码',
    alarm_object VARCHAR(100) NOT NULL DEFAULT '' COMMENT '告警对象',
    severity TINYINT NOT NULL DEFAULT 3 COMMENT '1=P1 2=P2 3=P3，L5定级的结果',
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
 'BFD会话删除/迁移，BGP_DOWN的伴生日志，建议配黑名单在L2截掉'),
('IF_ATTR_CHG',     'stateless', 'interface', 600, 1, '',
 '速率/双工/流控变化，端口up的伴生日志（一次up刷四条），建议配黑名单'),
-- L7 自己产生的码：没有对应的 mnemonic，不在 syslog_rule 里
-- clear_code 留空是故意的 —— 闪断禁止自动恢复，必须人工确认才关闭
('IF_FLAP',         'raise',     'interface', 1800, 3, '',
 '端口闪断。L7长窗口计数升级产生：同指纹30分钟内3次新开告警。禁止自动恢复'),
-- 加密许可带宽饱和：撞 securityk9 的 85Mbps 上限。是容量项不是网络故障，
-- 定级表里配了 ignore 不开告警，但日志照样解析归档。窗口给长，
-- 因为持续发的时候按 300s 切段会产生大量碎窗口
('CRYPTO_BW',       'stateless', 'none',      3600, 1, '',
 'Cisco加密功能吞吐撞上license带宽上限。容量问题走license审计，不进告警'),
-- PoE / 风扇 / 杂项。全部 stateless：这批日志没有一个有可靠的恢复日志，
-- 配 raise 会开出永远关不掉的告警（DEV/4/FAN 尤其明显，20 分钟刷 30 条）。
-- 窗口按日志自身的重复节奏给，不统一用 300s
('POE_PD_CHG',        'stateless', 'interface', 600,   1, '',
 'PoE终端插拔。办公网日常行为，定级配ignore，留日志回溯AP/话机掉线时间'),
-- 和 PSU_FAIL 分开：那个码配了 clear_code=PSU_OK，而思科这条没有恢复日志，
-- 混进去会让 PSU_FAIL 的恢复配对出错
('FAN_LOW_RPM',       'stateless', 'slot',      3600,  1, '',
 '风扇转速过低，其余风扇已升速补偿。是备件工单不是故障告警'),
-- 和 MAC_FLAP 分开：那个码的 object_type 是 mac，这条的对象是被限速的接口，
-- 塞进同一个码会让指纹的对象类型不一致
('MAC_FLAP_SUPPRESS', 'stateless', 'interface', 600,   1, '',
 'MAC漂移导致未知单播被限速到端口带宽50%。已在影响业务转发，比单纯MAC_FLAP要紧'),
('MAC_FLAP_RECOVER',  'stateless', 'none',      600,   1, '',
 'MAC漂移检测恢复。MAC_FLAP是stateless、静默即恢复，这条只用于回溯环路何时消失'),
('BUFFER_THRESHOLD',  'stateless', 'slot',      3600,  1, '',
 'Nexus缓存池超90%水线。微突发征兆，容量项走容量审计，不进告警'),
('DHCP_TIMEOUT',      'stateless', 'interface', 600,   1, '',
 '设备自身DHCP客户端超时拿不到地址，管理面可能失联'),
('CERT_EXPIRED',      'stateless', 'none',      86400, 1, '',
 '设备本地证书已过期，影响HTTPS管理/802.1X，按天提醒'),
('CLOCK_CHG',         'stateless', 'none',      3600,  1, '',
 '系统时钟变更。NTP对时的正常结果，定级配ignore'),
('NTP_DROP',          'stateless', 'none',      3600,  1, '',
 'NTP丢弃私有模式报文，公网扫描打上来的。安全侧信息，不是网络故障'),
-- 温度异常。三家厂商 15 条 mnemonic 收敛成一对 raise/clear。
--
-- 为什么不按 minor/major 拆成两个事件码：华三和华为各自只有一条恢复
-- mnemonic（DEV/5/TEMPERATURE_NORMAL、ENTITYTRAP/4/ENTITYBRDTEMPRESUME），
-- 不区分是从哪个级别恢复的。拆开之后 clear_code 只能挂给其中一个
-- （syslog_event 的 clear_code 反查表不允许一个恢复码对应两个故障码，
-- 加载时会打 error），另一个就永远关不掉。
--
-- object_type=none：不抽对象，一台设备一条温度告警。
-- 同一块板多个传感器同时超限收敛成一条，不会一个传感器一条。
--
-- window 3600：现网 rsw1_mdu15_prod_dc07_m01 的 Back 传感器常年贴着
-- 45 度线上下晃（46 报、44 恢复），一天一对。给长窗口避免碎窗口。
('TEMP_ALARM', 'raise', 'none', 3600, 1, 'TEMP_OK',
 '温度异常，需要IDC介入。三家厂商的温度告警/高温/严重告警都归这里'),
('TEMP_OK',    'clear', 'none', 3600, 1, '',
 '温度恢复，按TEMP_ALARM的指纹回关告警');

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
-- 按网段定级：测试网段的漂移不用按生产环境的级别看
-- 职场设备的 MAC 漂移不告警。priority=10 必须小于下面测试网段那条（50），
-- 否则 corp 职场里恰好落在 10.19.9.x 的设备会先命中那条被降成 P3 正常告警。
-- sysname_reg 用不带锚的 'corp' 走 re.search，子串命中即可 ——
-- 职场里不只有 rsw，asw/csw 也要盖住，'^rsw.*corp' 会把它们漏掉
('MAC_FLAP', '', 'corp',                   3, 'ignore', 10,
 '职场设备MAC漂移不告警。无线漫游/终端换口天天发生，不是故障'),
('MAC_FLAP', '^10[.]19[.]9[.]', '',         3, '',       50,  '测试网段的MAC漂移降P3'),
('MAC_FLAP', '', '',           2, '',       100, 'MAC漂移'),
('PSU_FAIL', '', '',           2, '',       100, '电源/风扇/板卡故障'),
-- 闪断是轮询监控最容易漏、又最常导致业务抖动的一类，不分角色都是P1。
-- 注意它不继承 IF_DOWN 的定级：corp rsw 的 IF_DOWN 配了 ignore，但同一个口
-- 真闪起来照样会升出 IF_FLAP 并按 P1 告警。要连闪断一起不看，
-- 得在这里补一行 sysname_reg='^rsw.*corp' 的 ignore
('IF_FLAP',  '', '',           1, '',       100, '端口闪断，L7升级产生'),
-- 加密许可带宽饱和：撞 securityk9 的 85Mbps 上限。这是容量项，不是网络故障，
-- 照常解析归档但不进告警列表。没配成黑名单是因为这条本身有信息量 ——
-- 某天真出现 IPsec 会话建不起来时要回溯它到底什么时候开始撞的
('CRYPTO_BW', '', '',          3, 'ignore', 100,
 '加密吞吐撞license带宽上限，容量项非网络故障，不开告警'),
-- PoE / 风扇 / 杂项的定级：5 个 ignore + 4 个正常告警。
--
-- 宁可配 ignore 也不配黑名单，判断同 CRYPTO_BW —— 这几个码的日志本身
-- 有回溯价值。PoE 插拔用来回答"这个 AP 是什么时候掉的"，缓存水线用来
-- 回答"丢包投诉那天缓存撞没撞顶"。L2 丢掉之后这些问题就查不了了。
-- 真正毫无价值的才配黑名单（那两条 PoE 功率回显）。
--
-- 四条正常告警里没有 P1：这批都不是"业务已经断了"的事件
('POE_PD_CHG',        '', '', 3, 'ignore', 100,
 'PoE终端插拔是办公网日常行为，不告警。留日志回溯AP/话机掉线时间'),
('BUFFER_THRESHOLD',  '', '', 3, 'ignore', 100,
 'Nexus缓存水线属容量项，走容量审计。留日志用于回溯丢包投诉'),
('MAC_FLAP_RECOVER',  '', '', 3, 'ignore', 100,
 '恢复类日志，MAC_FLAP本身stateless静默即恢复，不需要告警'),
('CLOCK_CHG',         '', '', 3, 'ignore', 100,
 'NTP对时的正常结果，不告警'),
('NTP_DROP',          '', '', 3, 'ignore', 100,
 '公网NTP扫描，安全侧信息非网络故障，不告警'),
('MAC_FLAP_SUPPRESS', '', '', 2, '',       100,
 '端口已被限速到50%带宽，已在影响业务转发，比单纯MAC_FLAP要紧'),
('FAN_LOW_RPM',       '', '', 3, '',       100,
 '风扇待更换，是备件工单。给P3不给P2：其余风扇已升速补偿，不会立即过温'),
('DHCP_TIMEOUT',      '', '', 3, '',       100,
 '设备自身管理地址拿不到。真失联轮询监控会先报，这条只用于定位原因'),
('CERT_EXPIRED',      '', '', 3, '',       100,
 '证书已过期，影响HTTPS管理/802.1X。按天提醒，不是紧急故障'),
-- 温度异常。老系统等级是"提示"，对应 P3；action 留空=正常告警，不是 ignore。
-- 全网生效（老系统设备组是"所有设备"），职场和机房都报 —— 温度是硬件问题，
-- 不像端口/MAC 那样分职场机房。
-- 恢复事件 TEMP_OK 不写专门行，落全局兜底的 '*'（P3 正常告警）
('TEMP_ALARM',        '', '', 3, '',       100,
 '温度异常，需要IDC介入。老系统等级"提示"，全网生效'),
-- 职场设备的速率/双工/流控变化不告警。
-- sysname_reg 用不带锚的 'corp' 而不是 '^rsw.*corp'：职场里不只有 rsw，
-- asw1_corp_ts_m20 / csw1_corp_hz_m09 这些都要盖住，而 ^rsw 开头的写法
-- 把它们漏在外面。sysname_reg 走 re.search，子串命中即可。
--
-- IF_ATTR_CHG 本来就是端口 up 的伴生日志（一次 up 刷速率/双工/收发流控
-- 四条），职场终端每天插拔，这四条跟着刷。没写专门规则之前它落全局兜底
-- 的 '*'（P3、正常告警），现网样本里是量最大的事件码。
--
-- 没配黑名单的理由同其他 ignore 项：日志留着能回答"这个口是不是协商到了
-- 100M"。真要彻底不解析，配 syslog_black_list 的 ETHPORT-5-SPEED 那几条。
--
-- priority 给 50 不给 100：留出 100 这一档，以后要给非职场的 IF_ATTR_CHG
-- 配默认级别时直接加一行 sysname_reg 为空的，不用再动这一行
('IF_ATTR_CHG',       '', 'corp', 3, 'ignore', 50,
 '职场设备的速率/双工/流控变化不告警。终端每天插拔，是端口up的伴生日志'),
-- 全局兜底。唯一允许匹配全网所有事件的规则，删了会打 error
('*',        '', '',           3, '',       999,
 '全局兜底。没写专门规则的事件码都是P3，加载时查不到这行会打error');

-- 停用示例：加载时被 enabled 过滤掉，验证开关。恢复事件没有升 P1 的道理，
-- 这行只是为了验证 enabled=0 的规则不会生效才留着
INSERT IGNORE INTO syslog_severity_rule
    (event_code, ip_reg, sysname_reg, severity, action, priority, enabled, descr)
VALUES
('BGP_UP', '', '', 1, '', 50, 0, '停用示例：恢复事件没有升 P1 的道理，留着验证 enabled');

-- ============================================================
-- 种子数据：L3 匹配规则
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
    (vendor, mnemonic, match_type, pattern, body_match,
     event_code, object_regex, priority, descr)
VALUES
-- NX-OS 物理口 down：两种正文格式。IF_DOWN 的接口名后面跟逗号，
-- LINK_FAILURE 跟空格再跟 (description:...)。字符类同时排掉空格/逗号/左括号，
-- 一套正则吃下两种正文，且绝不会把 description 里的内容当接口名
('cisco_nx', 'ETHPORT-5-IF_DOWN', 'exact', '', '',
 'IF_DOWN', 'Interface\\s+([^\\s,(]+)', 100,
 'Interface Ethernet1/38, changed state to down'),
('cisco_nx', 'ETHPORT-5-IF_DOWN_LINK_FAILURE', 'exact', '', '',
 'IF_DOWN', 'Interface\\s+([^\\s,(]+)', 100,
 'Interface Ethernet1/6 (description:pT:xxx) is down (Link failure)'),
('cisco_nx', 'LINEPROTO-5-UPDOWN', 'exact', '', 'changed state to down',
 'IF_DOWN', 'on Interface\\s+([^,\\s]+),', 100,
 'Line protocol on Interface Ethernet1/38, changed state to down'),
('cisco_nx', 'LINEPROTO-5-UPDOWN', 'exact', '', 'changed state to up',
 'IF_UP', 'on Interface\\s+([^,\\s]+),', 100,
 'Line protocol up'),
('cisco_nx', 'ETH_PORT_CHANNEL-5-PORT_DOWN', 'exact', '', '',
 'IF_DOWN', ':\\s+(\\S+)\\s+is\\s+down', 100,
 'port-channel38: Ethernet1/38 is down。对象是成员口，不是LAG'),
-- 聚合口：FOP_CHANGED 的 'to none' 才是全断，priority 小的先判。
-- 靠"冒号+空格+名字+冒号"定位行首的 LAG 名
('cisco_nx', 'ETH_PORT_CHANNEL-5-FOP_CHANGED', 'exact', '', 'to none',
 'LAG_DOWN', ':\\s+(\\S+?):', 10,
 'first operational port changed from Ethernet1/38 to none，最后一个成员没了'),
('cisco_nx', 'ETH_PORT_CHANNEL-5-FOP_CHANGED', 'exact', '', '',
 'LAG_MEMBER_CHG', ':\\s+(\\S+?):', 200,
 'changed from Ethernet1/38 to Ethernet1/39，还有成员时是正常冗余切换'),
('cisco_nx', 'ETHPORT-5-IF_DOWN_PORT_CHANNEL_MEMBERS_DOWN', 'exact', '', '',
 'LAG_DOWN', 'Interface\\s+([^\\s,(]+)', 100,
 'Interface port-channel38 is down (No operational members)'),
-- Comware / 华为：同一 mnemonic，up/down 只差正文
('h3c', 'IFNET/3/PHY_UPDOWN', 'exact', '', 'changed to down',
 'IF_DOWN', 'interface (\\S+?) changed', 100,
 'Physical state on the interface GigabitEthernet1/0/1 changed to down.'),
('h3c', 'IFNET/3/PHY_UPDOWN', 'exact', '', 'changed to up',
 'IF_UP', 'interface (\\S+?) changed', 100,
 'H3C 物理口 up'),
-- Comware 的链路协议层，和上面 PHY_UPDOWN 是同一次翻动的两条日志：
-- 现网 172.25.1.122 的 GigabitEthernet1/0/23 在 09:19:34 同一秒打了
-- IFNET/3/PHY_UPDOWN（物理层）和 IFNET/5/LINK_UPDOWN（链路协议层）。
-- 归同一个事件码、用同一个 object_regex，两条落同一指纹 -> 一次翻动
-- 只出一条告警。和 cisco_nx 那边 ETHPORT-5-IF_DOWN + LINEPROTO-5-UPDOWN
-- 都归 IF_DOWN 是同一个套路。
--
-- 正文只差一个词（Physical state / Line protocol state），所以
-- object_regex 和 body_match 都能直接沿用 PHY_UPDOWN 那两行
('h3c', 'IFNET/5/LINK_UPDOWN', 'exact', '', 'changed to down',
 'IF_DOWN', 'interface (\\S+?) changed', 100,
 'Line protocol state on the interface GigabitEthernet1/0/23 changed to down.'),
('h3c', 'IFNET/5/LINK_UPDOWN', 'exact', '', 'changed to up',
 'IF_UP', 'interface (\\S+?) changed', 100,
 'Line protocol state on the interface GigabitEthernet1/0/23 changed to up.（现网样本，S5130S/Comware 7.1.070）'),
('huawei', 'IFNET/3/PHY_UPDOWN', 'exact', '', 'turned into DOWN',
 'IF_DOWN', 'interface (\\S+?) has', 100,
 'The interface XGigabitEthernet0/0/1 has turned into DOWN state.'),
('huawei', 'IFNET/3/PHY_UPDOWN', 'exact', '', 'turned into UP',
 'IF_UP', 'interface (\\S+?) has', 100,
 '华为物理口 up'),
-- 各家写法一致的用 vendor='*' 一行覆盖
('*', 'ETHPORT-5-IF_UP', 'exact', '', '',
 'IF_UP', 'Interface\\s+([^\\s,(]+)', 100,
 '两种正文都有：Interface Eth1/6, operational... 和 Eth1/6 (description:...) is up'),
('*', 'BGP-5-ADJCHANGE', 'exact', '', 'Down',
 'BGP_DOWN', 'neighbor\\s+(\\d+\\.\\d+\\.\\d+\\.\\d+)', 100,
 'neighbor 172.28.2.133 Down - sent: bfd session down'),
('*', 'BGP-5-ADJCHANGE', 'exact', '', 'Up',
 'BGP_UP', 'neighbor\\s+(\\d+\\.\\d+\\.\\d+\\.\\d+)', 100,
 'neighbor 172.28.2.133 Up'),
-- BFD 掉了就是 BGP 掉了，归到同一个 event_code，同一指纹只出一条告警
('*', 'BFD-5-SESSION_STATE_DOWN', 'exact', '', '',
 'BGP_DOWN', 'neighbor\\s+(\\d+\\.\\d+\\.\\d+\\.\\d+)', 100,
 'BFD session to neighbor 172.28.2.133 on interface Eth1/6 has gone down'),
-- 噪声类：照常给事件码，L8 配 drop 拦掉
('*', 'BFD-5-SESSION_REMOVED', 'exact', '', '',
 'BFD_SESSION_CHG', 'neighbor\\s+(\\d+\\.\\d+\\.\\d+\\.\\d+)', 100,
 'BFD 会话删除，down 之后的必然结果'),
('*', 'BFD-5-SESSION_MOVED', 'exact', '', '',
 'BFD_SESSION_CHG', '', 100,
 'BFD 会话在板卡间迁移，正文里没有邻居IP'),
-- 另两条 BFD 会话事件，和上面两条一起归 BFD_SESSION_CHG。
-- 四条连起来能还原一次邻居震荡的全过程：
--   STATE_DOWN -> BGP_DOWN（真告警，P1）
--   REMOVED / MOVED / CREATED / STATE_UP -> BFD_SESSION_CHG（过程记录）
-- STATE_UP 没归到 BGP_UP：BGP 邻居恢复由 BGP-5-ADJCHANGE 的 Up 那条负责，
-- BFD 会话 up 只是底层探测通了，两件事。归过去会让 BGP_DOWN 的告警
-- 被一条 BFD 事件关掉，而 BGP 邻居可能还没起来
('*', 'BFD-5-SESSION_CREATED', 'exact', '', '',
 'BFD_SESSION_CHG', 'neighbor\\s+(\\d+\\.\\d+\\.\\d+\\.\\d+)', 100,
 'BFD 会话建立。正文格式未对现网核实，正则沿用 SESSION_REMOVED 那条'),
('*', 'BFD-5-SESSION_STATE_UP', 'exact', '', '',
 'BFD_SESSION_CHG', 'neighbor\\s+(\\d+\\.\\d+\\.\\d+\\.\\d+)', 100,
 'BFD 会话UP。正则沿用 SESSION_STATE_DOWN 那条（同一对事件，正文格式一致）'),
('*', 'ETHPORT-5-SPEED', 'exact', '', '',
 'IF_ATTR_CHG', 'Interface\\s+([^\\s,(]+)', 100,
 '协商速率变化，端口up的伴生日志'),
('*', 'ETHPORT-5-IF_DUPLEX', 'exact', '', '',
 'IF_ATTR_CHG', 'Interface\\s+([^\\s,(]+)', 100,
 '双工模式变化，伴生日志'),
('*', 'ETHPORT-5-IF_RX_FLOW_CONTROL', 'exact', '', '',
 'IF_ATTR_CHG', 'Interface\\s+([^\\s,(]+)', 100,
 '收向流控变化，伴生日志'),
('*', 'ETHPORT-5-IF_TX_FLOW_CONTROL', 'exact', '', '',
 'IF_ATTR_CHG', 'Interface\\s+([^\\s,(]+)', 100,
 '发向流控变化，伴生日志'),
-- FortiGate：mnemonic 取 logid
('fortinet', '0100032003', 'exact', '', '',
 'LOGIN_FAIL', '', 100,
 'Administrator admin login failed from ssh'),
('fortinet', '0101037129', 'exact', '', '',
 'BGP_DOWN', 'remote_ip=(\\d+\\.\\d+\\.\\d+\\.\\d+)', 100,
 'IPSec 隧道 down 当邻居 down 处理'),
-- mnemonic 留空：只对剥不出 mnemonic 的报文生效，走模糊匹配
('*', '', 'contains', 'authentication failure', '',
 'LOGIN_FAIL', '', 300,
 'sshd[1234]: authentication failure for admin，无mnemonic'),
('*', '', 'regex', '[Cc]onfigured from (console|vty)', '',
 'CONFIG_CHG', '', 300,
 'Configured from vty by admin，无mnemonic'),
-- MAC 漂移：L2FM-4-L2FM_MAC_MOVE2 的正文带版本号 2，不同型号/版本可能
-- 是 L2FM_MAC_MOVE（不带 2），mnemonic 不一样要分别配一行，不能只认一种
('cisco_nx', 'L2FM-4-L2FM_MAC_MOVE2', 'exact', '', '',
 'MAC_FLAP', 'Mac\\s+([0-9a-fA-F]{4}\\.[0-9a-fA-F]{4}\\.[0-9a-fA-F]{4})', 100,
 'Mac e67b.0b15.973f in vlan 1080 has moved from Po43 to Po45'),
-- 华为 V200R022 口 down/up 的另一套 mnemonic：DEVM 是物理层、IFNET 是接口协议层，
-- 同一次物理翻动两条一起打，对象字段名不同（EntPhysicalName vs ifName），分别配正则
('huawei', 'DEVM/2/hwPortDown', 'exact', '', '',
 'IF_DOWN', 'EntPhysicalName=([^,)]+)', 100,
 'EntPhysicalIndex=16847137, EntPhysicalName=GE1/0/32, hwPortDownReason=0, ifOperStatus=0, ifAdminStatus=1, faultID=144384'),
('huawei', 'DEVM/4/hwPortUp', 'exact', '', '',
 'IF_UP', 'EntPhysicalName=([^,)]+)', 100,
 'EntPhysicalIndex=16847137, EntPhysicalName=GE1/0/32, ifOperStatus=1, ifAdminStatus=1'),
('huawei', 'IFNET/2/linkDown_active', 'exact', '', '',
 'IF_DOWN', 'ifName=([^,)]+)', 100,
 'ifName=GE1/0/32, AdminStatus=UP, OperStatus=DOWN, Reason=Interface physical link is down, mainIfname=GE1/0/32'),
('huawei', 'IFNET/2/linkDown_clear', 'exact', '', '',
 'IF_UP', 'ifName=([^,)]+)', 100,
 'ifName=GE1/0/32, AdminStatus=UP, OperStatus=UP, Reason=Interface physical link is up, mainIfname=GE1/0/32'),
-- 华为 VLAN 环路导致的 MAC 漂移 trap，MAC 地址是四段中划线格式（c6e5-964a-24b5），
-- 和 cisco_nx 的点分格式不一样，正则单独配
('huawei', 'FEI/4/hwMflpVlanLoopPeriodicTrap', 'exact', '', '',
 'MAC_FLAP', 'address\\s*:\\s*([0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4})', 100,
 'MAC flapping detected, VlanId = 136, Original-Port = Eth-Trunk100, Flapping port 1 = Eth-Trunk1, port 2 = -. ...address : c6e5-964a-24b5'),
-- H3C 风扇故障。mnemonic 只能填 DEV/1/FAN ——
-- l1_prepare.strip_mnemonic 的正则在斜杠最后一段碰到空格就截断，
-- "DEV/1/FAN STATE CHANGES TO FAILURE" 实际剥出来的是 "DEV/1/FAN"，
-- 要靠 body_match 认后面的 STATE CHANGES TO FAILURE 才能区分故障/恢复。
-- 只配了 FAILURE，恢复日志样例还没拿到，先不配 PSU_OK，
-- 等现网出现"FAN STATE CHANGES TO NORMAL"之类的回显再补
('h3c', 'DEV/1/FAN', 'exact', '', 'STATE CHANGES TO FAILURE',
 'PSU_FAIL', 'fan ID is\\s+(\\d+)', 100,
 '%%10DEV/1/FAN STATE CHANGES TO FAILURE(t):-DevIP=10.39.240.32; Trap ...<hh3cfanfailure>: fan ID is 1'),
-- H3C 风扇故障的第二套 mnemonic：DEV/1/FAN 是 trap、DEV/4/FAN 是日志，
-- 同一次故障两条一起打。抽出的 fan ID 相同 -> 同一指纹 -> 只出一条告警。
-- mnemonic 同样只能填到 DEV/4/FAN（空格截断），靠 body_match 认 FAILED
('h3c', 'DEV/4/FAN', 'exact', '', 'FAN FAILED',
 'PSU_FAIL', 'Fan\\s+(\\d+)\\s+failed', 100,
 '%%10DEV/4/FAN FAILED(l):-DevIP=10.39.240.33;   Fan 1 failed.'),
-- 思科风扇低转速。单独事件码不并进 PSU_FAIL：没有恢复日志，
-- 并进去会让 PSU_FAIL->PSU_OK 的配对关不掉它
('cisco_ios', 'ENVMON-4-ONE_FAN_LOW_RPM', 'exact', '', '',
 'FAN_LOW_RPM', 'Fan\\s+(\\d+)', 100,
 'Warning: Fan 4 is running at low RPM. Rotation speed is now high for all other fans.'),
-- 华为 PoE 的 PD 插拔：syslog 与 trap 各打一条，归同一事件码、抽同一对象，
-- 落同一指纹，一次插拔只出一条记录（同 DEVM/IFNET 那一对）。
-- object_regex 用 Interface=([^,)]+) 同时吃下两种正文，不能写 ([^)]+) ——
-- 后者会把 "48, Interface=GE1/0/48" 整段抓进来
('huawei', 'POE/6/PDCONNECT', 'exact', '', '',
 'POE_PD_CHG', 'Interface=([^,)]+)', 100,
 'PD on the interface is connected. (Interface=GE1/0/48)'),
('huawei', 'POE/6/PDDISCONNECT', 'exact', '', '',
 'POE_PD_CHG', 'Interface=([^,)]+)', 100,
 'PD on the interface is disconnected. (Interface=GE1/0/48)'),
('huawei', 'POE/4/hwPoePdConnected_active', 'exact', '', '',
 'POE_PD_CHG', 'Interface=([^,)]+)', 100,
 'PD connected. (IfIndex=48, Interface=GE1/0/48)，PDCONNECT的伴生trap'),
('huawei', 'POE/4/hwPoePdDisconnected_active', 'exact', '', '',
 'POE_PD_CHG', 'Interface=([^,)]+)', 100,
 'PD disconnected. (IfIndex=47, Interface=GE1/0/47)，PDDISCONNECT的伴生trap'),
-- 华为 MAC 漂移限速。对象是被限速的接口，不是 MAC，所以不能并进 MAC_FLAP
('huawei', 'SECE/4/UCSUPPRESS', 'exact', '', '',
 'MAC_FLAP_SUPPRESS', 'Interface=([^,)]+)', 100,
 'MAC address flapping started on port. The rate of unknown unicast packets was limited to 50% of the port bandwidth.(Interface=GigabitEthernet0/0/36)'),
-- 设备自身做 DHCP 客户端要不到地址，正文里的键名是 InterfaceName
('huawei', 'DHCP/5/WAITOFFER_TIMEOUT', 'exact', '', '',
 'DHCP_TIMEOUT', 'InterfaceName=([^,)]+)', 100,
 'The DHCP server did not respond within the specified period. (Client InterfaceName=Vlanif1, CurrentState=Init, ...)'),
('huawei', 'PKI/4/LOCAL_EXPIRED', 'exact', '', '',
 'CERT_EXPIRED', '', 100,
 'LOCAL certificate (/OU=.../CN=S5720_device.pem) has expired for 71 days.'),
('h3c', 'SYSMIB/4/CLKCHANGE', 'exact', '', '',
 'CLOCK_CHG', '', 100,
 '<hh3cSysClockChangedNotification> System clock changed'),
-- DAEMON-3-SYSTEM_MSG 是大杂烩 mnemonic，各种守护进程都往里打。
-- body_match 把范围卡死在 NTP 丢包这一种正文 —— 不配的话这条会把所有
-- SYSTEM_MSG 都吞成 NTP_DROP，其余内容就从缺口清单里消失了
('cisco_nx', 'DAEMON-3-SYSTEM_MSG', 'exact', '', 'NTP Receive dropping message',
 'NTP_DROP', '', 100,
 'NTP Receive dropping message: Received NTP private mode packet from 35.210.65.179. Drop count: 44330'),
-- 加密许可带宽饱和。vendor 用 '*'：这条在 IOS / IOS-XE 上都见过，
-- 具体是哪台设备发的还没确认，先不限厂商，命中后看 stats 再收窄
('*', 'CERM-4-TX_BW_LIMIT', 'exact', '', '',
 'CRYPTO_BW', '', 100,
 'Maximum Tx Bandwidth limit of 85000 Kbps reached for Crypto functionality with securityk9 technology package license'),
-- ---------- 以下两条 mnemonic 留空，只对剥不出 mnemonic 的报文生效 ----------
--
-- 这两条不得不走 fuzzy：它们的 header 格式 strip_mnemonic 剥不出来。
-- 正则 #1 的 FAC 段和正则 #2 的模块段都是 [A-Za-z][A-Za-z0-9_]*，
-- 不收中划线，所以 "TAHUSD-SLOT1" 和 "FWM-ETH" 都过不去，mnemonic 是空串，
-- 按 mnemonic 配的规则永远查不到它们。
--
-- 本该改 l1_prepare 的正则把中划线收进去，但那是全量报文的热路径，
-- 一动所有日志的 mnemonic 都可能变，现有规则得全部重核。
-- 先用 fuzzy 接住，等有一轮完整回归再动 L1。
--
-- 代价可控：fuzzy_candidates 只在 mnemonic 为空时才跑。现网样本
-- 38/660 条无 mnemonic（5.8%），其中 10 条 "last message repeated"
-- 已被 L2 黑名单在更前面拦掉，真正走到这里的是 28 条。
-- 四条 fuzzy 互不重叠，已对现网样本核过，无交叉误命中
('cisco_nx', '', 'contains', 'BUFFER_THRESHOLD_EXCEEDED', '',
 'BUFFER_THRESHOLD', 'Module\\s+(\\d+)', 300,
 '%TAHUSD-SLOT1-4-BUFFER_THRESHOLD_EXCEEDED: Module 1 Instance 0 Pool-group buffer 90 percent threshold is exceeded!（FAC段含中划线，mnemonic剥不出）'),
('huawei', '', 'contains', 'hwMflpVlanLoopAlarm_clear', '',
 'MAC_FLAP_RECOVER', '', 300,
 '%%01FWM-ETH/4/hwMflpVlanLoopAlarm_clear(l):...;Mac flapping detection recovered in vlan 136.（模块段含中划线，mnemonic剥不出）');

-- ============================================================
-- 种子数据：温度异常（三家厂商 15 条）
--
-- 来源：上一套系统的"温度异常"告警规则（sql/log_config.json，
-- 规则名"温度异常"、描述"需要IDC介入"、等级提示、设备组所有设备）。
-- 那边 15 条 keyword 全是 matchMode=3（包含），我们这边按 mnemonic
-- 全名进 dict，所以逐条照搬 mnemonic。
--
-- object_regex 全部留空：不抽对象，一台设备一条温度告警。
-- 同一块板多个传感器同时超限收敛成一条。
--
-- 归一到 TEMP_ALARM / TEMP_OK 一对：告警侧 10 条、恢复侧 5 条。
-- 不按 minor/major 拆，理由见 syslog_event 那一节的注释。
-- ============================================================
INSERT IGNORE INTO syslog_rule
    (vendor, mnemonic, match_type, pattern, body_match,
     event_code, object_regex, priority, descr)
VALUES
-- Cisco NX-OS。现网 rsw1_mdu15_prod_dc07_m01（N3K-C3048TP）在刷
-- MOD_TEMPMINALRM / MOD_TEMPOK 这一对，正文已核对：
--   Module-1 reported minor temperature alarm. Sensor=1 Temperature=46 MinThreshold=45
--   Module-1 recovered from minor temperature alarm. Sensor=1 Temperature=44 MinThreshold=45
-- 注意 MOD_TEMPMAJALRM 的严重度数字是 0 不是 2，照搬老系统的写法
('cisco_nx', 'PLATFORM-0-MOD_TEMPMAJALRM', 'exact', '', '',
 'TEMP_ALARM', '', 100, '思科温度告警（严重）'),
('cisco_nx', 'PLATFORM-2-MOD_TEMPMINALRM', 'exact', '', '',
 'TEMP_ALARM', '', 100,
 'Module-1 reported minor temperature alarm. Sensor=1 Temperature=46 MinThreshold=45'),
('cisco_nx', 'PLATFORM-2-MOD_TEMPMAJOR2WARM', 'exact', '', '',
 'TEMP_ALARM', '', 100, '思科温度告警，major 降到 warm'),
('cisco_nx', 'PLATFORM-2-MOD_TEMPMINOR2WARM', 'exact', '', '',
 'TEMP_ALARM', '', 100, '思科温度告警，minor 降到 warm'),
('cisco_nx', 'PLATFORM-2-MOD_TEMPOK', 'exact', '', '',
 'TEMP_OK', '', 100,
 'Module-1 recovered from minor temperature alarm. Sensor=1 Temperature=44 MinThreshold=45'),
('cisco_nx', 'PLATFORM-2-MOD_TEMPMAJOR_OK', 'exact', '', '',
 'TEMP_OK', '', 100, '思科温度告警恢复（major）'),
('cisco_nx', 'PLATFORM-2-MOD_TEMPWARM_OK', 'exact', '', '',
 'TEMP_OK', '', 100, '思科温度告警恢复（warm）'),
-- 华为
('huawei', 'ENTITYTRAP/1/ENTITYBRDTEMPALARM', 'exact', '', '',
 'TEMP_ALARM', '', 100, '华为温度异常'),
('huawei', 'BASETRAP/3/TEMRISING', 'exact', '', '',
 'TEMP_ALARM', '', 100, '华为单板温度高'),
('huawei', 'ENTITYTRAP/4/ENTITYBRDTEMPRESUME', 'exact', '', '',
 'TEMP_OK', '', 100, '华为温度恢复'),
-- 华三。恢复那条老系统给了完整写法 DEV/5/TEMPERATURE_NORMAL，照搬。
--
-- 告警那三条老系统只写了裸名（TEMPERATURE_ALARM / _SHUTDOWN / _WARNING），
-- 它那边是全文"包含"所以裸名能命中，我们按 mnemonic 全名查 dict 不行 ——
-- 实际日志里应该是 DEV/<数字>/TEMPERATURE_xxx，但严重度数字我没有现网
-- 样例核实，不照手册臆造（DEV/1/FAN 那次就是照手册写法配的，剥出来对不上，
-- 白配一轮）。
--
-- 所以这三条按 DEV/ 前缀 + 常见严重度数字各配一行，宁可多配几行废规则
-- 也不漏：数字不对的那几行永远不命中，不影响别的；对的那行会命中。
-- 拿到现网样例后把没命中的删掉即可（看 alarm_log 的 rule_id 分布）。
-- 数字取值依据 Comware 的惯例：1=alert 2=critical 3=error 4=warning
('h3c', 'DEV/1/TEMPERATURE_ALARM', 'exact', '', '',
 'TEMP_ALARM', '', 100, '华三温度告警。严重度数字待现网样例核实'),
('h3c', 'DEV/2/TEMPERATURE_SHUTDOWN', 'exact', '', '',
 'TEMP_ALARM', '', 100, '华三温度严重告警（会关板卡）。严重度数字待核实'),
('h3c', 'DEV/4/TEMPERATURE_WARNING', 'exact', '', '',
 'TEMP_ALARM', '', 100, '华三温度告警（预警）。严重度数字待现网样例核实'),
('h3c', 'DEV/5/TEMPERATURE_NORMAL', 'exact', '', '',
 'TEMP_OK', '', 100, '华三温度恢复'),
-- SIC 模块温度控制电路异常。老系统归在同一条规则里，照搬
('h3c', 'HSC/4/SICTMPEXC', 'exact', '', '',
 'TEMP_ALARM', '', 100, 'SIC模块温度控制电路异常');

-- 不写 rule_id，交给 AUTO_INCREMENT。去重靠 uniq_match
-- (vendor, mnemonic, match_type, pattern, body_match)，重复执行不会插出第二份

-- ============================================================
-- 种子数据：L2 黑名单
--
-- 只放"确定是噪声、解析它纯属浪费"的日志。
-- 能按 mnemonic 配的一律用 scope=mnemonic，走 dict 命中；
-- scope=message 那一串每条日志都会扫，要保持小。
-- ============================================================
INSERT IGNORE INTO syslog_black_list
    (pattern, scope, ip, ignore_case, enabled, descr)
VALUES
('SSHD-6-SESSION_CONNECTED', 'mnemonic', '', 0, 1,
 'SSH 建连过程，登录成功与否看 LOGIN_FAIL'),
('VSHD-5-VSHD_SYSLOG_CONFIG_I', 'mnemonic', '', 0, 1,
 '配置变更的逐条回显，量大且无告警价值'),
('last message repeated', 'message', '', 1, 1,
 'syslog 自身的折叠提示，不带 mnemonic，只能按全文拦'),
('Configuration update aborted', 'message', '', 0, 1,
 '配置回滚的调试输出，不带 mnemonic'),
-- 只拦某台设备：进 (ip, mnemonic) 那张 dict，不参与全量流量
('ETHPORT-5-IF_DOWN_CHANNEL_ADMIN_DOWN', 'mnemonic', '10.16.249.5', 0, 1,
 '该设备成员口人工 shutdown 后持续刷，确认过无影响'),
-- BFD 那几条曾经在这里（SESSION_MOVED / SESSION_REMOVED），现在移出去了：
-- 四条 BFD 会话事件统一走 L3 的 BFD_SESSION_CHG 事件码，见 syslog_rule。
-- 理由是 BFD 会话的创建/迁移/删除/UP 连起来能还原一次邻居震荡的过程，
-- 在 L2 丢掉就什么都不剩了。不想看告警的话去 syslog_severity_rule
-- 配 action=ignore —— 那样日志照样落 alarm_log 可回溯，只是不开告警。
('LICENSE-6-VIOLATION', 'mnemonic', '', 0, 1,
 'License特性用量超授权数的周期性提示，非故障，每分钟刷一次。容量问题走license审计，不进告警管线'),
-- PoE 端口功率周期回显：几秒一条、每次数值都不一样（Power=2400/1100/3100），
-- 既不是故障也没有回溯价值。现网样本里 58 条，是未命中里量最大的一类。
-- 两个 mnemonic 是同一件事在两个版本上的写法，少配一个那台 S5720 会继续
-- 落 UNKNOWN_MNEMONIC：
--   POE/6/PORTPWR  V600R023（CloudEngine S5735）括号里 key=value
--   POE/6/PORTPW   V200R011（S5720 老 VRP）无括号纯文字，少个 R
('POE/6/PORTPWR', 'mnemonic', '', 0, 1,
 'PoE端口功率周期回显(V600R023)，几秒一条且数值每次都变，无告警与回溯价值'),
('POE/6/PORTPW', 'mnemonic', '', 0, 1,
 'PoE端口功率周期回显(V200R011老VRP写法，少个R)，同上'),
-- 日志文件老化删除。设备自己的日志轮转，和网络状态无关，连回溯价值都没有
-- （要查设备上还剩哪些日志文件直接登上去 dir flash:/logfile/ 看）。
-- 同一件事打两条：(t) 结尾的是 trap、(l) 结尾的是 log，两个 mnemonic 都要拦，
-- 少配一个另一条继续落 UNKNOWN_MNEMONIC。
-- INFO 模块下现网只有这两条，按 mnemonic 精确拦不会牵连别的
('INFO/4/hwICLogFileAging', 'mnemonic', '', 0, 1,
 '日志文件老化删除的trap。设备自身日志轮转，与网络状态无关'),
('INFO/4/IM_LOGFILE_AGING_DELETE', 'mnemonic', '', 0, 1,
 '日志文件老化删除的log，上面那条trap的伴生日志，同一件事打两条'),
-- ---------- 以下 6 条来自历史屏蔽词清单（sql/log_ignore.txt）----------
--
-- 那份清单是上一套系统攒的，判据只有"全文包含"一种，和现在的
-- (scope=mnemonic 走 dict) + (scope=message 线性扫) 两档对不上，所以整份
-- 不导入，只当参考 —— 遇到现网日志时查一下它里面有没有，有就说明之前
-- 已经判过是噪声，省一次判断。
--
-- 这 6 条的特殊之处：它们在清单里，但我们之前给它们配了 syslog_rule
-- 要识别。黑名单在 L2、比 L3 规则早，所以加在这里之后那些规则就永不命中，
-- 对应的事件码变成死码（见文件末尾"死码清单"那一节，列了是哪几个、
-- 以及想恢复时怎么做）。
--
-- 没有删掉那些 syslog_rule：黑名单这一行就是开关 —— 哪天想重新看某一类，
-- 把这里对应的行 enabled=0，L3 的规则和定级原样还在，立刻恢复识别。
-- 规则删了反而要重新配一遍正则。
-- BFD-5-SESSION_REMOVED 曾经在这里，已移出 —— 四条 BFD 会话事件统一走
-- L3 的 BFD_SESSION_CHG，见 syslog_rule 那一节
('DAEMON-3-SYSTEM_MSG', 'mnemonic', '', 0, 1,
 'Nexus守底进程杂项消息，现网见到的是NTP丢弃公网扫描报文。非网络故障'),
('DHCP/5/WAITOFFER_TIMEOUT', 'mnemonic', '', 0, 1,
 '设备自身DHCP客户端超时。真失联轮询监控会先报，这条自己不构成故障'),
('SYSMIB/4/CLKCHANGE', 'mnemonic', '', 0, 1,
 '系统时钟变更，NTP对时的正常结果'),
-- 下面四条是同一件事：一次端口 up 这四条一起刷（速率/双工/收向流控/发向流控）。
-- 四条必须一起拦 —— 只拦其中两条，另两条照样进管线，降噪只做一半。
-- 端口本身的 up/down 由 ETHPORT-5-IF_UP 和 IF_DOWN 那几条规则负责，不受影响
('ETHPORT-5-SPEED', 'mnemonic', '', 0, 1,
 '协商速率变化，端口up的伴生日志。一次up刷四条，四条一起拦'),
('ETHPORT-5-IF_DUPLEX', 'mnemonic', '', 0, 1,
 '双工模式变化，端口up的伴生日志'),
('ETHPORT-5-IF_RX_FLOW_CONTROL', 'mnemonic', '', 0, 1,
 '收向流控变化，端口up的伴生日志'),
('ETHPORT-5-IF_TX_FLOW_CONTROL', 'mnemonic', '', 0, 1,
 '发向流控变化，端口up的伴生日志'),
-- Nexus 缓存池水线。只能用 scope=message —— mnemonic 剥出来是空串：
-- strip_mnemonic 的 FAC 段正则是 [A-Za-z][A-Za-z0-9_]*，不收中划线，
-- "TAHUSD-SLOT1" 中间那个中划线过不去（和 FWM-ETH 同一个坑）。
--
-- pattern 选 BUFFER_THRESHOLD_EXCEEDED 而不是 TAHUSD 或 "Pool-group buffer"：
-- 四个候选子串在现网 2591 条样本里都精确命中同一批 160 条、无误伤，
-- 选这个是因为它自带语义，日后查表的人不用去猜 TAHUSD 是什么。
--
-- 依据：上一套系统 2021-01-22 就拦了这条（sql/log_ignore.json id=1337，
-- 江源远配的，理由"突发流量，不影响业务"）。现网 160/2591 = 6.2%，量不小。
--
-- 注意这条会让 syslog_rule 里那条 fuzzy 规则（映射 BUFFER_THRESHOLD）变成
-- 死码 —— 规则留着当开关，见文件末尾"死码清单"
('BUFFER_THRESHOLD_EXCEEDED', 'message', '', 0, 1,
 'Nexus缓存池超90%水线。突发流量不影响业务（沿用2021年的判断），mnemonic剥不出只能按全文拦'),
-- 接口丢包告警。txt 第 339 行 '01QOS/4/hwXQoSPacketsDropInterfaceAlarm'
-- 是前缀写法，我们的 dict 要 mnemonic 全名，所以 _active / _clear 各一行。
-- 现网 172.26.1.74 的 GE1/0/10 在刷这个：口协商成了 100M、CRC 15580，
-- 突发打满队列就丢。丢包率 0.0099%，对一台办公PC无影响 ——
-- 真要治是换线/换网卡，不是盯告警
('QOS/4/hwXQoSPacketsDropInterfaceAlarm_active', 'mnemonic', '', 0, 1,
 '接口丢包告警。突发打满队列所致，要治是查物理层不是看告警'),
('QOS/4/hwXQoSPacketsDropInterfaceAlarm_clear', 'mnemonic', '', 0, 1,
 '接口丢包恢复，上面那条的伴生日志'),
-- PoE 剩下 3 条，txt 第 40/41/114 行都有。
-- 上面已经配了 PORTPWR/PORTPW（功率回显），PD 插拔走 POE_PD_CHG 规则，
-- 这三条补齐 PoE 这一类：非标PD、PD下电、PSE端口上下电
('POE/4/NONSTANDARDPD', 'mnemonic', '', 0, 1,
 '接到非标PD。办公网终端五花八门，是终端的事不是网络故障'),
('POE/6/PDPOWEROFF', 'mnemonic', '', 0, 1,
 'PD下电。拔设备/PD自己断电都会打，和PDDISCONNECT同类'),
('POE/1/PSE_PORT_ON_OFF_CHANGE', 'mnemonic', '', 0, 1,
 'PSE端口供电开关变化，PoE口日常通断的伴生日志'),
-- 证书类。LOCAL_EXPIRED 原来走 CERT_EXPIRED 事件码按 P3 告警，现在拉黑
-- （事件码和规则留着当开关，见文件末尾"死码清单"）。
-- CA_VALID 来自 txt 第 33 行，一起配上，免得以后又冒出来
('PKI/4/LOCAL_EXPIRED', 'mnemonic', '', 0, 1,
 '设备本地证书过期。影响HTTPS管理/802.1X，但不是网络故障，走证书轮换流程'),
('PKI/4/CA_VALID', 'mnemonic', '', 0, 1,
 'CA证书有效期提示，txt第33行已判为噪声'),
-- License 类。上面已有 LICENSE-6-VIOLATION（用量超授权的周期提示），
-- 这两条是 license 缺失/文件丢失的告警，txt 第 282/522 行都判过。
-- 和 VIOLATION 一样：容量与授权的事走 license 审计，不进告警管线
('LICMGR-2-LOG_LIC_MISSING_WARNING', 'mnemonic', '', 0, 1,
 'License缺失告警。授权问题走license审计，不是网络故障'),
('LICMGR-3-LOG_LIC_FILE_MISSING', 'mnemonic', '', 0, 1,
 'License文件丢失，txt第522行已判为噪声，同族一起配');

-- ============================================================
-- 种子数据：L8 静默规则模板（三条，全部 enabled=0）
--
-- **执行本文件不会静默任何告警。** 三条都是停用的模板。
--
-- 为什么没有一条 enabled=1：静默规则压的是"该发但不发"的通知，配错的
-- 代价是真故障没人知道，而且表里看起来一切正常。开窗口必须对应一个具体的
-- 变更/工单，不该由建表脚本顺手开出来。
--
-- 写成 enabled=0 的真实行而不是注释，为两件事：
--   1. 加载逻辑能被验证 —— 同 syslog_severity_rule 里那条 BGP_UP 停用示例，
--      确认 enabled 过滤真的在生效
--   2. 要用的时候是 UPDATE 一行、填两个时间戳，不用从注释里拷 SQL 再自己
--      拼字段。割接前手忙脚乱时，少一步拼写就少一个出错的地方
--
-- 启用方式（填真实 epoch 与工单号）：
--   UPDATE syslog_mute_rule SET enabled=1,
--          start_time='1763000000', end_time='1763007200',
--          descr='...工单 CHG-xxx'
--    WHERE rule_id=?;
--
-- 时间用 epoch 秒，end_time 留空=永久静默，判据为空=不限、多字段取与。
--
-- 去重用 WHERE NOT EXISTS 而不是 INSERT IGNORE：syslog_mute_rule 没有
-- 唯一键（同样的判据配不同时间窗是合理的，不该被当成重复），
-- 而 INSERT IGNORE 在没有唯一键的表上不去重，重复执行会插出三份。
-- ============================================================

-- 1) 整机静默模板。本文件里 PSU_FAIL 的两台 oob 就是典型场景：
--    10.39.240.32/33 在 20 分钟样本里各刷了 30 条 FAN 日志，而 PSU_FAIL
--    是 raise、threshold=1，一来就开 P2；syslog_rule 里只配了 FAILURE
--    没配恢复（现网还没拿到恢复日志样例），这条告警开了就关不掉。
--    等备件到货、确认 RMA 工单号再启用 —— 现在写个假窗口比不写更糟
INSERT INTO syslog_mute_rule
    (ip_reg, event_code_reg, object_reg, start_time, end_time, enabled, descr)
SELECT '^10[.]39[.]240[.](32|33)$', '^(PSU_FAIL|FAN_LOW_RPM)$', '', '', '', 0,
       '模板-整机静默：dc07 oob 风扇待换件期间屏蔽，启用前填 start/end 与 RMA 工单号'
  FROM DUAL
 WHERE NOT EXISTS (SELECT 1 FROM syslog_mute_rule
                    WHERE descr LIKE '模板-整机静默%');

-- 2) 单接口静默模板。换光模块这类只动一个口的变更用这条，别拿上面那条
--    把整机盖住 —— 同一台设备上别的口真 down 了还得报
INSERT INTO syslog_mute_rule
    (ip_reg, event_code_reg, object_reg, start_time, end_time, enabled, descr)
SELECT '^10[.]16[.]249[.]5$', '^(IF_DOWN|IF_UP|IF_FLAP)$', '^Ethernet1/6$', '', '', 0,
       '模板-单口静默：换光模块/改配线只动一个接口时用，启用前填 ip/object/时间窗与工单号'
  FROM DUAL
 WHERE NOT EXISTS (SELECT 1 FROM syslog_mute_rule
                    WHERE descr LIKE '模板-单口静默%');

-- 3) 整机房静默模板。event_code_reg 故意留空（不限事件码）：断电演练期间
--    什么都会响，而且留空能自动盖住 IF_FLAP —— 割接期间的 raise 照样进
--    L7 的闪断计数，窗口内连续 3 次会升出一条 P1；只写 ^IF_DOWN$ 的话
--    那条 IF_FLAP 会漏出来
INSERT INTO syslog_mute_rule
    (ip_reg, event_code_reg, object_reg, start_time, end_time, enabled, descr)
SELECT '^10[.]19[.]19[.]', '', '', '', '', 0,
       '模板-机房静默：断电演练/整机房割接用，event_code_reg留空以一并盖住IF_FLAP'
  FROM DUAL
 WHERE NOT EXISTS (SELECT 1 FROM syslog_mute_rule
                    WHERE descr LIKE '模板-机房静默%');

-- ============================================================
-- 历史升级记录（本文件已不需要，留给不能重建的生产库）
--
-- 下面这些 ALTER 原来挂在文件末尾，是因为 CREATE TABLE IF NOT EXISTS
-- 对已存在的表什么都不做，新加的列和索引得手工补。本文件改成先删再建
-- 之后，上面的 CREATE 已经是最终结构，这些语句一句都不用执行。
--
-- 留着是因为生产库不能 DROP。那边要对齐结构，按下面逐条 ALTER：
--
--   1) alarm_log：去掉 log_date、加 is_read
--      ALTER TABLE alarm_log
--          ADD COLUMN is_read TINYINT NOT NULL DEFAULT 0
--              COMMENT '1=已读，排查时标记看过的日志',
--          ADD INDEX idx_ingest_ts (ingest_ts),
--          DROP INDEX idx_log_date,
--          DROP COLUMN log_date;
--      清理改成按 ingest_ts 删，idx_ingest_ts 必须先建起来 ——
--      idx_fingerprint_ts 是复合索引、fingerprint 在前，按 ingest_ts
--      单独做范围扫用不上它，少这个索引清理会扫全表。
--
--   2) alarm_list：加两个静默标记（L8 从三档收窄成只有 mute 时加的）
--      ALTER TABLE alarm_list
--          ADD COLUMN muted TINYINT NOT NULL DEFAULT 0
--              COMMENT '1=被L3静默规则压住，不发通知。窗口过了自动恢复',
--          ADD COLUMN mute_rule_id BIGINT NOT NULL DEFAULT 0
--              COMMENT '命中的syslog_mute_rule行，0=没被静默',
--          ADD INDEX idx_muted (muted);
--
--   3) 删掉旧的 syslog_suppress_rule。drop 改用 syslog_black_list 在 L2
--      截，depend 本轮不做。L8 还没实现过，旧表里应该是空的：
--      SELECT count(*) FROM syslog_suppress_rule;   -- 先确认是 0
--      DROP TABLE syslog_suppress_rule;
--
--   4) syslog_rule 补 uniq_match 唯一键。种子数据不再写 rule_id，少了这个
--      键 INSERT IGNORE 就不去重，补丁重跑会插出多份一样的规则（功能上不
--      致命，判据相同命中结果一样，但表会越跑越脏，改正则时要改好几行、
--      漏一行就有旧行还在生效）。
--      建键前先确认没有重复行，有的话 ADD UNIQUE KEY 会直接失败：
--      SELECT vendor, mnemonic, match_type, pattern, body_match, count(*) c,
--             group_concat(rule_id) ids
--        FROM syslog_rule GROUP BY 1,2,3,4,5 HAVING c > 1;
--      按 ids 保留最小那个、删掉其余，然后：
--      ALTER TABLE syslog_rule
--          ADD UNIQUE KEY uniq_match (vendor, mnemonic, match_type,
--                                     pattern, body_match);
--      这一句也在 sql/patch_20261113_poe_fan_misc.sql 里，执行过那个补丁
--      的环境不用再执行。
--
--   5) syslog_event 删掉旧的 severity 列（级别已搬到 syslog_severity_rule）
--      ALTER TABLE syslog_event DROP COLUMN severity;
--      不删也能跑，代码不再读这一列，只是留着会让人以为还在用。
--      删之前对一遍两边是否一致，有出入的说明定级规则漏配了：
--      SELECT e.event_code, e.severity AS 旧级别, r.severity AS 新级别
--        FROM syslog_event e
--        LEFT JOIN syslog_severity_rule r
--               ON r.event_code = e.event_code
--              AND r.ip_reg = '' AND r.sysname_reg = ''
--       WHERE r.severity IS NULL OR r.severity <> e.severity;
--      查出来的行分两类：新级别为空且旧级别是 3 的，由 '*' 兜底，正常；
--      其余的要在 syslog_severity_rule 里补一行。
--
--   6) alarm_list 补 L4 富化已查到、但 L9 原来没落库的四列。
--      alarm_object 是 L3 抽的原始识别对象（参与指纹，不能改），
--      object_name / object_alias 是 L4 在此基础上查到的归一化名字和
--      可读描述，目前只有接口对象会填（ports.if_name / ports.alias）：
--      ALTER TABLE alarm_list
--          ADD COLUMN vendor VARCHAR(30) NOT NULL DEFAULT ''
--              COMMENT '设备厂商，L4富化时按devices.vendor原值写入，排查用',
--          ADD COLUMN hardware VARCHAR(100) NOT NULL DEFAULT ''
--              COMMENT '设备型号，L4富化时按devices.hardware写入，排查用',
--          ADD COLUMN object_name VARCHAR(100) NOT NULL DEFAULT ''
--              COMMENT '对象归一化识别名，目前只有接口会填（ports.if_name全名），其它对象类型留空',
--          ADD COLUMN object_alias VARCHAR(200) NOT NULL DEFAULT ''
--              COMMENT '对象人类可读描述，目前只有接口会填（ports.alias接口描述），其它对象类型留空';
--      只补新字段，不回填历史行 —— 老告警这几列留空，不影响
--      state/severity 等既有逻辑，看板上显示为空即可。
-- ============================================================

-- ============================================================
-- 死码清单：有规则有定级，但被 L2 黑名单挡在前面，永不命中
--
-- 这几个事件码的 syslog_rule / syslog_severity_rule 都还在表里，但它们的
-- mnemonic 全部进了 syslog_black_list，日志在 L2 就被丢了，到不了 L3。
-- 所以它们现在是死码 —— 查 alarm_log 永远查不到。
--
--   NTP_DROP          DAEMON-3-SYSTEM_MSG
--   DHCP_TIMEOUT      DHCP/5/WAITOFFER_TIMEOUT
--   CLOCK_CHG         SYSMIB/4/CLKCHANGE
--   IF_ATTR_CHG       ETHPORT-5-SPEED / IF_DUPLEX /
--                     IF_RX_FLOW_CONTROL / IF_TX_FLOW_CONTROL
--   CERT_EXPIRED      PKI/4/LOCAL_EXPIRED
--   BUFFER_THRESHOLD  被 scope=message 的 BUFFER_THRESHOLD_EXCEEDED 拦下。
--                     它那条 syslog_rule 是 fuzzy（mnemonic 为空），
--                     所以下面那条按 pattern 关联的自查 SQL 查不到它，
--                     要单独看：
--                     SELECT * FROM syslog_black_list
--                      WHERE scope='message'
--                        AND pattern='BUFFER_THRESHOLD_EXCEEDED';
--
-- 为什么留着不删：黑名单那一行就是开关。想重新看某一类，把
-- syslog_black_list 里对应的 pattern 改 enabled=0，L3 的规则和定级原样
-- 生效，立刻恢复识别 —— 不用重新配正则、重新核对现网正文。
-- 反过来，删掉规则就得从头配一遍，而配错正则是这套表最容易踩的坑
-- （DEV/1/FAN 那次就是 mnemonic 写错，白配一轮）。
--
-- 代价是查表的人会看到"有规则却没有数据"的事件码，所以写在这里。
-- 想确认某个事件码是不是死码：
--
-- SELECT r.event_code, r.mnemonic,
--        (SELECT b.enabled FROM syslog_black_list b
--          WHERE b.scope='mnemonic' AND b.pattern = r.mnemonic
--          LIMIT 1) AS 黑名单状态
--   FROM syslog_rule r
--  WHERE r.event_code = 'DHCP_TIMEOUT';
--
-- 黑名单状态=1 说明这条 mnemonic 被拦；一个事件码下所有 mnemonic 都是 1
-- 才是死码（IF_ATTR_CHG 要四条都看）。
-- ============================================================

-- ============================================================
-- 执行后自查：8 张表都在、种子数据条数对得上
--
-- SELECT table_name, table_rows FROM information_schema.tables
--  WHERE table_schema='netops'
--    AND table_name IN ('syslog_black_list','syslog_rule','syslog_event',
--                       'syslog_severity_rule','syslog_mute_rule',
--                       'syslog_alarm_state','alarm_list','alarm_log');
--
-- 种子数据应为：
--   syslog_black_list    20  （全部 enabled=1，没有停用示例了）
--   syslog_rule          49
--   syslog_event         31  （含 3 个兜底码 + IF_FLAP）
--   syslog_severity_rule 24  （其中 1 条 enabled=0 停用示例：BGP_UP）
--   syslog_mute_rule      3  （全部 enabled=0，不静默任何告警）
--   其余三张表是数据表，重建后为空
--
-- SELECT count(*) FROM syslog_black_list;      -- 20
-- SELECT count(*) FROM syslog_rule;            -- 49
-- SELECT count(*) FROM syslog_event;           -- 31
-- SELECT count(*) FROM syslog_severity_rule;   -- 24
-- SELECT count(*) FROM syslog_mute_rule;       -- 3
--
-- 黑名单里 17 条是 scope=mnemonic、3 条是 scope=message。
-- 其中 9 条 mnemonic + 1 条 message 对应的 syslog_rule 仍在表里但永不命中
-- （见上面"死码清单"）。这不是配置错误，是故意留的开关
-- SELECT count(*) FROM syslog_black_list WHERE enabled=1;   -- 20
--
-- scope=message 这 3 条每条日志都要线性扫，实测 3 条约 0.1us、
-- 剥一次 mnemonic 是 0.41us，所以现在这个量级可以忽略。
-- 这一串要保持小：100 条就是 3.4us（8 倍剥 mnemonic），
-- 能按 mnemonic 配的一律别放这里
-- SELECT pattern FROM syslog_black_list WHERE scope='message';
--
-- 全局兜底定级规则必须存在，少了它加载时会打 error：
-- SELECT * FROM syslog_severity_rule
--  WHERE event_code='*' AND ip_reg='' AND sysname_reg='';
--
-- 确认没有启用中的静默规则，应返回 0：
-- SELECT count(*) FROM syslog_mute_rule WHERE enabled=1;
-- ============================================================

-- ============================================================
-- 升级：ignore 命中的事件改为写 alarm_list（status=5）
--
-- 之前的行为：L5 定级规则 action=ignore 判定不告警时，L7 直接返回、
-- 不进状态机，L9 因为 notify=False 整个跳过——事件照常走 L6 写了
-- alarm_log，但 alarm_list 没有对应行，变成查不到的孤儿数据
-- （alarm_log 只留 7 天，7 天内想回看"这条口的 ignore 规则到底
-- 命中了几次"都没有入口）。
--
-- 改成和 mute 一样的思路：ignore 命中也按指纹聚合写 alarm_list，
-- 只是 state 固定是 idle（不开告警，没有"活跃"这回事）、status 固定
-- 是 5（系统规则判定忽略，和人工操作的 0~4 分开），L9 不推通知。
--
-- 不是表结构变更，是列注释和合法取值范围的变化，不需要 ALTER 加列。
-- 已经建过 alarm_list 的环境，想同步列注释（纯描述性，不影响功能）
-- 可以手工执行：
--
-- ALTER TABLE alarm_list
--     MODIFY COLUMN state VARCHAR(10) NOT NULL DEFAULT 'open'
--         COMMENT 'open=告警中 clear=已恢复 idle=ignore判定不告警，没有活跃状态',
--     MODIFY COLUMN status VARCHAR(1) NOT NULL DEFAULT '0'
--         COMMENT '处理状态 0待处理1已确认2已处理3忽略4屏蔽5系统判定忽略，5由L9写入非人工操作';
--
-- 不改注释也能跑——代码不读列注释，只是看着容易把 status=5 和
-- status=3（人工忽略）搞混。前端的处理状态下拉（current_alarm.vue
-- 的 statusOptions/typeOptions）要分开看：typeOptions 是人工处理表单
-- 可选值，不应该出现 5（人不该手动把一条告警标成"系统判定忽略"）；
-- statusOptions 是筛选条件，应该加上 5 才能按它筛出这类事件。
-- ============================================================
