-- ============================================================
-- 补丁：补齐现网 UNKNOWN_MNEMONIC 缺口（PoE / 风扇 / 杂项）
--
-- 来源：logs/raw_packets.log 20 分钟样本里剥出的未命中 mnemonic，
-- 按 (vendor, mnemonic) 分组计数从高到低补。每条的 object_regex 和
-- body_match 都对着样本正文逐字核对过，不按厂商手册臆造 ——
-- 上一轮 DEV/1/FAN 就是照手册写法配的，mnemonic 剥出来对不上，白配一轮。
--
--     mysql -h <host> -P <port> -u netops -p netops < sql/patch_20261113_poe_fan_misc.sql
--
-- 和 schema.sql 的关系：本补丁的内容已经折进 schema.sql 的种子数据。
--   * 库是用 schema.sql 重建的（先删再建）-> 本补丁不用执行，已经在里面了
--   * 库里有要保留的数据、不能重建 -> 执行本补丁，只增不删
-- 两个都执行也没问题，五张表都靠唯一键去重，不会插出第二份。
--
-- 本补丁覆盖的 5 张表：
--   syslog_black_list    2 条，PoE 功率回显，纯噪声，L2 直接丢
--   syslog_rule         13 条，11 条按 mnemonic + 2 条 fuzzy
--   syslog_event         9 条新事件码
--   syslog_severity_rule 9 条定级，5 个 ignore + 4 个正常告警
--   syslog_mute_rule     3 条，全部 enabled=0（理由见该节注释）
--
-- 可重复执行：五张表都靠唯一键 INSERT IGNORE 去重。syslog_rule 原来
-- 没有唯一键，靠显式 rule_id 去重，本补丁第 0 步把唯一键建起来，
-- 之后所有规则都不带 rule_id 写，交给 AUTO_INCREMENT。
-- ============================================================
USE netops;

-- ============================================================
-- 0) syslog_rule 补唯一键
--
-- 原来的去重靠显式 rule_id：INSERT IGNORE 撞主键才跳过。这个办法有两个
-- 毛病 —— 补丁之间要人工对号（34 号被占了就得翻文件找下一个空号），
-- 而且同一条规则换个号就能重复插进去，表里出现两行判据完全一样的规则。
--
-- 改成按"匹配身份"去重：(vendor, mnemonic, match_type, pattern, body_match)
-- 这五列相同就是同一条规则，无论 rule_id 是几。之后插规则不带 rule_id。
--
-- event_code 不进唯一键：一个事件码天然对应多行（多厂商、多 mnemonic），
-- 这一点和原注释一致。object_regex / priority / descr 也不进 ——
-- 它们是同一条规则的属性，改正则不该算成一条新规则（否则改一次正则
-- 就多一行，旧行还在生效）。
--
-- 索引长度：30+80+10+300+200 = 620 字符 × 4 字节(utf8mb4) = 2480 字节，
-- 在 InnoDB DYNAMIC 行格式的 3072 字节上限内，不用加前缀长度。
--
-- 建键之前先确认表里没有重复行，有的话 ADD UNIQUE KEY 会直接失败：
--
--   SELECT vendor, mnemonic, match_type, pattern, body_match, count(*) c,
--          group_concat(rule_id) ids
--   FROM syslog_rule
--   GROUP BY 1,2,3,4,5 HAVING c > 1;
--
-- 查出来的按 ids 保留最小那个、删掉其余，再执行下面这句。
-- 重复执行本补丁时这一句会报 Duplicate key name 'uniq_match'，
-- 属预期，忽略即可，后面的 INSERT 不受影响。
-- ============================================================
ALTER TABLE syslog_rule
    ADD UNIQUE KEY uniq_match (vendor, mnemonic, match_type, pattern, body_match);


-- ============================================================
-- 1) 事件属性：9 个新事件码
--
-- 全部 stateless。没给 raise/clear 配对是因为这批日志里没有一个有
-- 可靠的恢复日志 —— PoE 的 PD 插拔、风扇低转速、证书过期都只打一个方向，
-- 配成 raise 会开出永远关不掉的告警（DEV/4/FAN 那条尤其明显：
-- 20 分钟刷 30 条，一旦 raise 就是一条挂死的 P2）。
--
-- 窗口按日志自身的重复节奏给，不统一用 300s：
--   PoE 插拔 600s   办公网一个工位早上插拔几次很正常
--   风扇/缓存 3600s 设备每 5 分钟重打一次，300s 会切出一堆碎窗口
--   证书过期 86400s 每天提醒一次就够，这事按天算不按秒算
-- ============================================================
INSERT IGNORE INTO syslog_event
    (event_code, state, object_type, window_sec, threshold, clear_code, descr)
VALUES
-- PoE：PD 插拔。connect/disconnect 归一个码，对象是接口。
-- 不拆成两个码的理由同 LAG_MEMBER_CHG —— 有人插拔终端不是故障，
-- 分开配两个码只是把同一件事记两遍，定级还要配两行
('POE_PD_CHG',        'stateless', 'interface', 600,   1, '',
 'PoE终端插拔。办公网日常行为，定级配ignore不告警，留日志用于回溯AP/话机什么时候掉的'),
-- 风扇低转速：和 PSU_FAIL 分开。PSU_FAIL 配了 clear_code=PSU_OK，
-- 而思科这条没有对应的恢复日志，混进去会让 PSU_FAIL 的恢复配对出错
('FAN_LOW_RPM',       'stateless', 'slot',      3600,  1, '',
 '风扇转速过低，其余风扇已升速补偿。厂商建议换风扇模块，是备件工单不是故障告警'),
-- MAC 漂移触发的端口限速。和 MAC_FLAP 分开：那个码的 object_type 是 mac，
-- 这条的对象是被限速的接口，塞进同一个码会让指纹的对象类型不一致
('MAC_FLAP_SUPPRESS', 'stateless', 'interface', 600,   1, '',
 'MAC漂移导致未知单播被限速到端口带宽50%。已经在影响业务转发，比单纯的MAC_FLAP要紧'),
('MAC_FLAP_RECOVER',  'stateless', 'none',      600,   1, '',
 'MAC漂移检测恢复。MAC_FLAP是stateless、静默即恢复，这条只用于回溯环路什么时候消的'),
-- Nexus 缓存池告警。9 台 rsw 一起刷，是微突发的征兆
('BUFFER_THRESHOLD',  'stateless', 'slot',      3600,  1, '',
 'Nexus缓存池超90%水线。微突发征兆，容量项走容量审计，不进告警'),
-- 交换机自己做 DHCP 客户端要不到地址，管理口可能上不来
('DHCP_TIMEOUT',      'stateless', 'interface', 600,   1, '',
 '设备自身DHCP客户端超时拿不到地址，管理面可能失联'),
('CERT_EXPIRED',      'stateless', 'none',      86400, 1, '',
 '设备本地证书已过期，影响HTTPS管理/802.1X，按天提醒'),
('CLOCK_CHG',         'stateless', 'none',      3600,  1, '',
 '系统时钟变更。NTP对时的正常结果，定级配ignore'),
('NTP_DROP',          'stateless', 'none',      3600,  1, '',
 'NTP丢弃私有模式报文，公网扫描打上来的。安全侧信息，不是网络故障');


-- ============================================================
-- 2) 匹配规则：11 条按 mnemonic
--
-- 不带 rule_id，靠第 0 步的 uniq_match 去重。
-- descr 一律抄样本正文原文，下次改正则时能直接对着核。
--
-- vendor 全部查过 devices 表确认，不猜：
--   huawei     172.26.1.34 / 172.25.1.x  CloudEngine S5735-S-V2(V600R023) 与 S5720(V200R011)
--   h3c        10.39.240.32/33           S5120-24P-EI(Comware 5.20)
--   cisco_ios  172.21.32.14              CISCO3945 15.4(3)M6a
--   cisco_nx   10.39.224.12              N9K-C93180YC-EX 7.0(3)I7(3)
--
-- object_regex 统一用 Interface=([^,)]+)：华为这批日志的对象都在括号内的
-- key=value 里，字符类排掉逗号和右括号就能同时吃下
-- "(Interface=GE1/0/48)" 和 "(IfIndex=48, Interface=GE1/0/48)" 两种正文。
-- 注意不能写成 ([^)]+) —— 后者会把 "48, Interface=GE1/0/48" 整段抓进来。
-- ============================================================
INSERT IGNORE INTO syslog_rule
    (vendor, mnemonic, match_type, pattern, body_match,
     event_code, object_regex, priority, descr)
VALUES
-- PoE 的 PD 插拔：syslog 和 trap 各打一条，归同一个事件码、抽同一个对象，
-- 所以落同一个指纹，一次插拔只出一条记录（和 DEVM/IFNET 那对是同一个套路）
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
-- H3C 风扇故障的第二套 mnemonic。DEV/1/FAN 是 trap(hh3cfanfailure)、
-- DEV/4/FAN 是日志，同一次故障两条一起打，抽出的 fan ID 相同 -> 同一指纹。
-- mnemonic 只能填到 DEV/4/FAN：strip_mnemonic 在斜杠最后一段碰空格就截断，
-- "DEV/4/FAN FAILED" 实际剥出来是 "DEV/4/FAN"，靠 body_match 认 FAILED。
-- 现网样本已核对，'FAN FAILED' 逐字出现在 30/30 条正文里
('h3c', 'DEV/4/FAN', 'exact', '', 'FAN FAILED',
 'PSU_FAIL', 'Fan\\s+(\\d+)\\s+failed', 100,
 '%%10DEV/4/FAN FAILED(l):-DevIP=10.39.240.33;   Fan 1 failed.'),
-- 思科风扇低转速。单独一个事件码，不并进 PSU_FAIL：没有恢复日志，
-- 并进去会让 PSU_FAIL->PSU_OK 的配对关不掉这一条
('cisco_ios', 'ENVMON-4-ONE_FAN_LOW_RPM', 'exact', '', '',
 'FAN_LOW_RPM', 'Fan\\s+(\\d+)', 100,
 'Warning: Fan 4 is running at low RPM. Rotation speed is now high for all other fans.'),
-- 华为 MAC 漂移限速。对象是被限速的接口，不是 MAC
('huawei', 'SECE/4/UCSUPPRESS', 'exact', '', '',
 'MAC_FLAP_SUPPRESS', 'Interface=([^,)]+)', 100,
 'MAC address flapping started on port. The rate of unknown unicast packets was limited to 50% of the port bandwidth.(Interface=GigabitEthernet0/0/36)'),
-- 设备自身 DHCP 客户端超时。对象取 Vlanif，正文里的键名是 InterfaceName
('huawei', 'DHCP/5/WAITOFFER_TIMEOUT', 'exact', '', '',
 'DHCP_TIMEOUT', 'InterfaceName=([^,)]+)', 100,
 'The DHCP server did not respond within the specified period. (Client InterfaceName=Vlanif1, CurrentState=Init, ...)'),
('huawei', 'PKI/4/LOCAL_EXPIRED', 'exact', '', '',
 'CERT_EXPIRED', '', 100,
 'LOCAL certificate (/OU=.../CN=S5720_device.pem) has expired for 71 days.'),
('h3c', 'SYSMIB/4/CLKCHANGE', 'exact', '', '',
 'CLOCK_CHG', '', 100,
 '<hh3cSysClockChangedNotification> System clock changed'),
-- DAEMON-3-SYSTEM_MSG 是个大杂烩 mnemonic，各种守护进程都往里打。
-- 只认 NTP 丢包这一种正文，body_match 把范围卡死 —— 不配 body_match 的话
-- 这条会把所有 SYSTEM_MSG 都吞成 NTP_DROP，其余内容就从缺口清单里消失了。
-- 其他 SYSTEM_MSG 继续落 UNKNOWN_MNEMONIC，等出现了再按正文分别补行
('cisco_nx', 'DAEMON-3-SYSTEM_MSG', 'exact', '', 'NTP Receive dropping message',
 'NTP_DROP', '', 100,
 'NTP Receive dropping message: Received NTP private mode packet from 35.210.65.179. Drop count: 44330 - ntpd[29273]');


-- ============================================================
-- 3) 匹配规则：2 条 fuzzy（mnemonic 留空）
--
-- 这两条不得不走 fuzzy —— 它们的 header 格式 strip_mnemonic 剥不出来，
-- mnemonic 是空串，按 mnemonic 配的规则永远不会被查到：
--
--   %TAHUSD-SLOT1-4-BUFFER_THRESHOLD_EXCEEDED
--     正则 #1 要求 FAC-SEV-MNEMONIC 里 FAC 段是 [A-Za-z][A-Za-z0-9_]*，
--     "TAHUSD-SLOT1" 中间那个中划线不在字符类里，整条匹配不上；
--     正则 #2 要斜杠，这条没有。剥出来是空串
--
--   %%01FWM-ETH/4/hwMflpVlanLoopAlarm_clear
--     正则 #2 的模块段同样不收中划线，"FWM-ETH" 过不去。剥出来是空串
--
-- 本来该改 l1_prepare 的正则把中划线收进去，但那是改全量报文的热路径，
-- 两条正则一动所有日志的 mnemonic 都可能变，现有 34 条规则得全部重核。
-- 先用 fuzzy 接住，等有一轮完整回归再动 L1。
--
-- fuzzy 的代价可控：index.fuzzy_candidates 只在 mnemonic 为空时才跑，
-- 现网样本里 38/660 条无 mnemonic（5.8%），其中 10 条是 "last message
-- repeated"，已被 L2 黑名单在更前面拦掉。真正走到这里的是 28 条。
--
-- priority 给 300，和现有两条 fuzzy（authentication failure / Configured
-- from vty）同级。四条互不重叠，已对着现网样本核过：BUFFER_THRESHOLD_EXCEEDED
-- 命中 27 条、hwMflpVlanLoopAlarm_clear 命中 1 条，两条新规则都没有误命中
-- 另外两条的正文，反之亦然。
--
-- 用 contains 不用 regex：两个 pattern 都是定长字符串，str.find 比正则快，
-- 而且不用担心转义写错。
-- ============================================================
INSERT IGNORE INTO syslog_rule
    (vendor, mnemonic, match_type, pattern, body_match,
     event_code, object_regex, priority, descr)
VALUES
-- 对象抽模块号。9 台 rsw 都在刷，带上模块号便于看是不是集中在某块板卡
('cisco_nx', '', 'contains', 'BUFFER_THRESHOLD_EXCEEDED', '',
 'BUFFER_THRESHOLD', 'Module\\s+(\\d+)', 300,
 '%TAHUSD-SLOT1-4-BUFFER_THRESHOLD_EXCEEDED: Module 1 Instance 0 Pool-group buffer 90 percent threshold is exceeded!（mnemonic剥不出，FAC段含中划线）'),
('huawei', '', 'contains', 'hwMflpVlanLoopAlarm_clear', '',
 'MAC_FLAP_RECOVER', '', 300,
 '%%01FWM-ETH/4/hwMflpVlanLoopAlarm_clear(l):...;Mac flapping detection recovered in vlan 136.（mnemonic剥不出，模块段含中划线）');


-- ============================================================
-- 4) 事件定级：9 条
--
-- 5 个 ignore + 4 个正常告警。
--
-- 为什么宁可配 ignore 也不配黑名单：这几个码的日志本身有回溯价值
-- （和 CRYPTO_BW 一个判断）。PoE 插拔用来回答"这个 AP 是什么时候掉的"，
-- 缓存水线用来回答"丢包投诉那天缓存撞没撞顶"。配黑名单在 L2 丢掉，
-- 这些问题以后就查不了了。ignore 的日志照样落 alarm_log、照样进 ES，
-- 只是不往 alarm_list 开告警。
--
-- 真正毫无价值的才配黑名单 —— 本补丁第 5 步那两条 PoE 功率回显，
-- 几秒刷一次、数值还在变，留着也没人看。
--
-- 四条正常告警里没有 P1：这批都不是"业务已经断了"的事件。
-- FAN_LOW_RPM / BUFFER_THRESHOLD 是备件和容量，MAC_FLAP_SUPPRESS 是
-- 已经在影响转发所以给 P2，DHCP_TIMEOUT 给 P3 —— 它只影响设备自己的
-- 管理地址，真失联了轮询监控会先报。
-- ============================================================
INSERT IGNORE INTO syslog_severity_rule
    (event_code, ip_reg, sysname_reg, severity, action, priority, descr)
VALUES
-- ignore 五条。severity 填 3 只是占位，action=ignore 时级别不参与告警
('POE_PD_CHG',        '', '', 3, 'ignore', 100,
 'PoE终端插拔是办公网日常行为，不告警。留日志回溯AP/话机掉线时间'),
('BUFFER_THRESHOLD',  '', '', 3, 'ignore', 100,
 'Nexus缓存水线属容量项，走容量审计不进告警。留日志用于回溯丢包投诉'),
('MAC_FLAP_RECOVER',  '', '', 3, 'ignore', 100,
 '恢复类日志，MAC_FLAP本身是stateless静默即恢复，不需要告警'),
('CLOCK_CHG',         '', '', 3, 'ignore', 100,
 'NTP对时的正常结果，不告警'),
('NTP_DROP',          '', '', 3, 'ignore', 100,
 '公网NTP扫描，安全侧信息非网络故障，不告警'),
-- 正常告警四条
('MAC_FLAP_SUPPRESS', '', '', 2, '',       100,
 '端口已被限速到50%带宽，已在影响业务转发，比单纯MAC_FLAP要紧'),
('FAN_LOW_RPM',       '', '', 3, '',       100,
 '风扇待更换，是备件工单。给P3不给P2：其余风扇已升速补偿，不会立即过温'),
('DHCP_TIMEOUT',      '', '', 3, '',       100,
 '设备自身管理地址拿不到。真失联轮询监控会先报，这条只用于定位原因'),
('CERT_EXPIRED',      '', '', 3, '',       100,
 '证书已过期，影响HTTPS管理/802.1X。按天提醒，不是紧急故障');


-- ============================================================
-- 5) L2 黑名单：2 条 PoE 功率回显
--
-- 这两条是本补丁里唯一配黑名单的 —— 几秒刷一次、每次数值都不一样
-- （Power=2400 / 1100 / 3100），既不是故障也没有回溯价值，
-- 解析它纯属浪费。20 分钟样本里 58 条，是未命中里量最大的一类。
--
-- 两个 mnemonic 是同一件事在两个版本上的不同写法，都要配：
--   POE/6/PORTPWR  V600R023（CloudEngine S5735）括号里 key=value
--   POE/6/PORTPW   V200R011（S5720 老 VRP）无括号，纯文字
-- 少一个字母，配漏了那台 S5720 会继续落 UNKNOWN_MNEMONIC。
--
-- scope 用 mnemonic 不用 message：走 dict O(1) 命中，不参与全量扫串。
-- ip 留空（所有设备）—— 这是日志类型本身的问题，不是某台设备的问题。
-- ============================================================
INSERT IGNORE INTO syslog_black_list
    (pattern, scope, ip, ignore_case, enabled, descr)
VALUES
('POE/6/PORTPWR', 'mnemonic', '', 0, 1,
 'PoE端口功率周期回显(V600R023)，几秒一条且数值每次都变，无告警与回溯价值'),
('POE/6/PORTPW',  'mnemonic', '', 0, 1,
 'PoE端口功率周期回显(V200R011老VRP写法，少个R)，同上');


-- ============================================================
-- 6) L8 静默规则：3 条，全部 enabled=0
--
-- **三条都是停用状态，执行本补丁不会静默任何告警。**
--
-- 为什么不敢给一条 enabled=1：静默规则压的是"该发但不发"的通知，
-- 配错的代价是真故障没人知道，而且表里看起来一切正常。开窗口这件事
-- 必须和一个具体的变更/工单对应，不该由一个建表补丁顺手开出来。
-- schema.sql 原来把这节写成注释（"默认不插入，按需手工执行"）就是这个考虑。
--
-- 改成 enabled=0 的真实行而不是继续留注释，是为了两件事：
--   1. 加载逻辑能被验证 —— 和 syslog_severity_rule 里那条 BGP_UP 停用示例
--      一个用途，确认 enabled 过滤真的在生效
--   2. 要用的时候是 UPDATE 一行、填两个时间戳，不是从注释里拷一段 SQL
--      再自己拼字段。割接前手忙脚乱的时候，少一步拼写就少一个出错的地方
--
-- 启用方式（填真实 epoch 和工单号，date -d 算时间戳）：
--   UPDATE syslog_mute_rule SET enabled=1,
--          start_time='1763000000', end_time='1763007200',
--          descr='...工单 CHG-xxx'
--    WHERE rule_id=?;
--
-- syslog_mute_rule 没有唯一键（同样的判据配不同时间窗是合理的），
-- 所以这里用 WHERE NOT EXISTS 按 descr 去重，而不是 INSERT IGNORE ——
-- 后者在没有唯一键的表上不去重，重复执行会插出三份。
-- ============================================================

-- 6.1) 整机静默模板。本补丁里 PSU_FAIL 的两台 oob 就是典型场景：
--      10.39.240.32/33 在 20 分钟样本里各刷了 30 条 FAN 日志，
--      而 PSU_FAIL 是 raise、threshold=1，一来就开 P2，并且
--      syslog_rule 里只配了 FAILURE 没配恢复（现网还没拿到恢复日志样例），
--      这条告警开了就关不掉。
--      等风扇模块备件到货、确认了 RMA 工单号再把 ip_reg 填上并启用 ——
--      现在不启用是因为我不知道备件什么时候到，写个假窗口比不写更糟
INSERT INTO syslog_mute_rule
    (ip_reg, event_code_reg, object_reg, start_time, end_time, enabled, descr)
SELECT '^10[.]39[.]240[.](32|33)$', '^(PSU_FAIL|FAN_LOW_RPM)$', '', '', '', 0,
       '模板-整机静默：dc07 oob 风扇待换件期间屏蔽，启用前填 start/end 与 RMA 工单号'
  FROM DUAL
 WHERE NOT EXISTS (SELECT 1 FROM syslog_mute_rule
                    WHERE descr LIKE '模板-整机静默%');

-- 6.2) 单接口静默模板。换光模块这类只动一个口的变更用这条，
--      别拿 6.1 把整机盖住 —— 同一台设备上别的口真 down 了还得报
INSERT INTO syslog_mute_rule
    (ip_reg, event_code_reg, object_reg, start_time, end_time, enabled, descr)
SELECT '^10[.]16[.]249[.]5$', '^(IF_DOWN|IF_UP|IF_FLAP)$', '^Ethernet1/6$', '', '', 0,
       '模板-单口静默：换光模块/改配线只动一个接口时用，启用前填 ip/object/时间窗与工单号'
  FROM DUAL
 WHERE NOT EXISTS (SELECT 1 FROM syslog_mute_rule
                    WHERE descr LIKE '模板-单口静默%');

-- 6.3) 整机房静默模板。event_code_reg 故意留空（不限事件码）：
--      断电演练期间什么都会响，而且留空自动盖住 IF_FLAP ——
--      只写 ^IF_DOWN$ 的话，窗口内连续 3 次 raise 升出来的那条 P1 会漏出来
INSERT INTO syslog_mute_rule
    (ip_reg, event_code_reg, object_reg, start_time, end_time, enabled, descr)
SELECT '^10[.]19[.]19[.]', '', '', '', '', 0,
       '模板-机房静默：断电演练/整机房割接用，event_code_reg留空以一并盖住IF_FLAP'
  FROM DUAL
 WHERE NOT EXISTS (SELECT 1 FROM syslog_mute_rule
                    WHERE descr LIKE '模板-机房静默%');


-- ============================================================
-- 执行后自查
-- ============================================================
-- 1) 五张表的新增条数，应为 9 / 13 / 9 / 2 / 3
-- SELECT count(*) FROM syslog_event WHERE event_code IN
--   ('POE_PD_CHG','FAN_LOW_RPM','MAC_FLAP_SUPPRESS','MAC_FLAP_RECOVER',
--    'BUFFER_THRESHOLD','DHCP_TIMEOUT','CERT_EXPIRED','CLOCK_CHG','NTP_DROP');
-- SELECT count(*) FROM syslog_rule WHERE event_code IN
--   ('POE_PD_CHG','FAN_LOW_RPM','MAC_FLAP_SUPPRESS','MAC_FLAP_RECOVER',
--    'BUFFER_THRESHOLD','DHCP_TIMEOUT','CERT_EXPIRED','CLOCK_CHG','NTP_DROP')
--    OR (mnemonic='DEV/4/FAN');
-- SELECT count(*) FROM syslog_black_list WHERE pattern LIKE 'POE/6/PORTPW%';
-- SELECT count(*) FROM syslog_mute_rule  WHERE descr LIKE '模板-%';
--
-- 2) 每个新事件码都必须既有匹配规则又有定级规则，缺一不生效。
--    这条查出来的行就是配漏了的：
-- SELECT e.event_code,
--        (SELECT count(*) FROM syslog_rule r WHERE r.event_code=e.event_code) AS 规则数,
--        (SELECT count(*) FROM syslog_severity_rule s
--          WHERE s.event_code=e.event_code) AS 定级数
--   FROM syslog_event e
--  WHERE e.event_code IN
--        ('POE_PD_CHG','FAN_LOW_RPM','MAC_FLAP_SUPPRESS','MAC_FLAP_RECOVER',
--         'BUFFER_THRESHOLD','DHCP_TIMEOUT','CERT_EXPIRED','CLOCK_CHG','NTP_DROP')
--    AND (规则数=0 OR 定级数=0);
--
-- 3) 确认 3 条静默规则都是停用的，应返回 0
-- SELECT count(*) FROM syslog_mute_rule WHERE descr LIKE '模板-%' AND enabled=1;
--
-- 4) 跑一轮之后看缺口清单，PoE/风扇那几类应该消失：
-- SELECT vendor, mnemonic, count(*) c FROM <日志归档>
--  WHERE event_code='UNKNOWN_MNEMONIC' GROUP BY 1,2 ORDER BY c DESC;
