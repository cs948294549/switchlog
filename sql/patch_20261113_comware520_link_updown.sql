-- ============================================================
-- 补丁：Comware 5.20 的端口 up/down（第三套 LINK_UPDOWN 写法）
--
-- 现网样例（10.39.240.71，oob1_mdu30_prod_dc07_m01，
-- H3C S5120-52SC-HI / Comware 5.20 Release 5206）：
--
--   %%10IFNET/3/LINK_UPDOWN(l): -DevIP=10.39.240.71;
--   GigabitEthernet1/0/41 link status is UP.
--
--   %%10IFNET/4/INTERFACE UPDOWN(t): -DevIP=10.39.240.71;
--   Trap 1.3.6.1.6.3.1.1.5.4<linkUp>: Interface 9437224 is Up,
--   ifAdminStatus is 1, ifOperStatus is 1
--
-- 做两件事：
--   1. IFNET/3/LINK_UPDOWN 加两条规则（down/up），走 IF_DOWN / IF_UP
--   2. IFNET/4/INTERFACE 拉黑（理由见下）
--
-- log_ignore.txt 里这两条都没有，是新出现的。
--
--     mysql -h <host> -P <port> -u netops -p netops < sql/patch_20261113_comware520_link_updown.sql
--
-- 和 schema.sql 的关系：内容已折进 schema.sql。
--   * 库是用 schema.sql 重建的 -> 不用执行本补丁
--   * 库里有数据要保留、不能重建 -> 执行本补丁
-- ============================================================
USE netops;

-- ============================================================
-- 1) IFNET/3/LINK_UPDOWN：两条规则
--
-- 这是 h3c 的第三套端口 up/down 写法。三套并存，互不通用：
--   Comware 7.1  IFNET/5/LINK_UPDOWN
--                'Line protocol state on the interface X changed to up.'
--   Comware 7.1  IFNET/3/PHY_UPDOWN
--                'Physical state on the interface X changed to up.'
--   Comware 5.20 IFNET/3/LINK_UPDOWN     <- 本次
--                'GigabitEthernet1/0/41 link status is UP.'
--
-- 严重度数字不同就是两个 mnemonic（IFNET/5 和 IFNET/3），dict 查不到彼此，
-- 必须各配一套。正文也完全不同，object_regex 和 body_match 都不能共用 ——
-- 这条的接口名在正文开头、后面跟 'link status is'，不是
-- 'on the interface X changed' 那种结构。
--
-- object_regex / body_match 都对现网正文逐字核对过：
--   '(\S+) link status is' 抽出 'GigabitEthernet1/0/41'
--   'link status is DOWN' / 'link status is UP' 分别命中两种正文
-- ============================================================
INSERT IGNORE INTO syslog_rule
    (vendor, mnemonic, match_type, pattern, body_match,
     event_code, object_regex, priority, descr)
VALUES
('h3c', 'IFNET/3/LINK_UPDOWN', 'exact', '', 'link status is DOWN',
 'IF_DOWN', '(\\S+) link status is', 100,
 'GigabitEthernet1/0/41 link status is DOWN.（现网样本，S5120-52SC-HI/Comware 5.20）'),
('h3c', 'IFNET/3/LINK_UPDOWN', 'exact', '', 'link status is UP',
 'IF_UP', '(\\S+) link status is', 100,
 'GigabitEthernet1/0/41 link status is UP.（现网样本，S5120-52SC-HI/Comware 5.20）');


-- ============================================================
-- 2) IFNET/4/INTERFACE：拉黑
--
-- 它和上面那条是同一次端口翻动的两条日志（时间戳完全相同），
-- 但抽出来的对象不一样：
--   trap  'Interface 9437224 is Up'        -> ifIndex 9437224
--   日志  'GigabitEthernet1/0/41 link ...'  -> GigabitEthernet1/0/41
--
-- 对象不同 -> 指纹不同 -> 一次 down 会开两条告警。按 schema 一贯的收敛
-- 原则（DEVM/IFNET 那对、DEV/1/FAN + DEV/4/FAN 那对都归一个指纹），
-- 这里只能留一条。
--
-- 留日志、拦 trap：ifIndex 对人没用 —— 看板上显示 9437224，没人认得出
-- 是哪个口，还得登设备查 ifIndex 映射；日志那条直接带可读接口名。
--
-- mnemonic 只能填到 'IFNET/4/INTERFACE'：strip_mnemonic 的正则在斜杠
-- 最后一段碰到空格就截断，'IFNET/4/INTERFACE UPDOWN' 实际剥出来是
-- 'IFNET/4/INTERFACE'（和 DEV/1/FAN 栽的是同一个坑，那次照手册写全名，
-- 配了一直不命中）。已对现网报文验证过剥出来就是这个值。
-- ============================================================
INSERT IGNORE INTO syslog_black_list
    (pattern, scope, ip, ignore_case, enabled, descr)
VALUES
('IFNET/4/INTERFACE', 'mnemonic', '', 0, 1,
 'Comware5.20端口翻动trap，对象是ifIndex不可读。同一次翻动的IFNET/3/LINK_UPDOWN带接口名，留那条');


-- ============================================================
-- 执行后自查
-- ============================================================
-- 1) 两条规则都在
-- SELECT rule_id, mnemonic, body_match, event_code, object_regex
--   FROM syslog_rule WHERE mnemonic='IFNET/3/LINK_UPDOWN';   -- 应 2 行
--
-- 2) trap 已拉黑
-- SELECT rule_id, pattern, enabled FROM syslog_black_list
--  WHERE pattern='IFNET/4/INTERFACE';                        -- 应 1 行
--
-- 3) h3c 现在有三套端口 up/down 写法，确认互不冲突
-- SELECT mnemonic, body_match, event_code FROM syslog_rule
--  WHERE vendor='h3c' AND mnemonic LIKE 'IFNET/%' ORDER BY mnemonic, body_match;
--    期望 6 行：IFNET/3/LINK_UPDOWN、IFNET/3/PHY_UPDOWN、IFNET/5/LINK_UPDOWN
--    各一对 down/up
--
-- 4) 两层都要刷新：规则在 L3、黑名单在 L2，间隔都是 300 秒。
--    等一轮或重启进程
--
-- 5) 跑一轮后确认一次翻动只出一条告警（不是两条）
-- SELECT alarm_id, keyword, alarm_object, counter, first_seen
--   FROM alarm_list WHERE ip='10.39.240.71' ORDER BY alarm_id DESC LIMIT 5;
--    alarm_object 应该是 GigabitEthernet1/0/41，不该出现 9437224
--
-- ============================================================
-- 另外：这个口在闪
--
-- 样例里 40 秒内翻了 4 次：
--   16:16:45 UP -> 16:17:04 DOWN -> 16:17:06 UP -> 16:17:24 DOWN
--
-- 规则生效后 L7 会按闪断处理：同指纹 30 分钟内 3 次新开告警就升级成
-- IF_FLAP，级别提一档且禁止自动恢复（要人工确认）。IF_FLAP 的定级是
-- P1（syslog_severity_rule 里有专门行），所以这个口会炸出一条 P1。
--
-- 这台是机房 oob 设备（oob1_mdu30_prod_dc07_m01），不在 corp 的 ignore
-- 范围内，所以告警会真发出来。GE1/0/41 接的是什么、为什么闪，
-- 建议先看一眼：
--   display interface GigabitEthernet1/0/41
-- 光模块/网线/对端重启都可能，CRC 在涨就是物理层。
-- 割接或已知在动的话，先用 syslog_mute_rule 盖住：
--   INSERT INTO syslog_mute_rule(ip_reg, event_code_reg, object_reg,
--                                start_time, end_time, enabled, descr)
--   VALUES('^10[.]39[.]240[.]71$', '^(IF_DOWN|IF_UP|IF_FLAP)$',
--          '^GigabitEthernet1/0/41$', '<开始epoch>', '<结束epoch>', 1,
--          'GE1/0/41 闪断处理中，工单 CHG-xxx');
--   注意 event_code_reg 要带上 IF_FLAP，否则升级出来的那条 P1 会漏出来。
