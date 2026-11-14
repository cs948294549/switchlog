-- ============================================================
-- 补丁：IOS/IOS-XE 的 MAC 漂移归入 MAC_FLAP
--
-- 现网样例：
--   5980: May 23 01:38:57.755: %SW_MATM-4-MACFLAP_NOTIF: Host b64e.d188.8b37
--   in vlan 148 is flapping between port Po1 and port Gi1/0/18
--
-- 这是 IOS / IOS-XE 的 MAC 漂移写法，和已配的 NX-OS
-- L2FM-4-L2FM_MAC_MOVE2 是同一事件的另一套 mnemonic。
--
-- log_ignore.txt 里没有这条（SW_MATM / MACFLAP 都查不到），
-- 本次按"归 MAC_FLAP"处理 —— 不屏蔽，MAC 漂移是要看的。
--
--     mysql -h <host> -P <port> -u netops -p netops < sql/patch_20261113_sw_matm_macflap.sql
--
-- 和 schema.sql 的关系：内容已折进 schema.sql 的规则种子。
--   * 库是用 schema.sql 重建的 -> 不用执行本补丁
--   * 库里有数据要保留、不能重建 -> 执行本补丁
--
-- 只加 syslog_rule 一行。MAC_FLAP 的事件属性和定级都已存在，不用动：
--   syslog_event          stateless / object_type=mac / window 600 / threshold 3
--   syslog_severity_rule  corp=ignore(pri 10) / 测试网段 P3(pri 50) / 默认 P2(pri 100)
-- ============================================================
USE netops;

-- 正文结构和 NX-OS 那条不同，object_regex 不能共用：
--   NX-OS  'Mac e67b.0b15.973f in vlan 1080 has moved from Po43 to Po45'
--   IOS    'Host b64e.d188.8b37 in vlan 148 is flapping between port Po1 and port Gi1/0/18'
-- 一个 Mac 开头、一个 Host 开头。MAC 格式都是点分四位，
-- 抽出来是 b64e.d188.8b37，和 syslog_event 里 object_type=mac 对得上。
--
-- 用 'Host\s+' 锚定而不是裸 MAC 正则：裸正则会在正文里碰到别的点分
-- 十六进制串时抓错。这条正文后半截是 Po1 / Gi1/0/18，现在不含点分四位，
-- 但别的型号的正文格式不保证。
--
-- vendor 用 '*' 不收窄到 cisco_ios：SW_MATM 在 IOS / IOS-XE / 部分
-- Catalyst 上都见过，而这条样例的源 IP 还没确认到具体设备
-- （日志里只有序号和时间戳，没带 hostname）。
-- 命中后看按 vendor 的分布再决定要不要收窄。
INSERT IGNORE INTO syslog_rule
    (vendor, mnemonic, match_type, pattern, body_match,
     event_code, object_regex, priority, descr)
VALUES
('*', 'SW_MATM-4-MACFLAP_NOTIF', 'exact', '', '',
 'MAC_FLAP', 'Host\\s+([0-9a-fA-F]{4}\\.[0-9a-fA-F]{4}\\.[0-9a-fA-F]{4})', 100,
 'Host b64e.d188.8b37 in vlan 148 is flapping between port Po1 and port Gi1/0/18');


-- 执行后自查
--
-- 1) MAC_FLAP 现在应有 3 条规则（NX-OS / IOS / 华为）
-- SELECT rule_id, vendor, mnemonic, object_regex FROM syslog_rule
--  WHERE event_code='MAC_FLAP' ORDER BY vendor, mnemonic;
--
-- 2) 确认没被黑名单挡住，应返回 0 行
-- SELECT r.mnemonic FROM syslog_rule r
--   JOIN syslog_black_list b ON b.scope='mnemonic' AND b.pattern=r.mnemonic
--  WHERE r.mnemonic='SW_MATM-4-MACFLAP_NOTIF' AND b.enabled=1;
--
-- 3) 规则由 L3 定时刷新，默认 300 秒一轮，等一轮或重启进程
--
-- 4) 跑一轮后确认对象抽出来是 MAC 不是 '-'
-- SELECT alarm_object, count(*) c FROM alarm_log
--  WHERE mnemonic='SW_MATM-4-MACFLAP_NOTIF' GROUP BY alarm_object ORDER BY c DESC;
--    出现大量 '-' 说明正则对不上现网正文，拿样例改 object_regex（用 UPDATE）
--
-- 5) 定级提醒：threshold=3，同指纹 10 分钟内 3 次才告警（兼做降噪，
--    虚机迁移造成的偶发单次不报）。职场设备（sysname 含 corp）是 ignore，
--    机房默认 P2。样例里 vlan 148 在 Po1 和 Gi1/0/18 之间漂 ——
--    Po1 是聚合口、Gi1/0/18 是物理口，这种组合通常是：
--      * 某台服务器双网卡一边接聚合一边接单口（配置错误）
--      * 或者下游有环路把流量绕回来了
--    真报出来建议查一下 Gi1/0/18 接的是什么。
