-- ============================================================
-- 补丁：Cisco CERM-4-TX_BW_LIMIT 走 ignore，不进告警
--
-- 日志样例：
--   %CERM-4-TX_BW_LIMIT: Maximum Tx Bandwidth limit of 85000 Kbps reached
--   for Crypto functionality with securityk9 technology package license.
--
-- 这是加密吞吐撞上 securityk9 许可的 85Mbps 上限，属于容量项，
-- 不是端口/链路故障。但也不能配黑名单丢在 L2 —— 它本身有回溯价值：
-- 某天真出现 IPsec 会话建不起来时，要靠它定位什么时候开始饱和。
--
-- 所以走 L5 定级规则的 action='ignore'：照常解析、照常落 alarm_log、
-- 照常按事件码计数，只是不往 alarm_list 开告警。
--
-- 三步齐备才生效：ignore 挂在 event_code 上，而事件码只有规则表给了
-- 才会有。少写 syslog_rule 这一行的话，日志继续落 UNKNOWN_MNEMONIC，
-- 那条兜底规则是 ''（正常告警），照样开 P3。
--
--     mysql -h <host> -P <port> -u netops -p netops < sql/patch_20261112_crypto_bw_limit.sql
--
-- 可重复执行：三张表都是 INSERT IGNORE。
--   syslog_event 按 event_code 主键忽略；
--   syslog_severity_rule 按 (event_code, ip_reg, sysname_reg) 唯一键忽略；
--   syslog_rule 按 rule_id=34 忽略 —— 若 34 已被占用会跳过并提示，
--   此时去掉 rule_id 重跑一次即可（AUTO_INCREMENT 会分配新号）。
-- ============================================================
USE netops;

-- 1) 事件属性：stateless，窗口给长。
--    持续饱和时每 300s 切一段会产生大量碎窗口，3600s 更贴合"一次饱和事件"
INSERT IGNORE INTO syslog_event
    (event_code, state, object_type, window_sec, threshold, clear_code, descr)
VALUES
('CRYPTO_BW', 'stateless', 'none', 3600, 1, '',
 'Cisco加密功能吞吐撞上license带宽上限。容量问题走license审计，不进告警');


-- 2) 匹配规则：mnemonic 直接精确命中。
--    vendor 用 '*' —— 这条在 IOS / IOS-XE 上都见过，具体设备还没确认，
--    先不限厂商；命中后看 stats 里按 vendor 的分布再决定要不要收窄。
--    object_regex 留空：正文里没有需要区分的对象，整机一个指纹即可
INSERT IGNORE INTO syslog_rule
    (rule_id, vendor, mnemonic, match_type, pattern, body_match,
     event_code, object_regex, priority, descr)
VALUES
(34, '*', 'CERM-4-TX_BW_LIMIT', 'exact', '', '',
 'CRYPTO_BW', '', 100,
 'Maximum Tx Bandwidth limit of 85000 Kbps reached for Crypto functionality with securityk9 technology package license');


-- 3) 定级：不开告警。
--    severity 填 3 只是占位，action='ignore' 时级别不参与告警
INSERT IGNORE INTO syslog_severity_rule
    (event_code, ip_reg, sysname_reg, severity, action, priority, descr)
VALUES
('CRYPTO_BW', '', '', 3, 'ignore', 100,
 '加密吞吐撞license带宽上限，容量项非网络故障，不开告警');


-- 执行后自查：应各返回 1 行
--   select * from syslog_rule          where event_code='CRYPTO_BW';
--   select * from syslog_event         where event_code='CRYPTO_BW';
--   select * from syslog_severity_rule where event_code='CRYPTO_BW';
