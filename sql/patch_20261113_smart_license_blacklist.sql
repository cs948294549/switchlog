-- ============================================================
-- 补丁：屏蔽 Smart Licensing 两条日志
--
-- 现网样例：
--   %LICMGR-6-LOG_LICAPP_SMART_GLOBAL_CHANGE: A global notification change
--   of type 11 is sent out for Application(s)when Smart licensing is used.
--   (message repeated 4 times)
--
--   %LICMGR-3-LOG_SMART_LIC_COMM_FAILED: (pid=24399) Communications failure
--   with the Cisco Smart License Utility (CSLU) : Could not resolve host:
--   cslu-local
--
-- log_ignore.txt 里这两条都没有，本次自行判断。
-- 和黑名单里已有的 LICMGR-2-LOG_LIC_MISSING_WARNING /
-- LICMGR-3-LOG_LIC_FILE_MISSING / LICENSE-6-VIOLATION 同一个归类：
-- 授权和容量的事走 license 审计，不进告警管线，设备照常转发。
--
--     mysql -h <host> -P <port> -u netops -p netops < sql/patch_20261113_smart_license_blacklist.sql
--
-- 和 schema.sql 的关系：内容已折进 schema.sql 的黑名单种子。
--   * 库是用 schema.sql 重建的 -> 不用执行本补丁
--   * 库里有数据要保留、不能重建 -> 执行本补丁
-- ============================================================
USE netops;

INSERT IGNORE INTO syslog_black_list
    (pattern, scope, ip, ignore_case, enabled, descr)
VALUES
('LICMGR-6-LOG_LICAPP_SMART_GLOBAL_CHANGE', 'mnemonic', '', 0, 1,
 'Smart Licensing全局通知变更，周期性刷（样例里一次repeated 4 times），无告警价值'),
('LICMGR-3-LOG_SMART_LIC_COMM_FAILED', 'mnemonic', '', 0, 1,
 '连不上CSLU(cslu-local域名没解析到)。license上报通道问题，不影响转发，走license审计');


-- 执行后自查
-- SELECT rule_id, pattern, enabled FROM syslog_black_list
--  WHERE pattern LIKE 'LICMGR%' OR pattern LIKE 'LICENSE%' ORDER BY pattern;
--    应 5 行：
--      LICENSE-6-VIOLATION
--      LICMGR-2-LOG_LIC_MISSING_WARNING
--      LICMGR-3-LOG_LIC_FILE_MISSING
--      LICMGR-3-LOG_SMART_LIC_COMM_FAILED        <- 本次
--      LICMGR-6-LOG_LICAPP_SMART_GLOBAL_CHANGE   <- 本次
--
-- 黑名单由 L2 定时刷新，默认 300 秒一轮，等一轮或重启进程。
--
-- 顺带一提：COMM_FAILED 那条暴露了一个真问题 —— cslu-local 这个主机名
-- 在 DNS 里没有记录。现在不影响转发，拦掉也没关系；但哪天真要做
-- Smart Licensing 合规上报，得先把这个名字解析通（或者改成直连
-- smartreceiver.cisco.com / 配 CSLU 的 IP）。这是 license 流程的事，
-- 不是靠告警推动的，所以拦掉是对的。
