-- ============================================================
-- 补丁：屏蔽漂移限速解除 SECE/4/UCSUPPRESSRESUME
--
-- 现网样例（172.25.1.121，rsw1_poe_corp_hz_m12_1.121，华为 S5720）：
--   %%01SECE/4/UCSUPPRESSRESUME(l)[330528]:MAC address flapping finished
--   on port. Unknown unicast packets were normally forwarded.
--   (Interface=GigabitEthernet0/0/24)
--
-- log_ignore.txt 里没有这条，本次自行判断。
--
-- 它是 SECE/4/UCSUPPRESS（限速开始）的配对事件。开始那条走
-- MAC_FLAP_SUPPRESS 事件码、P2 告警（端口被限到 50% 带宽，已影响转发），
-- 保持不变。
--
-- 解除这条不配规则直接拉黑，两个理由：
--   1. 关不掉告警。MAC_FLAP_SUPPRESS 是 stateless，恢复靠 sweep() 的
--      600s 窗口静默自动完成，不是恢复事件驱动的。配上规则也只是多一条
--      记录，对告警生命周期没有任何影响
--   2. 回溯用不上它。UCSUPPRESS 那条告警自己就带 first_seen 和
--      clear_time（sweep 自动恢复时填的），限速持续多久从那一条就能看出来
--
-- 不拉黑的代价是它会汇进 UNKNOWN_MNEMONIC 那条共用告警 ——
-- UNKNOWN_MNEMONIC 没有 object_regex，指纹是 md5(ip|UNKNOWN_MNEMONIC|-)，
-- 同一台设备所有未匹配日志共用一条 P3，把真正的规则缺口盖住。
--
--     mysql -h <host> -P <port> -u netops -p netops < sql/patch_20261113_ucsuppressresume_blacklist.sql
--
-- 和 schema.sql 的关系：内容已折进 schema.sql 的黑名单种子。
--   * 库是用 schema.sql 重建的 -> 不用执行本补丁
--   * 库里有数据要保留、不能重建 -> 执行本补丁
-- ============================================================
USE netops;

INSERT IGNORE INTO syslog_black_list
    (pattern, scope, ip, ignore_case, enabled, descr)
VALUES
('SECE/4/UCSUPPRESSRESUME', 'mnemonic', '', 0, 1,
 '漂移限速解除。MAC_FLAP_SUPPRESS靠窗口静默自动恢复，不靠这条驱动');


-- 执行后自查
--
-- 1) 规则已插入
-- SELECT rule_id, pattern, enabled FROM syslog_black_list
--  WHERE pattern LIKE 'SECE/%';            -- 应 1 行（只有 RESUME 这条）
--
-- 2) 限速开始那条没被一起拦掉 —— 它是 P2 告警，要留着
-- SELECT r.mnemonic, r.event_code,
--        (SELECT count(*) FROM syslog_black_list b
--          WHERE b.scope='mnemonic' AND b.pattern=r.mnemonic AND b.enabled=1) AS 被拦
--   FROM syslog_rule r WHERE r.mnemonic='SECE/4/UCSUPPRESS';
--    被拦应为 0
--
-- 3) 黑名单由 L2 定时刷新，默认 300 秒一轮，等一轮或重启进程
--
-- 4) 拦掉之后 172.25.1.121 的 UNKNOWN_MNEMONIC 那条共用告警应该安静下来。
--    确认还有哪些未匹配日志汇在里面：
-- SELECT mnemonic, count(*) c FROM alarm_log
--  WHERE event_code='UNKNOWN_MNEMONIC' AND ip='172.25.1.121'
--  GROUP BY mnemonic ORDER BY c DESC;
