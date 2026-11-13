-- ============================================================
-- 补丁：Cisco LICENSE-6-VIOLATION 加入 L2 黑名单
--
-- bbr1_dc07_m01 的 interface_10g 特性用量超授权数，每分钟刷一次周期性
-- 提示，不是故障，解析它纯属浪费，在 L2 直接拦掉。
--
-- 容量问题本身不会消失，这条只是不让它进告警管线刷屏——
-- 10G 口授权数量是否需要扩容，建议另外跟进。
--
--     mysql -h <host> -P <port> -u netops -p netops < sql/patch_20261112_license_violation.sql
--
-- 可重复执行：INSERT IGNORE，rule_id 唯一冲突会跳过，不会重复插入。
-- ============================================================
USE netops;

INSERT IGNORE INTO syslog_black_list
    (rule_id, pattern, scope, ip, ignore_case, enabled, descr)
VALUES
(7, 'LICENSE-6-VIOLATION', 'mnemonic', '', 0, 1,
 'License特性用量超授权数的周期性提示，非故障，每分钟刷一次。容量问题走license审计，不进告警管线');
