-- ============================================================
-- 修正：H3C 风扇故障 mnemonic 配错了
--
-- 上一版把 mnemonic 填成了日志表面的完整文字 "DEV/1/FAN STATE CHANGES
-- TO FAILURE"，但 l1_prepare.strip_mnemonic 的正则在斜杠最后一段碰到
-- 空格就截断，实际剥出来的 mnemonic 是 "DEV/1/FAN"，规则一直不命中，
-- 日志持续落 UNKNOWN_MNEMONIC。
--
-- 改成 mnemonic='DEV/1/FAN' + body_match='STATE CHANGES TO FAILURE'，
-- 用 body_match 在 dict 命中后做子串消歧（和 IFNET/3/PHY_UPDOWN 的
-- up/down 消歧是同一个套路）。
--
--     mysql -h <host> -P <port> -u netops -p netops < sql/patch_20261112_h3c_fan_failure.sql
--
-- 这条用 REPLACE 而不是 INSERT IGNORE：rule_id=33 已经插过一次错误版本，
-- 要覆盖掉，不是跳过。
-- ============================================================
USE netops;

REPLACE INTO syslog_rule
    (rule_id, vendor, mnemonic, match_type, pattern, body_match,
     event_code, object_regex, priority, descr)
VALUES
(33, 'h3c', 'DEV/1/FAN', 'exact', '', 'STATE CHANGES TO FAILURE',
 'PSU_FAIL', 'fan ID is\\s+(\\d+)', 100,
 '%%10DEV/1/FAN STATE CHANGES TO FAILURE(t):-DevIP=10.39.240.32; Trap ...<hh3cfanfailure>: fan ID is 1');
