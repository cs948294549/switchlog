-- ============================================================
-- 补丁：华为 VLAN 环路 MAC 漂移 trap
--
-- rsw1_poe_corp_ts_m21 发现 FEI/4/hwMflpVlanLoopPeriodicTrap 落
-- UNKNOWN_MNEMONIC。MAC 地址是四段中划线格式（c6e5-964a-24b5），
-- 和已有 cisco_nx 点分格式的 MAC_FLAP 规则不一样，单独配正则。
--
--     mysql -h <host> -P <port> -u netops -p netops < sql/patch_20261112_huawei_macflap.sql
--
-- 可重复执行：INSERT IGNORE，rule_id 唯一冲突会跳过，不会重复插入。
-- ============================================================
USE netops;

INSERT IGNORE INTO syslog_rule
    (rule_id, vendor, mnemonic, match_type, pattern, body_match,
     event_code, object_regex, priority, descr)
VALUES
(32, 'huawei', 'FEI/4/hwMflpVlanLoopPeriodicTrap', 'exact', '', '',
 'MAC_FLAP', 'address\\s*:\\s*([0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4})', 100,
 'MAC flapping detected, VlanId = 136, Original-Port = Eth-Trunk100, Flapping port 1 = Eth-Trunk1, port 2 = -. ...address : c6e5-964a-24b5');
