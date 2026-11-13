-- ============================================================
-- 补丁：华为 V200R022 口 down/up 的 DEVM/IFNET mnemonic
--
-- 现网 rsw1_corp_ts_m21 发现这组日志走不到 IFNET/3/PHY_UPDOWN 规则，
-- 落 UNKNOWN_MNEMONIC。DEVM 是物理层、IFNET 是接口协议层，
-- 同一次物理翻动两条一起打，对象字段名不同（EntPhysicalName vs ifName），
-- 分别配正则。
--
--     mysql -h <host> -P <port> -u netops -p netops < sql/patch_20261112_huawei_portdown.sql
--
-- 可重复执行：INSERT IGNORE，rule_id 唯一冲突会跳过，不会重复插入。
-- ============================================================
USE netops;

INSERT IGNORE INTO syslog_rule
    (rule_id, vendor, mnemonic, match_type, pattern, body_match,
     event_code, object_regex, priority, descr)
VALUES
(28, 'huawei', 'DEVM/2/hwPortDown', 'exact', '', '',
 'IF_DOWN', 'EntPhysicalName=([^,)]+)', 100,
 'EntPhysicalIndex=16847137, EntPhysicalName=GE1/0/32, hwPortDownReason=0, ifOperStatus=0, ifAdminStatus=1, faultID=144384'),
(29, 'huawei', 'DEVM/4/hwPortUp', 'exact', '', '',
 'IF_UP', 'EntPhysicalName=([^,)]+)', 100,
 'EntPhysicalIndex=16847137, EntPhysicalName=GE1/0/32, ifOperStatus=1, ifAdminStatus=1'),
(30, 'huawei', 'IFNET/2/linkDown_active', 'exact', '', '',
 'IF_DOWN', 'ifName=([^,)]+)', 100,
 'ifName=GE1/0/32, AdminStatus=UP, OperStatus=DOWN, Reason=Interface physical link is down, mainIfname=GE1/0/32'),
(31, 'huawei', 'IFNET/2/linkDown_clear', 'exact', '', '',
 'IF_UP', 'ifName=([^,)]+)', 100,
 'ifName=GE1/0/32, AdminStatus=UP, OperStatus=UP, Reason=Interface physical link is up, mainIfname=GE1/0/32');
