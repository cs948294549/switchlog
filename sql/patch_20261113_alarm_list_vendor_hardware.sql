-- ============================================================
-- 补丁：alarm_list 补 vendor / hardware
--
-- L4 富化时这两个字段其实已经查到了（devices.vendor / devices.hardware），
-- 但 L9 落库只挑了 ip/hostname 等字段写 alarm_list，没带上它们——排查时
-- 看板上看不出告警设备是什么厂商/型号，得现查 devices 表才知道。
--
--     mysql -h <host> -P <port> -u netops -p netops < sql/patch_20261113_alarm_list_vendor_hardware.sql
--
-- 只补新字段，不回填历史行——老告警的 vendor/hardware 留空，不影响
-- state/severity 等既有逻辑，看板上老数据这两列显示为空即可。
--
-- ALTER TABLE 没有 IF NOT EXISTS，重复执行会报 Duplicate column，
-- 执行前可以先确认列还不存在：
--     SELECT column_name FROM information_schema.columns
--     WHERE table_schema='netops' AND table_name='alarm_list'
--       AND column_name IN ('vendor','hardware');
-- ============================================================
USE netops;

ALTER TABLE alarm_list
    ADD COLUMN vendor VARCHAR(30) NOT NULL DEFAULT ''
        COMMENT '设备厂商，L4富化时按devices.vendor原值写入，排查用',
    ADD COLUMN hardware VARCHAR(100) NOT NULL DEFAULT ''
        COMMENT '设备型号，L4富化时按devices.hardware写入，排查用';
