-- ============================================================
-- 补丁：alarm_list 补 object_name / object_alias
--
-- L4 富化时这两个字段其实已经查到了（接口对象查 ports.if_name /
-- ports.alias），但 L9 落库没带上。alarm_object 是 L3 抽出来的原始
-- 识别对象（参与指纹，不能改），object_name/object_alias 是 L4 在此
-- 基础上查到的归一化名字和人类可读描述 —— 目前只有接口对象会填，
-- 其它对象类型（peer/mac/slot）留空。
--
--     mysql -h <host> -P <port> -u netops -p netops < sql/patch_20261113_alarm_list_object_alias.sql
--
-- 只补新字段，不回填历史行——老告警这两列留空，不影响既有逻辑。
--
-- ALTER TABLE 没有 IF NOT EXISTS，重复执行会报 Duplicate column，
-- 执行前可以先确认列还不存在：
--     SELECT column_name FROM information_schema.columns
--     WHERE table_schema='netops' AND table_name='alarm_list'
--       AND column_name IN ('object_name','object_alias');
-- ============================================================
USE netops;

ALTER TABLE alarm_list
    ADD COLUMN object_name VARCHAR(100) NOT NULL DEFAULT ''
        COMMENT '对象归一化识别名，目前只有接口会填（ports.if_name全名），其它对象类型留空',
    ADD COLUMN object_alias VARCHAR(200) NOT NULL DEFAULT ''
        COMMENT '对象人类可读描述，目前只有接口会填（ports.alias接口描述），其它对象类型留空';
