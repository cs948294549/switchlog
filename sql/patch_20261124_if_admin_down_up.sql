-- ============================================================
-- 补丁：人工 shutdown / no shutdown 一对归入 IF_DOWN / IF_UP
--
-- 现网样例（cisco_nx，都没解析）：
--   : 2026 Nov 24 19:43:10.932 CST: %ETHPORT-5-IF_DOWN_ADMIN_DOWN:
--     Interface Ethernet1/33 (description:9F_meeting) is down
--     (Administratively down)
--   : 2026 Nov 24 19:43:19.941 CST: %ETHPORT-5-IF_ADMIN_UP:
--     Interface Ethernet1/33 is admin up .
--
-- 判断依据
--   用户指定归 IF_DOWN / IF_UP。这两条是同一个动作(shut/no-shut)的两端，
--   9 秒一对，和已有的 ETHPORT-5-IF_DOWN_CFG_CHANGE 同性质（运维操作而非
--   故障），但口确实不转发了，所以照样走告警不配 ignore ——
--   办公网那批 rsw 的 IF_DOWN 在定级表里本来就配了 ignore。
--
--   和本仓库 IF_HARDWARE 插模块那次的区别：那次"插上模块"不等于"链路起来"，
--   所以插的那半归了 IF_ATTR_CHG(stateless) 不敢回关。这次 no-shut 是
--   shut 的反向动作，回关自己 shut 开的告警是对的。
--   唯一的坑：真链路故障期间有人 shut/no-shut 排查，no-shut 会把
--   LINK_FAILURE 开的告警一起关掉。但链路没真恢复设备会立刻再打
--   IF_DOWN_LINK_FAILURE 重新开，误关窗口只有几秒，不值得为它拆事件码。
--
--   老系统 log_config.txt 第 18/22 行判断一致（"接口手动关闭/手动开启"）。
--
-- 已验证（纯正则，未连库未跑管线）
--   两条都走 MNEMONIC_REGS[0]（cisco 三段式）正常剥出；
--   TS_REGS 第 3 条命中 "2026 Nov 24 19:43:10.932" 这种年在前的格式；
--   object_regex 直接复用 IF_DOWN 系列统一在用的
--   'Interface\s+([^\s,(]+)' —— ADMIN_DOWN 正文带 (description:9F_meeting)、
--   ADMIN_UP 正文结尾带 " ." 空格句点，两条都抽出 'Ethernet1/33'，
--   指纹一致，clear 能关住 raise。字符类排掉左括号，不会把 description
--   里的内容当接口名。
--   脚本校验：列名对得上 DDL、无唯一键冲突、没有引用不存在的事件码。
--
--     mysql -h <host> -P <port> -u netops -p netops < \
--       sql/patch_20261124_if_admin_down_up.sql
--
-- 不新建事件码、不改定级表：IF_DOWN / IF_UP 和它们的定级行都已存在。
--
-- 和 schema.sql 的关系：内容已折进 schema.sql（规则 107->109）。
--   * 库用 schema.sql 重建的 -> 不用执行本补丁
--   * 库里有数据要保留 -> 执行本补丁
-- ============================================================
USE netops;

INSERT IGNORE INTO syslog_rule
    (vendor, mnemonic, match_type, pattern, body_match,
     event_code, object_regex, priority, descr)
VALUES
('cisco_nx', 'ETHPORT-5-IF_DOWN_ADMIN_DOWN', 'exact', '', '',
 'IF_DOWN', 'Interface\\s+([^\\s,(]+)', 100,
 'Interface Ethernet1/33 (description:9F_meeting) is down (Administratively down)'),
('cisco_nx', 'ETHPORT-5-IF_ADMIN_UP', 'exact', '', '',
 'IF_UP', 'Interface\\s+([^\\s,(]+)', 100,
 'Interface Ethernet1/33 is admin up .，按IF_DOWN的指纹回关');

-- ============================================================
-- 执行后自查
-- ============================================================
-- SELECT * FROM syslog_rule
--   WHERE mnemonic IN ('ETHPORT-5-IF_DOWN_ADMIN_DOWN','ETHPORT-5-IF_ADMIN_UP');
-- SELECT count(*) FROM syslog_rule;   -- 109
-- 规则表各层定时刷新，默认 300 秒一轮，等一轮或重启进程
