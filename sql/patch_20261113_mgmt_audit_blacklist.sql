-- ============================================================
-- 补丁：屏蔽管理面操作留痕（OPS / CLI / CM 三组 15 条）
--
-- 现网样例（172.26.1.34，rsw1_poe_corp_ts_m21_1.34，华为）：
-- 同一秒内刷了十几条，是一次采集的完整过程 ——
--
--   CM/5/ADMIN_USER_ACCESSRESULT    USER:eca ... RESULT:success  认证通过
--   OPS/5/OPS_LOGIN                 UserName=eca  建立OPS连接
--   OPS/5/OPS_RESTCONF_REQ          Body=<op-type>open</op-type>  开CLI终端
--   OPS/5/OPS_RESTCONF_RSP          StatusCode=4 No Content
--   CLI/5/CMDRECORD                 Command="system-view"
--   CLI/5/CMDRECORD                 Command="diagnose"
--   OPS/5/OPS_RESTCONF_REQ          Body=<command>display exception 10 verbose all</command>
--   OPS/5/OPS_RESTCONF_RSP          StatusCode=4 No Content
--   OPS/5/OPS_LOGOUT                Reason=the client cut the OPS connection
--   CM/5/ADMIN_USER_OFFLINERESULT   RESULT:User request to offline
--
-- SourceAddress=0.0.0.0、DestAddress=127.0.0.1、UserName=eca ——
-- 本机环回，就是采集脚本自己在干活。
--
-- 这些是审计日志不是故障。设备上本来就有命令审计（display logbuffer），
-- 走告警管线只会把真告警淹掉：一次采集十几条、几百台设备轮着采。
--
-- 依据：log_ignore.txt 里这一批大部分都有，判断一致 ——
--   第 179 行  OPS/5/OPS_RESTCONF_REQ
--   第 216 行  OPS/5/OPS_RESTCONF_RSP
--   第 377 行  CLI/5/CMDRECORD
--   第 386 行  CLI/5/LOGOUT
--   第 387 行  CLI/5/LOGIN
--   第 439 行  CLI/5/INTER_CMDRECORD
--   第 458 行  CM/5/USER_OFFLINERESULT
--   第 464 行  CLI/5/CMDRECORDFAILED
--   第 503 行  OPS/5/OPS_LOGIN
--   第 507 行  OPS/5/OPS_LOGOUT
--   第 517 行  CM/5/USER_ACCESSRESULT
--   第 586 行  OPS/5/OPS_OPER_FAIL
--   第 664 行  OPS/5/OPS_OPER_SUCCESS
--
--     mysql -h <host> -P <port> -u netops -p netops < sql/patch_20261113_mgmt_audit_blacklist.sql
--
-- 和 schema.sql 的关系：内容已折进 schema.sql 的黑名单种子。
--   * 库是用 schema.sql 重建的 -> 不用执行本补丁
--   * 库里有数据要保留、不能重建 -> 执行本补丁
-- ============================================================
USE netops;

-- CM 那两条要特别注意写法：
--   txt 里是   CM/5/USER_ACCESSRESULT    / CM/5/USER_OFFLINERESULT
--   现网日志是 CM/5/ADMIN_USER_ACCESSRESULT / CM/5/ADMIN_USER_OFFLINERESULT
-- 多了 ADMIN_ 前缀。老系统全文"包含"，不带 ADMIN_ 的那个子串能同时命中
-- 两种；我们按 mnemonic 全名进 dict，必须四条都配，少配 ADMIN_ 那两条
-- 现网日志继续落 UNKNOWN_MNEMONIC。
--
-- 没有一起拦 CLI/5/LOGINFAILED（txt 第 452 行有它）：登录失败要能看见，
-- 暴力破解是安全事件。我们这边有 LOGIN_FAIL 事件码专门管它。
INSERT IGNORE INTO syslog_black_list
    (pattern, scope, ip, ignore_case, enabled, descr)
VALUES
-- OPS（RESTCONF/脚本通道）
('OPS/5/OPS_LOGIN', 'mnemonic', '', 0, 1,
 'RESTCONF/OPS连接建立，采集侧每次采集都打。txt第503行'),
('OPS/5/OPS_LOGOUT', 'mnemonic', '', 0, 1,
 'RESTCONF/OPS连接断开。txt第507行'),
('OPS/5/OPS_RESTCONF_REQ', 'mnemonic', '', 0, 1,
 'RESTCONF请求留痕，一次采集刷十几条。txt第179行'),
('OPS/5/OPS_RESTCONF_RSP', 'mnemonic', '', 0, 1,
 'RESTCONF响应留痕，和REQ成对。txt第216行'),
('OPS/5/OPS_OPER_SUCCESS', 'mnemonic', '', 0, 1,
 'OPS操作成功留痕。txt第664行，同族一起配'),
('OPS/5/OPS_OPER_FAIL', 'mnemonic', '', 0, 1,
 'OPS操作失败留痕。txt第586行，同族一起配'),
-- CLI（命令审计）
('CLI/5/CMDRECORD', 'mnemonic', '', 0, 1,
 '命令留痕。设备上有display logbuffer可查，不用进告警。txt第377行'),
('CLI/5/INTER_CMDRECORD', 'mnemonic', '', 0, 1,
 '交互式命令留痕。txt第439行，同族一起配'),
('CLI/5/CMDRECORDFAILED', 'mnemonic', '', 0, 1,
 '命令执行失败留痕。txt第464行，同族一起配'),
('CLI/5/LOGIN', 'mnemonic', '', 0, 1,
 'CLI登录留痕。txt第387行'),
('CLI/5/LOGOUT', 'mnemonic', '', 0, 1,
 'CLI登出留痕。txt第386行'),
-- CM（用户认证/下线）。四条写法都配
('CM/5/ADMIN_USER_ACCESSRESULT', 'mnemonic', '', 0, 1,
 '管理员认证结果留痕（现网写法带ADMIN_）。txt第517行是不带ADMIN_的写法'),
('CM/5/ADMIN_USER_OFFLINERESULT', 'mnemonic', '', 0, 1,
 '管理员下线结果留痕（现网写法带ADMIN_）。txt第458行是不带ADMIN_的写法'),
('CM/5/USER_ACCESSRESULT', 'mnemonic', '', 0, 1,
 '用户认证结果留痕，txt第517行的原写法，一并配上'),
('CM/5/USER_OFFLINERESULT', 'mnemonic', '', 0, 1,
 '用户下线结果留痕，txt第458行的原写法，一并配上');


-- ============================================================
-- 执行后自查
-- ============================================================
-- 1) 15 条都在
-- SELECT rule_id, pattern, enabled FROM syslog_black_list
--  WHERE pattern LIKE 'OPS/%' OR pattern LIKE 'CLI/%' OR pattern LIKE 'CM/%'
--  ORDER BY pattern;                                      -- 应 15 行
--
-- 2) 确认登录失败没被一起拦掉（安全事件要留着），应返回 0 行
-- SELECT * FROM syslog_black_list WHERE pattern LIKE '%LOGINFAIL%';
--
-- 3) LOGIN_FAIL 的识别能力还在
-- SELECT mnemonic, pattern, event_code FROM syslog_rule
--  WHERE event_code='LOGIN_FAIL';
--    应有 fortinet 的 0100032003 和那条 fuzzy（authentication failure）
--
-- 4) 黑名单由 L2 定时刷新，默认 300 秒一轮，等一轮或重启进程
--
-- 5) 这批量很大，执行前后对比 runner 的 blocked 计数
--    （pipeline/runner.py:155 的 self._stats.incr("blocked")），
--    应该涨得很明显 —— 一次采集十几条、几百台设备轮着采
--
-- 注：如果以后要审计"谁在设备上敲了什么命令"，别从告警库查 ——
-- 这些日志在 L2 就被丢了，连 alarm_log 都不写。去设备上
-- display logbuffer，或者另开一路 syslog 直接归档到 ES。
