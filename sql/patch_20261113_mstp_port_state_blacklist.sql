-- ============================================================
-- 补丁：屏蔽 MSTP 端口状态迁移
--
-- 现网样例（172.26.1.75，rsw5_corp_ts_m20_1.75，华为）：
--   %%01MSTP/4/MSTPLOG_PROPORT_STATE_LEARNING(l):CID=0x80547552;
--   The MSTP process's port has been set to learning state.
--   (ProcessID=0, InstanceID=0, PortID=27, IfIndex=27,
--    PortName=GE1/0/27, PwName=-)
--
--   %%01MSTP/4/MSTPLOG_PROPORT_STATE_FORWARDING(l):CID=0x80547552;
--   The MSTP process's port has been set to forwarding state. (同上参数)
--
-- 生成树收敛的正常过程：端口 up 之后依次走
-- discarding -> learning -> forwarding，一次插拔刷三条，都带同一个
-- PortName，没有告警价值。两条样例时间戳相同（16:30:09），
-- 就是同一次收敛的连续两态。
--
-- 依据：log_ignore.txt 第 10/11 行有老写法
--   MSTP/4/SET_PORT_LEARNING / MSTP/4/SET_PORT_FORWARDING
-- 上一套系统已判为噪声，判断一致。本次连新写法一起配。
--
--     mysql -h <host> -P <port> -u netops -p netops < sql/patch_20261113_mstp_port_state_blacklist.sql
--
-- 和 schema.sql 的关系：内容已折进 schema.sql 的黑名单种子。
--   * 库是用 schema.sql 重建的 -> 不用执行本补丁
--   * 库里有数据要保留、不能重建 -> 执行本补丁
-- ============================================================
USE netops;

-- 五条：新写法三态 + 老写法两条。
--
-- 新旧两套写法都配，是因为现网版本混合，两种都可能出现 ——
-- 老系统用全文"包含"不用管写法差异，我们按 mnemonic 全名进 dict，
-- 少配一套那批设备就继续落 UNKNOWN_MNEMONIC。
--
-- DISCARDING 这条本次样例里没有，但之前翻日志时见过
-- （MSTPLOG_PROPORT_STATE_DISCARDING），是收敛三态的第一个，
-- 一起配上免得单独漏出来。
--
-- 不影响环路发现：真正的拓扑变更（根桥切换、BPDU 丢失、环路检测）
-- 是别的 mnemonic，不在这五条里。MAC 漂移那套（MAC_FLAP、
-- MAC_FLAP_SUPPRESS、hwMflpVlanLoopPeriodicTrap）也照常生效 ——
-- 环路真发生时靠那边发现，不靠端口状态迁移日志。
INSERT IGNORE INTO syslog_black_list
    (pattern, scope, ip, ignore_case, enabled, descr)
VALUES
('MSTP/4/MSTPLOG_PROPORT_STATE_LEARNING', 'mnemonic', '', 0, 1,
 'MSTP端口进入learning，生成树收敛的中间态'),
('MSTP/4/MSTPLOG_PROPORT_STATE_FORWARDING', 'mnemonic', '', 0, 1,
 'MSTP端口进入forwarding，生成树收敛完成'),
('MSTP/4/MSTPLOG_PROPORT_STATE_DISCARDING', 'mnemonic', '', 0, 1,
 'MSTP端口进入discarding，收敛三态里的第一个，之前日志里见过'),
('MSTP/4/SET_PORT_LEARNING', 'mnemonic', '', 0, 1,
 'MSTP端口learning的老写法，txt第10行已判为噪声'),
('MSTP/4/SET_PORT_FORWARDING', 'mnemonic', '', 0, 1,
 'MSTP端口forwarding的老写法，txt第11行已判为噪声');


-- 执行后自查
-- SELECT rule_id, pattern, enabled FROM syslog_black_list
--  WHERE pattern LIKE 'MSTP/%' ORDER BY pattern;          -- 应 5 行
--
-- 黑名单由 L2 定时刷新，默认 300 秒一轮，等一轮或重启进程。
--
-- 环路发现能力确认还在：
-- SELECT mnemonic, event_code FROM syslog_rule
--  WHERE event_code IN ('MAC_FLAP','MAC_FLAP_SUPPRESS','MAC_FLAP_RECOVER')
--  ORDER BY event_code;
--
-- 注：syslog_event 里的 STP_TC（拓扑变更）目前一条匹配规则都没有，
-- 是个空码。哪天要做拓扑变更告警，往那个码上挂规则，
-- 别挂到这五条被拦的 mnemonic 上。
