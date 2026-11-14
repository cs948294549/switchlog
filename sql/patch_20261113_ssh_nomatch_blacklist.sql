-- ============================================================
-- 补丁：屏蔽 SSH 算法协商失败
--
-- 现网样例（172.21.32.14）：
--   %SSH-3-NO_MATCH: No matching kex algorithm found:
--   client curve25519-sha256,curve25519-sha256@libssh.org,
--          ecdh-sha2-nistp256,...,diffie-hellman-group14-sha256,ext-info-c
--   server diffie-hellman-group-exchange-sha1,
--          diffie-hellman-group14-sha1,diffie-hellman-group1-sha1
--
--     mysql -h <host> -P <port> -u netops -p netops < sql/patch_20261113_ssh_nomatch_blacklist.sql
--
-- 和 schema.sql 的关系：内容已折进 schema.sql 的黑名单种子。
--   * 库是用 schema.sql 重建的 -> 不用执行本补丁
--   * 库里有数据要保留、不能重建 -> 执行本补丁
-- ============================================================
USE netops;

-- 为什么拦：它反映的是"这台设备的 IOS 太老"，不是突发故障。
-- 每次有人用新客户端连它就刷一条，刷一百次问题还是同一个 ——
-- 真要解决是升级 IOS 或在客户端放开旧算法，不是靠告警推动。
--
-- log_ignore.txt 里没有 SSH-3-NO_MATCH，但第 450 行有华为的同义写法
-- SSHS/6/SSHS_ALGORITHM_MISMATCH（SSH 算法不匹配），判断一致。
-- 一起配上，顺带带上第 667 行的 SSH-4-SSH2_UNEXPECTED_MSG（同属协议层异常）。
--
-- txt 里 SSH 一族有 60 多条（登录/登出/认证失败/会话管理等），
-- 本次只配这三条协议层的。登录失败类的（SSH/5/SSH_USER_LOGIN_FAIL、
-- SSHS/6/SSHS_AUTH_PWD_FAIL、AUTH-5-SSHD_LOGIN_FAILED 等）故意不配 ——
-- 和上一轮保留 CLI/5/LOGINFAILED 同一个理由：暴力破解要能看见，
-- 我们这边有 LOGIN_FAIL 事件码专门管它。
INSERT IGNORE INTO syslog_black_list
    (pattern, scope, ip, ignore_case, enabled, descr)
VALUES
('SSH-3-NO_MATCH', 'mnemonic', '', 0, 1,
 'SSH算法协商失败(Cisco)。老IOS只支持SHA-1时代KEX，是版本能力问题不是故障'),
('SSHS/6/SSHS_ALGORITHM_MISMATCH', 'mnemonic', '', 0, 1,
 'SSH算法不匹配(华为写法)，txt第450行，同义一起配'),
('SSH-4-SSH2_UNEXPECTED_MSG', 'mnemonic', '', 0, 1,
 'SSH2协议层意外报文，txt第667行');


-- ============================================================
-- 执行后自查
-- ============================================================
-- 1) 三条都在
-- SELECT rule_id, pattern, enabled FROM syslog_black_list
--  WHERE pattern IN ('SSH-3-NO_MATCH','SSHS/6/SSHS_ALGORITHM_MISMATCH',
--                    'SSH-4-SSH2_UNEXPECTED_MSG');       -- 应 3 行
--
-- 2) 登录失败的发现能力还在（这几条故意没拦），应返回 0 行
-- SELECT * FROM syslog_black_list
--  WHERE pattern LIKE '%LOGIN_FAIL%' OR pattern LIKE '%AUTH_PWD_FAIL%'
--     OR pattern LIKE '%LOGINFAIL%';
--
-- 3) 黑名单由 L2 定时刷新，默认 300 秒一轮，等一轮或重启进程
--
-- ============================================================
-- 背后的真问题（拦掉日志不等于解决）
--
-- 172.21.32.14 = edr1_dc09_m01
--   Cisco 3945，IOS 15.4(3)M6a，Compiled 2016 年
--
-- 服务端只给出三个 SHA-1 时代的 KEX 算法。现代客户端默认不接受：
--   * OpenSSH 8.8+（2021 年起）默认禁用 ssh-rsa/SHA-1 相关
--   * 新版 paramiko / netmiko 同样不协商这些
--
-- 影响：用新客户端连这台设备会直接失败。采集侧如果升过 SSH 库，
-- 这台的数据就是停更的 —— 查一下它在 devices 表里的 timestamp
-- 还在不在走（之前查风扇时看到的是 2026-11-13 08:00:05，当时是在走的）。
--
-- 两条路：
--   1. 升级 IOS（15.4 是 2016 年的版本，这台机型本身也快到 EOL）
--   2. 客户端临时放开旧算法，在采集侧的 ssh 配置里加：
--        KexAlgorithms +diffie-hellman-group14-sha1
--        HostKeyAlgorithms +ssh-rsa
--      这是降级安全要求，只建议对这类老设备单独开，别全局放开
--
-- 这台也是之前报 ENVMON-4-ONE_FAN_LOW_RPM（风扇低转速、建议换风扇模块）
-- 的同一台设备。两件事可以一起排。
