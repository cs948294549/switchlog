-- ============================================================
-- 补丁：屏蔽 SHELL / SSHS 登录与命令审计（28 条）
--
-- 现网样例（10.26.252.13，new_csw1_dc19_m01）—— 一次人工登录刷四条：
--   %%10SSHS/6/SSHS_LOG:     Accepted password for chensong from 10.33.103.136 port 23510.
--   %%10SSHS/6/SSHS_CONNECT: SSH user chensong (IP: 10.33.103.136) connected to the server successfully.
--   %%10SHELL/5/SHELL_LOGIN: chensong logged in from 10.33.103.136.
--   %%10SHELL/6/SHELL_CMD:   -Line=vty0-IPAddr=10.33.103.136-User=chensong; Command is dis cu
--
-- 和之前那批 OPS/CLI/CM（patch_20261113_mgmt_audit_blacklist.sql）
-- 一个性质：审计日志不是故障。设备上有 display logbuffer 可查，
-- 走告警管线只会把真告警淹掉。
--
-- 依据：log_ignore.txt 里 SHELL/SSHS 一族共 42 条，你给的四条在
-- 第 375/381/403/373 行，判断一致。本次配 28 条。
--
--     mysql -h <host> -P <port> -u netops -p netops < sql/patch_20261113_shell_sshs_audit_blacklist.sql
--
-- 和 schema.sql 的关系：内容已折进 schema.sql 的黑名单种子。
--   * 库是用 schema.sql 重建的 -> 不用执行本补丁
--   * 库里有数据要保留、不能重建 -> 执行本补丁
--
-- 注：SSHS/6/SSHS_ALGORITHM_MISMATCH 上一个补丁
-- （patch_20261113_ssh_nomatch_blacklist.sql）已经配过，
-- 本补丁不重复，唯一键也会挡住重复插入。
-- ============================================================
USE netops;

-- ============================================================
-- 故意不拦的 13 条（txt 里有，但我们留着）
--
-- 和上一轮保留 CLI/5/LOGINFAILED 同一个理由：这些是安全事件，要能看见。
-- 暴力破解、权限拒绝、改密码失败，都是需要人去看一眼的：
--
--   SHELL/5/SHELL_LOGINFAIL              登录失败
--   SHELL/4/LOGINFAILED                  登录失败（另一写法）
--   SHELL/4/LOGINAUTHFAIL                认证失败
--   SHELL/4/CHANGE_PASSWORD_FAIL         改密码失败
--   SHELL/5/SETPASS_FAIL_FIRSTLOGIN      首次登录设密码失败
--   SHELL/5/SHELL_CMDDENY                命令被拒（权限不足）
--   SHELL/4/SHELL_CMD_MATCHFAIL          命令匹配失败
--   SHELL/4/SHELL_CMD_EXECUTEFAIL        命令执行失败
--   SSHS/6/SSHS_AUTH_PWD_FAIL            密码认证失败
--   SSHS/6/SSHS_AUTHOR_FAIL              授权失败
--   SSHS/6/SSHS_INVALID_USERNAME_PWD     用户名密码错误
--   SSHS/6/SSHS_AUTH_EXCEED_RETRY_TIMES  认证重试超限（典型暴力破解特征）
--   SSHS/5/SSHS_ACL_DENY                 被ACL拒绝
--
-- 它们现在落 UNKNOWN_MNEMONIC。要正式接的话往 LOGIN_FAIL 事件码上挂规则
-- （那个码现在只有 fortinet 的 0100032003 和一条 fuzzy），
-- 不要加到黑名单里来。
-- ============================================================

INSERT IGNORE INTO syslog_black_list
    (pattern, scope, ip, ignore_case, enabled, descr)
VALUES
-- SSHS：SSH 服务端会话管理（10 条）
('SSHS/6/SSHS_LOG', 'mnemonic', '', 0, 1,
 'SSH登录接受留痕，txt第375行'),
('SSHS/6/SSHS_CONNECT', 'mnemonic', '', 0, 1,
 'SSH连接建立，txt第381行'),
('SSHS/6/SSHS_DISCONNECT', 'mnemonic', '', 0, 1,
 'SSH连接断开，txt第379行'),
('SSHS/6/SSHS_AUTH_SUCCESS', 'mnemonic', '', 0, 1,
 'SSH认证成功，txt第572行'),
('SSHS/6/SSHS_AUTH_TIMEOUT', 'mnemonic', '', 0, 1,
 'SSH认证超时，txt第430行'),
('SSHS/6/SSHS_SCP_OPER', 'mnemonic', '', 0, 1,
 'SCP文件操作留痕，txt第120行'),
('SSHS/6/SSHS_MAC_ERROR', 'mnemonic', '', 0, 1,
 'SSH MAC校验错误，txt第275行'),
('SSHS/6/SSHS_REACH_SESSION_LIMIT', 'mnemonic', '', 0, 1,
 'SSH会话数达上限，txt第428行'),
('SSHS/6/SSHS_VERSION_MISMATCH', 'mnemonic', '', 0, 1,
 'SSH版本不匹配，txt第437行'),
('SSHS/6/SSHS_SRV_UNAVAILABLE', 'mnemonic', '', 0, 1,
 'SSH服务不可用，txt第669行'),
-- SHELL：登录/登出（7 条）。三种严重度写法都配，现网版本混合
('SHELL/5/SHELL_LOGIN', 'mnemonic', '', 0, 1,
 '用户登录留痕，txt第403行'),
('SHELL/5/SHELL_LOGOUT', 'mnemonic', '', 0, 1,
 '用户登出留痕，txt第378行'),
('SHELL/4/LOGIN', 'mnemonic', '', 0, 1,
 '登录留痕(severity 4写法)，txt第404行'),
('SHELL/4/LOGOUT', 'mnemonic', '', 0, 1,
 '登出留痕(severity 4写法)，txt第405行'),
('SHELL/5/LOGIN', 'mnemonic', '', 0, 1,
 '登录留痕(severity 5写法)，txt第455行'),
('SHELL/5/LOGOUT', 'mnemonic', '', 0, 1,
 '登出留痕(severity 5写法)，txt第457行'),
('SHELL/5/TIMEOUT', 'mnemonic', '', 0, 1,
 '会话超时退出，txt第500行'),
-- SHELL：命令审计（11 条）
('SHELL/6/SHELL_CMD', 'mnemonic', '', 0, 1,
 '命令留痕，txt第373行。设备上display logbuffer可查'),
('SHELL/5/CMDRECORD', 'mnemonic', '', 0, 1,
 '命令留痕(另一写法)，txt第515行'),
('SHELL/6/SHELL_CMD_INPUT', 'mnemonic', '', 0, 1,
 '命令输入留痕，txt第414行'),
('SHELL/6/DISPLAY_CMDRECORD', 'mnemonic', '', 0, 1,
 'display类命令留痕，txt第376行'),
('SHELL/6/SHELL_CMD_CONFIRM', 'mnemonic', '', 0, 1,
 '命令二次确认留痕，txt第440行'),
('SHELL/6/CMDCONFIRM_RECORD', 'mnemonic', '', 0, 1,
 '命令确认留痕，txt第24行'),
('SHELL/6/CMDCONFIRM_UNIFORMRECORD', 'mnemonic', '', 0, 1,
 '命令确认统一留痕，txt第609行'),
('SHELL/5/USERCONFIRM', 'mnemonic', '', 0, 1,
 '用户确认留痕，txt第70行'),
('SHELL/5/AUTHCMDNONEED', 'mnemonic', '', 0, 1,
 '命令无需授权留痕，txt第103行'),
('SHELL/6/SHELL_SECLOG', 'mnemonic', '', 0, 1,
 'shell安全日志留痕，txt第413行'),
('SHELL/6/CLI', 'mnemonic', '', 0, 1,
 'CLI操作留痕，txt第603行');


-- ============================================================
-- 执行后自查
-- ============================================================
-- 1) 28 条都在（加上上一个补丁的 ALGORITHM_MISMATCH 共 29 条 SHELL/SSHS）
-- SELECT count(*) FROM syslog_black_list
--  WHERE pattern LIKE 'SHELL/%' OR pattern LIKE 'SSHS/%';
--
-- 2) 失败类一条都没拦，应返回 0 行
-- SELECT * FROM syslog_black_list
--  WHERE pattern LIKE 'SHELL/%' OR pattern LIKE 'SSHS/%'
--    AND (pattern LIKE '%FAIL%' OR pattern LIKE '%DENY%'
--         OR pattern LIKE '%INVALID%' OR pattern LIKE '%EXCEED%');
--
-- 3) 黑名单由 L2 定时刷新，默认 300 秒一轮，等一轮或重启进程
--
-- 4) 这批量很大（一次登录四条，加上每条命令一条），执行前后对比
--    blocked 计数（pipeline/runner.py:155）
--
-- 5) 失败类现在落 UNKNOWN_MNEMONIC，看看有多少：
-- SELECT mnemonic, count(*) c FROM alarm_log
--  WHERE event_code='UNKNOWN_MNEMONIC'
--    AND (mnemonic LIKE '%FAIL%' OR mnemonic LIKE '%DENY%')
--  GROUP BY mnemonic ORDER BY c DESC;
--    有量的话建议给 LOGIN_FAIL 补规则，正式接进来
--
-- 注：以后要审计"谁在设备上敲了什么命令"别从告警库查 ——
-- 这些日志在 L2 就丢了。去设备 display logbuffer，
-- 或者另开一路 syslog 直接归档到 ES。
