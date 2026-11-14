-- ============================================================
-- 补丁：屏蔽内核杂项消息 KERN-*-SYSTEM_MSG
--
-- 现网样例：
--   %KERN-3-SYSTEM_MSG: [55031934.253621] cctrl_tor_nep_set_fan_speed_pwm:
--   index: 0, duty_cycle : 79 - kernel
--
-- 内容是风扇调速 —— 风扇随温度自动调转速是正常工作，不是故障。
-- 真的风扇坏了有专门的码：PSU_FAIL（DEV/1/FAN、DEV/4/FAN、
-- ENVMON-4-ONE_FAN_LOW_RPM）和温度那套（TEMP_ALARM 15 条），不靠这条。
--
--     mysql -h <host> -P <port> -u netops -p netops < sql/patch_20261113_kern_system_msg_blacklist.sql
--
-- 和 schema.sql 的关系：内容已折进 schema.sql 的黑名单种子。
--   * 库是用 schema.sql 重建的 -> 不用执行本补丁
--   * 库里有数据要保留、不能重建 -> 执行本补丁
-- ============================================================
USE netops;

-- 两条都配：严重度数字各是一个独立的 mnemonic。
-- log_ignore.txt 第 616 行只写了 KERN-2-SYSTEM_MSG，它那边是全文"包含"
-- 所以 KERN-2 / KERN-3 都能命中；我们按 mnemonic 全名进 dict，
-- KERN-2 那条拦不住 KERN-3。现网这次报的是 KERN-3。
-- 其余严重度（KERN-4/5/6）以后出现了再补。
--
-- txt 里还有两条 KERN 的，是 IOS-XR 写法、FAC 段带冒号，
-- strip_mnemonic 剥不出来（和 TAHUSD-SLOT1 同一个坑），真要配得走
-- scope=message，现网没见过，先不配：
--   第 141 行  KERN-4: tcp_auth_ok
--   第 311 行  KERN-3: mld6_input
-- 另有第 115 行 KERN-6-KERN_ARP_ADDR_CHANGE，正常 mnemonic 格式，
-- 现网也没见过，等出现再说。
--
-- 代价说明：SYSTEM_MSG 是大杂烩 mnemonic，内核什么都往里打。整个
-- mnemonic 拦掉之后，这个严重度下别的内核消息也一起丢，不再进
-- UNKNOWN_MNEMONIC 的缺口清单 —— 以后内核报别的事我们看不见。
-- 要保留发现能力得改成 scope=message 配具体子串（比如
-- 'set_fan_speed_pwm'），但那一串每条日志都要线性扫，比 dict 贵。
-- 这里和已经拦掉的 DAEMON-3-SYSTEM_MSG 保持同一个取舍。
INSERT IGNORE INTO syslog_black_list
    (pattern, scope, ip, ignore_case, enabled, descr)
VALUES
('KERN-3-SYSTEM_MSG', 'mnemonic', '', 0, 1,
 '内核杂项消息，现网见到的是风扇自动调速。风扇故障走PSU_FAIL/TEMP_ALARM，不靠这条'),
('KERN-2-SYSTEM_MSG', 'mnemonic', '', 0, 1,
 '内核杂项消息(严重度2)，txt第616行已判为噪声，同族一起配');


-- 执行后自查
-- SELECT rule_id, pattern, enabled FROM syslog_black_list
--  WHERE pattern LIKE '%SYSTEM_MSG' ORDER BY pattern;
--    应 3 行：DAEMON-3-SYSTEM_MSG（之前就有）+ KERN-2 / KERN-3（本次）
--
-- 黑名单由 L2 定时刷新，默认 300 秒一轮，等一轮或重启进程。
--
-- 风扇相关的告警能力没受影响，确认一下还在：
-- SELECT mnemonic, event_code FROM syslog_rule
--  WHERE event_code IN ('PSU_FAIL','FAN_LOW_RPM','TEMP_ALARM','TEMP_OK')
--  ORDER BY event_code, mnemonic;
