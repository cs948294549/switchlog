-- ============================================================
-- 补丁：TCAM 资源水线告警
--
-- 现网样例（10.39.232.15/16/25/26/67/68/75/76 八台，同一秒内各 1 条）：
--   %ACLQOS-SLOT1-4-ACLQOS_OVER_THRESHOLD: Inst 0 Tcam 2 Bank 0's
--   (IPV4 RACL [racl]) usage has reached its threshold
--
-- 这条不屏蔽：它是 TCAM 满之前唯一的预警。
--
-- 登 10.39.232.26 实测：
--   N3k Ingress IPv4 RACL   Used 488  Free 24  95.31%
--   N3K SUP                 Used 106  Free 22  82.81%
--   其余区域 VACL/PACL/E-RACL 都是空的（0.3~0.8%）
-- 吃掉 488 条的是 Vlan1503 上的 ACL-INGRESS-Test（94 条 ACE，开了 statistics），
-- RACL 区域总共只划了 512 条。
--
-- 影响：转发性能不受影响（TCAM 并行查表，用 95% 和 5% 一样快），现状也是
-- 安全的（静态分配，已写进硬件）。风险在"下次改 ACL 那一刻" ——
-- 这批设备 Atomic Update=DISABLED、Default ACL=DENY，改 ACL 是原地重写，
-- 余量不够导致编程失败时接口会落到 default deny，整个 VLAN 的流量被拒。
--
--     mysql -h <host> -P <port> -u netops -p netops < sql/patch_20261113_tcam_threshold.sql
--
-- 三张表都要写才生效。和 schema.sql 的关系：内容已折进 schema.sql。
--   * 库是用 schema.sql 重建的 -> 不用执行本补丁
--   * 库里有数据要保留、不能重建 -> 执行本补丁
-- ============================================================
USE netops;

-- 1) 事件属性
--
-- stateless 不配 raise：TCAM 用量降下来设备不打"已恢复"，
-- 配成 raise 会开出永远关不掉的告警。
--
-- window 86400：只在跨阈值时报、不周期刷（现网 8 台各 1 条）。一天一条够了，
-- 窗口再短会把同一次配置下发拆成多条。
--
-- threshold 1：第一条就报。这是满之前唯一的预警，攒阈值等于把预警往后推。
--
-- object_type=none，不抽对象：正文里的 Inst/Tcam/Bank 是硬件位置，
-- 对排查没用 —— 要知道哪个区域满了得登设备看
-- show hardware access-list resource utilization。一台设备一条就够。
INSERT IGNORE INTO syslog_event
    (event_code, state, object_type, window_sec, threshold, clear_code, descr)
VALUES
('TCAM_THRESHOLD', 'stateless', 'none', 86400, 1, '',
 'ACL/QoS的TCAM用量超水线。满了之后改ACL可能编程失败，接口落default ACL');


-- 2) 匹配规则：fuzzy
--
-- 不得不走 fuzzy：'ACLQOS-SLOT1' 的 FAC 段含中划线，strip_mnemonic 的
-- 正则要求 FAC 段是 [A-Za-z][A-Za-z0-9_]*，中划线过不去，剥出来是空串
-- （和 TAHUSD-SLOT1 / FWM-ETH 同一个坑）。按 mnemonic 配的规则永远查不到它。
--
-- vendor=cisco_nx：这条只在 Nexus 上出现，收窄能让 fuzzy 列表对其它厂商
-- 的设备少试一条（fuzzy_candidates 按 vendor in (*, 本机vendor) 过滤）。
--
-- pattern 用 ACLQOS_OVER_THRESHOLD 不用 'ACLQOS'：后者会把这个模块的其它
-- 消息一起吞成 TCAM_THRESHOLD，那些还没见过，留着让它们进缺口清单。
-- 已核对与现有 4 条 fuzzy（authentication failure / Configured from /
-- BUFFER_THRESHOLD_EXCEEDED / hwMflpVlanLoopAlarm_clear）无交叉误命中。
INSERT IGNORE INTO syslog_rule
    (vendor, mnemonic, match_type, pattern, body_match,
     event_code, object_regex, priority, descr)
VALUES
('cisco_nx', '', 'contains', 'ACLQOS_OVER_THRESHOLD', '',
 'TCAM_THRESHOLD', '', 300,
 '%ACLQOS-SLOT1-4-ACLQOS_OVER_THRESHOLD: Inst 0 Tcam 2 Bank 0 (IPV4 RACL [racl]) usage has reached its threshold（FAC段含中划线，mnemonic剥不出）');


-- 3) 定级：P2 正常告警
--
-- 给 P2 不是 P3：它不是普通容量项，是"下次改 ACL 可能把整个 VLAN 拒掉"
-- 的预警。现网那 8 台已经只剩 24 条余量。
-- 不配 ignore：满之前就这一道提示，压掉就没有第二道了。
INSERT IGNORE INTO syslog_severity_rule
    (event_code, ip_reg, sysname_reg, severity, action, priority, descr)
VALUES
('TCAM_THRESHOLD', '', '', 2, '', 100,
 'TCAM用量超水线。满了改ACL可能编程失败落default deny，需清理ACL或重划TCAM');


-- ============================================================
-- 执行后自查
-- ============================================================
-- 1) 三张表都齐，应各 1 行
-- SELECT count(*) FROM syslog_event        WHERE event_code='TCAM_THRESHOLD';
-- SELECT count(*) FROM syslog_rule         WHERE event_code='TCAM_THRESHOLD';
-- SELECT count(*) FROM syslog_severity_rule WHERE event_code='TCAM_THRESHOLD';
--
-- 2) 确认 fuzzy 列表里五条互不重叠
-- SELECT rule_id, vendor, match_type, pattern, event_code, priority
--   FROM syslog_rule WHERE mnemonic='' AND enabled=1 ORDER BY priority, rule_id;
--    期望 5 行，pattern 各不相同
--
-- 3) 跑一轮后应该能看到那 8 台的告警，alarm_object 是 '-'（不抽对象）
-- SELECT ip, hostname, alarm_object, counter, first_seen
--   FROM alarm_list WHERE keyword='TCAM_THRESHOLD' ORDER BY ip;
--
-- 4) 规则由 L3 定时刷新，默认 300 秒一轮，等一轮或重启进程
--
-- ============================================================
-- 处理建议（告警只是提示，TCAM 本身还得治）
--
-- 短期，不用重启 —— 压缩 Vlan1503 那 94 条 ACE：
--   * 看能不能合并相邻网段（掩码聚合）
--   * 端口列表改成走 LOU，那个资源只用了 2/24，很空
--   * 确认 ACL-INGRESS-Test 这个名字是不是测试遗留 ——
--     它挂在生产 VLAN 上还开着 statistics，statistics 本身有开销
--
-- 中期，要 reload —— 重划 TCAM。VACL 用 2/512、PACL 用 3/384、
-- Egress RACL 用 3/512，都是空的，匀给 RACL：
--   hardware access-list tcam region racl 768
--   hardware access-list tcam region vacl 256
-- 改 TCAM carving 必须 reload 才生效，得排窗口。
--
-- 八台设备配置是一套模板（同一秒内一起报），大概率都在 95% 左右，
-- 要一起处理。确认用量：
--   show hardware access-list resource utilization
