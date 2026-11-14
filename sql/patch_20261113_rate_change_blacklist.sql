-- ============================================================
-- 补丁：屏蔽接口速率变化通知（8 条）
--
-- 现网样例（172.26.1.45，rsw1_poe_corp_ts_m21_1.45，华为）：
--   %%01DEVM/5/hwOutputRateChangeOverThresholdNotice(t):
--   CID=0x80fc0101-OID=1.3.6.1.4.1.2011.5.25.157.2.220;
--   The output rate change ratio exceeded the threshold.
--   (IfIndex = 13, InterfaceName = GE1/0/13, ThresholdPercent = 50,
--    CurrentStatisticalPeriodRate = 64, LastStatisticalPeriodRate = 33133)
--
-- 注意它报的是"变化率"不是"速率过高"：上个统计周期 33133、这个周期 64，
-- 跌了 99.8%，超过 ThresholdPercent=50 就报。流量正常起落就会触发 ——
-- 办公网接口早晚峰谷差几十倍很常见，留着只会天天响。
--
-- 真要看带宽占用走流量监控那套（esflow / query_flow_traffic），
-- 按 IP 和出口分组统计，比 syslog 这种单口变化率通知有用得多。
--
-- 依据：log_ignore.txt 里同类有 6 条，判断一致 ——
--   第 71 行   IFPDT/4/OutputRateChangeOverThresholdNotice
--   第 75 行   IFPDT/4/InputRateChangeOverThresholdNotice
--   第 487 行  DEVM/4/hwIfMonitorOutputRateRising_clear
--   第 489 行  DEVM/4/hwIfMonitorOutputRateRising_active
--   第 502 行  DEVM/4/hwIfMonitorInputRateRising_active
--   第 506 行  DEVM/4/hwIfMonitorInputRateRising_clear
-- 现网这条写法又不一样（DEVM/5/hwOutputRateChange...），三套都配上。
--
--     mysql -h <host> -P <port> -u netops -p netops < sql/patch_20261113_rate_change_blacklist.sql
--
-- 和 schema.sql 的关系：内容已折进 schema.sql 的黑名单种子。
--   * 库是用 schema.sql 重建的 -> 不用执行本补丁
--   * 库里有数据要保留、不能重建 -> 执行本补丁
-- ============================================================
USE netops;

-- Input 那两条（DEVM/5/hwInputRateChange... 和现网没见过的）一起配：
-- Output 都出现了，对向迟早会来，等它冒出来再补一轮不值当。
--
-- txt 第 331 行还有个 '01IFNET/4/BWRATE_'，剥不出完整 mnemonic
-- （那是带版本号前缀又带下划线结尾的前缀写法），现网没见过，先不配。
-- 真出现的话会落 UNKNOWN_MNEMONIC，到时按实际 mnemonic 配。
INSERT IGNORE INTO syslog_black_list
    (pattern, scope, ip, ignore_case, enabled, descr)
VALUES
-- 现网这次遇到的写法
('DEVM/5/hwOutputRateChangeOverThresholdNotice', 'mnemonic', '', 0, 1,
 '出向速率变化率超阈值。流量正常起落就触发，带宽占用走流量监控不走syslog'),
('DEVM/5/hwInputRateChangeOverThresholdNotice', 'mnemonic', '', 0, 1,
 '入向速率变化率超阈值，上面那条的对向，现网还没出现先配上'),
-- txt 里的 DEVM/4 写法（速率上升 active/clear 成对）
('DEVM/4/hwIfMonitorOutputRateRising_active', 'mnemonic', '', 0, 1,
 '出向速率上升，txt第489行'),
('DEVM/4/hwIfMonitorOutputRateRising_clear', 'mnemonic', '', 0, 1,
 '出向速率上升恢复，txt第487行'),
('DEVM/4/hwIfMonitorInputRateRising_active', 'mnemonic', '', 0, 1,
 '入向速率上升，txt第502行'),
('DEVM/4/hwIfMonitorInputRateRising_clear', 'mnemonic', '', 0, 1,
 '入向速率上升恢复，txt第506行'),
-- txt 里的 IFPDT 模块写法
('IFPDT/4/OutputRateChangeOverThresholdNotice', 'mnemonic', '', 0, 1,
 '出向速率变化率超阈值(IFPDT模块写法)，txt第71行'),
('IFPDT/4/InputRateChangeOverThresholdNotice', 'mnemonic', '', 0, 1,
 '入向速率变化率超阈值(IFPDT模块写法)，txt第75行');


-- ============================================================
-- 执行后自查
-- ============================================================
-- 1) 8 条都在
-- SELECT rule_id, pattern, enabled FROM syslog_black_list
--  WHERE pattern LIKE '%RateChange%' OR pattern LIKE '%RateRising%'
--  ORDER BY pattern;                                   -- 应 8 行
--
-- 2) 黑名单由 L2 定时刷新，默认 300 秒一轮，等一轮或重启进程
--
-- 3) 带宽相关的告警能力：syslog 这条路本来就不负责带宽。
--    确认一下现在 syslog 侧和容量/带宽有关的事件码是哪些：
-- SELECT DISTINCT event_code FROM syslog_rule
--  WHERE event_code IN ('CRYPTO_BW','BUFFER_THRESHOLD','TCAM_THRESHOLD')
--  ORDER BY event_code;
--    CRYPTO_BW 是加密许可带宽上限、BUFFER_THRESHOLD 是缓存水线、
--    TCAM_THRESHOLD 是 ACL 资源 —— 都是资源类，不是流量大小。
--    接口带宽占用要看流量监控（esflow），不在这套管线里。
--
-- 4) 顺带：那条样例显示 GE1/0/13 的速率从 33133 跌到 64，
--    跌得这么狠通常是对端停了或业务下线。如果这个口接的是重要设备，
--    真正该关心的是它有没有 down（IF_DOWN 那套会报），不是速率变化率。
