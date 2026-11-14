-- ============================================================
-- 补丁：屏蔽 LLDP 邻居变化（17 条）
--
-- 现网样例（172.26.1.46，rsw1_poe_corp_ts_m21_1.46，华为）：
-- 一次邻居变化在同一秒内刷三条，GE1/0/23 的邻居被删除 ——
--
--   LLDP/4/hwLldpInterfaceNeighborChange
--     Action=deleted, Interface=GE1/0/23, RemotePortId=088f-c3bf-330e, ...
--   LLDP/4/hwLldpInterfaceRemTablesChange
--     Interface=GE1/0/23, Action=deleted, Added=0, Deleted=1, ...
--   LLDP/4/lldpRemTablesChange
--     Added=0, Deleted=0, Dropped=0, Aged=1
--
-- 三条说的是同一件事，详细程度递减（带完整邻居信息 -> 带接口 -> 只有计数）。
--
-- LLDP 邻居表变化不是故障：对端重启、改端口描述、拔插网线、邻居老化都会刷。
-- 端口真 down 了有 IF_DOWN 那一套负责（ETHPORT/IFNET/DEVM 十几条规则），
-- 不靠 LLDP 发现。
--
-- 依据：log_ignore.txt 里 LLDP 一族有 19 条，你这三条在第 218/382/385 行，
-- 判断一致。本次把 17 条能剥出 mnemonic 的一次配齐，免得以后一条条冒出来。
--
--     mysql -h <host> -P <port> -u netops -p netops < sql/patch_20261113_lldp_blacklist.sql
--
-- 和 schema.sql 的关系：内容已折进 schema.sql 的黑名单种子。
--   * 库是用 schema.sql 重建的 -> 不用执行本补丁
--   * 库里有数据要保留、不能重建 -> 执行本补丁
-- ============================================================
USE netops;

-- 跳过 txt 里两条剥不出 mnemonic 的，要配得走 scope=message，
-- 现网没见过先不配：
--   第 583 行  'LLDP_DUPLEX_INCONSISTENT'   裸子串，没有模块前缀
--   第 673 行  'LLDP邻居数量超限'            中文，英文日志里永不命中
--
-- 两条有保留价值但按 txt 判断一起拦的，想用就把它们 enabled=0：
--   LLDP/5/LLDP_PVID_INCONSISTENT    两端 PVID 不一致，是配置错误
--   LLDP/5/LLDP_DUPLEX_INCONSISTENT  两端双工不一致，是配置错误
-- 这两类真出现时会导致单向不通或大量 CRC，排查时有用。txt 判了噪声，
-- 本补丁跟着走，但单独点出来让你知道拦了什么。
INSERT IGNORE INTO syslog_black_list
    (pattern, scope, ip, ignore_case, enabled, descr)
VALUES
-- 华为/华三（本次现网遇到的三条在最前）
('LLDP/4/hwLldpInterfaceNeighborChange', 'mnemonic', '', 0, 1,
 'LLDP邻居变化(详细)，txt第218行。对端重启/改描述/拔插都会刷'),
('LLDP/4/hwLldpInterfaceRemTablesChange', 'mnemonic', '', 0, 1,
 'LLDP邻居表变化(带接口)，txt第382行，上面那条的伴生'),
('LLDP/4/lldpRemTablesChange', 'mnemonic', '', 0, 1,
 'LLDP邻居表变化(标准MIB)，txt第385行，同一件事的第三条'),
('LLDP/4/NBRCHGTRAP', 'mnemonic', '', 0, 1,
 'LLDP邻居变化trap，txt第51/52行'),
('LLDP/6/LLDP_CREATE_NEIGHBOR', 'mnemonic', '', 0, 1,
 'LLDP邻居建立，txt第394行'),
('LLDP/6/LLDP_DELETE_NEIGHBOR', 'mnemonic', '', 0, 1,
 'LLDP邻居删除，txt第466行'),
('LLDP/5/LLDP_NEIGHBOR_AGE_OUT', 'mnemonic', '', 0, 1,
 'LLDP邻居老化，txt第402行'),
('LLDP/5/LLDP_PVID_INCONSISTENT', 'mnemonic', '', 0, 1,
 'LLDP两端PVID不一致，txt第371行判为噪声。想查配置错误把这条enabled=0'),
('LLDP/5/LLDP_DUPLEX_INCONSISTENT', 'mnemonic', '', 0, 1,
 'LLDP两端双工不一致，txt第672行判为噪声。想查配置错误把这条enabled=0'),
-- Cisco
('LLDP-4-CREATEREM', 'mnemonic', '', 0, 1,
 'LLDP邻居建立(Cisco写法)，txt第286行'),
('LLDP-4-AGEOUTREM', 'mnemonic', '', 0, 1,
 'LLDP邻居老化(Cisco写法)，txt第287行'),
('LLDP-5-NEIGHBOR_NEW', 'mnemonic', '', 0, 1,
 'LLDP新邻居，txt第338行'),
('LLDP-5-NEIGHBOR_GONE', 'mnemonic', '', 0, 1,
 'LLDP邻居消失，txt第315行'),
('LLDP-5-NEIGHBOR_TIMEOUT', 'mnemonic', '', 0, 1,
 'LLDP邻居超时，txt第325行'),
('LLDP-3-MAC_PHY_CFG', 'mnemonic', '', 0, 1,
 'LLDP两端速率/双工配置不符，txt第674行'),
-- 其它平台（DAEMON facility）
('DAEMON-6-LLDP_NEIGHBOR_UP', 'mnemonic', '', 0, 1,
 'LLDP邻居up，txt第184行'),
('DAEMON-6-LLDP_NEIGHBOR_DOWN', 'mnemonic', '', 0, 1,
 'LLDP邻居down，txt第155/225行');


-- ============================================================
-- 执行后自查
-- ============================================================
-- 1) 17 条都在
-- SELECT rule_id, pattern, enabled FROM syslog_black_list
--  WHERE pattern LIKE 'LLDP%' OR pattern LIKE '%LLDP_NEIGHBOR%'
--  ORDER BY pattern;                                  -- 应 17 行
--
-- 2) 端口 up/down 的识别能力没受影响（LLDP 拦了不等于看不见断链）
-- SELECT event_code, count(*) FROM syslog_rule
--  WHERE event_code IN ('IF_DOWN','IF_UP') GROUP BY event_code;
--
-- 3) 黑名单由 L2 定时刷新，默认 300 秒一轮，等一轮或重启进程
--
-- 4) LLDP 量不小（一次变化三条），执行前后对比 blocked 计数
--    （pipeline/runner.py:155）
--
-- 5) 以后要做链路拓扑核对（LLDP 邻居和预期不符告警），别指望从告警库查 ——
--    这些日志在 L2 就丢了。采集侧的 lldp_list 表（MCP 的 location_device
--    返回里那个）才是拓扑数据的来源。
