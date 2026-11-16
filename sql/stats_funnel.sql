-- 告警漏斗统计：原始日志 -> 聚合告警 -> 有效告警
-- 口径说明：
--   原始日志接收量 = 黑名单拦截量(syslog_black_list.hit_count 累计) + alarm_log 实际入库条数
--     （被 L2 黑名单命中的日志在解析前就丢弃，不会写入 alarm_log，必须两者相加才是完整接收量）
--   系统屏蔽聚合告警 = status=5（L9系统判定ignore） 或 muted=1（L8静默压制），两者并列统计 + 合计
--   有效告警 = 全部聚合告警 - 系统屏蔽聚合告警（即 status!=5 且 muted=0）
-- 时间范围：以下默认全量统计。按天/按区间统计时，在各 SELECT 的 WHERE 里加：
--   AND create_time >= '2026-11-01 00:00:00' AND create_time < '2026-11-12 00:00:00'   -- alarm_list
--   AND ingest_ts   >= '2026-11-01 00:00:00' AND ingest_ts   < '2026-11-12 00:00:00'   -- alarm_log
--   黑名单 hit_count 是累计计数器，没有时间戳，无法按区间拆分，只能取全量。

-- 1. 黑名单拦截的原始日志数（L2层丢弃，从未进入 alarm_log）
SELECT COALESCE(SUM(hit_count), 0) AS blacklist_dropped
FROM syslog_black_list;

-- 2. alarm_log 实际原始日志条数（过了黑名单、进入管线解析的原子日志）
SELECT COUNT(*) AS raw_log_count
FROM alarm_log;

-- 3. alarm_list 全部聚合告警数量
SELECT COUNT(*) AS total_aggregated
FROM alarm_list;

-- 4. 系统屏蔽聚合告警数量：status=5 与 muted=1 分开列 + 合计（去重，避免同时满足两者被算两次）
SELECT
    SUM(CASE WHEN status = '5' THEN 1 ELSE 0 END)              AS suppressed_by_status5,
    SUM(CASE WHEN muted = 1    THEN 1 ELSE 0 END)               AS suppressed_by_muted,
    SUM(CASE WHEN status = '5' OR muted = 1 THEN 1 ELSE 0 END) AS suppressed_total
FROM alarm_list;

-- 5. 有效告警数量（排除系统屏蔽后，实际会展示给人工处理的聚合告警）
SELECT COUNT(*) AS effective_alarms
FROM alarm_list
WHERE status != '5' AND muted = 0;

-- 6. 一把梭：完整漏斗汇总（单行输出，便于报表/监控直接取值）
SELECT
    (SELECT COALESCE(SUM(hit_count), 0) FROM syslog_black_list)              AS blacklist_dropped,
    (SELECT COUNT(*) FROM alarm_log)                                        AS raw_log_count,
    (SELECT COALESCE(SUM(hit_count), 0) FROM syslog_black_list)
        + (SELECT COUNT(*) FROM alarm_log)                                 AS total_received_logs,
    (SELECT COUNT(*) FROM alarm_list)                                       AS total_aggregated,
    (SELECT COUNT(*) FROM alarm_list WHERE status = '5' OR muted = 1)      AS suppressed_total,
    (SELECT COUNT(*) FROM alarm_list WHERE status != '5' AND muted = 0)    AS effective_alarms;
