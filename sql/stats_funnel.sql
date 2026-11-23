-- ============================================================
-- 告警漏斗统计：日志总量 -> 按处理状态分三类
--
-- 只查 alarm_list 和 alarm_log 两张表。
--
-- ========== status 分组口径 ==========
--
--   pending   status='0'              待处理。L9 写入的初始值
--   handled   status IN ('1','2')     已确认 + 已处理，人工在看板上点的
--   ignored   status IN ('3','4','5') 人工忽略 + 人工屏蔽 + 系统判定忽略
--                                     （3/4 是人点的，5 由 L9 自动写）
--
-- 三组互斥，相加等于 alarm_list 总行数。
--
-- ========== 其余两个维度 ==========
--
-- muted 和 status 是**正交**的：L8 静默规则压住通知，但那行告警的
-- status 可能还是 0（待处理）。所以 muted 单独列一个数，不混进上面
-- 三组里，否则同一行会被重复计数。
--
-- state（open告警中 / clear已恢复 / idle=ignore判定）同样正交，
-- 单独列 open 的数量 —— 这个数才是"当前还需要盯的告警"，
-- 和看板上看到的条数对得上。
--
-- ========== 日志总量 ==========
--
-- alarm_log 的行数（一条日志一行）。注意这是**过了 L2 黑名单之后**的
-- 量：被黑名单拦下的日志在解析前就丢弃，从没写进 alarm_log。
-- 另外这张表只留 7 天。
--
-- ========== 时间范围 ==========
--
-- 两张表的时间列都是 VARCHAR(10) 存 epoch 秒，不是 datetime。
-- 按区间统计在对应 WHERE 里加（epoch 定长10位，字典序==数值序，
-- 比字符串能走索引；空串会被当成"很早"，所以要带 <> ''）：
--   alarm_log ： AND ingest_ts   <> '' AND ingest_ts   >= CAST(UNIX_TIMESTAMP('2026-11-01 00:00:00') AS CHAR)
--   alarm_list： AND create_time <> '' AND create_time >= CAST(UNIX_TIMESTAMP('2026-11-01 00:00:00') AS CHAR)
-- ============================================================

SELECT
    (SELECT COUNT(*) FROM alarm_log)                                          AS raw_logs,
    (SELECT COUNT(*) FROM alarm_list)                                         AS total_alarms,
    (SELECT COUNT(*) FROM alarm_list WHERE status = '0')                      AS pending,
    (SELECT COUNT(*) FROM alarm_list WHERE status IN ('1','2'))               AS handled,
    (SELECT COUNT(*) FROM alarm_list WHERE status IN ('3','4','5'))           AS ignored,
    -- 下面两个和上面三组正交，不参与相加
    (SELECT COUNT(*) FROM alarm_list WHERE muted = 1)                         AS muted_rows,
    (SELECT COUNT(*) FROM alarm_list WHERE state = 'open')                     AS still_open;
