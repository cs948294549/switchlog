# -*- coding: utf-8 -*-
"""
告警落库

L6 / L7 / L8 / L9 都还没实现，这里先把写入接口定下来，各层落地时直接调。

四张表：
    alarm_log           L6 写，原子告警，一条日志一行，只留 7 天
    alarm_list          L6 写、L7 更状态、L8 回写静默标记，看板读，
                        central-server/api/api_alarm.py 也读这张
    syslog_alarm_state  L7 状态机持久化，进程重启后接着算
    syslog_mute_rule    L8 读，静默规则

alarm_log 和 alarm_list 靠 fingerprint 关联：一条聚合告警由 N 条原子
记录支撑，看板点一条告警就能下钻到具体哪几条日志。
"""
import time
import logging

from db.database import MySQLConnection

logger = logging.getLogger(__name__)

# 两张表的字段清单，给调用方对照用（代码里不读这两个常量）。
# muted / mute_rule_id 由 muteAlarm() 单独回写，不在 addAlarm 的入参里
ALARM_FIELDS = [
    "ip", "hostname", "alarm_type", "group_label", "msg", "group_name", "alarm_object",
    "keyword", "status", "create_time", "fingerprint", "vendor", "hardware", "object_name",
    "object_alias", "severity", "state", "first_seen", "last_seen", "counter", "clear_time",
    "muted", "mute_rule_id",
]

ALARM_LOG_FIELDS = [
    "fingerprint", "ip", "hostname", "event_code", "alarm_object", "severity",
    "mnemonic", "rule_id", "severity_rule_id", "msg", "is_read", "ingest_ts",
]

REQUIRED_FIELDS = ["ip", "hostname", "group_label", "msg", "group_name",
                   "alarm_object", "keyword"]


class AlarmDB(object):
    """告警与告警状态的读写"""

    # ---------------- alarm_list ----------------

    def addAlarm(self, data):
        """
        插入一条告警

        muted / mute_rule_id 在入参里，一次写进去 —— 被静默的告警照样
        入库（割接完要能回看那段时间发生了什么），只是不发通知。
        先 INSERT（muted=0）再 UPDATE 的话，中间那一瞬间看板轮询到会显示成
        "割接期间有条没静默的告警"。L8 的判定在 L9 落库之前就有结果，
        没必要分两次写。

        :return: alarm_id；失败返回 0
        """
        for key in REQUIRED_FIELDS:
            if key not in data:
                logger.error("======AlarmDB addAlarm 参数不足========\n缺少 %s", key)
                return 0

        sql = '''
        insert into alarm_list(ip, hostname, alarm_type, group_label, msg, group_name,
                               alarm_object, keyword, status, create_time, fingerprint,
                               vendor, hardware, object_name, object_alias, severity, state,
                               first_seen, last_seen, counter, clear_time, muted, mute_rule_id)
        values(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        '''
        params = (
            data["ip"], data["hostname"], data.get("alarm_type", "syslog"),
            data["group_label"], str(data["msg"])[:500], str(data["group_name"])[:100],
            str(data["alarm_object"])[:100], str(data["keyword"])[:100],
            data.get("status", "0"), str(data.get("create_time", "")),
            data.get("fingerprint", ""),
            str(data.get("vendor", "") or "")[:30], str(data.get("hardware", "") or "")[:100],
            str(data.get("object_name", "") or "")[:100],
            str(data.get("object_alias", "") or "")[:200],
            data.get("severity", 3),
            data.get("state", "open"), str(data.get("first_seen", "")),
            str(data.get("last_seen", "")), int(data.get("counter", 1)),
            str(data.get("clear_time", "")),
            1 if data.get("muted") else 0, int(data.get("mute_rule_id", 0)),
        )
        try:
            with MySQLConnection() as conn:
                cursor = conn.cursor
                cursor.execute(sql, params)
                conn.conn.commit()
                return cursor.lastrowid
        except Exception as err:
            logger.error("======AlarmDB addAlarm error========\n%s", err)
            return 0

    def updateAlarmByFingerprint(self, fingerprint, data):
        """
        更新该指纹最近一条未恢复告警；没有未恢复记录时不动历史行

        keyword / group_name 也在白名单里：闪断升级时 event_code 从
        IF_DOWN 变成 IF_FLAP，这一列不跟着改的话，看板上级别提了但
        事件码还是 IF_DOWN，看不出这是闪断。
        fingerprint 不在白名单 —— 它是定位条件，改了就找不到这一行了。

        :return: 影响行数；失败返回 "failed"
        """
        update_keys = ["last_seen", "counter", "severity", "state", "clear_time",
                       "keyword", "group_name", "msg"]
        conditions = []
        params = []
        for key in update_keys:
            if key in data:
                conditions.append(key + " = %s")
                params.append(data[key])
        if not conditions:
            return "failed"

        sql = ("update alarm_list set " + ", ".join(conditions) +
               " where fingerprint=%s and state='open' order by alarm_id desc limit 1")
        params.append(fingerprint)
        try:
            with MySQLConnection() as conn:
                cursor = conn.cursor
                cursor.execute(sql, tuple(params))
                conn.conn.commit()
                return cursor.rowcount
        except Exception as err:
            logger.error("======AlarmDB updateAlarmByFingerprint error========\n%s", err)
            return "failed"

    def setAlarmMute(self, alarm_id, muted, rule_id=0):
        """
        改一条已存在告警的静默标记

        新开的告警不走这里 —— addAlarm 的时候 mute 已经判完，一次写进去。
        这个方法只给"告警已经开着，静默状态后来变了"用，两个方向：

            窗口开始：已开着的告警进了割接窗口 -> muted=1
            窗口结束：窗口过了，告警还没好 -> muted=0，恢复通知

        只动 muted / mute_rule_id 两列，不碰 status —— 那是人工处理状态。
        两者分开存就是为了这一刻：窗口过了只需要把 muted 改回 0，
        人工屏蔽（status=4）该留着，不能一起清掉。

        :param muted: True=静默 False=恢复通知
        :return: 影响行数；失败返回 "failed"
        """
        sql = "update alarm_list set muted=%s, mute_rule_id=%s where alarm_id=%s"
        flag = 1 if muted else 0
        try:
            with MySQLConnection() as conn:
                cursor = conn.cursor
                cursor.execute(sql, (flag, int(rule_id) if flag else 0, int(alarm_id)))
                conn.conn.commit()
                return cursor.rowcount
        except Exception as err:
            logger.error("======AlarmDB setAlarmMute error========\n%s", err)
            return "failed"

    def getMutedOpenAlarms(self, limit=5000):
        """
        取还在告警中、且被静默的记录。L8 的到期扫描用

        为什么需要这个扫描：窗口到期是时间到了，不是来了新日志。一个口在
        割接窗口里 down 了一直没好，窗口结束之后不会再有新日志进管线
        （L7 看到已有活跃告警只累加，也不会重新判 mute），这条告警就会
        永远 muted —— 割接结束了故障还在，但没人收到通知。

        所以 L8 要定期扫这些记录，重新判一遍当前时刻还命不命中静默规则，
        不命中就 setAlarmMute(alarm_id, False) 放出来。

        :return: [{...}]；失败返回 []
        """
        sql = '''
        select alarm_id, fingerprint, ip, keyword, alarm_object, severity,
               mute_rule_id, first_seen, last_seen
        from alarm_list
        where state='open' and muted=1 order by last_seen desc limit %s
        '''
        proper = ["alarm_id", "fingerprint", "ip", "keyword", "alarm_object", "severity",
                  "mute_rule_id", "first_seen", "last_seen"]
        try:
            with MySQLConnection() as conn:
                return conn.query(sql, params=(int(limit),), proper=proper)
        except Exception as err:
            logger.error("======AlarmDB getMutedOpenAlarms error========\n%s", err)
            return []

    # ---------------- alarm_log ----------------

    def addAlarmLogs(self, rows):
        """
        批量插入原子告警。日志量级的写入，必须批量 —— 一条一次 insert
        在日志风暴时扛不住

        :param rows: [{ALARM_LOG_FIELDS 的字段}]
        :return: 插入行数；失败返回 0
        """
        if not rows:
            return 0

        sql = '''
        insert into alarm_log(fingerprint, ip, hostname, event_code, alarm_object,
                              severity, mnemonic, rule_id, severity_rule_id, msg,
                              ingest_ts)
        values(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        '''
        params = []
        for row in rows:
            params.append((
                row.get("fingerprint", ""), row.get("ip", ""),
                str(row.get("hostname", ""))[:300], str(row.get("event_code", ""))[:50],
                str(row.get("alarm_object", ""))[:100], int(row.get("severity", 3)),
                str(row.get("mnemonic", ""))[:80], int(row.get("rule_id", 0)),
                int(row.get("severity_rule_id", 0)), str(row.get("msg", ""))[:1024],
                str(row.get("ingest_ts", "")),
            ))
        try:
            with MySQLConnection() as conn:
                cursor = conn.cursor
                cursor.executemany(sql, params)
                conn.conn.commit()
                return cursor.rowcount
        except Exception as err:
            logger.error("======AlarmDB addAlarmLogs error========\n%s", err)
            return 0

    def getAlarmLogs(self, fingerprint, start_ts, end_ts, limit=200, unread_only=False):
        """
        取支撑某一次告警的原子记录，看板下钻用

        **必须带时间范围。** 指纹是 md5(ip|event_code|alarm_object)，不含
        时间 —— 同一个口上周那次 down 和今天这次是同一个指纹。只按指纹查
        会把这个口所有历史故障的日志混在一起返回。

        指纹定位"哪个口的哪类故障"，时间范围定位"哪一次"，两个一起才唯一。
        范围取 alarm_list 那一行的 first_seen 和 last_seen（已恢复的用
        clear_time 作上界），所以正确的用法是 getAlarmLogsByAlarm()，
        本方法是它的底层。

        时间两头都是闭区间：L6 的段边界是"间隔大于窗口"切出来的，相邻两次
        故障之间必然有一个大于窗口的空档，闭区间不会互相串。

        ingest_ts 是定长 10 位的 epoch 字符串，字符串比较和数值比较等价
        （到 2286 年才会多一位）。

        :param start_ts: 下界，含
        :param end_ts:   上界，含
        :param unread_only: 只取未读的，排查时过掉看过的日志
        :return: [{...}]；失败返回 []
        """
        sql = '''
        select log_id, fingerprint, ip, hostname, event_code, alarm_object, severity,
               mnemonic, rule_id, severity_rule_id, msg, is_read, ingest_ts
        from alarm_log
        where fingerprint=%s and ingest_ts >= %s and ingest_ts <= %s {}
        order by ingest_ts limit %s
        '''.format("and is_read=0" if unread_only else "")
        proper = ["log_id", "fingerprint", "ip", "hostname", "event_code", "alarm_object",
                  "severity", "mnemonic", "rule_id", "severity_rule_id", "msg",
                  "is_read", "ingest_ts"]
        try:
            with MySQLConnection() as conn:
                return conn.query(sql, params=(fingerprint, str(start_ts), str(end_ts),
                                               int(limit)), proper=proper)
        except Exception as err:
            logger.error("======AlarmDB getAlarmLogs error========\n%s", err)
            return []

    def markAlarmLogsRead(self, log_ids=None, fingerprint=None,
                          start_ts=None, end_ts=None):
        """
        标记已读。两种用法，二选一：

            markAlarmLogsRead(log_ids=[1, 2, 3])          勾选几条
            markAlarmLogsRead(fingerprint=fp,
                              start_ts=a, end_ts=b)       整段全标

        第二种给"看完这条告警的日志，整段标已读"用，范围和
        getAlarmLogs 一致。

        :return: 影响行数；参数不对或失败返回 "failed"
        """
        if log_ids:
            marks = ",".join(["%s"] * len(log_ids))
            sql = "update alarm_log set is_read=1 where log_id in ({})".format(marks)
            params = tuple(int(i) for i in log_ids)
        elif fingerprint and start_ts is not None and end_ts is not None:
            sql = ("update alarm_log set is_read=1 "
                   "where fingerprint=%s and ingest_ts >= %s and ingest_ts <= %s")
            params = (fingerprint, str(start_ts), str(end_ts))
        else:
            logger.error("======AlarmDB markAlarmLogsRead 参数不足========\n"
                         "要么给 log_ids，要么给 fingerprint + 时间范围")
            return "failed"

        try:
            with MySQLConnection() as conn:
                cursor = conn.cursor
                cursor.execute(sql, params)
                conn.conn.commit()
                return cursor.rowcount
        except Exception as err:
            logger.error("======AlarmDB markAlarmLogsRead error========\n%s", err)
            return "failed"

    def getAlarmLogsByAlarm(self, alarm_id, limit=200, pad_seconds=2,
                            retention_days=7, unread_only=False):
        """
        按告警 ID 下钻到支撑它的日志。看板点一条告警就调这个

        自己去 alarm_list 取指纹和时间范围，调用方不用拼：

            select fingerprint, first_seen, last_seen, clear_time from alarm_list
            -> getAlarmLogs(fingerprint, first_seen, 上界)

        上界取 clear_time（已恢复）或 last_seen（还在告警中）。未恢复的
        告警 last_seen 会一直往后走，所以每次查都要重新读，不能缓存。

        pad_seconds 给两头各放宽几秒：L6 写 alarm_log 是攒批的，一条日志的
        ingest_ts 和 L7 更新 alarm_list.last_seen 的时刻之间有几秒的差，
        卡死边界会漏掉最后一两条。放宽的代价是可能多带进相邻故障的日志，
        但相邻两次故障之间有一个大于窗口（至少 300s）的空档，几秒的余量
        不可能串到上一次去。

        expired 这个返回值很重要：alarm_list 是永久的，alarm_log 只留 7 天，
        所以老告警查出来 logs 一定是空的。不区分的话看板会把它显示成
        "这条告警没有日志支撑"，而实际上是日志过期了 —— alarm_list.counter
        还记着当时有几条。

        :param retention_days: alarm_log 的保留天数，和
                               aggregate.DEFAULT_LOG_RETENTION_DAYS 保持一致
        :param unread_only: 只取未读的
        :return: {"alarm": {...}, "logs": [...], "truncated": bool,
                  "expired": bool, "start_ts": int, "end_ts": int}；
                 查不到这条告警返回 None；查询失败返回 {}

        返回里带 start_ts / end_ts 是为了接着调 markAlarmLogsRead()
        整段标已读，不用调用方自己再算一遍边界
        """
        head_sql = '''
        select fingerprint, ip, event_code, alarm_object, first_seen, last_seen,
               clear_time, counter, state
        from alarm_list where alarm_id=%s
        '''
        head_proper = ["fingerprint", "ip", "event_code", "alarm_object", "first_seen",
                       "last_seen", "clear_time", "counter", "state"]
        try:
            with MySQLConnection() as conn:
                alarm = conn.query_one(head_sql, params=(int(alarm_id),),
                                       proper=head_proper)
        except Exception as err:
            logger.error("======AlarmDB getAlarmLogsByAlarm error========\n%s", err)
            return {}
        if not alarm:
            return None

        pad = int(pad_seconds)
        start = self._to_int(alarm.get("first_seen")) - pad
        # 已恢复的用 clear_time 作上界，还在告警中的用 last_seen
        upper = alarm.get("clear_time") or alarm.get("last_seen")
        end = self._to_int(upper) + pad
        # 告警结束时间早于保留期起点，日志已经被清掉了
        expired = bool(end) and end < int(time.time()) - int(retention_days) * 86400

        if start <= 0 or end <= 0:
            logger.error("======alarm_list 时间字段为空========\nalarm_id=%s 查不出日志",
                         alarm_id)
            return {"alarm": alarm, "logs": [], "truncated": False, "expired": False}

        logs = self.getAlarmLogs(alarm["fingerprint"], start, end, limit=limit + 1,
                                 unread_only=unread_only)
        truncated = len(logs) > limit
        return {"alarm": alarm, "logs": logs[:limit], "truncated": truncated,
                "expired": expired, "start_ts": start, "end_ts": end}

    @staticmethod
    def _to_int(value):
        try:
            return int(value)
        except (TypeError, ValueError):
            return 0

    def delOldAlarmLogs(self, before_ts, batch=10000):
        """
        清理过期原子记录。按 ingest_ts 删，走 idx_ingest_ts

        分批删：一次删几十万行会长时间持锁，维护线程循环调到返回 0 为止

        :param before_ts: epoch 秒，早于这个时刻的删掉
        :return: 本批删除行数；失败返回 "failed"
        """
        sql = "delete from alarm_log where ingest_ts < %s limit %s"
        try:
            with MySQLConnection() as conn:
                cursor = conn.cursor
                cursor.execute(sql, (str(before_ts), int(batch)))
                conn.conn.commit()
                return cursor.rowcount
        except Exception as err:
            logger.error("======AlarmDB delOldAlarmLogs error========\n%s", err)
            return "failed"

    # ---------------- syslog_mute_rule ----------------

    def getMuteRules(self):
        """
        L8 的静默规则。只取在窗口内的 —— 过期规则留在表里供回溯，
        但不参与匹配

        end_time 空=永久静默，start_time 空=立即生效，所以两头都要
        判空。时间是 VARCHAR 存的 epoch 秒，定长 10 位，字符串比较
        和数值比较等价

        :return: [{...}]；失败返回 []
        """
        sql = '''
        select rule_id, ip_reg, event_code_reg, object_reg, start_time, end_time, descr
        from syslog_mute_rule
        where enabled=1
          and (start_time='' or start_time <= %s)
          and (end_time='' or end_time >= %s)
        order by rule_id
        '''
        now = str(int(time.time()))
        proper = ["rule_id", "ip_reg", "event_code_reg", "object_reg",
                  "start_time", "end_time", "descr"]
        try:
            with MySQLConnection() as conn:
                return conn.query(sql, params=(now, now), proper=proper)
        except Exception as err:
            logger.error("======AlarmDB getMuteRules error========\n%s", err)
            return []

    # ---------------- syslog_alarm_state ----------------

    def upsertAlarmState(self, data):
        """
        写一条告警状态，按指纹覆盖。L7 每处理一条事件都会调。

        :return: "success" / "failed"
        """
        sql = '''
        insert into syslog_alarm_state(fingerprint, ip, event_code, alarm_object, mode,
                                       state, severity, base_severity, first_seen,
                                       last_seen, counter, raise_count, clear_count,
                                       flapping, alarm_id, updated_time)
        values(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        on duplicate key update
            ip=values(ip), event_code=values(event_code), alarm_object=values(alarm_object),
            mode=values(mode), state=values(state), severity=values(severity),
            base_severity=values(base_severity), first_seen=values(first_seen),
            last_seen=values(last_seen), counter=values(counter),
            raise_count=values(raise_count), clear_count=values(clear_count),
            flapping=values(flapping), alarm_id=values(alarm_id),
            updated_time=values(updated_time)
        '''
        params = (
            data["fingerprint"], data.get("ip", ""), data.get("event_code", ""),
            data.get("alarm_object", ""), data.get("mode", "raise"),
            data.get("state", "idle"), int(data.get("severity", 3)),
            int(data.get("base_severity", 3)), str(data.get("first_seen", "")),
            str(data.get("last_seen", "")), int(data.get("counter", 0)),
            int(data.get("raise_count", 0)), int(data.get("clear_count", 0)),
            1 if data.get("flapping") else 0, int(data.get("alarm_id", 0)),
            str(data.get("updated_time", "")),
        )
        try:
            with MySQLConnection() as conn:
                conn.execute(sql, params)
            return "success"
        except Exception as err:
            logger.error("======AlarmDB upsertAlarmState error========\n%s", err)
            return "failed"

    def getOpenAlarmStates(self, limit=5000):
        """进程启动时回放：还没恢复的告警状态"""
        sql = '''
        select fingerprint, ip, event_code, alarm_object, mode, state, severity,
               base_severity, first_seen, last_seen, counter, raise_count,
               clear_count, flapping, alarm_id
        from syslog_alarm_state where state='open' order by last_seen desc limit %s
        '''
        proper = ["fingerprint", "ip", "event_code", "alarm_object", "mode", "state",
                  "severity", "base_severity", "first_seen", "last_seen", "counter",
                  "raise_count", "clear_count", "flapping", "alarm_id"]
        try:
            with MySQLConnection() as conn:
                return conn.query(sql, (int(limit),), proper=proper)
        except Exception as err:
            logger.error("======AlarmDB getOpenAlarmStates error========\n%s", err)
            return []

    def delOldAlarmStates(self, before_ts):
        """清理已恢复且久未更新的状态行，防止表无限增长"""
        sql = "delete from syslog_alarm_state where state<>'open' and updated_time<%s"
        try:
            with MySQLConnection() as conn:
                return conn.execute(sql, (str(int(before_ts)),))
        except Exception as err:
            logger.error("======AlarmDB delOldAlarmStates error========\n%s", err)
            return "failed"
