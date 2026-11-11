# -*- coding: utf-8 -*-
"""
告警落库

L6 还没实现，这里先把写入接口定下来，L6 落地时直接调。

两张表：
    alarm_list          看板读，central-server/api/api_alarm.py 也读这张
    syslog_alarm_state  L5 状态机持久化，进程重启后接着算
"""
import logging

from db.database import MySQLConnection

logger = logging.getLogger(__name__)

ALARM_FIELDS = [
    "ip", "hostname", "alarm_type", "group_label", "msg", "group_name", "alarm_object",
    "keyword", "status", "create_time", "fingerprint", "severity", "state", "first_seen",
    "last_seen", "counter", "clear_time",
]

REQUIRED_FIELDS = ["ip", "hostname", "group_label", "msg", "group_name",
                   "alarm_object", "keyword"]


class AlarmDB(object):
    """告警与告警状态的读写"""

    # ---------------- alarm_list ----------------

    def addAlarm(self, data):
        """
        插入一条告警

        :return: alarm_id；失败返回 0
        """
        for key in REQUIRED_FIELDS:
            if key not in data:
                logger.error("======AlarmDB addAlarm 参数不足========\n缺少 %s", key)
                return 0

        sql = '''
        insert into alarm_list(ip, hostname, alarm_type, group_label, msg, group_name,
                               alarm_object, keyword, status, create_time, fingerprint,
                               severity, state, first_seen, last_seen, counter, clear_time)
        values(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        '''
        params = (
            data["ip"], data["hostname"], data.get("alarm_type", "syslog"),
            data["group_label"], str(data["msg"])[:500], str(data["group_name"])[:100],
            str(data["alarm_object"])[:100], str(data["keyword"])[:100],
            data.get("status", "0"), str(data.get("create_time", "")),
            data.get("fingerprint", ""), data.get("severity", 3),
            data.get("state", "open"), str(data.get("first_seen", "")),
            str(data.get("last_seen", "")), int(data.get("counter", 1)),
            str(data.get("clear_time", "")),
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

        :return: 影响行数；失败返回 "failed"
        """
        update_keys = ["last_seen", "counter", "severity", "state", "clear_time"]
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

    # ---------------- syslog_alarm_state ----------------

    def upsertAlarmState(self, data):
        """
        写一条告警状态，按指纹覆盖。L5 每处理一条事件都会调。

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
