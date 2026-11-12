# -*- coding: utf-8 -*-
"""
MockSyslogDB：内存版数据源，不连 MySQL

方法签名和 db/ 下的真库一致，管线各层拿到的 db 参数直接换成它就能跑。
开关在 config.use_mock_db，由 db.get_db() 工厂决定，管线代码不知道 mock 存在。

样本数据在 tests/fixtures.py，跑法在 ../test.py。
"""
import time
import logging

from tests.fixtures import (
    MOCK_BLACKLIST, MOCK_DEVICES, MOCK_EVENTS, MOCK_PORTS, MOCK_RULES,
    MOCK_SEVERITY_RULES
)

logger = logging.getLogger(__name__)


class MockSyslogDB(object):
    """
    SyslogPipelineDB 的内存替身，方法签名一致，不连 MySQL

    构造时可以覆盖任意一张表，单测里按用例给最小规则集：

        db = MockSyslogDB(rules=[{...}], devices={"1.1.1.1": {"vendor": "cisco_nx"}})

    定级规则同理，传 severity_rules=[] 可以验证"缺全局兜底规则"那条 error。
    mute_rules 默认空（没有静默规则是常态），要测 L3 自己传。
    """

    def __init__(self, rules=None, events=None, devices=None, ports=None, blacklist=None,
                 severity_rules=None, mute_rules=None):
        self.rules = [dict(row) for row in (rules if rules is not None else MOCK_RULES)]
        self.events = [dict(row) for row in (events if events is not None else MOCK_EVENTS)]
        self.devices = dict(devices if devices is not None else MOCK_DEVICES)
        self.ports = dict(ports if ports is not None else MOCK_PORTS)
        self.blacklist = [dict(row) for row
                          in (blacklist if blacklist is not None else MOCK_BLACKLIST)]
        self.severity_rules = [
            dict(row) for row
            in (severity_rules if severity_rules is not None else MOCK_SEVERITY_RULES)]
        self.mute_rules = [dict(row) for row in (mute_rules or [])]
        # 落库的内容留在内存里，供断言查看
        self.alarms = []
        self.alarm_logs = []
        self.alarm_states = {}
        self.calls = {"rules": 0, "events": 0, "vendor": 0, "ports": 0,
                      "blacklist": 0, "device_info": 0, "severity": 0}
        # 置 True 模拟数据库不可用，验证各层的降级分支
        self.fail = False

    # ---------------- L0.5 ----------------

    def getBlacklistRules(self):
        self.calls["blacklist"] += 1
        if self.fail:
            return []
        rows = [dict(row) for row in self.blacklist if row.get("enabled", 1)]
        # 排序只为让加载日志稳定，黑名单没有匹配顺序
        rows.sort(key=lambda row: row.get("rule_id", 0))
        return rows

    # ---------------- L1 ----------------

    def getSyslogRules(self):
        self.calls["rules"] += 1
        if self.fail:
            return []
        return [dict(row) for row in self.rules if row.get("enabled", 1)]

    # ---------------- L2.5 ----------------

    def getSyslogEvents(self):
        self.calls["events"] += 1
        if self.fail:
            return []
        return [dict(row) for row in self.events if row.get("enabled", 1)]

    def getSeverityRules(self):
        """
        定级规则。order by 只为让加载日志稳定，真正的匹配顺序由
        SeverityIndex 按 (priority, rule_id) 排
        """
        self.calls["severity"] += 1
        if self.fail:
            return []
        rows = [dict(row) for row in self.severity_rules if row.get("enabled", 1)]
        rows.sort(key=lambda row: (row.get("priority", 100), row.get("rule_id", 0)))
        return rows

    # ---------------- L1 厂商判定 ----------------

    def getDeviceVendor(self, ip):
        """和真库一致：查不到返回 ''，查询失败返回 'failed'"""
        self.calls["vendor"] += 1
        if self.fail:
            return "failed"
        device = self.devices.get(str(ip))
        if not device:
            return ""
        return str(device.get("vendor", "") or "").strip().lower()

    def getPortNames(self, ip):
        self.calls["ports"] += 1
        if self.fail:
            return "failed"
        return [row["if_name"] for row in self.ports.get(str(ip), []) if row.get("if_name")]

    # ---------------- L2 ----------------

    def getDeviceInfo(self, ip):
        """和真库一致：查不到返回 {}，查询失败返回 'failed'"""
        self.calls["device_info"] += 1
        if self.fail:
            return "failed"
        device = self.devices.get(str(ip))
        if not device:
            return {}
        row = dict(device)
        for key in ("sysname", "sysdesc", "syscontact", "hardware", "sys_type", "vendor"):
            row.setdefault(key, "")
            row[key] = str(row[key] or "")
        return row

    def getPorts(self, ip):
        self.calls["ports"] += 1
        if self.fail:
            return "failed"
        return [dict(row) for row in self.ports.get(str(ip), []) if row.get("if_name")]

    # ---------------- L3 静默规则 ----------------

    def getMuteRules(self):
        """只返回在窗口内的，和真库一致"""
        if self.fail:
            return []
        now = str(int(time.time()))
        rows = []
        for row in self.mute_rules:
            if not row.get("enabled", 1):
                continue
            start = str(row.get("start_time", "") or "")
            end = str(row.get("end_time", "") or "")
            if start and start > now:
                continue
            if end and end < now:
                continue
            rows.append(dict(row))
        rows.sort(key=lambda row: row.get("rule_id", 0))
        return rows

    # ---------------- L5 规则 ----------------

    def getStateRules(self):
        return []

    # ---------------- L4 落库 ----------------

    def addAlarm(self, data):
        if self.fail:
            return 0
        row = dict(data)
        row["alarm_id"] = len(self.alarms) + 1
        # 和真库的 insert 默认值保持一致，否则断言里取不到这几个键
        row.setdefault("alarm_type", "syslog")
        row.setdefault("status", "0")
        row.setdefault("state", "open")
        row.setdefault("severity", 3)
        row.setdefault("counter", 1)
        # 和真库一致存 0/1，不存 True/False —— 断言在两边表现要一样
        row["muted"] = 1 if row.get("muted") else 0
        row["mute_rule_id"] = int(row.get("mute_rule_id", 0))
        self.alarms.append(row)
        return row["alarm_id"]

    # 和真库的 update_keys 一致。不照着限的话 mock 能更新任意列，
    # 单测过了上线却发现某一列真库压根不更新
    UPDATE_KEYS = ("last_seen", "counter", "severity", "state", "clear_time",
                   "keyword", "group_name", "msg")

    def updateAlarmByFingerprint(self, fingerprint, data):
        if self.fail:
            return "failed"
        allowed = {k: v for k, v in data.items() if k in self.UPDATE_KEYS}
        if not allowed:
            return "failed"
        for row in reversed(self.alarms):
            if row.get("fingerprint") == fingerprint and row.get("state") == "open":
                row.update(allowed)
                return 1
        return 0

    def setAlarmMute(self, alarm_id, muted, rule_id=0):
        """只动 muted / mute_rule_id，不碰 status"""
        if self.fail:
            return "failed"
        flag = 1 if muted else 0
        for row in self.alarms:
            if row.get("alarm_id") == int(alarm_id):
                row["muted"] = flag
                row["mute_rule_id"] = int(rule_id) if flag else 0
                return 1
        return 0

    def getMutedOpenAlarms(self, limit=5000):
        """还在告警中且被静默的，L3 到期扫描用"""
        if self.fail:
            return []
        rows = [dict(row) for row in self.alarms
                if row.get("state") == "open" and row.get("muted")]
        rows.sort(key=lambda row: str(row.get("last_seen", "")), reverse=True)
        return rows[:int(limit)]

    def addAlarmLogs(self, rows):
        if self.fail:
            return 0
        for row in rows or []:
            item = dict(row)
            item["log_id"] = len(self.alarm_logs) + 1
            # 和真库的 insert 默认值一致
            item["is_read"] = 1 if item.get("is_read") else 0
            self.alarm_logs.append(item)
        return len(rows or [])

    def getAlarmLogs(self, fingerprint, start_ts, end_ts, limit=200, unread_only=False):
        """和真库一致：指纹 + 时间范围，两头闭区间"""
        if self.fail:
            return []
        rows = [dict(row) for row in self.alarm_logs
                if row.get("fingerprint") == fingerprint
                and str(start_ts) <= str(row.get("ingest_ts", "")) <= str(end_ts)
                and (not unread_only or not row.get("is_read"))]
        rows.sort(key=lambda row: str(row.get("ingest_ts", "")))
        return rows[:int(limit)]

    def markAlarmLogsRead(self, log_ids=None, fingerprint=None,
                          start_ts=None, end_ts=None):
        if self.fail:
            return "failed"
        if log_ids:
            wanted = {int(i) for i in log_ids}
            hits = [row for row in self.alarm_logs if row.get("log_id") in wanted]
        elif fingerprint and start_ts is not None and end_ts is not None:
            hits = [row for row in self.alarm_logs
                    if row.get("fingerprint") == fingerprint
                    and str(start_ts) <= str(row.get("ingest_ts", "")) <= str(end_ts)]
        else:
            return "failed"
        for row in hits:
            row["is_read"] = 1
        return len(hits)

    def getAlarmLogsByAlarm(self, alarm_id, limit=200, pad_seconds=2,
                            retention_days=7, unread_only=False):
        if self.fail:
            return {}
        alarm = None
        for row in self.alarms:
            if row.get("alarm_id") == int(alarm_id):
                alarm = row
                break
        if alarm is None:
            return None

        def to_int(value):
            try:
                return int(value)
            except (TypeError, ValueError):
                return 0

        pad = int(pad_seconds)
        start = to_int(alarm.get("first_seen")) - pad
        end = to_int(alarm.get("clear_time") or alarm.get("last_seen")) + pad
        expired = bool(end) and end < int(time.time()) - int(retention_days) * 86400
        if start <= 0 or end <= 0:
            return {"alarm": dict(alarm), "logs": [], "truncated": False,
                    "expired": False, "start_ts": start, "end_ts": end}
        logs = self.getAlarmLogs(alarm.get("fingerprint"), start, end, limit=limit + 1,
                                 unread_only=unread_only)
        return {"alarm": dict(alarm), "logs": logs[:limit],
                "truncated": len(logs) > limit, "expired": expired,
                "start_ts": start, "end_ts": end}

    def delOldAlarmLogs(self, before_ts, batch=10000):
        """和真库一致：按 ingest_ts 删"""
        if self.fail:
            return "failed"
        keep = [row for row in self.alarm_logs
                if str(row.get("ingest_ts", "")) >= str(before_ts)]
        removed = len(self.alarm_logs) - len(keep)
        self.alarm_logs = keep
        return removed

    def upsertAlarmState(self, data):
        if self.fail:
            return "failed"
        self.alarm_states[data["fingerprint"]] = dict(data)
        return "success"

    def getOpenAlarmStates(self, limit=5000):
        if self.fail:
            return []
        rows = [dict(row) for row in self.alarm_states.values() if row.get("state") == "open"]
        return rows[:int(limit)]

    def delOldAlarmStates(self, before_ts):
        if self.fail:
            return "failed"
        removed = 0
        for key in list(self.alarm_states.keys()):
            row = self.alarm_states[key]
            if row.get("state") != "open" and str(row.get("updated_time", "")) < str(before_ts):
                self.alarm_states.pop(key, None)
                removed += 1
        return removed

    # ---------------- 辅助 ----------------

    def event_attr(self, event_code):
        """按事件码取属性，L2.5 第一步用，L1 不调。不含 severity"""
        for row in self.events:
            if row.get("event_code") == event_code:
                return dict(row)
        return {}
