# -*- coding: utf-8 -*-
"""
MockSyslogDB：内存版数据源，不连 MySQL

方法签名和 db/ 下的真库一致，管线各层拿到的 db 参数直接换成它就能跑。
开关在 config.use_mock_db，由 db.get_db() 工厂决定，管线代码不知道 mock 存在。

样本数据在 tests/fixtures.py，跑法在 tests/replay.py。
"""
import logging

from tests.fixtures import (
    MOCK_BLACKLIST, MOCK_DEVICES, MOCK_EVENTS, MOCK_PORTS, MOCK_RULES
)

logger = logging.getLogger(__name__)


class MockSyslogDB(object):
    """
    SyslogPipelineDB 的内存替身，方法签名一致，不连 MySQL

    构造时可以覆盖任意一张表，单测里按用例给最小规则集：

        db = MockSyslogDB(rules=[{...}], devices={"1.1.1.1": {"vendor": "cisco_nx"}})
    """

    def __init__(self, rules=None, events=None, devices=None, ports=None, blacklist=None):
        self.rules = [dict(row) for row in (rules if rules is not None else MOCK_RULES)]
        self.events = [dict(row) for row in (events if events is not None else MOCK_EVENTS)]
        self.devices = dict(devices if devices is not None else MOCK_DEVICES)
        self.ports = dict(ports if ports is not None else MOCK_PORTS)
        self.blacklist = [dict(row) for row
                          in (blacklist if blacklist is not None else MOCK_BLACKLIST)]
        # 落库的内容留在内存里，供断言查看
        self.alarms = []
        self.alarm_states = {}
        self.calls = {"rules": 0, "events": 0, "vendor": 0, "ports": 0,
                      "blacklist": 0, "device_info": 0}
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

    def getSyslogEvents(self):
        self.calls["events"] += 1
        if self.fail:
            return []
        return [dict(row) for row in self.events if row.get("enabled", 1)]

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

    # ---------------- L3 / L5 规则 ----------------

    def getSuppressRules(self):
        return []

    def getStateRules(self):
        return []

    # ---------------- L6 落库 ----------------

    def addAlarm(self, data):
        if self.fail:
            return 0
        row = dict(data)
        row["alarm_id"] = len(self.alarms) + 1
        self.alarms.append(row)
        return row["alarm_id"]

    def updateAlarmByFingerprint(self, fingerprint, data):
        if self.fail:
            return "failed"
        for row in reversed(self.alarms):
            if row.get("fingerprint") == fingerprint and row.get("state") == "open":
                row.update(data)
                return 1
        return 0

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
        """按事件码取属性，L2 之后确定 severity 用，L1 不调"""
        for row in self.events:
            if row.get("event_code") == event_code:
                return dict(row)
        return {}


# ============================================================
# 报文样本：(源IP, 原始报文, 期望 event_code, 期望 object)
#
# 第 1~5 条是设计 §4.7 的 port-channel 掉线现场，五条日志必须收敛成
# 两个指纹：LAG_DOWN/port-channel38 三条、IF_DOWN/Ethernet1/38 两条。
# 后面几条逐个踩兜底路径和消歧路径。
