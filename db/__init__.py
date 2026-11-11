# -*- coding: utf-8 -*-
"""
数据源工厂

管线各层只接受注入的 db，不知道背后是真库还是 mock。
开关在 config.use_mock_db 一处，不在各层的代码里分散判断。

    from db import get_rule_db, get_device_db

    parser = SyslogParser(db=get_rule_db())
    enricher = DeviceEnricher(db=get_device_db())
"""
import logging
import threading

from config.config import Config

logger = logging.getLogger(__name__)

_lock = threading.Lock()
_instances = {}


def _build(kind):
    if Config.use_mock_db:
        from tests.mock_db import MockSyslogDB
        return MockSyslogDB()
    if kind == "rule":
        from db.syslog_db import SyslogRuleDB
        return SyslogRuleDB()
    if kind == "device":
        from db.device_db import DeviceDB
        return DeviceDB()
    if kind == "alarm":
        from db.alarm_db import AlarmDB
        return AlarmDB()
    raise ValueError("unknown db kind: {}".format(kind))


def get_db(kind="rule"):
    """
    按 kind 拿一个进程内共用的实例

    :param kind: rule / device / alarm
    """
    if not Config.use_mock_db:
        return _build(kind)

    # mock 只有一个类，三种 kind 共用同一个实例 —— 样本数据在一处，
    # 测试里才能用同一个 db 既改规则又改设备表
    with _lock:
        if "mock" not in _instances:
            _instances["mock"] = _build("rule")
        return _instances["mock"]


def get_rule_db():
    return get_db("rule")


def get_device_db():
    return get_db("device")


def get_alarm_db():
    return get_db("alarm")


def reset():
    """测试用：清掉已建的实例，下次 get_db 重新建"""
    with _lock:
        _instances.clear()
