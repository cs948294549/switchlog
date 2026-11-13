# -*- coding: utf-8 -*-
"""
数据源工厂

管线各层只接受注入的 db，不知道背后是哪张表、连的哪个库。
三种 kind 各自对应一个真实数据源类，进程内各自单例。

    from db import get_rule_db, get_device_db

    parser = SyslogParser(db=get_rule_db())
    enricher = DeviceEnricher(db=get_device_db())
"""
import logging
import threading

logger = logging.getLogger(__name__)

_lock = threading.Lock()
_instances = {}


def _build(kind):
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
    with _lock:
        if kind not in _instances:
            _instances[kind] = _build(kind)
        return _instances[kind]


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
