# -*- coding: utf-8 -*-
"""
devices / ports 读取

这两张表是 central-server 采集侧维护的，switchlog 只读。
    devices   源 IP -> sysname / vendor / hardware / syscontact / sysdesc / sys_type
    ports     源 IP -> 接口表（if_name + alias 接口描述）

syscontact 在现网存的是资产号，看板上要显示的就是它。
"""
import logging

from db.database import MySQLConnection

logger = logging.getLogger(__name__)

DEVICE_FIELDS = ["sysname", "sysdesc", "syscontact", "hardware", "sys_type", "vendor"]
PORT_FIELDS = ["if_name", "alias", "admin_statu", "oper_statu", "speed"]


class DeviceDB(object):
    """设备与接口查询"""

    def getDeviceInfo(self, ip):
        """
        devices 一行。

        :return: dict；查不到返回 {}；查询失败返回 "failed"
                 （调用方据此不写负缓存，否则一次抖动会让这台设备 10 分钟都算未纳管）
        """
        sql = '''
        select sysname, sysdesc, syscontact, hardware, sys_type, vendor
        from devices where ip=%s limit 1
        '''
        try:
            with MySQLConnection() as conn:
                return conn.query_one(sql, (str(ip),), proper=DEVICE_FIELDS)
        except Exception as err:
            logger.error("======DeviceDB getDeviceInfo error========\n%s", err)
            return "failed"

    def getDeviceVendor(self, ip):
        """
        只取 vendor，L1 用它定语法族。

        比 getDeviceInfo 轻，但 L1 每条日志都要查一次 —— 靠调用方的 TTL 缓存
        兜住，实际一台设备 10 分钟只查一回。

        :return: vendor 原值（小写）；查不到返回 ""；查询失败返回 "failed"
        """
        sql = "select vendor from devices where ip=%s limit 1"
        try:
            with MySQLConnection() as conn:
                row = conn.query_one(sql, (str(ip),))
                return str(row[0] or "").strip().lower() if row else ""
        except Exception as err:
            logger.error("======DeviceDB getDeviceVendor error========\n%s", err)
            return "failed"

    def getPorts(self, ip):
        """
        某台设备的接口表，L2 用来补接口描述。

        :return: [{"if_name", "alias", ...}]；查询失败返回 "failed"
        """
        sql = '''
        select if_name, alias, admin_statu, oper_statu, speed
        from ports where ip=%s
        '''
        try:
            with MySQLConnection() as conn:
                rows = conn.query(sql, (str(ip),), proper=PORT_FIELDS)
            return [row for row in rows if row.get("if_name")]
        except Exception as err:
            logger.error("======DeviceDB getPorts error========\n%s", err)
            return "failed"
