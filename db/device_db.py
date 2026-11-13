# -*- coding: utf-8 -*-
"""
devices / ports 读取

这两张表是 central-server 采集侧维护的，switchlog 只读。
    devices   源 IP -> sysname / vendor / hardware / syscontact / sysdesc / sys_type
    ports     源 IP -> 接口表（if_name + alias 接口描述）

syscontact 在现网存的是资产号，看板上要显示的就是它。

传进来的 ip 不一定是采集侧登记在 devices 里的那个 ip —— 中转/NAT 场景下
switchlog 收到的可能是网关地址，真实设备按网关登记在 gates 表。
devices 直接查不到时，把传入 ip 当网关去 gates 反查一次真实采集 ip，
再用这个 ip 重查 devices，详见 _resolve_via_gateway()。
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
        devices 一行。直接查不到时，把 ip 当网关去 gates 反查真实采集 ip 再查一次。

        命中网关反查时，返回的 dict 里会带上 resolved_ip（真实采集 ip）——
        调用方查 ports 要用这个 ip，不能再用原始传入的网关地址。

        :return: dict；查不到返回 {}；查询失败返回 "failed"
                 （调用方据此不写负缓存，否则一次抖动会让这台设备 10 分钟都算未纳管）
        """
        sql = '''
        select sysname, sysdesc, syscontact, hardware, sys_type, vendor
        from devices where ip=%s limit 1
        '''
        try:
            with MySQLConnection() as conn:
                row = conn.query_one(sql, (str(ip),), proper=DEVICE_FIELDS)
                if row:
                    return row
                real_ip = self._resolve_via_gateway(conn, ip)
                if not real_ip:
                    return row
                row = conn.query_one(sql, (real_ip,), proper=DEVICE_FIELDS)
                if row:
                    row["resolved_ip"] = real_ip
                return row
        except Exception as err:
            logger.error("======DeviceDB getDeviceInfo error========\n%s", err)
            return "failed"

    def getDeviceVendor(self, ip):
        """
        只取 vendor，L3 用它定语法族。同样走 gates 网关兜底。

        比 getDeviceInfo 轻，但 L3 每条日志都要查一次 —— 靠调用方的 TTL 缓存
        兜住，实际一台设备 10 分钟只查一回。

        :return: vendor 原值（小写）；查不到返回 ""；查询失败返回 "failed"
        """
        sql = "select vendor from devices where ip=%s limit 1"
        try:
            with MySQLConnection() as conn:
                row = conn.query_one(sql, (str(ip),))
                if not row:
                    real_ip = self._resolve_via_gateway(conn, ip)
                    if real_ip:
                        row = conn.query_one(sql, (real_ip,))
                return str(row[0] or "").strip().lower() if row else ""
        except Exception as err:
            logger.error("======DeviceDB getDeviceVendor error========\n%s", err)
            return "failed"

    @staticmethod
    def _resolve_via_gateway(conn, ip):
        """
        devices 按 ip 查不到时的兜底：把 ip 当网关地址，去 gates 表反查
        真实的采集 ip —— gates.gateway 命中这个 ip 的那一行，它的
        gates.ip 才是 devices 里真正登记的 ip。

        :return: 反查到的真实采集 ip；查不到返回 None
        """
        sql = "select ip from gates where gateway=%s limit 1"
        row = conn.query_one(sql, (str(ip),))
        return str(row[0]).strip() if row else None

    def getPorts(self, ip):
        """
        某台设备的接口表，L4 用来补接口描述。

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
