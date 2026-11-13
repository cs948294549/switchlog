# -*- coding: utf-8 -*-
"""
L4 富化

L3 只看报文本身，出来的事件只有 ip / event_code / object，
光这些没法看：值班要知道**哪台设备**、**哪条链路**出的事。
这一层去查现网已有的两张表补上，不改 event_code，也不改 object。

    devices     sysname / vendor / hardware / syscontact(资产号)
    ports       if_name -> alias（接口描述）

查询按源 IP 走，结果本地缓存 10 分钟（含未命中的负缓存）——
一台设备一天发几万条日志，不能每条都查一次库。

查不到设备时打 managed=False / src_state=UNMANAGED_SRC，事件继续往下走，不丢。
它在发日志而 devices 表里没有，本身就是该补纳管的事件。

接口名怎么对上见 utils/ifname.py。
"""
import time
import logging
import threading

from utils.ifname import PortIndex

logger = logging.getLogger(__name__)

DEFAULT_TTL = 600              # 缓存秒数，10 分钟
NO_VALUE = "-"

STATE_MANAGED = "MANAGED"
STATE_UNMANAGED = "UNMANAGED_SRC"
STATE_LOOKUP_FAILED = "SRC_LOOKUP_FAILED"


class DeviceEnricher(object):
    """
    L4 富化：devices 补设备归属，ports 补接口描述

    缓存按 IP 存一份 (设备信息, 接口索引)，两者一起过期 ——
    devices 和 ports 都由采集侧定期刷新，TTL 一致就够。
    """

    def __init__(self, ttl=DEFAULT_TTL, db=None):
        """
        :param ttl: 缓存秒数，默认 600
        :param db: 数据源，由 db.get_device_db() 注入
        """
        self._ttl = int(ttl)
        self._db = db
        self._cache = {}          # ip -> (expire_ts, info, PortIndex)
        self._lock = threading.RLock()

    # ---------------- 数据源 ----------------

    @property
    def db(self):
        if self._db is None:
            from db import get_device_db
            self._db = get_device_db()
        return self._db

    def _load(self, ip):
        """
        查一次库，返回 (info, ports)。

        查询失败时不写缓存（返回 None 由调用方处理），否则一次数据库抖动
        会让这台设备 10 分钟内都被当成未纳管。
        """
        try:
            device = self.db.getDeviceInfo(ip)
        except Exception as err:
            logger.error("======DeviceEnricher getDeviceInfo error========\n%s", err)
            return None, None
        if device == "failed":
            return None, None

        if not device:
            # devices 里没有这台设备，接口表也不用查了
            info = {
                "sysname": NO_VALUE,
                "vendor": "",
                "hardware": NO_VALUE,
                "syscontact": NO_VALUE,
                "sysdesc": "",
                "sys_type": "",
                "managed": False,
                "src_state": STATE_UNMANAGED,
            }
            return info, PortIndex([])

        # devices 命中走的是网关反查时，resolved_ip 才是真实采集 ip ——
        # ports 表按真实采集 ip 登记，查接口表不能再用原始传入的网关地址
        ports_ip = str(device.get("resolved_ip", "") or "").strip() or ip

        ports = PortIndex([])
        try:
            rows = self.db.getPorts(ports_ip)
            if rows != "failed":
                ports = PortIndex(rows)
        except Exception as err:
            # 接口描述补不上不影响主流程，设备信息照样用
            logger.error("======DeviceEnricher getPorts error========\n%s", err)

        info = {
            "sysname": str(device.get("sysname", "") or "").strip() or NO_VALUE,
            "vendor": str(device.get("vendor", "") or "").strip().lower(),
            "hardware": str(device.get("hardware", "") or "").strip() or NO_VALUE,
            "syscontact": str(device.get("syscontact", "") or "").strip() or NO_VALUE,
            "sysdesc": str(device.get("sysdesc", "") or "").strip(),
            "sys_type": str(device.get("sys_type", "") or "").strip(),
            "managed": True,
            "src_state": STATE_MANAGED,
        }
        return info, ports

    def get(self, ip, now=None):
        """
        取某台设备的富化信息，命中缓存直接返回。

        :return: (info, PortIndex)；数据库不可用时返回 (None, None)
        """
        ip = str(ip or "").strip() or NO_VALUE
        now = int(now if now is not None else time.time())
        with self._lock:
            cached = self._cache.get(ip)
            if cached and cached[0] > now:
                return cached[1], cached[2]

        info, ports = self._load(ip)
        if info is None:
            return None, None

        with self._lock:
            self._cache[ip] = (now + self._ttl, info, ports)
        return info, ports

    def purge(self, now=None):
        """清掉过期缓存，长时间运行防止字典膨胀"""
        now = int(now if now is not None else time.time())
        with self._lock:
            expired = [ip for ip, (expire, _, _) in self._cache.items() if expire <= now]
            for ip in expired:
                self._cache.pop(ip, None)
        return len(expired)

    def invalidate(self, ip=None):
        with self._lock:
            if ip is None:
                self._cache.clear()
            else:
                self._cache.pop(str(ip), None)

    # ---------------- 流水线入口 ----------------

    def enrich(self, event, now=None):
        """
        给事件补富化字段，原地修改并返回

        查不到设备时打 UNMANAGED_SRC，事件照常返回，不丢。
        """
        ip = event.get("ip", NO_VALUE)
        info, ports = self.get(ip, now=now)

        if info is None:
            # 数据库不可用，保留 L3 的结果，标记一下继续走
            event.setdefault("sysname", NO_VALUE)
            event.setdefault("hardware", NO_VALUE)
            event.setdefault("syscontact", NO_VALUE)
            event.setdefault("object_name", "")
            event.setdefault("object_alias", "")
            event["managed"] = False
            event["src_state"] = STATE_LOOKUP_FAILED
            return event

        event.update({
            "sysname": info["sysname"],
            "hardware": info["hardware"],
            "syscontact": info["syscontact"],
            "sysdesc": info["sysdesc"],
            "sys_type": info["sys_type"],
            "managed": info["managed"],
            "src_state": info["src_state"],
        })
        # L3 已经按 devices.vendor 定好了厂商键，这里只在它没取到时补；
        # 覆盖会把规则匹配用的键冲掉
        if not event.get("vendor"):
            event["vendor"] = info["vendor"]
        # 设备名一律以 devices 表为准，覆盖 L1 剥出来的值 ——
        # L1 只是按正则猜信封结构，碰到年份在时间后面的格式会把年份
        # 当成设备名（Nov 12 18:39:05 2026 -> hostname=2026）。
        # 查到了设备就说明身份已经确定，不用管正文里写了什么。
        # sysname 取不到（未纳管设备）时才保留 L1 的结果
        if info["sysname"] not in ("", NO_VALUE, None):
            event["hostname"] = info["sysname"]

        self._enrich_object(event, ports)
        return event

    @staticmethod
    def _enrich_object(event, ports):
        """
        给 alarm_object 补一个人类可读的别名。object 是 L3 抽的，不动它 ——
        它参与 L6 指纹，改了就关不掉原来的告警。

        L4 跑在 L5 attrs 之前，这里还拿不到 object_type（L5 按 event_code
        查 syslog_event 才产出），没法先按类型分支再查表。现在只接了
        interface 一种：直接拿 alarm_object 去 ports 表试查，查到了就是
        接口、填 object_alias；查不到就留空，不强行判断它是不是接口。

        以后要接 peer/mac/slot 的别名，在这里按各自的数据源加一段
        "查不到就跳过" 的尝试，和接口这段并列，不要依赖 object_type。
        """
        alarm_object = str(event.get("alarm_object", "") or "")
        if not alarm_object or alarm_object == NO_VALUE or ports is None:
            event.setdefault("object_name", "")
            event.setdefault("object_alias", "")
            return

        row = ports.lookup(alarm_object)
        if not row:
            # 对象不是接口（peer IP / 槽位 / none），或接口表里没有这个口
            event["object_name"] = ""
            event["object_alias"] = ""
            return

        event["object_name"] = row.get("if_name", "")
        event["object_alias"] = str(row.get("alias", "") or "")
