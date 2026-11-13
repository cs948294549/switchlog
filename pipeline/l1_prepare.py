# -*- coding: utf-8 -*-
"""
L1 预处理：剥信封 + 剥 mnemonic

管线上黑名单和 parser 都要知道 mnemonic，所以在进任何一层之前剥好、往下透传。
两层各剥一遍是纯浪费 —— 实测 162 字节的报文剥一次 0.44us，命中第三条正则的
最坏情况 1.47us；剥好之后 dict 查一次只要 0.036us。

这也顺带决定了黑名单的匹配方式：mnemonic 已经在手上，dict 一级命中就够，
不用逐条规则扫全文（实测 20 条规则以上就比剥 mnemonic 还贵）。

不解析报文自带时间：设备时钟漂移会把 L6 滑动窗口算乱，时间统一用采集时间。
"""
import re
import time
import logging

logger = logging.getLogger(__name__)

# 报文与正文的截断长度。入库字段有限长，这里先截，
# 免得后面每层都要考虑超长字符串
MSG_LIMIT = 1024

# mnemonic 的三种写法，对所有报文一起试，不按厂商分派：
# 厂商只用来查规则表，报文长什么样由报文自己说。
# 顺序按现网量排：cisco 最多的放第一条，少试一次正则就省一次 search
MNEMONIC_REGS = (
    # Cisco 两段式 %ETHPORT-5-IF_DOWN:  %ETH_PORT_CHANNEL-5-FOP_CHANGED:
    # 三段式 %TAHUSD-SLOT1-4-BUFFER_THRESHOLD_EXCEEDED:（多一个槛位/模块段）。
    # 中间槛位段可选，SEV 段锁死纯数字不变，两段式格式不受影响
    re.compile(r"%{1,2}([A-Za-z][A-Za-z0-9_]*(?:-[A-Za-z][A-Za-z0-9_]*)?-\d+-[A-Za-z0-9_\-]+)\s*:"),
    # Comware %%10IFNET/3/PHY_UPDOWN:   华为 %%01IFNET/4/LINK_STATE:
    # 前导数字是日志版本号，剥掉，否则同一事件 V5/V7 算成两个 mnemonic
    re.compile(r"%{1,2}\d{0,2}([A-Za-z][A-Za-z0-9_]*(?:/\d+)?/[A-Za-z0-9_\-]+)"),
    # FortiGate  logid="0100032003"
    re.compile(r"\blogid=\"?(\d+)\"?"),
)

# 前导杂质：观察到个别链路在报文最前面多一个孤立的 "冒号+空格"
# （来源不确定，疑似某段转发/采集环节加的），不剥掉的话后面的 PRI/
# 时间戳正则全部锚定在 ^，一个字符都会把三条正则一起挡死，直接判
# PARSE_FAIL。只匹配"行首紧跟的单个冒号"，不触碰正文内部的冒号
# （Cisco 的 %MODULE-SEV-NAME: 那个冒号在 mnemonic 后面，不在行首）
LEADING_JUNK_REG = re.compile(r"^:\s+")

# 信封：和厂商无关，RFC3164 / RFC5424 都在这段消化。
# 只为了拿到 hostname 和 body，设备自报时间一律不用
PRI_REG = re.compile(r"^<(\d{1,3})>")
TS_REGS = (
    # 2026 Oct  9 05:18:56.483 CST   带年份，日期空格补位，时区缩写可选
    re.compile(r"^\d{4}\s+[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"
               r"(?:\.\d+)?(?:\s+[A-Z]{2,5})?\s*"),
    # Nov 12 18:39:05.412 2026   年份在时间之后（H3C 部分版本、rsyslog
    # timereported 渲染）。年份可选，不加的话 2026 会被 HOSTNAME_REG
    # 当成设备名取走；时区缩写同样可选，跟在年份后面或直接跟在时间后面
    re.compile(r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"
               r"(?:\.\d+)?(?:\s+\d{4})?(?:\s+[A-Z]{2,5})?\s*"),
    # 2026-11-11T14:03:22.412+08:00   RFC5424 ISO8601
    re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+\-]\d{2}:?\d{2})?\s*"),
)
HOSTNAME_REG = re.compile(r"^([A-Za-z0-9][A-Za-z0-9_.\-]{1,63})\s+")


def strip_mnemonic(body):
    """剥 mnemonic，三种写法依次试，都不中返回空串"""
    for reg in MNEMONIC_REGS:
        match = reg.search(body)
        if match:
            return match.group(1)
    return ""


def split_envelope(message):
    """
    剥信封，返回 (hostname, body, readable)

    readable=False 表示连 PRI 和时间戳都没有、正文里也剥不出 mnemonic，
    报文不可读 -> PARSE_FAIL。body 保留原文（含 %MNEMONIC 段），
    后面剥 mnemonic 和抽对象都用它。
    """
    text = str(message or "").strip()
    if not text:
        return "-", "", False

    # 剥掉行首孤立的冒号杂质，不算作"seen"——它不是 PRI 也不是时间戳，
    # 剥到它不代表信封可读，可读与否仍然看后面 PRI/时间戳有没有命中
    match = LEADING_JUNK_REG.match(text)
    if match:
        text = text[match.end():]

    seen = False
    match = PRI_REG.match(text)
    if match:
        seen = True
        text = text[match.end():].lstrip()

    # 时间戳可能出现两次（转发链路上各加一次），都剥掉
    for _ in range(2):
        for reg in TS_REGS:
            match = reg.match(text)
            if match:
                seen = True
                text = text[match.end():]
                break
        else:
            break

    hostname = "-"
    # hostname 只在时间戳后面那个位置取；% 开头说明设备没带设备名
    if seen and not text.startswith("%"):
        match = HOSTNAME_REG.match(text)
        if match and ("%" in text[match.end():] or "=" in text[match.end():]):
            hostname = match.group(1)
            text = text[match.end():]

    return hostname, text.strip(), seen


def prepare(raw, now=None):
    """
    管线第一步：剥信封、剥 mnemonic，结果往下透传

    :param raw: {"ip": 源IP, "message": 原始报文, "timestamp": 采集时间}
                ip 和 timestamp 由收包侧填好；timestamp 是采集时间，不是设备时间
    :return: L1 输出，字段见 pipeline/__init__.py 的契约
    """
    ingest_ts = int(now if now is not None else time.time())
    raw = raw if isinstance(raw, dict) else {}
    ip = str(raw.get("ip", "") or "").strip() or "-"
    message = str(raw.get("message", "") or "")
    try:
        ingest_ts = int(raw.get("timestamp") or ingest_ts)
    except (TypeError, ValueError):
        pass

    hostname, body, readable = split_envelope(message)
    mnemonic = strip_mnemonic(body) if body else ""
    # 没有 PRI 也没有时间戳，但剥得出 mnemonic 的仍然算可读：
    # FortiGate 直接以 date=... 开头，没有 RFC3164 信封
    if not readable and mnemonic:
        readable = True

    return {
        "ingest_ts": ingest_ts,
        "ip": ip,
        "message": message[:MSG_LIMIT],
        "hostname": hostname,
        "body": body[:MSG_LIMIT],
        "mnemonic": mnemonic,
        "readable": readable,
    }
