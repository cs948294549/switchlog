# -*- coding: utf-8 -*-
"""
接口名归一与短名展开

同一块口在不同日志里写法不一样，这是现网的常态：

    %ETHPORT-5-IF_DOWN_LINK_FAILURE: Interface Ethernet1/6 ...
    %BFD-5-SESSION_STATE_DOWN:       ... on interface Eth1/6 ...

ports.if_name 存的是设备自报的全名，所以先精确对，对不上再按
"字母前缀 + 端口号" 展开。两种缩写方式都从名字本身算出来，不维护对照表：

    Eth1/6     -> Ethernet1/6              截断式（前缀是全名的前缀）
    GE0/0/1    -> GigabitEthernet0/0/1     首字母式（取大写首字母）
    XGE0/0/1   -> XGigabitEthernet0/0/1    同上

不写死对照表的原因：新的接口类型（400G 口、堆叠改名、各家私有命名）
一出现就要改代码发版，而设备自己报的接口表本来就是权威来源。
"""
import re
import logging

logger = logging.getLogger(__name__)

# 接口名拆成 "字母前缀" + "端口号"
#   Ethernet1/6           -> ("ethernet", "1/6")
#   Eth1/6                -> ("eth", "1/6")
#   XGigabitEthernet0/0/1 -> ("xgigabitethernet", "0/0/1")
#   port-channel38        -> ("port-channel", "38")
IFNAME_REG = re.compile(r"^([A-Za-z][A-Za-z0-9_\-]*?)(\d+(?:/\d+)*)$")


def split_ifname(name):
    """拆成 (前缀小写, 端口号)，拆不开返回 ('', '')"""
    match = IFNAME_REG.match(str(name or "").strip())
    if not match:
        return "", ""
    return match.group(1).lower(), match.group(2)


def initials_of(prefix):
    """
    取大写首字母缩写，厂商缩写就是这么来的：

        GigabitEthernet     -> ge
        XGigabitEthernet    -> xge
        TenGigabitEthernet  -> tge

    少于两个大写字母返回空串：Ethernet 只有一个 E，
    拿它做匹配会撞上一切 E 开头的接口。
    """
    letters = [char for char in str(prefix or "") if char.isupper()]
    return "".join(letters).lower() if len(letters) >= 2 else ""


def prefix_compatible(short, full):
    """
    短名前缀能不能展开成全名前缀，两个参数都是小写

        eth     -> ethernet      True
        gigabit -> gigabitethernet  True
        eth     -> eth-trunk     False

    最后一行必须挡住：华为设备上 Eth-Trunk1 和 Eth1 可以同时存在，
    按纯 startswith 判的话 Eth1 会对到 Eth-Trunk1 上，
    补出来的接口描述是错的 —— 比补不上更糟。
    """
    if not short or not full:
        return False
    if short == full:
        return True
    if len(short) < 2 or not full.startswith(short):
        return False
    # 截断式缩写：紧跟在后面的必须还是字母，不能是 - 或 _
    return full[len(short)].isalpha()


class PortIndex(object):
    """
    一台设备的接口表索引，一次查询建一次

        by_name    dict[if_name 小写] -> row        精确命中，绝大多数走这里
        by_number  dict[端口号] -> [(前缀, 缩写, row)]  短名展开用

    按端口号先分桶是关键：Eth1/6 只跟同样是 1/6 的口比，
    一台设备几十个口里通常只有一个，比完就定了，不用遍历全表。
    """

    __slots__ = ("by_name", "by_number", "total")

    def __init__(self, rows):
        self.by_name = {}
        self.by_number = {}
        self.total = 0
        for row in rows or []:
            if_name = str(row.get("if_name", "") or "").strip()
            if not if_name:
                continue
            self.total += 1
            row = dict(row)
            row["if_name"] = if_name
            self.by_name[if_name.lower()] = row
            prefix, number = split_ifname(if_name)
            if number:
                self.by_number.setdefault(number, []).append(
                    (prefix, initials_of(if_name[:len(prefix)]), row))

    def lookup(self, name):
        """
        按报文里的接口名找接口行，找不到返回 {}

        非接口对象（peer IP、槽位号）会在 split_ifname 那步就拆不开，
        直接返回空，不会误匹配到某个接口上。
        """
        name = str(name or "").strip()
        if not name or not self.total:
            return {}

        row = self.by_name.get(name.lower())
        if row is not None:
            return row

        prefix, number = split_ifname(name)
        if not prefix or not number:
            return {}
        candidates = self.by_number.get(number)
        if not candidates:
            return {}

        initials = initials_of(name[:len(prefix)])
        best = None
        for candidate_prefix, candidate_initials, item in candidates:
            hit = (prefix_compatible(prefix, candidate_prefix)
                   or (initials and initials == candidate_initials)
                   or (initials and initials == candidate_prefix)
                   or (candidate_initials and candidate_initials == prefix))
            if not hit:
                continue
            # 命中多条时取名字最短的：Eth1/6 对 Ethernet1/6 比对更长的更可信
            if best is None or len(item["if_name"]) < len(best["if_name"]):
                best = item
        return best or {}
