# -*- coding: utf-8 -*-
"""
L4 聚合  [未实现]

这一级不做任何正则匹配。进来的是结构化事件，event_code 和归一化后的
object 都已在 L1 算好，这里只剩拼 key：

    fingerprint = md5(ip | event_code | alarm_object)

恢复事件（IF_UP）要落到对应故障事件（IF_DOWN）的指纹上才关得掉告警，
所以配 event 的 clear_code 用。

窗口用真滑动，不靠分桶继承：

    now - last_seen <= window      -> 同一个 label，count += 1，刷新 last_seen
    now - first_seen > max_life    -> 强制开新 label（解决无限继承）
    否则                            -> 新 label，count = 1

max_life 默认 1800s：持续闪断的接口每 30 分钟重新告警一次，不会永久静默。

输出给 L5：
    {"fingerprint", "group_label", "is_first", "count", "first_seen", "last_seen"}

count 是**日志条数**，不是事故次数。一次端口 down 在 Cisco 上可能同时落到
IF_DOWN、IF_DOWN_LINK_FAILURE、LINEPROTO down 三条日志，指纹相同 count 就是 3，
但这是一次端口 down。所以任何按"次数"做的判断（闪断识别）都不能直接读 count，
必须数 L5 里"无活跃告警 -> 开告警"这一跳。

状态先放内存，不引入 Redis：单实例跑内存够了，重启靠 syslog_alarm_state
表回放。多实例部署时再上 Redis。
"""

import logging

logger = logging.getLogger(__name__)

DEFAULT_WINDOW = 300
DEFAULT_MAX_LIFETIME = 1800
