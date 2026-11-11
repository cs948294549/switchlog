# -*- coding: utf-8 -*-
"""
L3 抑制  [未实现]

从现有链路的一档"丢"扩成三档，这是相对老 `filter_blacklist.py` 最大的改动：

    档位    行为                                                  用途
    drop    不进告警链路，原始日志照常落 ES                      确定是噪声
    mute    进管线、进聚合、进状态机，但不产生通知                变更窗口期
    depend  上游设备整机不可达时，挂起其下游设备的事件            拓扑抑制

mute 和 drop 的区别很重要：割接期间不该被电话轰炸，但割接完要能回看
那段时间发生了什么，所以变更窗口必须用 mute 而不是 drop。

规则表 syslog_suppress_rule 需要 scope 维度（全局 / 指定设备 / 指定机房）
和生效时间段。mute 的数据来源是变更工单（central-server 的
AlterationManageDB），depend 依赖 TopologyDB 已有的拓扑数据。

实现前置条件：
    1. syslog_suppress_rule 表定稿（见 sql/schema.sql 的注释）
    2. 变更工单的查询接口确定
    3. depend 先留接口，拓扑自动推导可以后置

接口约定（实现时照这个签名写）：
    handle(event, now) -> {"action": "pass"|"drop"|"mute"|"hold",
                           "reason": {...}}
"""

import logging

logger = logging.getLogger(__name__)

ACTION_PASS = "pass"
ACTION_DROP = "drop"
ACTION_MUTE = "mute"
ACTION_HOLD = "hold"
