# -*- coding: utf-8 -*-
"""
L6 告警出口  [未实现]

写 alarm_list，看板（chen_vue）和 central-server/api/api_alarm.py 都读这张表。

alarm_list 相对老结构要补的字段：

    severity      1/2/3，看板排序和通知分级的依据
    fingerprint   关联恢复事件、去重
    state         open / clear，区别于 status 的人工处理状态
    first_seen / last_seen / clear_time   持续时长、MTTR
    counter       聚合条数

status 是人工处理状态（0待处理/1已确认/2已处理/3忽略/4屏蔽），
state 是告警自身是否还成立，两者独立，不要混用。

注意 keyword 字段存的是 event_code，group_label 存 fingerprint ——
这两个沿用老表结构，是为了现有分组页面不用改。

写入接口见 db/alarm_db.py 的 AlarmDB.addAlarm / updateAlarmByFingerprint。

实现前置条件：
    1. L5 状态机先落地（它决定 raise / update / clear）
    2. alarm_list 的扩展字段建好（sql/schema.sql）
    3. 通知通道（企业微信 / 邮件 / 短信）的分发策略确定，这一版先只写库
"""

import logging

logger = logging.getLogger(__name__)

ALARM_TYPE = "syslog"
