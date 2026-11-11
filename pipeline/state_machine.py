# -*- coding: utf-8 -*-
"""
L5 状态机  [未实现]

现有链路完全缺失的一级，也是日志告警能不能用起来的关键。

有状态事件，state 取 raise / clear：

    alarm:active:{fingerprint} -> {alarm_id, event_code, severity, first_seen, count}

    raise 且无活跃告警  -> 开告警并写入
    raise 且已有活跃告警 -> 只累加 count
    clear               -> 按同一指纹找到活跃告警并关闭

指纹含 object，所以 BGP_UP peer=A 只会关 A 的告警，
不会误关同台设备上 B 邻居的告警。

无状态事件（MAC 漂移、配置变更、登录失败）没有恢复日志，用窗口计数触发，
窗口内不再出现即自动恢复：

    MAC_FLAP: 同指纹 10 分钟内 >= 3 次 -> 告警

这个门槛同时起降噪作用，虚机漂移造成的偶发单次 MAC 迁移不报。

闪断识别单独一条长窗口：

    同指纹 30 分钟内 >= 3 次「新开告警」-> 升级为 IF_FLAP，severity 提一档

计数点在"无活跃告警 -> 开告警"这一跳，不在 L4 的日志条数上。
一次端口 down 会产生 2~3 条同指纹日志，按日志条数计的话一次 down
就能凑满 3 次，当场误报成闪断。

闪断禁止自动恢复，需人工确认才关闭。

状态持久化在 syslog_alarm_state 表（db/alarm_db.py 已备好读写），
进程重启时回放未恢复的告警，避免重启后重复告警。
"""

import logging

logger = logging.getLogger(__name__)

MODE_RAISE = "raise"
MODE_CLEAR = "clear"
MODE_STATELESS = "stateless"
MODE_IGNORE = "ignore"

ACTION_RAISE = "raise"
ACTION_UPDATE = "update"
ACTION_ESCALATE = "escalate"
ACTION_CLEAR = "clear"
ACTION_IGNORE = "ignore"

DEFAULT_SILENCE = 600           # stateless 静默多久自动恢复
DEFAULT_FLAP_WINDOW = 1800      # 闪断统计窗口 30 分钟
DEFAULT_FLAP_THRESHOLD = 3      # 窗口内新开告警次数达到即判闪断
