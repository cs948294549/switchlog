# -*- coding: utf-8 -*-
"""
switchlog 配置模板

    cp config/config_example.py config/config.py

config.py 不进 git（含数据库口令），改完这份模板记得同步改 config.py。
"""


class Config:
    """交换机日志告警服务配置"""

    # ---------------- 日志接收 ----------------
    # 设备 logging host 指向本服务。514 是特权端口，需要 root 或
    # CAP_NET_BIND_SERVICE；用非特权端口时设备侧要配 logging port
    listen_ip = "0.0.0.0"
    listen_port = 514

    # 内核 socket 接收缓冲，吸收突发。设大一些，日志风暴时这是第一道缓冲。
    # 实际生效值受 /proc/sys/net/core/rmem_max 限制，起服务时日志会打印真实值
    socket_rcvbuf = 16 * 1024 * 1024

    # 单个 UDP 报文最大长度。RFC3164 限 1024，但现网设备常超，取 8K 够用
    max_packet_size = 8192

    # ---------------- 并发 ----------------
    # worker 线程数。同一设备的日志固定落到同一个 worker（按 IP hash），
    # 因为 L4 聚合和 L5 状态机依赖同设备事件的先后顺序
    workers = 4

    # 每个 worker 的待处理队列长度。满了直接丢并计数 ——
    # 阻塞收包线程会让内核 buffer 溢出，那是无声丢包
    queue_size = 20000

    # ---------------- 刷新与缓存 ----------------
    rule_refresh_interval = 300     # 规则表重新加载间隔（秒）
    enrich_cache_ttl = 600          # devices/ports 查询缓存（秒），含负缓存
    stats_interval = 60             # 统计输出间隔（秒）

    # ---------------- 数据库 ----------------
    # True 时走 tests/mock_db.py 的内存表，不连 MySQL。
    # 表结构还没定稿时用它跑链路，定稿后改 False
    use_mock_db = False

    mysql_config = {
        "db_host": "127.0.0.1",
        "db_port": 3306,
        "db_user": "netops",
        "db_token": "",             # 数据库密码，自行填写
        "db_name": "netops",
    }

    # ---------------- 告警出口 ----------------
    # L6 未实现前置 False，管线跑到 L2.5 就停，只打日志不落库
    alarm_enable = False

    # ---------------- 日志 ----------------
    log_level = "INFO"
    log_backup_days = 7
