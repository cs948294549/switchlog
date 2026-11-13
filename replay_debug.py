# -*- coding: utf-8 -*-
"""
临时脚本：把一段贴进来的现场日志，逐条真实 sleep 几秒后通过 UDP 发给
本机正在跑的 switchlog 服务（python main.py），而不是在脚本里直接调
pipeline 各层函数。

为什么换成真实发包，不再直接调 L1~L9：
    之前的写法在脚本自己的进程里手搭了一套简化调用链（build() 里攒一遍
    各层对象，main() 跑完所有行后手动 flush 一次），和 main.py 的
    run_service() 实际跑的东西不是一回事 —— 没有 Maintenance 线程，
    counter 累加（action=none）不会被 sync_counters 同步进 alarm_list，
    alarm_log 的攒批刷新判断用的 now 还是日志里的模拟时间，和
    Aggregator._last_flush 的真实系统时间对不上，导致行为和生产脱节
    （比如 counter 停在 1 不涨、日志要等脚本跑完才能查到）。

    换成发 UDP 包以后，处理逻辑完全是 main.py 进程里 Worker + Maintenance
    线程在跑，和生产用的是同一套代码路径，不用在这个脚本里反复对齐细节。

源IP：普通 UDP socket 发包，源地址由内核路由决定，本机发给 127.0.0.1
收到的就是 127.0.0.1，不是 SOURCE_IP 这个变量（那只是用来打印查询语句
提示，不代表服务端实际收到的源地址）。要在 devices 表里查得到设备信息
（sysname/hardware、按 sysname_reg 定级），得确保 127.0.0.1 在 devices
表里有对应记录，否则会落到 UNMANAGED_SRC。

用法：
    1. 另开一个终端，起好服务（会监听 Config.listen_ip:Config.listen_port）：
           python main.py
       或指定非特权端口方便本地测：
           python main.py --port 5514
    2. 跑这个脚本发包：
           python replay_debug.py
       如果用了 --port 覆盖，这里也要带上：
           python replay_debug.py --port 5514

这个脚本只管发包，不等 main.py 的处理结果 —— 处理在另一个进程里异步跑，
发完包脚本就退出。要看效果，去 main.py 的终端看 switchlog.log 输出的
决策行（"告警 raise/update/clear ..."），或者直接查 alarm_list/alarm_log：
    select * from alarm_log where ip='127.0.0.1' order by log_id desc limit 50;
    select * from alarm_list where ip='127.0.0.1' order by alarm_id desc limit 20;

timestamp 这个字段在真实生产里是 UdpReceiver 收包时打的 int(time.time())
（main.py:103），不是从报文内容解析出来的 —— 所以这里发包也不用关心
RAW_LOG 里写的 "2026 Nov 11" 是哪一天，服务端收到包的那一刻就是当前
真实时间，L6/L7 的窗口判断用的都是这个真实时间，不会再有模拟时间和
系统时间对不上的问题。

跑完用完就删，不是项目里要长期维护的文件。
"""
import socket
import time
import argparse

# 两条日志之间真实停顿几秒，方便你一条条看 main.py 终端的输出
SLEEP_SECONDS = 5

RAW_LOG = """
2026 Nov 11 15:15:25.144 bbs1_dc05_m01_new %ETHPORT-5-IF_DOWN_LINK_FAILURE: Interface Ethernet1/1 (description:pT:bbs1_dc07_m01:100G1/4) is down (Link failure)
2026 Nov 11 15:15:25.145 bbs1_dc05_m01_new %BGP-5-ADJCHANGE:  bgp- [25358] (default) neighbor 172.28.1.193 Down - sent:  other configuration change
2026 Nov 11 15:15:25.164 bbs1_dc05_m01_new %BFD-5-SESSION_STATE_DOWN: BFD session 1090519229 to neighbor 172.28.1.193 on interface Eth1/1 has gone down. Reason: Path Down.
2026 Nov 11 15:17:26.176 bbs1_dc05_m01_new %BFD-5-SESSION_REMOVED: BFD session to neighbor 172.28.1.193 on interface Eth1/1 has been removed
2026 Nov 11 15:18:16.734 bbs1_dc05_m01_new %ETHPORT-5-SPEED: Interface Ethernet1/1, operational speed changed to 100 Gbps
2026 Nov 11 15:18:16.734 bbs1_dc05_m01_new %ETHPORT-5-IF_DUPLEX: Interface Ethernet1/1, operational duplex mode changed to Full
2026 Nov 11 15:18:16.734 bbs1_dc05_m01_new %ETHPORT-5-IF_RX_FLOW_CONTROL: Interface Ethernet1/1, operational Receive Flow Control state changed to off
2026 Nov 11 15:18:16.734 bbs1_dc05_m01_new %ETHPORT-5-IF_TX_FLOW_CONTROL: Interface Ethernet1/1, operational Transmit Flow Control state changed to off
2026 Nov 11 15:18:16.750 bbs1_dc05_m01_new %ETHPORT-5-IF_UP: Interface Ethernet1/1 (description:pT:bbs1_dc07_m01:100G1/4) is up in Layer3
2026 Nov 11 15:18:18.534 bbs1_dc05_m01_new %BGP-5-ADJCHANGE:  bgp- [25358] (default) neighbor 172.28.1.193 Up
2026 Nov 11 15:18:19.541 bbs1_dc05_m01_new %BFD-5-SESSION_MOVED: BFD session 0x410000be: Installed on LC 1
2026 Nov 11 15:18:19.567 bbs1_dc05_m01_new %BFD-5-SESSION_CREATED: BFD session to neighbor 172.28.1.193 on interface Eth1/1 has been created
2026 Nov 11 15:18:28.011 bbs1_dc05_m01_new %BFD-5-SESSION_STATE_UP: BFD session 1090519230 to neighbor 172.28.1.193 on interface Eth1/1 is up.
2026 Nov 11 15:32:47.733 bbs1_dc05_m01_new %ETHPORT-5-IF_DOWN_LINK_FAILURE: Interface Ethernet1/1 (description:pT:bbs1_dc07_m01:100G1/4) is down (Link failure)
2026 Nov 11 15:32:47.737 bbs1_dc05_m01_new %BGP-5-ADJCHANGE:  bgp- [25358] (default) neighbor 172.28.1.193 Down - sent:  bfd session down
2026 Nov 11 15:32:47.738 bbs1_dc05_m01_new %BFD-5-SESSION_STATE_DOWN: BFD session 1090519230 to neighbor 172.28.1.193 on interface Eth1/1 has gone down. Reason: Path Down.
2026 Nov 11 15:32:48.768 bbs1_dc05_m01_new %BFD-5-SESSION_REMOVED: BFD session to neighbor 172.28.1.193 on interface Eth1/1 has been removed
2026 Nov 11 15:35:15.669 bbs1_dc05_m01_new %ETHPORT-5-SPEED: Interface Ethernet1/1, operational speed changed to 100 Gbps
2026 Nov 11 15:35:15.669 bbs1_dc05_m01_new %ETHPORT-5-IF_DUPLEX: Interface Ethernet1/1, operational duplex mode changed to Full
2026 Nov 11 15:35:15.669 bbs1_dc05_m01_new %ETHPORT-5-IF_RX_FLOW_CONTROL: Interface Ethernet1/1, operational Receive Flow Control state changed to off
2026 Nov 11 15:35:15.669 bbs1_dc05_m01_new %ETHPORT-5-IF_TX_FLOW_CONTROL: Interface Ethernet1/1, operational Transmit Flow Control state changed to off
2026 Nov 11 15:35:15.685 bbs1_dc05_m01_new %ETHPORT-5-IF_UP: Interface Ethernet1/1 (description:pT:bbs1_dc07_m01:100G1/4) is up in Layer3
2026 Nov 11 15:35:16.720 bbs1_dc05_m01_new %BGP-5-ADJCHANGE:  bgp- [25358] (default) neighbor 172.28.1.193 Up
2026 Nov 11 15:35:17.727 bbs1_dc05_m01_new %BFD-5-SESSION_MOVED: BFD session 0x410000bf: Installed on LC 1
2026 Nov 11 15:35:17.754 bbs1_dc05_m01_new %BFD-5-SESSION_CREATED: BFD session to neighbor 172.28.1.193 on interface Eth1/1 has been created
2026 Nov 11 15:35:24.699 bbs1_dc05_m01_new %BFD-5-SESSION_STATE_UP: BFD session 1090519231 to neighbor 172.28.1.193 on interface Eth1/1 is up.
2026 Nov 11 15:42:27.386 bbs1_dc05_m01_new %BGP-5-ADJCHANGE:  bgp- [25358] (default) neighbor 172.28.1.193 Down - sent:  bfd session down
2026 Nov 11 15:42:27.386 bbs1_dc05_m01_new %BFD-5-SESSION_STATE_DOWN: BFD session 1090519231 to neighbor 172.28.1.193 on interface Eth1/1 has gone down. Reason: Neighbor Signaled Session Down.
2026 Nov 11 15:42:27.428 bbs1_dc05_m01_new %ETHPORT-5-IF_DOWN_LINK_FAILURE: Interface Ethernet1/1 (description:pT:bbs1_dc07_m01:100G1/4) is down (Link failure)
2026 Nov 11 15:42:28.418 bbs1_dc05_m01_new %BFD-5-SESSION_REMOVED: BFD session to neighbor 172.28.1.193 on interface Eth1/1 has been removed
2026 Nov 11 15:43:59.801 bbs1_dc05_m01_new %ETHPORT-5-SPEED: Interface Ethernet1/1, operational speed changed to 100 Gbps
2026 Nov 11 15:43:59.801 bbs1_dc05_m01_new %ETHPORT-5-IF_DUPLEX: Interface Ethernet1/1, operational duplex mode changed to Full
2026 Nov 11 15:43:59.801 bbs1_dc05_m01_new %ETHPORT-5-IF_RX_FLOW_CONTROL: Interface Ethernet1/1, operational Receive Flow Control state changed to off
2026 Nov 11 15:43:59.801 bbs1_dc05_m01_new %ETHPORT-5-IF_TX_FLOW_CONTROL: Interface Ethernet1/1, operational Transmit Flow Control state changed to off
2026 Nov 11 15:43:59.817 bbs1_dc05_m01_new %ETHPORT-5-IF_UP: Interface Ethernet1/1 (description:pT:bbs1_dc07_m01:100G1/4) is up in Layer3
2026 Nov 11 15:43:59.916 bbs1_dc05_m01_new %ETHPORT-5-IF_DOWN_LINK_FAILURE: Interface Ethernet1/1 (description:pT:bbs1_dc07_m01:100G1/4) is down (Link failure)
2026 Nov 11 15:44:16.190 bbs1_dc05_m01_new %ETHPORT-5-SPEED: Interface Ethernet1/1, operational speed changed to 100 Gbps
2026 Nov 11 15:44:16.190 bbs1_dc05_m01_new %ETHPORT-5-IF_DUPLEX: Interface Ethernet1/1, operational duplex mode changed to Full
2026 Nov 11 15:44:16.191 bbs1_dc05_m01_new %ETHPORT-5-IF_RX_FLOW_CONTROL: Interface Ethernet1/1, operational Receive Flow Control state changed to off
2026 Nov 11 15:44:16.191 bbs1_dc05_m01_new %ETHPORT-5-IF_TX_FLOW_CONTROL: Interface Ethernet1/1, operational Transmit Flow Control state changed to off
2026 Nov 11 15:44:16.203 bbs1_dc05_m01_new %ETHPORT-5-IF_UP: Interface Ethernet1/1 (description:pT:bbs1_dc07_m01:100G1/4) is up in Layer3
2026 Nov 11 15:44:19.813 bbs1_dc05_m01_new %BGP-5-ADJCHANGE:  bgp- [25358] (default) neighbor 172.28.1.193 Up
2026 Nov 11 15:44:20.821 bbs1_dc05_m01_new %BFD-5-SESSION_MOVED: BFD session 0x410000c0: Installed on LC 1
2026 Nov 11 15:44:20.847 bbs1_dc05_m01_new %BFD-5-SESSION_CREATED: BFD session to neighbor 172.28.1.193 on interface Eth1/1 has been created
2026 Nov 11 15:44:28.670 bbs1_dc05_m01_new %BFD-5-SESSION_STATE_UP: BFD session 1090519232 to neighbor 172.28.1.193 on interface Eth1/1 is up.
"""


def parse_args():
    from config.config import Config
    parser = argparse.ArgumentParser(description="把 RAW_LOG 逐行通过 UDP 发给本机 switchlog 服务")
    parser.add_argument("--host", default="127.0.0.1",
                        help="服务监听地址，默认 127.0.0.1（listen_ip=0.0.0.0 时不能直接发给 0.0.0.0）")
    parser.add_argument("--port", type=int, default=Config.listen_port,
                        help="服务监听端口，要和启动 main.py 时用的端口一致（默认读配置 %(default)s）")
    parser.add_argument("--sleep", type=float, default=SLEEP_SECONDS,
                        help="每条日志之间真实停顿几秒（默认 %(default)s）")
    return parser.parse_args()


def main():
    args = parse_args()
    lines = [l.strip() for l in RAW_LOG.strip().split("\n") if l.strip()]

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print("发往 {}:{}，共 {} 条，每条间隔 {}s".format(args.host, args.port, len(lines), args.sleep))
    print("先确认另一个终端已经跑起来：python main.py --port {}".format(args.port))
    print("-" * 70)

    try:
        for i, line in enumerate(lines):
            sock.sendto(line.encode("utf-8"), (args.host, args.port))
            print("[{}/{}] {}".format(i + 1, len(lines), line[:90]))
            if i < len(lines) - 1 and args.sleep > 0:
                time.sleep(args.sleep)
    finally:
        sock.close()

    print("-" * 70)
    print("发完了。去 main.py 的终端看决策输出，或者查数据库：")
    print("  select * from alarm_log where ip='127.0.0.1' order by log_id desc limit 50;")
    print("  select * from alarm_list where ip='127.0.0.1' order by alarm_id desc limit 20;")


if __name__ == "__main__":
    main()
