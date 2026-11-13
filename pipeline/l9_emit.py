# -*- coding: utf-8 -*-
"""
L9 告警出口

两件事：落 alarm_list，再把要通知的推出去。

    L7 决策 -> L8 填 muted -> L9: 写库 + 通知

落库：
    action=raise                    addAlarm，insert 一行
    action=update/escalate/clear    updateAlarmByFingerprint，更新那一行
    action=none/ignore              不落库也不通知，L8 那边就没往下交

muted 在 insert 的时候一次写进去，不是先写 0 再 UPDATE —— 中间那一瞬间
看板轮询到会显示成"割接期间有条没静默的告警"。L8 的判定在这之前就有结果。

通知：
    被静默的（muted=1）只落库不推送，这是 mute 的全部意义
    闪断（flapping=1）照常推，但带上"需人工确认"

======================= 通知通道 =======================

这一版落地的是文件通道：一条通知写一行 JSON 到 logs/notify.log。
不是临时糊的占位，它有两个长期用途：

    1. HTTP 通道上线后仍然留着，作为推送失败的兜底 —— 接口挂了的时候
       通知不能凭空消失，文件里得有记录
    2. 对账：推送方说没收到的时候，拿这个文件比对

JSON 一行一条（JSONL），不是给人读的格式 —— 给人读的那份在
switchlog.log 里。这个文件是给程序读的：
    tail -f logs/notify.log | jq .
    grep IF_FLAP logs/notify.log | jq -r '.ip + " " + .alarm_object'

HTTP 通道按 Notifier 的接口实现，换一行配置就能切：

    class HttpNotifier(Notifier):
        def send(self, payload): ...

实现 HTTP 的时候有几件事必须做，不然日志风暴时会把管线拖垮：
    * 超时必须设，而且要短（2~3s）。接口卡住等于 worker 卡住
    * 失败不要在热路径上重试，退回文件通道，让重试走离线补偿
    * 要攒批。一次端口 down 产生几条通知，逐条 POST 是浪费
    * 对方限流要认，429 之后退避

所以 HttpNotifier 不是"把 send 换成 requests.post"那么简单，
留到单独一轮做。接口先定在这里。
"""
import os
import json
import time
import logging
import threading

logger = logging.getLogger(__name__)

ALARM_TYPE = "syslog"

# 通知文件。和 switchlog.log 同目录，容器里 logs/ 已经挂卷
NOTIFY_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          "logs")
NOTIFY_FILE = os.path.join(NOTIFY_DIR, "notify.log")

# 动作到人话的映射，通知内容里用
ACTION_TEXT = {
    "raise": "告警",
    "update": "告警更新",
    "escalate": "升级",
    "clear": "恢复",
    "clear_orphan": "恢复（故障发生在监控视野之外）",
    "notify_only": "告警",
}

# L8 静默到期放出来的动作：告警早就在库里，muted 那一列 L8 也改过了，
# 本层只补通知，一个字段都别再写
ACTION_NOTIFY_ONLY = "notify_only"

# L5 判定 ignore 不告警时 L7 产出的两个动作：按指纹聚合，首次插一行、
# 之后只累加 counter。需要落库（否则 alarm_log 写了但 alarm_list 查不到，
# 变成孤儿数据），但永远不发通知
ACTION_IGNORE_NEW = "ignore_new"
ACTION_IGNORE_UPDATE = "ignore_update"
IGNORE_ACTIONS = (ACTION_IGNORE_NEW, ACTION_IGNORE_UPDATE)

# L7 的恢复事件到了但没有活跃告警可关：故障发生在监控视野之外
# （初次上线 / 重建库 / 进程停机期间）。走 insert 落一行 state=clear，
# 照常通知 —— 不能走 _update()，那个按 state='open' 定位，
# alarm_list 里压根没有这条告警的行
ACTION_CLEAR_ORPHAN = "clear_orphan"
# 窗口内重复命中 orphan：同一个口反复发孤立的 up，L7 按指纹聚合到
# 同一行，这里只刷 counter/last_seen，不重复 insert、不重复通知
ACTION_CLEAR_ORPHAN_UPDATE = "clear_orphan_update"

# handle() 要处理的动作全集，和 ACTION_NONE 相对——这些动作都要做点
# 事（写库、或者单纯补通知），none 是"什么都没变"，直接跳过。
# 名字叫 WRITE_ACTIONS 但 notify_only 其实不落库，它落库那一步已经在
# L8 静默到期之前做过了，这里只补通知，具体分发看 _write() 的说明
WRITE_ACTIONS = ("raise", "update", "escalate", "clear", ACTION_CLEAR_ORPHAN,
                 ACTION_CLEAR_ORPHAN_UPDATE, ACTION_NOTIFY_ONLY) + IGNORE_ACTIONS


class Notifier(object):
    """
    通知通道接口

    send(payload) -> True/False。返回 False 表示这条没推出去，
    调用方负责兜底（落文件）或计数，不在这里重试。
    """

    name = "base"

    def send(self, payload):
        raise NotImplementedError

    def close(self):
        pass


class FileNotifier(Notifier):
    """
    写文件通道：一条通知一行 JSON

    追加写 + 每条 flush：进程被 kill 时不丢最后几条。通知量比日志量
    小得多（一次故障几条），这点开销换"崩了也不丢"值得。

    不按天切割 —— 交给 logrotate 或者和 switchlog.log 一样的外部机制。
    这里只管写，不管转。
    """

    name = "file"

    def __init__(self, path=NOTIFY_FILE):
        self._path = path
        self._lock = threading.Lock()
        self._handle = None
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
        except OSError as err:
            logger.error("======FileNotifier 建目录失败========\n%s", err)

    def _open(self):
        if self._handle is None:
            self._handle = open(self._path, "a", encoding="utf-8")
        return self._handle

    def send(self, payload):
        line = json.dumps(payload, ensure_ascii=False, sort_keys=True)
        with self._lock:
            try:
                handle = self._open()
                handle.write(line + "\n")
                handle.flush()
                return True
            except Exception as err:
                logger.error("======FileNotifier write error========\n%s", err)
                # 下次重新打开，文件被外部轮转/删除时能自愈
                self._handle = None
                return False

    def close(self):
        with self._lock:
            if self._handle is not None:
                try:
                    self._handle.close()
                except Exception:
                    pass
                self._handle = None


class HttpNotifier(Notifier):
    """
    HTTP 推送通道  [未实现]

    留这个类是为了把接口和注意事项固定下来。实现时照 send() 的签名写，
    返回 False 让调用方走兜底。

    几件必须做的事，漏了日志风暴时会把管线拖垮：

        超时必须设且要短（2~3s）。接口卡住等于 worker 卡住，
        worker 卡住等于队列堆积，队列满了就开始丢包

        失败不在热路径上重试。退回 FileNotifier，让补偿走离线 ——
        在 handle() 里重试三次，一次网络抖动就能把管线堵死

        要攒批。一次端口 down 产生几条通知，逐条 POST 是浪费

        认对方的限流。429 之后退避，别把人家打挂

    所以这不是"把 send 换成 requests.post"那么简单，留到单独一轮做。
    """

    name = "http"

    def __init__(self, url="", timeout=3, fallback=None):
        self._url = url
        self._timeout = int(timeout)
        # 推送失败的兜底，通知不能凭空消失
        self._fallback = fallback if fallback is not None else FileNotifier()
        logger.warning("HttpNotifier 还没实现，通知走文件通道。"
                       "接口和注意事项见 pipeline/l9_emit.py")

    def send(self, payload):
        # 实现之后这里换成带超时的 POST，失败再落 fallback
        return self._fallback.send(payload)

    def close(self):
        self._fallback.close()


def build_notifier():
    """按 config.notify_channel 建通知通道。配置读不到就用文件通道"""
    try:
        from config.config import Config
        channel = str(getattr(Config, "notify_channel", "file") or "file").lower()
        if channel == "http":
            return HttpNotifier(url=getattr(Config, "notify_http_url", ""),
                                timeout=getattr(Config, "notify_http_timeout", 3))
    except Exception as err:
        logger.error("======build_notifier 读配置失败，用文件通道========\n%s", err)
    return FileNotifier()


class AlarmEmitter(object):
    """
    L9：落 alarm_list + 推通知

    worker 共享一个实例。落库走数据库连接各自开，通知通道内部自己加锁。
    """

    def __init__(self, notifier=None, state_machine=None, db=None,
                 write_db=None, notify=None):
        """
        :param notifier:      通知通道，不传按 config.notify_channel 建
        :param state_machine: L7 实例，insert 之后要把 alarm_id 回填进状态
        :param db:            数据源，由 db.get_alarm_db() 注入
        :param write_db:      落不落 alarm_list，不传读 config.alarm_write_db
        :param notify:        推不推通知，不传读 config.alarm_notify

        两个开关分开：落库和通知是两件事。规则没调稳的时候常见的做法是
        落库但不推通知 —— 看板上能看到告警，但不打扰人
        """
        self._notifier = notifier if notifier is not None else build_notifier()
        self._state_machine = state_machine
        self._db = db
        self._write_db = self._switch(write_db, "alarm_write_db")
        self._notify_on = self._switch(notify, "alarm_notify")
        self._lock = threading.Lock()
        self._counts = {"inserted": 0, "updated": 0, "notified": 0,
                        "muted": 0, "failed": 0, "skipped": 0, "ignored": 0}
        # fingerprint -> 上次同步出去的 counter。没变就不写，
        # 否则一个 down 了一天的口每 10 秒白写一次 UPDATE
        self._synced = {}

        if not self._write_db:
            logger.warning("alarm_write_db=False，告警不落 alarm_list，"
                           "看板上看不到任何告警。只有对规则的时候才该这么配")

    @staticmethod
    def _switch(value, config_key):
        """不传就读配置。读不到（单测里没有 config.py）按 True —— 默认是出告警"""
        if value is not None:
            return bool(value)
        try:
            from config.config import Config
            return bool(getattr(Config, config_key, True))
        except Exception:
            return True

    @property
    def db(self):
        if self._db is None:
            from db import get_alarm_db
            self._db = get_alarm_db()
        return self._db

    # ---------------- 入口 ----------------

    def handle(self, decision, now=None):
        """
        落库 + 通知

        :param decision: L7 产出、L8 填过 muted 的决策
        :return: {"alarm_id", "notified", "muted"}；不用处理的返回 None

        "要不要落库"和"要不要通知"是两个独立判断：ignore_new/ignore_update
        要落库（否则 alarm_log 写了但 alarm_list 查不到，变成孤儿数据），
        但不通知；none 既不落库也不通知——它就是"什么都没变"
        """
        action = decision.get("action", "") if decision else ""
        if not decision or action not in WRITE_ACTIONS:
            return None

        clock = int(now if now is not None else (decision.get("ingest_ts") or time.time()))

        # 落库。alarm_list 是看板的唯一数据源，这一步不做看板上就什么都没有
        alarm_id = 0
        if self._write_db:
            alarm_id = self._write(decision, action, clock)
        else:
            with self._lock:
                self._counts["skipped"] += 1

        if action in IGNORE_ACTIONS:
            # L5 判定不告警，落库留痕即可，不走通知判断（不是被 mute 压住，
            # 是这类事件本来就不该发通知）
            with self._lock:
                self._counts["ignored"] += 1
            return {"alarm_id": alarm_id, "notified": False, "muted": False}

        if action == ACTION_CLEAR_ORPHAN_UPDATE:
            # 窗口内重复的孤立恢复，已经在第一次 orphan 通知过了，
            # 这次只是刷新同一行的 counter，不重复打扰
            with self._lock:
                self._counts["updated"] += 1
            return {"alarm_id": alarm_id, "notified": False, "muted": False}

        # 被静默的只落库不推送，这是 mute 的全部意义
        if decision.get("muted"):
            with self._lock:
                self._counts["muted"] += 1
            return {"alarm_id": alarm_id, "notified": False, "muted": True}

        if not self._notify_on:
            return {"alarm_id": alarm_id, "notified": False, "muted": False}

        notified = self._notify(decision, action, alarm_id, clock)
        return {"alarm_id": alarm_id, "notified": notified, "muted": False}

    # ---------------- 落库 ----------------

    def _write(self, decision, action, now):
        """
        新开的走 insert，已开着的走 update

        escalate 也算新开：L7 的 _escalate() 只在 _open() 里调，也就是
        "无活跃告警 -> 开告警"那一跳顺手判出了闪断。所以它和 raise 一样
        是一条新告警，只是级别提过、event_code 换成了 IF_FLAP。
        按 update 处理会落空 —— 闪断的前一跳是 clear，alarm_list 里那行
        已经是 state=clear，而 update 只认 state=open 的行。

        notify_only 不写库：那是 L8 静默到期放出来的，告警早就在
        alarm_list 里，muted 那一列 L8 也改过了。再 update 一次会拿
        决策里的默认值把 last_seen 和 counter 冲掉

        ignore_new/ignore_update 单独分发：这类行 state 永远是 idle，
        不能走 _update()（按 state='open' 定位，找不到行）

        :return: alarm_id。update 的时候返回决策里带的那个（L7 回填过）
        """
        if action == ACTION_NOTIFY_ONLY:
            return decision.get("alarm_id", 0)
        if action in ("raise", "escalate"):
            return self._insert(decision, now)
        if action == ACTION_CLEAR_ORPHAN:
            # 走 insert：alarm_list 里没有这条告警的行，_update() 的
            # where state='open' 找不到东西，只会打一条 warning 然后什么
            # 都不写。decision 里 state 是 idle、clear_time 已填好
            return self._insert(decision, now)
        if action == ACTION_CLEAR_ORPHAN_UPDATE:
            # 同样不能走 _update()：这一行 state='clear'，不是 'open'，
            # 按 state='open' 定位会找不到。走专用方法，同 ignore_update
            return self._update_clear_orphan(decision, now)
        if action == ACTION_IGNORE_NEW:
            return self._insert(decision, now)
        if action == ACTION_IGNORE_UPDATE:
            return self._update_ignore(decision, now)
        return self._update(decision, action, now)

    def _insert(self, decision, now):
        """
        新开一条告警

        state 从 decision 取，不硬编码 "open" —— ignore_new 的
        decision["state"] 是 "idle"（L7 的 _decide 里 state.state 就是
        idle，它不开"活跃告警"）。status 跟着 action 分支：ignore 系列
        标 "5"（系统规则判定忽略），其余新开的都是 "0" 待处理

        clear_orphan 是唯一一条"插进来就已经恢复了"的路径：故障发生在
        监控视野之外，只看到恢复日志。它的 state 要写 clear 而不是
        decision 里的 idle，并且带上 clear_time —— 两个字段都和另外
        几种 insert 不一样，所以单独判一个标志位
        """
        action_now = decision.get("action")
        is_ignore = action_now in IGNORE_ACTIONS
        is_clear_orphan = action_now == ACTION_CLEAR_ORPHAN
        row = {
            "ip": decision.get("ip", ""),
            "hostname": decision.get("hostname") or decision.get("ip", ""),
            "alarm_type": ALARM_TYPE,
            # 两个字段名沿用 central-server 的老结构，现有分组页面不用改
            "group_label": decision.get("fingerprint", ""),
            "keyword": decision.get("event_code", ""),
            "group_name": decision.get("event_code", ""),
            "msg": decision.get("message", ""),
            "alarm_object": decision.get("alarm_object", "-"),
            "fingerprint": decision.get("fingerprint", ""),
            # L4 富化结果，排查用，只在新开告警时写一次 ——
            # 恢复/更新走 _update，不碰这些列，老行也不受影响
            "vendor": decision.get("vendor", ""),
            "hardware": decision.get("hardware", ""),
            "object_name": decision.get("object_name", ""),
            "object_alias": decision.get("object_alias", ""),
            "severity": decision.get("severity", 3),
            # clear_orphan 落的是一行"已恢复"，不能用 decision 里的 state ——
            # 那是 syslog_alarm_state 的约定值 idle（它不是活跃告警），
            # 而 alarm_list.state 只认 open/clear，写 idle 进去看板认不出来
            "state": "clear" if is_clear_orphan else (decision.get("state") or "open"),
            "status": "5" if is_ignore else "0",
            "counter": decision.get("counter", 1),
            "first_seen": str(decision.get("first_seen") or now),
            "last_seen": str(decision.get("last_seen") or now),
            # 只有 clear_orphan 这条 insert 路径会带恢复时间（和恢复时刻同值，
            # 看板上持续时长显示 0）。raise/escalate/ignore 都还没恢复，留空
            "clear_time": str(decision.get("clear_time") or now) if is_clear_orphan else "",
            "create_time": str(now),
            # L8 判完了，一次写进去。ignore 系列没过 L8（L9 的 handle()
            # 在落库之后就直接返回了，不读 muted），固定不静默
            "muted": False if is_ignore else decision.get("muted", False),
            "mute_rule_id": 0 if is_ignore else decision.get("mute_rule_id", 0),
        }
        try:
            alarm_id = self.db.addAlarm(row)
        except Exception as err:
            logger.error("======AlarmEmitter addAlarm error========\n%s", err)
            alarm_id = 0

        if not alarm_id:
            with self._lock:
                self._counts["failed"] += 1
            if is_ignore:
                # ignore 本来就不发通知，落库失败只记一条 error，不用像
                # raise/update 那样"仍会推送通知"
                logger.error("======ignore 告警落库失败========\n%s %s %s",
                             decision.get("ip"), decision.get("event_code"),
                             decision.get("alarm_object"))
                return 0
            # 落库失败也要通知 —— 告警丢了比看板少一行严重得多
            logger.error("======告警落库失败，仍会推送通知========\n%s %s %s",
                         decision.get("ip"), decision.get("event_code"),
                         decision.get("alarm_object"))
            return 0

        with self._lock:
            self._counts["inserted"] += 1
        # alarm_id 回填进 L7 的状态，下次更新同一条告警要用。
        # for_ignore 决定绑到哪个槽位：同一指纹下 ignore 行和告警行是两条
        # 独立记录，id 混在一个槽位里会互相覆盖
        if self._state_machine is not None:
            try:
                self._state_machine.bind_alarm(decision.get("fingerprint"), alarm_id,
                                               for_ignore=is_ignore)
            except Exception as err:
                logger.error("======AlarmEmitter bind_alarm error========\n%s", err)
        return alarm_id

    def _update(self, decision, action, now):
        """更新已有告警。按指纹更新那条未恢复的"""
        data = {
            "last_seen": str(decision.get("last_seen") or now),
            "counter": decision.get("counter", 1),
            "severity": decision.get("severity", 3),
        }
        if action == "escalate":
            # 闪断升级：event_code 从 IF_DOWN 变成 IF_FLAP，keyword 要跟着改，
            # 否则看板上级别提了但事件码还是 IF_DOWN，看不出这是闪断。
            # 指纹不动（L7 升级时就没动），所以这一行还找得到
            code = decision.get("event_code", "")
            data["keyword"] = code
            data["group_name"] = code
        if action == "clear":
            data["state"] = "clear"
            data["clear_time"] = str(decision.get("clear_time") or now)

        try:
            result = self.db.updateAlarmByFingerprint(decision.get("fingerprint"), data)
        except Exception as err:
            logger.error("======AlarmEmitter update error========\n%s", err)
            result = "failed"

        if result == "failed":
            with self._lock:
                self._counts["failed"] += 1
        elif result == 0:
            # 没有未恢复的行可更新。L7 认为有活跃告警但 alarm_list 里没有，
            # 多半是上次进程 insert 失败或者库被手工清过。状态表和看板
            # 不一致，得能看出来
            logger.warning("alarm_list 里没有 %s 的未恢复告警，%s 动作没落库 —— "
                           "状态表和 alarm_list 不一致",
                           decision.get("fingerprint", "")[:12], action)
        else:
            with self._lock:
                self._counts["updated"] += 1
        return decision.get("alarm_id", 0)

    def _update_ignore(self, decision, now):
        """
        更新已有 ignore 行的 counter/last_seen

        不走 _update()：那个方法按 state='open' 定位行，但 ignore 行
        永远是 state='idle'。只更新这两个字段——ignore 没有级别变化、
        没有 event_code 变化（不会升级成 IF_FLAP），不需要 _update()
        里 escalate/clear 那两段特殊逻辑
        """
        data = {
            "last_seen": str(decision.get("last_seen") or now),
            "counter": decision.get("counter", 1),
        }
        try:
            # 带上 alarm_id 精确定位：同一指纹下可能还有一条 clear_orphan
            # 行（IF_UP 的指纹按 raise_code 换算成 IF_DOWN 的），只按指纹
            # 取最新一行会串写到那条上去
            result = self.db.updateIgnoreByFingerprint(
                decision.get("fingerprint"), data,
                alarm_id=decision.get("alarm_id", 0))
        except Exception as err:
            logger.error("======AlarmEmitter update_ignore error========\n%s", err)
            result = "failed"

        if result == "failed":
            with self._lock:
                self._counts["failed"] += 1
        elif result == 0:
            # 没有行可更新。多半是 ignore_new 那次落库失败了，状态表和
            # alarm_list 不一致，得能看出来
            logger.warning("alarm_list 里没有 %s 的 ignore 行，更新没落库 —— "
                           "状态表和 alarm_list 不一致",
                           decision.get("fingerprint", "")[:12])
        else:
            with self._lock:
                self._counts["updated"] += 1
        return decision.get("alarm_id", 0)

    def _update_clear_orphan(self, decision, now):
        """
        更新已有 clear_orphan 行的 counter/last_seen

        同一个口在聚合窗口内反复发孤立的 up（没有对应 down，纯粹链路抖动
        或设备侧重复上报），L7 只在第一次 insert，之后都走这里刷新同一行，
        不再新插、也不重复通知。复用 updateIgnoreByFingerprint ——
        两边都是"按 fingerprint 定位、不限制 state"的更新，没必要另写一份
        """
        data = {
            "last_seen": str(decision.get("last_seen") or now),
            "counter": decision.get("counter", 1),
        }
        try:
            result = self.db.updateIgnoreByFingerprint(
                decision.get("fingerprint"), data,
                alarm_id=decision.get("alarm_id", 0))
        except Exception as err:
            logger.error("======AlarmEmitter update_clear_orphan error========\n%s", err)
            result = "failed"

        if result == "failed":
            with self._lock:
                self._counts["failed"] += 1
        elif result == 0:
            logger.warning("alarm_list 里没有 %s 的 clear_orphan 行，更新没落库 —— "
                           "状态表和 alarm_list 不一致",
                           decision.get("fingerprint", "")[:12])
        else:
            with self._lock:
                self._counts["updated"] += 1
        return decision.get("alarm_id", 0)

    # ---------------- 通知 ----------------

    def _notify(self, decision, action, alarm_id, now):
        """推一条通知。推失败只计数，不在热路径上重试"""
        payload = self.build_payload(decision, action, alarm_id, now)
        try:
            ok = self._notifier.send(payload)
        except Exception as err:
            logger.error("======AlarmEmitter notify error========\n%s", err)
            ok = False

        with self._lock:
            if ok:
                self._counts["notified"] += 1
            else:
                self._counts["failed"] += 1
        return ok

    @staticmethod
    def build_payload(decision, action, alarm_id, now):
        """
        拼通知内容。HTTP 通道上线后推的就是这个结构，所以字段名要稳

        title 是给人看的一行摘要，其余字段给程序用（分发策略按 severity
        和 event_code 走，不靠解析 title）
        """
        severity = decision.get("severity", 3)
        event_code = decision.get("event_code", "")
        action_text = ACTION_TEXT.get(action, action)
        flags = []
        if decision.get("flapping"):
            flags.append("闪断，需人工确认")
        if decision.get("reason") == "mute_expired":
            flags.append("静默窗口已结束，故障仍未恢复")

        title = "[{}] {} {} {} {}".format(
            decision.get("severity_name", "P3"), action_text,
            decision.get("ip", "-"), decision.get("alarm_object", "-"), event_code)
        if flags:
            title += "（{}）".format("，".join(flags))

        return {
            "ts": now,
            "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now)),
            "title": title,
            "action": action,
            "alarm_id": alarm_id,
            "fingerprint": decision.get("fingerprint", ""),
            "ip": decision.get("ip", ""),
            "hostname": decision.get("hostname", ""),
            "event_code": event_code,
            "alarm_object": decision.get("alarm_object", "-"),
            "severity": severity,
            "severity_name": decision.get("severity_name", "P3"),
            "counter": decision.get("counter", 0),
            "first_seen": decision.get("first_seen", 0),
            "last_seen": decision.get("last_seen", 0),
            "flapping": decision.get("flapping", 0),
            "need_confirm": bool(decision.get("flapping")),
            "msg": decision.get("message", ""),
            "flags": flags,
        }

    # ---------------- 维护 ----------------

    def sync_counters(self, snapshots):
        """
        把还开着的告警的 counter / last_seen 刷进 alarm_list

        为什么需要这个：L7 对已有活跃告警的后续日志返回 ACTION_NONE
        （不重复通知，这是对的），于是 L9 整个不跑，alarm_list.counter
        停在开告警那一刻。一次端口 down 产生三条同指纹日志，
        schema 说 counter 是"窗口内日志条数"，看板上却显示 1。

        放在维护线程里按 tick 刷，不在热路径上每条日志都 UPDATE ——
        日志风暴时一个指纹刷一万条，那就是一万次 UPDATE。这里一轮
        一个指纹最多一次。

        只刷 counter / last_seen / severity 三列：state 和 clear_time 由
        正常的 clear 动作管，不能在这里碰。

        :param snapshots: StateMachine.open_snapshots() 的输出
        :return: 刷新的行数
        """
        if not self._write_db:
            return 0
        # snapshots 为空也要往下走：那说明所有告警都恢复了，
        # _synced 里的残留要清掉
        snapshots = snapshots or []

        alive = set()
        synced = 0
        for row in snapshots:
            fingerprint = row.get("fingerprint")
            if not fingerprint:
                continue
            alive.add(fingerprint)
            counter = row.get("counter", 1)
            last_seen = row.get("last_seen") or ""
            # counter 和 last_seen 都没动才不写。stateless 事件一旦开告警
            # 后 counter 就封顶不再涨（_on_stateless 的 is_open() 分支只
            # 推 last_seen，不碰 counter），只按 counter 判断会让这类
            # 事件的 last_seen 永远停在第一次同步时的值，详情下钻的时间
            # 窗口越往后收到的日志越漏得多
            mark = (counter, last_seen)
            if self._synced.get(fingerprint) == mark:
                continue
            data = {
                "counter": counter,
                "last_seen": str(last_seen),
                "severity": row.get("severity", 3),
            }
            try:
                result = self.db.updateAlarmByFingerprint(fingerprint, data)
            except Exception as err:
                logger.error("======AlarmEmitter sync_counters error========\n%s", err)
                continue
            if result not in ("failed", 0):
                self._synced[fingerprint] = mark
                synced += 1

        # 告警恢复了就从表里去掉，否则这个 dict 跟着历史告警无限涨。
        # 同一指纹下次再开告警时和这里的残留值比可能正好相等，
        # 那就漏写一次 —— 所以必须清
        for key in list(self._synced):
            if key not in alive:
                self._synced.pop(key, None)
        return synced

    def stats(self):
        with self._lock:
            return dict(self._counts)

    def stop(self):
        try:
            self._notifier.close()
        except Exception:
            pass
