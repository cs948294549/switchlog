# -*- coding: utf-8 -*-
"""
L9 告警出口

两件事：落 alarm_list，再把要通知的推出去。

    L7 决策 -> L8 填 muted -> L9: 写库 + 通知

一个窗口段 = alarm_list 的一行，L7 已经判完这条事件是插行还是改行：

    action=raise         addAlarm，insert 本段那一行
    action=reopen        updateAlarmById，翻回 open 并清掉恢复时间
    action=update        updateAlarmById，级别变了
    action=clear         updateAlarmById，盖恢复标签
    action=notify_only   不写库，只补通知（L8 静默到期）
    action=none          什么都不做，L7 那边就没往下交

**改行一律按 alarm_id 定位**，不按 fingerprint。一个指纹下有多行（每个
窗口段一行），按指纹只能"取最新一行"，段切换那一瞬间会串写到隔壁去。

muted 在 insert 的时候一次写进去，不是先写 0 再 UPDATE —— 中间那一瞬间
看板轮询到会显示成"割接期间有条没静默的告警"。L8 的判定在这之前就有结果。

通知：
    被静默的（muted=1）只落库不推送，这是 mute 的全部意义
    ignore 段（decision["ignored"]）也只落库不推送，但原因不同：
    前者是时间窗临时压住，后者是这类事件本来就不该告警

======================= 通知通道 =======================

这一版落地的是文件通道：一条通知写一行 JSON 到 logs/notify.log。
不是临时糊的占位，它有两个长期用途：

    1. HTTP 通道上线后仍然留着，作为推送失败的兜底 —— 接口挂了的时候
       通知不能凭空消失，文件里得有记录
    2. 对账：推送方说没收到的时候，拿这个文件比对

JSON 一行一条（JSONL），不是给人读的格式 —— 给人读的那份在
switchlog.log 里。这个文件是给程序读的：
    tail -f logs/notify.log | jq .
    grep IF_DOWN logs/notify.log | jq -r '.ip + " " + .alarm_object'

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
    "reopen": "再次告警",
    "update": "告警更新",
    "clear": "恢复",
    "notify_only": "告警",
}

# L8 静默到期放出来的动作：告警早就在库里，muted 那一列 L8 也改过了，
# 本层只补通知，一个字段都别再写
ACTION_NOTIFY_ONLY = "notify_only"

# 本段第一行，走 insert。clear 事件也可能产生它 —— 故障发生在监控视野
# 之外（初次上线 / 重建库 / 进程停机期间，或者 down 了两小时才 up，
# 那条 down 在上一段里），这一行生而恢复，state=clear
ACTION_RAISE = "raise"
# 同段内恢复之后又来故障：翻回 open 并清掉恢复时间，不插新行
ACTION_REOPEN = "reopen"

# handle() 要处理的动作全集，和 ACTION_NONE 相对——这些动作都要做点
# 事（写库、或者单纯补通知），none 是"什么都没变"，直接跳过。
# 名字叫 WRITE_ACTIONS 但 notify_only 其实不落库，它落库那一步已经在
# L8 静默到期之前做过了，这里只补通知，具体分发看 _write() 的说明
WRITE_ACTIONS = (ACTION_RAISE, ACTION_REOPEN, "update", "clear",
                 ACTION_NOTIFY_ONLY)


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

    def __init__(self, notifier=None, state_machine=None, db=None, notify=None,
                 write_db=True):
        """
        :param notifier:      通知通道，不传按 config.notify_channel 建
        :param state_machine: L7 实例，insert 之后要把 alarm_id 回填进状态
        :param db:            数据源，由 db.get_alarm_db() 注入
        :param notify:        推不推通知，不传读 config.alarm_notify
        :param write_db:      False=不落 alarm_list。给 test.py 这类调试
                              脚本用：整条管线照常跑、通知照常输出到
                              notify.log，只是不往库里写告警

        write_db 这个开关曾经去掉过，理由是"alarm_list 是看板的唯一数据
        源，关掉看板就全空，运行态没人会关它"。现在加回来是为了调试：
        test.py 要能拿真实日志过一遍完整管线看判定结果，但不该污染
        生产库。**运行态不要关这个开关**，关了看板就没数据。
        """
        self._notifier = notifier if notifier is not None else build_notifier()
        self._state_machine = state_machine
        self._db = db
        self._notify_on = self._switch(notify, "alarm_notify")
        self._write_db = bool(write_db)
        self._lock = threading.Lock()
        # skipped 记 write_db=False 时跳过落库的条数，调试时用来确认
        # "该落库的都走到了这一步"，和 failed（真的写失败）分开
        self._counts = {"inserted": 0, "updated": 0, "notified": 0,
                        "muted": 0, "failed": 0, "ignored": 0, "skipped": 0}
        # write_db=False 时发给 L7 的假 alarm_id，从 -1 开始递减。
        # 见 _emit_without_db() 的注释
        self._fake_alarm_seq = 0
        # alarm_id -> 上次同步出去的 (counter, last_seen)。没变就不写，
        # 否则一个 down 了一天的口每 10 秒白写一次 UPDATE。
        # 按 alarm_id 不按 fingerprint：一个指纹下有多行（每段一行）
        self._synced = {}

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

        "要不要落库"和"要不要通知"是两个独立判断：ignore 段要落库
        （否则 alarm_log 写了但 alarm_list 查不到，变成孤儿数据），
        但不通知；none 既不落库也不通知——它就是"什么都没变"。

        **例外是 mute 状态变了。** action=none 的意思是"告警本身没有新
        进展"，但人可能刚在前端加了一条静默规则：这条日志走到 L8 命中了，
        而库里那一行还是 muted=0 / status='0'。不单独处理的话这一行永远
        改不过来 —— 段内后续的日志全是 none（PSU_FAIL 窗口 7 天，一次
        风扇故障后面所有日志都落在同一段里），看板上就是"日志里一直在打
        静默，但告警还挂在待处理里"。所以 none 也要判一次 mute 有没有变，
        变了就只改那三列
        """
        action = decision.get("action", "") if decision else ""
        if not decision:
            return None
        if action not in WRITE_ACTIONS:
            return self._sync_mute(decision, now)

        clock = int(now if now is not None else (decision.get("ingest_ts") or time.time()))

        # 落库。alarm_list 是看板的唯一数据源，没有开关可以跳过这一步
        alarm_id = self._write(decision, action, clock)

        if decision.get("ignored"):
            # L5 判定不告警，落库留痕即可，不走通知判断（不是被 mute 压住，
            # 是这类事件本来就不该发通知）
            with self._lock:
                self._counts["ignored"] += 1
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
        本段第一行走 insert，其余都是改这一行

        raise 的行可能一出生就是 state=clear：故障发生在监控视野之外
        （初次上线 / 重建库 / 进程停机期间，或者 down 了两小时才 up，
        那条 down 在上一段里）。state 和 clear_time 都由 L7 在决策里
        填好，本层不自己判。

        notify_only 不写库：那是 L8 静默到期放出来的，告警早就在
        alarm_list 里，muted 那一列 L8 也改过了。再 update 一次会拿
        决策里的默认值把 last_seen 和 counter 冲掉

        :return: alarm_id。update 的时候返回决策里带的那个（L7 回填过）
        """
        if action == ACTION_NOTIFY_ONLY:
            return decision.get("alarm_id", 0)
        if action == ACTION_RAISE:
            return self._insert(decision, now)
        return self._update(decision, action, now)

    def _insert(self, decision, now):
        """
        插本段那一行

        state / clear_time 全从 decision 取，本层不自己判 —— L7 已经
        决定好这一行是 open、clear（视野外恢复，生而恢复）还是 idle
        （ignore 段，它不是活跃告警，没有恢复的那一刻）。

        status 三种来源，优先级从高到低：
            ignore 段            "5"  系统规则判定忽略，人工操作选不到
            L8 命中 mute 规则    "4"  已屏蔽（人工屏蔽就是 mute，不区分
                                      "人点的"和"规则设的"），由 L8 的
                                      handle() 填进 decision["status"]
            其余                 "0"  待处理
        ignore 优先级最高：那种段压根没过 L8（本层 handle() 在落库之后
        就返回了，不读 muted），不可能带 mute 状态
        """
        is_ignore = bool(decision.get("ignored"))
        row_state = decision.get("state") or "open"
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
            "state": row_state,
            # ignore 最高优先；否则用 L8 填的（命中mute='4'）；都没有就'0'
            "status": ("5" if is_ignore
                       else (decision.get("status") or "0")),
            "counter": decision.get("counter", 1),
            "first_seen": str(decision.get("first_seen") or now),
            "last_seen": str(decision.get("last_seen") or now),
            # 生而恢复的那一行带恢复时间（和恢复时刻同值，看板上持续时长
            # 显示 0）。open / idle 的留空，看板按"空=未恢复"判
            "clear_time": (str(decision.get("clear_time") or now)
                           if row_state == "clear" else ""),
            "create_time": str(now),
            # L8 判完了，一次写进去。ignore 段没过 L8（L9 的 handle()
            # 在落库之后就直接返回了，不读 muted），固定不静默
            "muted": False if is_ignore else decision.get("muted", False),
            "mute_rule_id": 0 if is_ignore else decision.get("mute_rule_id", 0),
        }
        if not self._write_db:
            # 不落库。给一个假的 alarm_id 让后面的通知分支照常跑完 ——
            # 调试时要看的就是"这条会不会通知、通知内容长什么样"。
            # 用负数，一眼能看出不是真的库里的 id
            with self._lock:
                self._counts["skipped"] += 1
            return self._emit_without_db(decision, row, now, is_ignore)

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
        # alarm_id 和 muted 一起回填进 L7 的段状态：前者定位这一行，
        # 后者让下一条事件判得出"这一行刚从静默解除"
        self._bind(decision.get("fingerprint"), alarm_id, row.get("muted"))
        return alarm_id

    def _emit_without_db(self, decision, row, now, is_ignore):
        """
        write_db=False 时代替 _insert 的落库那一段

        返回一个**负数**的假 alarm_id：
          - 让 bind_alarm 照常回填，L7 的段状态里有了 id，本段后续的
            update/clear 才会走 _update 分支而不是反复 insert ——
            调试时能看到完整的"开告警 -> 累加 -> 恢复"动作序列
          - 用负数是为了一眼看出不是库里的真 id，万一哪天误开了
            write_db=False 又去查库，不会拿这个 id 去 WHERE

        同一指纹多次 insert 要拿到不同的假 id（L7 按 id 区分段），
        所以用一个递减的计数器，不是写死 -1
        """
        with self._lock:
            self._fake_alarm_seq -= 1
            alarm_id = self._fake_alarm_seq
        logger.info("[write_db=False] 跳过落库 alarm_list：%s %s %s "
                    "state=%s status=%s muted=%s（假id=%s）",
                    row.get("ip"), row.get("keyword"), row.get("alarm_object"),
                    row.get("state"), row.get("status"), row.get("muted"),
                    alarm_id)
        self._bind(decision.get("fingerprint"), alarm_id, row.get("muted"))
        return alarm_id

    def _update(self, decision, action, now):
        """
        改本段那一行，按 alarm_id 定位

        不按 fingerprint：一个指纹下有多行（每个窗口段一行），按指纹只能
        "取最新一行"，段切换那一瞬间会串写到隔壁去。alarm_id 由 insert
        之后 bind_alarm 回填，L7 的段状态里一直带着。

        reset_status=True：这些动作都代表"故障有新进展"（又掉了、级别变了、
        恢复了），处理过的要翻回待处理重新入队，否则一次确认就把后面的
        进展全埋掉了。被 mute 的和已屏蔽的不翻，见 updateAlarmById

        reopen 要把 state 写回 open 并清空 clear_time —— 看板按
        "clear_time 为空 = 未恢复"判，只改 state 的话会显示成
        "告警中但有恢复时间"

        **mute 那三列每次都写。** 段内后续的日志照样过 L8，规则可能是在
        这一行 insert 之后才加的（PSU_FAIL 窗口 7 天，一次风扇故障后面
        所有日志都落在同一段里），只在 insert 时写的话库里永远是
        muted=0 / status='0'，看板上就是"日志里一直在打静默，但告警还挂在
        待处理里"。两个方向都写：
            命中规则    muted=1  mute_rule_id=N  status='4'
            不命中      muted=0  mute_rule_id=0  status 见下
        """
        data = {
            "last_seen": str(decision.get("last_seen") or now),
            "counter": decision.get("counter", 1),
            "severity": decision.get("severity", 3),
        }
        if action == ACTION_REOPEN:
            data["state"] = "open"
            data["clear_time"] = ""
        if action == "clear":
            data["state"] = "clear"
            data["clear_time"] = str(decision.get("clear_time") or now)

        muted = bool(decision.get("muted"))
        data["muted"] = muted
        data["mute_rule_id"] = decision.get("mute_rule_id", 0) if muted else 0
        if muted:
            # L8 填的 '4'。它一定有值 —— handle() 命中规则时写的
            data["status"] = decision.get("status") or "4"
        # 上次是静默的、这次不命中了（窗口过了）：要把 status='4' 翻回 '0'。
        # 交给 SQL 的 CASE 做，不在这里写死 —— 人工设的 1/2/3 得留着，
        # 由 reset_status 那条分支管
        unmute = bool(decision.get("row_muted")) and not muted

        alarm_id = decision.get("alarm_id", 0)
        if not self._write_db:
            with self._lock:
                self._counts["skipped"] += 1
            logger.info("[write_db=False] 跳过更新 alarm_list：alarm_id=%s "
                        "action=%s %s", alarm_id, action, data)
            # 返回 alarm_id，和正常路径一致（调用方拿它去发通知）
            return alarm_id

        try:
            result = self.db.updateAlarmById(alarm_id, data, reset_status=True,
                                             unmute=unmute)
        except Exception as err:
            logger.error("======AlarmEmitter update error========\n%s", err)
            result = "failed"

        if result == "failed":
            with self._lock:
                self._counts["failed"] += 1
        elif result == 0:
            # alarm_id 指向的行不在了，多半是库被手工清过。段状态和看板
            # 不一致，得能看出来
            logger.warning("alarm_list 里没有 alarm_id=%s 这一行，%s 动作没落库 —— "
                           "段状态和 alarm_list 不一致（指纹 %s）",
                           alarm_id, action, decision.get("fingerprint", "")[:12])
        else:
            with self._lock:
                self._counts["updated"] += 1
            # 把实际写进去的 muted 回填进段状态，下一条事件才判得出
            # "刚从静默解除"这一跳
            self._bind(decision.get("fingerprint"), None, muted)
            if unmute:
                logger.info("解除静默：alarm_id=%s %s %s（窗口已过，"
                            "status 翻回待处理）", alarm_id,
                            decision.get("ip"), decision.get("alarm_object"))
        return alarm_id

    def _sync_mute(self, decision, now=None):
        """
        action=none 时只同步 mute 那三列

        触发条件是 L8 这次的判定和库里那一行不一致（人刚加了规则、或者
        规则的窗口刚过）。不改 last_seen / counter —— 那两列由
        sync_counters() 定期刷，这里只管 mute。

        :return: {"alarm_id", "notified", "muted"}；没变化返回 None
        """
        muted = bool(decision.get("muted"))
        was_muted = bool(decision.get("row_muted"))
        alarm_id = decision.get("alarm_id", 0)
        # 没有行可改（本段还没到阈值 / insert 失败过），或者状态没变
        if not alarm_id or muted == was_muted:
            return None

        clock = int(now if now is not None else (decision.get("ingest_ts") or time.time()))
        data = {
            "muted": muted,
            "mute_rule_id": decision.get("mute_rule_id", 0) if muted else 0,
        }
        if muted:
            data["status"] = decision.get("status") or "4"

        if not self._write_db:
            with self._lock:
                self._counts["skipped"] += 1
            logger.info("[write_db=False] 跳过同步 mute：alarm_id=%s %s",
                        alarm_id, data)
            self._bind(decision.get("fingerprint"), None, muted)
            return None

        try:
            # reset_status=False：这一跳不是"故障有新进展"，不该把人工
            # 设的 1/2/3 翻回待处理。unmute 那条 CASE 照常要
            result = self.db.updateAlarmById(alarm_id, data, reset_status=False,
                                             unmute=(was_muted and not muted))
        except Exception as err:
            logger.error("======AlarmEmitter sync_mute error========\n%s", err)
            result = "failed"

        if result in ("failed", 0):
            with self._lock:
                self._counts["failed"] += 1
            return None

        with self._lock:
            self._counts["updated"] += 1
        self._bind(decision.get("fingerprint"), None, muted)
        logger.info("%s：alarm_id=%s %s %s %s（rule %s）",
                    "静默" if muted else "解除静默", alarm_id,
                    decision.get("ip"), decision.get("event_code"),
                    decision.get("alarm_object"), data["mute_rule_id"])
        # 这一跳不发通知：告警本身没有新进展，只是标记变了
        return {"alarm_id": alarm_id, "notified": False, "muted": muted}

    def _bind(self, fingerprint, alarm_id, muted):
        """回填落库结果进 L7 的段状态。没挂状态机（单测）时什么都不做"""
        if self._state_machine is None:
            return
        try:
            self._state_machine.bind_alarm(fingerprint, alarm_id, muted=muted)
        except Exception as err:
            logger.error("======AlarmEmitter bind_alarm error========\n%s", err)

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
        if action == ACTION_REOPEN:
            # 同一段内恢复之后又来故障。推送方据此知道这不是一条新告警，
            # 是同一行翻回了告警中
            flags.append("同一窗口内再次故障")
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
            # 这一行当前的状态：open / clear / idle。恢复通知靠 action
            # 也能看出来，但 state 是落库值，对账时拿它和 alarm_list 比
            "state": decision.get("state", ""),
            "msg": decision.get("message", ""),
            "flags": flags,
        }

    # ---------------- 维护 ----------------

    def sync_counters(self, snapshots):
        """
        把各段的 counter / last_seen 刷进 alarm_list

        为什么需要这个：段内的后续日志多半是 ACTION_NONE（不重复通知，
        这是对的），于是 L9 整个不跑，alarm_list.counter 停在插行那一刻。
        一次端口 down 产生三条同指纹日志，schema 说 counter 是"窗口内
        日志条数"，看板上却显示 1。

        放在维护线程里按 tick 刷，不在热路径上每条日志都 UPDATE ——
        日志风暴时一个指纹刷一万条，那就是一万次 UPDATE。这里一轮
        一个段最多一次。

        已恢复的段也刷：它可能在恢复之后又收到重复的恢复日志，counter
        还在涨。但那种情况下**不翻 status** —— 一条已经恢复的告警，因为
        设备把恢复日志发了两遍就被重新推回"待处理"，是纯噪声。所以
        reset_status 只对 state=open 的段开。

        state 和 clear_time 不碰：那两列由 raise/reopen/clear 动作管。

        write_db=False 时直接返回 0：这个方法的全部作用就是把 counter
        同步进库，不写库它就没有存在意义

        :param snapshots: StateMachine.current_snapshots() 的输出
        :return: 刷新的行数
        """
        if not self._write_db:
            return 0

        # snapshots 为空也要往下走：那说明段都清掉了，
        # _synced 里的残留要清掉
        snapshots = snapshots or []

        alive = set()
        synced = 0
        for row in snapshots:
            alarm_id = row.get("alarm_id") or 0
            if not alarm_id:
                continue
            alive.add(alarm_id)
            counter = row.get("counter", 1)
            last_seen = row.get("last_seen") or ""
            # counter 和 last_seen 都没动才不写。只按 counter 判断的话，
            # counter 封顶不再涨的段（比如已恢复之后只收到重复恢复日志）
            # 的 last_seen 会永远停在第一次同步时的值，详情下钻的时间
            # 窗口越往后收到的日志越漏得多
            mark = (counter, last_seen)
            if self._synced.get(alarm_id) == mark:
                continue
            data = {
                "counter": counter,
                "last_seen": str(last_seen),
                "severity": row.get("severity", 3),
            }
            try:
                result = self.db.updateAlarmById(
                    alarm_id, data, reset_status=(row.get("state") == "open"))
            except Exception as err:
                logger.error("======AlarmEmitter sync_counters error========\n%s", err)
                continue
            if result not in ("failed", 0):
                self._synced[alarm_id] = mark
                synced += 1

        # 段清掉了就从表里去掉，否则这个 dict 跟着历史告警无限涨
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
