# -*- coding: utf-8 -*-
"""
syslog_* 规则表读取

四张表对应管线的三层，各读各的，互不依赖：
    syslog_black_list     L2 解析前拦截（mnemonic / 全文子串）
    syslog_rule           L3   匹配规则（vendor + mnemonic -> event_code）
    syslog_event          L5 事件属性（state/object_type/窗口/clear_code）
    syslog_severity_rule  L5 事件定级（event_code + 设备 -> severity）
"""
import logging

from db.database import MySQLConnection

logger = logging.getLogger(__name__)


class SyslogRuleDB(object):
    """syslog_black_list / syslog_rule / syslog_event / syslog_severity_rule 的读"""

    # ---------------- L2 ----------------

    def getBlacklistRules(self):
        """
        解析前的黑名单。scope=mnemonic 的进 dict 查，scope=message 的线性扫子串。

        没有 priority：黑名单只有"丢"一个动作，同一键配多条是数据错误。
        按 rule_id 排序只为让加载日志稳定，不代表匹配顺序。
        """
        sql = '''
        select rule_id, pattern, scope, ip, ignore_case, descr
        from syslog_black_list where enabled=1 order by rule_id
        '''
        proper = ["rule_id", "pattern", "scope", "ip", "ignore_case", "descr"]
        try:
            with MySQLConnection() as conn:
                return conn.query(sql, proper=proper)
        except Exception as err:
            logger.error("======SyslogRuleDB getBlacklistRules error========\n%s", err)
            return []

    # ---------------- L3 ----------------

    def getSyslogRules(self):
        """
        匹配规则。object_regex 逐 mnemonic 配 —— 同一事件码下不同 mnemonic
        的正文格式不同，正则没法共用。

        event_code 上不能建唯一索引：一个事件码天然对应多行（多厂商、多
        mnemonic），同一 mnemonic 也可能对应多个事件码（靠 body_match 分开）。
        """
        sql = '''
        select rule_id, vendor, mnemonic, match_type, pattern, body_match, event_code,
               object_regex, priority, descr
        from syslog_rule where enabled=1 order by priority, rule_id
        '''
        proper = ["rule_id", "vendor", "mnemonic", "match_type", "pattern", "body_match",
                  "event_code", "object_regex", "priority", "descr"]
        try:
            with MySQLConnection() as conn:
                return conn.query(sql, proper=proper)
        except Exception as err:
            logger.error("======SyslogRuleDB getSyslogRules error========\n%s", err)
            return []

    # ---------------- L5 ----------------

    def getSyslogEvents(self):
        """
        事件属性。一个 event_code 一行，改窗口只改一处、全厂商同时生效。

        不含 severity —— 级别取决于"哪个事件 + 哪台设备"两个维度，
        在 syslog_severity_rule 里定，见 getSeverityRules()。
        """
        sql = '''
        select event_code, state, object_type, window_sec, threshold,
               clear_code, descr
        from syslog_event where enabled=1 order by event_code
        '''
        proper = ["event_code", "state", "object_type", "window_sec",
                  "threshold", "clear_code", "descr"]
        try:
            with MySQLConnection() as conn:
                return conn.query(sql, proper=proper)
        except Exception as err:
            logger.error("======SyslogRuleDB getSyslogEvents error========\n%s", err)
            return []

    def getSeverityRules(self):
        """
        事件定级规则。同一个事件码在不同角色的设备上不是一个级别
        （csw 的 IF_DOWN 是 P1，rsw 的是 P3），所以按 event_code + 设备判。

        order by 只为让加载日志稳定；真正的匹配顺序由 SeverityIndex
        按 (priority, rule_id) 排，priority 小的先判，首条命中即停。
        """
        sql = '''
        select rule_id, event_code, ip_reg, sysname_reg, severity, action,
               priority, descr
        from syslog_severity_rule where enabled=1 order by priority, rule_id
        '''
        proper = ["rule_id", "event_code", "ip_reg", "sysname_reg", "severity",
                  "action", "priority", "descr"]
        try:
            with MySQLConnection() as conn:
                return conn.query(sql, proper=proper)
        except Exception as err:
            logger.error("======SyslogRuleDB getSeverityRules error========\n%s", err)
            return []
