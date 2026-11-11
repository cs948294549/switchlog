# -*- coding: utf-8 -*-
"""
MySQL 连接

和 central-server/daos/database.py 一样的用法：连接按调用创建、用完即关。
长连接在管线里不好管（MySQL 会主动断 idle 连接，断了还得重连），
而这些查询本身频率很低（规则表 5 分钟一次、设备信息 10 分钟一台），
每次新建连接的开销可以忽略。
"""
import logging

import pymysql

from config.config import Config

logger = logging.getLogger(__name__)


class MySQLConnection(object):
    """一次查询用的连接，配成上下文管理器自动关"""

    def __init__(self, config=None):
        cfg = config or Config.mysql_config
        self.conn = pymysql.connect(
            host=cfg["db_host"],
            user=cfg["db_user"],
            password=cfg["db_token"],
            port=cfg["db_port"],
            database=cfg["db_name"],
            charset="utf8",
            # 查询超时，避免 MySQL 卡住时把整条管线拖死
            connect_timeout=5,
            read_timeout=10,
        )
        self.cursor = self.conn.cursor()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        try:
            self.cursor.close()
        finally:
            self.conn.close()
        return False

    def query(self, sql, params=None, proper=None):
        """
        查询并转成 dict 列表

        :param proper: 字段名列表，和 select 的顺序一致
        :return: [dict]
        """
        self.cursor.execute(sql, params or ())
        rows = self.cursor.fetchall()
        if proper is None:
            return list(rows)
        return [self._to_dict(proper, row) for row in rows]

    def query_one(self, sql, params=None, proper=None):
        """查一行，没有返回 {}"""
        self.cursor.execute(sql, params or ())
        row = self.cursor.fetchone()
        if row is None:
            return {}
        if proper is None:
            return row
        return self._to_dict(proper, row)

    def execute(self, sql, params=None):
        """写操作，自动提交，返回影响行数"""
        self.cursor.execute(sql, params or ())
        self.conn.commit()
        return self.cursor.rowcount

    @staticmethod
    def _to_dict(proper, row):
        result = {}
        for index in range(len(proper)):
            value = row[index] if index < len(row) else None
            result[proper[index]] = value if value is not None else ""
        return result
