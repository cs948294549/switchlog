# -*- coding: utf-8 -*-
"""
日志配置：按天切割，同时输出到文件和控制台

容器里跑时控制台那份归 docker logs，文件那份挂卷持久化。
"""
import os
import sys
import logging
from logging import Formatter, StreamHandler
from logging.handlers import TimedRotatingFileHandler

from config.config import Config

LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")
LOG_FILE = os.path.join(LOG_DIR, "switchlog.log")

LOG_FORMAT = "%(asctime)s %(levelname)-7s %(name)s %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def setup_logger(log_level=None):
    """
    配置根 logger，返回它。进程启动时调一次。

    :param log_level: 覆盖配置里的级别，调试时用
    """
    os.makedirs(LOG_DIR, exist_ok=True)

    level_name = str(log_level or Config.log_level).upper()
    level = getattr(logging, level_name, logging.INFO)

    root = logging.getLogger()
    root.setLevel(level)
    # 清掉已有 handler，避免重复调用时日志打两遍
    for handler in root.handlers[:]:
        root.removeHandler(handler)

    formatter = Formatter(LOG_FORMAT, datefmt=DATE_FORMAT)

    file_handler = TimedRotatingFileHandler(
        LOG_FILE, when="midnight", interval=1,
        backupCount=Config.log_backup_days, encoding="utf-8")
    file_handler.setFormatter(formatter)
    file_handler.setLevel(level)
    root.addHandler(file_handler)

    console = StreamHandler(sys.stdout)
    console.setFormatter(formatter)
    console.setLevel(level)
    root.addHandler(console)

    return root
