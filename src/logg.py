# """日志配置"""
# import logging
# import sys
# from pathlib import Path
# from typing import Optional
#
#
# def setup_logging(level: str = "INFO", log_file: Optional[Path] = None):
#     """设置日志配置"""
#     log_level = getattr(logging, level.upper(), logging.INFO)
#
#     # 创建日志格式
#     formatter = logging.Formatter(
#         "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
#         datefmt="%Y-%m-%d %H:%M:%S",
#     )
#
#     # 控制台处理器
#     console_handler = logging.StreamHandler(sys.stdout)
#     console_handler.setFormatter(formatter)
#
#     # 根日志记录器
#     root_logger = logging.getLogger()
#     root_logger.setLevel(log_level)
#     root_logger.addHandler(console_handler)
#
#     # 文件处理器（如果指定）
#     if log_file:
#         log_file.parent.mkdir(parents=True, exist_ok=True)
#         file_handler = logging.FileHandler(log_file)
#         file_handler.setFormatter(formatter)
#         root_logger.addHandler(file_handler)
#
