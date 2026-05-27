# -*- coding: utf-8 -*-
"""工具链二进制统一安装目录。后续其他需自动下载的可执行文件可复用此路径。"""
from __future__ import annotations

import sys
from pathlib import Path


def tool_bin_dir() -> Path:
    """
    用户级工具 bin 根目录（各工具在此下放独立子目录或约定文件名，避免冲突）。
    - Windows: ~/AppData/Local/ArgusMind/bin（常规用户配置目录布局，不读环境变量）
    - 其他: ~/.cache/argusmind/bin（与 XDG 未单独指定缓存根时的默认位置一致）
    """
    if sys.platform == "win32":
        return Path.home() / "AppData" / "Local" / "ArgusMind" / "bin"
    return Path.home() / ".cache" / "argusmind" / "bin"
