# -*- coding: utf-8 -*-
"""
工具链自动安装与路径解析：集中放在此包，避免与 `tools/` 下可调用工具实现混在一起。

- `common`：统一安装根目录等共享逻辑
- `ripgrep`：ripgrep（rg）下载与 ensure_ripgrep_path
- `startup`：进程启动时预检 ensure_tool_dependencies_at_startup
"""
from src.tools.bootstrap.common import tool_bin_dir
from src.tools.bootstrap.ripgrep import ensure_ripgrep_path, reset_ripgrep_cache_for_tests
from src.tools.bootstrap.startup import ensure_tool_dependencies_at_startup

__all__ = [
    "ensure_ripgrep_path",
    "ensure_tool_dependencies_at_startup",
    "reset_ripgrep_cache_for_tests",
    "tool_bin_dir",
]
