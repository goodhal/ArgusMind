# -*- coding: utf-8 -*-
"""进程启动时预检：在默认工具注册表创建前尽量确保 ripgrep、Node/npx 可用（含自动安装）。"""
from __future__ import annotations

import logging

from src.tools.bootstrap.ripgrep import ensure_ripgrep_path
from src.tools.bootstrap.node_runtime import ensure_node_npx
from src.tools.bootstrap.gitnexus_runtime import ensure_gitnexus_command
from src.tools.bootstrap.opencode_runtime import ensure_opencode_command
from src.tools.bootstrap.tokei_runtime import ensure_tokei_command

logger = logging.getLogger(__name__)


def ensure_tool_dependencies_at_startup() -> None:
    """
    尽早调用（如 get_default_registry、CLI main）。
    - ripgrep：PATH 无 `rg` 时按 ARGUSMIND_AUTO_INSTALL_RIPGREP 尝试下载到 tool_bin_dir
    - Node/npx：按 ensure_node_npx（含 GITNEXUS_AUTO_INSTALL_NODE）处理
    任一环节失败只写 stderr，不抛异常，便于无 GitNexus/无网络环境仍能部分启动。
    """
    errors: list[str] = []

    try:
        ensure_ripgrep_path()
    except (OSError, RuntimeError) as e:
        errors.append(f"ripgrep: {e}")

    ok_node, node_msg = ensure_node_npx()
    if not ok_node:
        errors.append(f"node/npx: {node_msg}")
    else:
        ok_gitnexus, gitnexus_msg = ensure_gitnexus_command()
        if not ok_gitnexus:
            errors.append(f"gitnexus: {gitnexus_msg}")
        ok_opencode, opencode_msg = ensure_opencode_command()
        if not ok_opencode:
            errors.append(f"opencode: {opencode_msg}")
        ok_tokei, tokei_msg = ensure_tokei_command()
        if not ok_tokei:
            errors.append(f"tokei: {tokei_msg}")

    if errors:
        logger.warning(
            "[ArgusMind] 工具链预检未完全通过（部分功能可能不可用）: %s",
            "; ".join(errors),
        )
