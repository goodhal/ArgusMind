# -*- coding: utf-8 -*-
"""项目根目录 Git 仓库检测与初始化。"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Tuple, Union


def is_git_repository(project_path: Union[str, Path]) -> bool:
    """判断目录是否为 Git 工作区根（存在 `.git` 文件或目录，含 worktree）。"""
    root = Path(project_path).resolve()
    return (root / ".git").exists()


def ensure_git_repo_initialized(project_path: Union[str, Path]) -> Tuple[bool, str]:
    """
    若根目录尚未初始化 Git，则执行 `git init`。
    返回 (是否已满足可分析条件, 说明)。
    """
    root = Path(project_path).resolve()
    if not root.is_dir():
        return False, f"项目路径不是目录: {root}"
    if is_git_repository(root):
        return True, "已是 Git 仓库"
    git_exe = shutil.which("git")
    if not git_exe:
        return False, "未找到 git，无法执行 git init"
    try:
        r = subprocess.run(
            [git_exe, "init"],
            cwd=str(root),
            capture_output=True,
            text=True,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        return False, f"git init 执行异常: {e}"
    if r.returncode != 0:
        err = (r.stderr or r.stdout or "").strip()
        return False, f"git init 失败 (exit {r.returncode}): {err}"
    return True, "已在项目根目录执行 git init"
