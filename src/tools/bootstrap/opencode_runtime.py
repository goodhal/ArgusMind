# -*- coding: utf-8 -*-
"""检测并安装 opencode 命令。"""
from __future__ import annotations

import shutil
import subprocess
from typing import List, Tuple


_CN_NPM_REGISTRY = "https://registry.npmmirror.com"


def _run(
    cmd: List[str],
    *,
    timeout: float = 300.0,
) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        shell=False,
    )


def _tool_version_ok(exe: str, version_flag: str = "--version") -> Tuple[bool, str]:
    path = shutil.which(exe)
    if not path:
        return False, f"未在 PATH 中找到 `{exe}`"
    try:
        r = _run([path, version_flag], timeout=20.0)
        if r.returncode != 0:
            err = (r.stderr or r.stdout or "").strip() or f"exit {r.returncode}"
            return False, f"`{exe}` 执行失败: {err}"
        return True, (r.stdout or r.stderr or "").strip()
    except FileNotFoundError:
        return False, f"无法执行 `{exe}`"
    except subprocess.TimeoutExpired:
        return False, f"`{exe} {version_flag}` 超时"


def check_opencode_command() -> Tuple[bool, str]:
    """检查 opencode 命令是否存在且可执行。"""
    return _tool_version_ok("opencode")


def _install_with_default_registry(npm_path: str) -> Tuple[bool, str]:
    r = _run([npm_path, "i", "-g", "opencode-ai"], timeout=600.0)
    out = (r.stdout or r.stderr or "").strip()
    if r.returncode == 0:
        return True, "已使用默认 npm 源安装 opencode-ai。"
    return False, f"默认 npm 源安装失败 (code={r.returncode}): {out[:500]}"


def _install_with_cn_registry(npm_path: str) -> Tuple[bool, str]:
    r = _run(
        [npm_path, "i", "-g", "opencode-ai", "--registry", _CN_NPM_REGISTRY],
        timeout=600.0,
    )
    out = (r.stdout or r.stderr or "").strip()
    if r.returncode == 0:
        return True, f"已使用国内 npm 源（{_CN_NPM_REGISTRY}）安装 opencode-ai。"
    return False, f"国内 npm 源安装失败 (code={r.returncode}): {out[:500]}"


def ensure_opencode_command() -> Tuple[bool, str]:
    """
    确保 opencode 命令可用：
    1) 已存在则直接返回；
    2) 不存在时通过 npm 全局安装（优先国内源）；
    3) 国内源失败则自动切换默认源重试。
    """
    ok, msg = check_opencode_command()
    if ok:
        return True, msg

    npm_path = shutil.which("npm")
    if not npm_path:
        return False, f"{msg}；未找到 `npm`，无法自动安装 opencode-ai。"

    installed, detail = _install_with_cn_registry(npm_path)
    if not installed:
        installed_default, detail_default = _install_with_default_registry(npm_path)
        if not installed_default:
            return False, f"{msg}；{detail}；{detail_default}"
        detail = f"{detail}；{detail_default}"

    ok2, msg2 = check_opencode_command()
    if ok2:
        return True, f"{detail} 然后: {msg2}"
    return False, f"{msg}；已尝试安装（{detail}）但仍不可用，请重启终端或检查 npm 全局 bin PATH。"
