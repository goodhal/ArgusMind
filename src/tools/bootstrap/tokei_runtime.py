# -*- coding: utf-8 -*-
"""检测并安装 tokei 命令。"""
from __future__ import annotations

import platform
import shutil
import subprocess
from typing import List, Tuple


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


def check_tokei_command() -> Tuple[bool, str]:
    """检查 tokei 命令是否存在且可执行。"""
    return _tool_version_ok("tokei")


def _install_windows() -> Tuple[bool, str]:
    winget = shutil.which("winget")
    if winget:
        r = _run(
            [
                winget,
                "install",
                "-e",
                "--id",
                "XAMPPRocky.Tokei",
                "--accept-package-agreements",
                "--accept-source-agreements",
            ],
            timeout=600.0,
        )
        out = (r.stdout or r.stderr or "").strip()
        if r.returncode == 0 or "已成功安装" in out or "successfully installed" in out.lower():
            return True, "已通过 winget 安装 tokei。"
        if "已安装" in out or "already installed" in out.lower():
            return True, "winget 报告 tokei 已安装。"

    choco = shutil.which("choco")
    if choco:
        r = _run([choco, "install", "tokei", "-y"], timeout=600.0)
        out = (r.stdout or r.stderr or "").strip()
        if r.returncode == 0:
            return True, "已通过 Chocolatey 安装 tokei。"
        return False, f"choco 安装 tokei 失败 (code={r.returncode}): {out[:500]}"

    return False, "未找到可用安装器（winget/choco），请手动安装 tokei。"


def _install_darwin() -> Tuple[bool, str]:
    brew = shutil.which("brew")
    if not brew:
        return False, "未找到 Homebrew，请手动安装：brew install tokei"
    r = _run([brew, "install", "tokei"], timeout=600.0)
    out = (r.stdout or r.stderr or "").strip()
    if r.returncode == 0:
        return True, "已通过 Homebrew 安装 tokei。"
    return False, f"brew install tokei 失败 (code={r.returncode}): {out[:500]}"


def _install_linux() -> Tuple[bool, str]:
    if shutil.which("apt-get"):
        r = _run(["sudo", "-n", "apt-get", "install", "-y", "tokei"], timeout=600.0)
        out = (r.stdout or r.stderr or "").strip()
        if r.returncode == 0:
            return True, "已通过 apt 安装 tokei。"
        return False, f"apt 安装 tokei 失败或需要密码: {out[:500]}"

    if shutil.which("dnf"):
        r = _run(["sudo", "-n", "dnf", "install", "-y", "tokei"], timeout=600.0)
        out = (r.stdout or r.stderr or "").strip()
        if r.returncode == 0:
            return True, "已通过 dnf 安装 tokei。"
        return False, f"dnf 安装 tokei 失败或需要密码: {out[:500]}"

    return False, "未识别包管理器（apt/dnf），请手动安装 tokei。"


def try_auto_install_tokei() -> Tuple[bool, str]:
    system = platform.system().lower()
    if system == "windows":
        return _install_windows()
    if system == "darwin":
        return _install_darwin()
    if system == "linux":
        return _install_linux()
    return False, f"不支持自动安装 tokei 的平台: {system}"


def ensure_tokei_command() -> Tuple[bool, str]:
    """
    确保 tokei 命令可用：
    - 已可用直接返回；
    - 不可用则尝试自动安装，再次检测。
    """
    ok, msg = check_tokei_command()
    if ok:
        return True, msg

    installed, detail = try_auto_install_tokei()
    if not installed:
        return False, f"{msg}；自动安装未成功: {detail}"

    ok2, msg2 = check_tokei_command()
    if ok2:
        return True, f"{detail} 然后: {msg2}"
    return False, f"{msg}；已尝试安装（{detail}）但仍不可用，请重启终端或检查 PATH。"
