# -*- coding: utf-8 -*-
"""检测 Node / npx 是否可用；缺失时按平台尝试自动安装（可关闭）。"""
from __future__ import annotations

import logging
import os
import platform
import shutil
import subprocess
from typing import List, Tuple

logger = logging.getLogger(__name__)




def _run(
    cmd: List[str],
    *,
    timeout: float = 300.0,
    check: bool = False,
) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=check,
        shell=False,
    )


def _version_ok(exe: str, version_flag: str = "-v") -> Tuple[bool, str]:
    path = shutil.which(exe)
    if not path:
        return False, f"未在 PATH 中找到 `{exe}`"
    try:
        r = _run([path, version_flag], timeout=15.0)
        if r.returncode != 0:
            err = (r.stderr or r.stdout or "").strip() or f"exit {r.returncode}"
            return False, f"`{exe}` 执行失败: {err}"
        out = (r.stdout or r.stderr or "").strip()
        return True, out
    except FileNotFoundError:
        return False, f"无法执行 `{exe}`"
    except subprocess.TimeoutExpired:
        return False, f"`{exe} {version_flag}` 超时"


def check_node_npx() -> Tuple[bool, str]:
    """检查 `node` 与 `npx` 是否在 PATH 中且可运行。返回 (是否可用, 说明)。"""
    ok_n, msg_n = _version_ok("node")
    ok_x, msg_x = _version_ok("npx")
    if ok_n and ok_x:
        return True, f"node {msg_n}; npx {msg_x}"
    parts = []
    if not ok_n:
        parts.append(f"node: {msg_n}")
    if not ok_x:
        parts.append(f"npx: {msg_x}")
    return False, "; ".join(parts)


def _prepend_path_dir(dirpath: str) -> None:
    if not dirpath or not os.path.isdir(dirpath):
        return
    sep = os.pathsep
    current = os.environ.get("PATH", "")
    if dirpath not in current.split(sep):
        os.environ["PATH"] = dirpath + sep + current


def _node_exe_basename() -> str:
    return "node.exe" if platform.system().lower() == "windows" else "node"


def _candidate_node_bindirs() -> Tuple[str, ...]:
    """常见安装位置（不依赖 ProgramFiles / LOCALAPPDATA 等环境变量）。"""
    sysname = platform.system().lower()
    home = os.path.expanduser("~")
    if sysname == "windows":
        return (
            os.path.join(r"C:\Program Files", "nodejs"),
            os.path.join(r"C:\Program Files (x86)", "nodejs"),
            os.path.join(home, "AppData", "Local", "Programs", "node"),
        )
    if sysname == "darwin":
        return ("/opt/homebrew/bin", "/usr/local/bin", "/usr/bin")
    return ("/usr/local/bin", "/usr/bin")


def _refresh_path_after_node_install() -> None:
    """安装完成后把实际存在 node 可执行文件的目录 prepend 到 PATH（当前进程）。"""
    name = _node_exe_basename()
    for base in _candidate_node_bindirs():
        node_exe = os.path.join(base, name)
        if os.path.isfile(node_exe):
            _prepend_path_dir(base)
            return


def _try_install_windows() -> Tuple[bool, str]:
    winget = shutil.which("winget")
    if winget:
        r = _run(
            [
                winget,
                "install",
                "-e",
                "--id",
                "OpenJS.NodeJS.LTS",
                "--accept-package-agreements",
                "--accept-source-agreements",
            ],
            timeout=600.0,
        )
        out = (r.stdout or r.stderr or "").strip()
        if r.returncode == 0 or "已成功安装" in out or "successfully installed" in out.lower():
            _refresh_path_after_node_install()
            return True, "已通过 winget 安装 Node.js LTS，请确认 PATH 已包含 node（必要时重启终端）。"
        if "已安装" in out or "already installed" in out.lower():
            _refresh_path_after_node_install()
            return True, "winget 报告 Node 已存在，已尝试刷新本进程 PATH。"
        return False, f"winget 安装未成功 (code={r.returncode}): {out[:500]}"

    choco = shutil.which("choco")
    if choco:
        r = _run([choco, "install", "nodejs-lts", "-y"], timeout=600.0)
        out = (r.stdout or r.stderr or "").strip()
        if r.returncode == 0:
            _refresh_path_after_node_install()
            return True, "已通过 Chocolatey 安装 nodejs-lts。"
        return False, f"choco 安装失败 (code={r.returncode}): {out[:500]}"

    return False, "未找到 winget 或 choco，请手动安装 Node.js: https://nodejs.org/"


def _try_install_darwin() -> Tuple[bool, str]:
    brew = shutil.which("brew")
    if not brew:
        return False, "未找到 Homebrew，请手动安装: brew install node 或从 https://nodejs.org/ 下载"
    r = _run([brew, "install", "node"], timeout=600.0)
    out = (r.stdout or r.stderr or "").strip()
    if r.returncode != 0:
        return False, f"brew install node 失败 (code={r.returncode}): {out[:500]}"
    _refresh_path_after_node_install()
    return True, "已通过 Homebrew 安装 node。"


def _try_install_linux() -> Tuple[bool, str]:
    if shutil.which("apt-get"):
        r = _run(["sudo", "-n", "apt-get", "install", "-y", "nodejs", "npm"], timeout=600.0)
        out = (r.stdout or r.stderr or "").strip()
        if r.returncode == 0:
            _refresh_path_after_node_install()
            return True, "已通过 apt 安装 nodejs/npm。"
        if r.returncode != 0 and ("password" in out.lower() or "a password is required" in out.lower()):
            pass
        return False, (
            "自动安装需要免密 sudo。请手动执行: sudo apt update && sudo apt install -y nodejs npm "
            "或使用 NodeSource / nvm。"
        )
    if shutil.which("dnf"):
        r = _run(["sudo", "-n", "dnf", "install", "-y", "nodejs", "npm"], timeout=600.0)
        out = (r.stdout or r.stderr or "").strip()
        if r.returncode == 0:
            _refresh_path_after_node_install()
            return True, "已通过 dnf 安装 nodejs/npm。"
        return False, f"dnf 安装失败或需要密码: {out[:300]}"
    return False, "未识别包管理器（apt/dnf），请手动安装 Node.js: https://nodejs.org/"


def try_auto_install_node() -> Tuple[bool, str]:
    """按当前操作系统尝试安装 Node（含 npx）。失败时返回说明。"""
    system = platform.system().lower()
    if system == "windows":
        return _try_install_windows()
    if system == "darwin":
        return _try_install_darwin()
    if system == "linux":
        return _try_install_linux()
    return False, f"不支持自动安装的平台: {system}，请从 https://nodejs.org/ 安装 Node.js"


def ensure_node_npx() -> Tuple[bool, str]:
    """
    确保 node / npx 可用。
    - 已可用则返回 (True, 版本信息摘要)。
    - 不可用且 GITNEXUS_AUTO_INSTALL_NODE 未关闭时尝试自动安装，再检测一次。
    """
    ok, msg = check_node_npx()
    if ok:
        return True, msg

    installed, detail = try_auto_install_node()
    if not installed:
        return False, f"{msg}。自动安装未成功: {detail}"

    ok2, msg2 = check_node_npx()
    if ok2:
        return True, f"{detail} 然后: {msg2}"
    return False, f"{msg}。已尝试安装（{detail}）但仍不可用，请重启终端或检查 PATH。"


def warn_if_node_missing() -> None:
    """在 import 早期可选调用：仅打印警告，不安装。"""
    if os.getenv("GITNEXUS_SKIP_NODE_CHECK", "").strip().lower() in ("1", "true", "yes", "on"):
        return
    ok, msg = check_node_npx()
    if not ok:
        logger.warning("[GitNexus] Node/npx 不可用: %s", msg)
