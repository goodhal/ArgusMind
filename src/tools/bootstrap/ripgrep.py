# -*- coding: utf-8 -*-
"""确保本机存在可执行的 `rg`：优先 PATH，否则下载 BurntSushi/ripgrep 发行包并解压到 bootstrap 统一 bin。

平台与版本与 opencode 的 Ripgrep 模块对齐：
https://github.com/anomalyco/opencode/blob/ec3ae17e/packages/opencode/src/file/ripgrep.ts
"""
from __future__ import annotations

import os
import platform
import shutil
import stat
import sys
import tarfile
import zipfile
from pathlib import Path
from typing import Dict, Optional, Tuple

import requests

from src.tools.bootstrap.common import tool_bin_dir

try:
    from filelock import FileLock
except ImportError:  # pragma: no cover
    FileLock = None  # type: ignore[misc, assignment]

_RIPGREP_VERSION = "14.1.1"

# key: "{arch}-{os}" 与 Node 的 process.arch / process.platform 对应
_PLATFORM: Dict[str, Tuple[str, str]] = {
    "arm64-darwin": ("aarch64-apple-darwin", "tar.gz"),
    "arm64-linux": ("aarch64-unknown-linux-gnu", "tar.gz"),
    "x64-darwin": ("x86_64-apple-darwin", "tar.gz"),
    "x64-linux": ("x86_64-unknown-linux-musl", "tar.gz"),
    "arm64-win32": ("aarch64-pc-windows-msvc", "zip"),
    "x64-win32": ("x86_64-pc-windows-msvc", "zip"),
}


def _auto_install_enabled() -> bool:
    v = os.getenv("ARGUSMIND_AUTO_INSTALL_RIPGREP", "1").strip().lower()
    return v not in ("0", "false", "no", "off")


def _rg_target_path() -> Path:
    return tool_bin_dir() / ("rg.exe" if sys.platform == "win32" else "rg")


def _arch_key() -> str:
    m = platform.machine().lower()
    if m in ("amd64", "x86_64", "x64", "i386", "i686"):
        return "x64"
    if m in ("arm64", "aarch64"):
        return "arm64"
    raise RuntimeError(f"不支持的 CPU 架构: {platform.machine()}")


def _platform_key() -> str:
    pl = sys.platform
    if pl == "win32":
        suffix = "win32"
    elif pl == "darwin":
        suffix = "darwin"
    elif pl.startswith("linux"):
        suffix = "linux"
    else:
        raise RuntimeError(f"不支持的操作系统: {pl}")
    return f"{_arch_key()}-{suffix}"


def _which_rg() -> Optional[str]:
    p = shutil.which("rg")
    if not p:
        return None
    try:
        if Path(p).is_file():
            return p
    except OSError:
        return None
    return None


def _download(url: str, dest_dir: Path, timeout: float = 120.0) -> Path:
    dest_dir.mkdir(parents=True, exist_ok=True)
    name = url.rsplit("/", 1)[-1]
    archive = dest_dir / name
    try:
        r = requests.get(url, timeout=timeout)
    except requests.RequestException as e:
        raise RuntimeError(f"下载 ripgrep 失败: {e}") from e
    if r.status_code != 200:
        raise RuntimeError(f"下载 ripgrep 失败 HTTP {r.status_code}: {url}")
    archive.write_bytes(r.content)
    return archive


def _extract_tar_gz(archive: Path, rg_out: Path) -> None:
    with tarfile.open(archive, "r:gz") as tf:
        member = None
        for m in tf.getmembers():
            if not m.isfile():
                continue
            norm = m.name.replace("\\", "/")
            if norm.endswith("/rg") or norm == "rg":
                member = m
                break
        if member is None:
            raise RuntimeError("压缩包中未找到 rg 可执行文件")
        f = tf.extractfile(member)
        if f is None:
            raise RuntimeError("无法从压缩包读取 rg")
        try:
            data = f.read()
        finally:
            f.close()
    rg_out.write_bytes(data)


def _extract_zip(archive: Path, rg_out: Path) -> None:
    with zipfile.ZipFile(archive, "r") as zf:
        chosen = None
        for info in zf.infolist():
            n = info.filename.replace("\\", "/")
            if n.endswith("rg.exe"):
                chosen = info.filename
                break
        if not chosen:
            raise RuntimeError("zip 中未找到 rg.exe")
        rg_out.write_bytes(zf.read(chosen))


def _ensure_bundled_rg() -> Path:
    key = _platform_key()
    cfg = _PLATFORM.get(key)
    if not cfg:
        raise RuntimeError(f"当前平台无预置 ripgrep 发行包映射: {key}")

    triple, ext = cfg
    filename = f"ripgrep-{_RIPGREP_VERSION}-{triple}.{ext}"
    url = f"https://github.com/BurntSushi/ripgrep/releases/download/{_RIPGREP_VERSION}/{filename}"

    bindir = tool_bin_dir()
    bindir.mkdir(parents=True, exist_ok=True)
    rg_path = _rg_target_path()
    lock_path = bindir / ".rg-install.lock"

    if FileLock is not None:
        lock = FileLock(str(lock_path), timeout=600)
        with lock:
            if rg_path.is_file():
                return rg_path
            return _install_unlocked(url, filename, ext, rg_path)
    if rg_path.is_file():
        return rg_path
    return _install_unlocked(url, filename, ext, rg_path)


def _install_unlocked(url: str, _filename: str, ext: str, rg_path: Path) -> Path:
    if rg_path.is_file():
        return rg_path
    bindir = rg_path.parent
    archive = _download(url, bindir)
    try:
        if ext == "tar.gz":
            _extract_tar_gz(archive, rg_path)
        else:
            _extract_zip(archive, rg_path)
    finally:
        try:
            if archive.is_file():
                archive.unlink()
        except OSError:
            pass

    if sys.platform != "win32":
        rg_path.chmod(rg_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return rg_path


_cached_rg: Optional[str] = None


def ensure_ripgrep_path() -> str:
    """
    返回 `rg` 可执行文件绝对路径。
    - 优先使用 PATH 中的 rg
    - 否则若允许自动安装，下载并解压到 tool_bin_dir()
    """
    global _cached_rg
    if _cached_rg:
        return _cached_rg

    w = _which_rg()
    if w:
        _cached_rg = w
        return w

    if not _auto_install_enabled():
        raise RuntimeError(
            "PATH 中未找到 rg，且已关闭自动安装（ARGUSMIND_AUTO_INSTALL_RIPGREP=0）。"
            "请安装 ripgrep 或将 rg 加入 PATH。"
        )

    p = _ensure_bundled_rg()
    _cached_rg = str(p.resolve())
    return _cached_rg


def reset_ripgrep_cache_for_tests() -> None:
    global _cached_rg
    _cached_rg = None
