"""ArgusMind 任务临时目录：统一解析、初始化与 OpenCode glob。"""
from __future__ import annotations

import tempfile
from pathlib import Path

import src.globals as g

ARGUSMIND_TMP_NAME = "ArgusMind"


def default_tmp_base() -> Path:
    """系统临时目录下的 ArgusMind 根目录（expanduser + resolve，消除 Windows 8.3 短路径）。"""
    return (Path(tempfile.gettempdir()) / ARGUSMIND_TMP_NAME).expanduser().resolve()


def normalize_tmp_path(raw: Path | str) -> Path:
    """将任意 TMP 路径规范为绝对、已 resolve 的 Path。"""
    return Path(raw).expanduser().resolve()


def get_tmp_base() -> Path:
    """读取当前 TMP 根目录；未初始化时返回 default_tmp_base()（不写入 globals）。"""
    raw = getattr(g, "TMP_DIR", None)
    if raw is not None and str(raw).strip():
        return normalize_tmp_path(raw)
    return default_tmp_base()


def init_tmp_dir() -> Path:
    """创建 TMP 根目录并写入 g.TMP_DIR（已 resolve）。"""
    base = default_tmp_base()
    base.mkdir(parents=True, exist_ok=True)
    g.TMP_DIR = base
    return base


def ensure_tmp_base() -> Path:
    """若 g.TMP_DIR 未设置则 init；否则规范化已有值并写回 g.TMP_DIR。"""
    raw = getattr(g, "TMP_DIR", None)
    if raw is None or not str(raw).strip():
        return init_tmp_dir()
    base = normalize_tmp_path(raw)
    base.mkdir(parents=True, exist_ok=True)
    g.TMP_DIR = base
    return base


def task_tmp_dir(task_id: str) -> Path:
    """任务级子目录：{TMP_BASE}/{task_id}（不自动 mkdir）。"""
    return ensure_tmp_base() / task_id


def tmp_base_glob() -> str:
    """OpenCode external_directory glob：正斜杠 + /**。"""
    base = ensure_tmp_base()
    normalized = str(base).replace("\\", "/").rstrip("/")
    return f"{normalized}/**"
