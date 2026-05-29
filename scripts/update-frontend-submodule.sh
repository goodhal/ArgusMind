#!/usr/bin/env bash
# 将 frontend 子模块对齐到 origin/main 最新提交（detached HEAD）
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FRONTEND_DIR="$ROOT/frontend"

info() { echo "[ArgusMind] $*"; }
err() { echo "[ArgusMind] 错误: $*" >&2; exit 1; }

[[ -f "$ROOT/.gitmodules" ]] || err "缺少 .gitmodules，无法更新前端子模块"

git -C "$ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1 || err "当前目录不是 Git 仓库"

info "同步并初始化前端子模块..."
git -C "$ROOT" submodule sync --recursive frontend
git -C "$ROOT" submodule update --init --recursive frontend

info "拉取 frontend 子模块 origin/main 最新代码..."
git -C "$FRONTEND_DIR" fetch origin main
git -C "$FRONTEND_DIR" checkout --detach origin/main

new_sha="$(git -C "$FRONTEND_DIR" rev-parse HEAD)"
info "frontend 已对齐到 origin/main: ${new_sha:0:12}"
