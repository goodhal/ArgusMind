#!/usr/bin/env bash
# ArgusMind 卸载脚本：停止并删除容器，可选删除数据和镜像
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

info() { echo "[ArgusMind] $*"; }
warn() { echo "[ArgusMind] 警告: $*" >&2; }
err() { echo "[ArgusMind] 错误: $*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || err "未找到 docker，请先安装 Docker。"

if docker compose version >/dev/null 2>&1; then
  COMPOSE=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE=(docker-compose)
else
  err "未找到 docker compose，请安装 Docker Compose V2。"
fi

ENV_FILE="$ROOT/.env"
if [[ -f "$ENV_FILE" ]]; then
  # shellcheck disable=SC1091
  set -a
  source "$ENV_FILE"
  set +a
fi

DATA_DIR="${DATA_DIR:-./data}"
if [[ "$DATA_DIR" != /* && "$DATA_DIR" != ./* ]]; then
  DATA_DIR="./$DATA_DIR"
fi
if [[ "$DATA_DIR" == /* ]]; then
  HOST_DATA_DIR="$DATA_DIR"
else
  HOST_DATA_DIR="$ROOT/${DATA_DIR#./}"
fi

ask_yes_no() {
  local prompt="$1"
  local default="${2:-N}"
  local answer
  if [[ "$default" == "Y" ]]; then
    read -r -p "$prompt [Y/n]: " answer || true
    answer="${answer:-Y}"
  else
    read -r -p "$prompt [y/N]: " answer || true
    answer="${answer:-N}"
  fi
  [[ "$answer" =~ ^[Yy]([Ee][Ss])?$ ]]
}

info "停止并删除 ArgusMind 相关容器..."
if [[ -f "$ROOT/docker-compose.yml" ]]; then
  "${COMPOSE[@]}" -f docker-compose.yml down --remove-orphans || warn "compose down 失败，尝试直接删除容器。"
fi

for c in argusmind argusmind-postgres argusmind-neo4j; do
  if docker ps -a --format '{{.Names}}' | rg -x "$c" >/dev/null 2>&1; then
    docker rm -f "$c" >/dev/null 2>&1 || warn "删除容器 $c 失败。"
  fi
done

if ask_yes_no "是否删除本地数据目录（$HOST_DATA_DIR）？" "N"; then
  if [[ -d "$HOST_DATA_DIR" ]]; then
    rm -rf "$HOST_DATA_DIR"
    info "已删除本地数据目录: $HOST_DATA_DIR"
  else
    info "本地数据目录不存在，无需删除: $HOST_DATA_DIR"
  fi
else
  info "已保留本地数据目录: $HOST_DATA_DIR"
fi

ARGUSMIND_IMAGE="${ARGUSMIND_IMAGE:-pulseio76/argusmind:latest}"
if ask_yes_no "是否删除 ArgusMind 镜像（${ARGUSMIND_IMAGE} 及同仓库其它标签）？" "N"; then
  image_ids="$(docker images pulseio76/argusmind --format '{{.ID}}' | awk 'NF' | sort -u || true)"
  if [[ -n "${image_ids:-}" ]]; then
    while IFS= read -r image_id; do
      [[ -n "$image_id" ]] || continue
      docker rmi "$image_id" >/dev/null 2>&1 || warn "删除镜像 $image_id 失败（可能仍被占用）。"
    done <<< "$image_ids"
    info "已尝试删除 argusmind 镜像。"
  else
    info "未发现本地 argusmind 镜像。"
  fi
else
  info "已保留 argusmind 镜像。"
fi

info "卸载完成。"
