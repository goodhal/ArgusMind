#!/usr/bin/env bash
# ArgusMind 本机构建脚本：拉取前端子模块最新 main 并本地编译
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

info() { echo "[ArgusMind] $*"; }
err() { echo "[ArgusMind] 错误: $*" >&2; exit 1; }

FRONTEND_DIR="$ROOT/frontend"
# 与 Docker Hub 发布名一致；可通过环境变量或第一个参数覆盖
DEFAULT_IMAGE="pulseio76/argusmind:latest"
IMAGE_TAG="${1:-${ARGUSMIND_IMAGE:-$DEFAULT_IMAGE}}"

require_git_repo() {
  git rev-parse --is-inside-work-tree >/dev/null 2>&1 || err "当前目录不是 Git 仓库"
}

ensure_node20() {
  if command -v node >/dev/null 2>&1 && command -v npm >/dev/null 2>&1; then
    local node_major
    node_major="$(node -v | sed -E 's/^v([0-9]+).*/\1/')"
    if [[ "$node_major" =~ ^[0-9]+$ ]] && [[ "$node_major" -ge 20 ]]; then
      info "检测到 Node.js $(node -v)，满足构建要求"
      return 0
    fi
    info "检测到 Node.js $(node -v)，版本低于 20，尝试自动安装 Node.js 20"
  else
    info "未检测到 Node.js/npm，尝试自动安装 Node.js 20"
  fi

  case "$(uname -s)" in
    Linux)
      if command -v apt-get >/dev/null 2>&1; then
        if [[ "$(id -u)" -eq 0 ]]; then
          apt-get update
          apt-get install -y --no-install-recommends curl ca-certificates gnupg
          mkdir -p /etc/apt/keyrings
          curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg
          echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_20.x nodistro main" > /etc/apt/sources.list.d/nodesource.list
          apt-get update
          apt-get install -y --no-install-recommends nodejs
        elif command -v sudo >/dev/null 2>&1; then
          sudo apt-get update
          sudo apt-get install -y --no-install-recommends curl ca-certificates gnupg
          sudo mkdir -p /etc/apt/keyrings
          curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | sudo gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg
          echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_20.x nodistro main" | sudo tee /etc/apt/sources.list.d/nodesource.list >/dev/null
          sudo apt-get update
          sudo apt-get install -y --no-install-recommends nodejs
        else
          err "需要 sudo/root 权限安装 Node.js 20，请先手动安装后重试"
        fi
      else
        err "当前 Linux 发行版未检测到 apt-get，请先手动安装 Node.js 20+"
      fi
      ;;
    Darwin)
      if command -v brew >/dev/null 2>&1; then
        brew install node@20
        if [[ -d "/opt/homebrew/opt/node@20/bin" ]]; then
          export PATH="/opt/homebrew/opt/node@20/bin:$PATH"
        elif [[ -d "/usr/local/opt/node@20/bin" ]]; then
          export PATH="/usr/local/opt/node@20/bin:$PATH"
        fi
      else
        err "未检测到 Homebrew，请先安装 Node.js 20+"
      fi
      ;;
    *)
      err "当前系统不支持自动安装 Node.js，请手动安装 Node.js 20+"
      ;;
  esac

  command -v node >/dev/null 2>&1 || err "Node.js 安装失败"
  command -v npm >/dev/null 2>&1 || err "npm 安装失败"
  local node_major
  node_major="$(node -v | sed -E 's/^v([0-9]+).*/\1/')"
  [[ "$node_major" =~ ^[0-9]+$ ]] && [[ "$node_major" -ge 20 ]] || err "Node.js 版本仍低于 20，请手动检查安装"
  info "Node.js 安装完成: $(node -v)"
}

update_frontend_submodule() {
  chmod +x "$ROOT/scripts/update-frontend-submodule.sh"
  "$ROOT/scripts/update-frontend-submodule.sh"
}

build_frontend() {
  [[ -f "$FRONTEND_DIR/package.json" ]] || err "未找到 frontend/package.json"
  info "安装前端依赖..."
  npm --prefix "$FRONTEND_DIR" config set registry https://registry.npmmirror.com
  npm --prefix "$FRONTEND_DIR" install

  info "构建前端..."
  npm --prefix "$FRONTEND_DIR" run build

  [[ -d "$FRONTEND_DIR/dist" ]] || err "构建完成但未找到 frontend/dist"
  info "前端构建完成: frontend/dist"
}

build_docker_image() {
  command -v docker >/dev/null 2>&1 || err "未检测到 docker，请先安装 Docker"
  info "开始构建 Docker 镜像: ${IMAGE_TAG}"
  docker build -t "${IMAGE_TAG}" .
}

require_git_repo
ensure_node20
update_frontend_submodule
build_frontend
if [[ "${SKIP_DOCKER:-0}" != "1" ]]; then
  build_docker_image
fi

cat <<EOF

========================================
 构建完成
========================================
输出目录: frontend/dist
镜像标签: ${IMAGE_TAG}
========================================
EOF
