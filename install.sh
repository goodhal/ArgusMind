#!/usr/bin/env bash
# ArgusMind 一键安装（Linux / macOS / WSL）
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

info() { echo "[ArgusMind] $*"; }
err() { echo "[ArgusMind] 错误: $*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || err "未找到 docker，请先安装 Docker: https://docs.docker.com/get-docker/"

if docker compose version >/dev/null 2>&1; then
  COMPOSE=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE=(docker-compose)
else
  err "未找到 docker compose，请安装 Docker Compose V2"
fi

ENV_FILE="$ROOT/.env"
ENV_EXAMPLE="$ROOT/.env.docker.example"
CREATED_ENV=0

random_password() {
  local len="${1:-24}"
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | head -c "$len"
  else
    LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c "$len"
  fi
}

write_env_with_random_passwords() {
  local pg_pass neo_pass
  pg_pass="$(random_password 24)"
  neo_pass="$(random_password 24)"
  while IFS= read -r line || [[ -n "$line" ]]; do
    case "$line" in
      POSTGRES_PASSWORD=*|POSTGRES_PASSWORD=__AUTO_GENERATE__*)
        echo "POSTGRES_PASSWORD=${pg_pass}"
        ;;
      NEO4J_PASSWORD=*|NEO4J_PASSWORD=__AUTO_GENERATE__*)
        echo "NEO4J_PASSWORD=${neo_pass}"
        ;;
      *)
        echo "$line"
        ;;
    esac
  done < "$ENV_EXAMPLE" > "$ENV_FILE"
  CREATED_ENV=1
  info "已生成 .env，PostgreSQL / Neo4j 密码为随机值（见安装完成提示或 .env 文件）"
}

if [[ ! -f "$ENV_FILE" ]]; then
  [[ -f "$ENV_EXAMPLE" ]] || err "缺少 .env.docker.example"
  write_env_with_random_passwords
fi

# shellcheck disable=SC1091
set -a
[[ -f "$ENV_FILE" ]] && source "$ENV_FILE"
set +a
DATA_DIR="${DATA_DIR:-./data}"
PORT="${ARGUSMIND_PORT:-6066}"

# 去掉 ./ 前缀，统一为相对项目根的路径
DATA_DIR="${DATA_DIR#./}"
mkdir -p "$ROOT/$DATA_DIR/postgres" "$ROOT/$DATA_DIR/neo4j" "$ROOT/$DATA_DIR/work" "$ROOT/$DATA_DIR/repos"

info "构建并启动服务（PostgreSQL + Neo4j + API）..."
"${COMPOSE[@]}" -f docker-compose.yml up -d --build

info "等待 API 就绪..."
for i in $(seq 1 90); do
  if curl -fsS "http://127.0.0.1:${PORT}/api/health" >/dev/null 2>&1 \
    || curl -fsS "http://localhost:${PORT}/api/health" >/dev/null 2>&1; then
    break
  fi
  if [[ "$i" -eq 90 ]]; then
    err "API 启动超时，请执行: ${COMPOSE[*]} -f docker-compose.yml logs argusmind"
  fi
  sleep 2
done

cat <<EOF

========================================
 ArgusMind 安装完成
========================================
 API 地址:     http://localhost:${PORT}
 API 文档:     http://localhost:${PORT}/docs
 健康检查:     http://localhost:${PORT}/api/ready

 默认登录:     用户名 ArgusMind  密码 ArgusMind
 （生产环境请尽快修改密码）
EOF

if [[ "$CREATED_ENV" -eq 1 ]]; then
  # shellcheck disable=SC1091
  source "$ENV_FILE"
  cat <<EOF

 数据库凭据（已写入 .env，请妥善保管）:
   PostgreSQL  用户 ${POSTGRES_USER:-argusmind}  密码 ${POSTGRES_PASSWORD}
   Neo4j       用户 ${NEO4J_USER:-neo4j}  密码 ${NEO4J_PASSWORD}
EOF
fi

cat <<EOF

 数据目录:     ${DATA_DIR}/postgres  PostgreSQL
               ${DATA_DIR}/neo4j     Neo4j
               ${DATA_DIR}/work      应用工作区
               ${DATA_DIR}/repos     被测代码（容器路径 /data/repos/...）

 常用命令:
   查看日志:   ${COMPOSE[*]} -f docker-compose.yml logs -f argusmind
   停止服务:   ${COMPOSE[*]} -f docker-compose.yml down
   清空数据库: 先 down，再手动删除 ${DATA_DIR}/postgres 与 ${DATA_DIR}/neo4j

 启动后请在「配置管理」中填写 LLM 与 Code Agent 密钥。
========================================
EOF
