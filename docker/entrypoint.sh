#!/usr/bin/env bash
set -euo pipefail

# 统一带时间戳的日志，便于 docker logs 与重启循环对照
log() {
  echo "[entrypoint $(date '+%Y-%m-%d %H:%M:%S')] $*"
}

log_err() {
  echo "[entrypoint $(date '+%Y-%m-%d %H:%M:%S')] $*" >&2
}

# 读取容器/宿主可用内存（cgroup v1/v2 + /proc）
log_memory() {
  local mem_total_kb mem_avail_kb cgroup_limit="(未检测到 cgroup 内存上限)"
  if [[ -r /proc/meminfo ]]; then
    mem_total_kb=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)
    mem_avail_kb=$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo)
    log "内存: MemTotal=$((mem_total_kb / 1024))MiB MemAvailable=$((mem_avail_kb / 1024))MiB"
  fi
  if [[ -r /sys/fs/cgroup/memory.max ]]; then
    local max
    max=$(cat /sys/fs/cgroup/memory.max 2>/dev/null || echo "max")
    if [[ "$max" != "max" && "$max" =~ ^[0-9]+$ ]]; then
      cgroup_limit="$((max / 1024 / 1024))MiB (cgroup v2 memory.max)"
    else
      cgroup_limit="无限制 (cgroup v2)"
    fi
  elif [[ -r /sys/fs/cgroup/memory/memory.limit_in_bytes ]]; then
    local lim
    lim=$(cat /sys/fs/cgroup/memory/memory.limit_in_bytes 2>/dev/null || echo 0)
    if [[ "$lim" =~ ^[0-9]+$ && "$lim" -lt 9223372036854771712 ]]; then
      cgroup_limit="$((lim / 1024 / 1024))MiB (cgroup v1)"
    else
      cgroup_limit="无限制 (cgroup v1)"
    fi
  fi
  log "容器内存上限: ${cgroup_limit}"
  if [[ -r /sys/fs/cgroup/memory.events ]]; then
    local oom
    oom=$(awk '/^oom_kill / {print $2}' /sys/fs/cgroup/memory.events 2>/dev/null || echo 0)
    log "cgroup oom_kill 累计次数: ${oom:-0}"
  fi
}

log_startup_context() {
  log "========== ArgusMind 容器启动 =========="
  log "PID=$$ 用户=$(id -un 2>/dev/null || echo unknown) 主机名=${HOSTNAME:-unknown}"
  log "Python=$(python --version 2>&1)  Node=$(node --version 2>&1 || echo N/A)"
  log "POSTGRES_HOST=${POSTGRES_HOST:-<未设置>} POSTGRES_PORT=${POSTGRES_PORT:-5432} POSTGRES_DB=${POSTGRES_DB:-<未设置>} POSTGRES_USER=${POSTGRES_USER:-<未设置>}"
  log "NEO4J_URI=${NEO4J_URI:-<未设置>} LOG_LEVEL=${LOG_LEVEL:-INFO} TZ=${TZ:-UTC}"
  log_memory
  log "========================================"
}

# 解释常见退出码（主进程被 kill 时尤其有用）
explain_exit_code() {
  local code=$1
  case "$code" in
    0) log "主进程正常退出" ;;
    137)
      log_err "主进程退出 code=137 (128+9 SIGKILL)。常见原因: 内存不足被 OOM Killer 终止、docker memory 限制、宿主机 swap 不足"
      log_err "建议: 在宿主机执行 free -m、docker inspect <容器> --format '{{.State.OOMKilled}}'、dmesg | grep -i oom"
      ;;
    143)
      log_err "主进程退出 code=143 (128+15 SIGTERM)，通常为 compose stop / docker stop"
      ;;
    *)
      log_err "主进程异常退出 code=${code}"
      ;;
  esac
}

# 等待 PostgreSQL（compose healthcheck 通过后通常已就绪，此处作双保险）
wait_postgres() {
  if [[ -z "${POSTGRES_HOST:-}" ]]; then
    log "未设置 POSTGRES_HOST，跳过 PostgreSQL 等待"
    return 0
  fi

  log "等待 PostgreSQL ${POSTGRES_HOST}:${POSTGRES_PORT:-5432} (db=${POSTGRES_DB:-postgres}, user=${POSTGRES_USER:-?}) ..."
  local last_err=""
  for i in $(seq 1 60); do
    if err=$(python - <<'PY' 2>&1
import os, sys
import psycopg2
try:
    psycopg2.connect(
        host=os.environ["POSTGRES_HOST"],
        port=int(os.environ.get("POSTGRES_PORT", "5432")),
        user=os.environ["POSTGRES_USER"],
        password=os.environ["POSTGRES_PASSWORD"],
        dbname=os.environ.get("POSTGRES_DB", "postgres"),
        connect_timeout=3,
    ).close()
    sys.exit(0)
except Exception as e:
    print(f"{type(e).__name__}: {e}", file=sys.stderr)
    sys.exit(1)
PY
    ); then
      log "PostgreSQL 已就绪 (第 ${i} 次尝试)"
      return 0
    fi
    last_err="$err"
    if (( i % 5 == 0 )); then
      log "PostgreSQL 尚未就绪 (${i}/60): ${last_err:-连接失败}"
    fi
    if [[ "$i" -eq 60 ]]; then
      log_err "PostgreSQL 连接超时 (60 次): ${last_err:-未知错误}"
      exit 1
    fi
    sleep 2
  done
}

start_nginx() {
  log "检查 Nginx 配置..."
  local nginx_test_out
  if nginx_test_out=$(nginx -t 2>&1); then
    while IFS= read -r line; do
      [[ -n "$line" ]] && log "nginx -t: $line"
    done <<< "$nginx_test_out"
  else
    while IFS= read -r line; do
      [[ -n "$line" ]] && log_err "nginx -t: $line"
    done <<< "$nginx_test_out"
    log_err "Nginx 配置检查失败"
    exit 1
  fi
  log "启动 Nginx（前端静态资源 + /api 反代）..."
  nginx
  if [[ -f /var/run/nginx.pid ]]; then
    log "Nginx 已启动 pid=$(cat /var/run/nginx.pid)"
  else
    log "Nginx 已启动（未找到 /var/run/nginx.pid，可能使用其他 pid 路径）"
  fi
}

# 前台运行主进程并记录退出码（不用 exec，以便 OOM/SIGKILL 后仍能打出日志）
run_main() {
  local cmd=("$@")
  log "即将启动主进程: ${cmd[*]}"
  log "工作目录: $(pwd)  PYTHONPATH=${PYTHONPATH:-<未设置>}"

  "${cmd[@]}" &
  local main_pid=$!
  log "主进程已 fork PID=${main_pid}"

  term_handler() {
    log "收到终止信号，向主进程 PID=${main_pid} 发送 SIGTERM"
    kill -TERM "$main_pid" 2>/dev/null || true
    wait "$main_pid" 2>/dev/null || true
    exit 0
  }
  trap term_handler TERM INT

  local code=0
  if ! wait "$main_pid"; then
    code=$?
  fi

  log_memory
  explain_exit_code "$code"
  exit "$code"
}

log_startup_context
wait_postgres
start_nginx
run_main "$@"
