#!/usr/bin/env bash
set -euo pipefail

# 等待 PostgreSQL（compose healthcheck 通过后通常已就绪，此处作双保险）
if [[ -n "${POSTGRES_HOST:-}" ]]; then
  echo "[entrypoint] 等待 PostgreSQL ${POSTGRES_HOST}:${POSTGRES_PORT:-5432} ..."
  for i in $(seq 1 60); do
    if python - <<'PY' 2>/dev/null; then
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
except Exception:
    sys.exit(1)
PY
      echo "[entrypoint] PostgreSQL 已就绪"
      break
    fi
    if [[ "$i" -eq 60 ]]; then
      echo "[entrypoint] PostgreSQL 连接超时" >&2
      exit 1
    fi
    sleep 2
  done
fi

exec "$@"
