# ArgusMind API — Python 3.11 + Node（OpenCode / npx 工具链）+ ripgrep
FROM python:3.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app \
    ARGUSMIND_AUTO_INSTALL_RIPGREP=0

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        ca-certificates \
        gnupg \
        ripgrep \
        git \
    && mkdir -p /etc/apt/keyrings \
    && curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key \
        | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg \
    && echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_20.x nodistro main" \
        > /etc/apt/sources.list.d/nodesource.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src

RUN pip install --upgrade pip \
    # 安装 GitNexus MCP 需要的 mcp（以及项目依赖）
    && pip install -e ".[gitnexus]"

# 预装 opencode / gitnexus CLI，避免运行时 npm 在线安装
RUN npm config set registry https://registry.npmmirror.com \
    && npm i -g opencode-ai gitnexus

# 预装 tokei（二进制），避免运行时通过 sudo/包管理器失败
# TARGETARCH 在 buildx 时可用；普通 docker build 可能为空，此时默认 amd64。
ARG TARGETARCH
RUN set -e; \
    arch="${TARGETARCH:-amd64}"; \
    case "$arch" in \
      amd64) asset="tokei-x86_64-unknown-linux-gnu" ;; \
      arm64) asset="tokei-aarch64-unknown-linux-gnu" ;; \
      *) echo "[Dockerfile] Unsupported TARGETARCH=$arch for tokei; skip." >&2; exit 0 ;; \
    esac; \
    url="https://github.com/XAMPPRocky/tokei/releases/latest/download/${asset}.tar.gz"; \
    curl -fsSL "$url" -o /tmp/tokei.tar.gz; \
    tar -xzf /tmp/tokei.tar.gz -C /usr/local/bin; \
    chmod +x /usr/local/bin/tokei; \
    rm -f /tmp/tokei.tar.gz

RUN mkdir -p /app/work /app/data/repos

COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 6066

ENTRYPOINT ["/entrypoint.sh"]
CMD ["python", "-m", "src.main"]
