# 官方未提供 Debian/apt 包；Debian 上需通过 cargo 编译安装 tokei
FROM rust:1-bookworm AS tokei-builder
RUN cargo install tokei --locked

# ArgusMind 单容器：前端（Nginx）+ 后端（FastAPI）
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
        nginx \
    && rm -f /etc/nginx/sites-enabled/default \
    && rm -f /etc/nginx/sites-available/default \
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
    && pip install -e ".[gitnexus]"

# 预装 opencode / gitnexus CLI，避免运行时 npm 在线安装
RUN npm config set registry https://registry.npmmirror.com \
    && npm i -g opencode-ai@latest gitnexus@latest

# 预装 tokei（来自 tokei-builder 阶段；Debian 无 apt 包）
COPY --from=tokei-builder /usr/local/cargo/bin/tokei /usr/local/bin/tokei

RUN mkdir -p /app/work /app/data/repos

COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# 再保险：复制自定义 nginx 配置前，清理可能存在的默认配置
RUN rm -f /etc/nginx/sites-enabled/default \
    && rm -f /etc/nginx/sites-available/default \
    && rm -f /etc/nginx/conf.d/default.conf

COPY docker/nginx.single.conf /etc/nginx/conf.d/default.conf

COPY frontend/dist/ /usr/share/nginx/html/

EXPOSE 6066
EXPOSE 80

ENTRYPOINT ["/entrypoint.sh"]
CMD ["python", "-m", "src.main"]