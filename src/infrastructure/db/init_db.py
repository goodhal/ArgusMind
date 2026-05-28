"""数据库初始化：建表 + 种子数据"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List

import psycopg2
from psycopg2 import sql
import httpx
from sqlalchemy import text
from sqlalchemy.orm import Session

from src.config import Config
from src.infrastructure.db import Base, init_engine, session_scope
from src.infrastructure.db.models import ConfigEntry, User  # noqa: F401  保证模型被注册
from src.infrastructure.db import models  # noqa: F401  批量注册所有模型
from src.infrastructure.security.password import hash_password
from src.tools.opencode import OpenCodeTool

logger = logging.getLogger(__name__)

# ---------------- 默认种子 ----------------

DEFAULT_USERNAME = "ArgusMind"
DEFAULT_PASSWORD = "ArgusMind"

POPULAR_PROVIDERS = {
    "opencode",
    "opencode-go",
    "anthropic",
    "github-copilot",
    "openai",
    "google",
    "openrouter",
    "vercel",
    "deepseek",
}

DEFAULT_CONFIGS: List[Dict[str, Any]] = [
    {
        "name": "LLM_config",
        "value_json": {
            "LLM_provider": "",
            "LLM_key": "",
            "LLM_model": "",
            "LLM_baseurl": "",
        },
        "description": "默认 LLM 接入配置",
    },
    {
        "name": "code_agent_config",
        "value_json": {
            "code_agent_provider": "",
            "code_agent_key": "",
            "code_agent_model": "",
            "code_agent_baseurl": "",
            "code_agent_engine": "",
        },
        "description": "默认 Code Agent 配置",
    },
    {
        "name": "LLM_provider_list",
        "value_json": {},
        "description": "内置 LLM 厂商/模型清单（通过 litellm.model_cost 获取）",
    },
    {
        "name": "code_agent_provider_list",
        "value_json": {"providers": []},
        "description": "内置 Code Agent 厂商/模型清单（通过 opencode 获取；当前占位，后续补充）",
    },
]


def fetch_litellm_provider_list() -> Dict[str, Any]:
    """拉取 litellm 内置厂商/模型清单并标记热门厂商。

    返回结构：{provider: {"models": [...], "provider_type": "popular"(可选)}}
    """
    try:
        from litellm import model_cost  # type: ignore

        provider_models: Dict[str, set[str]] = {}
        for model, info in (model_cost or {}).items():
            if not isinstance(info, dict):
                continue
            provider = (info.get("litellm_provider") or "").strip()
            if not provider:
                continue
            provider_models.setdefault(provider, set()).add(model)

        provider_entries: Dict[str, Any] = {}
        for provider, models in sorted(provider_models.items()):
            provider_item: Dict[str, Any] = {"models": sorted(models)}
            if provider in POPULAR_PROVIDERS:
                provider_item["provider_type"] = "popular"
            provider_entries[provider] = provider_item
        logger.info(
            "[init_db] litellm provider 清单拉取完成: providers=%d",
            len(provider_entries),
        )
        return provider_entries
    except Exception as ex:  # pragma: no cover - 离线或 litellm 未装时降级为空
        logger.warning("[init_db] litellm provider 清单拉取失败: %s", ex)
        return {"error": str(ex)}


def fetch_opencode_provider_list() -> Dict[str, Any]:
    """拉取 OpenCode 的 provider/model 清单（通过本地 opencode 服务）。"""
    tool: OpenCodeTool | None = None
    service_url = ""
    try:
        project_root = str(Path(__file__).resolve().parents[3])
        directory = str(Path(project_root).anchor or Path(project_root))
        # 初始化服务时 model/provider 参数可为空；这里给出默认占位值。
        tool = OpenCodeTool(
            project_path=project_root,
            model_id="gpt-4o-mini",
            provider_id="openai",
        )
        service_url = tool.get_url().rstrip("/")

        with httpx.Client(timeout=5.0, follow_redirects=True) as client:
            resp = client.get(
                f"{service_url}/provider",
                params={"directory": directory},
            )
            if resp.status_code == 200:
                data = resp.json()
                providers: List[Dict[str, Any]] = []
                all_providers = data.get("all") if isinstance(data, dict) else None
                if isinstance(all_providers, list):
                    for p in all_providers:
                        if not isinstance(p, dict):
                            continue
                        provider_id = (p.get("id") or "").strip()
                        if not provider_id:
                            continue
                        models = p.get("models") or {}
                        model_items: List[Dict[str, Any]] = []
                        if isinstance(models, dict):
                            for model_id in sorted(models.keys()):
                                model_info = models.get(model_id) or {}
                                model_item: Dict[str, Any] = {"id": model_id}
                                if provider_id == "opencode":
                                    cost = (
                                        model_info.get("cost")
                                        if isinstance(model_info, dict)
                                        else None
                                    )
                                    input_cost = None
                                    if isinstance(cost, dict):
                                        try:
                                            input_cost = float(cost.get("input"))
                                        except (TypeError, ValueError):
                                            input_cost = None
                                    if not cost or (
                                        isinstance(cost, dict) and input_cost == 0
                                    ):
                                        model_item["type"] = "free"
                                model_items.append(model_item)

                        provider_item: Dict[str, Any] = {
                            "id": provider_id,
                            "name": p.get("name") or provider_id,
                            "models": model_items,
                        }
                        if provider_id in POPULAR_PROVIDERS:
                            provider_item["provider_type"] = "popular"
                        providers.append(provider_item)
                logger.info(
                    "[init_db] opencode provider 清单拉取完成: providers=%d source=%s/provider",
                    len(providers),
                    service_url,
                )
                return {"providers": providers, "source": f"{service_url}/provider"}

            body_preview = (resp.text or "")[:200]
            logger.warning(
                "[init_db] opencode provider 清单拉取失败: status=%s url=%s/provider directory=%s body=%s",
                resp.status_code,
                service_url,
                directory,
                body_preview,
            )
            return {
                "providers": [],
                "error": f"HTTP {resp.status_code}",
                "source": f"{service_url}/provider",
            }
    except Exception as ex:  # pragma: no cover
        logger.warning(
            "[init_db] opencode provider 清单拉取失败: url=%s err=%s",
            service_url or "(服务未启动)",
            ex,
        )
        return {"providers": [], "error": str(ex)}
    finally:
        if tool is not None:
            try:
                tool.close()
            except Exception:
                pass
    logger.warning(
        "[init_db] opencode provider 清单拉取失败: url=%s reason=未返回有效响应",
        service_url or "(未知)",
    )
    return {"providers": []}


def create_all_tables(config: Config) -> bool:
    """确保所有 ORM 模型对应的表都存在；返回数据库是否是本次新创建的。

    Base.metadata.create_all 是幂等操作：已存在的表会跳过，缺失的表会被补建。
    这样新增模型（例如 opencode_events）也能在已存在的数据库上自动生效。
    """
    created = ensure_database_exists(config)
    engine = init_engine(config.postgres)
    Base.metadata.create_all(engine)
    logger.info("[init_db] ORM 建表完成: db=%s created=%s", config.postgres.db, created)
    return created

def ensure_database_exists(config: Config) -> bool:
    """若目标数据库不存在则自动创建，返回是否新建了数据库。"""
    pg = config.postgres
    target_db = pg.db

    for maintenance_db in ("postgres", "template1"):
        conn = None
        try:
            conn = psycopg2.connect(
                host=pg.host,
                port=pg.port,
                user=pg.user,
                password=pg.password,
                dbname=maintenance_db,
            )
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("SELECT 1 FROM pg_database WHERE datname = %s", (target_db,))
                exists = cur.fetchone() is not None
                if not exists:
                    cur.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(target_db)))
                    logger.info(
                        "[init_db] 目标数据库不存在，已创建: db=%s via=%s",
                        target_db,
                        maintenance_db,
                    )
                    return True
                logger.info("[init_db] 目标数据库已存在: db=%s via=%s", target_db, maintenance_db)
                return False
        except Exception as ex:
            logger.warning(
                "[init_db] 使用维护库连接失败，尝试下一个: maintenance_db=%s err=%s",
                maintenance_db,
                ex,
            )
            if maintenance_db == "template1":
                raise
        finally:
            if conn is not None:
                conn.close()


def set_llm_provider(session: Session) -> None:
    # 若 provider list 当前为空，尝试在线拉取一次填充（失败不阻塞）
    _hydrate_provider_list(
        session,
        name="LLM_provider_list",
        fetcher=fetch_litellm_provider_list,
    )
    _hydrate_provider_list(
        session,
        name="code_agent_provider_list",
        fetcher=fetch_opencode_provider_list,
    )


def seed_default_data(session: Session) -> None:
    """写入默认种子数据（幂等）"""
    # 默认用户
    user = session.query(User).filter(User.username == DEFAULT_USERNAME).one_or_none()
    if user is None:
        user = User(
            username=DEFAULT_USERNAME,
            password_hash=hash_password(DEFAULT_PASSWORD),
            display_name="Administrator",
        )
        session.add(user)
        logger.info("[init_db] 默认用户已创建: username=%s", DEFAULT_USERNAME)
    else:
        logger.info("[init_db] 默认用户已存在: username=%s", DEFAULT_USERNAME)

    # 默认配置项
    created_config_count = 0
    for cfg in DEFAULT_CONFIGS:
        row = session.query(ConfigEntry).filter(ConfigEntry.name == cfg["name"]).one_or_none()
        if row is None:
            row = ConfigEntry(
                name=cfg["name"],
                value_json=cfg.get("value_json"),
                value_str=cfg.get("value_str"),
                description=cfg.get("description", ""),
            )
            session.add(row)
            created_config_count += 1

    session.flush()
    logger.info(
        "[init_db] 默认配置写入完成: created=%d total=%d",
        created_config_count,
        len(DEFAULT_CONFIGS),
    )




def _hydrate_provider_list(session: Session, *, name: str, fetcher) -> None:
    row = session.query(ConfigEntry).filter(ConfigEntry.name == name).one_or_none()
    if row is None:
        logger.info("[init_db] 跳过 provider list 填充：配置项不存在 name=%s", name)
        return
    try:
        fetched = fetcher() or {}
    except Exception as ex:  # pragma: no cover
        logger.warning("[init_db] 拉取 %s 失败: %s", name, ex)
        fetched = {}
    row.value_json = fetched
    logger.info(
        "[init_db] provider list 已更新: name=%s empty=%s",
        name,
        not bool(fetched),
    )


def init_neo4j_indexes(config: Config) -> None:
    """确保 Neo4j 属性索引存在（``CREATE INDEX IF NOT EXISTS``，每次 init_db 调用）。"""
    from src.storage.neo4j.client import Neo4jClient
    from src.storage.neo4j.schema import ensure_neo4j_indexes

    client = Neo4jClient(config.neo4j)
    try:
        ensure_neo4j_indexes(client)
        logger.info("[init_db] Neo4j 索引初始化完成")
    except Exception as ex:
        logger.warning("[init_db] Neo4j 索引初始化失败: %s", ex)
    finally:
        client.close()


def init_db(config: Config) -> None:
    """初始化数据库：建表 + 种子数据 + Neo4j 索引（幂等可重复运行）"""
    logger.info("[init_db] 开始初始化: postgres_db=%s", config.postgres.db)
    create_all_tables(config)
    with session_scope() as session:
        logger.info("[init_db] 开始写入种子数据")
        seed_default_data(session)
        logger.info("[init_db] 开始刷新 provider 清单")
        set_llm_provider(session)
    init_neo4j_indexes(config)
    logger.info("[init_db] 初始化完成")
