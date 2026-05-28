"""OpenCode 客户端与符号解析工具"""
import asyncio
import atexit
import json
import logging
import re
import subprocess
import threading
import time
from typing import Any, Callable, Dict, Optional

from openai._base_client import make_request_options
from opencode_ai import Opencode, Omit
import httpx
from opencode_ai.types import Session

from src.core.code_agent_run_registry import get_code_agent_run_registry
from src.tools.base import (
    BaseTool,
    ERROR_CODE_CANCELLED,
    ERROR_CODE_EXTERNAL,
    ToolResult,
)
from src.tools.bootstrap.opencode_runtime import resolve_opencode_executable
from src.utils.base import get_free_port

logger = logging.getLogger(__name__)


def _extract_response_text(response: Any) -> str:
    """从响应对象中提取文本。"""
    if hasattr(response, "content"):
        content = response.content
        if isinstance(content, list):
            texts = []
            for part in content:
                if hasattr(part, "text"):
                    texts.append(part.text)
                elif isinstance(part, dict) and "text" in part:
                    texts.append(part["text"])
                elif isinstance(part, str):
                    texts.append(part)
            if texts:
                return "\n".join(texts)
        elif isinstance(content, str):
            return content
    if hasattr(response, "text") and isinstance(getattr(response, "text"), str):
        return response.text
    if hasattr(response, "parts") and isinstance(response.parts, list):
        texts = []
        for part in response.parts:
            if isinstance(part, dict) and "text" in part:
                texts.append(part["text"])
            elif hasattr(part, "text"):
                texts.append(part.text)
        if texts:
            return "\n".join(texts)
    result = str(response)
    if result.startswith("<") or "object" in result.lower():
        json_match = re.search(r"\{.*\}", result, re.DOTALL)
        if json_match:
            return json_match.group(0)
    return result


def _truncate(s: Optional[str], limit: int = 4000) -> Optional[str]:
    """对长文本做截断，避免持久化/日志过大。"""
    if s is None:
        return None
    if not isinstance(s, str):
        s = str(s)
    if len(s) <= limit:
        return s
    return s[:limit] + f"…(truncated {len(s) - limit} chars)"


def _to_jsonable(obj: Any) -> Any:
    """把任意 SDK 对象（pydantic / dataclass / 普通对象）转成可 JSON 序列化的结构。"""
    if obj is None or isinstance(obj, (bool, int, float, str)):
        return obj
    if isinstance(obj, dict):
        return {str(k): _to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [_to_jsonable(v) for v in obj]
    for attr in ("model_dump", "to_dict", "dict"):
        method = getattr(obj, attr, None)
        if callable(method):
            try:
                if attr == "model_dump":
                    try:
                        return _to_jsonable(
                            method(mode="python", warnings=False, serialize_as_any=True)
                        )
                    except TypeError:
                        try:
                            return _to_jsonable(method(warnings=False))
                        except TypeError:
                            return _to_jsonable(method())
                return _to_jsonable(method())
            except Exception:
                pass
    if hasattr(obj, "__dict__"):
        try:
            return _to_jsonable({k: v for k, v in vars(obj).items() if not k.startswith("_")})
        except Exception:
            pass
    return repr(obj)


def _opencode_sse_event_full_payload(ev: Any) -> Optional[Dict[str, Any]]:
    """将整条 OpenCode SSE 事件对象序列化为可写入 JSONB 的 dict（含 type、properties 及 SDK 其它顶层字段）。"""
    try:
        out = _to_jsonable(ev)
        if isinstance(out, dict):
            return out
    except Exception as ex:
        logger.debug("[opencode SSE] 整事件序列化失败: %s", ex)
    try:
        return {
            "type": getattr(ev, "type", None),
            "properties": _to_jsonable(getattr(ev, "properties", None)),
        }
    except Exception:
        return None


def _describe_opencode_part_for_log(part: Any) -> Optional[str]:
    """将 message.part.updated 中的 part 转为一条可读的执行步骤说明。"""
    ptype = getattr(part, "type", None)
    if ptype == "step-start":
        return "执行步骤：开始"
    if ptype == "step-finish":
        tok = getattr(part, "tokens", None)
        if tok is not None:
            inp = getattr(tok, "input", None)
            out = getattr(tok, "output", None)
            return f"执行步骤：结束（tokens in={inp} out={out}）"
        return "执行步骤：结束"
    if ptype == "tool":
        name = getattr(part, "tool", "") or "?"
        state = getattr(part, "state", None)
        status = getattr(state, "status", None) if state is not None else None
        if status == "pending":
            return f"工具调用：{name}（排队）"
        if status == "running":
            title = getattr(state, "title", None) or ""
            return f"工具调用：{name} 执行中{f' — {title}' if title else ''}"
        if status == "completed":
            title = getattr(state, "title", None) or ""
            out = getattr(state, "output", None)
            preview = ""
            if isinstance(out, str) and out.strip():
                s = out.strip().replace("\n", " ")
                preview = f" 输出预览：{s[:200]}{'…' if len(s) > 200 else ''}"
            return f"工具调用：{name} 已完成{f' — {title}' if title else ''}{preview}"
        if status == "error":
            return f"工具调用：{name} 失败"
        return f"工具调用：{name}（状态={status}）"
    if ptype == "reasoning":
        text = getattr(part, "text", "") or ""
        if text.strip():
            one = text.strip().replace("\n", " ")
            return f"推理片段：{one[:300]}{'…' if len(one) > 300 else ''}"
    if ptype == "text":
        t = getattr(part, "time", None)
        end = getattr(t, "end", None) if t is not None else None
        if end is not None:
            text = getattr(part, "text", "") or ""
            if text.strip():
                one = text.strip().replace("\n", " ")
                return f"助手文本（本轮片段）：{one[:300]}{'…' if len(one) > 300 else ''}"
    if ptype == "patch":
        files = getattr(part, "files", None) or []
        return f"代码补丁：{len(files)} 个文件"
    if ptype == "file":
        return f"文件：{getattr(part, 'filename', '') or getattr(part, 'url', '')}"
    return None


def _event_session_id(ev: Any) -> Optional[str]:
    """尝试从各种事件结构上提取 session_id，匹配当前会话。"""
    props = getattr(ev, "properties", None)
    if props is None:
        return None
    sid = getattr(props, "session_id", None)
    if sid:
        return sid
    info = getattr(props, "info", None)
    if info is not None:
        sid = getattr(info, "session_id", None)
        if sid:
            return sid
    part = getattr(props, "part", None)
    if part is not None:
        sid = getattr(part, "session_id", None)
        if sid:
            return sid
    return None


def _extract_opencode_event_payload(ev: Any, session_id: str) -> Optional[Dict[str, Any]]:
    """把 SSE 事件解析为 opencode_event_service.record_opencode_event 所需的字段字典。

    payload 存整条事件的完整 JSON；其它列为便于查询/展示的冗余摘要。
    返回 None 表示该事件与当前 session 无关（应跳过）。
    """
    ev_type = getattr(ev, "type", None) or ""
    sid = _event_session_id(ev)
    if not ev_type or sid != session_id:
        return None

    props = getattr(ev, "properties", None)
    full_payload = _opencode_sse_event_full_payload(ev)

    record: Dict[str, Any] = {
        "session_id": session_id,
        "event_type": ev_type,
        "payload": full_payload,
    }

    if ev_type == "message.part.updated" and props is not None:
        part = getattr(props, "part", None)
        if part is None:
            return None
        ptype = getattr(part, "type", None)
        record["part_type"] = ptype
        record["part_id"] = getattr(part, "id", None)
        record["message_id"] = getattr(part, "message_id", None)

        if ptype == "tool":
            state = getattr(part, "state", None)
            record["tool_name"] = getattr(part, "tool", None)
            record["tool_status"] = getattr(state, "status", None) if state is not None else None
            record["title"] = _truncate(getattr(state, "title", None) if state is not None else None, 1000)
            out = getattr(state, "output", None) if state is not None else None
            err = getattr(state, "error", None) if state is not None else None
            record["content"] = _truncate(out if isinstance(out, str) and out else err, 8000)
        elif ptype in ("step-start", "step-finish"):
            tok = getattr(part, "tokens", None)
            if tok is not None:
                record["token_input"] = int(getattr(tok, "input", 0) or 0)
                record["token_output"] = int(getattr(tok, "output", 0) or 0)
        elif ptype in ("text", "reasoning"):
            record["content"] = _truncate(getattr(part, "text", None), 8000)
        elif ptype == "file":
            record["title"] = _truncate(
                getattr(part, "filename", None) or getattr(part, "url", None),
                500,
            )
        elif ptype == "patch":
            files = getattr(part, "files", None) or []
            record["title"] = _truncate(
                f"patch with {len(files)} files: {', '.join(map(str, files[:5]))}",
                500,
            )
        return record

    if ev_type == "message.updated" and props is not None:
        info = getattr(props, "info", None)
        record["message_id"] = getattr(info, "id", None) if info is not None else None
        return record

    if ev_type == "message.removed" and props is not None:
        record["message_id"] = getattr(props, "message_id", None)
        return record

    if ev_type == "message.part.removed" and props is not None:
        record["part_id"] = getattr(props, "part_id", None)
        record["message_id"] = getattr(props, "message_id", None)
        return record

    if ev_type == "message.part.delta" and props is not None:
        record["part_id"] = getattr(props, "part_id", None)
        record["message_id"] = getattr(props, "message_id", None)
        record["title"] = _truncate(getattr(props, "field", None), 200)
        record["content"] = _truncate(getattr(props, "delta", None), 8000)
        return record

    if ev_type == "session.error" and props is not None:
        err = getattr(props, "error", None)
        record["title"] = _truncate(getattr(err, "name", None) if err is not None else None, 500)
        data = getattr(err, "data", None) if err is not None else None
        record["content"] = _truncate(
            getattr(data, "message", None) if data is not None else (str(err) if err is not None else None),
            8000,
        )
        return record

    if ev_type in (
        "session.idle",
        "session.compacted",
        "session.diff",
        "todo.updated",
        "permission.asked",
        "permission.replied",
        "question.asked",
        "question.replied",
        "question.rejected",
        "file.edited",
    ):
        return record

    return record


def _fingerprint_opencode_sse_event(ev: Any) -> Optional[tuple[Any, ...]]:
    """
    生成事件指纹用于去重。
    仅按文本去重会误吞"不同事件但文案相同"的情况，因此优先基于事件结构字段去重。
    """
    ev_type = getattr(ev, "type", None)
    props = getattr(ev, "properties", None)
    if not ev_type or props is None:
        return None

    if ev_type == "message.part.updated":
        part = getattr(props, "part", None)
        if part is None:
            return None

        ptype = getattr(part, "type", None)
        if ptype == "tool":
            state = getattr(part, "state", None)
            return (
                ev_type,
                ptype,
                getattr(part, "session_id", None),
                getattr(part, "id", None),
                getattr(part, "message_id", None),
                getattr(part, "tool", None),
                getattr(state, "status", None) if state is not None else None,
                getattr(state, "title", None) if state is not None else None,
                getattr(state, "output", None) if state is not None else None,
            )
        if ptype == "step-start" or ptype == "step-finish":
            tok = getattr(part, "tokens", None)
            return (
                ev_type,
                ptype,
                getattr(part, "session_id", None),
                getattr(part, "id", None),
                getattr(part, "message_id", None),
                getattr(tok, "input", None) if tok is not None else None,
                getattr(tok, "output", None) if tok is not None else None,
            )
        if ptype in ("text", "reasoning"):
            t = getattr(part, "time", None)
            return (
                ev_type,
                ptype,
                getattr(part, "session_id", None),
                getattr(part, "id", None),
                getattr(part, "message_id", None),
                getattr(t, "end", None) if t is not None else None,
                getattr(part, "text", None),
            )
        return (
            ev_type,
            ptype,
            getattr(part, "session_id", None),
            getattr(part, "id", None),
            getattr(part, "message_id", None),
        )

    # 其它事件按 type + 全部 property 摘要去重
    try:
        digest = json.dumps(_to_jsonable(props), sort_keys=True, ensure_ascii=False, default=str)
    except Exception:
        digest = repr(props)
    return (ev_type, digest)


def _extract_step_finish_tokens_from_event(ev: Any, session_id: str) -> Optional[tuple[float, float]]:
    """从 step-finish 事件提取 token（用于全流程累计）。"""
    if getattr(ev, "type", None) != "message.part.updated":
        return None
    props = getattr(ev, "properties", None)
    if props is None:
        return None
    part = getattr(props, "part", None)
    if part is None:
        return None
    if getattr(part, "session_id", None) != session_id:
        return None
    if getattr(part, "type", None) != "step-finish":
        return None

    tok = getattr(part, "tokens", None)
    if tok is None:
        return None

    inp = getattr(tok, "input", None)
    out = getattr(tok, "output", None)
    try:
        fin = float(inp if inp is not None else 0)
        fout = float(out if out is not None else 0)
    except Exception:
        return None
    return fin, fout


_SESSION_STATUS_POLL_INTERVAL_SEC = 10.0


def _opencode_client_base_url(client: Opencode) -> str:
    base = getattr(client, "base_url", None)
    if base is None:
        return ""
    return str(base).rstrip("/")


def _parse_opencode_session_status_entry(
        data: Any,
        session_id: str,
) -> Optional[Dict[str, Any]]:
    """从 /session/status 响应体中解析当前 session 的状态对象。"""
    if not isinstance(data, dict):
        return None
    entry = data.get(session_id)
    if isinstance(entry, dict):
        return entry
    if entry is not None and hasattr(entry, "model_dump"):
        try:
            dumped = entry.model_dump(mode="python")
            if isinstance(dumped, dict):
                return dumped
        except Exception:
            pass
    if entry is not None:
        try:
            converted = _to_jsonable(entry)
            if isinstance(converted, dict):
                return converted
        except Exception:
            pass
    return None


async def _fetch_opencode_session_status(
        session_id: str,
        http: httpx.AsyncClient,
        *,
        client: Opencode,
        base_url: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """异步 GET /session/status，返回当前 session_id 对应的状态对象。"""
    base = (base_url or _opencode_client_base_url(client)).rstrip("/")
    if not base or not session_id:
        return None
    url = f"{base}/session/status"
    try:
        resp = await http.get(url)
        resp.raise_for_status()
        data = resp.json()
    except Exception as ex:
        logger.debug("[opencode status] 查询 %s 失败: %s", url, ex)
        return None
    return _parse_opencode_session_status_entry(data, session_id)


async def _async_wait_until_stop(stop: threading.Event, seconds: float) -> None:
    """可被 threading.Event 提前唤醒的 asyncio 睡眠。"""
    deadline = time.monotonic() + seconds
    while not stop.is_set():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return
        await asyncio.sleep(min(0.2, remaining))


async def _run_opencode_session_status_poll(
        *,
        client: Opencode,
        session_id: str,
        base_url: Optional[str],
        stop: threading.Event,
        event_id: Optional[int],
        persisted_fps: set[tuple[Any, ...]],
        _oes: Any,
) -> None:
    """在 asyncio 事件循环中每 10s 异步轮询 /session/status。"""
    last_status_fp: Optional[tuple[Any, ...]] = None
    timeout = httpx.Timeout(connect=10.0, read=10.0, write=10.0, pool=10.0)
    async with httpx.AsyncClient(timeout=timeout) as http:
        while not stop.is_set():
            try:
                status = await _fetch_opencode_session_status(
                    session_id,
                    http,
                    client=client,
                    base_url=base_url,
                )
                if status is not None:
                    fp = _fingerprint_session_status(status)
                    if fp != last_status_fp:
                        if _oes is not None and event_id and fp not in persisted_fps:
                            record = _session_status_to_event_record(session_id, status)
                            _oes.record_opencode_event(event_id=event_id, **record)
                            persisted_fps.add(fp)
                        logger.debug(
                            "[opencode status] %s",
                            _describe_session_status_for_log(status),
                        )
                        last_status_fp = fp
            except Exception as ex:
                if not stop.is_set():
                    logger.debug("[opencode status] 轮询异常: %s", ex)
            await _async_wait_until_stop(stop, _SESSION_STATUS_POLL_INTERVAL_SEC)


def _fingerprint_session_status(status: Dict[str, Any]) -> tuple[Any, ...]:
    stype = status.get("type")
    if stype == "retry":
        return (
            "session.status",
            stype,
            status.get("attempt"),
            status.get("message"),
            status.get("next"),
        )
    return ("session.status", stype)


def _session_status_to_event_record(session_id: str, status: Dict[str, Any]) -> Dict[str, Any]:
    """把 /session/status 中单条会话状态转为 opencode_events 落库字段。"""
    stype = str(status.get("type") or "")
    content: Optional[str] = None
    if stype == "retry":
        content = (
            f"attempt={status.get('attempt')}; "
            f"message={status.get('message')}; "
            f"next={status.get('next')}"
        )
    return {
        "session_id": session_id,
        "event_type": stype,
        "content": _truncate(content, 8000) if content else None,
        "payload": {"source": "session.status", "status": _to_jsonable(status)},
    }


def _describe_session_status_for_log(status: Dict[str, Any]) -> str:
    stype = str(status.get("type") or "?")
    if stype == "retry":
        return (
            f"会话状态：retry — attempt={status.get('attempt')}; "
            f"message={status.get('message')}; next={status.get('next')}"
        )
    return f"会话状态：{stype}"


def _start_opencode_sse_step_printer(
        client: Opencode,
        session_id: str,
        token_accumulator: Optional[dict[str, float]] = None,
        event_id: Optional[int] = None,
        task_id: str = "",
        base_url: Optional[str] = None,
) -> Callable[[], None]:
    """在后台线程订阅 client.event.list()（SSE），打印 + 持久化与本会话相关的事件。

    另起一线程（内建 asyncio 事件循环）每 10s 异步轮询 GET /session/status，
    将当前 session 的 type 写入 event_type；retry 时把 attempt、message、next 拼入 content。

    - token_accumulator：用于全流程累计 step-finish 的 token，便于结束后回填到 EventSpan
    - event_id：当前 code_agent 调用对应的 events.id；非空时把 SSE 事件持久化到 opencode_events，
      并在每次 step-finish 时实时把累计 token 回写到 events.code_agent_*_delta
    - base_url：OpenCode 服务根地址（默认从 client.base_url 读取）

    返回关闭函数：应在 chat 结束后调用以释放连接并 join 线程。
    """
    holder: dict[str, Any] = {}
    stop = threading.Event()
    last_fingerprint: Optional[tuple[Any, ...]] = None
    counted_token_fps: set[tuple[Any, ...]] = set()
    persisted_fps: set[tuple[Any, ...]] = set()

    # 延迟导入避免与 src.services / config_service 之间的循环依赖。
    if event_id:
        from src.services import opencode_event_service as _oes
    else:
        _oes = None  # type: ignore[assignment]

    def status_worker() -> None:
        try:
            asyncio.run(
                _run_opencode_session_status_poll(
                    client=client,
                    session_id=session_id,
                    base_url=base_url,
                    stop=stop,
                    event_id=event_id,
                    persisted_fps=persisted_fps,
                    _oes=_oes,
                )
            )
        except Exception as ex:
            if not stop.is_set():
                logger.warning("[opencode status] 异步轮询线程异常: %s", ex)

    def worker() -> None:
        nonlocal last_fingerprint
        stream = None
        try:
            stream = client.event.list()
            holder["stream"] = stream
            if stop.is_set():
                return
            for ev in stream:
                if stop.is_set():
                    break

                fp = _fingerprint_opencode_sse_event(ev)

                token_changed = False
                if token_accumulator is not None and fp is not None and fp not in counted_token_fps:
                    token_pair = _extract_step_finish_tokens_from_event(ev, session_id)
                    if token_pair is not None:
                        token_accumulator["input"] = token_accumulator.get("input", 0.0) + token_pair[0]
                        token_accumulator["output"] = token_accumulator.get("output", 0.0) + token_pair[1]
                        token_accumulator["count"] = token_accumulator.get("count", 0.0) + 1.0
                        counted_token_fps.add(fp)
                        token_changed = True

                # 持久化：仅在指纹变化时落库，避免 SSE 抖动产生重复行
                if _oes is not None and event_id and fp is not None and fp not in persisted_fps:
                    try:
                        record = _extract_opencode_event_payload(ev, session_id)
                    except Exception as ex:
                        record = None
                        logger.debug("[opencode SSE] 解析事件失败: %s", ex)
                    if record is not None:
                        _oes.record_opencode_event(event_id=event_id, **record)
                        persisted_fps.add(fp)

                # 实时回写 events.code_agent_*_delta，便于前端拿到滚动总额
                if _oes is not None and event_id and token_changed and token_accumulator is not None:
                    _oes.update_event_code_agent_tokens(
                        event_id=event_id,
                        task_id=task_id,
                        total_input=int(token_accumulator.get("input", 0.0)),
                        total_output=int(token_accumulator.get("output", 0.0)),
                    )

                line = None
                if fp != last_fingerprint:
                    if getattr(ev, "type", None) == "message.part.updated":
                        props = getattr(ev, "properties", None)
                        part = getattr(props, "part", None) if props is not None else None
                        if part is not None and getattr(part, "session_id", None) == session_id:
                            line = _describe_opencode_part_for_log(part)
                    elif getattr(ev, "type", None) == "session.error":
                        props = getattr(ev, "properties", None)
                        if props is not None and getattr(props, "session_id", None) == session_id:
                            err = getattr(props, "error", None)
                            name = getattr(err, "name", None) if err is not None else None
                            line = f"会话错误：{name or err}"

                    if line:
                        logger.debug("[opencode SSE] %s", line)
                    last_fingerprint = fp
        except Exception as e:
            if not stop.is_set():
                logger.warning("[opencode SSE] 监听异常: %s", e)
        finally:
            holder.pop("stream", None)
            if stream is not None:
                try:
                    stream.close()
                except Exception:
                    pass

    t = threading.Thread(target=worker, name="opencode-event-sse", daemon=True)
    status_t = threading.Thread(target=status_worker, name="opencode-session-status", daemon=True)
    t.start()
    status_t.start()

    def closer() -> None:
        stop.set()
        s = holder.get("stream")
        if s is not None:
            try:
                s.close()
            except Exception:
                pass
        t.join(timeout=5.0)
        status_t.join(timeout=5.0)

    return closer


def _latest_assistant_text_from_messages(client: Opencode, session_id: str) -> str:
    """chat 响应中若无正文，则从会话消息列表中取最后一条 assistant 的文本 part。"""
    try:
        rows = client.session.messages(id=session_id)
    except Exception:
        return ""
    last_parts: list[Any] = []
    for item in rows:
        info = getattr(item, "info", None)
        if getattr(info, "role", None) == "assistant":
            last_parts = list(getattr(item, "parts", []) or [])
    chunks: list[str] = []
    for p in last_parts:
        if getattr(p, "type", None) == "text":
            tx = getattr(p, "text", None)
            if isinstance(tx, str) and tx:
                chunks.append(tx)
    return "\n".join(chunks).strip()


class OpenCodeTool(BaseTool):
    """OpenCode API 客户端（基于对话的代码分析接口）。"""

    _parameters_schema = [
        {"name": "msg", "type": "string", "description": "指令（自然语言问题或指令）", "required": True},
        {"name": "result_file_flag", "type": "boolean", "description": "是否将结果写入文件", "required": False},
        {"name": "result_file_path", "type": "string", "description": "写入结果文件路径（目录或完整文件路径），当result_file_flag为true时",
         "required": False},
        {"name": "output", "type": "string", "description": "输出结构要求（如格式、字段等）", "required": False},
    ]

    @property
    def name(self) -> str:
        return self._name

    @property
    def description(self) -> str:
        return "智能代码助手，擅长理解代码，支持根据自然语言指令执行任务。"

    @property
    def usage(self) -> str:
        return (
            "run(msg, session_id='', result_file_flag=False, result_file_path='', output='') -> ToolResult。"
            "msg 为指令；result_file_flag 为是否写入文件；result_file_path 为结果文件路径；output 为输出结构要求。"
            "返回 data 为 (response_text, token_input, token_output)。"
        )

    @property
    def status(self) -> bool:
        return self._status

    def _start_service(self):
        if self._process is not None:
            return  # 已启动，避免重复

        opencode_exe = resolve_opencode_executable()
        if not opencode_exe:
            logger.error(
                "OpenCode 启动失败：未在 PATH 中找到 opencode 命令（可尝试 npm i -g opencode-ai）"
            )
            return

        cmd = [
            opencode_exe,
            "serve",
            "--port",
            str(self.port),
        ]

        self._process = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=None,  # 继承当前进程 stderr，报错会打印到控制台
            cwd=self.project_path,
        )
        # 若进程很快退出，说明启动失败
        time.sleep(0.5)
        if self._process.poll() is not None:
            self._process = None
            return
        # 程序退出时（含 PyCharm 停止调试）自动结束子进程，避免孤儿进程
        atexit.register(lambda: self.close())

    def close(self):
        if self._process is None:
            return

        # 1. 尝试优雅停止
        self._process.terminate()

        try:
            self._process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            # 2. 兜底强杀
            self._process.kill()
            self._process.wait()

        self._process = None

    def __init__(
            self,
            max_retries: int = 3,
            model_id: str = "",
            provider_id: str = "",
            project_path: str = ""
    ):
        self._name = "OpenCode"
        self._status = False
        self.url = ""
        if project_path == "":
            logger.error("OpenCode初始化失败，项目路径为空")
            pass

        self.event_id = None

        self.project_path = project_path
        self.port = get_free_port()

        self._process: Optional[subprocess.Popen] = None
        self._start_service()
        time.sleep(3)
        self.url = "http://localhost:" + str(self.port)
        logger.info("opencode %s", self.url)
        self.client = Opencode(
            base_url=self.url,
            _strict_response_validation=False,
            max_retries=0,
            http_client=httpx.Client(
                timeout=httpx.Timeout(
                    connect=10.0,
                    read=None,  # ⭐ 等待直到 AI 完成
                    write=10.0,
                    pool=10.0,
                )
            ),
        )
        self.max_retries = max_retries
        self.model_id = model_id
        self.provider_id = provider_id
        try:
            self.client.session.list()
            self._status = True
        except Exception as e:
            logger.exception("opencode 初始化探测失败: %s", e)


    def set_event_id(self, event_id: str):
        self.event_id = event_id

    def get_url(self) -> str:
        return self.url

    def run(
            self,
            msg: str,
            session_id: str = "",
            result_file_flag: bool = False,
            result_file_path: str = "",
            output: str = "",
            **kwargs,
    ) -> ToolResult:
        """执行 OpenCode 指令。
        msg: 指令（自然语言问题或指令）
        result_file_flag: 是否将结果写入文件
        result_file_path: 结果文件路径（目录或完整路径）
        output: 输出结构要求（如格式、字段等）
        kwargs.event_id: 关联的 events.id；非空时 SSE 事件会被实时持久化到 opencode_events，
                         同时 step-finish 的累计 token 会实时回写到 events.code_agent_*_delta。
                         若调用方未显式传入，则回退使用 self.event_id。
        """
        note = f"[重要提示] 请仅依据 (项目根路径)：{self.project_path} 中明确提供的内容进行生成。若相关信息在该路径中不存在，请明确说明“未找到相关信息”，不得自行推断或编造。\n"

        # 兼容 set_event_id 与 kwargs 透传两种使用方式
        run_event_id_raw = kwargs.pop("event_id", None)
        if run_event_id_raw is None:
            run_event_id_raw = self.event_id
        try:
            run_event_id = int(run_event_id_raw) if run_event_id_raw is not None else None
        except (TypeError, ValueError):
            run_event_id = None
        task_id = kwargs.pop("task_id", "")
        msg = note + msg
        if session_id == "":
            sid = self.create_session()
        else:
            sid = session_id
        if result_file_flag and result_file_path:
            msg += f"\n[必须！]将结果写入{result_file_path}中(对该目录文件你是具有读写权限的无需人工确认)"
        if output:
            msg += f"\n[输出要求] {output}\n\n"
        token_input = token_output = None
        task_id_str = str(task_id).strip() if task_id else ""
        registry = get_code_agent_run_registry()
        for attempt in range(self.max_retries):
            active_run = None
            try:
                if task_id_str:
                    active_run = registry.register(task_id_str, sid, self.client)
                    if active_run and active_run.cancelled.is_set():
                        return ToolResult(
                            success=False,
                            error="任务已暂停或取消",
                            error_code=ERROR_CODE_CANCELLED,
                            meta={"session_id": sid},
                        )

                sse_tokens: dict[str, float] = {"input": 0.0, "output": 0.0, "count": 0.0}
                close_sse = _start_opencode_sse_step_printer(
                    self.client,
                    sid,
                    token_accumulator=sse_tokens,
                    event_id=run_event_id,
                    task_id=task_id,
                    base_url=self.url,
                )
                try:
                    response = self.client.session.chat(
                        id=sid,
                        model_id=self.model_id,
                        provider_id=self.provider_id,
                        parts=[{"type": "text", "text": msg}],
                        extra_body={
                            "model": {
                                "providerID": self.provider_id,
                                "modelID": self.model_id,
                            }
                        },
                    )
                finally:
                    close_sse()

                if task_id_str and registry.is_cancelled(task_id_str):
                    return ToolResult(
                        success=False,
                        error="任务已暂停或取消",
                        error_code=ERROR_CODE_CANCELLED,
                        meta={"session_id": sid},
                    )

                response_text = _extract_response_text(response)
                if not (response_text or "").strip():
                    response_text = _latest_assistant_text_from_messages(self.client, sid)

                response_token_input = (
                    getattr(response, "model_extra", {})
                    .get("info", {})
                    .get("tokens", {})
                    .get("input")
                )

                response_token_output = (
                    getattr(response, "model_extra", {})
                    .get("info", {})
                    .get("tokens", {})
                    .get("output")
                )
                if response_token_input is None and response_token_output is None:
                    tok = getattr(response, "tokens", None)
                    if tok is not None:
                        response_token_input = getattr(tok, "input", None)
                        response_token_output = getattr(tok, "output", None)

                # 优先返回 SSE 累计 token；无有效 step-finish token 时回退到 chat 响应中的 token。
                if sse_tokens.get("count", 0.0) > 0:
                    token_input = sse_tokens.get("input")
                    token_output = sse_tokens.get("output")
                else:
                    token_input = response_token_input
                    token_output = response_token_output
                result = ToolResult(
                    success=True,
                    data={
                        "response_text": response_text,
                        "token_input": token_input,
                        "token_output": token_output,
                    },
                    meta={"session_id": sid},
                )
                logger.debug("opencode 响应 %s", result)
                return result
            except Exception as e:
                if task_id_str and registry.is_cancelled(task_id_str):
                    return ToolResult(
                        success=False,
                        error="任务已暂停或取消",
                        error_code=ERROR_CODE_CANCELLED,
                        meta={"session_id": sid},
                    )
                if attempt >= self.max_retries - 1:
                    return ToolResult(
                        success=False,
                        error=str(e),
                        error_code=ERROR_CODE_EXTERNAL,
                        meta={"session_id": sid},
                    )
            finally:
                if task_id_str:
                    registry.unregister(task_id_str)
        return ToolResult(
            success=False,
            error="max retries exceeded",
            error_code=ERROR_CODE_EXTERNAL,
            meta={"session_id": sid},
        )

    def chat(self, msg: str, session_id: str = "") -> str:
        """兼容旧接口：仅返回回复文本，供 discovery 等直接当字符串使用。"""
        r = self.run(msg=msg, session_id=session_id)
        if r.success and r.data:
            out = r.data
            if isinstance(out, dict) and "response_text" in out:
                return out["response_text"] or ""
            return out[0] if isinstance(out, (list, tuple)) else str(out)
        return ""

    def create_session(self) -> str:
        session = self.client.session.create(extra_headers={"Content-Type": Omit()})
        return session.id

    def fork(self, session_id: str) -> str:
        if session_id:
            session = self.client.post(
                f"/session/{session_id}/fork",
                options=make_request_options(
                    timeout=None, extra_headers={"Content-Type": Omit()}
                ),
                cast_to=Session,
            )
            return session.id
        else:
            return self.create_session()

    @status.setter
    def status(self, value):
        self._status = value

    @name.setter
    def name(self, value):
        self._name = value
