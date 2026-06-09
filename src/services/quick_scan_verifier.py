# -*- coding: utf-8 -*-
"""快速扫描结果 LLM 验证器。

在联机模式下，对快速扫描（规则引擎）的发现进行 LLM 逐条验证：
- 读取每条 finding 对应的源代码上下文
- 让 LLM 判断是否为真实漏洞（confirmed）或误报（false_positive）
- 更新 finding 的 verification_status 和 confidence
- 过滤掉 LLM 判定为误报的发现
"""

from __future__ import annotations

import logging
import os
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple

from src.llm.client import LLMClient
from src.utils import parse_json

logger = logging.getLogger(__name__)

# 验证结果常量
VERIFIED_CONFIRMED = "confirmed"
VERIFIED_FALSE_POSITIVE = "false_positive"
VERIFIED_NEED_REVIEW = "need_review"

# 单次验证最大 findings 数（避免 token 过长）
_MAX_FINDINGS_PER_BATCH = 10
# 读取源代码上下文的行数范围
_CONTEXT_LINES = 15


class QuickScanVerifier:
    """使用 LLM 验证快速扫描结果。"""

    def __init__(self, llm: LLMClient, project_path: str = "", task_id: str = "") -> None:
        self._llm = llm
        self._project_path = project_path
        self._task_id = task_id
        self._stats: Dict[str, int] = {
            "total": 0,
            "confirmed": 0,
            "false_positive": 0,
            "need_review": 0,
            "error": 0,
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "cached_tokens": 0,
        }
        self._lock = threading.Lock()

    def verify_findings(
        self,
        findings: List[Dict[str, Any]],
        project_info: str = "",
        max_workers: int = 5,
    ) -> List[Dict[str, Any]]:
        """批量验证快速扫描结果，返回验证后的 findings 列表。

        每条 finding 会被添加以下字段：
        - verification_status: confirmed / false_positive / need_review
        - verification_reason: LLM 给出的判断理由
        - confidence: 更新后的置信度

        Args:
            findings: 待验证的发现列表
            project_info: 项目信息描述
            max_workers: 并行验证的最大批数（控制 LLM 并发）
        """
        if not findings:
            return []

        self._stats["total"] = len(findings)
        batches = [findings[i : i + _MAX_FINDINGS_PER_BATCH]
                   for i in range(0, len(findings), _MAX_FINDINGS_PER_BATCH)]

        if len(batches) <= 1:
            # 单批直接串行，避免线程开销
            verified: List[Dict[str, Any]] = []
            for batch in batches:
                verified.extend(self._verify_batch(batch, project_info))
        else:
            # 多批并行验证
            verified = self._verify_batches_parallel(batches, project_info, max_workers)

        logger.info(
            "QuickScanVerifier 完成: total=%d confirmed=%d false_positive=%d need_review=%d error=%d prompt_tokens=%d completion_tokens=%d cached_tokens=%d",
            self._stats["total"],
            self._stats["confirmed"],
            self._stats["false_positive"],
            self._stats["need_review"],
            self._stats["error"],
            self._stats["prompt_tokens"],
            self._stats["completion_tokens"],
            self._stats["cached_tokens"],
        )
        # 上报 token 用量到 token_ledger
        if self._task_id and (self._stats["prompt_tokens"] or self._stats["completion_tokens"]):
            try:
                from src.services.token_service import report_token_usage
                report_token_usage(
                    task_id=self._task_id,
                    llm_input=self._stats["prompt_tokens"],
                    llm_output=self._stats["completion_tokens"],
                    note="llm_verification",
                )
                # 上报 LLM prompt cache 命中统计
                cached = self._stats["cached_tokens"]
                total_prompt = self._stats["prompt_tokens"]
                if total_prompt > 0:
                    report_token_usage(
                        task_id=self._task_id,
                        llm_input=cached,
                        llm_output=total_prompt - cached,
                        note="cache_stats:llm_verification",
                    )
            except Exception:
                pass
        return verified

    def _verify_batches_parallel(
        self,
        batches: List[List[Dict[str, Any]]],
        project_info: str,
        max_workers: int,
    ) -> List[Dict[str, Any]]:
        """并行验证多批 findings。"""
        verified: List[Dict[str, Any]] = []
        workers = min(max_workers, len(batches))
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(self._verify_batch, batch, project_info): batch
                for batch in batches
            }
            for future in as_completed(futures):
                try:
                    verified.extend(future.result())
                except Exception as e:
                    logger.warning("QuickScanVerifier 批量验证异常: %s", e)
                    # 异常批全部标记为 need_review
                    batch = futures[future]
                    for f in batch:
                        f["verification_status"] = VERIFIED_NEED_REVIEW
                        f["verification_reason"] = f"LLM 验证异常: {e}"
                        verified.append(f)
                        with self._lock:
                            self._stats["need_review"] += 1
        return verified

    def _verify_batch(
        self,
        batch: List[Dict[str, Any]],
        project_info: str,
    ) -> List[Dict[str, Any]]:
        """验证一批 findings。"""
        # 为每条 finding 读取源代码上下文
        findings_with_context = []
        for f in batch:
            context = self._read_source_context(f)
            findings_with_context.append({**f, "_source_context": context})

        # 构建 LLM prompt
        messages = self._build_verification_messages(findings_with_context, project_info)

        try:
            resp = self._llm.call(messages, temperature=0.1)
            result = parse_json(resp.content, default={})
            # 累计 token 用量
            with self._lock:
                self._stats["prompt_tokens"] += resp.prompt_tokens
                self._stats["completion_tokens"] += resp.completion_tokens
                self._stats["cached_tokens"] += resp.cached_tokens
        except Exception as e:
            logger.warning("QuickScanVerifier LLM 调用失败: %s", e)
            # LLM 调用失败时，所有 finding 标记为 need_review
            for f in batch:
                f["verification_status"] = VERIFIED_NEED_REVIEW
                f["verification_reason"] = f"LLM 验证调用失败: {e}"
                with self._lock:
                    self._stats["need_review"] += 1
            return batch

        # 解析 LLM 返回的验证结果
        verifications = result.get("verifications", [])
        verdict_map: Dict[int, Dict[str, Any]] = {}
        for idx, v in enumerate(verifications):
            verdict_map[idx] = v

        for idx, f in enumerate(batch):
            verdict = verdict_map.get(idx, {})
            status = str(verdict.get("verdict", "")).lower()
            reason = str(verdict.get("reason", ""))
            confidence = verdict.get("confidence")

            if status in ("confirmed", "true", "yes", "real"):
                f["verification_status"] = VERIFIED_CONFIRMED
                with self._lock:
                    self._stats["confirmed"] += 1
            elif status in ("false_positive", "false", "no", "fp", "误报"):
                f["verification_status"] = VERIFIED_FALSE_POSITIVE
                with self._lock:
                    self._stats["false_positive"] += 1
            else:
                f["verification_status"] = VERIFIED_NEED_REVIEW
                with self._lock:
                    self._stats["need_review"] += 1

            f["verification_reason"] = reason
            if isinstance(confidence, (int, float)) and 0 <= confidence <= 1:
                f["confidence"] = confidence

        return batch

    def _build_verification_messages(
        self,
        findings_with_context: List[Dict[str, Any]],
        project_info: str,
    ) -> List[Dict[str, str]]:
        """构建验证用的 LLM 消息。"""
        system_prompt = (
            "你是一位资深安全审计专家。你的任务是验证规则引擎快速扫描发现的安全漏洞是否为真实漏洞。\n\n"
            "对于每条发现，你需要：\n"
            "1. 阅读对应的源代码上下文\n"
            "2. 判断该发现是否为真实安全漏洞（confirmed）还是误报（false_positive）\n"
            "3. 如果无法确定，标记为 need_review\n"
            "4. 给出判断理由和置信度（0-1）\n\n"
            "判断要点：\n"
            "- 检查是否存在用户输入到达危险函数的数据流\n"
            "- 检查是否有有效的安全防护（参数化查询、输入校验、编码转义等）\n"
            "- 区分测试代码/示例代码与生产代码\n"
            "- 考虑框架内置的安全机制\n\n"
            "请以 JSON 格式返回结果，格式如下：\n"
            '{"verifications": [{"verdict": "confirmed|false_positive|need_review", "reason": "判断理由", "confidence": 0.8}]}\n\n'
            "每条 verdict 与输入的 finding 一一对应。"
        )

        # 构建用户消息：逐条列出 findings
        user_parts = []
        if project_info:
            user_parts.append(f"项目信息：\n{project_info[:500]}\n")

        user_parts.append(f"以下共 {len(findings_with_context)} 条快速扫描发现，请逐条验证：\n")

        for idx, f in enumerate(findings_with_context):
            location = f.get("location", f.get("file", ""))
            line = f.get("line", "")
            vuln_type = f.get("vuln_type", f.get("category_name", ""))
            title = f.get("title", "")
            evidence = f.get("evidence", "")
            severity = f.get("severity", "")
            source_context = f.get("_source_context", "")

            part = f"### Finding {idx}\n"
            part += f"- 位置: {location}"
            if line:
                part += f":{line}"
            part += "\n"
            part += f"- 漏洞类型: {vuln_type}\n"
            if title:
                part += f"- 标题: {title}\n"
            part += f"- 严重等级: {severity}\n"
            if evidence:
                part += f"- 规则引擎证据: {evidence[:300]}\n"
            if source_context:
                part += f"- 源代码上下文:\n```\n{source_context}\n```\n"
            user_parts.append(part)

        user_message = "\n".join(user_parts)

        return [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message},
        ]

    def _read_source_context(self, finding: Dict[str, Any]) -> str:
        """读取 finding 对应的源代码上下文。"""
        if not self._project_path:
            return ""

        file_path = finding.get("location", finding.get("file", ""))
        # location 可能是 "path/to/file.java:42" 格式
        if ":" in str(file_path):
            file_path = str(file_path).split(":")[0]

        if not file_path:
            return ""

        # 转为绝对路径
        abs_path = os.path.join(self._project_path, file_path)
        if not os.path.isfile(abs_path):
            return ""

        # 获取行号
        line_num = 0
        raw_line = finding.get("line", 0)
        if raw_line:
            try:
                line_num = int(str(raw_line).strip().split("-")[0])
            except (ValueError, IndexError):
                line_num = 0
        if not line_num and ":" in str(finding.get("location", "")):
            parts = str(finding["location"]).split(":")
            if len(parts) >= 2:
                try:
                    line_num = int(parts[1].strip().split("-")[0])
                except (ValueError, IndexError):
                    line_num = 0

        try:
            with open(abs_path, "r", encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()

            if line_num > 0:
                start = max(0, line_num - _CONTEXT_LINES - 1)
                end = min(len(lines), line_num + _CONTEXT_LINES)
                selected = lines[start:end]
                # 标注目标行
                context_lines = []
                for i, line in enumerate(selected):
                    actual_line = start + i + 1
                    marker = ">>>" if actual_line == line_num else "   "
                    context_lines.append(f"{marker} {actual_line:4d} | {line.rstrip()}")
                return "\n".join(context_lines)
            else:
                # 无行号，返回文件前 30 行
                return "".join(lines[:30])
        except Exception:
            return ""

    def get_stats(self) -> Dict[str, int]:
        """获取验证统计。"""
        return dict(self._stats)

    @staticmethod
    def filter_verified(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """过滤掉 LLM 判定为误报的发现，保留 confirmed 和 need_review。"""
        return [
            f for f in findings
            if f.get("verification_status") != VERIFIED_FALSE_POSITIVE
        ]
