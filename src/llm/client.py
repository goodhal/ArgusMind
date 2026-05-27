"""LLM 客户端（基于 LiteLLM 统一接口）"""
from dataclasses import dataclass
from typing import Dict, List, Optional

from src.config import LLMConfig

try:
    from litellm import completion as litellm_completion
except ImportError:
    litellm_completion = None

@dataclass
class LLMResponse:
    """单次调用的返回：回复内容 + 本次对话消耗的 token"""

    content: str
    """AI 回复文本"""

    prompt_tokens: int = 0
    """输入（提示）消耗的 token 数"""

    completion_tokens: int = 0
    """输出（补全）消耗的 token 数"""

    total_tokens: int = 0
    """总 token 数（prompt_tokens + completion_tokens）"""

    raw: object | None = None
    """底层 LLM 原始响应对象（用于调试/透传）"""

    @property
    def usage(self) -> Dict[str, int]:
        """以字典形式返回用量，便于日志或上报"""
        return {
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
        }


class LLMClient:
    """
    LLM 客户端，基于 [LiteLLM](https://docs.litellm.ai/docs/) 统一调用多种模型。

    所有参数通过 config 传入，不读写环境变量。
    模型格式为：`provider/model`，例如：
    - openai/gpt-4o
    - anthropic/claude-3-sonnet-20240229
    - azure/your-deployment-name
    - ollama/llama2（本地）
    - 自建服务：config 中设置 base_url，model 用 openai/your-model 或 custom/your-model
    """

    def __init__(self, config: LLMConfig):
        """
        初始化 LLM 客户端。

        Args:
            config: LLM 配置（api_key、base_url、api_version 等均通过 config 传入）
        """
        self.MAX_RETRIES = 3
        if litellm_completion is None:
            raise ImportError("请安装 litellm: pip install litellm")
        self.config = config

    def _litellm_kwargs(self, temperature: float = 0.7, max_tokens: Optional[int] = None, **kwargs) -> Dict:
        """从 config 构建 litellm completion 参数，不依赖环境变量"""
        model = self.config.model
        if "/" not in model and self.config.provider:
            model = f"{self.config.provider}/{model}"
        kw: Dict = {
            "model": model,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if self.config.api_key:
            kw["api_key"] = self.config.api_key
        # base_url：自建或自定义端点；Azure 时也可用 azure_endpoint
        api_base = self.config.base_url or getattr(self.config, "azure_endpoint", None)
        if api_base and self.config.type != "builtin":
            kw["api_base"] = api_base
        if getattr(self.config, "api_version", None):
            kw["api_version"] = self.config.api_version
        kw.update(kwargs)
        return {k: v for k, v in kw.items() if v is not None}

    def _parse_usage(self, response) -> tuple[int, int, int]:
        """从 LiteLLM 响应中解析 usage，返回 (prompt_tokens, completion_tokens, total_tokens)"""
        prompt_tokens = completion_tokens = total_tokens = 0
        if getattr(response, "usage", None):
            u = response.usage
            prompt_tokens = getattr(u, "prompt_tokens", 0) or 0
            completion_tokens = getattr(u, "completion_tokens", 0) or 0
            total_tokens = getattr(u, "total_tokens", 0) or (prompt_tokens + completion_tokens)
        return (prompt_tokens, completion_tokens, total_tokens)

    def call(
            self,
            messages: List[Dict[str, str]],
            temperature: float = 0.7,
            max_tokens: Optional[int] = None,
            **kwargs,
    ) -> LLMResponse:
        """
        调用 LLM 接口。

        Args:
            messages: 消息列表，格式为 [{"role": "user", "content": "..."}]
            temperature: 温度参数
            max_tokens: 最大 token 数
            **kwargs: 其他 LiteLLM 支持的参数（如 stream=True）

        Returns:
            LLMResponse：包含 content（回复文本）与 prompt_tokens/completion_tokens/total_tokens
        """
        try:
            litellm_kw = self._litellm_kwargs(
                temperature=temperature,
                max_tokens=max_tokens,
                **kwargs,
            )
            response = litellm_completion(
                messages=messages,
                **litellm_kw,
            )
            content = response.choices[0].message.content or ""
            prompt_tokens, completion_tokens, total_tokens = self._parse_usage(response)
            return LLMResponse(
                content=content,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=total_tokens,
                raw=response,
            )
        except Exception as e:
            raise RuntimeError(f"LLM 调用失败: {e}")



    def supports_streaming(self) -> bool:
        """LiteLLM 支持流式，传 stream=True 即可"""
        return True

    def supports_json_mode(self) -> bool:
        """部分模型支持 response_format json_object"""
        return True
