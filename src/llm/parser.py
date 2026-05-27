"""JSON schema 校验"""
import json
import re
from typing import Dict, Optional

from pydantic import BaseModel, ValidationError


def parse_json_response(text: str) -> Dict:
    """
    从 LLM 响应中提取 JSON
    
    支持提取代码块中的 JSON 或纯 JSON 文本
    """
    # 尝试提取代码块中的 JSON
    json_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', text, re.DOTALL)
    if json_match:
        try:
            return json.loads(json_match.group(1))
        except json.JSONDecodeError:
            pass
    
    # 尝试提取第一个 { ... } 块
    json_match = re.search(r'\{.*\}', text, re.DOTALL)
    if json_match:
        try:
            return json.loads(json_match.group(0))
        except json.JSONDecodeError:
            pass
    
    # 直接解析整个文本
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {}


class JSONParser:
    """JSON 解析和校验器"""
    
    @staticmethod
    def parse_json(text: str) -> Optional[Dict]:
        """解析 JSON 文本"""
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return None
    
    @staticmethod
    def validate_schema(data: Dict, schema_class: type[BaseModel]) -> Optional[BaseModel]:
        """
        使用 Pydantic schema 校验数据
        
        返回：校验后的模型实例，失败返回 None
        """
        try:
            return schema_class(**data)
        except ValidationError as e:
            # TODO: 记录验证错误
            return None

