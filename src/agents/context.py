# -------------------------------------
# @file      : context.py
# @author    : Autumn
# @contact   : rainy-autumn@outlook.com
# @time      : 2026/2/5 23:59
# -------------------------------------------

from dataclasses import dataclass

from src.config import LLMConfig


@dataclass
class BrainContext:
    project_id: str
    project_name: str
    project_path: str
    task_id: str
    llm_config: LLMConfig
