# -------------------------------------
# @file      : __init__.py
# @author    : Autumn
# @contact   : rainy-autumn@outlook.com
# @time      : 2026/2/6 0:18
# -------------------------------------------

from .chain_analyzer import chain_analyzer_system_prompt, chain_node_prompt, chain_analyzer_force_conclude_prompt
from .chain_confirmer import chain_confirmer_system_prompt, chain_confirmer_user_prompt, chain_confirmer_force_conclude_prompt
from .plan import plan_prompt
from .project_info import opencode_project_info_prompt, project_info_compact_system_prompt
from .sink_finder import sink_finder_prompt
from .sink_finder_refine import sink_finder_refine_prompt
# 新增：完成性评估器和渐进式重规划提示词
from .final_answer import final_answer_prompt
from .step_replan import step_replan_prompt

__all__ = [
    'chain_analyzer_system_prompt',
    'chain_node_prompt',
    'chain_analyzer_force_conclude_prompt',
    'chain_confirmer_system_prompt',
    'chain_confirmer_user_prompt',
    'chain_confirmer_force_conclude_prompt',
    'plan_prompt',
    'opencode_project_info_prompt',
    'project_info_compact_system_prompt',
    'sink_finder_prompt',
    'sink_finder_refine_prompt',
    'final_answer_prompt',
    'step_replan_prompt',
]
