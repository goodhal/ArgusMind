"""Tokei 语言统计工具"""
import subprocess
from pathlib import Path
from typing import Any, Dict, Union

from src.tools.base import (
    BaseTool,
    ERROR_CODE_EXTERNAL,
    ERROR_CODE_NOT_FOUND,
    ERROR_CODE_TIMEOUT,
    ToolResult,
)


class TokeiTool(BaseTool):
    """基于 Tokei 的项目代码语言统计（文件数、行数）。"""

    _parameters_schema = [
        {"name": "project_path", "type": "string", "description": "项目或目录路径", "required": True},
    ]

    @property
    def name(self) -> str:
        return "tokei"

    @property
    def description(self) -> str:
        return "统计项目或目录下各语言的文件数和代码行数。"

    @property
    def usage(self) -> str:
        return (
            "run(project_path: str | Path) -> ToolResult。"
            "data 为 {languages: {language: {files, lines, code}}, total: {files, code}}。"
            "示例：run(project_path='.')"
        )

    def run(self, project_path: Union[str, Path], **kwargs) -> ToolResult:
        path = Path(project_path) if isinstance(project_path, str) else project_path
        try:
            data = self.analyze_project(path)
            return ToolResult(
                success=True,
                data=data,
                meta={"project_path": str(path)},
            )
        except FileNotFoundError as e:
            return ToolResult(
                success=False,
                error=str(e),
                error_code=ERROR_CODE_NOT_FOUND,
                meta={"project_path": str(path)},
            )
        except TimeoutError as e:
            return ToolResult(
                success=False,
                error=str(e),
                error_code=ERROR_CODE_TIMEOUT,
                meta={"project_path": str(path)},
            )
        except (RuntimeError, ValueError) as e:
            return ToolResult(
                success=False,
                error=str(e),
                error_code=ERROR_CODE_EXTERNAL,
                meta={"project_path": str(path)},
            )
        except Exception as e:
            return ToolResult(
                success=False,
                error=str(e),
                meta={"project_path": str(path)},
            )

    def analyze_project(self, project_path: Union[str, Path]) -> Dict[str, Dict[str, Any]]:
        """
        分析项目语言统计。
        返回：{
            "languages": {language: {files, lines, code}},
            "total": {files, code}
        }
        """
        path = Path(project_path) if isinstance(project_path, str) else project_path
        
        if not path.exists():
            raise FileNotFoundError(f"路径不存在: {path}")
        
        # 调用 tokei CLI，使用普通文本输出
        cmd = ["tokei", "-C", "-s", "code", str(path)]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True,
                timeout=60,  # 60秒超时
            )
            
            # 解析文本输出
            formatted_data = self._parse_tokei_output(result.stdout)
            
            return formatted_data
            
        except FileNotFoundError:
            raise FileNotFoundError(
                "未找到 tokei 命令。请确保已安装 tokei："
                "https://github.com/XAMPPRocky/tokei#installation"
            )
        except subprocess.TimeoutExpired:
            raise TimeoutError("tokei 执行超时（超过60秒）")
        except subprocess.CalledProcessError as e:
            error_msg = e.stderr or e.stdout or str(e)
            raise RuntimeError(f"tokei 执行失败: {error_msg}")
        except ValueError as e:
            raise ValueError(f"解析 tokei 输出失败: {e}")
    
    def _parse_tokei_output(self, output: str) -> Dict[str, Dict[str, Any]]:
        """
        解析 tokei 的文本输出。
        
        输出格式示例：
        ===============================================================================
         Language            Files        Lines         Code     Comments       Blanks
        ===============================================================================
         Batch                   1           18           11            1            6
         ...
        ===============================================================================
         Total                9604      1310038      1040844       180583        88611
        ===============================================================================
        """
        languages_data = {}
        total_files = 0
        total_code = 0
        lines = output.strip().split('\n')
        
        # 找到表头行（包含 "Language" 和 "Files"）
        header_index = -1
        for i, line in enumerate(lines):
            if 'Language' in line and 'Files' in line:
                header_index = i
                break
        
        if header_index == -1:
            raise ValueError("无法找到 tokei 输出表头")
        
        # 从表头下一行开始解析数据
        # 跳过分隔线（如果存在）
        start_index = header_index + 1
        if start_index < len(lines) and lines[start_index].strip().startswith('='):
            start_index += 1
        
        # 解析数据行，直到遇到 Total 行或分隔线
        for i in range(start_index, len(lines)):
            line = lines[i].strip()
            
            # 遇到分隔线，检查下一行是否是 Total
            if line.startswith('='):
                # 检查下一行是否是 Total 行
                if i + 1 < len(lines):
                    next_line = lines[i + 1].strip()
                    if next_line.startswith('Total'):
                        # 解析 Total 行
                        total_parts = next_line.split()
                        if len(total_parts) >= 5:
                            try:
                                total_files = int(total_parts[1])
                                total_code = int(total_parts[3])  # Code 是第4个字段（索引3）
                            except (ValueError, IndexError):
                                pass
                break
            
            # 遇到 Total 行，解析总计信息
            if line.startswith('Total'):
                total_parts = line.split()
                if len(total_parts) >= 5:
                    try:
                        total_files = int(total_parts[1])
                        total_code = int(total_parts[3])  # Code 是第4个字段（索引3）
                    except (ValueError, IndexError):
                        pass
                break
            
            # 跳过空行
            if not line:
                continue
            
            # 解析数据行
            # 格式：Language            Files        Lines         Code     Comments       Blanks
            # 使用固定宽度解析（tokei 输出是固定宽度的）
            parts = line.split()
            if len(parts) >= 3:
                # 语言名可能包含空格（如 "C Header"），需要特殊处理
                # 从右往左解析数字，剩余部分就是语言名
                try:
                    blanks = int(parts[-1])
                    comments = int(parts[-2])
                    code = int(parts[-3])
                    total_lines = int(parts[-4])
                    files = int(parts[-5])
                    # 剩余部分组合成语言名
                    language = ' '.join(parts[:-5])
                    
                    languages_data[language] = {
                        "files": files,
                        "lines": total_lines,
                        "code": code,
                    }
                except (ValueError, IndexError):
                    # 如果解析失败，跳过这一行
                    continue
        
        return {
            "languages": languages_data,
            "total": {
                "files": total_files,
                "code": total_code,
            }
        }
