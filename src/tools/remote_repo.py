"""远程仓库下载工具：支持从 ZIP URL 或 Git 仓库下载代码"""
import io
import os
import subprocess
import tempfile
import zipfile
from pathlib import Path
from typing import Optional

import requests

from src.tools.base import (
    ERROR_CODE_EXTERNAL,
    ERROR_CODE_INVALID_ARGUMENT,
    BaseTool,
    ToolResult,
)


class RemoteRepoTool(BaseTool):
    """从远程仓库下载代码并进行准备。支持 zip:URL 或 git:URL 格式。"""

    _parameters_schema = [
        {
            "name": "repository_url",
            "type": "string",
            "description": "远程仓库URL，支持格式: zip:https://example.com/repo.zip 或 git:https://github.com/user/repo.git",
            "required": True,
        },
        {
            "name": "branch",
            "type": "string",
            "description": "Git分支名 (仅用于git仓库)",
            "required": False,
        },
    ]

    @property
    def name(self) -> str:
        return "remote_code_audit"

    @property
    def description(self) -> str:
        return (
            "从远程仓库下载代码并进行自动化代码审计准备。"
            "支持格式: zip:https://example.com/repo.zip 或 git:https://github.com/user/repo.git"
        )

    def _download_zip(self, url: str, target_path: str) -> bool:
        """下载并解压 ZIP 文件"""
        try:
            response = requests.get(url, stream=True, timeout=120)
            response.raise_for_status()

            with zipfile.ZipFile(io.BytesIO(response.content)) as zf:
                zf.extractall(target_path)
            return True
        except Exception as e:
            self._last_error = str(e)
            return False

    def _clone_git(self, url: str, branch: str, target_path: str) -> bool:
        """克隆 Git 仓库"""
        try:
            args = ["git", "clone"]
            if branch:
                args.extend(["--branch", branch])
            args.extend([url, target_path])

            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=300,
                encoding="utf-8",
                errors="replace",
            )

            if result.returncode != 0:
                self._last_error = result.stderr or result.stdout
                return False
            return True
        except Exception as e:
            self._last_error = str(e)
            return False

    def run(self, repository_url: str = "", branch: str = "main", **kwargs) -> ToolResult:
        if not repository_url:
            return ToolResult(
                success=False,
                error="repository_url 参数是必需的",
                error_code=ERROR_CODE_INVALID_ARGUMENT,
            )

        # 解析 URL 格式
        parts = repository_url.split(":", 1)
        if len(parts) != 2:
            return ToolResult(
                success=False,
                error="远程仓库格式错误，应为 type:url（如 zip:https://xxx 或 git:https://xxx）",
                error_code=ERROR_CODE_INVALID_ARGUMENT,
            )

        repo_type, repo_url = parts[0].lower(), parts[1]

        # 创建临时目录
        temp_dir = tempfile.mkdtemp(prefix="argusmind_remote_")

        self._last_error = ""

        if repo_type == "zip":
            success = self._download_zip(repo_url, temp_dir)
        elif repo_type == "git":
            success = self._clone_git(repo_url, branch, temp_dir)
        else:
            return ToolResult(
                success=False,
                error=f"不支持的仓库类型: {repo_type}，仅支持 zip 或 git",
                error_code=ERROR_CODE_INVALID_ARGUMENT,
            )

        if not success:
            # 清理临时目录
            import shutil
            try:
                shutil.rmtree(temp_dir)
            except:
                pass
            return ToolResult(
                success=False,
                error=f"下载仓库失败: {self._last_error}",
                error_code=ERROR_CODE_EXTERNAL,
            )

        # 统计文件数量
        file_count = 0
        for root, dirs, files in os.walk(temp_dir):
            file_count += len(files)

        return ToolResult(
            success=True,
            data={
                "path": temp_dir,
                "repository_url": repository_url,
                "branch": branch if repo_type == "git" else None,
                "file_count": file_count,
            },
            meta={
                "temp_dir": temp_dir,
                "repo_type": repo_type,
            },
        )