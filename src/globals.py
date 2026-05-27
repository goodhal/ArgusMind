"""全局变量管理"""
from pathlib import Path

# 由 src.tmp_dir.init_tmp_dir / ensure_tmp_base 写入；请通过 get_tmp_base() 读取。
TMP_DIR: str | Path = ""