# 路径遍历漏洞审计指南

## 漏洞定义

路径遍历（Path Traversal）攻击是指攻击者通过构造特殊路径，访问应用服务器上本不应该访问的文件。

## CWE 分类

- **CWE-22**: Path Traversal

## 严重性评估

- **Critical**: 可读取系统敏感文件（密码文件、配置等）
- **High**: 可读取应用内部文件
- **Medium**: 需要特定条件才能利用

## 检测方法

### 1. 搜索危险函数

```python
# Python
"open", "file", "os.path.join", "pathlib.Path"
"send_file", "send_from_directory"
"file_get_contents", "readfile"  # PHP

# Java
"new File", "FileInputStream", "FileReader"
" Paths.get", "Path.resolve"

# Node.js
"fs.readFile", "fs.readFileSync", "fs.createReadStream"
"path.join", "path.resolve"
```

### 2. 识别用户输入来源

```python
"request.args", "request.form", "request.GET", "request.POST"
"$_GET", "$_POST", "$_REQUEST"
"req.params", "req.query"
```

## 验证步骤

### 1. 确认路径构造方式

```python
# 危险示例
filename = request.args.get('file')
with open(f"/uploads/{filename}", "r") as f:  # 可使用 ../../../etc/passwd
    content = f.read()

# 安全示例
from pathlib import Path
filename = request.args.get('file')
base = Path("/uploads").resolve()
filepath = (base / filename).resolve()
if not str(filepath).startswith(str(base)):
    raise ValueError("Invalid path")
```

### 2. 检查防护措施

- **路径规范化**: 使用 realpath 或 resolve
- **路径验证**: 确保路径在允许范围内
- **白名单**: 只允许特定文件名

## 修复建议

### Python

```python
from pathlib import Path
import os

def safe_read_file(base_dir, user_filename):
    base = Path(base_dir).resolve()
    filepath = (base / user_filename).resolve()
    
    # 确保文件在 base 目录内
    if not str(filepath).startswith(str(base)):
        raise ValueError("Access denied")
    
    return filepath.read_text()

# 使用
content = safe_read_file("/uploads", user_input)
```

### Node.js

```javascript
const path = require('path');
const fs = require('fs');

function safeReadFile(baseDir, userFilename) {
  const base = path.resolve(baseDir);
  const filepath = path.resolve(baseDir, userFilename);
  
  // 确保文件在 base 目录内
  if (!filepath.startsWith(base)) {
    throw new Error('Access denied');
  }
  
  return fs.readFileSync(filepath, 'utf8');
}
```

## 报告模板

```
#### [严重性] 路径遍历漏洞

- **位置**: `file.py:123`
- **漏洞类型**: Path Traversal
- **CWE**: CWE-22
- **描述**: 用户输入未经验证直接用于构造文件路径
- **代码片段**: ...
- **修复建议**: 使用路径规范化并验证路径在允许范围内
```