# 命令注入漏洞审计指南

## 漏洞定义

命令注入是指攻击者通过在应用程序中注入恶意命令，来执行未授权的系统命令。

## CWE 分类

- **CWE-78**: OS Command Injection

## 严重性评估

- **Critical**: 可执行任意系统命令
- **High**: 可执行受限系统命令
- **Medium**: 需要特定条件才能利用

## 检测方法

### 1. 搜索危险函数

```python
# Python
"system", "popen", "subprocess", "exec", "spawn"
"os.system", "os.popen", "subprocess.call", "subprocess.run"
"commands.getoutput", "commands.getstatusoutput"

# Java
"Runtime.exec", "ProcessBuilder"

# JavaScript/Node.js
"child_process.exec", "child_process.execSync"
"eval", "new Function", "vm.runInContext"

# PHP
"system", "exec", "passthru", "shell_exec", "popen", "proc_open"
"eval", "assert", "preg_replace"  # 代码执行
```

### 2. 识别用户输入来源

```python
"request.args", "request.form", "req.body"
"$_GET", "$_POST", "$_REQUEST"
"process.argv", "process.env"
```

## 验证步骤

### 1. 确认命令构造方式

```python
# 危险示例
os.system("ping " + user_input)
subprocess.run(f"ping {user_input}", shell=True)

# 安全示例
subprocess.run(["ping", user_input])  # 参数列表，不会注入
```

### 2. 检查防护措施

- **参数列表**: 使用列表而非字符串
- **输入验证**: 白名单验证
- **转义**: 使用 shlex.quote() 转义

## 修复建议

### Python

```python
# 使用参数列表（推荐）
subprocess.run(["ping", user_input])

# 使用 shlex 转义
import shlex
subprocess.run(f"ping {shlex.quote(user_input)}", shell=True)
```

### Java

```java
// 使用数组而非字符串
String[] cmd = {"ping", userInput};
Runtime.getRuntime().exec(cmd);

// 避免 shell=true
```

## 报告模板

```
#### [严重性] 命令注入漏洞

- **位置**: `file.py:123`
- **漏洞类型**: OS Command Injection
- **CWE**: CWE-78
- **描述**: 用户输入直接拼接到系统命令中
- **代码片段**: ...
- **修复建议**: 使用参数列表而非字符串
```