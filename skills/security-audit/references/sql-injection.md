# SQL 注入漏洞审计指南

## 漏洞定义

SQL 注入是一种代码注入技术，攻击者通过在应用程序的 SQL 查询中插入恶意 SQL 代码，来操纵数据库执行非预期的操作。

## CWE 分类

- **CWE-89**: SQL Injection

## 严重性评估

- **Critical**: 可读取/修改/删除任意数据，绕过认证
- **High**: 可读取敏感数据，影响业务逻辑
- **Medium**: 有限的数据访问，需要特定条件
- **Low**: 需要复杂条件才能利用

## 检测方法

### 1. 搜索危险模式

使用 `ripgrep_search` 搜索以下模式：

```python
# Python
"execute", "executemany", "raw", "RawSQL"
"cursor.execute", "connection.execute"
"SELECT", "INSERT", "UPDATE", "DELETE", "WHERE"
"format", "f\"", "f'", "%s", "+"

# Java
"executeQuery", "executeUpdate", "prepareStatement"
"createQuery", "createNativeQuery"
"String.format", "+"

# PHP
"mysql_query", "mysqli_query", "PDO::query"
"execute", "prepare"
"sprintf", "$sql .= ", "$query .= "
```

### 2. 识别用户输入来源

使用 `code_search` 查找：

```python
# HTTP 参数
"request.args", "request.form", "request.GET", "request.POST"
"$_GET", "$_POST", "$_REQUEST", "input"

# 用户可控变量
"user_input", "user_data", "param", "id", "name"
```

### 3. 分析数据流

追踪用户输入到 SQL 查询的路径：

1. 识别输入点（HTTP 参数、文件读取、数据库查询结果）
2. 追踪变量传递（函数调用、赋值、拼接）
3. 确认是否到达 SQL 执行点

## 验证步骤

### 1. 确认 SQL 查询构造方式

```python
# 危险示例
cursor.execute("SELECT * FROM users WHERE id = " + user_id)
cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")
cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)

# 安全示例
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
cursor.execute("SELECT * FROM users WHERE name = :name", {"name": name})
```

### 2. 检查防护措施

- **参数化查询**: 使用 `?`、`:param` 或 `%s` 占位符
- **ORM**: 使用 Django ORM、SQLAlchemy 等
- **输入验证**: 类型检查、长度限制、白名单
- **转义函数**: `escape_string`、`quote_ident` 等

### 3. 验证防护有效性

```python
# 无效防护示例
# 只过滤空格，可使用 /**/ 绕过
user_id = user_id.replace(" ", "")
cursor.execute("SELECT * FROM users WHERE id = " + user_id)

# 有效防护示例
# 参数化查询，完全隔离数据和代码
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
```

## 常见绕过技术

### 1. 注释绕过

```sql
-- 使用注释替代空格
SELECT/**/*/**/FROM/**/users/**/WHERE/**/id/**/=/**/1

-- 使用注释截断后续代码
SELECT * FROM users WHERE id = 1 -- AND status = 'active'
```

### 2. 编码绕过

```sql
-- URL 编码
SELECT * FROM users WHERE name = '%27%20OR%20%271%27=%271'

-- Unicode 编码
SELECT * FROM users WHERE name = '' OR '1'='1'
```

### 3. 函数绕过

```sql
-- 使用字符串函数
SELECT * FROM users WHERE name = CHAR(39) OR CHAR(49)=CHAR(49)

-- 使用 CONCAT
SELECT * FROM users WHERE name = CONCAT('\'', ' OR \'1\'=\'1')
```

## 修复建议

### 1. 使用参数化查询（推荐）

```python
# Python
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))

# Java
PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
stmt.setInt(1, userId);

# PHP
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$user_id]);
```

### 2. 使用 ORM

```python
# Django
User.objects.filter(id=user_id)

# SQLAlchemy
session.query(User).filter(User.id == user_id).first()
```

### 3. 输入验证

```python
# 类型验证
if not isinstance(user_id, int):
    raise ValueError("Invalid user ID")

# 范围验证
if user_id < 1 or user_id > 1000000:
    raise ValueError("User ID out of range")
```

## 测试验证

### 1. 手动测试

```sql
-- 测试注入点
' OR '1'='1
" OR "1"="1
1 OR 1=1
'; DROP TABLE users; --
```

### 2. 自动化测试

使用工具：
- **SQLMap**: 自动化 SQL 注入检测
- **Burp Suite**: Web 应用扫描
- **OWASP ZAP**: 开源安全扫描器

## 报告模板

```
#### [严重性] SQL 注入漏洞

- **位置**: `file.py:123`
- **漏洞类型**: SQL Injection
- **CWE**: CWE-89
- **描述**: 用户输入 `user_id` 直接拼接到 SQL 查询中，未使用参数化查询
- **代码片段**:
```python
cursor.execute("SELECT * FROM users WHERE id = " + user_id)
```
- **攻击示例**:
```python
user_id = "1 OR 1=1"
# 执行: SELECT * FROM users WHERE id = 1 OR 1=1
```
- **修复建议**: 使用参数化查询
```python
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
```
- **严重程度**: Critical
```