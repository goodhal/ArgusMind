# 认证/授权问题审计指南

## 漏洞定义

认证/授权问题包括身份验证缺陷、授权绕过、会话管理不当等，可能导致未授权访问。

## CWE 分类

- **CWE-287**: Improper Authentication
- **CWE-862**: Missing Authorization
- **CWE-306**: Missing Authentication for Critical Function
- **CWE-639**: Authorization Bypass Through User-Controlled Key

## 严重性评估

- **Critical**: 完全绕过认证或授权
- **High**: 部分绕过，可访问受限资源
- **Medium**: 需要特定条件才能利用

## 检测方法

### 1. 搜索认证相关代码

```python
# 认证检查
"login", "authenticate", "check_user"
"@login_required", "@auth", "@authenticated"
"is_authenticated", "current_user"
"session.get", "session['user']"

# 授权检查
"@permission_required", "@role_required"
"check_permission", "has_role", "is_admin"
"can_access", "authorize"
```

### 2. 识别敏感操作

```python
# 用户管理
"create_user", "delete_user", "update_user"
"change_password", "reset_password"
"grant_permission", "revoke_permission"

# 数据访问
"delete", "update", "create"
"GET", "POST", "PUT", "DELETE"  # HTTP 方法
```

## 验证步骤

### 1. 确认认证实现

```python
# 危险示例 - 缺少认证
@app.route('/admin/users')
def list_users():
    # 没有检查用户是否登录或是否有权限
    return render_template('users.html', users=get_all_users())

# 安全示例
@app.route('/admin/users')
@login_required
@permission_required('admin')
def list_users():
    return render_template('users.html', users=get_all_users())
```

### 2. 检查授权逻辑

```python
# 危险示例 - IDOR
@app.route('/user/<id>')
@login_required
def get_user(id):
    # 直接使用用户提供的 ID，没有验证所有权
    return User.get(id)

# 安全示例
@app.route('/user/<id>')
@login_required
def get_user(id):
    # 验证用户只能访问自己的数据
    if current_user.id != id and not current_user.is_admin:
        abort(403)
    return User.get(id)
```

### 3. 常见问题

- **缺少认证装饰器**: 敏感路由没有 @login_required
- **IDOR**: 使用用户控制的 ID 而不验证所有权
- **水平越权**: 用户可以访问同级用户的资源
- **垂直越权**: 低权限用户可以执行高权限操作
- **会话固定**: 登录后未更换会话 ID
- **弱密码策略**: 未强制要求强密码

## 修复建议

### 1. 强制认证

```python
# Flask-Login
from flask_login import login_required, current_user

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)
```

### 2. 权限检查

```python
# Flask-Principal 或 Flask-Authorize
from functools import wraps

def permission_required(permission):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.has_permission(permission):
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/admin')
@permission_required('admin')
def admin_panel():
    return render_template('admin.html')
```

### 3. IDOR 防护

```python
@app.route('/document/<doc_id>')
@login_required
def view_document(doc_id):
    doc = Document.get(doc_id)
    
    # 验证用户对文档的访问权限
    if not current_user.can_access(doc):
        abort(403)
    
    return render_template('document.html', doc=doc)
```

### 4. 会话管理

```python
# 登录后重新生成会话 ID
from flask_login import login_user, regenerate_on_idle

@app.route('/login', methods=['POST'])
def login():
    # 验证凭据
    user = authenticate(username, password)
    
    # 重新生成会话 ID
    login_user(user)
    session.regenerate()
    
    return redirect('/dashboard')
```

## 报告模板

```
#### [严重性] 认证/授权漏洞

- **位置**: `file.py:123`
- **漏洞类型**: [Missing Authentication / IDOR / Broken Access Control]
- **CWE**: CWE-XXX
- **描述**: 敏感操作缺少认证检查或授权验证
- **代码片段**: ...
- **修复建议**: 添加适当的认证和授权检查
```