# XSS 漏洞审计指南

## 漏洞定义

跨站脚本（XSS）攻击是指攻击者在网页中注入恶意脚本代码，当其他用户浏览该网页时，恶意脚本会在用户浏览器中执行。

## CWE 分类

- **CWE-79**: Cross-site Scripting

## 严重性评估

- **Critical**: 可窃取会话 cookie、执行任意操作
- **High**: 可修改页面内容、钓鱼攻击
- **Medium**: 需要用户交互才能触发

## 检测方法

### 1. 搜索危险模式

```python
# 搜索未转义的用户输入输出
"innerHTML", "outerHTML", "document.write"
"v-html", "dangerouslySetInnerHTML"
"$html", "$('#output').html"
"echo", "print", "printf"  # PHP
"response.write"  # ASP.NET

# 搜索模板引擎
"{{", "{%", "render_template", "render"
"${", "${", "Thymeleaf", "FreeMarker"
```

### 2. 识别用户输入来源

```python
"request.args", "request.form", "request.GET", "request.POST"
"$_GET", "$_POST", "$_REQUEST"
"req.body", "req.query", "req.params"
```

## 验证步骤

### 1. 确认数据流

```python
# 危险示例 - Flask
@app.route('/hello')
def hello():
    name = request.args.get('name', '')
    return f'<h1>Hello {name}</h1>'  # 直接输出用户输入

# 安全示例 - Django
from django.utils.html import escape
return f'<h1>Hello {escape(name)}</h1>'
```

### 2. 检查防护措施

- **转义**: HTML 转义、URL 转义
- **内容安全策略**: CSP header
- **HTTPOnly**: Cookie 标记

## 修复建议

### 1. HTML 转义

```python
# Python
from django.utils.html import escape
from markupsafe import escape

# Jinja2
{{ user_input | escape }}

# React
{escape(user_input)}
```

### 2. 使用安全 API

```python
# React
return <div>{userInput}</div>  # 自动转义
# 避免
return <div dangerouslySetInnerHTML={{__html: userInput}} />
```

## 报告模板

```
#### [严重性] XSS 漏洞

- **位置**: `file.py:123`
- **漏洞类型**: Cross-site Scripting
- **CWE**: CWE-79
- **描述**: 用户输入未经转义直接输出到 HTML
- **代码片段**: ...
- **修复建议**: 使用转义函数
```