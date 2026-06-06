# SSRF 漏洞审计指南

## 漏洞定义

服务器端请求伪造（SSRF）攻击是指攻击者通过诱导服务器发起恶意请求，来访问内部系统或执行恶意操作。

## CWE 分类

- **CWE-918**: Server-Side Request Forgery

## 严重性评估

- **Critical**: 可访问内部服务、数据泄露
- **High**: 可扫描内部网络
- **Medium**: 需要特定条件才能利用

## 检测方法

### 1. 搜索危险函数

```python
# Python
"requests.get", "requests.post", "requests.request"
"urllib.urlopen", "urllib.request.urlopen"
"httpx.get", "httpx.post"
"subprocess", "socket"

# Java
"new URL", "HttpClient.newHttpClient"
"RestTemplate", "WebClient", "HTTPClient"

# Node.js
"fetch", "axios.get", "axios.post"
"http.request", "https.request"
"node-fetch"
```

### 2. 识别用户输入来源

```python
"request.args", "request.form", "request.GET", "request.POST"
"$_GET", "$_POST", "$_REQUEST"
"req.params", "req.query", "req.body"
"url", "uri", "link", "src", "href"
```

## 验证步骤

### 1. 确认 URL 构造方式

```python
# 危险示例
url = request.args.get('url')
response = requests.get(url)  # 可访问内网资源

# 安全示例
from urllib.parse import urlparse
url = request.args.get('url')
parsed = urlparse(url)

# 白名单验证
ALLOWED_SCHEMES = ['http', 'https']
ALLOWED_HOSTS = ['api.example.com']

if parsed.scheme not in ALLOWED_SCHEMES:
    raise ValueError("Invalid scheme")
if parsed.hostname not in ALLOWED_HOSTS:
    raise ValueError("Invalid host")
```

### 2. 检查防护措施

- **URL 验证**: scheme、hostname、port 白名单
- **DNS 重绑定防护**: 解析后再次验证 IP
- **禁止内网地址**: 验证 IP 不在私有范围

## 修复建议

### Python

```python
from urllib.parse import urlparse
import ipaddress

def validate_url(url):
    parsed = urlparse(url)
    
    # 方案验证
    if parsed.scheme not in ('http', 'https'):
        raise ValueError("Invalid scheme")
    
    # 解析 IP
    try:
        ip = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        raise ValueError("Invalid hostname")
    
    # 检查是否为私有地址
    if ip.is_private or ip.is_loopback or ip.is_reserved:
        raise ValueError("Access to internal networks is not allowed")
    
    return True

# 使用
validate_url(user_url)
response = requests.get(user_url, timeout=5)
```

### Java

```java
import java.net.*;

public class URLValidator {
    public static void validate(String urlString) throws MalformedURLException {
        URL url = new URL(urlString);
        InetAddress addr = InetAddress.getByName(url.getHost());
        
        if (addr.isSiteLocalAddress() || 
            addr.isLoopbackAddress() || 
            addr.isLinkLocalAddress()) {
            throw new SecurityException("Internal network access denied");
        }
    }
}
```

## 报告模板

```
#### [严重性] SSRF 漏洞

- **位置**: `file.py:123`
- **漏洞类型**: Server-Side Request Forgery
- **CWE**: CWE-918
- **描述**: 用户提供的 URL 未经验证直接发起请求
- **代码片段**: ...
- **修复建议**: 实现 URL 验证和白名单控制
```