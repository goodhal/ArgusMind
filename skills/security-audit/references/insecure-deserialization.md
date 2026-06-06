# 不安全反序列化漏洞审计指南

## 漏洞定义

不安全反序列化是指应用程序在反序列化用户提供的数据时，未进行充分验证，可能导致代码执行或拒绝服务攻击。

## CWE 分类

- **CWE-502**: Deserialization of Untrusted Data

## 严重性评估

- **Critical**: 可导致远程代码执行（RCE）
- **High**: 可导致代码执行或拒绝服务
- **Medium**: 需要特定 gadget 链才能利用

## 检测方法

### 1. 搜索危险函数

```python
# Python
"pickle.load", "pickle.loads"
"pickle.Unpickler"
"yaml.load"  # YAML 未使用 Loader
"jsonpickle.encode", "jsonpickle.decode"
"marshal.load", "marshal.loads"
"shelve", "dbm"
"dill.load", "dill.loads"

# Java
"ObjectInputStream", "readObject"
"XMLDecoder", "readObject"
"Yaml.load", "Yaml.loadAll"
"JSON.parseObject", "fastjson"

# PHP
"unserialize"
```

### 2. 识别用户输入来源

```python
"request.args", "request.form", "request.body"
"$_GET", "$_POST", "$_REQUEST"
"req.body", "req.data"
```

## 验证步骤

### 1. 确认反序列化来源

```python
# 危险示例
import pickle
import base64

data = request.args.get('data')
obj = pickle.loads(base64.b64decode(data))  # 用户提供的序列化数据

# 安全示例
import json
obj = json.loads(user_data)  # JSON 反序列化是安全的
```

### 2. 检查防护措施

- **使用 JSON**: 避免 pickle/YAML
- **完整性校验**: HMAC 签名
- **类型验证**: 反序列化后验证对象类型

## 修复建议

### Python

```python
# 使用 JSON（推荐）
import json

# 序列化
data = json.dumps(obj)

# 反序列化
obj = json.loads(user_data)

# 如果必须使用 pickle
import pickle
import hmac

# 添加签名验证
def secure_loads(data, key):
    signature, payload = data.split(b'|', 1)
    if not hmac.new(key, payload, 'sha256').hexdigest() == signature.decode():
        raise ValueError("Invalid signature")
    return pickle.loads(payload)
```

### Java

```java
// 使用 JSON 而非 Java 序列化
ObjectMapper mapper = new ObjectMapper();

// 如果必须使用 ObjectInputStream
public class TrustedObjectInputStream extends ObjectInputStream {
    private static final Set<String> ALLOWED_CLASSES = Set.of(
        "com.example.TrustedClass"
    );
    
    @Override
    protected Class<?> resolveClass(ObjectStreamClass desc) 
            throws IOException, ClassNotFoundException {
        if (!ALLOWED_CLASSES.contains(desc.getName())) {
            throw new InvalidClassException("Unauthorized class: " + desc.getName());
        }
        return super.resolveClass(desc);
    }
}
```

## 报告模板

```
#### [严重性] 不安全反序列化漏洞

- **位置**: `file.py:123`
- **漏洞类型**: Deserialization of Untrusted Data
- **CWE**: CWE-502
- **描述**: 使用 pickle 反序列化用户提供的未信任数据
- **代码片段**: ...
- **修复建议**: 使用 JSON 或添加完整性校验
```