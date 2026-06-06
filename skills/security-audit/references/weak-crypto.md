# 弱加密漏洞审计指南

## 漏洞定义

弱加密漏洞是指使用了不安全的加密算法、密钥长度不足、或加密实现存在缺陷，可能导致数据泄露或密码破解。

## CWE 分类

- **CWE-327**: Use of Weak Cryptographic Primitive
- **CWE-328**: Use of Weak Hash
- **CWE-331**: Insufficient Entropy

## 严重性评估

- **Critical**: 使用已知不安全的算法（MD5、SHA1 等）
- **High**: 密钥长度不足
- **Medium**: 加密实现存在缺陷

## 检测方法

### 1. 搜索危险算法

```python
# 弱哈希算法
"md5", "MD5", "hashlib.md5"
"sha1", "SHA1", "hashlib.sha1"
"hashlib.new('md5')", "hashlib.new('sha1')"

# 弱加密算法
"des", "DES", "Cryptodome.Cipher.DES"
"rc4", "RC4", "ARC4"
"blowfish", "Blowfish"
"xor", "XOR"

# 弱随机数生成
"random.random", "random.randint"  # 用于安全目的
"Math.random"  # JavaScript

# 硬编码密钥
"password", "secret", "key", "token"
"PRIVATE_KEY", "ENCRYPTION_KEY"
```

### 2. 检查密钥长度

```python
# 不足的密钥长度
"AES-128"  # 128 位（最小要求）
"RSA-1024"  # 1024 位（不安全）

# 推荐的密钥长度
"AES-256"  # 256 位
"RSA-2048"  # 2048 位或更高
```

## 验证步骤

### 1. 确认加密用途

```python
# 密码存储
# 危险 - MD5
import hashlib
hashed = hashlib.md5(password.encode()).hexdigest()

# 安全 - bcrypt
import bcrypt
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

# 数据加密
# 危险 - 使用 hashlib.md5 作为密钥派生
key = hashlib.md5(password.encode()).digest()  # 不安全

# 安全 - 使用 PBKDF2 或 Argon2
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
key = kdf.derive(password.encode())
```

### 2. 检查加密实现

- **哈希算法**: 使用 SHA-256 或更强
- **密码存储**: 使用 bcrypt、Argon2、PBKDF2
- **密钥长度**: AES-256、RSA-2048+
- **随机数**: 使用 crypto.random_bytes

## 修复建议

### 密码哈希

```python
# Python - bcrypt（推荐）
import bcrypt

# 哈希密码
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

# 验证密码
bcrypt.checkpw(password.encode(), hashed)

# Python - argon2-cffi（推荐）
from argon2 import PasswordHasher
ph = PasswordHasher()
hashed = ph.hash(password)
ph.verify(hashed, password)
```

### 对称加密

```python
# Python - 使用 cryptography 库
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

# AES-256-GCM（推荐）
key = os.urandom(32)  # 256 位
iv = os.urandom(12)   # 96 位（GCM 推荐）
cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
encryptor = cipher.encryptor()
ciphertext = encryptor.update(data) + encryptor.finalize()
```

### 非对称加密

```python
# Python - RSA
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# 生成 RSA-2048 或更高（推荐 RSA-4096）
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=4096,  # 使用 2048 位或更高
)
```

## 报告模板

```
#### [严重性] 弱加密漏洞

- **位置**: `file.py:123`
- **漏洞类型**: Use of Weak Cryptographic Algorithm
- **CWE**: CWE-327 / CWE-328
- **描述**: 使用不安全的 MD5 哈希算法
- **代码片段**: ...
- **修复建议**: 使用 bcrypt 或 Argon2 进行密码哈希
```