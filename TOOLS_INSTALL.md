# ArgusMind 代码审计工具安装指南

## 一、工具清单

ArgusMind 代码审计使用以下外部工具，分为两个阶段：

### 【信息收集阶段工具】

| 工具 | 类型 | 用途 | 自动调用 | 自动安装 |
|------|------|------|----------|----------|
| **Tokei** | CLI | 代码语言统计（文件数、行数） | ✓ | ✗ |
| **Ripgrep** | CLI | 快速代码搜索工具 | ✓ | ✓ |
| **GitNexus** | CLI | 代码知识图谱（分析代码结构、调用关系） | ✓ | ✗ |
| **OpenCode** | CLI | AI 代码分析工具 | ✓ | ✗ |

### 【安全扫描阶段工具】

| 工具 | 类型 | 用途 | 自动调用 | 自动安装 |
|------|------|------|----------|----------|
| **Gitleaks** | CLI | 密钥和敏感信息检测 | ✓ | ✗ |
| **Bandit** | Python | Python 代码安全分析 | ✓ | ✗ |
| **Semgrep** | CLI | 多语言静态分析 | ✓ | ✗ |

> **说明**：Ripgrep 会在首次运行时自动下载，其他工具需要手动安装。

---

## 二、快速安装（推荐）

### 方式一：使用安装脚本（Windows）

```powershell
# 以管理员身份运行 PowerShell
cd e:\code\ArgusMind
.\install_tools.ps1
```

### 方式二：手动安装

#### 1. 安装 Tokei

**Windows：**
```powershell
choco install tokei -y
```

**macOS/Linux：**
```bash
brew install tokei
```

**验证安装：**
```bash
tokei --version
```

#### 2. 安装 Ripgrep

**Windows：**
```powershell
choco install ripgrep -y
```

**macOS/Linux：**
```bash
brew install ripgrep
```

**验证安装：**
```bash
rg --version
```

> **注意**：如果不手动安装，Ripgrep 会在首次运行时自动下载到 `~/.argusmind/tools/bin`

#### 3. 安装 GitNexus

```bash
# 使用 npm 安装（需要 Node.js >= 20.0.0）
npm install -g gitnexus --registry https://registry.npmmirror.com

# 或使用默认源
npm install -g gitnexus
```

**验证安装：**
```bash
gitnexus --version
```

#### 4. 安装 OpenCode

```bash
# 使用 npm 安装（需要 Node.js >= 20.0.0）
npm install -g opencode-ai --registry https://registry.npmmirror.com

# 或使用默认源
npm install -g opencode-ai
```

**验证安装：**
```bash
opencode --version
```

#### 5. 安装 Gitleaks

**Windows：**
```powershell
choco install gitleaks -y
```

**macOS/Linux：**
```bash
brew install gitleaks
```

**验证安装：**
```bash
gitleaks version
```

#### 6. 安装 Bandit

```bash
pip install bandit
```

**验证安装：**
```bash
bandit --version
```

#### 7. 安装 Semgrep

```bash
pip install semgrep
```

**验证安装：**
```bash
semgrep --version
```

---

## 三、工具详细说明

### 1. Tokei

**用途**：统计项目中各编程语言的文件数、代码行数、注释行数等

**调用位置**：`ProjectInfo.run()` - 信息收集阶段

**输出示例**：
```json
{
  "languages": {
    "Python": {"files": 42, "lines": 5120, "code": 4230},
    "TypeScript": {"files": 28, "lines": 3840, "code": 3120}
  },
  "total": {"files": 70, "code": 7350}
}
```

### 2. Ripgrep (rg)

**用途**：超快速的代码搜索工具，用于文件枚举和内容搜索

**调用位置**：`RipgrepFilesTool`、`RipgrepSearchTool`

**功能**：
- 文件枚举（`rg --files`）
- 正则表达式搜索（`rg --json`）
- 支持 `.gitignore` 过滤

**特点**：比 Python glob 快数十倍，适合大仓库

### 3. GitNexus

**用途**：代码知识图谱，分析代码结构和调用关系

**调用位置**：`GitNexusMcpBridge` - 通过 MCP 协议调用

**注册的工具**：
| 工具名 | 用途 |
|--------|------|
| `gitnexus_query` | 查询代码知识图谱 |
| `gitnexus_cypher` | 执行 Cypher 查询 |
| `gitnexus_context` | 获取符号上下文信息 |
| `gitnexus_impact` | 影响分析 |
| `gitnexus_symbol` | 符号定义查询 |

**使用前需要**：在目标仓库执行 `gitnexus analyze` 建立索引

### 4. OpenCode

**用途**：AI 驱动的代码分析工具

**调用位置**：`ProjectInfo.run()` - 信息收集阶段

**功能**：
- 生成项目级长文介绍
- 代码理解和分析
- 漏洞检测和修复建议
- 代码优化建议

### 5. Gitleaks

**用途**：检测代码库中的硬编码密钥、API 密钥、密码等敏感信息

**检测类型**：
- API 密钥（AWS、Google、Azure、GitHub 等）
- 密码和令牌
- 证书和私钥
- 配置文件中的敏感数据

**调用位置**：`ExternalToolService.scan_all()` - 安全扫描阶段

### 6. Bandit

**用途**：Python 代码安全漏洞扫描

**检测类型**：
| 类别 | 示例漏洞 |
|------|----------|
| 命令注入 | `subprocess.call(shell=True)` |
| SQL 注入 | 硬编码 SQL 查询 |
| 不安全反序列化 | `pickle.load()` |
| 弱加密 | MD5/SHA1 哈希 |
| 硬编码密码 | 密码明文存储 |
| 不安全随机数 | `random` 模块 |

**调用位置**：`ExternalToolService.scan_all()` - 安全扫描阶段

### 7. Semgrep

**用途**：多语言静态代码分析

**支持语言**：Python、JavaScript、TypeScript、Java、Go、C++、C#、PHP、Ruby、Rust 等

**检测类型**：
- SQL 注入
- XSS 跨站脚本
- 命令注入
- 路径遍历
- SSRF（服务端请求伪造）
- XXE（XML 外部实体注入）
- 不安全的反序列化

**调用位置**：`ExternalToolService.scan_all()` - 安全扫描阶段

---

## 四、工具配置

### 配置文件位置

1. **Semgrep 规则**：
   - 内置规则：自动使用 Semgrep 官方规则
   - 自定义规则：可在项目中添加 `.semgrep.yml` 文件

2. **GitNexus 配置**：
   - 环境变量：`GITNEXUS_MCP_ENABLED=true` 启用
   - 索引：首次使用前执行 `gitnexus analyze /path/to/project`

3. **OpenCode 配置**：
   - 通过数据库 `configs` 表配置
   - 配置项包括 API 地址、超时时间等

### 环境变量

```env
# GitNexus 配置
GITNEXUS_MCP_ENABLED=true
GITNEXUS_ANALYZE_TIMEOUT=3600

# OpenCode 配置
OPENCODE_API_URL=http://localhost:8080
OPENCODE_TIMEOUT=300

# Semgrep 配置
SEMGREP_RULES=https://semgrep.dev/p/r2c-security-audit

# Ripgrep 自动安装配置
ARGUSMIND_AUTO_INSTALL_RIPGREP=1
```

---

## 五、使用方式

### 自动调用

所有工具都会在代码审计过程中自动调用：

```bash
# 启动代码审计任务
curl -X POST http://localhost:6066/api/tasks \
  -H "Content-Type: application/json" \
  -d '{
    "project_id": "project-001",
    "project_name": "My Project",
    "project_path": "/path/to/project"
  }'
```

### 手动调用（调试用）

```bash
# Tokei 统计
tokei -C -s code /path/to/project

# Ripgrep 文件枚举
rg --files /path/to/project

# Ripgrep 搜索
rg --json "password" /path/to/project

# GitNexus 建立索引
gitnexus analyze /path/to/project

# Gitleaks 扫描
gitleaks detect --source /path/to/project --report-format json

# Bandit 扫描
bandit -r /path/to/project -f json -o bandit-report.json

# Semgrep 扫描
semgrep --json --output semgrep-report.json /path/to/project

# OpenCode 分析
opencode analyze /path/to/project --output opencode-report.json
```

---

## 六、常见问题

### Q1: GitNexus 安装失败

**原因**：网络问题或 Node.js 版本过低

**解决方案**：
```bash
# 检查 Node.js 版本
node --version  # 需要 >= 20.0.0

# 更新 Node.js
choco install nodejs-lts -y

# 使用国内源
npm install -g gitnexus --registry https://registry.npmmirror.com
```

### Q2: GitNexus 无法建立索引

**原因**：仓库不是 Git 仓库或权限不足

**解决方案**：
```bash
# 确保在 Git 仓库根目录
cd /path/to/project
git status

# 执行索引分析
gitnexus analyze .
```

### Q3: Ripgrep 下载失败

**原因**：网络问题或代理配置

**解决方案**：
```bash
# 手动安装
choco install ripgrep -y  # Windows
brew install ripgrep       # macOS
```

### Q4: OpenCode 安装失败

**原因**：Node.js 版本过低或网络问题

**解决方案**：
```bash
node --version  # 需要 >= 20.0.0
npm install -g opencode-ai --registry https://registry.npmmirror.com
```

### Q5: 工具未被自动调用

**原因**：工具未安装或未在 PATH 中

**解决方案**：
```bash
# 检查工具是否安装
tokei --version
rg --version
gitnexus --version
opencode --version
gitleaks version
bandit --version
semgrep --version

# 如果命令未找到，检查 PATH
echo $env:PATH
```

---

## 七、工具卸载

```bash
# Windows
choco uninstall tokei ripgrep gitleaks -y
pip uninstall bandit semgrep -y
npm uninstall -g gitnexus opencode-ai

# macOS/Linux
brew uninstall tokei ripgrep gitleaks
pip uninstall bandit semgrep -y
npm uninstall -g gitnexus opencode-ai
```

---

## 附录：工具版本要求

| 工具 | 最低版本 | 推荐版本 |
|------|----------|----------|
| Tokei | >= 12.0 | >= 12.1 |
| Ripgrep | >= 14.0 | >= 14.1 |
| GitNexus | >= 0.1 | >= 0.1.30 |
| OpenCode | >= 0.1 | >= 0.1.36 |
| Gitleaks | >= 8.0 | >= 8.18 |
| Bandit | >= 1.7 | >= 1.7.8 |
| Semgrep | >= 1.0 | >= 1.54 |
| Node.js | >= 20.0 | >= 20.10 |
| Python | >= 3.10 | >= 3.12 |