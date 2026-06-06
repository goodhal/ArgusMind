# ArgusMind 安装指南

## 一、外部依赖清单

ArgusMind 项目依赖以下外部工具：

| 工具 | 版本要求 | 用途 |
|------|----------|------|
| **PostgreSQL** | >= 16 | 关系型数据库，存储任务、漏洞等结构化数据 |
| **Neo4j** | >= 5.20 | 图数据库，存储分析链路、代码依赖关系 |
| **Node.js** | >= 20.0.0 | 前端构建工具链 |
| **Python** | >= 3.10 | 后端运行环境 |

---

## 二、快速安装（推荐）

### 方式一：使用安装脚本（Windows）

```powershell
# 以管理员身份运行 PowerShell
cd e:\code\ArgusMind
.\install_deps.ps1
```

### 方式二：手动安装

#### 1. 安装 PostgreSQL

**Windows：**
```powershell
# 使用 Chocolatey
choco install postgresql16 -y --params "/Password:YourPgPassword123!"
```

**macOS：**
```bash
brew install postgresql@16
brew services start postgresql@16
```

**Linux：**
```bash
# Ubuntu/Debian
sudo apt update && sudo apt install -y postgresql-16
```

#### 2. 安装 Neo4j

**Windows：**
- 下载地址：https://neo4j.com/download-center/
- 选择 Community Edition 5.x

**macOS：**
```bash
brew install neo4j
brew services start neo4j
```

**Linux：**
```bash
# Ubuntu/Debian
wget -O - https://debian.neo4j.com/neotechnology.gpg.key | sudo apt-key add -
echo 'deb https://debian.neo4j.com stable 5' | sudo tee -a /etc/apt/sources.list.d/neo4j.list
sudo apt update && sudo apt install neo4j
```

#### 3. 安装 Node.js

```bash
# Windows
choco install nodejs-lts -y

# macOS/Linux
curl -fsSL https://fnm.vercel.app/install | bash
fnm use 20 --install
```

---

## 三、数据库配置

### 1. PostgreSQL 配置

```sql
-- 登录 PostgreSQL
psql -U postgres

-- 创建用户和数据库
CREATE USER argusmind WITH PASSWORD 'YourPgPassword123!';
CREATE DATABASE argusmind OWNER argusmind;
GRANT ALL PRIVILEGES ON DATABASE argusmind TO argusmind;
```

### 2. Neo4j 配置

```bash
# 设置初始密码
neo4j-admin dbms set-initial-password YourNeo4jPassword123!

# 启动 Neo4j
neo4j start

# 验证连接
# 浏览器访问: http://localhost:7474
# 用户名: neo4j
# 密码: YourNeo4jPassword123!
```

### 3. 创建环境变量文件

```bash
cp .env.example .env
```

编辑 `.env` 文件：

```env
# Neo4j
NEO4J_URI=bolt://127.0.0.1:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=YourNeo4jPassword123!

# PostgreSQL
POSTGRES_HOST=127.0.0.1
POSTGRES_PORT=5432
POSTGRES_DB=argusmind
POSTGRES_USER=argusmind
POSTGRES_PASSWORD=YourPgPassword123!

LOG_LEVEL=INFO
```

---

## 四、Python 环境配置

```bash
# 创建虚拟环境
python -m venv .venv

# 激活虚拟环境
# Windows
.venv\Scripts\activate

# macOS/Linux
source .venv/bin/activate

# 安装依赖
pip install -r requirements.txt
```

---

## 五、前端环境配置

```bash
cd frontend

# 安装依赖（首次运行）
npm install

# 或者使用 pnpm（推荐）
pnpm install
```

---

## 六、启动应用

### 方式一：使用启动脚本（推荐）

```powershell
# Windows
.\start.ps1
```

### 方式二：手动启动

**后端：**
```bash
cd e:\code\ArgusMind
.venv\Scripts\python.exe -m uvicorn src.api.app:create_app --factory --host 0.0.0.0 --port 6066 --reload
```

**前端：**
```bash
cd e:\code\ArgusMind\frontend
npm run start
```

---

## 七、验证服务

### 后端健康检查

```bash
curl http://127.0.0.1:6066/api/health
# 预期响应: {"success":true,"data":{"status":"ok"}}
```

### 前端访问

打开浏览器访问：http://localhost:8000

---

## 八、常见问题

### Q1: PostgreSQL 连接失败

**原因**：PostgreSQL 服务未启动或配置错误

**解决方案**：
```bash
# 检查服务状态
net start postgresql-x64-16

# 或者
services.msc  # 找到 PostgreSQL 服务并启动
```

### Q2: Neo4j 连接失败

**原因**：Neo4j 服务未启动或密码错误

**解决方案**：
```bash
# 启动 Neo4j
neo4j start

# 重置密码
neo4j-admin dbms set-initial-password YourNeo4jPassword123!
```

### Q3: 前端启动失败

**原因**：Node.js 版本过低或依赖未安装

**解决方案**：
```bash
# 检查 Node.js 版本
node --version  # 需要 >= 20.0.0

# 重新安装依赖
cd frontend
rm -rf node_modules package-lock.json
npm install
```

### Q4: Python 依赖安装失败

**原因**：缺少编译工具或网络问题

**解决方案**：
```bash
# 安装编译工具（Windows）
choco install visualstudio2022-buildtools -y

# 或使用预编译包
pip install psycopg2-binary
```

---

## 九、服务管理

### 启动服务

```bash
# PostgreSQL
net start postgresql-x64-16  # Windows
brew services start postgresql@16  # macOS
sudo systemctl start postgresql  # Linux

# Neo4j
neo4j start
```

### 停止服务

```bash
# PostgreSQL
net stop postgresql-x64-16  # Windows
brew services stop postgresql@16  # macOS
sudo systemctl stop postgresql  # Linux

# Neo4j
neo4j stop
```

---

## 十、卸载清理

```bash
# 停止服务
neo4j stop
net stop postgresql-x64-16

# 卸载（Windows）
choco uninstall postgresql16 -y
choco uninstall neo4j -y
choco uninstall nodejs-lts -y

# 删除数据目录
rm -rf C:\neo4j
rm -rf "C:\Program Files\PostgreSQL"
```

---

## 附录：默认配置汇总

| 服务 | 默认端口 | 默认用户名 | 默认密码 |
|------|----------|-----------|----------|
| PostgreSQL | 5432 | argusmind | YourPgPassword123! |
| Neo4j | 7687 (Bolt) | neo4j | YourNeo4jPassword123! |
| Neo4j Web | 7474 | neo4j | YourNeo4jPassword123! |
| Backend API | 6066 | - | - |
| Frontend | 8000 | - | - |