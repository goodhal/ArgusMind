# 错误处理文档模板

## 为什么需要错误处理文档

ArgusMind 作为 AI 驱动的代码审计系统，在审计过程中可能遇到各种错误和异常情况。清晰的错误处理文档可以帮助用户理解错误原因，并提供解决方案。

## 错误文档结构

每个错误文档应包含以下部分：

1. **错误标题**: 简短明确的错误名称
2. **为什么出现此错误**: 错误的根本原因
3. **如何修复**: 具体的解决方案
4. **可能的修复方式**: 多种解决方案（如果有）
5. **预防措施**: 如何避免此错误再次发生

## 错误文档模板

```markdown
# [错误名称]

## 为什么出现此错误

[详细描述错误出现的根本原因，包括技术细节和上下文]

## 如何修复

[提供最常见或最推荐的修复方法]

### 步骤 1: [第一步]
[详细说明]

### 步骤 2: [第二步]
[详细说明]

### 步骤 3: [验证]
[如何验证问题已解决]

## 可能的修复方式

### 方案 1: [方案名称]
- **适用场景**: [什么情况下使用此方案]
- **优点**: [此方案的优点]
- **缺点**: [此方案的缺点]
- **步骤**: [具体步骤]

### 方案 2: [方案名称]
[类似结构]

## 预防措施

- [如何避免此错误再次发生]
- [最佳实践建议]
- [配置建议]

## 相关错误

- [相关错误 1]: [链接]
- [相关错误 2]: [链接]

## 示例

### 错误示例
```
[错误代码或错误信息示例]
```

### 正确示例
```
[正确的代码或配置示例]
```
```

## ArgusMind 常见错误类型

### 1. 数据库连接错误

- Neo4j 连接失败
- PostgreSQL 连接失败
- 数据库认证错误

### 2. Agent 执行错误

- LLM API 调用失败
- 工具调用失败
- Agent 超时

### 3. 项目分析错误

- 项目路径不存在
- Git 仓库初始化失败
- 代码解析失败

### 4. 配置错误

- 配置文件缺失
- 配置项错误
- 环境变量缺失

## 错误严重性分类

- **Critical**: 系统无法继续运行，需要立即修复
- **High**: 主要功能受影响，但系统仍可运行
- **Medium**: 部分功能受影响，不影响核心功能
- **Low**: 警告信息，不影响功能使用

## 错误处理最佳实践

### 1. 结构化异常

使用 `src/api/exceptions.py` 中定义的结构化异常：

```python
from src.api.exceptions import (
    DatabaseConnectionError,
    AgentExecutionError,
    ConfigurationError,
    ProjectNotFoundError
)

# 使用示例
try:
    result = agent.run()
except AgentExecutionError as e:
    logger.error(f"Agent execution failed: {e}")
    raise
```

### 2. 事件总线记录

通过事件总线记录错误，而不是直接写日志：

```python
from src.core.event_bus import get_event_bus
from src.core.events import LogEvent

# 使用示例
bus = get_event_bus()
bus.publish(LogEvent(
    task_id=task_id,
    level="ERROR",
    message=f"Agent execution failed: {error}"
))
```

### 3. 用户友好错误消息

将技术错误转换为用户友好的消息：

```python
# 技术错误
"Neo4j connection failed: bolt://127.0.0.1:7687 - AuthenticationError"

# 用户友好消息
"无法连接到 Neo4j 数据库。请检查数据库是否运行，以及连接配置是否正确。"
```

### 4. 提供解决方案

错误消息应包含解决方案：

```python
# 错误消息 + 解决方案
"无法连接到 Neo4j 数据库。请检查：
1. Neo4j 服务是否运行（bolt://127.0.0.1:7687）
2. 用户名和密码是否正确
3. 网络连接是否正常

参考文档: errors/neo4j-connection-failed.md"
```

## 错误文档示例

### Neo4j 连接失败

```markdown
# Neo4j 连接失败

## 为什么出现此错误

Neo4j 数据库连接失败可能由以下原因导致：
1. Neo4j 服务未启动
2. 连接地址或端口错误
3. 用户名或密码错误
4. 网络连接问题
5. Neo4j 版本不兼容

## 如何修复

### 步骤 1: 检查 Neo4j 服务状态
```bash
# Linux/macOS
systemctl status neo4j
# 或
neo4j status

# Windows
# 检查 Neo4j 服务是否在运行
```

### 步骤 2: 验证连接配置
检查 `config.yaml` 中的 Neo4j 配置：
```yaml
neo4j:
  uri: bolt://127.0.0.1:7687
  user: neo4j
  password: YourNeo4jPassword123!
```

### 步骤 3: 测试连接
使用 Neo4j Browser 或 cypher-shell 测试连接：
```bash
cypher-shell -a bolt://127.0.0.1:7687 -u neo4j -p YourNeo4jPassword123!
```

## 可能的修复方式

### 方案 1: 启动 Neo4j 服务
- **适用场景**: Neo4j 服务未启动
- **步骤**:
  ```bash
  # Linux/macOS
  systemctl start neo4j
  # 或
  neo4j start

  # Windows
  # 通过 Neo4j Desktop 或服务管理器启动
  ```

### 方案 2: 更新连接配置
- **适用场景**: 配置错误
- **步骤**:
  1. 打开 `config.yaml`
  2. 更新 Neo4j 连接信息
  3. 重启 ArgusMind 后端

## 预防措施

- 使用 Docker Compose 确保 Neo4j 自动启动
- 定期检查 Neo4j 服务状态
- 使用健康检查端点监控连接状态
- 在配置文件中使用环境变量，避免硬编码密码

## 相关错误

- PostgreSQL 连接失败
- 数据库认证错误
```

## 错误文档维护

### 1. 定期更新

- 当发现新错误时，创建新的错误文档
- 当错误解决方案更新时，更新文档
- 定期审查错误文档的准确性

### 2. 版本控制

- 错误文档应与代码版本同步
- 使用 Git 管理错误文档变更
- 在 PR 中包含错误文档更新

### 3. 用户反馈

- 收集用户遇到的错误反馈
- 根据反馈更新错误文档
- 添加用户实际遇到的错误案例