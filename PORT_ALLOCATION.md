# 端口分配规划

## 设计原则

1. **基础设施服务** (Docker): 1000-1999
2. **后端服务**: 8000-8999
3. **前端服务**: 3000-3999 (开发), 9000-9999 (生产)

## 具体分配

### 基础设施 (Docker Compose)

| 服务 | 内部端口 | 外部端口 | 说明 |
|------|----------|----------|------|
| PostgreSQL | 5432 | 5434 | 数据库 |
| Redis | 6379 | 6381 | 缓存 |
| RabbitMQ | 5672 | 5673 | 消息队列 |
| RabbitMQ UI | 15672 | 15673 | 管理界面 |
| ChromaDB | 8000 | 8001 | 向量数据库 |

### 后端服务 (Python/FastAPI)

| 服务 | 端口 | 说明 |
|------|------|------|
| API Gateway | 8000 | 主API入口 |
| Alert Ingestor | 8002 | 告警摄入 |
| AI Triage Agent | 8003 | AI分析 |
| Similarity Search | 8004 | 相似度搜索 |
| Context Collector | 8005 | 上下文收集 |
| Threat Intel | 8006 | 威胁情报 |
| Workflow Engine | 8007 | 工作流引擎 |
| Automation Orchestrator | 8008 | 自动化编排 |

### 前端服务

| 服务 | 开发端口 | 生产端口 | 说明 |
|------|----------|----------|------|
| Web Dashboard | 3000 | 9000 | Web界面 |
| 8010 (临时) | | | 当前使用 |

## 端口检查命令

```bash
# 检查端口占用
lsof -i :<port>

# 批量检查端口
for port in 8000 8002 8003 8004 8005 8006 8007 8008 9000; do
    echo -n "Port $port: "
    lsof -i :$port > /dev/null 2>&1 && echo "In use" || echo "Available"
done
```

## 避免冲突

1. ChromaDB Docker 使用 8001 (与后端服务分离)
2. Web Dashboard 生产环境使用 9000 (避免与ChromaDB冲突)
3. 所有服务启动前检查端口是否可用
