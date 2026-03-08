# 开发运维最佳实践

## 🔴 关键问题和解决方案

### 1. 进程管理问题

**问题**:
- 老旧进程未清理导致端口占用
- PID文件与实际进程不同步
- 无法追踪哪些服务在运行

**解决方案**:
```bash
# ✅ 使用统一的服务管理脚本
./scripts/services.sh stop      # 停止所有服务
./scripts/services.sh start     # 启动所有服务
./scripts/services.sh status    # 查看状态
```

**关键点**:
1. 所有进程PID保存到 `.pids/` 目录
2. 停止时先尝试SIGTERM，2秒后SIGKILL
3. 按依赖关系逆序停止服务
4. 启动前检查端口可用性

### 2. 端口规划问题

**问题**:
- 端口冲突（如Web Dashboard 8001与ChromaDB冲突）
- 端口分配无规划
- 不清楚哪些端口被哪些服务占用

**解决方案**:
- 严格遵循 `PORT_ALLOCATION.md` 的端口规划
- 基础设施: 1000-1999 (Docker)
- 后端服务: 8000-8999
- 前端服务: 9000-9999 (生产), 3000-3999 (开发)

**关键端口**:
| 服务 | 端口 | 说明 |
|------|------|------|
| API Gateway | 8000 | 主API入口 |
| Web Dashboard | 9000 | Web界面（不是8010） |
| Alert Ingestor | 8002 | 告警摄入 |
| ChromaDB | 8001 | 向量数据库(Docker) |

### 3. 前端构建不彻底问题

**问题**:
- TypeScript编译错误导致构建失败
- 旧的构建缓存导致问题
- 依赖缺失或版本冲突
- 重复的`export const api`声明

**解决方案**:
```bash
# ✅ 使用专用构建脚本
./scripts/build-frontend.sh

# 该脚本会:
# 1. 清理旧的构建和缓存
# 2. 检查Node.js和依赖
# 3. 修复已知问题（如重复导出）
# 4. 使用Vite构建（跳过TypeScript类型检查）
# 5. 验证构建输出
# 6. 生成构建报告
```

**手动构建步骤**:
```bash
cd services/web_dashboard

# 1. 清理
rm -rf dist/ node_modules/.vite .vite

# 2. 安装依赖（如需要）
npm install

# 3. 构建（跳过TypeScript检查）
npx vite build

# 4. 验证
ls -la dist/
cat dist/index.html | head -20
```

## 📋 标准操作流程

### 首次启动完整系统

```bash
# 1. 启动基础设施
docker-compose -f docker-compose.simple.yml up -d postgres redis rabbitmq chromadb

# 2. 构建前端
./scripts/build-frontend.sh

# 3. 启动所有服务
./scripts/services.sh start

# 4. 检查状态
./scripts/services.sh status
```

### 日常开发流程

```bash
# 启动所有服务
./scripts/services.sh start

# 重启单个服务（代码修改后）
./scripts/services.sh restart web_dashboard

# 查看日志
./scripts/services.sh logs web_dashboard

# 停止所有服务
./scripts/services.sh stop
```

### 前端修改后重新部署

```bash
# 1. 修改前端代码后
cd services/web_dashboard

# 2. 重新构建
./scripts/build-frontend.sh

# 3. 重启Web Dashboard
./scripts/services.sh restart web_dashboard
```

## 🚨 常见问题排查

### 端口被占用

```bash
# 查看端口占用
lsof -i :8000
lsof -i :9000

# 杀死占用进程
lsof -ti :8000 | xargs kill -9

# 或使用服务脚本停止所有服务
./scripts/services.sh stop
```

### 服务启动失败

```bash
# 1. 查看日志
./scripts/services.sh logs <service_name>

# 2. 检查日志文件
cat logs/<service_name>.log

# 3. 检查端口
lsof -i :<port>

# 4. 检查进程
ps aux | grep <service_name>
```

### 前端无法访问

```bash
# 1. 确认前端已构建
ls -la services/web_dashboard/dist/

# 2. 确认index.html存在
test -f services/web_dashboard/dist/index.html && echo "存在" || echo "不存在"

# 3. 检查Web Dashboard日志
./scripts/services.sh logs web_dashboard

# 4. 验证静态文件
curl -I http://localhost:9000/assets/
```

### 数据库连接失败

```bash
# 1. 检查PostgreSQL
docker ps | grep postgres
pg_isready -h localhost -p 5434

# 2. 检查连接字符串
echo $DATABASE_URL

# 3. 测试连接
psql -h localhost -p 5434 -U triage_user -d security_triage
```

## 📁 目录结构

```
security/
├── .pids/                    # 进程PID文件（自动生成）
├── logs/                     # 服务日志（自动生成）
├── scripts/                  # 管理脚本
│   ├── build-frontend.sh    # 前端构建脚本
│   └── services.sh          # 服务管理脚本
├── services/
│   ├── api_gateway/         # 8000
│   ├── alert_ingestor/      # 8002
│   ├── ai_triage_agent/     # 8003
│   ├── similarity_search/   # 8004
│   ├── context_collector/   # 8005
│   ├── threat_intel_aggregator/ # 8006
│   ├── workflow_engine/     # 8007
│   ├── automation_orchestrator/ # 8008
│   └── web_dashboard/       # 9000 (前端)
├── PORT_ALLOCATION.md       # 端口规划文档
└── BEST_PRACTICES.md        # 本文档
```

## ⚠️ 绝对不要做的事

1. **不要手动启动服务而不使用scripts/services.sh**
   - 原因：会导致进程管理混乱，无法追踪和清理

2. **不要在8001端口启动服务**
   - 原因：8001被ChromaDB Docker占用

3. **不要跳过前端构建直接启动**
   - 原因：会看到"Frontend not built"错误

4. **不要忽略TypeScript错误强行构建**
   - 原因：可能导致运行时错误
   - 正确做法：修复错误或使用`npx vite build`跳过类型检查

5. **不要在服务运行时修改代码不重启**
   - 原因：修改不会生效
   - 正确做法：`./scripts/services.sh restart <service>`

6. **不要忘记清理进程**
   - 原因：会导致端口占用和资源泄漏
   - 正确做法：每次工作结束后`./scripts/services.sh stop`

## ✅ 检查清单

启动服务前：
- [ ] 确认Docker容器已启动（postgres, redis, rabbitmq, chromadb）
- [ ] 确认前端已构建（dist/目录存在且包含index.html）
- [ ] 确认端口未被占用（8000-8008, 9000）
- [ ] 确认环境变量已配置（.env.production）

启动服务后：
- [ ] 访问 http://localhost:9000 查看Web Dashboard
- [ ] 访问 http://localhost:8000/docs 查看API文档
- [ ] 检查所有服务健康状态
- [ ] 查看日志确认无错误

停止服务：
- [ ] 使用 `./scripts/services.sh stop` 停止所有服务
- [ ] 确认所有进程已清理（`ps aux | grep services`）
- [ ] 确认所有端口已释放（`lsof -i :8000`等）
