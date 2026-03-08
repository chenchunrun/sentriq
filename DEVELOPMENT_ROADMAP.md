# 开发规划 - 日志、配置、威胁建模

## 📍 当前配置位置

### 1. 日志配置

#### 位置：`services/shared/utils/logger.py`

**当前实现**：
```python
# 标准Python logging模块
- 支持结构化日志（JSON格式）
- 控制台输出（彩色）
- 文件轮转（100MB，30天保留）
- 日志级别：DEBUG, INFO, WARNING, ERROR, CRITICAL

# 使用方式
from shared.utils import get_logger
logger = get_logger(__name__)
logger.info("Message", extra={"key": "value"})  # 结构化日志
```

**配置文件**：`config/config.yaml`
```yaml
logging:
  level: INFO  # DEBUG|INFO|WARNING|ERROR|CRITICAL
  file: ./logs/triage.log
  rotation: 100 MB
  retention: 30 days
```

### 2. 环境变量配置

#### 配置文件层次

```
/Users/newmba/security/
├── config/config.yaml              # 主配置（推荐）
├── .env.production               # 生产环境
├── .env.docker.example           # Docker示例
├── services/web_dashboard/.env  # 前端配置
└── services/*/.env             # 各服务配置
```

#### 关键环境变量

| 变量名 | 说明 | 默认值 | 配置文件 |
|---------|------|----------|----------|
| `LLM_API_KEY` | LLM API密钥 | .env.production |
| `LLM_BASE_URL` | API基础URL | .env.production |
| `DATABASE_URL` | PostgreSQL连接 | .env.production |
| `REDIS_URL` | Redis连接 | .env.production |
| `RABBITMQ_URL` | 消息队列 | .env.production |
| `JWT_SECRET_KEY` | JWT密钥 | .env.production |
| `VITE_API_BASE_URL` | 前端API地址 | services/web_dashboard/.env |

### 3. 威胁建模

#### 位置：`services/shared/models/risk.py`

**当前实现**：
```python
# RiskAssessment 模型
class RiskAssessment(BaseModel):
    risk_score: float              # 0-100
    risk_level: RiskLevel         # CRITICAL|HIGH|MEDIUM|LOW|INFO
    confidence: float             # 0.0-1.0
    key_factors: list[str]        # 关键因素列表
    remediation_actions: list      # 建议操作

# 评分组件
- severity_score (30%): 告警严重程度
- threat_intel_score (30%): 威胁情报匹配
- asset_criticality_score (20%): 资产重要性
- exploitability_score (20%): 可利用性
```

#### 风险等级阈值

| 风险分数 | 风险等级 | 说明 |
|---------|---------|------|
| 90-100 | **CRITICAL** | 需要立即处理 |
| 70-89 | **HIGH** | 需要快速处理 |
| 40-69 | **MEDIUM** | 需要关注 |
| 20-39 | **LOW** | 常规监控 |
| 0-19 | **INFO** | 信息记录 |

## 📋 日志格式和解析配置

### 结构化日志格式

**当前实现**（`services/shared/utils/logger.py`）：
```python
def log_structured(level, message, extra):
    """Log structured message with extra fields"""
    logger = get_logger("structured")
    log_func(message, extra=extra)

# 使用示例
logger.info("Alert processed", extra={
    "alert_id": "ALT-001",
    "user": "admin",
    "action": "triage_complete",
    "processing_time_ms": 1234
})
```

**前端日志解析**：
```typescript
// services/web_dashboard/src/utils/formatters.ts
interface LogEntry {
    timestamp: string
    level: string
    message: string
    extra?: Record<string, any>
}

export const formatLogEntry = (entry: LogEntry): string => {
    const extra = entry.extra ? JSON.stringify(entry.extra, null, 2) : '';
    return `[${entry.timestamp}] [${entry.level}] ${entry.message}${extra}`;
}
```

### 日志级别配置

| 级别 | 使用场景 | 输出颜色 |
|------|----------|----------|
| DEBUG | 开发调试 | 灰色 |
| INFO | 一般信息 | 绿色 |
| WARNING | 警告信息 | 黄色 |
| ERROR | 错误信息 | 红色 |
| CRITICAL | 严重错误 | 加粗红色 |

### 实现位置

| 模块 | 文件位置 | 说明 |
|------|----------|----------|
| 日志工具 | `services/shared/utils/logger.py` | 统一日志配置 |
| 日志配置 | `config/config.yaml` | 日志级别、轮转策略 |
| 日志目录 | `logs/` | 所有服务日志统一存放 |
| 日志格式化 | `services/shared/utils/logger.py` | 结构化日志支持 |

## 🔍 威胁情报与建模

### 威胁建模实现

#### 1. 风险评分模型

**位置**：`services/shared/models/risk.py`

**核心类**：
- `RiskLevel`: 风险等级枚举
- `RiskAssessment`: 风险评估结果
- `TriageResult`: 告警分诊结果

**评分公式**：
```python
total_score = (
    (severity_score * 0.30) +      # 严重度 (30%)
    (threat_intel_score * 0.30) +   # 威胁情报 (30%)
    (asset_criticality_score * 0.20) + # 资产重要性 (20%)
    (exploitability_score * 0.20)      # 可利用性 (20%)
)
```

#### 2. 威胁情报源

**位置**：`services/threat_intel_aggregator/`

**当前配置**（`config/config.yaml`）：
```yaml
threat_intel:
  enabled_sources:
    - virustotal      # VirusTotal API
    - abouse_ch      # Abuse.ch URLhaus
    - isp            # 影响搜索引擎数据
    - custom         # 自定义威胁情报源

  cache_ttl: 3600  # 缓存1小时
  batch_size: 10      # 批量查询大小
```

**威胁情报数据模型**：
```python
class ThreatIntelQueryResult(BaseModel):
    ioc: str                  # 威胁指标（IP、域名、哈希等）
    ioc_type: str           # IO C类型（ip、domain、hash、url）
    aggregate_score: float   # 聚合威胁分数
    threat_level: str        # 威胁等级
    confidence: float        # 置信度
    detected_by_count: int  # 检测源数量
    total_sources: int      # 总源数
    sources: list           # 威胁源详情
    queried_at: str         # 查询时间
```

### 威胁建模增强建议

#### 短期可实现（1-2周）

**Phase 1: MITRE ATT&CK 映射**
- [ ] 创建 ATT&CK 战术到威胁类型的映射
- [ ] 在 RiskAssessment 中添加 `attack_technique` 字段
- [ ] 实现基于 TTP 的风险评分调整

**Phase 2: 威胁情报聚合增强**
- [ ] 实现多源情报聚合（VirusTotal + Abuse.ch + AlienVault）
- [ ] 添加 IOC 相似度计算（避免重复告警）
- [ ] 实现威胁情报缓存机制（Redis）

**Phase 3: 机器学习支持**
- [ ] 集成 TheHive 报告
- [ ] 实现历史告警的模式识别
- [ ] 基于历史数据训练风险预测模型

#### 长期优化方向（1-3个月）

**1. 行为分析（UEBA）**
- 用户行为基线建立
- 异常行为检测（横向移动、数据外传）
- 实体行为风险评估（UEBA评分）

**2. 威胁狩猎（Threat Hunting）**
- 失陷检测（Indicators of Compromise）
- APT 组织行为模式识别
- 0-day 漏洞利用检测

**3. 自动化响应编排**
- 基于 RiskLevel 的自动化 SOAR playbook
- 集成 Cortex/TheHive 等平台
- 实现隔离环境（sandbox）自动处置

## 📊 配置管理最佳实践

### 环境变量管理

#### 开发环境
```bash
# .env.local (不提交到git）
export LLM_API_KEY=sk-xxx
export LLM_BASE_URL=http://localhost:8000
export DATABASE_URL=postgresql+asyncpg://...
```

#### 生产环境
```bash
# .env.production
# 或从密钥管理系统注入
# 使用 Kubernetes secrets
# 使用 Vault (HashiCorp) 管理
```

#### 前端配置
```bash
# services/web_dashboard/.env
VITE_API_BASE_URL=  # 相对路径，自动指向当前host
# VITE_LOG_LEVEL=debug  # 开发时启用debug日志
```

### 日志解析和监控

#### 日志收集

**后端日志**：
- FastAPI/Uvicorn: 自动请求/响应日志
- 业务逻辑日志：使用 `logger.info()` 记录关键操作
- 结构化日志：使用 `extra={}` 传递上下文信息

**前端日志**：
- 浏览器 Console: 开发时启用
- 远程日志：集成 Sentry/Bugsnag
- 用户行为日志：页面访问、点击、操作

#### 日志分析

**实时日志解析**：
```python
# services/monitoring_metrics/main.py
class LogParser:
    def parse_error_logs(self, log_file: str) -> List[LogEntry]:
        """解析错误日志，识别常见问题"""
        # 使用正则表达式匹配：
        # - Database connection errors
        # - API timeout
        # - Authentication failures
        # - Threat intel API errors
```

### 安全配置检查清单

#### 部署前检查

- [ ] `.env` 文件中的密钥是否已更新
- [ ] `config/config.yaml` 中的敏感配置是否正确
- [ ] JWT_SECRET_KEY 是否使用强密钥（生产环境）
- [ ] 数据库密码是否已修改
- [ ] API密钥是否已轮换
- [ ] CORS 配置是否仅允许信任域名

#### 运行时监控

- [ ] 日志文件大小监控（防止磁盘占满）
- [ ] 错误日志聚合（集中到监控系统）
- [ ] API 响应时间监控（性能指标）
- [ ] 数据库连接池监控
- [ ] 威胁情报 API 调用限额监控

## 🎯 下一步开发重点

### 优先级 P0（核心功能）

1. **完善威胁建模**
   - [ ] 实现基于 ATT&CK 的风险评估
   - [ ] 集成更多威胁情报源
   - [ ] 实现威胁情报缓存机制

2. **日志分析增强**
   - [ ] 实现日志聚合和解析
   - [ ] 添加错误模式识别
   - [ ] 集成监控系统（Prometheus + Grafana）

3. **安全增强**
   - [ ] 实现 RBAC 权限细化
   - [ ] 添加审计日志功能
   - [ ] 实现密钥轮换机制

### 优先级 P1（重要功能）

1. **自动化响应编排**
   - [ ] 实现 SOAR playbook 执行引擎
   - [ ] 集成 Cortex/TheHive 平台
   - [ ] 实现自动化隔离环境

2. **威胁狩猎**
   - [ ] IOC 相似度计算
   - [ ] 历史告警模式识别
   - [ ] 0-day 漏洞利用检测

### 技术债务跟踪

| 项目 | 技术债务 | 优先级 |
|------|----------|--------|
| 日志格式不统一 | 中 | 统一日志格式 |
| 威胁建模简化 | 中 | 增强 ATT&CK 映射 |
| 环境配置混乱 | 高 | 使用统一的配置管理 |
| 缺少监控 | 中 | 集成可观测性工具 |

---

**创建时间**: 2026-02-10
**最后更新**: 根据 config/config.yaml、services/shared/models/risk.py、services/threat_intel_aggregator/
