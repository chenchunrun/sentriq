# Development Roadmap

**Version**: 1.1
**Last Updated**: 2026-03-08
**Project**: Security Alert Triage System

---

## 📊 Current Status Update (2026-03-08)

### Actual Repository State

- Core services, system tests, integration tests, and unit tests are currently green in the local workspace.
- Historical roadmap phases are no longer the active source of truth for day-to-day work; the repository is in stabilization and integration close-out mode.
- Recent work focused on:
  - fixing stale test failures and compatibility drift
  - normalizing UTC time handling across services, models, and tests
  - correcting threat intelligence aggregation scoring
  - cleaning deprecated test patterns and warning noise
  - restoring RabbitMQ-backed message queue integration coverage
  - enabling real local Temporal workflow execution with the Temporal CLI dev server
  - enforcing JWT/RBAC on core API gateway alert and analytics routes
  - aligning local default credentials and frontend auth flow with the current API gateway

### Latest Test Status

```bash
pytest -q tests -q
164 passed, 64 skipped in 19.25s
```

### Meaning Of The Current Skips

- External infrastructure not enabled locally (full service stack, API keys)
- Explicit environment-gated suites (`RUN_E2E_TESTS=true`)
- Remaining skips are primarily environment-gated rather than stale compatibility skips

### Local Integration Baseline

- Local Temporal development server verified with `temporal server start-dev`
- `workflow_engine` now connects to Temporal successfully when `TEMPORAL_ENABLED=true`
- Real workflow execution verified through Temporal and mirrored back into `workflow_executions`
- `api_gateway` now enforces JWT/RBAC on core alert and analytics routes
- Web dashboard auth flow was updated to use the API client for `/api/v1/auth/me`, avoiding cross-port origin drift during local development
- Web dashboard local dev flow was verified through the Vite server on `127.0.0.1:9000`
- End-to-end local UI/API smoke path is now verified for:
  - login through the frontend dev server proxy
  - alert creation through the frontend proxy path
  - alert listing through the frontend proxy path
  - dashboard metrics retrieval through the frontend proxy path
  - alert detail status transitions through the frontend proxy path
  - workflow execution listing and workflow start through the frontend proxy path
  - workflow step detail rendering from real execution output
- Local default credentials are now consistent across database seed, docs, and dashboard hints:
  - `admin / admin123`
  - `analyst / analyst123`

---

## 📊 Historical Project Status Overview

### ✅ Completed (Phase 1)

**Core Infrastructure**
- Docker Compose deployment (dev/production)
- PostgreSQL 15 + Redis + RabbitMQ + ChromaDB
- Web Dashboard (React + TypeScript)
- LLM multi-provider support (Zhipu AI, DeepSeek, Qwen, OpenAI)

**Microservices Architecture**
- 15 microservice skeletons created
- API Gateway (Kong)
- Alert Ingestor, Context Collector, Threat Intel Aggregator
- AI Triage Agent, LLM Router, Similarity Search
- Workflow Engine, Automation Orchestrator
- Notification Service, User Management, Reporting Service

**Feature Completion**

| Module | Status | Description |
|--------|--------|-------------|
| Alert Ingestion | ✅ Complete | REST API, Webhook support |
| Alert Normalization | ✅ Complete | Unified data model |
| AI Triage | ✅ Complete | Multi-LLM provider, intelligent routing |
| Web Dashboard | ✅ Complete | Alert list, details, settings page |
| Configuration Management | ✅ Complete | LLM API Key encrypted storage |
| Test Framework | ✅ Complete | 13 infrastructure tests passing |
| Documentation | ✅ Complete | Full architecture docs and deployment guides |

**Deployed Services (Development)**
```bash
# 8 core services
- PostgreSQL (5434)
- Redis (6381)
- RabbitMQ (5673, 15673)
- ChromaDB (8001)
- Alert Ingestor (8000)
- Web Dashboard (3000)
```

---

## 🎯 Development Roadmap

### Phase 2: Core Feature Enhancement (2-3 weeks)

---

#### 🔧 Week 1: Real Threat Intelligence Integration

| Priority | Task | Estimated Time |
|----------|------|----------------|
| **P0** | VirusTotal API integration | 1-2 days |
| **P0** | Abuse.ch API integration | 0.5-1 day |
| **P1** | OTX (AlienVault) integration | 1 day |
| **P1** | Threat intelligence caching | 0.5-1 day |
| **P1** | IOC query result aggregation | 1 day |

**Acceptance Criteria**:
- [ ] Can query real VirusTotal threat intelligence
- [ ] Can query Abuse.ch malicious IPs/domains
- [ ] Threat intelligence results cached in Redis
- [ ] Fallback strategy when API calls fail

**Implementation Files**:
- `services/threat_intel_aggregator/providers/virustotal.py`
- `services/threat_intel_aggregator/providers/abusech.py`
- `services/threat_intel_aggregator/providers/otx.py`
- `services/threat_intel_aggregator/cache.py`
- Update `config/config.yaml` with API endpoints

---

#### 🚀 Week 2: AI Triage Capability Enhancement

| Priority | Task | Estimated Time |
|----------|------|----------------|
| **P0** | Vector similarity search implementation | 2-3 days |
| **P0** | Historical alert vectorization | 1 day |
| **P0** | Similar alert recommendation logic | 1 day |
| **P1** | LangChain Agent optimization | 1 day |
| **P1** | Prompt engineering optimization | 0.5-1 day |

**Acceptance Criteria**:
- [ ] Can retrieve similar historical alerts
- [ ] AI triage references historical remediation
- [ ] Similarity search latency < 1 second
- [ ] Vector index correctly created and queried

**Implementation Files**:
- `services/similarity_search/vectorizer.py`
- `services/similarity_search/index.py`
- `services/similarity_search/retriever.py`
- `services/ai_triage_agent/prompts.py`
- ChromaDB collection setup and embeddings

---

#### 📊 Week 3: Workflow and Automation

| Priority | Task | Estimated Time |
|----------|------|----------------|
| **P1** | Temporal workflow integration | 2-3 days |
| **P1** | Automated response rule engine | 2 days |
| **P2** | SOAR Playbook examples | 1-2 days |
| **P2** | Multi-channel notification enhancement | 1 day |

**Acceptance Criteria**:
- [ ] Temporal workflows running normally
- [ ] Can configure automated response rules (e.g., block IP)
- [ ] Notifications support Email/DingTalk/WeChat
- [ ] Workflow status visualization

**Implementation Files**:
- `services/workflow_engine/temporal_workflows.py`
- `services/automation_engine/rules.py`
- `services/automation_engine/playbooks/`
- `services/notification_service/channels/`

---

### Phase 3: Production Ready (2-3 weeks)

---

#### 🏗️ Week 4-5: High Availability Deployment

| Priority | Task | Estimated Time |
|----------|------|----------------|
| **P0** | Kubernetes deployment manifests | 3-4 days |
| **P0** | PostgreSQL high availability config | 1-2 days |
| **P0** | Redis Cluster config | 1-2 days |
| **P1** | RabbitMQ cluster config | 1 day |
| **P1** | Helm Charts authoring | 2 days |

**Acceptance Criteria**:
- [ ] All services deploy via kubectl/helm
- [ ] PostgreSQL failover works
- [ ] Redis cluster stable
- [ ] RabbitMQ cluster stable
- [ ] Health checks configured

**Implementation Files**:
- `kubernetes/` directory structure
- `helm/security-triage/` chart
- PostgreSQL HA (Patroni/repmgr)
- Redis Cluster config
- RabbitMQ cluster config

---

#### 🔒 Week 6: Security and Monitoring

| Priority | Task | Estimated Time |
|----------|------|----------------|
| **P0** | JWT authentication complete implementation | 2 days |
| **P0** | RBAC permission control | 2 days |
| **P0** | Prometheus + Grafana | 1-2 days |
| **P0** | Log aggregation | 1-2 days |
| **P1** | Distributed tracing | 1-2 days |
| **P1** | Security hardening audit | 2 days |

**Acceptance Criteria**:
- [ ] JWT tokens work with refresh flow
- [ ] RBAC permissions enforced
- [ ] Metrics collected in Prometheus
- [ ] Logs aggregated in ELK/Loki
- [ ] Traces visible in Jaeger
- [ ] Security audit passed

**Implementation Files**:
- `services/user_management/auth.py`
- `services/api_gateway/middleware/auth.py`
- `monitoring/prometheus/` config
- `monitoring/grafana/` dashboards
- `monitoring/jaeger/` config
- Security checklist and hardening docs

---

### 📱 Parallel Development: Web Enhancement Features

| Feature | Description | Priority |
|---------|-------------|----------|
| **Alert Trend Charts** | Recharts time series visualization | P1 |
| **MITRE ATT&CK Mapping** | Tactics/techniques visualization | P1 |
| **Workflow Status Dashboard** | Temporal workflow visualization | P1 |
| **Batch Operations** | Batch assign/close alerts | P2 |
| **Export Function** | PDF/Excel report export | P2 |

**Implementation Files**:
- `services/web_dashboard/src/pages/Trends.tsx`
- `services/web_dashboard/src/pages/AttackMap.tsx`
- `services/web_dashboard/src/pages/Workflows.tsx`
- `services/web_dashboard/src/components/BatchActions.tsx`
- `services/web_dashboard/src/components/Export.tsx`

---

## 🎯 Recommended Next Steps

### Current Iteration (Recommended)

```
1. Run full local service-stack smoke tests with web dashboard + API gateway + workflow engine together
2. Continue extending RBAC coverage to remaining API gateway route groups
3. Start end-to-end local message-chain verification across live services
```

**Outcome**: Move the project from "tests pass in core and queue paths" to "stabilized local development workflow with minimal environment skips".

### Option A: Quick Core Value Validation (Recommended)

```
Week 1: Real threat intelligence integration (VirusTotal + Abuse.ch)
Week 2: Vector similarity search implementation
Week 3: AI triage optimization + prompt engineering
```

**Outcome**: After 3 weeks, demonstrate complete AI + threat intelligence + historical retrieval capabilities.

---

### Option B: User Experience Enhancement

```
Week 1: Web Dashboard enhancement (charts, dashboards)
Week 2: Workflow visualization
Week 3: Notifications and reports
```

**Outcome**: After 3 weeks, have complete visualization and management interface.

---

### Option C: Production Ready Priority

```
Week 1-2: Kubernetes deployment manifests
Week 3: Monitoring and logging
Week 4: Security hardening
```

**Outcome**: After 4 weeks, ready for production deployment.

---

## 📋 Task Tracking Template

When implementing each phase, use this template:

```markdown
### [Task Name]

**Status**: 🔲 Todo | 🔄 In Progress | ✅ Done
**Priority**: P0 | P1 | P2
**Assigned To**: [Name]
**Estimated Time**: X days
**Actual Time**: X days

**Description**:
- [ ] Subtask 1
- [ ] Subtask 2

**Implementation Files**:
- `path/to/file1.py`
- `path/to/file2.py`

**Testing**:
- [ ] Unit tests written
- [ ] Integration tests written
- [ ] Manual testing completed

**Notes**:
[Any challenges, decisions, or important information]
```

---

## 🔄 Sprint Planning

**Recommended Sprint Length**: 1 week
**Sprint Review**: Weekly demo and retrospective
**Sprint Planning**: Every Monday morning
**Daily Standup**: Async updates via issue comments

---

## 📈 Progress Tracking

## 2026-03-08 Local Integration Baseline

The current local development baseline is ahead of the original phased status in this document. These end-to-end flows are now verified against real running services:

- `Web Dashboard (9000) -> API Gateway (8000)` for login, alert create/list/detail, analytics dashboard, and alert status transitions
- `Web Dashboard (9000) -> Workflow Engine (8018)` for workflow listing, execution start, and step detail expansion
- `Web Dashboard (9000) -> Automation Orchestrator (9005)` for playbook list, execution start, execution detail, and automation config
- `Web Dashboard (9000) -> Configuration Service (9009)` for settings load, config group updates, reset-to-default, and per-user preferences persistence
- `Web Dashboard (9000) -> Reporting Service (9010)` for reports list, report generation, report status lookup, and download
- `Workflow Engine (8018) -> Temporal CLI dev server (7233)` for real workflow execution

Verified local service endpoints:

- Web Dashboard dev server: `http://127.0.0.1:9000`
- API Gateway: `http://127.0.0.1:8000`
- Workflow Engine: `http://127.0.0.1:8018`
- Automation Orchestrator: `http://127.0.0.1:9005`
- Configuration Service: `http://127.0.0.1:9009`
- Reporting Service: `http://127.0.0.1:9010`
- Temporal gRPC/UI: `127.0.0.1:7233` / `http://127.0.0.1:8233`

Latest manual smoke validations:

- `POST /api/v1/auth/login` returned valid JWTs for `admin/admin123`
- `GET /api/v1/alerts`, `PATCH /api/v1/alerts/{id}/status`, and `GET /api/v1/analytics/dashboard` all succeeded through the frontend proxy path
- `GET /api/v1/workflows/executions` and `GET /api/v1/playbooks` returned real execution/template data
- `POST /api/v1/playbooks/execute` produced completed playbook executions in mock mode
- `GET /api/v1/config/preferences` and `PUT /api/v1/config/preferences` persisted user settings successfully
- `PUT /api/v1/config/alerts` and `POST /api/v1/config/alerts/reset` worked through the frontend proxy path
- `POST /api/v1/reports/generate` produced completed reports against local data
- `GET /api/v1/reports/{id}/download?format=html` and `format=json` returned `200 OK` through the frontend proxy path

Current Progress: **Phase 1 Complete** (15%)
- [x] Phase 1: Infrastructure and Core Services
- [ ] Phase 2: Core Feature Enhancement (0%)
- [ ] Phase 3: Production Ready (0%)
- [ ] Phase 4: Advanced Features (Future)

**Overall Completion**: 15%

---

## 🚀 Quick Start Commands

```bash
# Start development environment
docker-compose -f docker-compose.simple.yml up -d

# Run tests
pytest tests/ -v

# Check service health
curl http://localhost:3000/api/v1/health

# View logs
docker-compose -f docker-compose.simple.yml logs -f
```

---

## 📚 Related Documentation

- [Architecture Overview](./01_architecture_overview.md)
- [Functional Requirements](./02_functional_requirements.md)
- [Components Inventory](./03_components_inventory.md)
- [Database Design](./04_database_design.md)
- [API Design](./05_api_design.md)
- [POC Implementation](./06_poc_implementation.md)
- [Development Standards](../standards/README.md)

---

**Next Review Date**: After Phase 2 completion
**Maintainer**: Development Team
