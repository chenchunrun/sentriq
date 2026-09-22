# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Sentriq is an AI-powered Security Alert Triage System. It uses LLM agents (any OpenAI-compatible API, including private MaaS such as DeepSeek-V3 and Qwen3) to analyze security alerts, enrich them with context and threat intelligence, score risk, and generate remediation recommendations.

This repository contains two implemented codebases:

1. **Prototype CLI** (`src/` + `main.py`) — a single-node LangChain agent with mocked data, ideal for understanding the AI triage workflow.
2. **Microservices source** (`services/`) — the full platform implementation: FastAPI services connected by RabbitMQ, PostgreSQL/Redis/ChromaDB storage, a React web dashboard, and Prometheus/Grafana monitoring configs. Deployment assets (docker-compose, k8s/helm, the root-level test suites) are kept local and are not part of this public repo.

## Essential Commands

### Prototype

```bash
# Setup
pip install -r requirements.txt
cp .env.example .env
# Edit .env with LLM_API_KEY and LLM_BASE_URL

# Run
python main.py --sample                        # Process 4 sample alerts
python main.py --interactive                   # Interactive mode
python main.py --file data/sample_alerts.json  # Batch processing
python main.py --alert '{...}'                 # Single alert JSON
```

### Service tests (in-repo)

```bash
pytest services/ai_triage_agent/tests/ -v
pytest services/shared/tests/ -v
# with PYTHONPATH pointing at services/:
PYTHONPATH=$PWD/services pytest services/alert_normalizer/tests/ -v
```

### Web dashboard frontend

```bash
cd services/web_dashboard
npm install
npm run dev    # Vite dev server; requires Node >=20 <25
npm run build
```

See `services/web_dashboard/README.md` for stack details (React 18 + TypeScript + Vite + Tailwind CSS).

## LLM Configuration

Supports any OpenAI-compatible API via `.env`:

```bash
# 通义千问 Qwen (recommended for China)
LLM_API_KEY=sk-your-qwen-key
LLM_BASE_URL=https://dashscope.aliyuncs.com/compatible-mode/v1

# OpenAI
LLM_API_KEY=sk-your-openai-key
LLM_BASE_URL=
```

Model selection in `config/config.yaml` (`llm.model`, e.g. `qwen-plus`). In the microservices stack, `services/llm_router/` routes between DeepSeek-V3 (complex analysis) and Qwen3 (fast analysis).

## Prototype Architecture

```
src/
├── agents/triage_agent.py           # SecurityAlertTriageAgent (LangChain)
├── tools/context_tools.py           # Network/Asset/User context (mocked)
├── tools/threat_intel_tools.py      # IOC queries, CVE checks (mocked)
├── tools/risk_assessment_tools.py   # Risk scoring, impact, containment
├── models/alert.py                  # SecurityAlert, TriageResult, RiskAssessment
└── utils/{config.py,logger.py}      # YAML config loader, Loguru logger
```

`SecurityAlertTriageAgent.process_alert()` executes:

```python
1. collect_context()         # Network/Asset/User context
2. query_threat_intel()      # IPs, hashes, URLs
3. assess_risk()             # Weighted calculation
4. generate_remediation()    # Priority-based actions
5. determine_human_review()  # Based on risk/confidence
```

Risk score (0-100) = severity (30%) + threat intel (30%) + asset criticality (20%) + exploitability (20%). Thresholds in `config/config.yaml`: Critical ≥90, High ≥70, Medium ≥40, Low ≥20, Info <20. Critical/High require human review. Results are written to `logs/triage_result_*.json`.

## Microservices Architecture (implemented in services/)

Processing pipeline (RabbitMQ-driven):

```
alert_ingestor → alert_normalizer → context_collector / threat_intel_aggregator
    → llm_router → ai_triage_agent
    → similarity_search (ChromaDB) / attack_chain_analyzer (MITRE ATT&CK)
    → workflow_engine (Temporal) → automation_orchestrator (SOAR) / notification_service
```

Key directories:

- `alert_ingestor/`, `alert_normalizer/` (Splunk/QRadar/CEF processors) — ingestion and normalization
- `context_collector/` (network/asset/user collectors), `threat_intel_aggregator/` (VirusTotal/OTX/Abuse.ch sources) — enrichment
- `llm_router/`, `ai_triage_agent/` (prompts, risk scoring), `similarity_search/`, `attack_chain_analyzer/` — AI analysis
- `workflow_engine/`, `automation_orchestrator/`, `notification_service/`, `reporting_service/`, `data_analytics/`, `configuration_service/`, `monitoring_metrics/` — orchestration and support
- `api_gateway/` — FastAPI gateway (alerts/analytics/auth routes)
- `web_dashboard/` — React frontend + FastAPI backend serving it
- `shared/` — shared library (models, database, messaging, auth); import as `shared.*`

Each service follows the same layout: `main.py` (FastAPI), `Dockerfile`, `requirements.txt`, plus pattern directories (`processors/`, `collectors/`, `sources/`) where applicable.

## Development Practices

- Use type hints for all function parameters and returns
- Async functions for all I/O operations (database, HTTP, message queues)
- Structured logging with `extra={}` for contextual data
- Google-style docstrings for all public functions
- Standard API response format: `{"success": true/false, "data": {...}, "meta": {...}}`
- Custom exceptions inherit from a base `SecurityTriageError`; never silently ignore exceptions

## Extending the System

- **New prototype tools**: create a function with the `@tool` decorator in `src/tools/`, register it in `SecurityAlertTriageAgent.__init__()`, call it in the workflow
- **Real integrations**: replace mocked implementations in `src/tools/` or the corresponding `services/*/sources|collectors/`; add API keys to `.env`
- **New alert types**: extend `AlertType` in `src/models/alert.py` (and `services/shared/models/` for the services side)
- **New services**: follow the existing `services/<name>/` pattern (main.py + Dockerfile + requirements.txt) and use `shared/` for models/messaging/DB access

## Troubleshooting

**ImportError**:
```bash
pip install -r requirements.txt --upgrade
```

**API Connection Errors**:
```bash
# Check .env configuration; ensure format LLM_API_KEY=sk-key (no quotes)
cat .env
```

**Module Not Found**:
```bash
# Run from the repository root
python main.py --sample
```

**Frontend build issues**: Node must be >=20 <25 (Vite 5 / Rollup 4 hang on newer Node versions). See `services/web_dashboard/README.md`.

---

**Last Updated**: 2026-09-22
**Project Status**: 🟢 Prototype complete | 🟢 Microservices implemented | Deployment assets and full test suites kept local
