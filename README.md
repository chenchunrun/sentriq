# Sentriq

AI-powered security alert triage system.

## What's in This Repository

Two implemented codebases:

- **Prototype CLI** (`src/` + `main.py`) — single-node LangChain agent that collects context, queries threat intel (mocked), scores risk, and generates remediation for security alerts.
- **Microservices source** (`services/`) — the full platform: FastAPI services connected by RabbitMQ (ingestion, normalization, context/threat-intel enrichment, LLM routing, AI triage, similarity search, attack-chain analysis, workflow/automation, notifications, reporting, API gateway), a shared library (`services/shared/`), and a React dashboard (`services/web_dashboard/`).

Historical design docs, deployment assets (docker-compose, k8s/helm), the root-level test suites, helper scripts, and process reports are kept local and are not part of this public repository.

## Quick Start

```bash
git clone https://github.com/chenchunrun/sentriq.git
cd sentriq
cp .env.example .env
pip install -r requirements.txt
python main.py --sample
```

Useful commands:

```bash
python main.py --interactive
python main.py --file data/sample_alerts.json
```

## Output

- runtime logs: `logs/triage.log`
- result files: `logs/triage_result_*.json`

## Kept Public

- `README.md`
- `QUICKSTART.md`
- `CURRENT_STARTUP_GUIDE.md`
- `INSTALL_GUIDE.md`
- `CLAUDE.md`
- `docs/README.md`
- `services/web_dashboard/README.md`
