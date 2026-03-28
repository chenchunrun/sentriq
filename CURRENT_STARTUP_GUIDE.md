# Current Startup Guide

This guide reflects the repository as it exists now, not the older "100% complete" claims.

## Recommended Paths

### Path A: Prototype CLI

Use this when you want the fastest, least fragile demo path.

```bash
pip install -r requirements.txt
cp .env.example .env
python main.py --sample
```

This uses the prototype under `src/` and is the most self-contained flow.

### Path B: POC Microservices

Use this when you want the current multi-service demo path.

```bash
cp .env.example .env
docker compose -f docker-compose.dev.yml up -d
```

Development mode starts these services:

- `postgres` on `5434`
- `redis` on `6381`
- `rabbitmq` on `5673` and `15673`
- `chromadb` on `8001`
- `alert-ingestor` on `9001`
- `alert-normalizer` on `9002`
- `context-collector` on `9003`
- `ai-triage-agent` on `9006`
- `web-dashboard` on `3000`

Notes:

- Dev mode does not currently start `threat-intel-aggregator` or `llm-router`.
- The POC path is valid, but some enrichment and AI behavior still falls back to mock logic.

### Path B1: Containerized Frontend Dev

Use this when you want to work on the active frontend without changing the host Node version.

```bash
docker run --rm -it \
  -p 3000:3000 \
  -v "$PWD/services/web_dashboard:/app" \
  -w /app \
  node:22.16.0-bookworm \
  bash -lc "npm ci && npm run dev -- --host 0.0.0.0 --port 3000"
```

### Path C: Full Compose

Use this only when you need the entire service graph.

```bash
cp .env.example .env
docker compose up -d
```

Production mode uses `docker-compose.yml` and exposes the dashboard on `3100`.

## What Is Actually Reliable Today

- The prototype CLI under `src/`
- The ingestion-to-triage POC path in dev mode
- Database initialization in full compose via `db-init`

## Known Gaps

- Some services still use mock mode by default, especially LLM and similarity features.
- The authoritative frontend is `services/web_dashboard/`.
- The old standalone frontend has been archived to `archived/web_dashboard_legacy/`.
- Some older docs still mention outdated ports or static dashboard flows.

## Verification

After startup, check:

```bash
docker compose -f docker-compose.dev.yml ps
```

For dev mode, open:

- Web dashboard: `http://localhost:3000`
- RabbitMQ UI: `http://localhost:15673`

For prod mode, open:

- Web dashboard: `http://localhost:3100`

## Recommended Next Cleanup

1. Keep one authoritative startup document.
2. Clean up any remaining references to the archived `archived/web_dashboard_legacy/` path.
3. Decide whether dev mode should also include `threat-intel-aggregator` and `llm-router`.
