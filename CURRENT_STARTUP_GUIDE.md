# Current Startup Guide

This guide reflects the public repository as it exists now.

## Recommended Path

Use the prototype CLI:

```bash
pip install -r requirements.txt
cp .env.example .env
python main.py --sample
```

## Alternative Commands

```bash
python main.py --interactive
python main.py --file data/sample_alerts.json
```

## What Is Public

- Prototype source under `src/`
- Service source under `services/`
- Active frontend source under `services/web_dashboard/`

## What Is Local-Only

- Multi-service deployment assets
- Historical design and process documents
- Local helper scripts and test artifacts
