# Sentriq

AI-powered security alert triage prototype.

## Public Scope

This public repository now focuses on:

- the prototype CLI under `src/`
- the current service source under `services/`
- the active frontend source under `services/web_dashboard/`

Historical design docs, deployment assets, helper scripts, and process reports are kept local only.

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
- `docs/README.md`
- `services/web_dashboard/README.md`
