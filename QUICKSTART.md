# Quick Start

This public repository now focuses on the prototype CLI path.

## Prerequisites

- Python 3.11+
- `pip`
- An LLM API key for Qwen, OpenAI, DeepSeek, or another OpenAI-compatible endpoint

## Setup

```bash
git clone https://github.com/chenchunrun/sentriq.git
cd sentriq
cp .env.example .env
pip install -r requirements.txt
```

Set these values in `.env`:

```bash
LLM_API_KEY=sk-your-key
LLM_BASE_URL=https://dashscope.aliyuncs.com/compatible-mode/v1
```

## Run

```bash
python main.py --sample
```

Other useful prototype commands:

```bash
python main.py --interactive
python main.py --file data/sample_alerts.json
```

## Output

The prototype writes logs and JSON results under `logs/`.

## Notes

- The active frontend source is under `services/web_dashboard/`.
- Multi-service deployment assets are kept local and are not part of this public repository.
