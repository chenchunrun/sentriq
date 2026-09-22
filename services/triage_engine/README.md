# Triage Engine - AI Security Triage Engine

双速（快/慢）安全告警分诊引擎：**System 1 快思考**（开源 [Laya](https://github.com/NandhaKishorM/laya) typed probabilistic decisions，本机通过 [laya-mlx](https://github.com/mizorewww/laya-mlx) 原生运行）+ **Security Decision Plane**（Hard Gate / Router / Policy）+ **System 2 慢思考**（假设驱动的 Investigation Agent）。

## 架构

```
Alert → Normalize(AlertContext) → State Compressor(确定性)
      → System 1: Laya 8 个 typed questions（noul/score/choice）
      → Hard Gate（9 类硬规则，命中即禁止 FAST_CLOSE）
      → Decision Router（5 路由 + reason codes）
      ├── FAST_CLOSE / FAST_QUEUE（快路径，低成本）
      ├── HUMAN_REVIEW（不确定或 provider 降级 → 人）
      └── DEEP_INVESTIGATE / URGENT_ESCALATE
            → System 2: Investigation Agent（只读工具 → Evidence → Hypothesis 更新 → Timeline）
            → Final Verdict（引用 Evidence ID，No Evidence → No Fact）
            → Policy Engine（AUTO / APPROVAL_REQUIRED / MANUAL / DENY）
```

核心不变式（需求 §49）：**模型给概率，证据立事实，Router 定流程，Policy 定权限，人保留最终控制权。**

## 运行

```bash
# 本机（macOS Apple Silicon，laya-mlx 原生 System 1）
cd services/triage_engine
python main.py                 # 0.0.0.0:8009

# 环境变量
LLM_API_KEY / LLM_BASE_URL / LLM_MODEL    # System 2 judge（OpenAI 兼容；未配置则规则裁决）
LAYA_RUNTIME=mlx|torch                     # System 1 运行时（默认 mlx）
TRIAGE_ENGINE_PROVIDER / TRIAGE_ENGINE_CONFIG / TRIAGE_ENGINE_DB
```

首次调用 Laya 会从 HuggingFace 下载权重（`convaiinnovations/laya`，约 800MB）到本地缓存；下载失败或权重缺失时按 §41 自动回退 RuleProvider（决策标记 `degraded`，路由到 HUMAN_REVIEW，绝不自动关闭）。

> **校准提示**：Laya base checkpoint 在 typed-decisions 上 zero-shot 接近随机，安全 8 问题的真实效果依赖后续安全语料微调（官方提供 fine-tune notebook）。上线前务必走 Replay + Shadow Mode（`POST /api/v1/replay`）验证，False Close Rate 是核心红线指标。

## API

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/v1/triage` | 完整快路径（`run_slow: true` 时慢路径联动） |
| POST | `/api/v1/decision`、`/decision/v1/system-one` | 统一快决策接口（§30，调用方无感知 Laya/Jev） |
| POST | `/api/v1/investigations` | 发起深度调查 |
| GET | `/api/v1/investigations/{id}`、`/api/v1/cases/{id}` | 案例/调查详情 |
| POST | `/api/v1/replay` | 批量回放 + Shadow 评估（≤1000 条，含 False Close Rate 等指标） |
| POST | `/api/v1/feedback` | 人工反馈（agree/override/…，用于阈值与校准优化） |
| POST | `/api/v1/policy/evaluate` | 动作策略判定 |
| GET | `/health` | 健康检查（provider/LLM 可用性、版本号） |

## 结构

```
config/engine.yaml      决策问题注册表 + 阈值注册表 + 策略白名单（单一事实来源，禁止硬编码阈值）
core/                   context / compressor / gate / router / policy / evidence / timeline / store(SQLite)
decision_models/        base(Provider 抽象) / laya(原生 mlx|torch) / rule(确定性+回退) / jev(预留) / ensemble(分歧检测)
fast_path/              快路径编排
slow_path/              state / planner / evaluator / judge / investigator / tool_gateway / 13 个只读工具
evaluation/             replay + shadow
tests/                  42 个单元/接口测试（不依赖权重与网络）
```

## 测试

```bash
PYTHONPATH=services venv/bin/python -m pytest services/triage_engine/tests -q
```

## 依赖说明

- `laya-mlx` 已装入仓库 venv（Apple Silicon 7–14ms/问）；它把 `tokenizers` 升到 0.23.2，与 chromadb 0.5.23 的 `<=0.20.3` 约束冲突（当前实测 import 共存无问题，若 similarity_search 受影响需单独 venv 隔离）。
- Docker（Linux）内不装 mlx：快模型自动回退 RuleProvider，System 2 judge 走 OpenAI 兼容接口。
