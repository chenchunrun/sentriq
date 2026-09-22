# Copyright 2026 CCR <chenchunrun@gmail.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Evaluate base vs fine-tuned Laya on the security triage benchmark.

Two layers of metrics (requirement §33/§37):
1. Decision quality per question type: accuracy (choice/score), MAE +
   within-1-level (score), MAE + Brier (noul), plus overall ECE.
2. Routing metrics via the engine's replay: fast-path coverage, false close
   rate, malicious recall - the business KPI the fine-tune exists to move.

Usage:
    PYTHONPATH=services venv/bin/python services/triage_engine/finetune/evaluate.py \
        --model services/triage_engine/models/laya-security-v1
"""

import argparse
import json
import math
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import laya_mlx as laya_mlx

from triage_engine.core.registry import registry
from triage_engine.decision_models.laya import LayaDecisionProvider
from triage_engine.evaluation.replay import replay
from triage_engine.fast_path.triage import triage_fast


def load_agent(path_or_repo: str, subfolder=None):
    return laya_mlx.load(path_or_repo, subfolder=subfolder)


def question_metrics(agent, cases):
    per_type = {"choice": [], "score": [], "noul": []}
    bin_conf = [0.0] * 10
    bin_count = [0] * 10
    bin_correct = [0] * 10

    for case in cases:
        state = json.loads(case["state"])
        questions = json.loads(case["questions"])
        gold = json.loads(case["gold"])
        result = agent.predict(state, questions)
        for qid, q in questions.items():
            if qid not in gold:
                continue
            pred = result["answers"][qid]
            g = gold[qid]["probabilities"]
            if q["type"] == "choice":
                keys = list(q["criteria"].keys())
                pred_p = [pred["probabilities"].get(k, 0.0) for k in keys]
                pred_label = keys[max(range(len(keys)), key=lambda i: pred_p[i])]
                correct = pred_label == max(g, key=lambda k: g[k])
                conf = max(pred_p) / (sum(pred_p) or 1)
                per_type["choice"].append(correct)
            elif q["type"] == "score":
                levels = list(range(len(q["criteria"])))
                pred_exp = sum(l * pred["probabilities"].get(str(l), 0.0) for l in levels)
                gold_exp = sum(int(l) * p for l, p in g.items())
                mae = abs(pred_exp - gold_exp)
                per_type["score"].append((mae, mae <= 1.0))
                correct = mae <= 1.0
                conf = max(pred["probabilities"].values())
            else:  # noul
                p = pred.get("noul", pred.get("confidence", 0.5))
                gold_p = g.get("true", 0.5)
                per_type["noul"].append((abs(p - gold_p), (p - gold_p) ** 2))
                correct = abs(p - gold_p) <= 0.25
                conf = max(p, 1 - p)
            bin_i = min(9, int(conf * 10))
            bin_conf[bin_i] += conf
            bin_count[bin_i] += 1
            bin_correct[bin_i] += 1 if correct else 0

    total = sum(bin_count) or 1
    ece = sum(
        (n / total) * abs((c / n) - (s / n))
        for s, n, c in zip(bin_conf, bin_count, bin_correct) if n
    )
    metrics = {"ece": round(ece, 4)}
    ch = per_type["choice"]
    metrics["choice_accuracy"] = round(sum(ch) / len(ch), 4) if ch else None
    sc = per_type["score"]
    if sc:
        metrics["score_mae"] = round(sum(x[0] for x in sc) / len(sc), 3)
        metrics["score_within_1"] = round(sum(x[1] for x in sc) / len(sc), 4)
    no = per_type["noul"]
    if no:
        metrics["noul_mae"] = round(sum(x[0] for x in no) / len(no), 3)
        metrics["noul_brier"] = round(sum(x[1] for x in no) / len(no), 4)
    return metrics


async def routing_metrics(provider, cases, store):
    alerts = [case["_raw_alert"] for case in cases]
    labels = {
        case["_raw_alert"]["alert_id"]: (
            "benign" if json.loads(case["gold"])["malicious"]["probabilities"]["true"] < 0.2
            else "malicious"
        )
        for case in cases
    }
    run = await replay(alerts, labels=labels, provider=provider, store=store)
    return run["metrics"]


async def main_async(args):
    cases = [json.loads(line) for line in open(args.eval_data, encoding="utf-8")]
    report = {"cases": len(cases), "decisions": len(cases) * 8, "base_subfolder": args.base_subfolder}

    base = load_agent("convaiinnovations/laya", subfolder=args.base_subfolder)
    report["base"] = question_metrics(base, cases)
    del base

    ft = load_agent(args.model)
    report["fine_tuned"] = question_metrics(ft, cases)
    del ft

    # routing layer: base provider vs fine-tuned provider
    from triage_engine.core.store import Store

    checkpoint = args.checkpoint
    store = Store(":memory:")
    base_provider = LayaDecisionProvider(prewarm=False, checkpoint_override=checkpoint)
    base_provider._agents[checkpoint] = load_agent("convaiinnovations/laya", subfolder=args.base_subfolder)
    report["base"]["routing"] = await routing_metrics(base_provider, cases, store)

    ft_provider = LayaDecisionProvider(prewarm=False, checkpoint_override=checkpoint)
    ft_provider._agents[checkpoint] = load_agent(args.model)
    report["fine_tuned"]["routing"] = await routing_metrics(ft_provider, cases, store)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=1, ensure_ascii=False))
    print(json.dumps(report, indent=1, ensure_ascii=False))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", default=str(Path(__file__).resolve().parents[1] / "models" / "laya-security-v1"))
    parser.add_argument("--eval-data", default=str(Path(__file__).parent / "data" / "eval.jsonl"))
    parser.add_argument("--out", default="data/reports/laya_security_finetune_eval.json")
    parser.add_argument("--base-subfolder", default="typed-decisions",
                        help="base checkpoint to compare against (typed-decisions | multilingual)")
    parser.add_argument("--checkpoint", default="typed", choices=["typed", "multilingual"],
                        help="which checkpoint slot the fine-tuned model serves")
    args = parser.parse_args()
    import asyncio

    asyncio.run(main_async(args))
