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

"""Threshold sweep for FAST_CLOSE bars on shadow data (requirement §32/§33).

Sweeps (authorized_min x malicious_max x require_similar_history) through the
real routing plane over the held-out eval set, keeping every other threshold
at default. Safety constraint: false_close_rate must stay 0 - a threshold that
closes a single truly-malicious alert is disqualified regardless of coverage.

``run_route_sweep`` runs the decision pipeline ONCE per alert (thresholds
never change model answers, only routing) and then re-evaluates the pure
``router.route()`` per grid combination - a full 30-combo sweep costs one
model pass instead of thirty. recalibrate.py reuses it.
"""

import asyncio
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from triage_engine.core.registry import registry  # noqa: E402

DEFAULT_GRID: List[Tuple[float, float, bool]] = [
    (auth_min, mal_max, need_history)
    for auth_min in (0.95, 0.90, 0.85, 0.80, 0.75)
    for mal_max in (0.10, 0.15, 0.20)
    for need_history in (True, False)
]


async def run_route_sweep(
    alerts: List[Dict[str, Any]],
    labels: Dict[str, str],
    provider=None,
    grid: Optional[Sequence[Tuple[float, float, bool]]] = None,
) -> List[Dict[str, Any]]:
    """One decision pass per alert, then pure router sweeps per combo.

    Returns rows of ``{authorized_min, malicious_max, require_similar_history,
    fast_close, fast_queue, fast_path_coverage, false_close_rate}``.
    """
    from triage_engine.core import gate as gate_mod
    from triage_engine.core import router as router_mod
    from triage_engine.core.compressor import compress
    from triage_engine.core.context import AlertContext
    from triage_engine.decision_models import decide_with_fallback
    from triage_engine.decision_models.base import DecisionContext
    from triage_engine.evaluation.replay import metrics_from_results

    base_fc = registry.thresholds("fast_close")
    prepared = []
    for raw in alerts:
        state = compress(AlertContext.build(raw), raw)
        state_dict = state.model_dump()
        decision = await decide_with_fallback(
            state_dict, registry.questions,
            DecisionContext(
                alert_id=state.alert_id,
                state_text=raw.get("state_text_override") or state.to_text(),
                question_version=registry.question_version,
            ),
            provider,
        )
        gates = gate_mod.evaluate_hard_gates(state_dict)
        prepared.append((state.alert_id, decision, gates, state_dict))

    results = []
    for auth_min, mal_max, need_history in (grid or DEFAULT_GRID):
        th = {"fast_close": {**base_fc, "authorized_min": auth_min,
                             "malicious_max": mal_max,
                             "require_similar_history": need_history}}
        rows = [
            {
                "alert_id": alert_id,
                "route": router_mod.route(decision, gates, state_dict, thresholds=th).route,
                "malicious": decision.decisions.get("malicious", 0.0),
                "truth": labels.get(alert_id),
                "latency_ms": 0.0,
                "degraded": decision.degraded,
            }
            for alert_id, decision, gates, state_dict in prepared
        ]
        m = metrics_from_results(rows, latencies=[0.0] * len(rows))
        results.append({
            "authorized_min": auth_min, "malicious_max": mal_max,
            "require_similar_history": need_history,
            "fast_close": m["route_distribution"].get("FAST_CLOSE", 0),
            "fast_queue": m["route_distribution"].get("FAST_QUEUE", 0),
            "fast_path_coverage": m["fast_path_coverage"],
            "false_close_rate": m["false_close_rate"],
        })
    return results


def best_safe_combo(results: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Highest fast-path coverage among combos that never false-close."""
    safe = [r for r in results if r["false_close_rate"] == 0]
    return max(safe, key=lambda r: r["fast_path_coverage"]) if safe else None


async def main():
    from triage_engine.decision_models.laya import LayaDecisionProvider

    cases = [json.loads(l) for l in open(Path(__file__).parent / "data" / "ngsoc_eval.jsonl")]
    alerts = [c["_raw_alert"] for c in cases]
    labels = {
        c["_raw_alert"]["alert_id"]: (
            "benign" if json.loads(c["gold"])["malicious"]["probabilities"]["true"] < 0.2
            else "malicious"
        )
        for c in cases
    }

    provider = LayaDecisionProvider(prewarm=False, checkpoint_override="multilingual")
    import laya_mlx
    provider._agents["multilingual"] = laya_mlx.load(
        str(Path(__file__).resolve().parents[1] / "models" / "laya-security-ngsoc-v1"))

    results = await run_route_sweep(alerts, labels, provider=provider)
    for row in results:
        print(row, flush=True)

    Path("data/reports").mkdir(exist_ok=True)
    Path("data/reports/fast_close_threshold_sweep.json").write_text(json.dumps(results, indent=1))
    print("\nSAFEST BEST:", best_safe_combo(results))


if __name__ == "__main__":
    asyncio.run(main())
