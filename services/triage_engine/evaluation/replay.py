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

"""Decision Replay + Shadow Mode evaluation (requirement §34/§39).

Re-runs the fast path over historical alerts (optionally with alternative
providers / thresholds for A-B comparison, up to 1000 alerts per run) and
computes the fast-path metrics of §37 - Fast Close Precision, Malicious
Recall, Fast Path Coverage, False Close Rate (the critical one), P95 latency,
cost per alert. When analyst labels are supplied the same run doubles as
shadow-mode AI-vs-Analyst comparison.
"""

import time
from typing import Any, Dict, List, Optional

from ..core.registry import registry  # noqa: F401  (thresholds variant support)
from ..decision_models import DecisionModelProvider, get_provider
from ..fast_path.triage import triage_fast


def _percentile(values: List[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, int(round(pct / 100.0 * (len(ordered) - 1))))
    return ordered[idx]


async def replay(
    alerts: List[Dict[str, Any]],
    labels: Optional[Dict[str, str]] = None,
    provider: Optional[DecisionModelProvider] = None,
    thresholds: Optional[Dict[str, Dict[str, Any]]] = None,
    persist_decisions: bool = False,
    store=None,
) -> Dict[str, Any]:
    """Run the fast path over a batch of alerts and summarize.

    `labels` maps alert_id -> analyst ground truth: "malicious" | "benign".
    """
    labels = labels or {}
    limit = int(registry.replay_limits.get("max_alerts_per_run", 1000))
    alerts = alerts[:limit]

    results: List[Dict[str, Any]] = []
    latencies: List[float] = []
    route_counts: Dict[str, int] = {}
    fast_close_tp = fast_close_fp = false_close = 0
    malicious_total = malicious_caught = 0

    for alert in alerts:
        t0 = time.perf_counter()
        outcome = await triage_fast(
            alert, provider=provider, thresholds=thresholds,
            store=store, persist=persist_decisions,
        )
        elapsed = (time.perf_counter() - t0) * 1000
        latencies.append(elapsed)
        route = outcome["route"]
        route_counts[route] = route_counts.get(route, 0) + 1

        alert_id = outcome["alert_id"]
        truth = labels.get(alert_id) or labels.get(str(alert.get("alert_id")))
        malicious = outcome["decision"]["decisions"].get("malicious", 0.0)

        if truth == "malicious":
            malicious_total += 1
            if malicious >= 0.5 or route in ("DEEP_INVESTIGATE", "URGENT_ESCALATE"):
                malicious_caught += 1
        if route == "FAST_CLOSE":
            if truth == "malicious":
                fast_close_fp += 1
                false_close += 1
            elif truth == "benign":
                fast_close_tp += 1

        results.append({
            "alert_id": alert_id,
            "route": route,
            "reason_codes": outcome["reason_codes"],
            "malicious": malicious,
            "truth": truth,
            "latency_ms": round(elapsed, 1),
            "degraded": outcome["decision"].get("degraded", False),
        })

    total = len(results) or 1
    fast_path_count = route_counts.get("FAST_CLOSE", 0) + route_counts.get("FAST_QUEUE", 0)
    metrics = {
        "total": len(results),
        "route_distribution": route_counts,
        "fast_path_coverage": round(fast_path_count / total, 4),
        "fast_close_precision": round(fast_close_tp / (fast_close_tp + fast_close_fp), 4) if (fast_close_tp + fast_close_fp) else None,
        "false_close_rate": round(false_close / total, 4),
        "malicious_recall": round(malicious_caught / malicious_total, 4) if malicious_total else None,
        "p95_latency_ms": round(_percentile(latencies, 95), 1),
        "avg_latency_ms": round(sum(latencies) / total, 1),
        "cost_per_alert_usd": 0.0,  # local laya inference has no marginal API cost
        "labeled": len(labels),
        "degraded_decisions": sum(1 for r in results if r["degraded"]),
    }

    run = {
        "provider": (provider.name if provider else get_provider().name),
        "threshold_version": registry.threshold_version,
        "question_version": registry.question_version,
        "alert_count": len(results),
        "metrics": metrics,
        "results": results,
    }
    if store is not None:
        store.save_replay_run(run)
    return run
