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
real replay engine over the held-out eval set, keeping every other threshold
at default. Safety constraint: false_close_rate must stay 0 - a threshold that
closes a single truly-malicious alert is disqualified regardless of coverage.
"""

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from triage_engine.core.registry import registry
from triage_engine.decision_models.laya import LayaDecisionProvider
from triage_engine.evaluation.replay import replay


async def main():
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

    base_fc = registry.thresholds("fast_close")
    results = []
    for auth_min in (0.95, 0.90, 0.85, 0.80, 0.75):
        for mal_max in (0.10, 0.15, 0.20):
            for need_history in (True, False):
                th = {"fast_close": {**base_fc, "authorized_min": auth_min,
                                     "malicious_max": mal_max,
                                     "require_similar_history": need_history}}
                run = await replay(alerts, labels=labels, provider=provider, thresholds=th)
                m = run["metrics"]
                results.append({
                    "authorized_min": auth_min, "malicious_max": mal_max,
                    "require_similar_history": need_history,
                    "fast_close": m["route_distribution"].get("FAST_CLOSE", 0),
                    "fast_queue": m["route_distribution"].get("FAST_QUEUE", 0),
                    "fast_path_coverage": m["fast_path_coverage"],
                    "false_close_rate": m["false_close_rate"],
                })
                print(results[-1], flush=True)

    Path("data/reports").mkdir(exist_ok=True)
    Path("data/reports/fast_close_threshold_sweep.json").write_text(json.dumps(results, indent=1))
    safe = [r for r in results if r["false_close_rate"] == 0]
    best = max(safe, key=lambda r: r["fast_path_coverage"]) if safe else None
    print("\nSAFEST BEST:", best)


if __name__ == "__main__":
    asyncio.run(main())
