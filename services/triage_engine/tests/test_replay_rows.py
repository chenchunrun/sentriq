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

"""Replay result-row richness tests (SOC adjudication loop, step 3).

Per-alert rows must carry the fields the shadow-rows JSONL and the
worksheet need: hard gates, all 8 typed-decision answers, the model's
suggested route and the state hash (stable join key across replays).
"""

from triage_engine.decision_models.rule import RuleProvider
from triage_engine.evaluation.replay import replay

_QUESTIONS = (
    "malicious", "authorized", "evidence_strength", "novelty",
    "business_impact", "containment_state", "investigation_need", "route",
)


async def test_replay_rows_carry_full_decision_context(benign_scan_alert,
                                                       critical_credential_alert,
                                                       store):
    run = await replay(
        [benign_scan_alert, critical_credential_alert],
        labels={"ALT-BENIGN-001": "benign", "ALT-CRIT-001": "malicious"},
        provider=RuleProvider(), store=store,
    )
    by_id = {r["alert_id"]: r for r in run["results"]}
    for alert_id, row in by_id.items():
        assert set(_QUESTIONS) <= set(row["decisions"]), alert_id
        assert isinstance(row["hard_gates"], list), alert_id
        assert row["state_hash"], alert_id                 # sha256(state_text)[:16]
        assert row["model_suggested_route"], alert_id
    # hard gate visible on the row: critical asset blocks FAST_CLOSE
    assert "asset_critical" in by_id["ALT-CRIT-001"]["hard_gates"]
    assert by_id["ALT-CRIT-001"]["route"] != "FAST_CLOSE"


async def test_metrics_from_results_matches_run_metrics(benign_scan_alert, store):
    from triage_engine.evaluation.replay import metrics_from_results

    run = await replay([benign_scan_alert], labels={"ALT-BENIGN-001": "benign"},
                       provider=RuleProvider(), store=store)
    recomputed = metrics_from_results(run["results"], latencies=[r["latency_ms"] for r in run["results"]])
    assert recomputed["total"] == run["metrics"]["total"]
    assert recomputed["false_close_rate"] == run["metrics"]["false_close_rate"]
    assert recomputed["route_distribution"] == run["metrics"]["route_distribution"]
    assert recomputed["fast_path_coverage"] == run["metrics"]["fast_path_coverage"]
