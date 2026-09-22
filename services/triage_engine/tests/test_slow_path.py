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

"""Slow path tests: hypotheses, planner, stop conditions, tool gateway,
investigation loop and judge (requirement §13-§24)."""

import pytest

from triage_engine.core.evidence import EvidenceService, reset_ids
from triage_engine.slow_path.evaluator import evaluate_stop
from triage_engine.slow_path.investigator import run_investigation
from triage_engine.slow_path.planner import next_tool
from triage_engine.slow_path.state import Budget, HypothesisSet, link_evidence_text
from triage_engine.slow_path.tool_gateway import ToolGateway, ToolGatewayError
from triage_engine.slow_path.tools_catalog import ToolEnvironment, TOOL_CATALOG, TOOL_NAMES


def test_hypothesis_update_supports_and_contradicts():
    hs = HypothesisSet.default()
    for h in hs.hypotheses:
        h.posterior = 0.2
    hs.update({"H2": {"supports": 0.8}, "H0": {"contradicts": 0.9}})
    top = hs.top()
    assert top.id == "H2"
    assert sum(h.posterior for h in hs.hypotheses) == pytest.approx(1.0)


def test_link_evidence_text_deterministic():
    links = link_evidence_text("rundll32.exe opened handle to lsass.exe with PROCESS_VM_READ")
    assert "H2" in links and links["H2"]["supports"] >= 0.8
    links2 = link_evidence_text("no active change records covering the asset")
    assert links2 == {}


def test_planner_prefers_discriminating_tool():
    posteriors = {"H0": 0.1, "H1": 0.6, "H2": 0.2, "H3": 0.05, "H4": 0.05}
    tool, value = next_tool([], posteriors)
    assert tool == "search_user_logins"          # H1 dominant -> login history first
    tool2, _ = next_tool(["search_user_logins"], posteriors)
    assert tool2 != "search_user_logins"
    assert next_tool(TOOL_NAMES, posteriors) is None   # everything called -> None


def test_stop_conditions_budget_and_convergence():
    hs = HypothesisSet.default()
    for h in hs.hypotheses:
        h.posterior = 0.2
    budget = Budget(max_steps=2, max_tool_calls=8)
    budget.steps_used = 2
    stop = evaluate_stop(hs, budget, evidence_count=1, no_more_tools=False)
    assert stop.finished and stop.reason == "BUDGET_MAX_STEPS"

    hs.hypotheses[2].posterior = 0.9  # H2 converged
    for h in hs.hypotheses:
        if h.id != "H2":
            h.posterior = 0.01
    hs.renormalize()
    budget2 = Budget(max_steps=10)
    stop2 = evaluate_stop(hs, budget2, evidence_count=4, no_more_tools=False)
    assert stop2.finished and stop2.reason.startswith("HYPOTHESIS_CONVERGED_H2")

    stop3 = evaluate_stop(hs, Budget(max_steps=10), evidence_count=1, no_more_tools=True)
    assert stop3.finished and stop3.reason == "NO_MORE_USEFUL_EVIDENCE"


async def test_tool_gateway_allowlist_only():
    gw = ToolGateway(ToolEnvironment({"alert_id": "A1"}))
    with pytest.raises(ToolGatewayError):
        await gw.execute("run_shell", {"cmd": "rm -rf /"})
    with pytest.raises(ToolGatewayError):
        await gw.execute("get_asset", {"bogus_param": 1})
    result = await gw.execute("get_asset", {"asset_id": "SRV-PROD-001"})
    assert any("criticality=critical" in f for f in result["facts"])
    assert all(t.ok for t in gw.audit)


async def test_investigation_end_to_end_no_llm(critical_credential_alert, store):
    """Full slow path with rule judge: evidence collected, timeline from
    evidence, verdict cites existing evidence IDs only (§3.4)."""
    reset_ids()
    from triage_engine.core.compressor import compress
    from triage_engine.core.context import AlertContext

    state = compress(AlertContext.build(critical_credential_alert), critical_credential_alert).model_dump()
    case = await run_investigation(
        critical_credential_alert, state, route="DEEP_INVESTIGATE",
        escalation_reasons=["HIGH_ASSET_IMPACT"], llm=None, store=store,
    )
    assert case["status"] in ("complete", "needs_human")
    assert len(case["evidence"]) >= 3
    assert len(case["tool_history"]) >= 3
    assert case["budget"]["tool_calls_used"] >= 3
    assert case["budget"]["steps_used"] <= case["budget"]["max_steps"]

    # verdict integrity: every cited evidence id exists (No Evidence -> No Fact)
    valid_ids = {e["evidence_id"] for e in case["evidence"]}
    verdict = case["verdict"]
    assert set(verdict["evidence_ids"]) <= valid_ids
    for finding in verdict.get("findings", []):
        assert set(finding.get("evidence_ids", [])) <= valid_ids

    # timeline derived from evidence only
    assert {t["evidence_id"] for t in case["timeline"]} <= valid_ids

    # case retrievable from the store
    fetched = store.get_case(case["case_id"])
    assert fetched["case_id"] == case["case_id"]


async def test_investigation_escalates_to_human_when_unclear(benign_scan_alert, store):
    from triage_engine.core.compressor import compress
    from triage_engine.core.context import AlertContext

    state = compress(AlertContext.build(benign_scan_alert), benign_scan_alert).model_dump()
    case = await run_investigation(benign_scan_alert, state, llm=None, store=store)
    assert case["verdict"]["verdict"] in ("BENIGN", "FALSE_POSITIVE", "UNCLEAR", "MALICIOUS")
    if case["verdict"]["verdict"] == "UNCLEAR":
        assert case["status"] == "needs_human"
