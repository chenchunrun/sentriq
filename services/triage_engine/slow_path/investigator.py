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

"""Investigation Agent Runtime (requirement §13/§16).

Loop: assess_case -> identify_open_questions -> choose_next_best_action ->
execute_readonly_tool -> normalize_evidence -> update_hypotheses ->
evaluate_stop_condition. The agent is READ ONLY; verdict actions flow through
the Policy Engine, never executed here (§40).
"""

import time
from typing import Any, Dict, List, Optional

from ..core.evidence import EvidenceService
from ..core.registry import registry
from ..core.timeline import build_timeline
from .evaluator import evaluate_stop
from .judge import judge
from .llm import LLMClient
from .planner import default_params, next_tool
from .state import Budget, HypothesisSet, InvestigationState, link_evidence_text
from .tool_gateway import ToolGateway, ToolGatewayError
from .tools_catalog import ToolEnvironment


async def run_investigation(
    raw_alert: Dict[str, Any],
    compressed_state: Dict[str, Any],
    route: str = "DEEP_INVESTIGATE",
    escalation_reasons: Optional[List[str]] = None,
    llm: Optional[LLMClient] = None,
    budget_overrides: Optional[Dict[str, Any]] = None,
    store=None,
) -> Dict[str, Any]:
    """Run a full slow-path investigation and return the case record."""
    t0 = time.perf_counter()
    budgets_cfg = registry.budgets
    budget = Budget(**{**budgets_cfg, **(budget_overrides or {})})

    hypotheses = HypothesisSet.default()
    evidence_service = EvidenceService()
    gateway = ToolGateway(ToolEnvironment(raw_alert))

    state = InvestigationState(
        alert_id=str(raw_alert.get("alert_id") or compressed_state.get("alert_id") or "ALT-UNKNOWN"),
        alert_context=compressed_state,
        route=route,
        escalation_reasons=escalation_reasons or [],
    )

    # seed evidence: the alert itself is the first fact
    _absorb(evidence_service, hypotheses, {
        "facts": [f"alert {state.alert_id}: {compressed_state.get('alert_type')} / "
                  f"{compressed_state.get('title') or compressed_state.get('description') or ''} (severity={compressed_state.get('severity')})"],
        "source": "SIEM",
        "timestamp": compressed_state.get("timestamp"),
        "relationships": [],
    }, state)

    stop_reason = ""
    called_tools: List[str] = []
    tool_failures = 0
    while True:
        budget.steps_used += 1
        pick = next_tool(called_tools, {h.id: h.posterior for h in hypotheses.hypotheses})
        no_more_tools = pick is None
        stop = evaluate_stop(
            hypotheses, budget, len(evidence_service.all()), no_more_tools, tool_failures
        )
        if stop.finished:
            stop_reason = stop.reason
            break

        tool, value = pick
        params = default_params(tool, compressed_state, raw_alert)
        try:
            result = await gateway.execute(tool, params)
            budget.tool_calls_used += 1
            _absorb(evidence_service, hypotheses, result, state, tool=tool, params=params)
        except ToolGatewayError:
            tool_failures += 1
        called_tools.append(tool)

    # timeline strictly from evidence (requirement §22)
    timeline = build_timeline(evidence_service.all())

    # final verdict (LLM judge when configured; deterministic rules otherwise)
    verdict = await judge(
        hypotheses,
        [e.model_dump() for e in evidence_service.all()],
        [t.model_dump() for t in timeline],
        compressed_state,
        llm=llm,
    )
    budget.tokens_used += int(verdict.get("tokens_used", 0))

    state.status = "complete" if verdict.get("verdict") != "UNCLEAR" else "needs_human"
    state.hypotheses = hypotheses.snapshot()
    state.evidence = [e.model_dump() for e in evidence_service.all()]
    state.timeline = [t.model_dump() for t in timeline]
    state.relationships = [r.model_dump() for r in evidence_service.relationships()]
    state.findings = verdict.get("findings", [])
    state.open_questions = verdict.get("remaining_uncertainties", [])
    state.tool_history = [t.model_dump() for t in gateway.audit]
    state.verdict = verdict
    state.budget = {
        "max_steps": budget.max_steps,
        "steps_used": budget.steps_used,
        "tool_calls_used": budget.tool_calls_used,
        "tokens_used": budget.tokens_used,
        "elapsed_seconds": round(budget.elapsed, 2),
        "stop_reason": stop_reason,
    }
    state.created_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    case = state.model_dump()
    case["llm"] = (llm.model if llm and llm.available else None)
    case["prompt_version"] = "judge_v1"
    case["latency_ms"] = int((time.perf_counter() - t0) * 1000)
    if store is not None:
        store.save_case(case)
    return case


def _absorb(
    evidence_service: EvidenceService,
    hypotheses: HypothesisSet,
    result: Dict[str, Any],
    state: InvestigationState,
    tool: str = "alert",
    params: Optional[Dict[str, Any]] = None,
) -> None:
    """Normalize a tool response into Evidence records and update hypotheses."""
    source = result.get("source") or "TOOL"
    timestamp = result.get("timestamp")
    for fact in result.get("facts", []):
        links = link_evidence_text(fact)
        ev = evidence_service.add(
            fact=fact,
            source=source,
            tool=tool,
            query=params or {},
            entity={},
            timestamp=timestamp,
            raw_reference=result.get("raw_reference"),
            hypothesis_links=links,
        )
        if links:
            hypotheses.update(links)
    for subject, verb, obj in result.get("relationships", []):
        evidence_service.add_relationship(subject, verb, obj, evidence_service.all()[-1].evidence_id if evidence_service.all() else "EV-00000")
    for entity in result.get("entities", []):
        if entity and isinstance(entity, dict) and entity not in state.entities:
            state.entities.append(entity)
