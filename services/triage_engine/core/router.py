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

"""Security Decision Router (requirement §10/§11).

Final route = Model Decisions + Security Context + Hard Rules + Policy
thresholds. The model's Q8 suggestion is one input among several - never the
final route (§3.2). Every escalation records reason codes (§28) so the SOC can
answer "why did this alert consume the slow model?".

Fail-safe ordering: when uncertain, escalate - never close (§41).
"""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from ..core.registry import registry
from ..decision_models.base import DecisionResult, ROUTES
from .gate import HardGateResult

# reason codes (requirement §28)
LOW_CONFIDENCE = "LOW_CONFIDENCE"
HIGH_ASSET_IMPACT = "HIGH_ASSET_IMPACT"
PRIVILEGED_IDENTITY = "PRIVILEGED_IDENTITY"
NOVEL_BEHAVIOR = "NOVEL_BEHAVIOR"
EVIDENCE_CONFLICT = "EVIDENCE_CONFLICT"
MULTI_HOST = "MULTI_HOST"
LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
CREDENTIAL_ACCESS = "CREDENTIAL_ACCESS"
INSUFFICIENT_CONTEXT = "INSUFFICIENT_CONTEXT"
UNKNOWN_ATTACK = "UNKNOWN_ATTACK"
MODEL_DISAGREEMENT = "MODEL_DISAGREEMENT"
POLICY_REQUIRED = "POLICY_REQUIRED"
PROVIDER_DEGRADED = "PROVIDER_DEGRADED"

_GATE_REASONS = {
    "asset_critical": HIGH_ASSET_IMPACT,
    "privileged_identity": PRIVILEGED_IDENTITY,
    "credential_access": CREDENTIAL_ACCESS,
    "lateral_movement": LATERAL_MOVEMENT,
    "multiple_hosts": MULTI_HOST,
    "active_attack": UNKNOWN_ATTACK,
    "data_exfiltration": HIGH_ASSET_IMPACT,
    "ransomware": UNKNOWN_ATTACK,
    "evidence_conflict": EVIDENCE_CONFLICT,
}


class RouteDecision(BaseModel):
    model_config = {"protected_namespaces": ()}

    route: str
    reason_codes: List[str] = Field(default_factory=list)
    hard_gates: List[str] = Field(default_factory=list)
    model_suggested_route: Optional[str] = None
    detail: Dict[str, Any] = Field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()


def route(
    decision: DecisionResult,
    gates: HardGateResult,
    state: Dict[str, Any],
    thresholds: Optional[Dict[str, Dict[str, Any]]] = None,
) -> RouteDecision:
    """Compute the final route. `thresholds` may override the registry (replay)."""
    th = thresholds or {}
    fast_close_th = th.get("fast_close", registry.thresholds("fast_close"))
    fast_queue_th = th.get("fast_queue", registry.thresholds("fast_queue"))
    deep_th = th.get("deep_investigate", registry.thresholds("deep_investigate"))
    urgent_th = th.get("urgent", registry.thresholds("urgent"))

    malicious = decision.p("malicious")
    authorized = decision.p("authorized")
    evidence_strength = decision.p("evidence_strength")
    novelty = decision.p("novelty")
    impact = decision.p("business_impact")
    investigation_need = decision.p("investigation_need")
    containment = str(decision.decisions.get("containment_state", "UNKNOWN"))
    uncertainty = 1.0 - max(malicious, authorized)

    reasons: List[str] = []
    model_route = decision.decisions.get("route") or max(
        decision.route_prediction, key=decision.route_prediction.get, default=None
    ) if decision.route_prediction else decision.decisions.get("route")

    # 1. degraded provider -> human (fail safe, requirement §41)
    if decision.degraded:
        return RouteDecision(
            route="HUMAN_REVIEW",
            reason_codes=[PROVIDER_DEGRADED, POLICY_REQUIRED],
            hard_gates=gates.gates_hit,
            model_suggested_route=str(model_route) if model_route else None,
            detail={"degraded_reason": decision.degraded_reason},
        )

    # ensemble disagreement flag -> slow path (requirement §29)
    if decision.model_metadata.get("model_disagreement_flag"):
        reasons.append(MODEL_DISAGREEMENT)

    # 2. hard-gate reason codes
    for gate in gates.gates_hit:
        if gate in _GATE_REASONS:
            reasons.append(_GATE_REASONS[gate])

    # 3. URGENT: high confidence + critical impact (§11.4) - notification +
    #    parallel deep investigation, never "skip investigation"
    if malicious >= float(urgent_th["malicious_min"]) and impact >= float(urgent_th["impact_min"]):
        return RouteDecision(
            route="URGENT_ESCALATE",
            reason_codes=_dedupe(reasons + [HIGH_ASSET_IMPACT]),
            hard_gates=gates.gates_hit,
            model_suggested_route=str(model_route) if model_route else None,
            detail={"note": "urgent notification + parallel deep investigation"},
        )

    # 4. DEEP_INVESTIGATE triggers (§11.3)
    deep_reasons: List[str] = list(reasons)
    if uncertainty >= float(deep_th["uncertainty_min"]):
        deep_reasons.append(LOW_CONFIDENCE)
    if investigation_need >= float(deep_th["investigation_need_min"]):
        deep_reasons.append(POLICY_REQUIRED)
    if novelty >= float(deep_th["novelty_min"]):
        deep_reasons.append(NOVEL_BEHAVIOR)
    if evidence_strength <= float(deep_th["evidence_strength_max"]):
        deep_reasons.append(INSUFFICIENT_CONTEXT)
    if gates.hit or any(r in deep_reasons for r in (LOW_CONFIDENCE, NOVEL_BEHAVIOR, INSUFFICIENT_CONTEXT, MODEL_DISAGREEMENT)):
        return RouteDecision(
            route="DEEP_INVESTIGATE",
            reason_codes=_dedupe(deep_reasons),
            hard_gates=gates.gates_hit,
            model_suggested_route=str(model_route) if model_route else None,
        )

    # 5. FAST_QUEUE: confirmed malicious but contained + bounded impact (§11.2)
    contained = containment == "CONTAINED"
    if (
        contained or not fast_queue_th.get("contained_only", True)
    ) and malicious >= float(fast_queue_th["malicious_min"]) and impact <= float(fast_queue_th["impact_max"]):
        return RouteDecision(
            route="FAST_QUEUE",
            reason_codes=[],
            hard_gates=gates.gates_hit,
            model_suggested_route=str(model_route) if model_route else None,
            detail={"containment": containment},
        )

    # 6. FAST_CLOSE: only without any hard gate and with strong authorization (§11.1)
    history = state.get("history", {}) or {}
    similar_ok = (
        not fast_close_th.get("require_similar_history", True)
        or int(history.get("similar_alerts_30d", 0)) >= int(fast_close_th.get("similar_history_min", 1))
    )
    if (
        gates.fast_close_allowed
        and malicious <= float(fast_close_th["malicious_max"])
        and authorized >= float(fast_close_th["authorized_min"])
        and impact <= float(fast_close_th["impact_max"])
        and evidence_strength >= float(fast_close_th["evidence_strength_min"])
        and novelty <= float(fast_close_th["novelty_max"])
        and similar_ok
    ):
        return RouteDecision(
            route="FAST_CLOSE",
            reason_codes=[],
            hard_gates=[],
            model_suggested_route=str(model_route) if model_route else None,
        )

    # 7. default: human review - uncertainty escalates, never closes
    return RouteDecision(
        route="HUMAN_REVIEW",
        reason_codes=_dedupe(reasons + [LOW_CONFIDENCE, POLICY_REQUIRED]),
        hard_gates=gates.gates_hit,
        model_suggested_route=str(model_route) if model_route else None,
    )


def _dedupe(items: List[str]) -> List[str]:
    seen, out = set(), []
    for i in items:
        if i and i not in seen:
            seen.add(i)
            out.append(i)
    return out


VALID_ROUTES = ROUTES
