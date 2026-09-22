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

"""RuleProvider - deterministic typed-decision rules (requirement §6.2).

Doubles as the mandated fail-safe fallback when the Laya runtime is
unavailable, times out, or returns invalid output (requirement §41).
Never "fails closed": uncertainty raises investigation_need instead.
"""

import time
from typing import Any, Dict

from .base import (
    DecisionContext,
    DecisionModelProvider,
    DecisionResult,
    CONTAINMENT_STATES,
    ROUTES,
    state_hash,
)

# Deterministic rule weights (model internals, not router thresholds).
_SEVERITY_MALICE = {"info": 0.05, "low": 0.15, "medium": 0.35, "high": 0.60, "critical": 0.85}
_TYPE_MALICE = {
    "malware": 0.75, "ransomware": 0.90, "data_exfiltration": 0.80, "phishing": 0.60,
    "brute_force": 0.50, "anomaly": 0.30, "policy_violation": 0.20, "scan": 0.15,
    "unknown": 0.30,
}
_CRITICALITY_IMPACT = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 1}
_PRIVILEGED_ROLES = {"admin", "administrator", "dba", "domain_admin", "privileged", "root"}


def _clamp01(x: float) -> float:
    return max(0.0, min(1.0, x))


class RuleProvider(DecisionModelProvider):
    name = "rule"

    async def decide(
        self,
        state: Dict[str, Any],
        questions: Dict[str, Dict[str, Any]],
        context: DecisionContext,
    ) -> DecisionResult:
        t0 = time.perf_counter()
        asset = state.get("asset", {}) or {}
        identity = state.get("identity", {}) or {}
        history = state.get("history", {}) or {}
        containment = state.get("containment", {}) or {}
        change = state.get("change_context", {}) or {}
        features = state.get("detection_features", {}) or {}

        flags = {
            k: bool(features.get(k, False))
            for k in ("credential_access", "lateral_movement", "multiple_hosts",
                      "active_attack", "data_exfiltration", "ransomware", "evidence_conflict")
        }

        # Q1 maliciousness
        malice = (
            _SEVERITY_MALICE.get(state.get("severity", "medium"), 0.35) * 0.5
            + _TYPE_MALICE.get(state.get("alert_type", "unknown"), 0.30) * 0.3
        )
        if state.get("ioc_hit"):
            malice = max(malice, 0.80)
        for flag in ("ransomware", "data_exfiltration", "credential_access", "lateral_movement"):
            if flags[flag]:
                malice += 0.10
        malice = _clamp01(malice)

        # Q2 authorization
        authorized = 0.30
        if change.get("active_change"):
            authorized += 0.45
        if state.get("alert_type") in ("scan", "policy_violation") and state.get("severity") in ("info", "low"):
            authorized += 0.30
        if history.get("similar_alerts_30d", 0) >= 5 and malice < 0.4:
            authorized += 0.20
        if state.get("ioc_hit"):
            authorized -= 0.30
        if flags["credential_access"] or flags["ransomware"]:
            authorized -= 0.20
        if not identity.get("normal_work_hours", True):
            authorized -= 0.10
        authorized = _clamp01(authorized)

        # Q3 evidence strength (0-4)
        evidence_signals = sum(
            1 for present in (
                state.get("ioc_hit"), state.get("file_hash"), state.get("process_tree"),
                flags["credential_access"], flags["lateral_movement"],
                state.get("source_ip") and state.get("destination_ip"),
            ) if present
        )
        evidence_strength = min(4, evidence_signals)

        # Q4 novelty (0-4)
        similar = int(history.get("similar_alerts_30d", 0))
        if similar >= 5:
            novelty = 0
        elif similar >= 2:
            novelty = 1
        elif similar >= 1:
            novelty = 2
        else:
            novelty = 3
        if flags["ransomware"] or flags["lateral_movement"]:
            novelty = max(novelty, 3)

        # Q5 business impact - driven by asset/identity context, not AI (requirement §8.5)
        impact = _CRITICALITY_IMPACT.get(asset.get("asset_criticality", "unknown"), 1)
        if identity.get("privileged"):
            impact = min(4, impact + 1)
        if asset.get("internet_exposed"):
            impact = min(4, impact + 0)  # exposure adds urgency, not impact magnitude

        # Q6 containment state
        if containment.get("edr_blocked") and containment.get("process_killed"):
            containment_state = "CONTAINED"
        elif containment.get("edr_blocked") or containment.get("process_killed"):
            containment_state = "PARTIALLY_CONTAINED"
        else:
            containment_state = "NOT_CONTAINED"

        # Q7 investigation need
        uncertainty = 1.0 - max(malice, authorized)
        investigation_need = _clamp01(
            0.45 * malice * (1 if containment_state != "CONTAINED" else 0.4)
            + 0.35 * uncertainty
            + 0.15 * (novelty / 4.0)
            + (0.15 if any(flags.values()) else 0.0)
        )

        # Q8 route prediction (advisory only - the Router decides the final route)
        route_prediction = {r: 0.0 for r in ROUTES}
        if malice >= 0.9 and impact >= 3:
            route_prediction["URGENT_ESCALATE"] = 0.6
            route_prediction["DEEP_INVESTIGATE"] = 0.3
        elif malice >= 0.7 and containment_state == "CONTAINED" and impact <= 2:
            route_prediction["FAST_QUEUE"] = 0.6
            route_prediction["DEEP_INVESTIGATE"] = 0.2
        elif malice <= 0.1 and authorized >= 0.95:
            route_prediction["FAST_CLOSE"] = 0.7
            route_prediction["FAST_QUEUE"] = 0.1
        else:
            route_prediction["DEEP_INVESTIGATE"] = 0.5
            route_prediction["HUMAN_REVIEW"] = 0.3
        total = sum(route_prediction.values()) or 1.0
        route_prediction = {k: round(v / total, 3) for k, v in route_prediction.items()}
        suggested_route = max(route_prediction, key=route_prediction.get)

        decisions: Dict[str, Any] = {
            "malicious": round(malice, 3),
            "authorized": round(authorized, 3),
            "evidence_strength": float(evidence_strength),
            "novelty": float(novelty),
            "business_impact": float(impact),
            "containment_state": containment_state,
            "investigation_need": round(investigation_need, 3),
            "route": suggested_route,   # advisory only (§8.8)
        }
        latency_ms = int((time.perf_counter() - t0) * 1000)
        return DecisionResult(
            provider=self.name,
            model="deterministic-rules-v1",
            version="1",
            decisions=decisions,
            route_prediction=route_prediction,
            latency_ms=latency_ms,
            model_metadata={"rule_engine": "deterministic"},
            state_hash=state_hash(context.state_text),
            question_version=context.question_version,
        )
