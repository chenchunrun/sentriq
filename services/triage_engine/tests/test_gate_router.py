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

"""Hard Gate + Decision Router tests (requirement §10-§12, §28, §3.2/§3.3)."""

import pytest

from triage_engine.core import gate as gate_mod
from triage_engine.core import router as router_mod
from triage_engine.core.compressor import compress
from triage_engine.core.registry import registry
from triage_engine.core.context import AlertContext
from triage_engine.decision_models.base import DecisionResult


def _state(alert: dict) -> dict:
    return compress(AlertContext.build(alert), alert).model_dump()


def _decision(**over) -> DecisionResult:
    base = {
        "malicious": 0.05, "authorized": 0.98, "evidence_strength": 3.0,
        "novelty": 0.0, "business_impact": 1.0, "containment_state": "UNKNOWN",
        "investigation_need": 0.1, "route": "FAST_CLOSE",
    }
    base.update(over)
    return DecisionResult(provider="test", model="m", decisions=base,
                          route_prediction={})


def test_hard_gates_block_fast_close(critical_credential_alert):
    gates = gate_mod.evaluate_hard_gates(_state(critical_credential_alert))
    assert gates.hit is True
    assert "asset_critical" in gates.gates_hit
    assert "credential_access" in gates.gates_hit
    assert gates.fast_close_allowed is False


def test_no_gates_on_benign(benign_scan_alert):
    gates = gate_mod.evaluate_hard_gates(_state(benign_scan_alert))
    assert gates.hit is False


def test_fast_close_route(rule_provider, benign_scan_alert):
    state = benign_scan_alert
    result = router_mod.route(_decision(), gate_mod.evaluate_hard_gates(_state(state)), _state(state))
    assert result.route == "FAST_CLOSE"
    assert result.reason_codes == []


def test_model_route_is_never_final(rule_provider, critical_credential_alert):
    """§3.2/§8.8: model says FAST_CLOSE with high confidence - hard gates win."""
    state = _state(critical_credential_alert)
    decision = _decision(malicious=0.02, authorized=0.99, route="FAST_CLOSE")
    result = router_mod.route(decision, gate_mod.evaluate_hard_gates(state), state)
    assert result.route != "FAST_CLOSE"
    assert result.model_suggested_route == "FAST_CLOSE"


def test_urgent_escalate(rule_provider, critical_credential_alert):
    state = _state(critical_credential_alert)
    decision = _decision(malicious=0.95, business_impact=4.0)
    result = router_mod.route(decision, gate_mod.evaluate_hard_gates(state), state)
    assert result.route == "URGENT_ESCALATE"
    assert "HIGH_ASSET_IMPACT" in result.reason_codes


def test_deep_investigate_on_lateral_movement():
    alert = {
        "alert_id": "ALT-LM", "alert_type": "anomaly", "severity": "medium",
        "description": "suspicious lateral movement via SMB to multiple hosts",
        "asset_id": "WS-050", "similar_alerts_30d": 0,
    }
    state = _state(alert)
    decision = _decision(malicious=0.5, authorized=0.4, business_impact=2.0)
    result = router_mod.route(decision, gate_mod.evaluate_hard_gates(state), state)
    assert result.route in ("DEEP_INVESTIGATE", "URGENT_ESCALATE")
    assert "LATERAL_MOVEMENT" in result.reason_codes


def test_fast_queue_contained_malicious(contained_malware_alert):
    state = _state(contained_malware_alert)
    decision = _decision(malicious=0.8, business_impact=1.0, novelty=1.0,
                         containment_state="CONTAINED", evidence_strength=3.0,
                         investigation_need=0.2, authorized=0.0)
    result = router_mod.route(decision, gate_mod.evaluate_hard_gates(state), state)
    assert result.route == "FAST_QUEUE"


def test_degraded_provider_goes_to_human(critical_credential_alert):
    state = _state(critical_credential_alert)
    decision = _decision()
    decision.degraded = True
    decision.degraded_reason = "laya unavailable: simulated outage"
    result = router_mod.route(decision, gate_mod.evaluate_hard_gates(state), state)
    assert result.route == "HUMAN_REVIEW"
    assert "PROVIDER_DEGRADED" in result.reason_codes


def test_fast_close_history_gate_configurable():
    """Calibrated policy (triage_policy_v1.1): history gate off by default; when
    an operator re-enables it, no-history alerts must not FAST_CLOSE."""
    alert = {
        "alert_id": "ALT-NOHIST", "alert_type": "scan", "severity": "info",
        "description": "scanner", "asset_id": "WS-050", "similar_alerts_30d": 0,
        "active_change": True,
    }
    state = _state(alert)
    gates = gate_mod.evaluate_hard_gates(state)
    strict = {"fast_close": {**registry.thresholds("fast_close"), "require_similar_history": True}}
    result = router_mod.route(_decision(), gates, state, thresholds=strict)
    assert result.route != "FAST_CLOSE"


def test_fast_close_blocked_by_attempt_or_success_gates():
    """shadow-0921 postmortem: inbound attempts and confirmed successes never close."""
    attempt = {
        "alert_id": "ALT-INBOUND", "alert_type": "anomaly", "severity": "medium",
        "description": "TFTP probe", "source_ip": "205.210.31.96", "target_ip": "10.0.1.5",
        "attack_result": "企图", "asset_id": "WS-050",
    }
    gates = gate_mod.evaluate_hard_gates(_state(attempt))
    assert "external_to_internal" in gates.gates_hit
    assert gates.fast_close_allowed is False

    success = {
        "alert_id": "ALT-SUCCESS", "alert_type": "anomaly", "severity": "medium",
        "description": "command exec", "source_ip": "10.0.1.5", "target_ip": "10.0.1.6",
        "attack_result": "成功", "asset_id": "WS-050",
    }
    gates2 = gate_mod.evaluate_hard_gates(_state(success))
    assert "attack_success" in gates2.gates_hit


def test_reason_codes_present_for_escalation():
    alert = {
        "alert_id": "ALT-NOVEL", "alert_type": "anomaly", "severity": "medium",
        "description": "unusual service account behavior at 02:00",
        "asset_id": "WS-050", "similar_alerts_30d": 0,
    }
    state = _state(alert)
    decision = _decision(malicious=0.4, authorized=0.3, novelty=4.0, evidence_strength=0.0)
    result = router_mod.route(decision, gate_mod.evaluate_hard_gates(state), state)
    assert result.route == "DEEP_INVESTIGATE"
    assert "NOVEL_BEHAVIOR" in result.reason_codes
    assert "INSUFFICIENT_CONTEXT" in result.reason_codes
