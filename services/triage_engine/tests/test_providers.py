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

"""Decision model provider tests: RuleProvider, Laya adapter (mocked runtime),
fail-safe fallback chain, ensemble disagreement (requirement §6/§29/§41)."""

import pytest

from triage_engine.core.compressor import compress
from triage_engine.core.context import AlertContext
from triage_engine.core.registry import registry
from triage_engine.decision_models import decide_with_fallback
from triage_engine.decision_models.base import (
    DecisionContext,
    DecisionModelProvider,
    DecisionResult,
    ProviderUnavailable,
    validate_answers,
)
from triage_engine.decision_models.ensemble import EnsembleProvider
from triage_engine.decision_models.laya import LayaDecisionProvider, SecurityLayaRouter
from triage_engine.decision_models.rule import RuleProvider


def _ctx(alert: dict) -> DecisionContext:
    state = compress(AlertContext.build(alert), alert)
    return DecisionContext(
        alert_id=state.alert_id, state_text=state.to_text(),
        question_version=registry.question_version,
    )


async def test_rule_provider_answers_all_questions(rule_provider, critical_credential_alert):
    state = compress(AlertContext.build(critical_credential_alert), critical_credential_alert).model_dump()
    result = await rule_provider.decide(state, registry.questions, _ctx(critical_credential_alert))
    assert set(result.decisions) == {"malicious", "authorized", "evidence_strength", "novelty",
                                     "business_impact", "containment_state", "investigation_need",
                                     "route"}
    assert validate_answers(result.decisions, registry.questions) == []
    assert 0.0 <= result.p("malicious") <= 1.0
    assert 0 <= result.p("business_impact") <= 4


def test_validate_answers_rejects_bad_output():
    good = {"malicious": 0.9, "evidence_strength": 3, "route": "FAST_CLOSE",
            "authorized": 0.1, "novelty": 2, "business_impact": 3,
            "containment_state": "CONTAINED", "investigation_need": 0.8}
    assert validate_answers(good, registry.questions) == []
    bad = {"malicious": 1.5, "evidence_strength": 9, "route": "NOPE", "authorized": "high"}
    issues = validate_answers(bad, registry.questions)
    assert any(i.startswith("out_of_range") for i in issues)
    assert any(i.startswith("invalid_choice") for i in issues)


def test_security_laya_router_checkpoint_routing():
    router = SecurityLayaRouter(registry.providers["laya"])
    zh = DecisionContext(alert_id="a", state_text="告警描述：可疑的凭据访问行为")
    assert router.select(zh.state_text, zh) == ("multilingual", "chinese_state")
    en = DecisionContext(alert_id="a", state_text="LSASS memory access on domain controller",
                         use_typed_workflow=True)
    assert router.select(en.state_text, en) == ("typed", "security_typed_workflow")
    plain = DecisionContext(alert_id="a", state_text="customer refund request",
                            use_typed_workflow=False)
    assert router.select(plain.state_text, plain) == ("general", "default_english")


class _FakeAgent:
    """Mimics laya predict() output (real schema) without loading weights."""

    def __init__(self, payload):
        self.payload = payload

    def predict(self, state, questions):
        return self.payload


async def test_laya_provider_maps_structured_answers(monkeypatch):
    provider = LayaDecisionProvider(prewarm=False)
    provider.runtime = "mlx"
    fake = _FakeAgent({
        "model": "laya-rl-agent",
        "answers": {
            "malicious": {"type": "noul", "confidence": 0.93, "noul": 0.93},
            "authorized": {"type": "noul", "confidence": 0.08, "noul": 0.08},
            "evidence_strength": {"type": "score", "confidence": 0.7, "score": 3.1,
                                   "probabilities": {"2": 0.2, "3": 0.8}},
            "novelty": {"type": "score", "confidence": 0.6, "score": 2.0},
            "business_impact": {"type": "score", "confidence": 0.8, "score": 3.9},
            "containment_state": {"type": "choice", "confidence": 0.9, "choice": "NOT_CONTAINED",
                                   "probabilities": {"NOT_CONTAINED": 0.9, "CONTAINED": 0.1}},
            "investigation_need": {"type": "noul", "confidence": 0.89, "noul": 0.89},
            "route": {"type": "choice", "confidence": 0.8, "choice": "DEEP_INVESTIGATE",
                       "probabilities": {"DEEP_INVESTIGATE": 0.8, "URGENT_ESCALATE": 0.13,
                                          "FAST_CLOSE": 0.01, "FAST_QUEUE": 0.03, "HUMAN_REVIEW": 0.03}},
        },
        "usage": {"input_tokens": 300, "output_tokens": 0},
    })
    provider._agents["typed"] = fake  # bypass weight loading
    alert = {"alert_id": "ALT-1", "alert_type": "malware", "severity": "high",
             "description": "lsass access"}
    state = compress(AlertContext.build(alert), alert).model_dump()
    ctx = _ctx(alert)
    result = await provider.decide(state, registry.questions, ctx)
    assert result.provider == "laya"
    assert result.model == "laya-typed"
    assert result.p("malicious") == pytest.approx(0.93)
    assert result.decisions["containment_state"] == "NOT_CONTAINED"
    assert result.route_prediction["DEEP_INVESTIGATE"] == pytest.approx(0.8, abs=0.02)
    assert result.model_metadata["routing_reason"] == "security_typed_workflow"
    assert result.model_metadata["input_tokens"] == 300
    assert validate_answers(result.decisions, registry.questions) == []


async def test_laya_provider_invalid_output_raises(monkeypatch):
    provider = LayaDecisionProvider(prewarm=False)
    provider.runtime = "mlx"
    provider._agents["typed"] = _FakeAgent({"answers": {"malicious": 42.0}})  # missing questions
    alert = {"alert_id": "ALT-2", "alert_type": "anomaly", "severity": "low"}
    state = compress(AlertContext.build(alert), alert).model_dump()
    with pytest.raises(ProviderUnavailable):
        await provider.decide(state, registry.questions, _ctx(alert))


class _FailingProvider(DecisionModelProvider):
    name = "failing"

    async def decide(self, state, questions, context):
        raise ProviderUnavailable("simulated outage")


async def test_fallback_chain_is_fail_safe(critical_credential_alert):
    """Primary dead -> rule fallback, degraded flag set (requirement §41)."""
    state = compress(AlertContext.build(critical_credential_alert), critical_credential_alert).model_dump()
    result = await decide_with_fallback(state, registry.questions, _ctx(critical_credential_alert),
                                        provider=_FailingProvider())
    assert result.degraded is True
    assert result.provider == "rule"
    assert "failing" in (result.degraded_reason or "")


async def test_ensemble_flags_disagreement(critical_credential_alert):
    class _HighMalice(DecisionModelProvider):
        name = "high"

        async def decide(self, state, questions, context):
            return DecisionResult(provider="high", model="m", decisions={
                "malicious": 0.95, "authorized": 0.02, "evidence_strength": 3.0,
                "novelty": 3.0, "business_impact": 4.0, "containment_state": "NOT_CONTAINED",
                "investigation_need": 0.9, "route": "URGENT_ESCALATE"})

    class _LowMalice(DecisionModelProvider):
        name = "low"

        async def decide(self, state, questions, context):
            return DecisionResult(provider="low", model="m", decisions={
                "malicious": 0.05, "authorized": 0.9, "evidence_strength": 3.0,
                "novelty": 1.0, "business_impact": 2.0, "containment_state": "CONTAINED",
                "investigation_need": 0.2, "route": "FAST_CLOSE"})

    ensemble = EnsembleProvider([_HighMalice(), _LowMalice()])
    state = compress(AlertContext.build(critical_credential_alert), critical_credential_alert).model_dump()
    result = await ensemble.decide(state, registry.questions, _ctx(critical_credential_alert))
    assert result.model_metadata["model_disagreement_flag"] is True
    assert result.p("malicious") == pytest.approx(0.5)
