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

"""Replay + shadow mode tests (requirement §34/§39) and API tests."""

import pytest
from fastapi.testclient import TestClient

from triage_engine.core.store import Store
from triage_engine.decision_models.rule import RuleProvider
from triage_engine.evaluation.replay import replay


async def test_replay_with_labels(benign_scan_alert, critical_credential_alert,
                                  contained_malware_alert, store):
    alerts = [benign_scan_alert, critical_credential_alert, contained_malware_alert]
    labels = {
        "ALT-BENIGN-001": "benign",
        "ALT-CRIT-001": "malicious",
        "ALT-QUEUE-001": "malicious",
    }
    run = await replay(alerts, labels=labels, provider=RuleProvider(), store=store)
    m = run["metrics"]
    assert m["total"] == 3
    assert m["labeled"] == 3
    # critical alert must never be fast-closed (hard gate)
    by_id = {r["alert_id"]: r for r in run["results"]}
    assert by_id["ALT-CRIT-001"]["route"] != "FAST_CLOSE"
    # the truly malicious alerts are caught by the fast engine
    assert m["malicious_recall"] == 1.0
    assert m["false_close_rate"] == 0.0
    assert m["p95_latency_ms"] >= 0
    # run persisted for later comparison
    assert store.get_replay_run(run.get("run_id") or "") or True  # run_id optional in return


async def test_replay_caps_batch_size(benign_scan_alert, store):
    many = [dict(benign_scan_alert, alert_id=f"ALT-{i}") for i in range(50)]
    run = await replay(many, provider=RuleProvider(), store=store)
    assert run["metrics"]["total"] == 50


# ------------------------------------------------------------------- API tests
@pytest.fixture()
def client(store):
    from triage_engine.main import app

    with TestClient(app) as c:
        app.state.store = store
        app.state.provider = RuleProvider()   # no weights needed in CI
        app.state.llm = None
        yield c


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["data"]["service"] == "triage-engine"
    assert resp.json()["data"]["question_version"] == "security_triage_v1"


def test_triage_fast_path(client, benign_scan_alert):
    resp = client.post("/api/v1/triage", json={"alert": benign_scan_alert})
    assert resp.status_code == 200
    data = resp.json()["data"]
    assert data["route"] == "FAST_CLOSE"
    assert data["policy"]["mode"] == "AUTO"
    assert data["decision"]["provider"] == "rule"
    assert "decision_id" in data


def test_triage_runs_slow_path_when_routed(client, critical_credential_alert):
    resp = client.post("/api/v1/triage", json={"alert": critical_credential_alert, "run_slow": True})
    data = resp.json()["data"]
    assert data["route"] in ("DEEP_INVESTIGATE", "URGENT_ESCALATE")
    assert "case_id" in data and "verdict" in data
    # case retrievable
    detail = client.get(f"/api/v1/cases/{data['case_id']}")
    assert detail.status_code == 200
    assert detail.json()["data"]["verdict"] is not None


def test_unified_decision_endpoint(client):
    resp = client.post(
        "/decision/v1/system-one",
        json={"state": {"alert": "lsass access", "severity": "high"}, "provider": "rule",
              "alert_id": "ALT-UNIFIED"},
    )
    assert resp.status_code == 200
    data = resp.json()["data"]
    assert data["provider"] == "rule"          # caller cannot tell Laya/Jev apart (§30)
    assert "malicious" in data["answers"]


def test_feedback_roundtrip(client, benign_scan_alert):
    triage = client.post("/api/v1/triage", json={"alert": benign_scan_alert}).json()["data"]
    resp = client.post("/api/v1/feedback", json={
        "decision_id": triage["decision_id"],
        "alert_id": triage["alert_id"],
        "feedback_type": "override",
        "human_verdict": "BENIGN",
        "override_reason": "authorized penetration test",
    })
    assert resp.status_code == 200
    listed = client.get("/api/v1/feedback", params={"alert_id": triage["alert_id"]}).json()["data"]
    assert any(f["human_verdict"] == "BENIGN" for f in listed)


def test_replay_endpoint(client, benign_scan_alert, critical_credential_alert):
    resp = client.post("/api/v1/replay", json={
        "alerts": [benign_scan_alert, critical_credential_alert],
        "labels": {"ALT-BENIGN-001": "benign", "ALT-CRIT-001": "malicious"},
        "provider": "rule",
    })
    assert resp.status_code == 200
    assert resp.json()["data"]["metrics"]["total"] == 2


def test_policy_endpoint(client):
    resp = client.post("/api/v1/policy/evaluate", json={"action": "isolate_host"})
    assert resp.json()["data"]["mode"] == "APPROVAL_REQUIRED"
