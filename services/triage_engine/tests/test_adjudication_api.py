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

"""Adjudication API tests (SOC adjudication loop, step 9)."""

import pytest
from fastapi.testclient import TestClient

from triage_engine.decision_models.rule import RuleProvider


@pytest.fixture()
def client(store):
    from triage_engine.main import app

    with TestClient(app) as c:
        app.state.store = store
        app.state.provider = RuleProvider()   # no weights needed in CI
        app.state.llm = None
        yield c


def _payload(**over):
    body = {
        "adjudications": [
            {
                "family_id": "F-1a2b3c4d",
                "family_key": ["Tailscale远控命令注入攻击", ["CGNAT覆盖网"], ["内网"], ""],
                "name": "Tailscale远控命令注入攻击",
                "soc_verdict": "无效告警",
                "disposition": "auto_close_ok",
                "alert_ids": ["SHD-20260921-00001", "SHD-20260913-00002"],
                "applies_to_family": True,
                "days": ["20260913", "20260921"],
                "engine_route": "FAST_CLOSE",
                "adjudicator": "soc.1",
                "source_worksheet": "soc_worksheet_20260921.csv",
                "notes": "组网工具流量",
            }
        ]
    }
    body["adjudications"][0].update(over)
    return body


def test_post_adjudications_batch_links_feedback(client):
    resp = client.post("/api/v1/adjudications", json=_payload())
    assert resp.status_code == 200
    data = resp.json()["data"]
    assert data["imported"] == 1
    assert data["family_ids"] == ["F-1a2b3c4d"]
    assert data["feedback_rows"] == 2          # one per member alert

    # adjudication visible
    listed = client.get("/api/v1/adjudications").json()
    assert listed["data"][0]["soc_verdict"] == "无效告警"
    assert listed["meta"]["stats"]["total"] == 1

    # feedback linkage via the existing read path
    fb = client.get("/api/v1/feedback", params={"alert_id": "SHD-20260921-00001"}).json()["data"]
    assert any(f["feedback_type"] == "soc_adjudication" and
               f["payload"]["family_id"] == "F-1a2b3c4d" for f in fb)


def test_post_adjudications_can_skip_feedback_linkage(client):
    resp = client.post("/api/v1/adjudications", json={**_payload(), "link_feedback": False})
    assert resp.status_code == 200
    assert resp.json()["data"]["feedback_rows"] == 0
    fb = client.get("/api/v1/feedback", params={"alert_id": "SHD-20260921-00001"}).json()["data"]
    assert fb == []


def test_post_adjudications_rejects_invalid_verdict(client):
    resp = client.post("/api/v1/adjudications", json=_payload(soc_verdict="maybe"))
    assert resp.status_code == 422
    assert resp.json()["detail"]["error_code"] == "INVALID_VERDICT"


def test_post_adjudications_rejects_invalid_disposition(client):
    resp = client.post("/api/v1/adjudications", json=_payload(disposition="nuke"))
    assert resp.status_code == 422
    assert resp.json()["detail"]["error_code"] == "INVALID_DISPOSITION"


def test_post_adjudications_rejects_empty_batch(client):
    resp = client.post("/api/v1/adjudications", json={"adjudications": []})
    assert resp.status_code == 422


def test_get_adjudication_single_and_missing(client):
    client.post("/api/v1/adjudications", json=_payload())
    found = client.get("/api/v1/adjudications/F-1a2b3c4d")
    assert found.status_code == 200
    assert found.json()["data"]["name"] == "Tailscale远控命令注入攻击"
    missing = client.get("/api/v1/adjudications/F-nonexist1")
    assert missing.status_code == 404
    assert missing.json()["detail"]["error_code"] == "ADJUDICATION_NOT_FOUND"


def test_reimport_upserts_family_state(client):
    client.post("/api/v1/adjudications", json=_payload())
    client.post("/api/v1/adjudications",
                json=_payload(soc_verdict="有效告警", disposition="blocklist"))
    listed = client.get("/api/v1/adjudications").json()["data"]
    assert len(listed) == 1                     # one row per family, latest verdict
    assert listed[0]["soc_verdict"] == "有效告警"
    # feedback rows append (audit log), they do not overwrite
    fb = client.get("/api/v1/feedback", params={"alert_id": "SHD-20260921-00001"}).json()["data"]
    assert len([f for f in fb if f["feedback_type"] == "soc_adjudication"]) == 2
