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

"""AlertContext + State Compressor tests (requirement §5/§7)."""

import pytest

from triage_engine.core.compressor import compress
from triage_engine.core.context import AlertContext


def test_context_enrichment_from_repo_data(critical_credential_alert):
    ctx = AlertContext.build(critical_credential_alert)
    assert ctx.asset.criticality == "critical"          # from assets.json SRV-PROD-001
    assert ctx.asset.environment == "production"
    assert ctx.threat_intel.ioc_hit is True             # 45.33.32.156 in internal_iocs
    assert ctx.flags.credential_access is True          # lsass keyword detected


def test_context_identity_from_users(benign_scan_alert):
    ctx = AlertContext.build(benign_scan_alert)
    assert ctx.change_context.active_change is True


def test_compressor_retains_required_fields(critical_credential_alert):
    state = compress(AlertContext.build(critical_credential_alert), critical_credential_alert)
    for field in ("alert_type", "severity", "timestamp", "host", "user", "source_ip",
                  "destination_ip", "process_tree", "ioc_hit", "asset", "identity",
                  "history", "containment", "detection_features"):
        assert hasattr(state, field)
    assert state.process_tree == ["powershell.exe", "rundll32.exe", "lsass.exe"]
    assert state.asset["asset_criticality"] == "critical"
    assert state.detection_features["credential_access"] is True


def test_compressor_deterministic_and_bounded(critical_credential_alert):
    ctx = AlertContext.build(critical_credential_alert)
    s1, s2 = compress(ctx, critical_credential_alert), compress(ctx, critical_credential_alert)
    assert s1.to_text() == s2.to_text()          # deterministic program, not an LLM
    assert s1.token_estimate() < 800             # §7: 200~800 token target


def test_compressor_clips_large_descriptions():
    raw = {
        "alert_id": "ALT-BIG", "alert_type": "anomaly", "severity": "low",
        "description": "x" * 100000,
    }
    state = compress(AlertContext.build(raw), raw)
    assert len(state.description) <= 200
