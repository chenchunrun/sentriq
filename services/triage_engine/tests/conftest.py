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

"""Shared fixtures for the triage engine test suite."""

import sys
from pathlib import Path

import pytest

_SERVICES_DIR = str(Path(__file__).resolve().parents[2])
if _SERVICES_DIR not in sys.path:
    sys.path.insert(0, _SERVICES_DIR)

from triage_engine.core.store import Store  # noqa: E402
from triage_engine.decision_models.rule import RuleProvider  # noqa: E402


@pytest.fixture()
def rule_provider() -> RuleProvider:
    return RuleProvider()


@pytest.fixture()
def store() -> Store:
    return Store(":memory:")


@pytest.fixture()
def benign_scan_alert() -> dict:
    """Authorized vuln scan on a workstation - should be FAST_CLOSE-able."""
    return {
        "alert_id": "ALT-BENIGN-001",
        "timestamp": "2026-09-22T01:12:00Z",
        "alert_type": "scan",
        "source": "nessus",
        "severity": "info",
        "description": "Scheduled vulnerability scan from approved scanner asset",
        "source_ip": "192.168.1.101",
        "target_ip": "10.0.9.77",
        "asset_id": "WS-050",
        "user_id": "scanner.service@example.com",
        "file_hash": "aaaa0000bbbb0000cccc0000dddd0000eeee0000ffff0000aaaa0000bbbb0000",
        "active_change": True,
        "similar_alerts_30d": 6,
        "historical_false_positive_rate": 0.97,
    }


@pytest.fixture()
def critical_credential_alert() -> dict:
    """LSASS access on a critical production server - hard gates must hit."""
    return {
        "alert_id": "ALT-CRIT-001",
        "timestamp": "2026-09-22T01:12:00Z",
        "alert_type": "malware",
        "source": "EDR",
        "rule_id": "T1003-LSASS",
        "severity": "high",
        "description": "powershell spawned rundll32 which accessed lsass.exe memory (credential dumping)",
        "source_ip": "45.33.32.156",
        "target_ip": "10.0.1.10",
        "asset_id": "SRV-PROD-001",
        "user_id": "john.doe@example.com",
        "similar_alerts_30d": 0,
        "process_tree": ["powershell.exe", "rundll32.exe", "lsass.exe"],
    }


@pytest.fixture()
def contained_malware_alert() -> dict:
    """Confirmed malicious but EDR-contained on a low-value asset - FAST_QUEUE."""
    return {
        "alert_id": "ALT-QUEUE-001",
        "timestamp": "2026-09-22T02:00:00Z",
        "alert_type": "malware",
        "source": "EDR",
        "severity": "high",
        "description": "Known malware hash executed on workstation",
        "source_ip": "45.33.32.156",
        "target_ip": "10.0.1.99",
        "asset_id": "WS-099",
        "user_id": "user123",
        "file_hash": "5e884898da28047151e0e56f8dc6292773603d0d6aabbdd62a11ef721a1542d8",
        "edr_blocked": True,
        "process_killed": True,
        "similar_alerts_30d": 3,
    }
