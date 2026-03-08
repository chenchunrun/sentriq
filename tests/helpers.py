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

"""
Test helper functions and utilities.
"""

import asyncio
import json
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, Mock
from shared.utils.time import utc_now, utc_now_iso


def create_mock_alert(
    alert_id: str = "test-alert-001", alert_type: str = "malware", severity: str = "high", **kwargs
) -> Dict[str, Any]:
    """Create a mock alert for testing."""
    return {
        "alert_id": alert_id,
        "alert_type": alert_type,
        "severity": severity,
        "title": kwargs.get("title", "Test Alert"),
        "description": kwargs.get("description", "Test alert description"),
        "source_ip": kwargs.get("source_ip", "192.168.1.100"),
        "target_ip": kwargs.get("target_ip", "10.0.0.50"),
        "file_hash": kwargs.get("file_hash", "abc123"),
        "url": kwargs.get("url"),
        "process_name": kwargs.get("process_name"),
        "asset_id": kwargs.get("asset_id", "SERVER-001"),
        "user_id": kwargs.get("user_id", "admin"),
        "timestamp": kwargs.get("timestamp", utc_now_iso()),
        "raw_data": kwargs.get("raw_data", {}),
    }


def create_mock_triage_result(
    alert_id: str = "test-alert-001", risk_level: str = "high", confidence: int = 85, **kwargs
) -> Dict[str, Any]:
    """Create a mock triage result for testing."""
    return {
        "alert_id": alert_id,
        "risk_level": risk_level,
        "confidence": confidence,
        "reasoning": kwargs.get("reasoning", "Test reasoning"),
        "recommended_actions": kwargs.get(
            "recommended_actions",
            [{"action": "Test action", "priority": "high", "timeline": "Immediate"}],
        ),
        "iocs": kwargs.get("iocs", {"file_hashes": [], "ips": [], "domains": []}),
        "references": kwargs.get("references", []),
        "created_at": utc_now_iso(),
    }


def create_mock_enrichment(alert_id: str = "test-alert-001", **kwargs) -> Dict[str, Any]:
    """Create a mock enrichment for testing."""
    return {
        "alert_id": alert_id,
        "enriched_at": utc_now_iso(),
        "enrichment_sources": ["source_network", "threat_intel"],
        "source_network": {
            "ip_address": kwargs.get("source_ip", "192.168.1.100"),
            "is_internal": True,
            "subnet": "192.168.1.0/24",
            "country": "Internal",
        },
        "threat_intel": {
            "threat_score": kwargs.get("threat_score", 75),
            "sources_queried": 2,
            "sources_found": 1,
            "indicators": {},
        },
        "asset": {"asset_id": kwargs.get("asset_id", "SERVER-001"), "criticality": "high"},
    }


async def wait_for_condition(
    condition: callable, timeout: float = 5.0, interval: float = 0.1, *args, **kwargs
) -> bool:
    """
    Wait for a condition to become true.

    Args:
        condition: Callable that returns bool
        timeout: Maximum time to wait in seconds
        interval: Check interval in seconds
        *args: Args to pass to condition
        **kwargs: Kwargs to pass to condition

    Returns:
        True if condition met, False if timeout
    """
    start = time.time()
    while time.time() - start < timeout:
        if condition(*args, **kwargs):
            return True
        await asyncio.sleep(interval)
    return False


def assert_valid_alert(alert: Dict[str, Any]) -> None:
    """Assert that alert has required fields."""
    required_fields = ["alert_id", "alert_type", "severity", "title", "description", "timestamp"]
    for field in required_fields:
        assert field in alert, f"Missing required field: {field}"
        assert alert[field] is not None, f"Field {field} is None"


def assert_valid_triage_result(result: Dict[str, Any]) -> None:
    """Assert that triage result has required fields."""
    required_fields = ["alert_id", "risk_level", "confidence", "reasoning"]
    for field in required_fields:
        assert field in result, f"Missing required field: {field}"
        assert result[field] is not None, f"Field {field} is None"

    # Validate risk level
    valid_risk_levels = ["critical", "high", "medium", "low", "info"]
    assert result["risk_level"] in valid_risk_levels, f"Invalid risk_level: {result['risk_level']}"

    # Validate confidence
    assert 0 <= result["confidence"] <= 100, f"Confidence out of range: {result['confidence']}"


def assert_valid_enrichment(enrichment: Dict[str, Any]) -> None:
    """Assert that enrichment has required fields."""
    required_fields = ["alert_id", "enriched_at", "enrichment_sources"]
    for field in required_fields:
        assert field in enrichment, f"Missing required field: {field}"
        assert enrichment[field] is not None, f"Field {field} is None"


def compare_dicts(
    dict1: Dict[str, Any], dict2: Dict[str, Any], ignore_fields: Optional[List[str]] = None
) -> bool:
    """
    Compare two dictionaries, ignoring specified fields.

    Args:
        dict1: First dictionary
        dict2: Second dictionary
        ignore_fields: Fields to ignore in comparison

    Returns:
        True if equal (ignoring specified fields), False otherwise
    """
    if ignore_fields:
        dict1 = {k: v for k, v in dict1.items() if k not in ignore_fields}
        dict2 = {k: v for k, v in dict2.items() if k not in ignore_fields}

    return dict1 == dict2


def mock_message_queue_message(
    message_type: str, payload: Dict[str, Any], message_id: Optional[str] = None
) -> Dict[str, Any]:
    """Create a mock message queue message."""
    return {
        "message_id": message_id or f"msg-{int(time.time() * 1000)}",
        "message_type": message_type,
        "correlation_id": payload.get("alert_id", "unknown"),
        "timestamp": utc_now_iso(),
        "version": "1.0",
        "payload": payload,
    }


class MockMessageQueue:
    """Mock message queue for testing."""

    def __init__(self):
        self.messages = []
        self.consumed = False

    async def publish(self, queue: str, message: Dict[str, Any]) -> None:
        """Mock publish message."""
        self.messages.append((queue, message))

    async def consume(self, callback):
        """Mock consume messages."""
        self.consumed = True
        # In tests, you can manually trigger callback
        self.callback = callback

    async def trigger_message(self, message: Dict[str, Any]) -> None:
        """Trigger callback with message."""
        if hasattr(self, "callback"):
            await self.callback(message)


class AsyncContextManager:
    """Helper for creating async context managers."""

    def __init__(self, enter_result=None):
        self.enter_result = enter_result

    async def __aenter__(self):
        return self.enter_result

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass


def create_async_mock(return_value=None):
    """Create an async mock with specified return value."""
    mock = AsyncMock()
    mock.return_value = return_value
    return mock
