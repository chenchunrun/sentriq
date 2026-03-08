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

"""Unit tests for the current Alert Normalizer service surface."""

from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

import services.alert_normalizer.main as normalizer
from shared.models import AlertType, Severity


@pytest.fixture(autouse=True)
def reset_normalizer_state():
    """Keep module-level caches isolated between tests."""
    normalizer.processed_alerts_cache.clear()
    normalizer.aggregator.batches.clear()
    normalizer.aggregator.batch_timestamps.clear()
    yield
    normalizer.processed_alerts_cache.clear()
    normalizer.aggregator.batches.clear()
    normalizer.aggregator.batch_timestamps.clear()


@pytest.fixture
def client():
    """Test client for lightweight HTTP endpoints."""
    return TestClient(normalizer.app)


@pytest.fixture
def splunk_alert():
    """Representative Splunk-style raw alert."""
    return {
        "result": {
            "_time": "2026-01-06T10:30:00Z",
            "signature": "Malware detected",
            "alert_type": "malware",
            "severity": "high",
            "src_ip": "192.168.1.100",
            "dest_ip": "10.0.0.50",
            "file_hash": "5d41402abc4b2a76b9719d911017c592",
            "user": "admin",
        }
    }


@pytest.mark.unit
class TestAlertNormalizerHttp:
    """Validate the current public HTTP endpoints."""

    def test_health_check(self, client):
        response = client.get("/health")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["service"] == "alert-normalizer"
        assert "checks" in data

    def test_metrics_endpoint(self, client):
        response = client.get("/metrics")

        assert response.status_code == 200
        data = response.json()
        assert data["service"] == "alert-normalizer"
        assert "cache" in data
        assert "aggregation" in data
        assert "processors" in data


@pytest.mark.unit
class TestFieldMappingAndExtraction:
    """Validate pure helper functions in the current module."""

    def test_map_field_for_splunk(self):
        raw_alert = {"src_ip": "192.168.1.100", "user": "admin"}

        assert normalizer.map_field(raw_alert, "splunk", "source_ip") == "192.168.1.100"
        assert normalizer.map_field(raw_alert, "splunk", "user_id") == "admin"

    def test_map_field_for_default_format(self):
        raw_alert = {"target_ip": "10.0.0.50", "description": "Example"}

        assert normalizer.map_field(raw_alert, "default", "target_ip") == "10.0.0.50"
        assert normalizer.map_field(raw_alert, "default", "description") == "Example"

    def test_extract_iocs(self):
        raw_alert = {
            "description": "Malware from 192.168.1.100 to 10.0.0.50",
            "file_hash": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
        }

        iocs = normalizer.extract_iocs(raw_alert)

        assert "192.168.1.100" in iocs["ip_addresses"]
        assert "10.0.0.50" in iocs["ip_addresses"]
        assert raw_alert["file_hash"] in iocs["file_hashes"]

    def test_generate_alert_fingerprint_is_stable(self):
        alert = {
            "alert_type": "malware",
            "source_ip": "192.168.1.100",
            "target_ip": "10.0.0.50",
            "file_hash": "5d41402abc4b2a76b9719d911017c592",
        }

        fingerprint_1 = normalizer.generate_alert_fingerprint(alert)
        fingerprint_2 = normalizer.generate_alert_fingerprint(alert)

        assert fingerprint_1 == fingerprint_2

    def test_duplicate_detection(self):
        alert = {
            "alert_type": "malware",
            "source_ip": "192.168.1.100",
            "target_ip": "10.0.0.50",
            "file_hash": "5d41402abc4b2a76b9719d911017c592",
        }

        assert normalizer.is_duplicate_alert(alert) is False
        assert normalizer.is_duplicate_alert(alert) is True


@pytest.mark.unit
class TestNormalization:
    """Validate normalization using the current processor-based flow."""

    def test_normalize_splunk_alert(self, splunk_alert):
        normalized = normalizer.normalize_alert(splunk_alert, "splunk")

        assert normalized.alert_type == AlertType.MALWARE
        assert normalized.severity == Severity.HIGH
        assert normalized.source_ip == "192.168.1.100"
        assert normalized.target_ip == "10.0.0.50"
        assert normalized.file_hash == "5d41402abc4b2a76b9719d911017c592"
        assert normalized.normalized_data["source_type"] == "splunk"
        assert "normalized_at" in normalized.normalized_data

    def test_normalize_qradar_alert(self):
        qradar_alert = {
            "offense_id": 12345,
            "description": "Brute force attack detected",
            "start_time": 1704795000000,
            "severity": 7,
            "magnitude": 5,
            "offense_type": "Brute Force",
            "source_ip": "192.168.1.100",
            "destination_ip": "10.0.0.1",
            "username": "admin",
        }

        normalized = normalizer.normalize_alert(qradar_alert, "qradar")

        assert normalized.alert_type == AlertType.BRUTE_FORCE
        assert normalized.severity in {Severity.MEDIUM, Severity.HIGH}
        assert normalized.source_ip == "192.168.1.100"
        assert normalized.target_ip == "10.0.0.1"

    def test_normalize_cef_alert(self):
        cef_alert = {
            "raw_message": (
                "CEF:0|Security|IDS|1.0|100|Malware Detected|10|"
                "src=45.33.32.156 dst=10.0.0.50 "
                "duser=admin fileHash=5d41402abc4b2a76b9719d911017c592"
            )
        }

        normalized = normalizer.normalize_alert(cef_alert, "cef")

        assert normalized.alert_type == AlertType.MALWARE
        assert normalized.severity in {Severity.CRITICAL, Severity.HIGH}
        assert normalized.source_ip == "45.33.32.156"
        assert normalized.target_ip == "10.0.0.50"

    def test_normalize_invalid_alert_raises_value_error(self):
        with pytest.raises(ValueError):
            normalizer.normalize_alert(
                {"result": {"signature": "Bad alert", "src_ip": "999.999.999.999"}},
                "splunk",
            )


@pytest.mark.unit
class TestAlertAggregation:
    """Validate current aggregation behavior."""

    def _make_alert(self, alert_id: str):
        return normalizer.SecurityAlert(
            alert_id=alert_id,
            timestamp=datetime.now(UTC),
            alert_type=AlertType.MALWARE,
            severity=Severity.HIGH,
            description="Test aggregated alert",
            source_ip="192.168.1.100",
            target_ip="10.0.0.50",
        )

    def test_aggregator_releases_batch_at_max_size(self):
        aggregator = normalizer.AlertAggregator(window_seconds=30, max_batch_size=2)

        batch = aggregator.add_alert(self._make_alert("ALT-001"))
        assert batch is None

        batch = aggregator.add_alert(self._make_alert("ALT-002"))
        assert batch is not None
        assert len(batch) == 2

    def test_aggregator_flush_all(self):
        aggregator = normalizer.AlertAggregator(window_seconds=30, max_batch_size=10)

        aggregator.add_alert(self._make_alert("ALT-001"))
        aggregator.add_alert(self._make_alert("ALT-002"))

        batches = aggregator.flush_all()

        assert len(batches) == 1
        assert len(batches[0]) == 2

    def test_aggregator_stats(self):
        aggregator = normalizer.AlertAggregator(window_seconds=15, max_batch_size=5)
        aggregator.add_alert(self._make_alert("ALT-001"))

        stats = aggregator.get_stats()

        assert stats["active_batches"] == 1
        assert stats["total_alerts_buffered"] == 1
        assert stats["window_seconds"] == 15
        assert stats["max_batch_size"] == 5
