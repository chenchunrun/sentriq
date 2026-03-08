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
Unit tests for Alert Ingestor service.

Refactored to use mock AppConfig to avoid validation errors.
"""

import os
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest
from fastapi.testclient import TestClient

# Set environment variables BEFORE importing any services
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost/test_db")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/1")
os.environ.setdefault("RABBITMQ_URL", "amqp://guest:guest@localhost:5672/")
os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-for-testing-only")


class TestAlertIngestorAPI:
    """Test Alert Ingestor API endpoints."""

    @pytest.fixture
    def mock_publisher(self):
        """Mock message publisher."""
        with patch("shared.messaging.MessagePublisher") as mock:
            publisher_instance = MagicMock()
            publisher_instance.connect = AsyncMock()
            publisher_instance.publish = AsyncMock()
            publisher_instance.close = AsyncMock()
            mock.return_value = publisher_instance
            yield publisher_instance

    @pytest.fixture
    def mock_db(self):
        """Mock database manager."""
        with patch("shared.database.get_database_manager") as mock:
            db_instance = MagicMock()
            db_instance.initialize = AsyncMock()
            db_instance.close = AsyncMock()
            db_instance.health_check = AsyncMock(return_value=True)

            session = MagicMock()
            session.execute = AsyncMock()
            session.commit = AsyncMock()

            result = MagicMock()
            result.fetchone = MagicMock(return_value=None)
            session.execute.return_value = result

            session_context = MagicMock()
            session_context.__aenter__ = AsyncMock(return_value=session)
            session_context.__aexit__ = AsyncMock(return_value=None)
            db_instance.get_session = MagicMock(return_value=session_context)

            mock.return_value = db_instance
            yield db_instance

    @pytest.fixture
    def client(self, mock_publisher, mock_db):
        """Create test client with all mocks in place."""
        # Import AFTER environment is set
        import services.alert_ingestor.main as alert_ingestor_main

        alert_ingestor_main.db_manager = mock_db
        alert_ingestor_main.message_publisher = mock_publisher

        return TestClient(alert_ingestor_main.app)

    def test_health_check(self, client):
        """Test health check endpoint."""
        response = client.get("/health")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["service"] == "alert-ingestor"

    def test_ingest_alert_success(self, client, mock_publisher):
        """Test successful alert ingestion."""
        alert_data = {
            "alert_id": "ALT-TEST-001",
            "timestamp": datetime.now(UTC).isoformat(),
            "alert_type": "malware",
            "severity": "high",
            "description": "Test alert",
            "source_ip": "45.33.32.156",
            "target_ip": "10.0.0.50",
        }

        response = client.post("/api/v1/alerts", json=alert_data)

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert "ingestion_id" in data["data"]
        assert data["data"]["status"] == "queued"

        # Verify message was published
        mock_publisher.publish.assert_called_once()

    def test_ingest_alert_invalid_data(self, client):
        """Test alert ingestion with invalid data."""
        invalid_data = {
            "alert_id": "",  # Invalid: empty
            "timestamp": "invalid-date",  # Invalid format
            "alert_type": "invalid-type",
            "severity": "critical",
        }

        response = client.post("/api/v1/alerts", json=invalid_data)

        assert response.status_code == 422  # Validation error

    def test_ingest_batch_alerts(self, client, mock_publisher):
        """Test batch alert ingestion."""
        batch_data = {
            "alerts": [
                {
                    "alert_id": f"ALT-BATCH-{i}",
                    "timestamp": datetime.now(UTC).isoformat(),
                    "alert_type": "malware",
                    "severity": "high",
                    "description": f"Batch alert {i}",
                }
                for i in range(3)
            ]
        }

        response = client.post("/api/v1/alerts/batch", json=batch_data)

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["data"]["successful"] == 3
        assert data["data"]["failed"] == 0

    def test_get_alert_status(self, client):
        """Test getting alert status."""
        alert_id = "ALT-TEST-001"

        response = client.get(f"/api/v1/alerts/{alert_id}")

        # Should return status (may be 404 if not found in cache)
        assert response.status_code in [200, 404]


class TestAlertIngestorLogic:
    """Test Alert Ingestor business logic."""

    @pytest.mark.asyncio
    async def test_message_format(self):
        """Test message is formatted correctly."""
        from shared.models import AlertType, SecurityAlert, Severity

        from services.alert_ingestor.main import create_alert_message

        alert = SecurityAlert(
            alert_id="ALT-MSG-TEST",
            timestamp=datetime.now(UTC),
            alert_type=AlertType.MALWARE,
            severity=Severity.HIGH,
            description="Test",
        )

        message = create_alert_message(alert)

        assert message["message_type"] == "alert.raw"
        assert "payload" in message
        assert message["payload"]["alert_id"] == "ALT-MSG-TEST"
        assert "timestamp" in message


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
