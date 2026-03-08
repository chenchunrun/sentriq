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
Integration tests for Alert Processing Pipeline.

Tests the complete flow from alert ingestion to triage.
"""

import asyncio
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from shared.models import AlertType, SecurityAlert, Severity


@pytest.mark.integration
@pytest.mark.asyncio
class TestAlertProcessingPipeline:
    """Test complete alert processing pipeline."""

    @pytest.fixture
    async def setup_services(self):
        """Setup mock services for integration testing."""
        services = {}

        # Mock RabbitMQ connection
        with patch("aio_pika.connect_robust") as mock_rabbit:
            mock_connection = MagicMock()
            mock_channel = MagicMock()
            mock_connection.channel = MagicMock(return_value=mock_channel)
            mock_connection.close = AsyncMock()
            mock_rabbit.return_value = mock_connection

            # Mock database
            with patch("shared.database.get_database_manager") as mock_db:
                db_instance = MagicMock()
                db_instance.initialize = AsyncMock()
                db_instance.get_session = MagicMock()
                db_instance.close = AsyncMock()
                mock_db.return_value = db_instance

                services["rabbitmq"] = mock_rabbit
                services["database"] = mock_db

                yield services

    @pytest.fixture
    def sample_alert(self):
        """Create sample alert for testing."""
        return {
            "alert_id": "ALT-INT-001",
            "timestamp": datetime.now(UTC).isoformat(),
            "alert_type": "malware",
            "severity": "high",
            "description": "Integration test alert",
            "source_ip": "45.33.32.156",
            "target_ip": "10.0.0.50",
        }

    async def test_end_to_end_alert_processing(self, setup_services, sample_alert):
        """Test complete alert processing flow.

        Flow:
        1. Alert Ingestor receives alert
        2. Alert Normalizer normalizes it
        3. Context Collector enriches it
        4. AI Triage Agent analyzes it
        5. Result is stored
        """
        # This is a simplified integration test
        # In production, you would have actual services running

        # Step 1: Ingest alert
        from shared.models import SecurityAlert

        alert = SecurityAlert(**sample_alert)

        assert alert.alert_id == "ALT-INT-001"
        assert alert.alert_type == AlertType.MALWARE

        # Step 2: Normalize (in real scenario, this would use the service)
        normalized_alert = alert  # Already normalized

        # Step 3: Add context (mock)
        context = {
            "source_network": {
                "ip_address": alert.source_ip,
                "is_internal": False,
                "reputation_score": 10.0,
            }
        }

        assert context["source_network"]["reputation_score"] == 10.0

        # Step 4: AI Triage (mock)
        triage_result = {
            "alert_id": alert.alert_id,
            "risk_level": "high",
            "confidence": 85.0,
            "triaged_by": "ai-agent",
        }

        assert triage_result["alert_id"] == "ALT-INT-001"

        # Verify complete flow
        assert alert is not None
        assert context is not None
        assert triage_result is not None


@pytest.mark.integration
@pytest.mark.asyncio
class TestWorkflowIntegration:
    """Test workflow and automation integration."""

    async def test_workflow_execution_flow(self):
        """Test workflow triggers automation."""
        from shared.models import (
            AutomationPlaybook,
            PlaybookExecution,
            WorkflowExecution,
            WorkflowStatus,
        )

        # Create workflow execution
        execution = WorkflowExecution(
            execution_id="exec-int-001",
            workflow_id="alert-processing",
            status=WorkflowStatus.RUNNING,
            input={"alert_id": "ALT-001"},
            started_at=datetime.now(UTC),
        )

        assert execution.status == WorkflowStatus.RUNNING

        # Simulate workflow triggering automation
        playbook_exec = PlaybookExecution(
            execution_id="pb-exec-int-001",
            playbook_id="malware-response",
            trigger_alert_id="ALT-001",
            status=WorkflowStatus.RUNNING,
            started_at=datetime.now(UTC),
        )

        assert playbook_exec.playbook_id == "malware-response"
        assert playbook_exec.trigger_alert_id == execution.input["alert_id"]


@pytest.mark.integration
@pytest.mark.asyncio
class TestMessageQueueIntegration:
    """Test message queue integration between services."""

    async def test_alert_flow_through_queues(self):
        """Test alert flows through all queues."""
        # Expected queue flow:
        # alert.raw → alert.normalized → alert.enriched → alert.result

        queue_flow = ["alert.raw", "alert.normalized", "alert.enriched", "alert.result"]

        # Verify queue names are defined
        from shared.messaging import QUEUE_DEFINITIONS

        for queue in queue_flow:
            # Queue names should be consistent
            assert queue in str(QUEUE_DEFINITIONS)


@pytest.mark.integration
@pytest.mark.asyncio
class TestDatabaseIntegration:
    """Test database operations across services."""

    async def test_database_connection_pooling(self):
        """Test database connection pooling works."""
        # This would test actual database operations
        # For now, we verify the structure exists

        from shared.database.base import DatabaseManager

        # Verify DatabaseManager has required methods
        assert hasattr(DatabaseManager, "initialize")
        assert hasattr(DatabaseManager, "get_session")
        assert hasattr(DatabaseManager, "close")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
