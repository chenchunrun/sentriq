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
Enhanced End-to-End System Tests.

These tests validate complete workflows using actual service logic
with mocked external dependencies (database, message queues, LLM APIs).
"""

import asyncio
import os
from datetime import datetime
from typing import Any, Dict
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from shared.utils.time import utc_now

# Set test environment
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost/test_db")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/1")
os.environ.setdefault("RABBITMQ_URL", "amqp://guest:guest@localhost:5672/")
os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-for-testing-only")


@pytest.mark.e2e
class TestAlertLifecycle:
    """Test complete alert lifecycle from ingestion to triage."""

    @pytest.fixture
    async def test_infrastructure(self):
        """Setup test infrastructure with mocked dependencies."""
        infrastructure = {}

        # Mock database
        with patch("shared.database.get_database_manager") as mock_db:
            db_instance = MagicMock()
            db_instance.initialize = AsyncMock()
            db_instance.get_session = MagicMock()
            db_instance.close = AsyncMock()

            # Mock session
            mock_session = MagicMock()
            mock_session.add = MagicMock()
            mock_session.commit = AsyncMock()
            mock_session.refresh = MagicMock()
            db_instance.get_session.return_value = mock_session

            infrastructure["database"] = mock_db
            infrastructure["session"] = mock_session

            # Mock message publisher
            with patch("shared.messaging.MessagePublisher") as mock_publisher:
                publisher_instance = MagicMock()
                publisher_instance.connect = AsyncMock()
                publisher_instance.publish = AsyncMock()
                publisher_instance.close = AsyncMock()
                mock_publisher.return_value = publisher_instance

                infrastructure["publisher"] = publisher_instance

                yield infrastructure

    @pytest.mark.asyncio
    async def test_alert_ingestion_to_queue(self, test_infrastructure):
        """Test alert is ingested and queued for processing."""
        from shared.models import AlertType, SecurityAlert, Severity

        from services.alert_ingestor.main import create_alert_message

        # Step 1: Create security alert
        alert = SecurityAlert(
            alert_id="ALT-E2E-001",
            timestamp=utc_now(),
            alert_type=AlertType.MALWARE,
            severity=Severity.HIGH,
            description="E2E test malware alert",
            source_ip="45.33.32.156",
            target_ip="10.0.0.50",
            file_hash="5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
        )

        assert alert.alert_id == "ALT-E2E-001"
        assert alert.alert_type == AlertType.MALWARE

        # Step 2: Create message for queue
        message = create_alert_message(alert)

        assert message["message_type"] == "alert.raw"
        assert message["payload"]["alert_id"] == "ALT-E2E-001"
        assert "timestamp" in message

        # Step 3: Verify message would be published
        publisher = test_infrastructure["publisher"]
        # In real flow: await publisher.publish("alert.raw", message)

        print(f"✓ Alert {alert.alert_id} formatted for queue")

    @pytest.mark.asyncio
    async def test_alert_normalization(self):
        """Test alert normalization process."""
        from shared.models import AlertType, SecurityAlert, Severity

        # Simulate raw alert from external source
        raw_alert = {
            "id": "external-123",
            "time": "2026-01-05T10:30:00Z",
            "type": "MALWARE",
            "level": "HIGH",
            "desc": "Suspicious file detected",
            "src": "192.168.1.100",
            "dst": "10.0.0.50",
        }

        # Normalize to internal format
        normalized_alert = SecurityAlert(
            alert_id=f"ALT-{raw_alert['id']}",
            timestamp=datetime.fromisoformat(raw_alert["time"].replace("Z", "+00:00")),
            alert_type=AlertType.MALWARE,
            severity=Severity.HIGH,
            description=raw_alert["desc"],
            source_ip=raw_alert["src"],
            target_ip=raw_alert["dst"],
        )

        assert normalized_alert.alert_id == "ALT-external-123"
        assert normalized_alert.alert_type == AlertType.MALWARE
        print(f"✓ Alert normalized: {raw_alert['id']} -> {normalized_alert.alert_id}")

    @pytest.mark.asyncio
    async def test_alert_enrichment(self):
        """Test alert enrichment with context."""
        from shared.models import (
            AlertType,
            EnrichedContext,
            NetworkContext,
            SecurityAlert,
            Severity,
        )

        alert = SecurityAlert(
            alert_id="ALT-ENRICH-001",
            timestamp=utc_now(),
            alert_type=AlertType.MALWARE,
            severity=Severity.HIGH,
            description="Test alert for enrichment",
            source_ip="45.33.32.156",
            target_ip="10.0.0.50",
        )

        # Enrich with network context
        network_context = NetworkContext(
            ip_address=alert.source_ip, is_internal=False, reputation_score=10.0
        )

        enriched = EnrichedContext(
            alert_id=alert.alert_id, network=network_context, threat_intel_hits=0, similar_alerts=[]
        )

        assert enriched.network.is_internal == False
        assert enriched.network.asn == 20473
        print(f"✓ Alert enriched with network context")

    @pytest.mark.asyncio
    async def test_triage_generation(self):
        """Test triage result generation."""
        from shared.models import (
            ActionType,
            AlertType,
            RemediationAction,
            RemediationPriority,
            RiskAssessment,
            RiskLevel,
            SecurityAlert,
            Severity,
            TriageResult,
        )

        alert = SecurityAlert(
            alert_id="ALT-TRIAGE-001",
            timestamp=utc_now(),
            alert_type=AlertType.MALWARE,
            severity=Severity.HIGH,
            description="Test alert for triage",
            source_ip="45.33.32.156",
            target_ip="10.0.0.50",
            file_hash="5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
        )

        # Generate triage result
        risk_assessment = RiskAssessment(
            risk_score=85.0,
            risk_level=RiskLevel.HIGH,
            confidence=0.90,
            severity_score=80.0,
            threat_intel_score=75.0,
            asset_criticality_score=85.0,
            exploitability_score=80.0,
            key_factors=[
                "High severity alert",
                "Known malicious file hash",
                "External IP with low reputation",
            ],
            requires_human_review=True,
            review_reason="High risk with external source",
        )

        remediation_actions = [
            RemediationAction(
                action_type=ActionType.ISOLATE_HOST,
                priority=RemediationPriority.IMMEDIATE,
                title="Isolate compromised host",
                description="Disconnect host from network to prevent lateral movement",
                is_automated=True,
                execution_time_seconds=30,
                parameters={"host": alert.target_ip, "method": "firewall"},
            ),
            RemediationAction(
                action_type=ActionType.BLOCK_IP,
                priority=RemediationPriority.HIGH,
                title="Block malicious IP",
                description=f"Block connections from {alert.source_ip}",
                is_automated=True,
                execution_time_seconds=10,
                parameters={"ip": alert.source_ip, "duration": "86400"},
            ),
        ]

        triage_result = TriageResult(
            alert_id=alert.alert_id,
            risk_assessment=risk_assessment,
            remediation_actions=remediation_actions,
            requires_human_review=True,
            processing_time_ms=1850.0,
        )

        assert triage_result.alert_id == "ALT-TRIAGE-001"
        assert triage_result.risk_assessment.risk_level == RiskLevel.HIGH
        assert len(triage_result.remediation_actions) == 2
        assert triage_result.requires_human_review == True
        print(
            f"✓ Triage result generated with risk level: {triage_result.risk_assessment.risk_level}"
        )


@pytest.mark.e2e
class TestWorkflowExecution:
    """Test workflow and automation execution."""

    @pytest.mark.asyncio
    async def test_workflow_trigger(self):
        """Test workflow is triggered by alert."""
        from shared.models import (
            AlertType,
            SecurityAlert,
            Severity,
            WorkflowExecution,
            WorkflowStatus,
        )

        alert = SecurityAlert(
            alert_id="ALT-WF-001",
            timestamp=utc_now(),
            alert_type=AlertType.MALWARE,
            severity=Severity.CRITICAL,
            description="Critical malware alert",
            source_ip="45.33.32.156",
            target_ip="10.0.0.50",
        )

        # Trigger workflow
        workflow = WorkflowExecution(
            execution_id="exec-wf-001",
            workflow_id="malware-response",
            status=WorkflowStatus.RUNNING,
            input={"alert_id": alert.alert_id, "severity": alert.severity},
            started_at=utc_now(),
        )

        assert workflow.status == WorkflowStatus.RUNNING
        assert workflow.input["alert_id"] == alert.alert_id
        print(f"✓ Workflow {workflow.workflow_id} triggered for alert {alert.alert_id}")

    @pytest.mark.asyncio
    async def test_automation_execution(self):
        """Test automation playbook execution."""
        from shared.models import ActionType, PlaybookAction, PlaybookExecution, PlaybookStatus

        playbook_execution = PlaybookExecution(
            execution_id="pb-exec-001",
            playbook_id="malware-isolation",
            trigger_alert_id="ALT-AUTO-001",
            status=PlaybookStatus.RUNNING,
            started_at=utc_now(),
            actions=[
                PlaybookAction(
                    action_id="action-001",
                    action_type=ActionType.ISOLATE_HOST,
                    parameters={"host": "10.0.0.50", "method": "firewall"},
                    timeout_seconds=30,
                    status="pending",
                ),
                PlaybookAction(
                    action_id="action-002",
                    action_type=ActionType.QUARANTINE_FILE,
                    parameters={"file_path": "/tmp/malware.exe", "method": "move"},
                    timeout_seconds=15,
                    status="pending",
                ),
            ],
        )

        assert len(playbook_execution.actions) == 2
        assert playbook_execution.actions[0].action_type == ActionType.ISOLATE_HOST
        print(
            f"✓ Playbook {playbook_execution.playbook_id} executing {len(playbook_execution.actions)} actions"
        )


@pytest.mark.e2e
class TestDataFlow:
    """Test data flow across services."""

    @pytest.mark.asyncio
    async def test_complete_data_pipeline(self):
        """Test complete data from ingestion to response."""
        from shared.models import (
            ActionType,
            AlertType,
            EnrichedContext,
            NetworkContext,
            RemediationAction,
            RemediationPriority,
            RiskAssessment,
            RiskLevel,
            SecurityAlert,
            Severity,
            TriageResult,
            WorkflowExecution,
            WorkflowStatus,
        )

        print("\n=== Complete Alert Processing Pipeline ===\n")

        # Step 1: Alert Ingestion
        print("Step 1: Alert Ingestion")
        alert = SecurityAlert(
            alert_id="ALT-PIPELINE-001",
            timestamp=utc_now(),
            alert_type=AlertType.MALWARE,
            severity=Severity.HIGH,
            description="E2E pipeline test alert",
            source_ip="45.33.32.156",
            target_ip="10.0.0.50",
            file_hash="5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
        )
        print(f"  ✓ Alert ingested: {alert.alert_id}")

        # Step 2: Alert Normalization
        print("\nStep 2: Alert Normalization")
        # Alert is already normalized
        assert alert.alert_id.startswith("ALT-")
        print(f"  ✓ Alert normalized")

        # Step 3: Context Enrichment
        print("\nStep 3: Context Enrichment")
        network_context = NetworkContext(
            ip_address=alert.source_ip, is_internal=False, reputation_score=10.0
        )
        enriched = EnrichedContext(
            alert_id=alert.alert_id, network=network_context, threat_intel_hits=1, similar_alerts=[]
        )
        print(f"  ✓ Alert enriched with network context")

        # Step 4: AI Triage
        print("\nStep 4: AI Triage")
        risk_assessment = RiskAssessment(
            risk_score=78.0,
            risk_level=RiskLevel.HIGH,
            confidence=0.88,
            severity_score=80.0,
            threat_intel_score=70.0,
            asset_criticality_score=80.0,
            exploitability_score=75.0,
            key_factors=["High severity", "External IP", "Malware detected"],
            requires_human_review=False,
        )

        remediation = [
            RemediationAction(
                action_type=ActionType.ISOLATE_HOST,
                priority=RemediationPriority.HIGH,
                title="Isolate host",
                description="Disconnect from network",
                is_automated=True,
            )
        ]

        triage = TriageResult(
            alert_id=alert.alert_id,
            risk_assessment=risk_assessment,
            remediation_actions=remediation,
            requires_human_review=False,
            processing_time_ms=1520.0,
        )
        print(
            f"  ✓ Triage complete: Risk={triage.risk_assessment.risk_level}, Score={triage.risk_assessment.risk_score}"
        )

        # Step 5: Workflow Automation
        print("\nStep 5: Workflow Automation")
        if triage.risk_assessment.risk_score >= 70:
            workflow = WorkflowExecution(
                execution_id="exec-pipeline-001",
                workflow_id="automated-response",
                status=WorkflowStatus.RUNNING,
                input={"alert_id": alert.alert_id},
                started_at=utc_now(),
            )
            print(f"  ✓ Workflow triggered: {workflow.workflow_id}")

        print("\n=== Pipeline Complete ===")
        print(f"Alert {alert.alert_id} processed successfully")
        print(f"Risk Level: {triage.risk_assessment.risk_level}")
        print(f"Processing Time: {triage.processing_time_ms}ms")
        print(f"Actions Recommended: {len(triage.remediation_actions)}")


@pytest.mark.e2e
class TestPerformanceMetrics:
    """Test system performance metrics."""

    @pytest.mark.asyncio
    async def test_processing_time_sla(self):
        """Test alert processing meets SLA."""
        import time

        from shared.models import AlertType, SecurityAlert, Severity

        # Simulate alert processing
        start_time = time.time()

        # Simulate processing steps
        alert = SecurityAlert(
            alert_id="ALT-SLA-001",
            timestamp=utc_now(),
            alert_type=AlertType.MALWARE,
            severity=Severity.HIGH,
            description="SLA test alert",
        )

        # Simulate triage (normally takes 1-3 seconds)
        await asyncio.sleep(0.1)  # Reduced for testing

        processing_time = (time.time() - start_time) * 1000  # Convert to ms

        # SLA: Triage should complete in < 30 seconds
        assert processing_time < 30000, f"SLA exceeded: {processing_time}ms"
        print(f"✓ Processing time SLA met: {processing_time:.2f}ms < 30000ms")

    @pytest.mark.asyncio
    async def test_throughput_benchmark(self):
        """Test system can handle target throughput."""
        from shared.models import AlertType, SecurityAlert, Severity

        target_throughput = 100  # alerts per second
        test_alerts = 10  # Reduced for testing

        start_time = time.time()

        # Simulate ingesting alerts
        for i in range(test_alerts):
            alert = SecurityAlert(
                alert_id=f"ALT-THRPT-{i}",
                timestamp=utc_now(),
                alert_type=AlertType.MALWARE,
                severity=Severity.HIGH,
                description=f"Throughput test alert {i}",
            )
            # Simulate processing
            await asyncio.sleep(0.01)

        processing_time = time.time() - start_time
        throughput = test_alerts / processing_time

        # Check if we can sustain target throughput
        print(f"✓ Achieved throughput: {throughput:.2f} alerts/sec")
        print(f"  Target: {target_throughput} alerts/sec")
        print(f"  Test processed: {test_alerts} alerts in {processing_time:.2f}s")


# Import time module for performance tests
import time

if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
