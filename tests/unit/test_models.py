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
Unit tests for shared models.

Tests all Pydantic models in the shared module.
"""

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError
from shared.models import (
    AlertStatus,
    AlertType,
    EnrichedContext,
    LLMRequest,
    NetworkContext,
    RiskLevel,
    SecurityAlert,
    Severity,
    TaskType,
    TriageResult,
    VectorSearchRequest,
    WorkflowExecution,
    WorkflowStatus,
)


class TestSecurityAlert:
    """Test SecurityAlert model."""

    def test_create_valid_alert(self, sample_alert):
        """Test creating a valid alert."""
        assert sample_alert.alert_id == "ALT-TEST-001"
        assert sample_alert.alert_type == AlertType.MALWARE
        assert sample_alert.severity == Severity.HIGH
        assert sample_alert.description == "Test malware alert"

    def test_alert_validation_invalid_ip(self):
        """Test alert validation with invalid IP."""
        with pytest.raises(ValidationError):
            SecurityAlert(
                alert_id="ALT-INVALID",
                timestamp=datetime.now(UTC),
                alert_type=AlertType.MALWARE,
                severity=Severity.HIGH,
                description="Test",
                source_ip="999.999.999.999",  # Invalid IP
            )

    def test_alert_validation_invalid_hash(self):
        """Test alert validation with invalid hash length."""
        with pytest.raises(ValidationError):
            SecurityAlert(
                alert_id="ALT-INVALID",
                timestamp=datetime.now(UTC),
                alert_type=AlertType.MALWARE,
                severity=Severity.HIGH,
                description="Test",
                file_hash="not-a-hash",  # Invalid hash
            )

    def test_alert_validation_future_timestamp(self):
        """Test alert validation rejects future timestamps (> 5 minutes)."""
        future_time = datetime.now(UTC) + timedelta(minutes=10)

        with pytest.raises(ValidationError):
            SecurityAlert(
                alert_id="ALT-FUTURE",
                timestamp=future_time,
                alert_type=AlertType.MALWARE,
                severity=Severity.HIGH,
                description="Test",
            )

    def test_alert_serialization(self, sample_alert):
        """Test alert can be serialized to JSON."""
        alert_dict = sample_alert.model_dump(mode="json")

        assert alert_dict["alert_id"] == "ALT-TEST-001"
        assert alert_dict["alert_type"] == "malware"
        assert alert_dict["severity"] == "high"
        assert isinstance(alert_dict["timestamp"], str)


class TestTriageResult:
    """Test TriageResult model."""

    def test_create_triage_result(self, sample_triage_result):
        """Test creating a valid triage result."""
        assert sample_triage_result.alert_id == "ALT-TEST-001"
        assert sample_triage_result.risk_assessment.risk_level == RiskLevel.HIGH
        assert sample_triage_result.risk_assessment.confidence == 0.85
        assert len(sample_triage_result.remediation_actions) > 0
        assert sample_triage_result.requires_human_review == False

    def test_triage_result_confidence_range(self):
        """Test confidence is between 0 and 100."""
        with pytest.raises(ValidationError):
            TriageResult(
                alert_id="ALT-TEST",
                risk_level=RiskLevel.HIGH,
                confidence=150.0,  # Invalid: > 100
                reasoning="Test",
                recommended_actions=[],
                triaged_by="ai-agent",
                triaged_at=datetime.now(UTC),
            )


class TestWorkflowExecution:
    """Test WorkflowExecution model."""

    def test_create_workflow_execution(self, sample_workflow_execution):
        """Test creating a valid workflow execution."""
        assert sample_workflow_execution.execution_id == "exec-test-001"
        assert sample_workflow_execution.workflow_id == "alert-processing"
        assert sample_workflow_execution.status == WorkflowStatus.RUNNING
        assert sample_workflow_execution.progress == 0.0

    def test_workflow_execution_progress_range(self):
        """Test progress is between 0 and 1."""
        exec = WorkflowExecution(
            execution_id="exec-test",
            workflow_id="test-workflow",
            status=WorkflowStatus.RUNNING,
            input={},
            progress=0.5,
        )

        assert 0.0 <= exec.progress <= 1.0

        with pytest.raises(ValidationError):
            WorkflowExecution(
                execution_id="exec-invalid",
                workflow_id="test",
                status=WorkflowStatus.RUNNING,
                input={},
                progress=1.5,  # Invalid: > 1.0
            )


class TestLLMRequest:
    """Test LLMRequest model."""

    def test_create_llm_request(self):
        """Test creating a valid LLM request."""
        request = LLMRequest(
            task_type=TaskType.TRIAGE,
            messages=[
                {"role": "system", "content": "You are a security analyst."},
                {"role": "user", "content": "Analyze this alert."},
            ],
            temperature=0.7,
            max_tokens=2000,
        )

        assert request.task_type == TaskType.TRIAGE
        assert len(request.messages) == 2
        assert 0.0 <= request.temperature <= 1.0
        assert request.max_tokens == 2000

    def test_llm_request_empty_messages(self):
        """Test LLM request rejects empty messages."""
        with pytest.raises(ValidationError):
            LLMRequest(task_type=TaskType.TRIAGE, messages=[], temperature=0.7)  # Invalid: empty

    def test_llm_request_temperature_range(self):
        """Test temperature is between 0 and 1."""
        with pytest.raises(ValidationError):
            LLMRequest(
                task_type=TaskType.TRIAGE,
                messages=[{"role": "user", "content": "Test"}],
                temperature=1.5,  # Invalid: > 1.0
            )


class TestVectorSearchRequest:
    """Test VectorSearchRequest model."""

    def test_create_search_request(self):
        """Test creating a valid vector search request."""
        request = VectorSearchRequest(query_text="Malware infection", top_k=5, min_similarity=0.75)

        assert request.query_text == "Malware infection"
        assert request.top_k == 5
        assert 0.0 <= request.min_similarity <= 1.0

    def test_search_request_with_alert_data(self):
        """Test search request with alert data."""
        request = VectorSearchRequest(
            alert_data={"alert_type": "malware", "description": "Test alert"},
            top_k=10,
            min_similarity=0.8,
        )

        assert request.alert_data is not None
        assert request.alert_data["alert_type"] == "malware"


class TestEnrichedContext:
    """Test EnrichedContext model."""

    def test_create_enriched_context(self):
        """Test creating enriched context."""
        context = EnrichedContext(
            alert_id="ALT-001",
            source_network=NetworkContext(
                ip_address="45.33.32.156", is_internal=False, reputation_score=10.0
            ),
            target_network=NetworkContext(
                ip_address="10.0.0.50", is_internal=True, reputation_score=50.0
            ),
        )

        assert context.alert_id == "ALT-001"
        assert context.source_network.ip_address == "45.33.32.156"
        assert context.source_network.is_internal is False
        assert context.target_network.is_internal is True


class TestNetworkContext:
    """Test NetworkContext model."""

    def test_create_network_context(self):
        """Test creating network context."""
        context = NetworkContext(
            ip_address="192.168.1.1",
            is_internal=True,
            reputation_score=75.0,
            country="US",
            city="San Francisco",
            asn=15169,
        )

        assert context.ip_address == "192.168.1.1"
        assert context.is_internal is True
        assert context.reputation_score == 75.0
        assert 0.0 <= context.reputation_score <= 100.0

    def test_network_context_internal_ip_detection(self):
        """Test internal IP detection."""
        internal_ips = ["10.0.0.1", "192.168.1.1", "172.16.0.1"]

        for ip in internal_ips:
            context = NetworkContext(ip_address=ip, is_internal=True, reputation_score=50.0)
            assert context.is_internal is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
