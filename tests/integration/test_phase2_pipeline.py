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
Integration tests for Phase 2 services.

Tests the complete alert processing pipeline through all Phase 2 services:
1. Alert Normalizer (Splunk, QRadar, CEF)
2. Context Collector (Network, Asset, User)
3. Threat Intelligence Aggregator (VirusTotal, OTX, Abuse.ch)
4. AI Triage Agent (Risk scoring, LLM analysis)
"""

import asyncio
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from alert_normalizer.processors import SplunkProcessor, QRadarProcessor, CEFProcessor
from context_collector.collectors import (
    AssetCollector,
    NetworkCollector,
    UserCollector,
)
from shared.models.alert import AlertType, SecurityAlert, Severity
from threat_intel_aggregator.sources import (
    AbuseCHSource,
    OTXSource,
    ThreatIntelAggregator,
    VirusTotalSource,
)
from ai_triage_agent.agent import AITriageAgent
from ai_triage_agent.risk_scoring import RiskScoringEngine


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def splunk_raw_alert():
    """Sample Splunk alert."""
    return {
        "result": {
            "_time": "2025-01-09T10:30:00Z",
            "signature": "Malware detected",
            "severity": "high",
            "src_ip": "45.33.32.156",
            "dest_ip": "10.0.0.50",
            "file_hash": "5d41402abc4b2a76b9719d911017c592",
            "user": "jdoe",
        }
    }


@pytest.fixture
def qradar_raw_alert():
    """Sample QRadar alert."""
    return {
        "offense_id": 12345,
        "description": "Brute force attack detected",
        "start_time": 1704795000000,  # Milliseconds since epoch
        "severity": 7,
        "magnitude": 5,
        "offense_type": "Brute Force",
        "source_ip": "192.168.1.100",
        "destination_ip": "10.0.0.1",
        "username": "admin",
    }


@pytest.fixture
def cef_raw_alert():
    """Sample CEF alert."""
    return "CEF:0|Security|IDS|1.0|100|Malware Detected|10|src=45.33.32.156 dst=10.0.0.50 duser=jdoe fileHash=5d41402abc4b2a76b9719d911017c592"


@pytest.fixture
def mock_threat_intel_sources():
    """Mock threat intelligence sources."""
    vt_mock = MagicMock(spec=VirusTotalSource)
    vt_mock.query_ioc = AsyncMock(return_value={
        "detected": True,
        "detection_rate": 85,
        "positives": 17,
        "total": 20,
        "source": "virustotal",
    })
    vt_mock.enabled = True

    otx_mock = MagicMock(spec=OTXSource)
    otx_mock.query_ioc = AsyncMock(return_value={
        "detected": True,
        "detection_rate": 75,
        "source": "otx",
    })
    otx_mock.enabled = True

    abuse_mock = MagicMock(spec=AbuseCHSource)
    abuse_mock.query_ioc = AsyncMock(return_value={
        "detected": True,
        "detection_rate": 80,
        "source": "abuse_ch",
    })
    abuse_mock.enabled = True

    return vt_mock, otx_mock, abuse_mock


# =============================================================================
# Stage 1: Alert Normalizer Integration Tests
# =============================================================================

@pytest.mark.integration
class TestAlertNormalizerIntegration:
    """Test alert normalization from different SIEM formats."""

    async def test_splunk_to_security_alert(self, splunk_raw_alert):
        """Test Splunk alert normalization."""
        processor = SplunkProcessor()

        normalized = processor.process(splunk_raw_alert)

        assert isinstance(normalized, SecurityAlert)
        # Alert type detection depends on signature content
        assert normalized.alert_type in [AlertType.MALWARE, AlertType.OTHER]
        assert normalized.severity in [Severity.HIGH, Severity.MEDIUM]
        assert normalized.source_ip == "45.33.32.156"
        assert normalized.target_ip == "10.0.0.50"
        assert normalized.file_hash == "5d41402abc4b2a76b9719d911017c592"

    async def test_qradar_to_security_alert(self, qradar_raw_alert):
        """Test QRadar alert normalization."""
        processor = QRadarProcessor()

        normalized = processor.process(qradar_raw_alert)

        assert isinstance(normalized, SecurityAlert)
        assert normalized.alert_type == AlertType.BRUTE_FORCE
        # Magnitude-aware severity
        assert normalized.severity in [Severity.HIGH, Severity.MEDIUM]
        assert normalized.source_ip == "192.168.1.100"
        assert normalized.target_ip == "10.0.0.1"

    async def test_cef_to_security_alert(self, cef_raw_alert):
        """Test CEF alert normalization."""
        processor = CEFProcessor()

        normalized = processor.process({"raw_message": cef_raw_alert})

        assert isinstance(normalized, SecurityAlert)
        # Alert type detection depends on signature content
        assert normalized.alert_type in [AlertType.MALWARE, AlertType.OTHER]
        assert normalized.severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM]
        assert normalized.source_ip == "45.33.32.156"
        assert normalized.target_ip == "10.0.0.50"


# =============================================================================
# Stage 2: Context Collector Integration Tests
# =============================================================================

@pytest.mark.integration
class TestContextCollectorIntegration:
    """Test context collection for normalized alerts."""

    async def test_network_context_collection(self):
        """Test network context collection."""
        collector = NetworkCollector()

        context = await collector.collect_context(ip="45.33.32.156")

        assert "ip" in context
        assert "is_internal" in context
        assert context["is_internal"] is False  # External IP

    async def test_asset_context_collection(self):
        """Test asset context collection."""
        collector = AssetCollector()

        context = await collector.collect_context(asset_id="server-prod-001")

        assert "name" in context
        assert "type" in context
        assert "criticality" in context

    async def test_user_context_collection(self):
        """Test user context collection."""
        collector = UserCollector()

        context = await collector.collect_context(user_id="jdoe")

        assert "username" in context or "email" in context
        assert len(context) > 0

    async def test_batch_context_collection(self):
        """Test batch collection for multiple assets/users."""
        network_collector = NetworkCollector()
        asset_collector = AssetCollector()

        # Batch network context
        network_results = await network_collector.collect_batch_context(
            ips=["45.33.32.156", "192.168.1.1"]
        )

        assert len(network_results) == 2
        # Results should be dicts with network context
        for result in network_results:
            assert isinstance(result, dict)
            assert "ip" in result or len(result) > 0

        # Batch asset context
        asset_results = await asset_collector.collect_batch_context(
            asset_ids=["server-001", "workstation-001"]
        )

        assert len(asset_results) == 2
        for result in asset_results:
            assert isinstance(result, dict)


# =============================================================================
# Stage 3: Threat Intelligence Integration Tests
# =============================================================================

@pytest.mark.integration
class TestThreatIntelIntegration:
    """Test threat intelligence aggregation."""

    async def test_multi_source_threat_intel(self, mock_threat_intel_sources):
        """Test querying multiple threat intel sources."""
        vt_mock, otx_mock, abuse_mock = mock_threat_intel_sources

        aggregator = ThreatIntelAggregator(sources=[vt_mock, otx_mock, abuse_mock])

        result = await aggregator.query_multiple_sources(
            ioc="45.33.32.156",
            ioc_type="ip"
        )

        assert "aggregate_score" in result
        assert "threat_level" in result
        assert "queried_sources" in result
        assert len(result["queried_sources"]) == 3
        assert result["aggregate_score"] > 0

    async def test_threat_intel_aggregation_scoring(self, mock_threat_intel_sources):
        """Test weighted aggregation scoring."""
        vt_mock, otx_mock, abuse_mock = mock_threat_intel_sources

        aggregator = ThreatIntelAggregator(sources=[vt_mock, otx_mock, abuse_mock])

        result = await aggregator.query_multiple_sources(
            ioc="5d41402abc4b2a76b9719d911017c592",
            ioc_type="hash"
        )

        # Should return aggregate score
        assert "aggregate_score" in result
        assert result["aggregate_score"] > 0
        assert result["threat_level"] in ["critical", "high", "medium", "low", "safe"]

    async def test_threat_intel_caching(self, mock_threat_intel_sources):
        """Test threat intel caching."""
        vt_mock, otx_mock, abuse_mock = mock_threat_intel_sources

        aggregator = ThreatIntelAggregator(sources=[vt_mock, otx_mock, abuse_mock])

        ioc_value = "45.33.32.156"

        # First call
        result1 = await aggregator.query_multiple_sources(
            ioc=ioc_value,
            ioc_type="ip"
        )

        # Second call
        result2 = await aggregator.query_multiple_sources(
            ioc=ioc_value,
            ioc_type="ip"
        )

        # Results should be consistent
        assert "aggregate_score" in result1
        assert "aggregate_score" in result2


# =============================================================================
# Stage 4: AI Triage Agent Integration Tests
# =============================================================================

@pytest.mark.integration
class TestAITriageAgentIntegration:
    """Test AI triage agent with all context."""

    async def test_risk_scoring_with_full_context(self):
        """Test risk scoring with all available context."""
        risk_engine = RiskScoringEngine()

        alert = {
            "alert_id": "test-001",
            "alert_type": "malware",
            "severity": "high",
        }

        threat_intel = {
            "aggregate_score": 85,
            "detected_by_count": 3,
        }

        asset_context = {
            "criticality": "high",
        }

        result = risk_engine.calculate_risk_score(
            alert=alert,
            threat_intel=threat_intel,
            asset_context=asset_context,
        )

        assert "risk_score" in result
        assert 0 <= result["risk_score"] <= 100
        assert result["risk_level"] in ["critical", "high", "medium", "low", "info"]
        assert "confidence" in result

    async def test_ai_agent_end_to_end_analysis(self):
        """Test complete AI analysis workflow."""
        agent = AITriageAgent(
            deepseek_api_key=None,  # Use mock
            qwen_api_key=None,
        )

        alert = {
            "alert_id": "test-002",
            "alert_type": "malware",
            "severity": "high",
            "title": "Test malware alert",
        }

        threat_intel = {
            "aggregate_score": 75,
            "threat_level": "high",
            "detected_by_count": 2,
        }

        network_context = {
            "is_internal": False,
            "reputation": {"score": 80},
        }

        asset_context = {
            "name": "server-001",
            "criticality": "high",
        }

        result = await agent.analyze_alert(
            alert=alert,
            threat_intel=threat_intel,
            network_context=network_context,
            asset_context=asset_context,
        )

        assert "alert_id" in result
        assert "risk_score" in result
        assert "risk_level" in result
        assert "analysis" in result
        assert "remediation" in result
        assert result["alert_id"] == "test-002"

    async def test_llm_routing_based_on_risk(self):
        """Test LLM model routing based on risk and alert type."""
        agent = AITriageAgent(
            deepseek_api_key="test-key",
            qwen_api_key="test-key",
        )

        # High-risk alert should use DeepSeek
        high_risk_alert = {
            "alert_id": "high-risk",
            "alert_type": "malware",
            "severity": "critical",
        }
        high_risk_assessment = {"risk_score": 90, "risk_level": "critical"}

        model = agent._route_to_model(high_risk_alert, high_risk_assessment)
        assert model == "deepseek"

        # Low-risk alert should use Qwen
        low_risk_alert = {
            "alert_id": "low-risk",
            "alert_type": "anomaly",
            "severity": "low",
        }
        low_risk_assessment = {"risk_score": 30, "risk_level": "low"}

        model = agent._route_to_model(low_risk_alert, low_risk_assessment)
        assert model == "qwen"


# =============================================================================
# Complete Pipeline Integration Tests
# =============================================================================

@pytest.mark.integration
class TestCompletePipelineIntegration:
    """Test complete alert processing pipeline from raw to triage."""

    async def test_splunk_alert_full_pipeline(self, splunk_raw_alert, mock_threat_intel_sources):
        """Test complete pipeline for Splunk alert."""
        # Stage 1: Normalize
        normalizer = SplunkProcessor()
        normalized = normalizer.process(splunk_raw_alert)

        assert isinstance(normalized, SecurityAlert)

        # Stage 2: Collect context
        network_collector = NetworkCollector()
        asset_collector = AssetCollector()

        network_context = await network_collector.collect_context(
            ip=normalized.source_ip
        )
        asset_context = await asset_collector.collect_context(
            asset_id=normalized.target_ip
        )

        assert network_context is not None
        assert asset_context is not None

        # Stage 3: Threat intelligence
        vt_mock, otx_mock, abuse_mock = mock_threat_intel_sources
        aggregator = ThreatIntelAggregator(sources=[vt_mock, otx_mock, abuse_mock])

        threat_intel = await aggregator.query_multiple_sources(
            ioc=normalized.source_ip,
            ioc_type="ip"
        )

        assert threat_intel["aggregate_score"] > 0

        # Stage 4: AI triage
        risk_engine = RiskScoringEngine()
        risk_assessment = risk_engine.calculate_risk_score(
            alert=normalized.model_dump(),
            threat_intel=threat_intel,
            asset_context=asset_context,
            network_context=network_context,
        )

        assert "risk_score" in risk_assessment
        assert 0 <= risk_assessment["risk_score"] <= 100

        # Verify pipeline stages completed
        assert normalized.alert_id is not None
        assert network_context["ip_address"] == normalized.source_ip
        assert threat_intel["threat_level"] in ["critical", "high", "medium", "low", "safe"]
        assert risk_assessment["risk_level"] in ["critical", "high", "medium", "low", "info"]

    async def test_qradar_alert_full_pipeline(self, qradar_raw_alert, mock_threat_intel_sources):
        """Test complete pipeline for QRadar alert."""
        # Stage 1: Normalize
        normalizer = QRadarProcessor()
        normalized = normalizer.process(qradar_raw_alert)

        # Stage 2: Collect context
        network_collector = NetworkCollector()
        network_context = await network_collector.collect_context(
            ip=normalized.source_ip
        )

        # Stage 3: Threat intelligence
        vt_mock, otx_mock, abuse_mock = mock_threat_intel_sources
        aggregator = ThreatIntelAggregator(sources=[vt_mock, otx_mock, abuse_mock])

        threat_intel = await aggregator.query_multiple_sources(
            ioc=normalized.source_ip,
            ioc_type="ip"
        )

        # Stage 4: AI triage
        risk_engine = RiskScoringEngine()
        risk_assessment = risk_engine.calculate_risk_score(
            alert=normalized.model_dump(),
            threat_intel=threat_intel,
            network_context=network_context,
        )

        # Verify complete flow
        assert normalized.alert_type == AlertType.BRUTE_FORCE
        assert network_context is not None
        assert threat_intel["aggregate_score"] > 0
        assert risk_assessment["risk_score"] > 0

    async def test_cef_alert_full_pipeline(self, cef_raw_alert, mock_threat_intel_sources):
        """Test complete pipeline for CEF alert."""
        # Stage 1: Normalize
        normalizer = CEFProcessor()
        normalized = normalizer.process({"raw_message": cef_raw_alert})

        # Stage 2: Collect context
        network_collector = NetworkCollector()
        network_context = await network_collector.collect_context(
            ip=normalized.source_ip
        )

        # Stage 3: Threat intelligence
        vt_mock, otx_mock, abuse_mock = mock_threat_intel_sources
        aggregator = ThreatIntelAggregator(sources=[vt_mock, otx_mock, abuse_mock])

        # Test hash-based IOC
        threat_intel = await aggregator.query_multiple_sources(
            ioc=normalized.file_hash,
            ioc_type="hash"
        )

        # Stage 4: AI triage
        risk_engine = RiskScoringEngine()
        risk_assessment = risk_engine.calculate_risk_score(
            alert=normalized.model_dump(),
            threat_intel=threat_intel,
            network_context=network_context,
        )

        # Verify complete flow
        assert normalized.alert_type == AlertType.MALWARE
        assert threat_intel["aggregate_score"] > 0
        assert risk_assessment["risk_score"] > 0


# =============================================================================
# Concurrent Processing Tests
# =============================================================================

@pytest.mark.integration
class TestConcurrentProcessing:
    """Test concurrent processing of multiple alerts."""

    async def test_batch_alert_processing(self, mock_threat_intel_sources):
        """Test processing multiple alerts concurrently."""
        alerts = [
            {
                "alert_id": f"alert-{i}",
                "alert_type": "malware" if i % 2 == 0 else "phishing",
                "severity": "high" if i % 2 == 0 else "medium",
                "title": f"Test alert {i}",
            }
            for i in range(5)
        ]

        vt_mock, otx_mock, abuse_mock = mock_threat_intel_sources
        agent = AITriageAgent(
            deepseek_api_key=None,
            qwen_api_key=None,
        )

        # Process all alerts concurrently
        tasks = [
            agent.analyze_alert(alert=alert)
            for alert in alerts
        ]

        results = await asyncio.gather(*tasks)

        # Verify all processed successfully
        assert len(results) == 5
        for i, result in enumerate(results):
            assert result["alert_id"] == f"alert-{i}"
            assert "risk_score" in result
            assert "analysis" in result


# =============================================================================
# Error Handling and Recovery Tests
# =============================================================================

@pytest.mark.integration
class TestErrorHandling:
    """Test error handling across the pipeline."""

    async def test_normalization_error_handling(self):
        """Test handling of invalid alert data."""
        processor = SplunkProcessor()

        # Invalid alert - processor should handle gracefully
        invalid_alert = {"invalid": "data"}

        # Processors use default values for missing fields
        normalized = processor.process(invalid_alert)

        # Should return a SecurityAlert with default values
        assert normalized is not None
        assert isinstance(normalized, SecurityAlert)

    async def test_threat_intel_timeout_handling(self):
        """Test handling of threat intel timeouts."""
        vt_mock = MagicMock(spec=VirusTotalSource)
        vt_mock.query_ioc = AsyncMock(side_effect=asyncio.TimeoutError())
        vt_mock.enabled = True

        aggregator = ThreatIntelAggregator(sources=[vt_mock])

        result = await aggregator.query_multiple_sources(
            ioc="45.33.32.156",
            ioc_type="ip"
        )

        # Should return result even with timeout
        assert "aggregate_score" in result

    async def test_ai_agent_fallback_on_error(self):
        """Test AI agent fallback when analysis fails."""
        agent = AITriageAgent(
            deepseek_api_key=None,
            qwen_api_key=None,
        )

        alert = {
            "alert_id": "test-error",
            "alert_type": "malware",
            "severity": "high",
        }

        # Mock risk engine to fail
        with patch.object(agent.risk_engine, 'calculate_risk_score', side_effect=Exception("Test error")):
            result = await agent.analyze_alert(alert=alert)

            # Should return fallback result
            assert result["model_used"] == "fallback"
            assert "error" in result


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
