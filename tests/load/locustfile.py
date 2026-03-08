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
Performance tests for Security Triage System using Locust.

Tests the system's ability to handle concurrent alert processing
with target performance of 100 alerts/second and P95 latency < 3 seconds.
"""

import asyncio
import json
import random
from datetime import UTC, datetime
from typing import Dict

from locust import HttpUser, between, task
from locust.runners import MasterRunner

from alert_normalizer.processors import SplunkProcessor, QRadarProcessor, CEFProcessor
from context_collector.collectors import AssetCollector, NetworkCollector, UserCollector
from threat_intel_aggregator.sources import ThreatIntelAggregator, VirusTotalSource, OTXSource, AbuseCHSource
from ai_triage_agent.agent import AITriageAgent
from shared.models.alert import AlertType, Severity


# =============================================================================
# Test Data Generators
# =============================================================================

class TestDataGenerator:
    """Generate realistic test data for load testing."""

    ALERT_TYPES = ["malware", "phishing", "brute_force", "data_exfiltration", "anomaly"]
    SEVERITIES = ["critical", "high", "medium", "low", "info"]
    SOURCE_IPS = ["45.33.32.156", "192.168.1.100", "10.0.0.50", "172.16.0.1", "8.8.8.8"]
    TARGET_IPS = ["10.0.0.1", "10.0.0.50", "192.168.1.1", "172.16.0.100"]

    FILE_HASHES = [
        "5d41402abc4b2a76b9719d911017c592",  # MD5
        "e99a18c428cb38d5f260853678922e03",  # MD5
        "44afb36dc7b35dd2afec54d7c450d5d9",  # MD5
    ]

    MALWARE_KEYWORDS = ["trojan", "ransomware", "malware", "virus", "spyware", "worm", "rootkit"]
    PHISHING_KEYWORDS = ["phishing", "credential", "spear", "whaling", "vishing"]
    BRUTE_FORCE_KEYWORDS = ["brute", "force", "authentication", "login", "ssh", "rdp", "smb"]

    @classmethod
    def generate_splunk_alert(cls, alert_id: int) -> Dict:
        """Generate realistic Splunk alert."""
        alert_type = random.choice(cls.ALERT_TYPES)
        severity = random.choice(cls.SEVERITIES)

        # Add signature keywords based on alert type
        if alert_type == "malware":
            signature = f"{random.choice(cls.MALWARE_KEYWORDS)} detected".title()
        elif alert_type == "phishing":
            signature = f"{random.choice(cls.PHISHING_KEYWORDS)} attempt".title()
        elif alert_type == "brute_force":
            signature = f"{random.choice(cls.BRUTE_FORCE_KEYWORDS)} attack".title()
        else:
            signature = f"Security {alert_type} detected".title()

        return {
            "result": {
                "_time": datetime.now(UTC).isoformat(),
                "signature": signature,
                "severity": severity,
                "src_ip": random.choice(cls.SOURCE_IPS),
                "dest_ip": random.choice(cls.TARGET_IPS),
                "file_hash": random.choice(cls.FILE_HASHES) if alert_type == "malware" else None,
                "user": f"user{random.randint(1, 100)}",
            }
        }

    @classmethod
    def generate_qradar_alert(cls, alert_id: int) -> Dict:
        """Generate realistic QRadar alert."""
        return {
            "offense_id": 10000 + alert_id,
            "description": f"Security alert {alert_id}",
            "start_time": int(datetime.now(UTC).timestamp() * 1000),  # Milliseconds
            "severity": random.randint(1, 10),
            "magnitude": random.randint(1, 10),
            "offense_type": random.choice(cls.ALERT_TYPES).replace("_", " ").title(),
            "source_ip": random.choice(cls.SOURCE_IPS),
            "destination_ip": random.choice(cls.TARGET_IPS),
            "username": f"user{random.randint(1, 100)}",
        }

    @classmethod
    def generate_cef_alert(cls, alert_id: int) -> Dict:
        """Generate realistic CEF alert."""
        alert_type = random.choice(cls.ALERT_TYPES)
        severity = random.randint(1, 10)

        return {
            "raw_message": f"CEF:0|Security|IDS|1.0|{1000 + alert_id}|{alert_type.title()} Detected|{severity}|src={random.choice(cls.SOURCE_IPS)} dst={random.choice(cls.TARGET_IPS)} duser=user{random.randint(1, 100)}"
        }


# =============================================================================
# Performance Test User
# =============================================================================

class SecurityTriageUser(HttpUser):
    """
    Simulates users submitting security alerts for processing.

    Weight is 1-3 seconds between tasks to simulate realistic traffic patterns.
    """

    wait_time = between(1, 3)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Initialize processors (reuse for performance)
        self.splunk_processor = SplunkProcessor()
        self.qradar_processor = QRadarProcessor()
        self.cef_processor = CEFProcessor()
        self.network_collector = NetworkCollector()
        self.asset_collector = AssetCollector()
        self.user_collector = UserCollector()

        # AI Agent (mock mode for testing)
        self.ai_agent = AITriageAgent(
            deepseek_api_key=None,  # Use mock
            qwen_api_key=None,
        )

    @task(3)
    def process_splunk_alert(self):
        """Process Splunk alert - most common format."""
        alert_id = random.randint(1, 100000)
        raw_alert = TestDataGenerator.generate_splunk_alert(alert_id)

        # Measure normalization time
        start = datetime.now(UTC)

        try:
            normalized = self.splunk_processor.process(raw_alert)

            # Measure processing time
            processing_time = (datetime.now(UTC) - start).total_seconds()

            # Record metrics
            self.environment.stats.log_request(
                method="SPLUNK_NORMALIZE",
                name="/alert/splunk/normalize",
                response_time=processing_time * 1000,  # Convert to ms
                response_length=1,  # Success
                exception=None,
            )

        except Exception as e:
            processing_time = (datetime.now(UTC) - start).total_seconds()
            self.environment.stats.log_request(
                method="SPLUNK_NORMALIZE",
                name="/alert/splunk/normalize",
                response_time=processing_time * 1000,
                response_length=0,  # Failure
                exception=e,
            )

    @task(2)
    def process_qradar_alert(self):
        """Process QRadar alert."""
        alert_id = random.randint(1, 100000)
        raw_alert = TestDataGenerator.generate_qradar_alert(alert_id)

        start = datetime.now(UTC)

        try:
            normalized = self.qradar_processor.process(raw_alert)
            processing_time = (datetime.now(UTC) - start).total_seconds()

            self.environment.stats.log_request(
                method="QRADAR_NORMALIZE",
                name="/alert/qradar/normalize",
                response_time=processing_time * 1000,
                response_length=1,
                exception=None,
            )

        except Exception as e:
            processing_time = (datetime.now(UTC) - start).total_seconds()
            self.environment.stats.log_request(
                method="QRADAR_NORMALIZE",
                name="/alert/qradar/normalize",
                response_time=processing_time * 1000,
                response_length=0,
                exception=e,
            )

    @task(1)
    def process_cef_alert(self):
        """Process CEF alert."""
        alert_id = random.randint(1, 100000)
        raw_alert = TestDataGenerator.generate_cef_alert(alert_id)

        start = datetime.now(UTC)

        try:
            normalized = self.cef_processor.process(raw_alert)
            processing_time = (datetime.now(UTC) - start).total_seconds()

            self.environment.stats.log_request(
                method="CEF_NORMALIZE",
                name="/alert/cef/normalize",
                response_time=processing_time * 1000,
                response_length=1,
                exception=None,
            )

        except Exception as e:
            processing_time = (datetime.now(UTC) - start).total_seconds()
            self.environment.stats.log_request(
                method="CEF_NORMALIZE",
                name="/alert/cef/normalize",
                response_time=processing_time * 1000,
                response_length=0,
                exception=e,
            )

    @task(2)
    def collect_network_context(self):
        """Test network context collection performance."""
        ip = random.choice(TestDataGenerator.SOURCE_IPS)

        start = datetime.now(UTC)

        try:
            context = asyncio.run(self.network_collector.collect_context(ip=ip))
            processing_time = (datetime.now(UTC) - start).total_seconds()

            self.environment.stats.log_request(
                method="NETWORK_CONTEXT",
                name="/context/network",
                response_time=processing_time * 1000,
                response_length=1,
                exception=None,
            )

        except Exception as e:
            processing_time = (datetime.now(UTC) - start).total_seconds()
            self.environment.stats.log_request(
                method="NETWORK_CONTEXT",
                name="/context/network",
                response_time=processing_time * 1000,
                response_length=0,
                exception=e,
            )

    @task(1)
    def ai_triage_analysis(self):
        """Test AI triage analysis performance (mock mode)."""
        alert = {
            "alert_id": f"alert-{random.randint(1, 100000)}",
            "alert_type": random.choice(TestDataGenerator.ALERT_TYPES),
            "severity": random.choice(TestDataGenerator.SEVERITIES),
            "title": "Performance test alert",
        }

        start = datetime.now(UTC)

        try:
            result = asyncio.run(self.ai_agent.analyze_alert(alert=alert))
            processing_time = (datetime.now(UTC) - start).total_seconds()

            self.environment.stats.log_request(
                method="AI_TRIAGE",
                name="/triage/analyze",
                response_time=processing_time * 1000,
                response_length=1,
                exception=None,
            )

        except Exception as e:
            processing_time = (datetime.now(UTC) - start).total_seconds()
            self.environment.stats.log_request(
                method="AI_TRIAGE",
                name="/triage/analyze",
                response_time=processing_time * 1000,
                response_length=0,
                exception=e,
            )


# =============================================================================
# Performance Test User - Full Pipeline
# =============================================================================

class FullPipelineUser(HttpUser):
    """
    Tests the complete alert processing pipeline from ingestion to triage.

    This simulates the real-world scenario where alerts flow through
    all services sequentially.
    """

    wait_time = between(1, 2)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Initialize all processors and services
        self.splunk_processor = SplunkProcessor()
        self.network_collector = NetworkCollector()
        self.ai_agent = AITriageAgent(deepseek_api_key=None, qwen_api_key=None)

    @task
    def full_alert_pipeline(self):
        """Test complete alert processing pipeline."""
        # Generate alert
        alert_id = random.randint(1, 100000)
        raw_alert = TestDataGenerator.generate_splunk_alert(alert_id)

        total_start = datetime.now(UTC)

        try:
            # Stage 1: Normalize
            stage1_start = datetime.now(UTC)
            normalized = self.splunk_processor.process(raw_alert)
            stage1_time = (datetime.now(UTC) - stage1_start).total_seconds()

            # Stage 2: Context collection
            stage2_start = datetime.now(UTC)
            if normalized.source_ip:
                network_context = asyncio.run(
                    self.network_collector.collect_context(ip=normalized.source_ip)
                )
            stage2_time = (datetime.now(UTC) - stage2_start).total_seconds()

            # Stage 3: AI Triage
            stage3_start = datetime.now(UTC)
            triage_result = asyncio.run(
                self.ai_agent.analyze_alert(alert=normalized.model_dump())
            )
            stage3_time = (datetime.now(UTC) - stage3_start).total_seconds()

            # Total time
            total_time = (datetime.now(UTC) - total_start).total_seconds()

            # Log metrics for each stage
            self.environment.stats.log_request(
                method="PIPELINE_STAGE1_NORMALIZE",
                name="/pipeline/stage1",
                response_time=stage1_time * 1000,
                response_length=1,
                exception=None,
            )

            self.environment.stats.log_request(
                method="PIPELINE_STAGE2_CONTEXT",
                name="/pipeline/stage2",
                response_time=stage2_time * 1000,
                response_length=1,
                exception=None,
            )

            self.environment.stats.log_request(
                method="PIPELINE_STAGE3_TRIAGE",
                name="/pipeline/stage3",
                response_time=stage3_time * 1000,
                response_length=1,
                exception=None,
            )

            # Log total pipeline time
            self.environment.stats.log_request(
                method="FULL_PIPELINE",
                name="/pipeline/full",
                response_time=total_time * 1000,
                response_length=1,
                exception=None,
            )

            # Performance assertion: P95 should be < 3000ms
            if total_time > 3.0:
                self.environment.stats.log_request(
                    method="FULL_PIPELINE_SLOW",
                    name="/pipeline/slow",
                    response_time=total_time * 1000,
                    response_length=0,  # Flag as slow
                    exception=None,
                )

        except Exception as e:
            total_time = (datetime.now(UTC) - total_start).total_seconds()
            self.environment.stats.log_request(
                method="FULL_PIPELINE_ERROR",
                name="/pipeline/error",
                response_time=total_time * 1000,
                response_length=0,
                exception=e,
            )


# =============================================================================
# Stress Test User
# =============================================================================

class StressTestUser(HttpUser):
    """
    High-intensity stress test user.

    Sends requests with minimal wait time to test system limits.
    """

    wait_time = between(0.1, 0.5)  # Much faster than normal users

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.splunk_processor = SplunkProcessor()
        self.ai_agent = AITriageAgent(deepseek_api_key=None, qwen_api_key=None)

    @task
    def rapid_alert_processing(self):
        """Rapid alert processing for stress testing."""
        alert_id = random.randint(1, 100000)
        raw_alert = TestDataGenerator.generate_splunk_alert(alert_id)

        start = datetime.now(UTC)

        try:
            # Quick normalization
            normalized = self.splunk_processor.process(raw_alert)

            # Quick AI analysis
            result = asyncio.run(
                self.ai_agent.analyze_alert(alert=normalized.model_dump())
            )

            processing_time = (datetime.now(UTC) - start).total_seconds()

            self.environment.stats.log_request(
                method="STRESS_TEST",
                name="/stress/rapid",
                response_time=processing_time * 1000,
                response_length=1,
                exception=None,
            )

        except Exception as e:
            self.environment.stats.log_request(
                method="STRESS_TEST_ERROR",
                name="/stress/error",
                response_time=0,
                response_length=0,
                exception=e,
            )


# =============================================================================
# Configuration
# =============================================================================

class TestConfig:
    """Performance test configuration."""

    # Target performance metrics
    TARGET_REQUESTS_PER_SECOND = 100
    TARGET_P95_RESPONSE_TIME_MS = 3000  # 3 seconds
    TARGET_P99_RESPONSE_TIME_MS = 5000  # 5 seconds

    # Load test scenarios
    SMOKE_TEST_USERS = 1
    SMOKE_TEST_DURATION = "1m"

    LOAD_TEST_USERS = 10
    LOAD_TEST_DURATION = "5m"
    LOAD_TEST_SPAWN_RATE = 2  # Users per second

    STRESS_TEST_USERS = 50
    STRESS_TEST_DURATION = "2m"
    STRESS_TEST_SPAWN_RATE = 10

    # Soak test (long duration)
    SOAK_TEST_USERS = 5
    SOAK_TEST_DURATION = "30m"
    SOAK_TEST_SPAWN_RATE = 1


# =============================================================================
# CLI Usage Guide
# =============================================================================

"""
Performance Test Usage Guide:

1. Smoke Test (Quick validation):
   locust -f tests/load/locustfile.py --headless -u 1 -t 1m --html smoke_test.html

2. Load Test (Normal traffic):
   locust -f tests/load/locustfile.py --headless -u 10 -r 2 -t 5m --html load_test.html

3. Stress Test (High traffic):
   locust -f tests/load/locustfile.py --headless -u 50 -r 10 -t 2m --html stress_test.html

4. Soak Test (Long duration stability):
   locust -f tests/load/locustfile.py --headless -u 5 -r 1 -t 30m --html soak_test.html

5. Interactive Mode (Web UI):
   locust -f tests/load/locustfile.py --host http://localhost:8089

Target Metrics:
- Requests/sec: > 100
- P95 Latency: < 3000ms (3 seconds)
- P99 Latency: < 5000ms (5 seconds)
- Error Rate: < 1%

Expected Results:
- All services should handle 100+ alerts/second
- P95 latency should remain under 3 seconds
- System should remain stable during stress test
- No memory leaks or resource exhaustion
"""
