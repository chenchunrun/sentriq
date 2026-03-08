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
Pytest configuration and fixtures.

This module provides shared fixtures and configuration for all tests.
"""

import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import AsyncGenerator, Generator
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio

# Add parent directory to path for imports
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Add services directory to path for shared module imports
services_dir = project_root / "services"
if str(services_dir) not in sys.path:
    sys.path.insert(0, str(services_dir))

import uuid
from datetime import datetime, timedelta

from fastapi.testclient import TestClient
from httpx import ASGITransport, AsyncClient
from shared.utils.time import utc_now, utc_now_iso

# Environment setup
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost/test_db")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/1")
os.environ.setdefault("RABBITMQ_URL", "amqp://guest:guest@localhost:5672/")
os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-for-testing-only")


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def mock_config():
    """Mock configuration for testing."""
    from shared.utils import Config

    config = Config()
    config.app_config.database_url = "sqlite+aiosqlite:///:memory:"
    config.app_config.redis_url = "redis://localhost:6379/1"
    config.app_config.rabbitmq_url = "amqp://guest:guest@localhost:5672/"
    config.app_config.jwt_secret_key = "test-secret-key-for-testing-only"

    return config


@pytest.fixture
def mock_db():
    """Mock database session for testing.

    This fixture provides a simple mock database object for tests.
    Currently the project uses Pydantic models, not SQLAlchemy ORM models.
    If you need to use SQLAlchemy in the future, update this fixture.
    """
    from unittest.mock import MagicMock

    # Create a simple mock database manager
    db = MagicMock()
    db.execute_query = MagicMock(return_value=[])
    db.execute = MagicMock()
    db.commit = MagicMock()
    db.rollback = MagicMock()

    return db


@pytest.fixture
def mock_redis():
    """Mock Redis client for testing."""
    import redis

    # Use fakeredis for testing
    try:
        import fakeredis

        client = fakeredis.FakeStrictRedis(decode_responses=False)
    except ImportError:
        client = redis.Redis(decode_responses=False, db=15)  # Use test DB

    yield client

    # Cleanup
    client.flushall()
    client.close()


@pytest.fixture
def mock_rabbitmq():
    """Mock RabbitMQ connection for testing."""
    # For testing, we'll just return a mock
    mock = MagicMock()
    yield mock


@pytest.fixture
def sample_alert():
    """Sample security alert for testing."""
    from shared.models import AlertType, SecurityAlert, Severity

    return SecurityAlert(
        alert_id="ALT-TEST-001",
        timestamp=utc_now(),
        alert_type=AlertType.MALWARE,
        severity=Severity.HIGH,
        description="Test malware alert",
        source_ip="45.33.32.156",
        target_ip="10.0.0.50",
        file_hash="5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
    )


@pytest.fixture
def sample_triage_result():
    """Sample triage result for testing."""
    from shared.models import (
        ActionType,
        RemediationAction,
        RemediationPriority,
        RiskAssessment,
        RiskLevel,
        TriageResult,
    )

    return TriageResult(
        alert_id="ALT-TEST-001",
        risk_assessment=RiskAssessment(
            risk_score=75.5, risk_level=RiskLevel.HIGH, confidence=0.85, requires_human_review=False
        ),
        remediation_actions=[
            RemediationAction(
                action_type=ActionType.ISOLATE_HOST,
                title="Isolate affected system",
                description="Isolate affected system from network",
                priority=RemediationPriority.HIGH,
            )
        ],
        requires_human_review=False,
        processing_time_ms=1500.0,
    )


@pytest.fixture
def sample_workflow_execution():
    """Sample workflow execution for testing."""
    from shared.models import WorkflowExecution, WorkflowStatus

    return WorkflowExecution(
        execution_id="exec-test-001",
        workflow_id="alert-processing",
        status=WorkflowStatus.RUNNING,
        input={"alert_id": "ALT-001"},
        started_at=utc_now(),
    )


# Test clients for FastAPI apps


@pytest.fixture
def alert_ingestor_client():
    """Test client for Alert Ingestor service."""
    from services.alert_ingestor.main import app

    return TestClient(app)


@pytest.fixture
def llm_router_client():
    """Test client for LLM Router service."""
    from services.llm_router.main import app

    return TestClient(app)


@pytest.fixture
async def async_llm_router_client():
    """Async test client for LLM Router service."""
    from services.llm_router.main import app

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        yield client


# Mock data generators


@pytest.fixture
def generate_alert_data():
    """Factory function to generate alert data."""

    def _generate(alert_id: str = None, severity: str = "medium", alert_type: str = "malware"):
        return {
            "alert_id": alert_id or f"ALT-{uuid.uuid4()}",
            "timestamp": utc_now_iso(),
            "alert_type": alert_type,
            "severity": severity,
            "description": f"Test {alert_type} alert",
            "source_ip": "45.33.32.156",
            "target_ip": "10.0.0.50",
        }

    return _generate


@pytest.fixture
def valid_alert_data():
    """Valid alert data for testing."""
    return {
        "alert_id": f"ALT-{uuid.uuid4()}",
        "timestamp": utc_now_iso(),
        "alert_type": "malware",
        "severity": "high",
        "description": "Test malware alert",
        "source_ip": "45.33.32.156",
        "target_ip": "10.0.0.50",
        "file_hash": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
        "domain": "malicious.example.com",
        "url": "http://malicious.example.com/payload.exe",
    }


@pytest.fixture
def mock_publisher():
    """Mock message publisher for testing."""
    publisher = AsyncMock()
    publisher.publish = AsyncMock()
    return publisher


@pytest.fixture
def test_env():
    """
    Lightweight environment fixture for e2e placeholders.

    By default this suite does not require full external infrastructure
    unless RUN_E2E_TESTS=true is explicitly set.
    """
    if os.getenv("RUN_E2E_TESTS", "false").lower() != "true":
        pytest.skip("E2E infra not enabled (set RUN_E2E_TESTS=true to run)")
    return {"e2e_enabled": True}


# Cleanup fixtures


@pytest.fixture(autouse=True)
async def cleanup_test_data():
    """Cleanup test data after each test."""
    yield

    # Cleanup logic here if needed
    # For example, clear test databases, etc.


# Performance testing fixtures


@pytest.fixture
def benchmark_thresholds():
    """Performance benchmark thresholds."""
    return {
        "api_response_time": 0.5,  # 500ms
        "db_query_time": 0.1,  # 100ms
        "llm_response_time": 30.0,  # 30 seconds
    }
