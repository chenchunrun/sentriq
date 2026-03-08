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
Integration tests for database operations.

Tests database repositories, models, and session management
including CRUD operations, filtering, relationships, and transactions.
"""

import asyncio
from datetime import UTC, datetime, timedelta
from typing import AsyncGenerator, Dict, List
from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from shared.database.base import DatabaseManager, close_database, init_database
from shared.database.models import Alert, AlertContext, Asset, TriageResult, User
from shared.database.repositories.alert_repository import AlertRepository
from shared.database.repositories.base import BaseRepository
from shared.database.repositories.triage_repository import TriageRepository
from shared.models.alert import AlertFilter, AlertStatus, AlertType, Severity


# =============================================================================
# Test Configuration
# =============================================================================

TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture(scope="function")
async def test_engine():
    """Create test database engine."""
    pytest.importorskip("aiosqlite", reason="aiosqlite is required for sqlite async integration tests")
    engine = create_async_engine(
        TEST_DATABASE_URL,
        echo=False,
    )

    # Create tables
    from shared.database.models import Base
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield engine

    # Drop tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

    await engine.dispose()


@pytest.fixture(scope="function")
async def test_session(test_engine) -> AsyncGenerator[AsyncSession, None]:
    """Create test database session."""
    async_session = sessionmaker(
        test_engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autocommit=False,
        autoflush=False,
    )

    async with async_session() as session:
        yield session


@pytest.fixture(scope="function")
async def db_manager(test_engine) -> DatabaseManager:
    """Create database manager for testing."""
    manager = DatabaseManager(
        database_url=TEST_DATABASE_URL,
        echo=False,
    )
    await manager.initialize()

    yield manager

    await manager.close()


@pytest.fixture
def sample_alert_data() -> Dict:
    """Sample alert data for testing."""
    return {
        "alert_id": f"alert-{uuid4()}",
        "timestamp": datetime.now(UTC),
        "alert_type": "malware",
        "severity": "high",
        "status": "new",
        "title": "Test Malware Alert",
        "description": "Test malware detected on endpoint",
        "source_ip": "45.33.32.156",
        "destination_ip": "10.0.0.50",
        "file_hash": "5d41402abc4b2a76b9719d911017c592",
        "source": "splunk",
    }


@pytest.fixture
def sample_user_data() -> Dict:
    """Sample user data for testing."""
    return {
        "username": "test_analyst",
        "email": "test@example.com",
        "full_name": "Test Analyst",
        "role": "analyst",
        "is_active": True,
    }


@pytest.fixture
def sample_asset_data() -> Dict:
    """Sample asset data for testing."""
    return {
        "asset_id": "server-prod-001",
        "name": "Production Server 1",
        "asset_type": "server",
        "ip_address": "10.0.0.50",
        "criticality": "high",
        "is_active": True,
    }


# =============================================================================
# Database Connection Tests
# =============================================================================

@pytest.mark.integration
@pytest.mark.database
class TestDatabaseConnection:
    """Test database connection and session management."""

    async def test_database_initialization(self, db_manager):
        """Test database manager initialization."""
        assert db_manager._initialized is True
        assert db_manager.engine is not None

    async def test_health_check(self, db_manager):
        """Test database health check."""
        health = await db_manager.health_check()

        assert health["status"] == "healthy"
        assert "pool_size" in health
        assert "checked_out_connections" in health

    async def test_session_creation(self, db_manager):
        """Test database session creation."""
        async with db_manager.get_session() as session:
            result = await session.execute(text("SELECT 1"))
            assert result.scalar() == 1

    async def test_session_commit(self, db_manager):
        """Test session commit."""
        async with db_manager.get_session() as session:
            alert = Alert(
                alert_id="test-commit-001",
                timestamp=datetime.now(UTC),
                alert_type="malware",
                severity="high",
                status="new",
                title="Commit Test",
                description="Test commit functionality",
            )
            session.add(alert)
            await session.commit()

        # Verify in new session
        async with db_manager.get_session() as session:
            from sqlalchemy import select
            result = await session.execute(
                select(Alert).where(Alert.alert_id == "test-commit-001")
            )
            assert result.scalar_one_or_none() is not None

    async def test_session_rollback(self, db_manager):
        """Test session rollback on error."""
        async with db_manager.get_session() as session:
            alert = Alert(
                alert_id="test-rollback-001",
                timestamp=datetime.now(UTC),
                alert_type="malware",
                severity="high",
                status="new",
                title="Rollback Test",
                description="Test rollback functionality",
            )
            session.add(alert)
            await session.rollback()

        # Verify not saved
        async with db_manager.get_session() as session:
            result = await session.execute(
                select(Alert).where(Alert.alert_id == "test-rollback-001")
            )
            assert result.scalar_one_or_none() is None


# =============================================================================
# Alert Repository Tests
# =============================================================================

@pytest.mark.integration
@pytest.mark.database
class TestAlertRepository:
    """Test AlertRepository database operations."""

    async def test_create_alert(self, test_session, sample_alert_data):
        """Test creating an alert."""
        repo = AlertRepository(test_session)
        alert = await repo.create_alert(sample_alert_data)

        assert alert.alert_id == sample_alert_data["alert_id"]
        assert alert.alert_type == sample_alert_data["alert_type"]
        assert alert.severity == sample_alert_data["severity"]
        assert alert.source_ip == sample_alert_data["source_ip"]

    async def test_get_alert_by_id(self, test_session, sample_alert_data):
        """Test retrieving alert by ID."""
        repo = AlertRepository(test_session)
        created = await repo.create_alert(sample_alert_data)

        retrieved = await repo.get_alert_by_id(created.alert_id)

        assert retrieved is not None
        assert retrieved.alert_id == created.alert_id
        assert retrieved.title == created.title

    async def test_get_alert_by_id_not_found(self, test_session):
        """Test retrieving non-existent alert."""
        repo = AlertRepository(test_session)
        result = await repo.get_alert_by_id("non-existent-id")
        assert result is None

    async def test_update_alert_status(self, test_session, sample_alert_data):
        """Test updating alert status."""
        repo = AlertRepository(test_session)
        alert = await repo.create_alert(sample_alert_data)

        updated = await repo.update_alert_status(
            alert_id=alert.alert_id,
            status=AlertStatus.IN_PROGRESS,
            assigned_to=str(uuid4()),
            comment="Assigned to analyst",
        )

        assert updated is not None
        assert updated.status == AlertStatus.IN_PROGRESS.value
        assert updated.assigned_to is not None

    async def test_update_alert_risk_score(self, test_session, sample_alert_data):
        """Test updating alert risk score."""
        repo = AlertRepository(test_session)
        alert = await repo.create_alert(sample_alert_data)

        updated = await repo.update_alert_risk_score(
            alert_id=alert.alert_id,
            risk_score=85.5,
            confidence=0.92,
        )

        assert updated is not None
        assert updated.risk_score == 85.5
        assert updated.confidence == 0.92
        # Severity should be updated based on risk score
        assert updated.severity in ["high", "critical"]

    async def test_get_alerts_by_filter_with_alert_type(self, test_session, sample_alert_data):
        """Test filtering alerts by type."""
        repo = AlertRepository(test_session)

        # Create multiple alerts
        for i in range(3):
            data = sample_alert_data.copy()
            data["alert_id"] = f"alert-{uuid4()}"
            data["alert_type"] = "malware" if i % 2 == 0 else "phishing"
            await repo.create_alert(data)

        # Filter by malware type
        filters = AlertFilter(alert_type=AlertType.MALWARE)
        alerts, total = await repo.get_alerts_by_filter(filters)

        assert total >= 1
        assert all(a.alert_type == "malware" for a in alerts)

    async def test_get_alerts_by_filter_with_severity(self, test_session, sample_alert_data):
        """Test filtering alerts by severity."""
        repo = AlertRepository(test_session)

        # Create alerts with different severities
        for severity in ["critical", "high", "medium", "low"]:
            data = sample_alert_data.copy()
            data["alert_id"] = f"alert-{uuid4()}"
            data["severity"] = severity
            await repo.create_alert(data)

        # Filter by high severity
        filters = AlertFilter(severity=Severity.HIGH)
        alerts, total = await repo.get_alerts_by_filter(filters)

        assert total >= 1
        assert all(a.severity == "high" for a in alerts)

    async def test_get_alerts_by_filter_with_status(self, test_session, sample_alert_data):
        """Test filtering alerts by status."""
        repo = AlertRepository(test_session)

        # Create alerts with different statuses
        for status in ["new", "in_progress", "resolved"]:
            data = sample_alert_data.copy()
            data["alert_id"] = f"alert-{uuid4()}"
            data["status"] = status
            await repo.create_alert(data)

        # Filter by new status
        filters = AlertFilter(status=AlertStatus.NEW)
        alerts, total = await repo.get_alerts_by_filter(filters)

        assert total >= 1
        assert all(a.status == "new" for a in alerts)

    async def test_get_alerts_by_filter_with_source_ip(self, test_session, sample_alert_data):
        """Test filtering alerts by source IP."""
        repo = AlertRepository(test_session)

        alert = await repo.create_alert(sample_alert_data)
        filters = AlertFilter(source_ip=alert.source_ip)

        alerts, total = await repo.get_alerts_by_filter(filters)

        assert total >= 1
        assert all(a.source_ip == alert.source_ip for a in alerts)

    async def test_get_alerts_by_filter_with_search(self, test_session, sample_alert_data):
        """Test text search in alerts."""
        repo = AlertRepository(test_session)

        await repo.create_alert(sample_alert_data)

        # Search for "malware"
        filters = AlertFilter(search="malware")
        alerts, total = await repo.get_alerts_by_filter(filters)

        assert total >= 1
        assert any("malware" in a.title.lower() or "malware" in a.description.lower() for a in alerts)

    async def test_get_alerts_by_filter_with_date_range(self, test_session, sample_alert_data):
        """Test filtering alerts by date range."""
        repo = AlertRepository(test_session)

        await repo.create_alert(sample_alert_data)

        now = datetime.now(UTC)
        filters = AlertFilter(
            start_date=now - timedelta(hours=1),
            end_date=now + timedelta(hours=1),
        )
        alerts, total = await repo.get_alerts_by_filter(filters)

        assert total >= 1

    async def test_get_alerts_pagination(self, test_session, sample_alert_data):
        """Test pagination of alert results."""
        repo = AlertRepository(test_session)

        # Create 5 alerts
        for i in range(5):
            data = sample_alert_data.copy()
            data["alert_id"] = f"alert-{uuid4()}"
            await repo.create_alert(data)

        # Get first page
        alerts, total = await repo.get_alerts_by_filter(
            filters=AlertFilter(),
            skip=0,
            limit=3,
        )

        assert total == 5
        assert len(alerts) == 3

        # Get second page
        alerts2, _ = await repo.get_alerts_by_filter(
            filters=AlertFilter(),
            skip=3,
            limit=3,
        )

        assert len(alerts2) == 2

    async def test_bulk_create_alerts(self, test_session, sample_alert_data):
        """Test bulk creating alerts."""
        repo = AlertRepository(test_session)

        alerts_data = []
        for i in range(5):
            data = sample_alert_data.copy()
            data["alert_id"] = f"alert-{uuid4()}"
            alerts_data.append(data)

        alerts = await repo.bulk_create_alerts(alerts_data)

        assert len(alerts) == 5
        assert all(a.alert_id is not None for a in alerts)

    async def test_get_alerts_count_by_severity(self, test_session, sample_alert_data):
        """Test getting alert count grouped by severity."""
        repo = AlertRepository(test_session)

        # Create alerts with different severities
        for severity in ["critical", "high", "high", "medium"]:
            data = sample_alert_data.copy()
            data["alert_id"] = f"alert-{uuid4()}"
            data["severity"] = severity
            await repo.create_alert(data)

        counts = await repo.get_alerts_count_by_severity()

        assert counts.get("high") == 2
        assert counts.get("critical") == 1
        assert counts.get("medium") == 1

    async def test_get_alerts_count_by_status(self, test_session, sample_alert_data):
        """Test getting alert count grouped by status."""
        repo = AlertRepository(test_session)

        # Create alerts with different statuses
        for status in ["new", "new", "in_progress"]:
            data = sample_alert_data.copy()
            data["alert_id"] = f"alert-{uuid4()}"
            data["status"] = status
            await repo.create_alert(data)

        counts = await repo.get_alerts_count_by_status()

        assert counts.get("new") == 2
        assert counts.get("in_progress") == 1

    async def test_assign_alert(self, test_session, sample_alert_data):
        """Test assigning alert to user."""
        repo = AlertRepository(test_session)
        alert = await repo.create_alert(sample_alert_data)

        user_id = str(uuid4())
        assigned = await repo.assign_alert(alert.alert_id, user_id)

        assert assigned is not None
        assert assigned.status == AlertStatus.ASSIGNED.value
        assert assigned.assigned_to == user_id

    async def test_close_alert(self, test_session, sample_alert_data):
        """Test closing an alert."""
        repo = AlertRepository(test_session)
        alert = await repo.create_alert(sample_alert_data)

        closed = await repo.close_alert(alert.alert_id)

        assert closed is not None
        assert closed.status == AlertStatus.CLOSED.value

    async def test_get_high_priority_alerts(self, test_session, sample_alert_data):
        """Test getting high-priority alerts."""
        repo = AlertRepository(test_session)

        # Create alerts with different risk scores
        for risk_score in [50.0, 75.0, 90.0]:
            data = sample_alert_data.copy()
            data["alert_id"] = f"alert-{uuid4()}"
            data["risk_score"] = risk_score
            data["status"] = "new"
            await repo.create_alert(data)

        # Get alerts with risk score >= 70
        high_priority = await repo.get_high_priority_alerts(min_risk_score=70.0)

        assert len(high_priority) == 2
        assert all(a.risk_score >= 70.0 for a in high_priority)

    async def test_get_active_alerts(self, test_session, sample_alert_data):
        """Test getting active (non-resolved/closed) alerts."""
        repo = AlertRepository(test_session)

        # Create alerts
        for status in ["new", "in_progress", "resolved", "closed"]:
            data = sample_alert_data.copy()
            data["alert_id"] = f"alert-{uuid4()}"
            data["status"] = status
            await repo.create_alert(data)

        # Get active alerts
        active = await repo.get_active_alerts()

        assert len(active) >= 2  # new and in_progress
        assert all(a.status not in ["resolved", "closed"] for a in active)


# =============================================================================
# Triage Repository Tests
# =============================================================================

@pytest.mark.integration
@pytest.mark.database
class TestTriageRepository:
    """Test TriageRepository database operations."""

    @pytest.fixture
    async def sample_alert(self, test_session, sample_alert_data):
        """Create sample alert for triage tests."""
        repo = AlertRepository(test_session)
        return await repo.create_alert(sample_alert_data)

    @pytest.fixture
    def sample_triage_data(self, sample_alert):
        """Sample triage result data."""
        return {
            "alert_id": sample_alert.alert_id,
            "risk_score": 85.0,
            "risk_level": "high",
            "confidence": 0.92,
            "analysis": "Detailed analysis of the alert",
            "key_findings": ["Finding 1", "Finding 2"],
            "iocs_identified": {"ips": ["45.33.32.156"], "hashes": ["abc123"]},
            "model_used": "deepseek",
            "requires_human_review": True,
        }

    async def test_save_triage_result(self, test_session, sample_triage_data):
        """Test saving triage result."""
        repo = TriageRepository(test_session)
        result = await repo.save_triage_result(sample_triage_data)

        assert result.alert_id == sample_triage_data["alert_id"]
        assert result.risk_score == 85.0
        assert result.risk_level == "high"
        assert result.confidence == 0.92
        assert result.requires_human_review is True

    async def test_get_triage_result_by_alert_id(self, test_session, sample_triage_data):
        """Test retrieving triage result by alert ID."""
        repo = TriageRepository(test_session)
        created = await repo.save_triage_result(sample_triage_data)

        retrieved = await repo.get_triage_result_by_alert_id(created.alert_id)

        assert retrieved is not None
        assert retrieved.alert_id == created.alert_id
        assert retrieved.risk_score == created.risk_score

    async def test_update_risk_score(self, test_session, sample_triage_data):
        """Test updating risk score."""
        repo = TriageRepository(test_session)
        created = await repo.save_triage_result(sample_triage_data)

        updated = await repo.update_risk_score(
            alert_id=created.alert_id,
            risk_score=95.0,
            risk_level="critical",
            confidence=0.98,
        )

        assert updated is not None
        assert updated.risk_score == 95.0
        assert updated.risk_level == "critical"
        assert updated.confidence == 0.98

    async def test_mark_for_human_review(self, test_session, sample_triage_data):
        """Test marking for human review."""
        repo = TriageRepository(test_session)

        # Create without review flag
        data = sample_triage_data.copy()
        data["requires_human_review"] = False
        created = await repo.save_triage_result(data)

        # Mark for review
        updated = await repo.mark_for_human_review(created.alert_id, requires_review=True)

        assert updated is not None
        assert updated.requires_human_review is True

    async def test_submit_review(self, test_session, sample_triage_data):
        """Test submitting human review."""
        repo = TriageRepository(test_session)
        created = await repo.save_triage_result(sample_triage_data)

        reviewer_id = str(uuid4())
        comments = "Analyst reviewed and confirmed findings"

        reviewed = await repo.submit_review(
            alert_id=created.alert_id,
            reviewer_id=reviewer_id,
            comments=comments,
        )

        assert reviewed is not None
        assert reviewed.reviewed_by == reviewer_id
        assert reviewed.reviewer_comments == comments
        assert reviewed.reviewed_at is not None

    async def test_get_triage_results_pending_review(self, test_session, sample_triage_data):
        """Test getting results pending human review."""
        repo = TriageRepository(test_session)

        # Create multiple triage results
        for i in range(3):
            data = sample_triage_data.copy()
            data["alert_id"] = f"alert-{uuid4()}"
            data["requires_human_review"] = True
            await repo.save_triage_result(data)

        # Get pending reviews
        pending = await repo.get_triage_results_pending_review()

        assert len(pending) >= 3
        assert all(t.requires_human_review for t in pending)
        assert all(t.reviewed_by is None for t in pending)

    async def test_get_triage_results_by_risk_level(self, test_session, sample_triage_data):
        """Test filtering triage results by risk level."""
        repo = TriageRepository(test_session)

        # Create results with different risk levels
        for risk_level in ["critical", "high", "medium"]:
            data = sample_triage_data.copy()
            data["alert_id"] = f"alert-{uuid4()}"
            data["risk_level"] = risk_level
            data["risk_score"] = 90.0 if risk_level == "critical" else 70.0
            await repo.save_triage_result(data)

        # Get high risk results
        high_results = await repo.get_triage_results_by_risk_level("high")

        assert len(high_results) >= 1
        assert all(t.risk_level == "high" for t in high_results)

    async def test_get_average_risk_score(self, test_session, sample_triage_data):
        """Test getting average risk score."""
        repo = TriageRepository(test_session)

        # Create results with known risk scores
        risk_scores = [50.0, 70.0, 90.0]
        for score in risk_scores:
            data = sample_triage_data.copy()
            data["alert_id"] = f"alert-{uuid4()}"
            data["risk_score"] = score
            await repo.save_triage_result(data)

        avg = await repo.get_average_risk_score()

        assert avg is not None
        expected_avg = sum(risk_scores) / len(risk_scores)
        assert abs(avg - expected_avg) < 0.01

    async def test_get_risk_level_distribution(self, test_session, sample_triage_data):
        """Test getting risk level distribution."""
        repo = TriageRepository(test_session)

        # Create results with different risk levels
        risk_levels = ["critical", "high", "high", "medium", "low"]
        for risk_level in risk_levels:
            data = sample_triage_data.copy()
            data["alert_id"] = f"alert-{uuid4()}"
            data["risk_level"] = risk_level
            await repo.save_triage_result(data)

        distribution = await repo.get_risk_level_distribution()

        assert distribution.get("high") == 2
        assert distribution.get("critical") == 1
        assert distribution.get("medium") == 1
        assert distribution.get("low") == 1

    async def test_get_pending_review_count(self, test_session, sample_triage_data):
        """Test getting count of pending reviews."""
        repo = TriageRepository(test_session)

        # Create pending and reviewed results
        for i in range(3):
            data = sample_triage_data.copy()
            data["alert_id"] = f"alert-{uuid4()}"
            data["requires_human_review"] = True
            await repo.save_triage_result(data)

        # Review one
        reviewer_id = str(uuid4())
        await repo.submit_review(
            alert_id=data["alert_id"],
            reviewer_id=reviewer_id,
        )

        pending_count = await repo.get_pending_review_count()

        assert pending_count >= 2

    async def test_get_triage_results_with_exploits(self, test_session, sample_triage_data):
        """Test getting results with known exploits."""
        repo = TriageRepository(test_session)

        # Create results with and without exploits
        data1 = sample_triage_data.copy()
        data1["alert_id"] = f"alert-{uuid4()}"
        data1["known_exploits"] = True
        await repo.save_triage_result(data1)

        data2 = sample_triage_data.copy()
        data2["alert_id"] = f"alert-{uuid4()}"
        data2["known_exploits"] = False
        await repo.save_triage_result(data2)

        # Get results with exploits
        with_exploits = await repo.get_triage_results_with_exploits()

        assert len(with_exploits) >= 1
        assert all(t.known_exploits for t in with_exploits)

    async def test_bulk_create_triage_results(self, test_session, sample_triage_data):
        """Test bulk creating triage results."""
        repo = TriageRepository(test_session)

        triage_results_data = []
        for i in range(5):
            data = sample_triage_data.copy()
            data["alert_id"] = f"alert-{uuid4()}"
            triage_results_data.append(data)

        results = await repo.bulk_create_triage_results(triage_results_data)

        assert len(results) == 5
        assert all(t.alert_id is not None for t in results)


# =============================================================================
# Model Relationships Tests
# =============================================================================

@pytest.mark.integration
@pytest.mark.database
class TestModelRelationships:
    """Test relationships between database models."""

    async def test_alert_user_relationship(self, test_session, sample_alert_data, sample_user_data):
        """Test Alert-User relationship (assigned_to)."""
        # Create user
        user = User(**sample_user_data)
        test_session.add(user)
        await test_session.flush()

        # Create alert and assign to user
        repo = AlertRepository(test_session)
        data = sample_alert_data.copy()
        alert = await repo.create_alert(data)

        await repo.update_alert_status(
            alert_id=alert.alert_id,
            status=AlertStatus.ASSIGNED,
            assigned_to=user.id,
        )

        # Verify relationship
        await test_session.refresh(alert)
        assert alert.assigned_to == user.id

    async def test_alert_triage_relationship(self, test_session, sample_alert_data):
        """Test Alert-TriageResult relationship."""
        # Create alert
        alert_repo = AlertRepository(test_session)
        alert = await alert_repo.create_alert(sample_alert_data)

        # Create triage result
        triage_repo = TriageRepository(test_session)
        triage_data = {
            "alert_id": alert.alert_id,
            "risk_score": 75.0,
            "risk_level": "high",
            "confidence": 0.85,
            "analysis": "Test analysis",
            "model_used": "deepseek",
        }
        triage_result = await triage_repo.save_triage_result(triage_data)

        # Update alert with triage reference
        alert.triage_result_id = triage_result.id
        await test_session.flush()

        # Verify relationship
        await test_session.refresh(alert)
        assert alert.triage_result_id == triage_result.id

    async def test_alert_context_relationship(self, test_session, sample_alert_data):
        """Test Alert-AlertContext relationship."""
        # Create alert
        repo = AlertRepository(test_session)
        alert = await repo.create_alert(sample_alert_data)

        # Create context
        context = AlertContext(
            alert_id=alert.alert_id,
            source_geo={"country": "US", "city": "New York"},
            asset_criticality="high",
            asset_owner="IT Department",
        )
        test_session.add(context)
        await test_session.flush()

        # Verify relationship
        await test_session.refresh(alert)
        assert alert.context_data is not None
        assert alert.context_data.source_geo["country"] == "US"


# =============================================================================
# Transaction Tests
# =============================================================================

@pytest.mark.integration
@pytest.mark.database
class TestTransactions:
    """Test database transaction behavior."""

    async def test_transaction_commit(self, test_session, sample_alert_data):
        """Test transaction commit."""
        alert = Alert(**sample_alert_data)
        test_session.add(alert)
        await test_session.commit()

        # Verify in same session
        result = await test_session.execute(
            select(Alert).where(Alert.alert_id == sample_alert_data["alert_id"])
        )
        assert result.scalar_one_or_none() is not None

    async def test_transaction_rollback(self, test_session, sample_alert_data):
        """Test transaction rollback."""
        alert = Alert(**sample_alert_data)
        test_session.add(alert)
        await test_session.rollback()

        # Verify not saved
        result = await test_session.execute(
            select(Alert).where(Alert.alert_id == sample_alert_data["alert_id"])
        )
        assert result.scalar_one_or_none() is None

    async def test_transaction_on_error(self, test_session, sample_alert_data):
        """Test automatic rollback on error."""
        alert1 = Alert(**sample_alert_data)
        test_session.add(alert1)

        # Trigger error with duplicate alert_id
        alert2 = Alert(**sample_alert_data)
        test_session.add(alert2)

        try:
            await test_session.commit()
            assert False, "Should have raised an error"
        except Exception:
            await test_session.rollback()

        # Verify neither was saved
        result = await test_session.execute(
            select(Alert).where(Alert.alert_id == sample_alert_data["alert_id"])
        )
        assert result.scalar_one_or_none() is None


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
