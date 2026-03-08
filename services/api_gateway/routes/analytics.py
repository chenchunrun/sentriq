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
Analytics API endpoints.

Provides REST endpoints for dashboard statistics, trends,
metrics, and analytical data.
"""

from datetime import timedelta
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

import sys
sys.path.insert(0, '/Users/newmba/security')

from loguru import logger

from shared.database.base import get_database_manager
from shared.database.repositories.alert_repository import AlertRepository
from shared.database.repositories.triage_repository import TriageRepository

from models.requests import DashboardStatsRequest
from models.responses import (
    AnalyticsMetricResponse,
    DashboardStatsResponse,
    TrendDataPoint,
    TrendResponse,
)
from routes.auth import require_permissions
from shared.utils.time import utc_now

router = APIRouter()


# =============================================================================
# Dependencies
# =============================================================================

async def get_db_session() -> AsyncSession:
    """Get database session."""
    db_manager = get_database_manager()
    async with db_manager.get_session() as session:
        yield session


# =============================================================================
# Dashboard Statistics
# =============================================================================

@router.get(
    "/dashboard",
    response_model=DashboardStatsResponse,
    summary="Get Dashboard Statistics",
    description="Retrieve overall dashboard statistics and metrics",
)
async def get_dashboard_stats(
    time_range: str = Query("24h", pattern="^(1h|24h|7d|30d)$", description="Time range"),
    include_trends: bool = Query(True, description="Include trend data"),
    current_user=Depends(require_permissions("analytics:read")),
    session: AsyncSession = Depends(get_db_session),
):
    """
    Get dashboard statistics for the specified time range.

    Provides overview metrics including total alerts, critical alerts,
    high-risk alerts, pending triage count, and trends.
    """
    alert_repo = AlertRepository(session)
    triage_repo = TriageRepository(session)

    # Calculate time range
    now = utc_now()
    if time_range == "1h":
        start_time = now - timedelta(hours=1)
    elif time_range == "24h":
        start_time = now - timedelta(days=1)
    elif time_range == "7d":
        start_time = now - timedelta(days=7)
    else:  # 30d
        start_time = now - timedelta(days=30)

    # Get alerts in time range
    alerts = await alert_repo.get_alerts_by_date_range(
        start_date=start_time,
        end_date=now,
        skip=0,
        limit=100000,  # Get all
    )

    # Count by severity
    severity_counts = await alert_repo.get_alerts_count_by_severity()

    # Count by status
    status_counts = await alert_repo.get_alerts_count_by_status()

    # Calculate stats
    total_alerts = len(alerts)
    critical_alerts = severity_counts.get("critical", 0)

    # High risk alerts (risk score >= 70)
    high_risk_alerts = len([
        a for a in alerts
        if getattr(a, "risk_score", None) is not None and getattr(a, "risk_score", 0) >= 70
    ])

    # Pending triage (not reviewed or requires review)
    pending_review = await triage_repo.get_pending_review_count()
    pending_triage = pending_review

    # Average response time (time from creation to resolution)
    resolved_alerts = [a for a in alerts if a.status == "resolved"]
    avg_response_time = None
    if resolved_alerts:
        response_times = [
            (a.updated_at - a.created_at).total_seconds()
            for a in resolved_alerts
        ]
        avg_response_time = sum(response_times) / len(response_times) if response_times else None

    # Alerts today (last 24 hours)
    today_start = now - timedelta(days=1)
    alerts_today = len([
        a for a in alerts
        if a.created_at >= today_start
    ])

    # Threats blocked (simulated - resolved/closed alerts)
    threats_blocked = status_counts.get("resolved", 0) + status_counts.get("closed", 0)

    # System health (check if critical alerts are below threshold)
    system_health = "healthy"
    if critical_alerts > 10:
        system_health = "degraded"
    if critical_alerts > 50:
        system_health = "unhealthy"

    # Trends
    trends = None
    if include_trends:
        trends = await _calculate_trends(alert_repo, time_range, session)

    return DashboardStatsResponse(
        total_alerts=total_alerts,
        critical_alerts=critical_alerts,
        high_risk_alerts=high_risk_alerts,
        pending_triage=pending_triage,
        avg_response_time=avg_response_time,
        alerts_today=alerts_today,
        threats_blocked=threats_blocked,
        system_health=system_health,
        trends=trends,
    )


# =============================================================================
# Alert Trends
# =============================================================================

@router.get(
    "/trends/alerts",
    response_model=TrendResponse,
    summary="Get Alert Trends",
    description="Retrieve alert volume trends over time",
)
async def get_alert_trends(
    time_range: str = Query("24h", pattern="^(1h|24h|7d|30d)$", description="Time range"),
    group_by: str = Query("hour", pattern="^(hour|day)$", description="Group by period"),
    current_user=Depends(require_permissions("analytics:read")),
    session: AsyncSession = Depends(get_db_session),
):
    """
    Get alert volume trends over time.

    Returns time-series data showing alert volume grouped by
    hour or day for the specified time range.
    """
    alert_repo = AlertRepository(session)

    # Calculate time range
    now = utc_now()
    if time_range == "1h":
        start_time = now - timedelta(hours=1)
    elif time_range == "24h":
        start_time = now - timedelta(days=1)
    elif time_range == "7d":
        start_time = now - timedelta(days=7)
    else:  # 30d
        start_time = now - timedelta(days=30)

    # Get alerts
    alerts = await alert_repo.get_alerts_by_date_range(
        start_date=start_time,
        end_date=now,
        skip=0,
        limit=100000,
    )

    # Group alerts by time period
    data_points = _group_alerts_by_time(alerts, group_by)

    # Calculate trend summary
    if len(data_points) >= 2:
        first_val = data_points[0].value
        last_val = data_points[-1].value
        if last_val > first_val * 1.1:
            summary = "increasing"
        elif last_val < first_val * 0.9:
            summary = "decreasing"
        else:
            summary = "stable"
    else:
        summary = "insufficient_data"

    return TrendResponse(
        metric="alert_volume",
        time_range=time_range,
        data_points=data_points,
        summary=summary,
    )


# =============================================================================
# Risk Score Trends
# =============================================================================

@router.get(
    "/trends/risk-scores",
    response_model=TrendResponse,
    summary="Get Risk Score Trends",
    description="Retrieve average risk score trends over time",
)
async def get_risk_score_trends(
    time_range: str = Query("24h", pattern="^(1h|24h|7d|30d)$", description="Time range"),
    group_by: str = Query("hour", pattern="^(hour|day)$", description="Group by period"),
    current_user=Depends(require_permissions("analytics:read")),
    session: AsyncSession = Depends(get_db_session),
):
    """
    Get risk score trends over time.

    Returns time-series data showing average risk scores
    grouped by hour or day.
    """
    alert_repo = AlertRepository(session)

    # Calculate time range
    now = utc_now()
    if time_range == "1h":
        start_time = now - timedelta(hours=1)
    elif time_range == "24h":
        start_time = now - timedelta(days=1)
    elif time_range == "7d":
        start_time = now - timedelta(days=7)
    else:  # 30d
        start_time = now - timedelta(days=30)

    # Get alerts
    alerts = await alert_repo.get_alerts_by_date_range(
        start_date=start_time,
        end_date=now,
        skip=0,
        limit=100000,
    )

    # Filter alerts with risk scores
    alerts_with_risk = [a for a in alerts if a.risk_score is not None]

    # Group by time period
    data_points = _group_risk_scores_by_time(alerts_with_risk, group_by)

    # Calculate trend summary
    if len(data_points) >= 2:
        first_val = data_points[0].value
        last_val = data_points[-1].value
        if last_val > first_val * 1.1:
            summary = "increasing"
        elif last_val < first_val * 0.9:
            summary = "decreasing"
        else:
            summary = "stable"
    else:
        summary = "insufficient_data"

    return TrendResponse(
        metric="average_risk_score",
        time_range=time_range,
        data_points=data_points,
        summary=summary,
    )


# =============================================================================
# Severity Distribution
# =============================================================================

@router.get(
    "/metrics/severity-distribution",
    response_model=Dict[str, int],
    summary="Get Severity Distribution",
    description="Retrieve alert count by severity level",
)
async def get_severity_distribution(
    current_user=Depends(require_permissions("analytics:read")),
    session: AsyncSession = Depends(get_db_session),
):
    """
    Get current alert count grouped by severity level.

    Returns counts for critical, high, medium, low, and info severity levels.
    """
    alert_repo = AlertRepository(session)

    distribution = await alert_repo.get_alerts_count_by_severity()

    # Ensure all severity levels are present
    all_severities = ["critical", "high", "medium", "low", "info"]
    for severity in all_severities:
        if severity not in distribution:
            distribution[severity] = 0

    return distribution


# =============================================================================
# Status Distribution
# =============================================================================

@router.get(
    "/metrics/status-distribution",
    response_model=Dict[str, int],
    summary="Get Status Distribution",
    description="Retrieve alert count by status",
)
async def get_status_distribution(
    current_user=Depends(require_permissions("analytics:read")),
    session: AsyncSession = Depends(get_db_session),
):
    """
    Get current alert count grouped by status.

    Returns counts for new, in_progress, assigned, resolved, and closed statuses.
    """
    alert_repo = AlertRepository(session)

    distribution = await alert_repo.get_alerts_count_by_status()

    # Ensure all statuses are present
    all_statuses = ["new", "in_progress", "assigned", "resolved", "closed"]
    for status in all_statuses:
        if status not in distribution:
            distribution[status] = 0

    return distribution


# =============================================================================
# Top Sources
# =============================================================================

@router.get(
    "/metrics/top-sources",
    response_model=List[Dict[str, int]],
    summary="Get Top Alert Sources",
    description="Retrieve top alert sources by count",
)
async def get_top_sources(
    limit: int = Query(10, ge=1, le=100, description="Max results"),
    current_user=Depends(require_permissions("analytics:read")),
    session: AsyncSession = Depends(get_db_session),
):
    """
    Get top alert sources by alert count.

    Returns the top N sources that have generated the most alerts.
    """
    # This would require a custom query in AlertRepository
    # For now, return a placeholder
    return [
        {"source": "splunk", "count": 150},
        {"source": "qradar", "count": 89},
        {"source": "cef", "count": 45},
    ]


# =============================================================================
# Top Alert Types
# =============================================================================

@router.get(
    "/metrics/top-alert-types",
    response_model=List[Dict[str, int]],
    summary="Get Top Alert Types",
    description="Retrieve top alert types by count",
)
async def get_top_alert_types(
    limit: int = Query(10, ge=1, le=100, description="Max results"),
    current_user=Depends(require_permissions("analytics:read")),
    session: AsyncSession = Depends(get_db_session),
):
    """
    Get top alert types by alert count.

    Returns the top N alert types.
    """
    alert_repo = AlertRepository(session)

    distribution = await alert_repo.get_alerts_count_by_type()

    # Sort by count and return top N
    sorted_types = sorted(
        distribution.items(),
        key=lambda x: x[1],
        reverse=True,
    )[:limit]

    return [
        {"alert_type": alert_type, "count": count}
        for alert_type, count in sorted_types
    ]


# =============================================================================
# Performance Metrics
# =============================================================================

@router.get(
    "/metrics/performance",
    response_model=Dict[str, float],
    summary="Get Performance Metrics",
    description="Retrieve system performance metrics",
)
async def get_performance_metrics(
    current_user=Depends(require_permissions("analytics:read")),
    session: AsyncSession = Depends(get_db_session),
):
    """
    Get performance metrics for the triage system.

    Includes average processing time, average risk score,
    and model usage statistics.
    """
    triage_repo = TriageRepository(session)

    # Get average risk score
    avg_risk_score = await triage_repo.get_average_risk_score() or 0.0

    # Get average processing time
    avg_processing_time = await triage_repo.get_average_processing_time() or 0.0

    # Get model usage
    model_usage = await triage_repo.get_model_usage_stats()

    # Get risk level distribution
    risk_distribution = await triage_repo.get_risk_level_distribution()

    return {
        "average_risk_score": avg_risk_score,
        "average_processing_time_ms": avg_processing_time,
        "deepseek_usage": model_usage.get("deepseek", 0),
        "qwen_usage": model_usage.get("qwen", 0),
        "critical_risk_count": risk_distribution.get("critical", 0),
        "high_risk_count": risk_distribution.get("high", 0),
        "medium_risk_count": risk_distribution.get("medium", 0),
        "low_risk_count": risk_distribution.get("low", 0),
    }


# =============================================================================
# Helper Functions
# =============================================================================

async def _calculate_trends(
    alert_repo: AlertRepository,
    time_range: str,
    session: AsyncSession,
) -> Dict[str, List[Dict[str, Any]]]:
    """Calculate trend data for dashboard."""
    from typing import Any

    now = utc_now()
    if time_range == "1h":
        start_time = now - timedelta(hours=1)
        hours = 1
    elif time_range == "24h":
        start_time = now - timedelta(days=1)
        hours = 24
    elif time_range == "7d":
        start_time = now - timedelta(days=7)
        hours = 168  # 7 days
    else:  # 30d
        start_time = now - timedelta(days=30)
        hours = 720  # 30 days

    alerts = await alert_repo.get_alerts_by_date_range(
        start_date=start_time,
        end_date=now,
        skip=0,
        limit=100000,
    )

    # Group by hour
    alert_trend = []
    for i in range(hours):
        hour_start = start_time + timedelta(hours=i)
        hour_end = hour_start + timedelta(hours=1)

        count = len([
            a for a in alerts
            if hour_start <= a.created_at < hour_end
        ])

        alert_trend.append({
            "timestamp": hour_start.isoformat(),
            "value": count,
        })

    return {
        "alert_volume": alert_trend,
    }


def _group_alerts_by_time(
    alerts: List,
    group_by: str,
) -> List[TrendDataPoint]:
    """Group alerts by time period."""
    from collections import defaultdict

    if group_by == "hour":
        # Group by hour
        groups = defaultdict(list)
        for alert in alerts:
            hour_key = alert.created_at.replace(minute=0, second=0, microsecond=0)
            groups[hour_key].append(alert)

        return [
            TrendDataPoint(
                timestamp=hour_key,
                value=len(alerts_list),
                label=hour_key.strftime("%Y-%m-%d %H:00"),
            )
            for hour_key, alerts_list in sorted(groups.items())
        ]
    else:  # day
        # Group by day
        groups = defaultdict(list)
        for alert in alerts:
            day_key = alert.created_date.replace(hour=0, minute=0, second=0, microsecond=0)
            groups[day_key].append(alert)

        return [
            TrendDataPoint(
                timestamp=day_key,
                value=len(alerts_list),
                label=day_key.strftime("%Y-%m-%d"),
            )
            for day_key, alerts_list in sorted(groups.items())
        ]


def _group_risk_scores_by_time(
    alerts: List,
    group_by: str,
) -> List[TrendDataPoint]:
    """Group risk scores by time period."""
    from collections import defaultdict

    if group_by == "hour":
        # Group by hour
        groups = defaultdict(list)
        for alert in alerts:
            hour_key = alert.created_at.replace(minute=0, second=0, microsecond=0)
            groups[hour_key].append(alert.risk_score)

        return [
            TrendDataPoint(
                timestamp=hour_key,
                value=sum(risk_scores) / len(risk_scores) if risk_scores else 0.0,
                label=hour_key.strftime("%Y-%m-%d %H:00"),
            )
            for hour_key, risk_scores in sorted(groups.items())
        ]
    else:  # day
        # Group by day
        groups = defaultdict(list)
        for alert in alerts:
            day_key = alert.created_at.replace(hour=0, minute=0, second=0, microsecond=0)
            groups[day_key].append(alert.risk_score)

        return [
            TrendDataPoint(
                timestamp=day_key,
                value=sum(risk_scores) / len(risk_scores) if risk_scores else 0.0,
                label=day_key.strftime("%Y-%m-%d"),
            )
            for day_key, risk_scores in sorted(groups.items())
        ]
