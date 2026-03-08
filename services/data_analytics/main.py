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

"""Data Analytics Service - Provides analytics and metrics for security alerts."""

import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Any, Dict

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from shared.database import DatabaseManager, get_database_manager, init_database, close_database
from shared.models import AlertMetric, AutomationMetric, DashboardData, TimeRange, TrendData, TriageMetric
from shared.utils import Config, get_logger, utc_now, utc_now_iso

logger = get_logger(__name__)
config = Config()

db_manager: DatabaseManager = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifespan."""
    global db_manager
    logger.info("Starting Data Analytics service...")
    await init_database(
        database_url=config.database_url,
        pool_size=config.db_pool_size,
        max_overflow=config.db_max_overflow,
        echo=config.debug,
    )
    db_manager = get_database_manager()
    logger.info("Data Analytics service started successfully")
    yield
    await close_database()
    logger.info("Data Analytics service stopped")


app = FastAPI(
    title="Data Analytics Service",
    description="Provides analytics and metrics for security operations",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def response_meta(extra: Dict[str, Any] | None = None) -> Dict[str, Any]:
    meta = {"timestamp": utc_now_iso(), "request_id": str(uuid.uuid4())}
    if extra:
        meta.update(extra)
    return meta


def calculate_time_range(time_range: TimeRange) -> tuple[datetime, datetime]:
    end_date = utc_now().replace(tzinfo=None)
    if time_range == TimeRange.LAST_HOUR:
        start_date = end_date - timedelta(hours=1)
    elif time_range == TimeRange.LAST_24H:
        start_date = end_date - timedelta(days=1)
    elif time_range == TimeRange.LAST_7D:
        start_date = end_date - timedelta(days=7)
    elif time_range == TimeRange.LAST_30D:
        start_date = end_date - timedelta(days=30)
    else:
        start_date = end_date - timedelta(days=1)
    return start_date, end_date


async def fetch_alert_metrics(start_date: datetime, end_date: datetime) -> AlertMetric:
    async with db_manager.get_session() as session:
        total_alerts = await session.scalar(
            text("SELECT COUNT(*) FROM alerts WHERE received_at BETWEEN :start AND :end"),
            {"start": start_date, "end": end_date},
        )
        sev_result = await session.execute(
            text(
                """
                SELECT severity, COUNT(*) AS count
                FROM alerts
                WHERE received_at BETWEEN :start AND :end
                GROUP BY severity
                """
            ),
            {"start": start_date, "end": end_date},
        )
        by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for row in sev_result.fetchall():
            by_severity[row.severity] = row.count

        type_result = await session.execute(
            text(
                """
                SELECT alert_type, COUNT(*) AS count
                FROM alerts
                WHERE received_at BETWEEN :start AND :end
                GROUP BY alert_type
                """
            ),
            {"start": start_date, "end": end_date},
        )
        by_type = {row.alert_type: row.count for row in type_result.fetchall()}

        status_result = await session.execute(
            text(
                """
                SELECT status, COUNT(*) AS count
                FROM alerts
                WHERE received_at BETWEEN :start AND :end
                GROUP BY status
                """
            ),
            {"start": start_date, "end": end_date},
        )
        by_status = {row.status: row.count for row in status_result.fetchall()}

        triaged = await session.scalar(
            text("SELECT COUNT(*) FROM triage_results WHERE created_at BETWEEN :start AND :end"),
            {"start": start_date, "end": end_date},
        )
        human_reviewed = await session.scalar(
            text(
                """
                SELECT COUNT(*)
                FROM triage_results
                WHERE requires_human_review = true
                  AND created_at BETWEEN :start AND :end
                """
            ),
            {"start": start_date, "end": end_date},
        )
        avg_resolution_time = await session.scalar(
            text(
                """
                SELECT AVG(EXTRACT(EPOCH FROM (updated_at - created_at)) / 60.0)
                FROM alerts
                WHERE status = 'resolved'
                  AND updated_at IS NOT NULL
                  AND created_at IS NOT NULL
                  AND updated_at >= created_at
                """
            )
        )
        mtta = await session.scalar(
            text(
                """
                SELECT AVG(EXTRACT(EPOCH FROM (t.first_triage - a.received_at)) / 60.0)
                FROM alerts a
                JOIN (
                    SELECT alert_id, MIN(created_at) AS first_triage
                    FROM triage_results
                    GROUP BY alert_id
                ) t ON t.alert_id = a.alert_id
                WHERE a.received_at IS NOT NULL
                  AND t.first_triage IS NOT NULL
                  AND t.first_triage >= a.received_at
                """
            )
        )

    return AlertMetric(
        total_alerts=total_alerts or 0,
        by_severity=by_severity,
        by_type=by_type,
        by_status=by_status,
        triaged=triaged or 0,
        auto_closed=max((triaged or 0) - (human_reviewed or 0), 0),
        human_reviewed=human_reviewed or 0,
        avg_resolution_time=round(avg_resolution_time or 0.0, 2),
        mtta=round(mtta or 0.0, 2),
        mttr=round(avg_resolution_time or 0.0, 2),
    )


async def fetch_triage_metrics(start_date: datetime, end_date: datetime) -> TriageMetric:
    async with db_manager.get_session() as session:
        triage_row = (
            await session.execute(
                text(
                    """
                    SELECT
                        COUNT(*) AS total,
                        COUNT(*) FILTER (WHERE requires_human_review = true) AS human_reviewed,
                        AVG(processing_time_ms) AS avg_processing_ms,
                        AVG(confidence_score) AS avg_confidence
                    FROM triage_results
                    WHERE created_at BETWEEN :start AND :end
                    """
                ),
                {"start": start_date, "end": end_date},
            )
        ).fetchone()

    total = triage_row.total if triage_row else 0
    human_reviewed = triage_row.human_reviewed if triage_row else 0
    avg_processing_ms = triage_row.avg_processing_ms if triage_row else 0.0
    avg_confidence = triage_row.avg_confidence if triage_row else 0.0

    return TriageMetric(
        avg_triage_time_seconds=round((avg_processing_ms or 0.0) / 1000.0, 2),
        triaged_by_ai=max(total - human_reviewed, 0),
        triaged_by_human=human_reviewed or 0,
        accuracy_score=float(avg_confidence or 0.0),
        false_positive_rate=0.0,
    )


async def fetch_automation_metrics(start_date: datetime, end_date: datetime) -> AutomationMetric:
    async with db_manager.get_session() as session:
        row = (
            await session.execute(
                text(
                    """
                    SELECT
                        COUNT(*) AS total,
                        COUNT(*) FILTER (WHERE status = 'completed') AS successful,
                        AVG(EXTRACT(EPOCH FROM (COALESCE(completed_at, started_at) - started_at))) AS avg_seconds
                    FROM playbook_executions
                    WHERE started_at BETWEEN :start AND :end
                    """
                ),
                {"start": start_date, "end": end_date},
            )
        ).fetchone()

    total = row.total if row else 0
    successful = row.successful if row else 0
    avg_seconds = row.avg_seconds if row else 0.0
    return AutomationMetric(
        playbooks_executed=total or 0,
        actions_executed=total or 0,
        success_rate=(successful / total) if total else 0.0,
        avg_execution_time_seconds=round(avg_seconds or 0.0, 2),
        time_saved_hours=(total or 0) * 0.5,
    )


async def fetch_trends(metric_type: str, start_date: datetime, end_date: datetime) -> list[TrendData]:
    if metric_type == "alert_volume":
        query = """
            SELECT DATE_TRUNC('hour', received_at) AS bucket, COUNT(*) AS value
            FROM alerts
            WHERE received_at BETWEEN :start AND :end
            GROUP BY bucket
            ORDER BY bucket
        """
    elif metric_type == "triage_accuracy":
        query = """
            SELECT DATE_TRUNC('hour', created_at) AS bucket, AVG(confidence_score) * 100 AS value
            FROM triage_results
            WHERE created_at BETWEEN :start AND :end
            GROUP BY bucket
            ORDER BY bucket
        """
    elif metric_type == "automation_rate":
        query = """
            SELECT DATE_TRUNC('hour', started_at) AS bucket,
                   COUNT(*) FILTER (WHERE status = 'completed')::float / NULLIF(COUNT(*), 0) * 100 AS value
            FROM playbook_executions
            WHERE started_at BETWEEN :start AND :end
            GROUP BY bucket
            ORDER BY bucket
        """
    else:
        raise HTTPException(status_code=404, detail=f"Unknown metric type: {metric_type}")

    async with db_manager.get_session() as session:
        result = await session.execute(text(query), {"start": start_date, "end": end_date})
        rows = result.fetchall()

    return [
        TrendData(
            timestamp=row.bucket,
            value=float(row.value or 0.0),
            label=row.bucket.strftime("%m-%d %H:%M"),
        )
        for row in rows
        if row.bucket is not None
    ]


@app.get("/api/v1/dashboard", response_model=Dict[str, Any])
async def get_dashboard():
    """Get complete dashboard data."""
    start_date, end_date = calculate_time_range(TimeRange.LAST_24H)
    alert_metrics = await fetch_alert_metrics(start_date, end_date)
    triage_metrics = await fetch_triage_metrics(start_date, end_date)
    automation_metrics = await fetch_automation_metrics(start_date, end_date)
    trends = {
        "alert_volume": [t.model_dump() for t in await fetch_trends("alert_volume", start_date, end_date)],
        "triage_accuracy": [t.model_dump() for t in await fetch_trends("triage_accuracy", start_date, end_date)],
        "automation_rate": [t.model_dump() for t in await fetch_trends("automation_rate", start_date, end_date)],
    }

    async with db_manager.get_session() as session:
        top_rows = (
            await session.execute(
                text(
                    """
                    SELECT alert_id, alert_type, severity, description
                    FROM alerts
                    WHERE received_at BETWEEN :start AND :end
                    ORDER BY
                      CASE severity
                        WHEN 'critical' THEN 5
                        WHEN 'high' THEN 4
                        WHEN 'medium' THEN 3
                        WHEN 'low' THEN 2
                        ELSE 1
                      END DESC,
                      received_at DESC
                    LIMIT 5
                    """
                ),
                {"start": start_date, "end": end_date},
            )
        ).fetchall()

    dashboard = DashboardData(
        alert_metrics=alert_metrics,
        triage_metrics=triage_metrics,
        automation_metrics=automation_metrics,
        trends=trends,
        top_alerts=[
            {
                "alert_id": row.alert_id,
                "type": row.alert_type,
                "severity": row.severity,
                "description": row.description,
            }
            for row in top_rows
        ],
    )
    return {"success": True, "data": dashboard.model_dump(), "meta": response_meta()}


@app.get("/api/v1/metrics/alerts", response_model=Dict[str, Any])
async def get_alert_metrics(time_range: TimeRange = Query(TimeRange.LAST_24H)):
    start_date, end_date = calculate_time_range(time_range)
    metrics = await fetch_alert_metrics(start_date, end_date)
    return {
        "success": True,
        "data": metrics.model_dump(),
        "meta": response_meta({"time_range": {"start": start_date.isoformat(), "end": end_date.isoformat()}}),
    }


@app.get("/api/v1/metrics/triage", response_model=Dict[str, Any])
async def get_triage_metrics_endpoint(time_range: TimeRange = Query(TimeRange.LAST_24H)):
    start_date, end_date = calculate_time_range(time_range)
    metrics = await fetch_triage_metrics(start_date, end_date)
    return {
        "success": True,
        "data": metrics.model_dump(),
        "meta": response_meta({"time_range": {"start": start_date.isoformat(), "end": end_date.isoformat()}}),
    }


@app.get("/api/v1/metrics/automation", response_model=Dict[str, Any])
async def get_automation_metrics(time_range: TimeRange = Query(TimeRange.LAST_24H)):
    start_date, end_date = calculate_time_range(time_range)
    metrics = await fetch_automation_metrics(start_date, end_date)
    return {
        "success": True,
        "data": metrics.model_dump(),
        "meta": response_meta({"time_range": {"start": start_date.isoformat(), "end": end_date.isoformat()}}),
    }


@app.get("/api/v1/trends/{metric_type}", response_model=Dict[str, Any])
async def get_trends(metric_type: str, time_range: TimeRange = Query(TimeRange.LAST_24H)):
    start_date, end_date = calculate_time_range(time_range)
    trends = await fetch_trends(metric_type, start_date, end_date)
    return {
        "success": True,
        "data": {
            "metric_type": metric_type,
            "time_range": time_range.value,
            "trends": [trend.model_dump() for trend in trends],
        },
        "meta": response_meta(),
    }


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    async with db_manager.get_session() as session:
        total_alerts = await session.scalar(text("SELECT COUNT(*) FROM alerts"))
    return {
        "status": "healthy",
        "service": "data-analytics",
        "timestamp": utc_now_iso(),
        "metrics": {"total_alerts": total_alerts or 0},
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=config.host, port=config.port)
