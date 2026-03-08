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

"""Reporting Service - Generates various security reports."""

import csv
import io
import json
import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy import func, select, text

from shared.database import DatabaseManager, get_database_manager, init_database, close_database
from shared.database.models import Report
from shared.utils import Config, get_logger, utc_now, utc_now_iso

logger = get_logger(__name__)
config = Config()

db_manager: DatabaseManager = None
REPORT_DIR = Path(os.getenv("REPORT_OUTPUT_DIR", "data/reports"))


class ReportFormat(str, Enum):
    PDF = "pdf"
    HTML = "html"
    CSV = "csv"
    JSON = "json"


class ReportType(str, Enum):
    DAILY_SUMMARY = "daily_summary"
    WEEKLY_SUMMARY = "weekly_summary"
    MONTHLY_SUMMARY = "monthly_summary"
    INCIDENT_REPORT = "incident_report"
    TREND_ANALYSIS = "trend_analysis"
    CUSTOM = "custom"


class ReportStatus(str, Enum):
    PENDING = "pending"
    GENERATING = "generating"
    COMPLETED = "completed"
    FAILED = "failed"


class ReportGenerateRequest(BaseModel):
    name: Optional[str] = Field(default=None, description="Display name for the report")
    description: Optional[str] = Field(default=None, description="Optional description")
    format: Optional[str] = Field(default=ReportFormat.HTML.value, description="Requested output format")
    report_type: ReportType
    date: Optional[str] = Field(default=None, description="Date for summary reports (YYYY-MM-DD)")
    alert_id: Optional[str] = Field(default=None, description="Alert ID for incident reports")
    parameters: Optional[Dict[str, Any]] = Field(default=None)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifespan."""
    global db_manager
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    logger.info("Starting Reporting service...")
    await init_database(
        database_url=config.database_url,
        pool_size=config.db_pool_size,
        max_overflow=config.db_max_overflow,
        echo=config.debug,
    )
    db_manager = get_database_manager()
    async with db_manager.engine.begin() as conn:
        await conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS reports (
                    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                    report_id VARCHAR(255) UNIQUE NOT NULL,
                    name VARCHAR(255) NOT NULL,
                    description TEXT,
                    report_type VARCHAR(50) NOT NULL,
                    format VARCHAR(20) NOT NULL,
                    status VARCHAR(50) NOT NULL DEFAULT 'pending',
                    filters JSON,
                    related_alerts JSON,
                    file_path VARCHAR(500),
                    file_size INTEGER,
                    created_by VARCHAR(255) NOT NULL DEFAULT 'system',
                    schedule_frequency VARCHAR(20),
                    schedule_time VARCHAR(10),
                    schedule_recipients TEXT[],
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    completed_at TIMESTAMPTZ,
                    error_message TEXT
                )
                """
            )
        )
    logger.info("Reporting service started successfully")
    yield
    await close_database()
    logger.info("Reporting service stopped")


app = FastAPI(
    title="Reporting Service",
    description="Generates various security reports and summaries",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def response_meta() -> Dict[str, str]:
    return {"timestamp": utc_now_iso(), "request_id": str(uuid.uuid4())}


def report_json_path(report_id: str) -> Path:
    return REPORT_DIR / f"{report_id}.json"


async def fetch_summary_data(start_date: datetime, end_date: datetime) -> Dict[str, Any]:
    """Fetch summary data for a time range from database."""
    async with db_manager.get_session() as session:
        total_result = await session.execute(
            text(
                """
                SELECT COUNT(*) AS total
                FROM alerts
                WHERE received_at BETWEEN :start AND :end
                """
            ),
            {"start": start_date, "end": end_date},
        )
        total_alerts = total_result.scalar() or 0

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

        triaged_result = await session.execute(
            text(
                """
                SELECT COUNT(*) AS triaged
                FROM triage_results
                WHERE created_at BETWEEN :start AND :end
                """
            ),
            {"start": start_date, "end": end_date},
        )
        triaged = triaged_result.scalar() or 0

        playbook_result = await session.execute(
            text(
                """
                SELECT COUNT(*) AS total
                FROM playbook_executions
                WHERE started_at BETWEEN :start AND :end
                """
            ),
            {"start": start_date, "end": end_date},
        )
        automation_executed = playbook_result.scalar() or 0

        top_alerts_result = await session.execute(
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
        top_alert_rows = top_alerts_result.fetchall()

    return {
        "total_alerts": total_alerts,
        "by_severity": by_severity,
        "triaged": triaged,
        "automation_executed": automation_executed,
        "top_alerts": [
            {
                "alert_id": r.alert_id,
                "type": r.alert_type,
                "severity": r.severity,
                "description": r.description,
            }
            for r in top_alert_rows
        ],
    }


async def get_report_row(report_id: str) -> Optional[Report]:
    async with db_manager.get_session() as session:
        result = await session.execute(select(Report).where(Report.report_id == report_id))
        return result.scalar_one_or_none()


async def create_report_row(report_id: str, request: ReportGenerateRequest) -> Report:
    normalized_format = request.format or ReportFormat.HTML.value
    if normalized_format == "pdf":
        normalized_format = ReportFormat.HTML.value
    elif normalized_format == "excel":
        normalized_format = ReportFormat.CSV.value

    async with db_manager.get_session() as session:
        report = Report(
            report_id=report_id,
            name=request.name or f"{request.report_type.value}-{report_id}",
            description=request.description or f"Generated report for {request.report_type.value}",
            report_type=request.report_type.value,
            format=normalized_format,
            status=ReportStatus.PENDING.value,
            filters=request.parameters or {},
            related_alerts={"alert_id": request.alert_id} if request.alert_id else None,
            created_by="system",
        )
        session.add(report)
        await session.commit()
        await session.refresh(report)
        return report


async def update_report_row(
    report_id: str,
    *,
    status: ReportStatus,
    file_path: Optional[str] = None,
    file_size: Optional[int] = None,
    error_message: Optional[str] = None,
) -> None:
    async with db_manager.get_session() as session:
        result = await session.execute(select(Report).where(Report.report_id == report_id))
        report = result.scalar_one_or_none()
        if not report:
            return
        report.status = status.value
        if file_path is not None:
            report.file_path = file_path
        if file_size is not None:
            report.file_size = file_size
        report.error_message = error_message
        if status == ReportStatus.COMPLETED:
            report.completed_at = utc_now()
        await session.commit()


def save_report_payload(report_id: str, data: Dict[str, Any]) -> Path:
    path = report_json_path(report_id)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def load_report_payload(report: Report) -> Dict[str, Any]:
    if not report.file_path:
        raise HTTPException(status_code=404, detail="Report data not available")
    path = Path(report.file_path)
    if not path.exists():
        raise HTTPException(status_code=404, detail="Report file not found")
    return json.loads(path.read_text(encoding="utf-8"))


async def generate_daily_summary(report_id: str, date: datetime):
    try:
        await update_report_row(report_id, status=ReportStatus.GENERATING)
        start_date = datetime(date.year, date.month, date.day)
        end_date = start_date + timedelta(days=1)
        summary = await fetch_summary_data(start_date, end_date)

        report_data = {
            "report_id": report_id,
            "report_type": ReportType.DAILY_SUMMARY.value,
            "date": date.date().isoformat(),
            "generated_at": utc_now_iso(),
            "summary": {
                "total_alerts": summary["total_alerts"],
                "critical_alerts": summary["by_severity"]["critical"],
                "high_alerts": summary["by_severity"]["high"],
                "medium_alerts": summary["by_severity"]["medium"],
                "low_alerts": summary["by_severity"]["low"],
                "triaged_alerts": summary["triaged"],
                "automation_executed": summary["automation_executed"],
                "time_saved_hours": summary["automation_executed"] * 0.5,
            },
            "top_alerts": summary["top_alerts"],
            "recommendations": [
                "Update firewall rules for known malicious IPs",
                "Conduct security awareness training for phishing",
                "Review EDR policies for endpoint protection",
            ],
        }

        path = save_report_payload(report_id, report_data)
        await update_report_row(
            report_id,
            status=ReportStatus.COMPLETED,
            file_path=str(path),
            file_size=path.stat().st_size,
        )
    except Exception as exc:
        logger.error(f"Failed to generate daily summary: {exc}", exc_info=True)
        await update_report_row(report_id, status=ReportStatus.FAILED, error_message=str(exc))


async def generate_incident_report(report_id: str, alert_id: str):
    try:
        await update_report_row(report_id, status=ReportStatus.GENERATING)
        async with db_manager.get_session() as session:
            alert_result = await session.execute(
                text(
                    """
                    SELECT alert_id, alert_type, severity, received_at, description
                    FROM alerts
                    WHERE alert_id = :alert_id
                    """
                ),
                {"alert_id": alert_id},
            )
            alert_row = alert_result.fetchone()
            triage_result = await session.execute(
                text(
                    """
                    SELECT risk_level, confidence_score, analysis_result, created_at
                    FROM triage_results
                    WHERE alert_id = :alert_id
                    """
                ),
                {"alert_id": alert_id},
            )
            triage_row = triage_result.fetchone()

        if not alert_row:
            raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")

        report_data = {
            "report_id": report_id,
            "report_type": ReportType.INCIDENT_REPORT.value,
            "alert_id": alert_id,
            "generated_at": utc_now_iso(),
            "incident_details": {
                "alert_id": alert_id,
                "type": alert_row.alert_type,
                "severity": alert_row.severity,
                "first_seen": alert_row.received_at.isoformat() if alert_row.received_at else None,
                "description": alert_row.description,
            },
            "triage_details": {
                "risk_level": triage_row.risk_level if triage_row else "unknown",
                "confidence": float(triage_row.confidence_score) if triage_row else 0.0,
                "triaged_at": triage_row.created_at.isoformat() if triage_row else None,
                "reasoning": triage_row.analysis_result if triage_row else "No triage result",
            },
        }

        path = save_report_payload(report_id, report_data)
        await update_report_row(
            report_id,
            status=ReportStatus.COMPLETED,
            file_path=str(path),
            file_size=path.stat().st_size,
        )
    except Exception as exc:
        logger.error(f"Failed to generate incident report: {exc}", exc_info=True)
        await update_report_row(report_id, status=ReportStatus.FAILED, error_message=str(exc))


async def generate_period_summary(report_id: str, start_date: datetime, end_date: datetime, label: str):
    try:
        await update_report_row(report_id, status=ReportStatus.GENERATING)
        summary = await fetch_summary_data(start_date, end_date)
        report_data = {
            "report_id": report_id,
            "report_type": label,
            "start_date": start_date.date().isoformat(),
            "end_date": end_date.date().isoformat(),
            "generated_at": utc_now_iso(),
            "summary": summary,
        }
        path = save_report_payload(report_id, report_data)
        await update_report_row(
            report_id,
            status=ReportStatus.COMPLETED,
            file_path=str(path),
            file_size=path.stat().st_size,
        )
    except Exception as exc:
        logger.error(f"Failed to generate period summary: {exc}", exc_info=True)
        await update_report_row(report_id, status=ReportStatus.FAILED, error_message=str(exc))


def format_report_html(report_data: Dict[str, Any]) -> str:
    return f"""
<!DOCTYPE html>
<html>
<head>
    <title>{report_data['report_type'].replace('_', ' ').title()}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1 {{ color: #333; }}
        .section {{ margin: 20px 0; }}
        pre {{ background: #f5f5f5; padding: 16px; border-radius: 6px; }}
    </style>
</head>
<body>
    <h1>{report_data['report_type'].replace('_', ' ').title()}</h1>
    <p><strong>Generated:</strong> {report_data.get('generated_at', 'N/A')}</p>
    <div class="section"><pre>{json.dumps(report_data, indent=2, ensure_ascii=False)}</pre></div>
</body>
</html>
"""


@app.post("/api/v1/reports/generate", response_model=Dict[str, Any])
async def generate_report(request: ReportGenerateRequest, background_tasks: BackgroundTasks):
    """Generate a report asynchronously and persist its metadata."""
    report_id = f"report-{uuid.uuid4()}"
    await create_report_row(report_id, request)

    if request.report_type == ReportType.DAILY_SUMMARY:
        report_date = datetime.fromisoformat(request.date) if request.date else utc_now()
        background_tasks.add_task(generate_daily_summary, report_id, report_date)
    elif request.report_type == ReportType.INCIDENT_REPORT:
        if not request.alert_id:
            raise HTTPException(status_code=400, detail="alert_id is required for incident reports")
        background_tasks.add_task(generate_incident_report, report_id, request.alert_id)
    elif request.report_type == ReportType.WEEKLY_SUMMARY:
        end_date = utc_now()
        background_tasks.add_task(generate_period_summary, report_id, end_date - timedelta(days=7), end_date, ReportType.WEEKLY_SUMMARY.value)
    elif request.report_type == ReportType.MONTHLY_SUMMARY:
        end_date = utc_now()
        background_tasks.add_task(generate_period_summary, report_id, end_date - timedelta(days=30), end_date, ReportType.MONTHLY_SUMMARY.value)
    elif request.report_type == ReportType.TREND_ANALYSIS:
        end_date = utc_now()
        background_tasks.add_task(generate_period_summary, report_id, end_date - timedelta(days=30), end_date, ReportType.TREND_ANALYSIS.value)
    else:
        await update_report_row(report_id, status=ReportStatus.FAILED, error_message="Report type not yet implemented")

    return {
        "success": True,
        "data": {
            "report_id": report_id,
            "name": request.name or f"{request.report_type.value}-{report_id}",
            "description": request.description or f"Generated report for {request.report_type.value}",
            "report_type": request.report_type.value,
            "format": request.format or ReportFormat.HTML.value,
            "status": ReportStatus.PENDING.value,
        },
        "meta": response_meta(),
    }


@app.get("/api/v1/reports/{report_id}", response_model=Dict[str, Any])
async def get_report(report_id: str):
    """Get report status and payload."""
    report = await get_report_row(report_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Report not found: {report_id}")

    payload = None
    if report.status == ReportStatus.COMPLETED.value and report.file_path:
        payload = load_report_payload(report)

    return {
        "success": True,
        "data": {
            "report_id": report.report_id,
            "name": report.name,
            "description": report.description,
            "report_type": report.report_type,
            "format": report.format,
            "status": report.status,
            "created_at": report.created_at.isoformat() if report.created_at else None,
            "completed_at": report.completed_at.isoformat() if report.completed_at else None,
            "file_path": report.file_path,
            "file_size": report.file_size,
            "created_by": report.created_by,
            "error": report.error_message,
            "payload": payload,
        },
        "meta": response_meta(),
    }


@app.get("/api/v1/reports/{report_id}/download")
async def download_report(report_id: str, format: ReportFormat = ReportFormat.HTML):
    """Download generated report in specified format."""
    report = await get_report_row(report_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Report not found: {report_id}")
    if report.status != ReportStatus.COMPLETED.value:
        raise HTTPException(status_code=400, detail=f"Report not ready. Current status: {report.status}")

    report_data = load_report_payload(report)
    if format == ReportFormat.HTML and report.format in {ReportFormat.JSON.value, ReportFormat.CSV.value}:
        format = ReportFormat(report.format)

    if format == ReportFormat.HTML:
        return Response(
            content=format_report_html(report_data),
            media_type="text/html",
            headers={"Content-Disposition": f"attachment; filename={report_id}.html"},
        )
    if format == ReportFormat.JSON:
        return JSONResponse(
            content=report_data,
            headers={"Content-Disposition": f"attachment; filename={report_id}.json"},
        )
    if format == ReportFormat.CSV:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Key", "Value"])
        for key, value in report_data.items():
            writer.writerow([key, json.dumps(value, ensure_ascii=False) if isinstance(value, (dict, list)) else value])
        return Response(
            content=output.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename={report_id}.csv"},
        )
    raise HTTPException(status_code=501, detail="PDF format not yet implemented")


@app.get("/api/v1/reports", response_model=Dict[str, Any])
async def list_reports(status: Optional[ReportStatus] = None, report_type: Optional[ReportType] = None):
    """List persisted reports."""
    async with db_manager.get_session() as session:
        query = select(Report).order_by(Report.created_at.desc())
        if status:
            query = query.where(Report.status == status.value)
        if report_type:
            query = query.where(Report.report_type == report_type.value)
        result = await session.execute(query)
        reports = result.scalars().all()

    data = [
        {
            "report_id": row.report_id,
            "name": row.name,
            "description": row.description,
            "report_type": row.report_type,
            "format": row.format,
            "status": row.status,
            "created_at": row.created_at.isoformat() if row.created_at else None,
            "completed_at": row.completed_at.isoformat() if row.completed_at else None,
            "file_size": row.file_size,
            "created_by": row.created_by,
            "error": row.error_message,
        }
        for row in reports
    ]
    return {"success": True, "data": {"reports": data, "total": len(data)}, "meta": response_meta()}


@app.delete("/api/v1/reports/{report_id}", response_model=Dict[str, Any])
async def delete_report(report_id: str):
    """Delete a report and its stored payload."""
    async with db_manager.get_session() as session:
        result = await session.execute(select(Report).where(Report.report_id == report_id))
        report = result.scalar_one_or_none()
        if not report:
            raise HTTPException(status_code=404, detail=f"Report not found: {report_id}")
        if report.file_path and Path(report.file_path).exists():
            Path(report.file_path).unlink()
        await session.delete(report)
        await session.commit()
    return {"success": True, "message": "Report deleted", "meta": response_meta()}


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    async with db_manager.get_session() as session:
        total = await session.scalar(select(func.count()).select_from(Report))
        completed = await session.scalar(
            select(func.count()).select_from(Report).where(Report.status == ReportStatus.COMPLETED.value)
        )
    return {
        "status": "healthy",
        "service": "reporting-service",
        "timestamp": utc_now_iso(),
        "reports": {"total": total or 0, "completed": completed or 0},
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=config.host, port=config.port)
