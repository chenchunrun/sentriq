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
Alert management API endpoints.

Provides REST endpoints for alert CRUD operations, filtering,
status updates, and triage management.
"""

from typing import Dict, List, Optional
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

import sys
sys.path.insert(0, '/Users/newmba/security')

from loguru import logger

from shared.database.base import get_database_manager
from shared.database.models import Alert, TriageResult
from shared.database.repositories.alert_repository import AlertRepository
from shared.database.repositories.triage_repository import TriageRepository
from shared.models.alert import AlertFilter, AlertStatus, AlertType, Severity

from models.requests import (
    AlertBulkActionRequest,
    AlertCreateRequest,
    AlertFilterRequest,
    AlertStatusUpdateRequest,
)
from models.responses import (
    AlertDetailResponse,
    AlertResponse,
    AlertStatsResponse,
    BulkActionResponse,
    PaginatedResponse,
    TriageResultResponse,
)
from routes.auth import require_permissions
from shared.utils.time import utc_now

router = APIRouter()
SUPPORTED_ALERT_STATUSES = {
    "pending",
    "analyzing",
    "analyzed",
    "investigating",
    "resolved",
    "false_positive",
    "suppressed",
}


# =============================================================================
# Dependencies
# =============================================================================

async def get_db_session() -> AsyncSession:
    """Get database session."""
    db_manager = get_database_manager()
    async with db_manager.get_session() as session:
        yield session


# =============================================================================
# Helper Functions
# =============================================================================

def alert_to_response(alert: Alert) -> AlertResponse:
    """Convert Alert model to AlertResponse."""
    return AlertResponse(
        alert_id=alert.alert_id,
        timestamp=getattr(alert, "timestamp", None) or alert.received_at,
        alert_type=alert.alert_type,
        severity=alert.severity,
        status=alert.status,
        title=alert.title,
        description=alert.description,
        source_ip=str(alert.source_ip) if alert.source_ip else None,
        destination_ip=str(alert.destination_ip) if alert.destination_ip else None,
        file_hash=alert.file_hash,
        url=alert.url,
        asset_id=alert.asset_id,
        user_id=alert.user_id,
        risk_score=getattr(alert, "risk_score", None),
        confidence=getattr(alert, "confidence", None),
        assigned_to=str(getattr(alert, "assigned_to", "")) if getattr(alert, "assigned_to", None) else None,
        source=getattr(alert, "source", None),
        tags=getattr(alert, "tags", None) or [],
        created_at=alert.created_at,
        updated_at=alert.updated_at,
    )


async def get_alert_with_details(
    alert_id: str,
    session: AsyncSession,
) -> Dict:
    """
    Get alert with triage result and context.

    Args:
        alert_id: Alert ID
        session: Database session

    Returns:
        Dictionary with alert details
    """
    # Get alert
    result = await session.execute(
        select(Alert).where(Alert.alert_id == alert_id)
    )
    alert = result.scalar_one_or_none()

    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert not found: {alert_id}",
        )

    # Get triage result
    triage_result = None
    triage_result_id = getattr(alert, "triage_result_id", None)
    if triage_result_id:
        triage_result = await session.execute(
            select(TriageResult).where(TriageResult.id == triage_result_id)
        )
        triage_result = triage_result.scalar_one_or_none()

    return {
        "alert": alert,
        "triage_result": triage_result,
    }


# =============================================================================
# List Alerts
# =============================================================================

@router.get(
    "",
    response_model=PaginatedResponse,
    summary="List Alerts",
    description="Retrieve alerts with filtering and pagination",
)
async def list_alerts(
    alert_type: Optional[str] = Query(None, description="Filter by alert type"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    status: Optional[str] = Query(None, description="Filter by status"),
    source_ip: Optional[str] = Query(None, description="Filter by source IP"),
    search: Optional[str] = Query(None, description="Text search"),
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(100, ge=1, le=1000, description="Max records to return"),
    sort_by: str = Query("received_at", description="Field to sort by"),
    sort_order: str = Query("desc", pattern="^(asc|desc)$", description="Sort order"),
    current_user=Depends(require_permissions("alerts:read")),
    session: AsyncSession = Depends(get_db_session),
):
    """
    List alerts with filtering and pagination.

    Supports filtering by alert type, severity, status, source IP,
    and text search. Results are paginated and sortable.
    """
    repo = AlertRepository(session)

    # Build filter object
    filters = AlertFilter()

    if alert_type:
        try:
            filters.alert_type = AlertType(alert_type)
        except ValueError:
            pass  # Invalid alert type, ignore

    if severity:
        try:
            filters.severity = Severity(severity)
        except ValueError:
            pass

    if status:
        try:
            filters.status = AlertStatus(status)
        except ValueError:
            pass

    if source_ip:
        filters.source_ip = source_ip

    if search:
        filters.search = search

    # Get alerts
    alerts, total = await repo.get_alerts_by_filter(
        filters=filters,
        skip=skip,
        limit=limit,
        sort_by=sort_by,
        sort_order=sort_order,
    )

    # Convert to response models
    alert_responses = [alert_to_response(alert) for alert in alerts]

    return PaginatedResponse.create(
        items=alert_responses,
        total=total,
        skip=skip,
        limit=limit,
        success=True,
    )


# =============================================================================
# Get Alert by ID
# =============================================================================

@router.get(
    "/{alert_id}",
    response_model=AlertDetailResponse,
    summary="Get Alert Details",
    description="Retrieve detailed information about a specific alert",
)
async def get_alert(
    alert_id: str,
    current_user=Depends(require_permissions("alerts:read")),
    session: AsyncSession = Depends(get_db_session),
):
    """
    Get alert by ID with full details including triage result.
    """
    data = await get_alert_with_details(alert_id, session)
    alert = data["alert"]
    triage_result = data["triage_result"]

    response_data = {
        **alert_to_response(alert).model_dump(),
        "triage_result": None,
        "threat_intel": None,
        "network_context": None,
        "asset_context": None,
        "user_context": None,
    }

    # Add triage result
    if triage_result:
        response_data["triage_result"] = {
            "id": str(triage_result.id),
            "risk_score": triage_result.risk_score,
            "risk_level": triage_result.risk_level,
            "confidence": triage_result.confidence,
            "analysis": triage_result.analysis,
            "key_findings": triage_result.key_findings or [],
            "iocs_identified": triage_result.iocs_identified or {},
            "requires_human_review": triage_result.requires_human_review,
            "model_used": triage_result.model_used,
            "created_at": triage_result.created_at,
        }

    return AlertDetailResponse(**response_data)


# =============================================================================
# Create Alert
# =============================================================================

@router.post(
    "",
    response_model=AlertResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create Alert",
    description="Create a new security alert",
)
async def create_alert(
    alert_data: AlertCreateRequest,
    current_user=Depends(require_permissions("alerts:write")),
    session: AsyncSession = Depends(get_db_session),
):
    """
    Create a new security alert.

    The alert will be processed by the normalizer and enriched
    with context and threat intelligence.
    """
    repo = AlertRepository(session)

    # Generate alert ID
    alert_id = f"alert-{uuid4()}"

    # Prepare alert data
    alert_dict = {
        "alert_id": alert_id,
        "received_at": utc_now(),
        "alert_type": alert_data.alert_type,
        "severity": alert_data.severity,
        "status": "pending",
        "title": alert_data.title,
        "description": alert_data.description,
        "source_ip": alert_data.source_ip,
        "destination_ip": alert_data.destination_ip,
        "file_hash": alert_data.file_hash,
        "url": alert_data.url,
        "asset_id": alert_data.asset_id,
        "user_id": alert_data.user_id,
        "raw_data": {
            **(alert_data.raw_data or {}),
            **({"source": alert_data.source} if alert_data.source else {}),
        } or None,
    }

    # Create alert
    alert = await repo.create_alert(alert_dict)
    await session.commit()
    await session.refresh(alert)

    logger.info(
        "Alert created via API",
        extra={"alert_id": alert_id, "api": True},
    )

    return alert_to_response(alert)


# =============================================================================
# Update Alert Status
# =============================================================================

@router.patch(
    "/{alert_id}/status",
    response_model=AlertResponse,
    summary="Update Alert Status",
    description="Update the status of an alert",
)
async def update_alert_status(
    alert_id: str,
    status_update: AlertStatusUpdateRequest,
    current_user=Depends(require_permissions("alerts:write")),
    session: AsyncSession = Depends(get_db_session),
):
    """
    Update alert status.

    Supported status transitions:
    - new → in_progress
    - in_progress → assigned
    - assigned → resolved
    - resolved → closed
    """
    repo = AlertRepository(session)

    status_value = status_update.status.strip().lower()
    if status_value not in SUPPORTED_ALERT_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid status: {status_update.status}",
        )

    # Update status
    alert = await repo.update_alert_status(
        alert_id=alert_id,
        status=status_value,
        assigned_to=status_update.assigned_to,
        comment=status_update.comment,
    )

    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert not found: {alert_id}",
        )

    logger.info(
        "Alert status updated",
        extra={
            "alert_id": alert_id,
            "new_status": status_value,
        },
    )

    return alert_to_response(alert)


# =============================================================================
# Get Alert Statistics
# =============================================================================

@router.get(
    "/stats/summary",
    response_model=AlertStatsResponse,
    summary="Get Alert Statistics",
    description="Retrieve alert statistics and counts",
)
async def get_alert_stats(
    current_user=Depends(require_permissions("alerts:read")),
    session: AsyncSession = Depends(get_db_session),
):
    """
    Get alert statistics including counts by severity, status, and type.
    """
    repo = AlertRepository(session)

    # Get counts
    by_severity = await repo.get_alerts_count_by_severity()
    by_status = await repo.get_alerts_count_by_status()
    by_type = await repo.get_alerts_count_by_type()

    # Get high priority alerts
    high_priority = await repo.get_high_priority_alerts(min_risk_score=70.0, limit=1000)
    high_priority_count = len(high_priority)

    # Get pending review count
    triage_repo = TriageRepository(session)
    pending_review = await triage_repo.get_pending_review_count()

    # Get total count
    total = sum(by_severity.values())

    # Get average risk score
    avg_risk = await triage_repo.get_average_risk_score()

    return AlertStatsResponse(
        total_alerts=total,
        by_severity=by_severity,
        by_status=by_status,
        by_type=by_type,
        avg_risk_score=avg_risk,
        high_priority_count=high_priority_count,
        pending_review_count=pending_review,
    )


# =============================================================================
# Get High Priority Alerts
# =============================================================================

@router.get(
    "/high-priority",
    response_model=List[AlertResponse],
    summary="Get High Priority Alerts",
    description="Retrieve high-priority alerts based on risk score",
)
async def get_high_priority_alerts(
    min_risk_score: float = Query(70.0, ge=0, le=100, description="Minimum risk score"),
    limit: int = Query(100, ge=1, le=1000, description="Max results"),
    current_user=Depends(require_permissions("alerts:read")),
    session: AsyncSession = Depends(get_db_session),
):
    """
    Get high-priority alerts with risk score above threshold.
    """
    repo = AlertRepository(session)

    alerts = await repo.get_high_priority_alerts(
        min_risk_score=min_risk_score,
        skip=0,
        limit=limit,
    )

    return [alert_to_response(alert) for alert in alerts]


# =============================================================================
# Get Active Alerts
# =============================================================================

@router.get(
    "/active",
    response_model=List[AlertResponse],
    summary="Get Active Alerts",
    description="Retrieve active (non-resolved/closed) alerts",
)
async def get_active_alerts(
    limit: int = Query(100, ge=1, le=1000, description="Max results"),
    current_user=Depends(require_permissions("alerts:read")),
    session: AsyncSession = Depends(get_db_session),
):
    """
    Get active alerts that are not resolved or closed.
    """
    repo = AlertRepository(session)

    alerts = await repo.get_active_alerts(skip=0, limit=limit)

    return [alert_to_response(alert) for alert in alerts]


# =============================================================================
# Bulk Actions
# =============================================================================

@router.post(
    "/bulk",
    response_model=BulkActionResponse,
    summary="Bulk Action on Alerts",
    description="Perform bulk actions on multiple alerts",
)
async def bulk_action(
    action_request: AlertBulkActionRequest,
    current_user=Depends(require_permissions("alerts:write")),
    session: AsyncSession = Depends(get_db_session),
):
    """
    Perform bulk actions on multiple alerts.

    Supported actions:
    - assign: Assign alerts to a user
    - close: Close multiple alerts
    - resolve: Mark alerts as resolved
    """
    repo = AlertRepository(session)

    action = action_request.action
    alert_ids = action_request.alert_ids
    params = action_request.params or {}

    success_count = 0
    failure_count = 0
    errors = []

    for alert_id in alert_ids:
        try:
            if action == "close":
                await repo.close_alert(alert_id)
                success_count += 1
            elif action == "assign":
                user_id = params.get("user_id")
                if not user_id:
                    raise ValueError("user_id required for assign action")
                await repo.assign_alert(alert_id, user_id)
                success_count += 1
            else:
                raise ValueError(f"Unsupported action: {action}")
        except Exception as e:
            failure_count += 1
            errors.append({
                "alert_id": alert_id,
                "error": str(e),
            })

    logger.info(
        "Bulk action completed",
        extra={
            "action": action,
            "total": len(alert_ids),
            "success": success_count,
            "failure": failure_count,
        },
    )

    return BulkActionResponse(
        action=action,
        total=len(alert_ids),
        success_count=success_count,
        failure_count=failure_count,
        errors=errors,
    )


# =============================================================================
# Get Triage Result
# =============================================================================

@router.get(
    "/{alert_id}/triage",
    response_model=TriageResultResponse,
    summary="Get Alert Triage Result",
    description="Retrieve the AI triage result for an alert",
)
async def get_triage_result(
    alert_id: str,
    current_user=Depends(require_permissions("triage:read")),
    session: AsyncSession = Depends(get_db_session),
):
    """
    Get the AI triage result for an alert.
    """
    repo = TriageRepository(session)

    triage_result = await repo.get_triage_result_by_alert_id(alert_id)

    if not triage_result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Triage result not found for alert: {alert_id}",
        )

    return TriageResultResponse(
        id=str(triage_result.id),
        alert_id=triage_result.alert_id,
        risk_score=triage_result.risk_score,
        risk_level=triage_result.risk_level,
        confidence=triage_result.confidence,
        analysis=triage_result.analysis,
        key_findings=triage_result.key_findings or [],
        iocs_identified=triage_result.iocs_identified or {},
        threat_intel_summary=triage_result.threat_intel_summary,
        requires_human_review=triage_result.requires_human_review,
        reviewed_by=str(triage_result.reviewed_by) if triage_result.reviewed_by else None,
        reviewed_at=triage_result.reviewed_at,
        reviewer_comments=triage_result.reviewer_comments,
        model_used=triage_result.model_used,
        processing_time_ms=triage_result.processing_time_ms,
        created_at=triage_result.created_at,
    )
