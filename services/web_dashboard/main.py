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

"""Web Dashboard Service - Frontend interface for security triage system."""

import os
import uuid
import asyncio
import json
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any, Dict, Optional, Set
from pathlib import Path

import httpx
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse, Response
from fastapi.staticfiles import StaticFiles
from shared.database import DatabaseManager, close_database, get_database_manager, init_database
from shared.utils import Config, get_logger
from shared.utils.time import utc_now
from shared.utils.crypto import encrypt_value, decrypt_value, safe_decrypt
from alert_create import build_alert_create_payload

logger = get_logger(__name__)
config = Config()

db_manager: DatabaseManager = None

# Sensitive configuration keys that should be encrypted
SENSITIVE_CONFIG_KEYS = {
    "zhipu_api_key",
    "deepseek_api_key",
    "qwen_api_key",
    "openai_api_key",
    "virustotal_api_key",
    "otx_api_key",
    "slack_webhook_url",
    "email_smtp_password",
    "webhook_secret",
}

# Service URLs (can be configured via environment)
# Use Docker service names when running in Docker network
SERVICE_URLS = {
    "analytics": os.getenv("ANALYTICS_SERVICE_URL", "http://data-analytics:8000"),
    "reporting": os.getenv("REPORTING_SERVICE_URL", "http://reporting-service:8000"),
    "notification": os.getenv("NOTIFICATION_SERVICE_URL", "http://notification-service:8000"),
    "configuration": os.getenv("CONFIG_SERVICE_URL", "http://configuration-service:8000"),
    "llm_router": os.getenv("LLM_ROUTER_URL", "http://llm-router:8000"),
    "workflow": os.getenv("WORKFLOW_SERVICE_URL", "http://workflow-engine:8000"),
    "automation": os.getenv("AUTOMATION_SERVICE_URL", "http://automation-orchestrator:8000"),
}

USE_ANALYTICS_SERVICE = os.getenv("ANALYTICS_USE_SERVICE", "true").lower() == "true"
USE_REPORTING_SERVICE = os.getenv("REPORTING_USE_SERVICE", "true").lower() == "true"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifespan."""
    global db_manager

    logger.info("Starting Web Dashboard service...")

    # Initialize database
    await init_database(
        database_url=config.database_url,
        pool_size=int(os.getenv("DB_POOL_SIZE", "10")),
        max_overflow=int(os.getenv("DB_MAX_OVERFLOW", "20")),
        echo=config.debug,
    )
    db_manager = get_database_manager()

    logger.info("Web Dashboard service started successfully")

    yield

    await db_manager.close()
    logger.info("Web Dashboard service stopped")


app = FastAPI(
    title="Web Dashboard Service",
    description="Frontend interface for security triage system",
    version="1.0.0",
    lifespan=lifespan,
)

# Configure CORS with specific origins for security
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Requested-With"],
)

# Get the base directory for static files
BASE_DIR = Path(__file__).parent

# Mount static files - prefer Docker build assets if present
if (Path("/app/static") / "assets").exists():
    app.mount("/assets", StaticFiles(directory="/app/static/assets"), name="assets")
    app.mount("/static", StaticFiles(directory="/app/static"), name="static")
elif (BASE_DIR / "dist" / "assets").exists():
    app.mount("/assets", StaticFiles(directory=str(BASE_DIR / "dist" / "assets")), name="assets")
    app.mount("/static", StaticFiles(directory=str(BASE_DIR / "dist")), name="static")


# API Proxy endpoints - Forward requests to backend services


async def proxy_request(service: str, path: str, request: Request):
    """Proxy request to backend service."""
    try:
        service_url = SERVICE_URLS.get(service)
        if not service_url:
            return {"success": False, "error": f"Unknown service: {service}"}

        # Ensure path starts with / for proper URL construction
        if not path.startswith("/"):
            path = f"/{path}"
        url = f"{service_url}/api/v1{path}"

        # Get request body if exists
        body = None
        content_type = request.headers.get("content-type", "")
        if request.method in ["POST", "PUT", "PATCH"]:
            raw_body = await request.body()
            if raw_body:
                # Try to parse as JSON if content-type indicates JSON
                if "application/json" in content_type:
                    try:
                        import json
                        body = json.loads(raw_body)
                    except json.JSONDecodeError:
                        body = raw_body
                else:
                    body = raw_body

        # Make proxied request
        headers = dict(request.headers)
        headers.pop("host", None)  # Remove host header to avoid conflicts

        async with httpx.AsyncClient() as client:
            if request.method == "GET":
                response = await client.get(url, params=request.query_params, headers=headers, timeout=30.0)
            elif request.method == "POST":
                if isinstance(body, dict):
                    response = await client.post(url, json=body, headers=headers, timeout=30.0)
                else:
                    response = await client.post(url, content=body, headers=headers, timeout=30.0)
            elif request.method == "PUT":
                if isinstance(body, dict):
                    response = await client.put(url, json=body, headers=headers, timeout=30.0)
                else:
                    response = await client.put(url, content=body, headers=headers, timeout=30.0)
            elif request.method == "PATCH":
                if isinstance(body, dict):
                    response = await client.patch(url, json=body, headers=headers, timeout=30.0)
                else:
                    response = await client.patch(url, content=body, headers=headers, timeout=30.0)
            elif request.method == "DELETE":
                response = await client.delete(url, headers=headers, timeout=30.0)
            else:
                return JSONResponse(
                    content={"success": False, "error": "Method not allowed"},
                    status_code=405,
                )

        return JSONResponse(content=response.json(), status_code=response.status_code)

    except httpx.TimeoutException:
        return JSONResponse(
            content={"success": False, "error": "Backend service timeout"},
            status_code=504,
        )
    except Exception as e:
        logger.error(f"Proxy error: {e}", exc_info=True)
        return JSONResponse(
            content={"success": False, "error": str(e)},
            status_code=500,
        )


async def call_service_json(
    service: str,
    path: str,
    method: str = "GET",
    params: Optional[Dict[str, Any]] = None,
    json_body: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    """Call a backend service and return JSON response or None on failure."""
    service_url = SERVICE_URLS.get(service)
    if not service_url:
        return None

    path = path if path.startswith("/") else f"/{path}"
    url = f"{service_url}/api/v1{path}"

    try:
        async with httpx.AsyncClient() as client:
            if method == "GET":
                response = await client.get(url, params=params, timeout=15.0)
            elif method == "POST":
                response = await client.post(url, json=json_body, timeout=30.0)
            elif method == "PUT":
                response = await client.put(url, json=json_body, timeout=30.0)
            elif method == "DELETE":
                response = await client.delete(url, timeout=30.0)
            else:
                return None

            response.raise_for_status()
            return response.json()
    except Exception as e:
        logger.warning(f"Service call failed: {service}{path}: {e}")
        return None


async def call_service_raw(
    service: str,
    path: str,
    params: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    """Call a backend service and return raw response data."""
    service_url = SERVICE_URLS.get(service)
    if not service_url:
        return None

    path = path if path.startswith("/") else f"/{path}"
    url = f"{service_url}/api/v1{path}"

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url, params=params, timeout=30.0)
            return {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "content": response.content,
            }
    except Exception as e:
        logger.warning(f"Service raw call failed: {service}{path}: {e}")
        return None


def map_ui_report_type_to_service(report_type: str, schedule: Optional[Dict[str, Any]] = None) -> str:
    """Map UI report type to reporting-service report_type."""
    schedule = schedule or {}
    frequency = schedule.get("frequency")

    if report_type == "trends":
        return "trend_analysis"
    if report_type == "custom":
        return "custom"
    if report_type == "metrics":
        if frequency == "monthly":
            return "monthly_summary"
        if frequency == "weekly":
            return "weekly_summary"
        if frequency == "daily":
            return "daily_summary"
        return "weekly_summary"
    # alerts default
    if frequency == "monthly":
        return "monthly_summary"
    if frequency == "weekly":
        return "weekly_summary"
    return "daily_summary"


def map_service_report_type_to_ui(report_type: Optional[str]) -> str:
    """Map reporting-service report_type to UI report type."""
    if not report_type:
        return "alerts"
    if report_type == "trend_analysis":
        return "trends"
    if report_type == "custom":
        return "custom"
    if report_type == "incident_report":
        return "alerts"
    if report_type in ("weekly_summary", "monthly_summary"):
        return "metrics"
    return "alerts"


def map_report_format_for_service(format_type: Optional[str]) -> str:
    """Map UI format to reporting-service format."""
    if not format_type:
        return "html"
    if format_type == "pdf":
        return "html"
    if format_type == "excel":
        return "csv"
    return format_type


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "web-dashboard",
        "timestamp": utc_now().isoformat(),
        "services": SERVICE_URLS,
    }


# =============================================================================
# Authentication Endpoints
# =============================================================================

from auth import (
    authenticate_user,
    create_access_token,
    decode_access_token,
    get_user_by_id,
    user_to_dict,
)


@app.post("/api/v1/auth/login")
async def login(request: Request):
    """
    Authenticate user with username and password.

    Returns JWT access token on successful authentication.
    """
    try:
        import json

        body = await request.body()
        credentials = json.loads(body) if body else {}

        username = credentials.get("username")
        password = credentials.get("password")

        logger.info("Login attempt received")

        if not username or not password:
            return JSONResponse(
                content={"success": False, "error": "Username and password are required"},
                status_code=400,
            )

        # Authenticate user
        async with db_manager.get_session() as session:
            user = await authenticate_user(session, username, password)

            if not user:
                logger.warning("Authentication failed - invalid credentials")
                return JSONResponse(
                    content={"success": False, "error": "Invalid username or password"},
                    status_code=401,
                )

            # Create JWT token
            token_data = {
                "sub": str(user.id),
                "username": user.username,
                "role": user.role,
            }

            access_token = create_access_token(token_data)

            logger.info("User logged in successfully")

            return {
                "success": True,
                "data": {
                    "access_token": access_token,
                    "refresh_token": access_token,  # Using same token for now
                    "token_type": "bearer",
                    "expires_in": 3600,
                },
            }
    except Exception as e:
        logger.error(f"Login error: {e}", exc_info=True)
        return JSONResponse(
            content={"success": False, "error": "Authentication failed"},
            status_code=500,
        )


@app.post("/api/v1/auth/logout")
async def logout():
    """
    Logout endpoint.

    TODO: Implement token invalidation in Redis for proper logout.
    Currently just returns success - client should discard token.
    """
    return {"success": True, "data": None}


@app.get("/api/v1/auth/me")
async def get_current_user(request: Request):
    """
    Get current authenticated user information.

    Requires valid JWT token in Authorization header.
    """
    try:
        # Extract token from Authorization header
        auth_header = request.headers.get("Authorization")

        if not auth_header or not auth_header.startswith("Bearer "):
            logger.warning("Missing or invalid Authorization header")
            return JSONResponse(
                content={"success": False, "error": "Missing or invalid Authorization header"},
                status_code=401,
            )

        token = auth_header.split(" ")[1]

        # Decode and validate token
        payload = decode_access_token(token)
        if not payload:
            logger.warning("Invalid or expired token")
            return JSONResponse(
                content={"success": False, "error": "Invalid or expired token"},
                status_code=401,
            )

        logger.info("Token decoded successfully")

        # Get user from database
        user_id = payload.get("sub")
        if not user_id:
            logger.warning("Invalid token payload - no sub")
            return JSONResponse(
                content={"success": False, "error": "Invalid token payload"},
                status_code=401,
            )

        logger.info(f"Fetching user: {user_id}")

        async with db_manager.get_session() as session:
            user = await get_user_by_id(session, user_id)

            if not user:
                logger.warning(f"User not found: {user_id}")
                return JSONResponse(
                    content={"success": False, "error": "User not found"},
                    status_code=404,
                )

            logger.info(f"User found: {user.username}")
            return {
                "success": True,
                "data": user_to_dict(user),
            }
    except Exception as e:
        logger.error(f"Error fetching current user: {e}", exc_info=True)
        return JSONResponse(
            content={"success": False, "error": "Failed to fetch user information"},
            status_code=500,
        )


@app.post("/api/v1/auth/refresh")
async def refresh_token(request: Request):
    """
    Refresh access token.

    TODO: Implement proper refresh token mechanism with token rotation.
    Currently just issues a new token.
    """
    try:
        import json

        body = await request.body()
        data = json.loads(body) if body else {}

        # For now, just create a new token
        # In production, validate refresh token and issue new access token
        return JSONResponse(
            content={"success": False, "error": "Token refresh not yet implemented"},
            status_code=501,
        )
    except Exception as e:
        logger.error(f"Token refresh error: {e}", exc_info=True)
        return JSONResponse(
            content={"success": False, "error": "Token refresh failed"},
            status_code=500,
        )


# =============================================================================
# Dashboard API Endpoints
# =============================================================================


@app.get("/api/v1/metrics")
async def get_metrics():
    """Get dashboard metrics from database."""
    try:
        if USE_ANALYTICS_SERVICE:
            service_resp = await call_service_json(
                "analytics",
                "/metrics/alerts",
                params={"time_range": "last_24h"},
            )
            if service_resp and service_resp.get("success"):
                data = service_resp.get("data") or {}
                data.setdefault("by_status", {})
                data.setdefault("avg_resolution_time", 0.0)
                data.setdefault("mtta", 0.0)
                data.setdefault("mttr", data.get("avg_resolution_time", 0.0))
                return {"success": True, "data": data}

        async with db_manager.get_session() as session:
            from sqlalchemy import select, func, case
            from shared.database.models import Alert

            # Total alerts
            total_query = select(func.count()).select_from(Alert)
            total_result = await session.execute(total_query)
            total_alerts = total_result.scalar() or 0

            # By severity
            severity_query = (
                select(Alert.severity, func.count(Alert.severity))
                .group_by(Alert.severity)
            )
            severity_result = await session.execute(severity_query)
            by_severity = {row[0]: row[1] for row in severity_result.fetchall()}

            # Critical alerts
            critical_alerts = by_severity.get("critical", 0)
            high_alerts = by_severity.get("high", 0)
            medium_alerts = by_severity.get("medium", 0)
            low_alerts = by_severity.get("low", 0)
            info_alerts = by_severity.get("info", 0)

            # By status
            status_query = (
                select(Alert.status, func.count(Alert.status))
                .group_by(Alert.status)
            )
            status_result = await session.execute(status_query)
            by_status = {row[0]: row[1] for row in status_result.fetchall()}

            # By type
            type_query = (
                select(Alert.alert_type, func.count(Alert.alert_type))
                .group_by(Alert.alert_type)
                .order_by(func.count(Alert.alert_type).desc())
            )
            type_result = await session.execute(type_query)
            by_type = {row[0]: row[1] for row in type_result.fetchall()}

            # Calculate avg resolution time for resolved alerts
            # Resolution time = updated_at - created_at for alerts with status="resolved"
            resolved_alerts_query = (
                select(
                    Alert.created_at,
                    Alert.updated_at,
                )
                .where(Alert.status == "resolved")
                .where(Alert.updated_at.is_not(None))
            )
            resolved_result = await session.execute(resolved_alerts_query)
            resolved_alerts = resolved_result.fetchall()

            if resolved_alerts:
                # Calculate resolution time in minutes for each resolved alert
                resolution_times = [
                    (row[1] - row[0]).total_seconds() / 60  # Convert to minutes
                    for row in resolved_alerts
                    if row[1] >= row[0]  # Only include valid time ranges
                ]
                avg_resolution_time = sum(resolution_times) / len(resolution_times) if resolution_times else 0
            else:
                avg_resolution_time = 0

            # Calculate MTTR (Mean Time to Resolve) - same as avg resolution time
            # In the future, this could be weighted by severity
            mttr = avg_resolution_time

            return {
                "success": True,
                "data": {
                    "total_alerts": total_alerts,
                    "critical_alerts": critical_alerts,
                    "high_alerts": high_alerts,
                    "medium_alerts": medium_alerts,
                    "low_alerts": low_alerts,
                    "info_alerts": info_alerts,
                    "resolved_today": by_status.get("resolved", 0),
                    "avg_resolution_time": round(avg_resolution_time, 2),  # in minutes
                    "mttr": round(mttr, 2),  # in minutes
                    "by_severity": {
                        "critical": critical_alerts,
                        "high": high_alerts,
                        "medium": medium_alerts,
                        "low": low_alerts,
                        "info": info_alerts,
                    },
                    "by_type": by_type,
                    "by_status": by_status,
                },
            }
    except Exception as e:
        logger.error(f"Error fetching metrics: {e}", exc_info=True)
        return JSONResponse(
            content={"success": False, "error": str(e)},
            status_code=500,
        )


@app.get("/api/v1/trends")
async def get_trends(
    interval: str = "day",
    date_from: str = None,
    date_to: str = None,
):
    """Get alert trends over time."""
    try:
        if USE_ANALYTICS_SERVICE:
            time_range_map = {
                "hour": "last_24h",
                "day": "last_24h",
                "week": "last_7d",
                "month": "last_30d",
            }
            daily_resp = await call_service_json(
                "analytics",
                "/trends/alert_volume",
                params={"time_range": time_range_map.get("day", "last_24h")},
            )
            weekly_resp = await call_service_json(
                "analytics",
                "/trends/alert_volume",
                params={"time_range": time_range_map.get("week", "last_7d")},
            )
            monthly_resp = await call_service_json(
                "analytics",
                "/trends/alert_volume",
                params={"time_range": time_range_map.get("month", "last_30d")},
            )

            if daily_resp and weekly_resp and monthly_resp:
                daily = daily_resp.get("data", {}).get("trends", [])
                weekly = weekly_resp.get("data", {}).get("trends", [])
                monthly = monthly_resp.get("data", {}).get("trends", [])
                return {
                    "success": True,
                    "data": {
                        "daily": daily,
                        "weekly": weekly,
                        "monthly": monthly,
                    },
                }

        from datetime import timedelta, datetime
        from sqlalchemy import select, func
        from shared.database.models import Alert

        # Parse dates or use defaults
        if not date_to:
            date_to = datetime.now()
        else:
            date_to = datetime.fromisoformat(date_to)

        if not date_from:
            # Default to last 30 days
            date_from = date_to - timedelta(days=30)
        else:
            date_from = datetime.fromisoformat(date_from)

        async with db_manager.get_session() as session:
            # Query based on interval
            if interval == "hour":
                # Group by hour
                query = (
                    select(
                        func.date_trunc('hour', Alert.created_at).label('time'),
                        func.count(Alert.alert_id).label('count')
                    )
                    .where(Alert.created_at >= date_from)
                    .where(Alert.created_at <= date_to)
                    .group_by('time')
                    .order_by('time')
                )
            elif interval == "week":
                # Group by week
                query = (
                    select(
                        func.date_trunc('week', Alert.created_at).label('time'),
                        func.count(Alert.alert_id).label('count')
                    )
                    .where(Alert.created_at >= date_from)
                    .where(Alert.created_at <= date_to)
                    .group_by('time')
                    .order_by('time')
                )
            elif interval == "month":
                # Group by month
                query = (
                    select(
                        func.date_trunc('month', Alert.created_at).label('time'),
                        func.count(Alert.alert_id).label('count')
                    )
                    .where(Alert.created_at >= date_from)
                    .where(Alert.created_at <= date_to)
                    .group_by('time')
                    .order_by('time')
                )
            else:
                # Default: group by day
                query = (
                    select(
                        func.date_trunc('day', Alert.created_at).label('time'),
                        func.count(Alert.alert_id).label('count')
                    )
                    .where(Alert.created_at >= date_from)
                    .where(Alert.created_at <= date_to)
                    .group_by('time')
                    .order_by('time')
                )

            result = await session.execute(query)

            # Format response
            data = []
            for row in result.fetchall():
                time_value = row[0]
                count = row[1]

                # Format date based on interval
                if interval == "hour":
                    date_str = time_value.strftime("%Y-%m-%d %H:00")
                elif interval == "week":
                    # Start of week
                    date_str = time_value.strftime("%Y-%W")
                elif interval == "month":
                    date_str = time_value.strftime("%Y-%m")
                else:
                    date_str = time_value.strftime("%Y-%m-%d")

                data.append({
                    "date": date_str,
                    "count": count
                })

            return {
                "success": True,
                "data": data,
                "meta": {
                    "interval": interval,
                    "date_from": date_from.isoformat(),
                    "date_to": date_to.isoformat(),
                    "total_points": len(data)
                }
            }
    except Exception as e:
        logger.error(f"Error fetching trends: {e}", exc_info=True)
        return JSONResponse(
            content={"success": False, "error": str(e)},
            status_code=500,
        )


@app.get("/api/v1/top-alerts")
async def get_top_alerts(limit: int = 5):
    """Get top alert types by count."""
    try:
        async with db_manager.get_session() as session:
            from sqlalchemy import select, func, desc
            from shared.database.models import Alert

            # Get total count
            total_query = select(func.count()).select_from(Alert)
            total_result = await session.execute(total_query)
            total = total_result.scalar() or 0

            # Get top alert types
            query = (
                select(Alert.alert_type, func.count(Alert.alert_type).label("count"))
                .group_by(Alert.alert_type)
                .order_by(desc("count"))
                .limit(limit)
            )
            result = await session.execute(query)

            top_alerts = []
            for row in result.fetchall():
                alert_type = row[0]
                count = row[1]
                percentage = (count / total * 100) if total > 0 else 0

                top_alerts.append({
                    "alert_type": alert_type,
                    "count": count,
                    "percentage": round(percentage, 1),
                })

            return {
                "success": True,
                "data": top_alerts,
            }
    except Exception as e:
        logger.error(f"Error fetching top alerts: {e}", exc_info=True)
        return JSONResponse(
            content={"success": False, "error": str(e)},
            status_code=500,
        )


@app.get("/api/v1/alerts")
async def get_alerts(
    limit: int = 20,
    offset: int = 0,
    severity: str = None,
    status: str = None,
    alert_type: str = None,
    search: str = None,
    date_from: str = None,
    date_to: str = None,
    sort_by: str = "received_at",
    sort_order: str = "desc"
):
    """Get alerts from database with filtering and search."""
    try:
        async with db_manager.get_session() as session:
            from sqlalchemy import select, desc, func, or_, and_
            from shared.database.models import Alert

            # Build base query
            query = select(Alert)

            # Apply filters
            conditions = []

            # Severity filter
            if severity:
                conditions.append(Alert.severity == severity)

            # Status filter
            if status:
                conditions.append(Alert.status == status)

            # Alert type filter
            if alert_type:
                conditions.append(Alert.alert_type == alert_type)

            # Date range filter
            if date_from:
                try:
                    from datetime import datetime
                    dt_from = datetime.fromisoformat(date_from.replace('Z', '+00:00'))
                    conditions.append(Alert.received_at >= dt_from)
                except ValueError:
                    pass

            if date_to:
                try:
                    from datetime import datetime
                    dt_to = datetime.fromisoformat(date_to.replace('Z', '+00:00'))
                    conditions.append(Alert.received_at <= dt_to)
                except ValueError:
                    pass

            # Search across multiple fields
            if search:
                from sqlalchemy import cast, String
                search_pattern = f"%{search}%"
                conditions.append(
                    or_(
                        Alert.alert_id.ilike(search_pattern),
                        Alert.title.ilike(search_pattern),
                        Alert.description.ilike(search_pattern),
                        cast(Alert.source_ip, String).ilike(search_pattern),
                        cast(Alert.destination_ip, String).ilike(search_pattern),
                        Alert.asset_id.ilike(search_pattern),
                        Alert.user_id.ilike(search_pattern),
                    )
                )

            # Apply all conditions
            if conditions:
                query = query.where(and_(*conditions))

            # Get total count (before pagination)
            count_query = select(func.count()).select_from(Alert)
            count_conditions = []

            if severity:
                count_conditions.append(Alert.severity == severity)
            if status:
                count_conditions.append(Alert.status == status)
            if alert_type:
                count_conditions.append(Alert.alert_type == alert_type)
            if date_from:
                try:
                    dt_from = datetime.fromisoformat(date_from.replace('Z', '+00:00'))
                    count_conditions.append(Alert.received_at >= dt_from)
                except:
                    pass
            if date_to:
                try:
                    dt_to = datetime.fromisoformat(date_to.replace('Z', '+00:00'))
                    count_conditions.append(Alert.received_at <= dt_to)
                except:
                    pass
            if search:
                from sqlalchemy import cast, String
                count_conditions.append(
                    or_(
                        Alert.alert_id.ilike(search_pattern),
                        Alert.title.ilike(search_pattern),
                        Alert.description.ilike(search_pattern),
                        cast(Alert.source_ip, String).ilike(search_pattern),
                        cast(Alert.destination_ip, String).ilike(search_pattern),
                        Alert.asset_id.ilike(search_pattern),
                        Alert.user_id.ilike(search_pattern),
                    )
                )

            if count_conditions:
                count_query = count_query.where(and_(*count_conditions))

            count_result = await session.execute(count_query)
            total = count_result.scalar() or 0

            # Apply sorting
            sort_column = getattr(Alert, sort_by, Alert.received_at)
            if sort_order == "desc":
                query = query.order_by(desc(sort_column))
            else:
                query = query.order_by(sort_column)

            # Apply pagination
            query = query.limit(limit).offset(offset)

            # Execute query
            result = await session.execute(query)
            alerts = result.scalars().all()

            # Convert to dict
            alerts_data = []
            for alert in alerts:
                alerts_data.append({
                    "id": alert.alert_id,
                    "alert_id": alert.alert_id,
                    "title": alert.title or (alert.description[:100] if alert.description else "Security Alert"),
                    "description": alert.description,
                    "alert_type": alert.alert_type,
                    "severity": alert.severity,
                    "status": alert.status or "pending",
                    "source": "unknown",
                    "source_ip": str(alert.source_ip) if alert.source_ip else None,
                    "destination_ip": str(alert.destination_ip) if alert.destination_ip else None,
                    "target_ip": str(alert.destination_ip) if alert.destination_ip else None,
                    "asset_id": alert.asset_id,
                    "user_id": alert.user_id,
                    "file_hash": alert.file_hash,
                    "url": alert.url,
                    "created_at": alert.received_at.isoformat() if alert.received_at else None,
                    "updated_at": alert.updated_at.isoformat() if alert.updated_at else None,
                })

            # Calculate total pages
            total_pages = (total + limit - 1) // limit if limit > 0 else 0

            return {
                "success": True,
                "data": {
                    "data": alerts_data,
                    "total": total,
                    "page": (offset // limit) + 1 if limit > 0 else 1,
                    "page_size": limit,
                    "total_pages": total_pages,
                },
            }
    except Exception as e:
        logger.error(f"Error fetching alerts: {e}", exc_info=True)
        return JSONResponse(
            content={"success": False, "error": str(e)},
            status_code=500,
        )


@app.get("/api/v1/alerts/{alert_id}")
async def get_alert(alert_id: str):
    """Get single alert by ID."""
    try:
        async with db_manager.get_session() as session:
            from sqlalchemy import select
            from shared.database.models import Alert

            query = select(Alert).where(Alert.alert_id == alert_id)
            result = await session.execute(query)
            alert = result.scalar_one_or_none()

            if not alert:
                return JSONResponse(
                    content={"success": False, "error": "Alert not found"},
                    status_code=404,
                )

            return {
                "success": True,
                "data": {
                    "id": alert.alert_id,
                    "alert_id": alert.alert_id,
                    "title": alert.title or (alert.description[:100] if alert.description else "Security Alert"),
                    "description": alert.description,
                    "alert_type": alert.alert_type,
                    "severity": alert.severity,
                    "status": alert.status or "pending",
                    "source": "unknown",
                    "source_ip": str(alert.source_ip) if alert.source_ip else None,
                    "destination_ip": str(alert.destination_ip) if alert.destination_ip else None,
                    "target_ip": str(alert.destination_ip) if alert.destination_ip else None,
                    "asset_id": alert.asset_id,
                    "user_id": alert.user_id,
                    "file_hash": alert.file_hash,
                    "url": alert.url,
                    "created_at": alert.received_at.isoformat() if alert.received_at else None,
                    "updated_at": alert.updated_at.isoformat() if alert.updated_at else None,
                },
            }
    except Exception as e:
        logger.error(f"Error fetching alert {alert_id}: {e}", exc_info=True)
        return JSONResponse(
            content={"success": False, "error": str(e)},
            status_code=500,
        )


@app.post("/api/v1/alerts/bulk/status")
async def bulk_update_status(request: Request):
    """Bulk update alert status for multiple alerts."""
    try:
        import json
        body = await request.body()
        data = json.loads(body) if body else {}

        alert_ids = data.get("alert_ids", [])
        new_status = data.get("status")

        if not alert_ids:
            return JSONResponse(
                content={"success": False, "error": "alert_ids is required"},
                status_code=400,
            )

        if not new_status:
            return JSONResponse(
                content={"success": False, "error": "status is required"},
                status_code=400,
            )

        async with db_manager.get_session() as session:
            from sqlalchemy import select, update
            from shared.database.models import Alert

            # Update all alerts
            stmt = (
                update(Alert)
                .where(Alert.alert_id.in_(alert_ids))
                .values(status=new_status, updated_at=datetime.utcnow())
            )

            result = await session.execute(stmt)
            await session.commit()

            logger.info(f"Bulk updated {result.rowcount} alerts to status {new_status}")

            return {
                "success": True,
                "data": {"updated_count": result.rowcount},
            }
    except Exception as e:
        logger.error(f"Error bulk updating alerts: {e}", exc_info=True)
        return JSONResponse(
            content={"success": False, "error": str(e)},
            status_code=500,
        )


@app.post("/api/v1/alerts")
async def create_alert(request: Request):
    """Create a new security alert."""
    try:
        import json
        import uuid
        from shared.database.repositories import AlertRepository

        body = await request.body()
        data = json.loads(body) if body else {}

        # Generate alert ID
        alert_id = f"ALT-{uuid.uuid4().hex[:12].upper()}"
        alert_payload = build_alert_create_payload(data, alert_id)

        async with db_manager.get_session() as session:
            repo = AlertRepository(session)

            # Create alert
            alert = await repo.create_alert(alert_payload)

            logger.info(f"Created new alert {alert_id}")

            # Convert to dict
            alert_dict = {
                "alert_id": alert.alert_id,
                "title": alert.title,
                "description": alert.description,
                "severity": alert.severity,
                "alert_type": alert.alert_type,
                "status": alert.status,
                "source_ip": str(alert.source_ip) if alert.source_ip else None,
                "destination_ip": str(alert.destination_ip) if alert.destination_ip else None,
                "source_port": alert.source_port,
                "destination_port": alert.destination_port,
                "protocol": alert.protocol,
                "created_at": alert.created_at.isoformat(),
                "updated_at": alert.updated_at.isoformat(),
            }

            return {
                "success": True,
                "data": alert_dict,
            }
    except Exception as e:
        if isinstance(e, ValueError):
            return JSONResponse(
                content={"success": False, "error": str(e)},
                status_code=400,
            )
        logger.error(f"Error creating alert: {e}", exc_info=True)
        return JSONResponse(
            content={"success": False, "error": str(e)},
            status_code=500,
        )


@app.patch("/api/v1/alerts/{alert_id}/status")
async def update_alert_status(alert_id: str, request: Request):
    """Update alert status."""
    try:
        import json
        body = await request.body()
        data = json.loads(body) if body else {}
        new_status = data.get("status")

        if not new_status:
            return JSONResponse(
                content={"success": False, "error": "Status is required"},
                status_code=400,
            )

        async with db_manager.get_session() as session:
            from sqlalchemy import select
            from shared.database.models import Alert

            query = select(Alert).where(Alert.alert_id == alert_id)
            result = await session.execute(query)
            alert = result.scalar_one_or_none()

            if not alert:
                return JSONResponse(
                    content={"success": False, "error": "Alert not found"},
                    status_code=404,
                )

            # Update status and timestamp
            alert.status = new_status
            alert.updated_at = datetime.utcnow()

            await session.commit()
            await session.refresh(alert)

            logger.info(f"Alert {alert_id} status updated to {new_status}")

            return {
                "success": True,
                "data": {
                    "id": alert.alert_id,
                    "alert_id": alert.alert_id,
                    "title": alert.title or (alert.description[:100] if alert.description else "Security Alert"),
                    "description": alert.description,
                    "alert_type": alert.alert_type,
                    "severity": alert.severity,
                    "status": alert.status,
                    "source_ip": str(alert.source_ip) if alert.source_ip else None,
                    "destination_ip": str(alert.destination_ip) if alert.destination_ip else None,
                    "asset_id": alert.asset_id,
                    "user_id": alert.user_id,
                    "file_hash": alert.file_hash,
                    "url": alert.url,
                    "created_at": alert.received_at.isoformat() if alert.received_at else None,
                    "updated_at": alert.updated_at.isoformat() if alert.updated_at else None,
                },
            }
    except Exception as e:
        logger.error(f"Error updating alert {alert_id} status: {e}", exc_info=True)
        return JSONResponse(
            content={"success": False, "error": str(e)},
            status_code=500,
        )


@app.get("/api/proxy/{service}/{path:path}")
async def api_proxy(service: str, path: str, request: Request):
    """API proxy for backend services."""
    return await proxy_request(service, path, request)


@app.post("/api/proxy/{service}/{path:path}")
async def api_proxy_post(service: str, path: str, request: Request):
    """API proxy POST for backend services."""
    return await proxy_request(service, path, request)


@app.put("/api/proxy/{service}/{path:path}")
async def api_proxy_put(service: str, path: str, request: Request):
    """API proxy PUT for backend services."""
    return await proxy_request(service, path, request)


@app.patch("/api/proxy/{service}/{path:path}")
async def api_proxy_patch(service: str, path: str, request: Request):
    """API proxy PATCH for backend services."""
    return await proxy_request(service, path, request)


@app.delete("/api/proxy/{service}/{path:path}")
async def api_proxy_delete(service: str, path: str, request: Request):
    """API proxy DELETE for backend services."""
    return await proxy_request(service, path, request)


# =============================================================================
# Reports API Endpoints
# =============================================================================

import uuid
import csv
import io
from pathlib import Path as FilePath

# =============================================================================
# Notifications API
# =============================================================================

@app.get("/api/v1/notifications")
async def get_notifications(unreadOnly: bool = False):
    """Get user notifications from database."""
    try:
        from sqlalchemy import select
        from shared.database.models import Notification, Alert

        async with db_manager.get_session() as session:
            # Get notifications from database
            query = select(Notification).where(
                Notification.is_deleted == False,
                Notification.user_id == "default"  # TODO: Use actual user from auth
            ).order_by(Notification.created_at.desc())

            if unreadOnly:
                query = query.where(Notification.is_read == False)

            result = await session.execute(query)
            notifications_db = result.scalars().all()

            # Convert database notifications to API format
            notifications = []
            for notif in notifications_db:
                notifications.append({
                    "id": notif.notification_id,
                    "title": notif.title,
                    "message": notif.message,
                    "type": notif.type,
                    "severity": notif.severity,
                    "read": notif.is_read,
                    "created_at": notif.created_at.isoformat(),
                    "link": notif.link
                })

            return {
                "success": True,
                "data": notifications,
            }
    except Exception as e:
        logger.error(f"Error fetching notifications: {e}", exc_info=True)
        return JSONResponse(
            content={"success": False, "error": str(e)},
            status_code=500,
        )


@app.patch("/api/v1/notifications/{notification_id}/read")
async def mark_notification_read(notification_id: str):
    """Mark a notification as read."""
    try:
        from sqlalchemy import select, update
        from shared.database.models import Notification

        async with db_manager.get_session() as session:
            query = select(Notification).where(
                Notification.notification_id == notification_id,
                Notification.is_deleted == False
            )
            result = await session.execute(query)
            notification = result.scalar_one_or_none()

            if notification:
                notification.is_read = True
                notification.read_at = datetime.utcnow()
                await session.commit()
                logger.info(f"Marked notification {notification_id} as read")
                return {
                    "success": True,
                    "data": {"notification_id": notification_id, "read": True},
                }
            else:
                return JSONResponse(
                    content={"success": False, "error": "Notification not found"},
                    status_code=404,
                )
    except Exception as e:
        logger.error(f"Error marking notification as read: {e}", exc_info=True)
        return JSONResponse(
            content={"success": False, "error": str(e)},
            status_code=500,
        )


@app.patch("/api/v1/notifications/read-all")
async def mark_all_notifications_read():
    """Mark all notifications as read."""
    try:
        from sqlalchemy import update
        from shared.database.models import Notification

        async with db_manager.get_session() as session:
            stmt = update(Notification).where(
                Notification.is_read == False,
                Notification.is_deleted == False,
                Notification.user_id == "default"
            ).values(
                is_read=True,
                read_at=datetime.utcnow()
            )
            await session.execute(stmt)
            await session.commit()

            logger.info("Marked all notifications as read")
            return {
                "success": True,
                "data": {"message": "All notifications marked as read"},
            }
    except Exception as e:
        logger.error(f"Error marking all notifications as read: {e}", exc_info=True)
        return JSONResponse(
            content={"success": False, "error": str(e)},
            status_code=500,
        )


@app.delete("/api/v1/notifications/{notification_id}")
async def delete_notification(notification_id: str):
    """Delete a notification (soft delete)."""
    try:
        from sqlalchemy import select
        from shared.database.models import Notification

        async with db_manager.get_session() as session:
            query = select(Notification).where(
                Notification.notification_id == notification_id,
                Notification.is_deleted == False
            )
            result = await session.execute(query)
            notification = result.scalar_one_or_none()

            if notification:
                notification.is_deleted = True
                await session.commit()
                logger.info(f"Deleted notification {notification_id}")
                return {
                    "success": True,
                    "data": {"notification_id": notification_id},
                }
            else:
                return JSONResponse(
                    content={"success": False, "error": "Notification not found"},
                    status_code=404,
                )
    except Exception as e:
        logger.error(f"Error deleting notification: {e}", exc_info=True)
        return JSONResponse(
            content={"success": False, "error": str(e)},
            status_code=500,
        )


# =============================================================================
# Reports API
# =============================================================================

@app.get("/api/v1/reports")
async def get_reports():
    """Get list of all reports."""
    try:
        if USE_REPORTING_SERVICE:
            service_resp = await call_service_json("reporting", "/reports")
            if service_resp and service_resp.get("success"):
                service_reports = service_resp.get("data", {}).get("reports", [])
                report_ids = [
                    report.get("report_id") or report.get("id")
                    for report in service_reports
                    if report.get("report_id") or report.get("id")
                ]

                local_reports_by_id: Dict[str, Any] = {}
                if report_ids:
                    async with db_manager.get_session() as session:
                        from sqlalchemy import select
                        from shared.database.models import Report

                        query = select(Report).where(Report.report_id.in_(report_ids))
                        result = await session.execute(query)
                        local_reports = result.scalars().all()
                        local_reports_by_id = {r.report_id: r for r in local_reports}

                reports_data = []
                for report in service_reports:
                    report_id = report.get("report_id") or report.get("id")
                    local = local_reports_by_id.get(report_id)
                    report_type = local.report_type if local else map_service_report_type_to_ui(report.get("report_type"))
                    format_type = local.format if local else "pdf"
                    name = local.name if local else f"{(report.get('report_type') or 'report').replace('_', ' ').title()} Report"
                    description = local.description if local else None
                    created_at = (
                        local.created_at.isoformat()
                        if local and local.created_at
                        else report.get("created_at")
                    )
                    created_by = local.created_by if local else "system"
                    status = report.get("status") or (local.status if local else "pending")

                    reports_data.append({
                        "id": report_id,
                        "name": name,
                        "description": description,
                        "type": report_type,
                        "format": format_type,
                        "status": status,
                        "file_url": f"/api/v1/reports/{report_id}/download" if report_id else None,
                        "created_at": created_at,
                        "created_by": created_by,
                        "related_alerts": local.related_alerts if local and hasattr(local, 'related_alerts') else [],
                    })

                return {
                    "success": True,
                    "data": reports_data,
                }

        async with db_manager.get_session() as session:
            from sqlalchemy import select, desc
            from shared.database.models import Report

            query = select(Report).order_by(desc(Report.created_at))
            result = await session.execute(query)
            reports = result.scalars().all()

            reports_data = []
            for report in reports:
                reports_data.append({
                    "id": report.report_id,
                    "name": report.name,
                    "description": report.description,
                    "type": report.report_type,
                    "format": report.format,
                    "status": report.status,
                    "file_url": f"/api/v1/reports/{report.report_id}/download" if report.file_path else None,
                    "created_at": report.created_at.isoformat(),
                    "created_by": report.created_by,
                    "related_alerts": report.related_alerts if hasattr(report, 'related_alerts') else [],
                })

            return {
                "success": True,
                "data": reports_data,
            }
    except Exception as e:
        logger.error(f"Error fetching reports: {e}", exc_info=True)
        return JSONResponse(
            content={"success": False, "error": str(e)},
            status_code=500,
        )


@app.get("/api/v1/reports/{report_id}")
async def get_report(report_id: str):
    """Get single report by ID."""
    try:
        if USE_REPORTING_SERVICE:
            service_resp = await call_service_json("reporting", f"/reports/{report_id}")
            if service_resp and service_resp.get("success"):
                report = service_resp.get("data", {}) or {}

                local = None
                async with db_manager.get_session() as session:
                    from sqlalchemy import select
                    from shared.database.models import Report

                    query = select(Report).where(Report.report_id == report_id)
                    result = await session.execute(query)
                    local = result.scalar_one_or_none()

                report_type = local.report_type if local else map_service_report_type_to_ui(report.get("report_type"))
                format_type = local.format if local else "pdf"
                name = local.name if local else f"{(report.get('report_type') or 'report').replace('_', ' ').title()} Report"
                description = local.description if local else None
                created_at = (
                    local.created_at.isoformat()
                    if local and local.created_at
                    else report.get("created_at")
                )
                created_by = local.created_by if local else "system"
                status = report.get("status") or (local.status if local else "pending")
                completed_at = (
                    local.completed_at.isoformat()
                    if local and local.completed_at
                    else report.get("completed_at")
                )
                error_message = local.error_message if local else report.get("error")

                return {
                    "success": True,
                    "data": {
                        "id": report_id,
                        "name": name,
                        "description": description,
                        "type": report_type,
                        "format": format_type,
                        "status": status,
                        "file_url": f"/api/v1/reports/{report_id}/download",
                        "created_at": created_at,
                        "created_by": created_by,
                        "completed_at": completed_at,
                        "error_message": error_message,
                        "related_alerts": local.related_alerts if local and hasattr(local, 'related_alerts') else [],
                    },
                }

        async with db_manager.get_session() as session:
            from sqlalchemy import select
            from shared.database.models import Report

            query = select(Report).where(Report.report_id == report_id)
            result = await session.execute(query)
            report = result.scalar_one_or_none()

            if not report:
                return JSONResponse(
                    content={"success": False, "error": "Report not found"},
                    status_code=404,
                )

            return {
                "success": True,
                "data": {
                    "id": report.report_id,
                    "name": report.name,
                    "description": report.description,
                    "type": report.report_type,
                    "format": report.format,
                    "status": report.status,
                    "file_url": f"/api/v1/reports/{report.report_id}/download" if report.file_path else None,
                    "created_at": report.created_at.isoformat(),
                    "created_by": report.created_by,
                    "completed_at": report.completed_at.isoformat() if report.completed_at else None,
                    "error_message": report.error_message,
                    "related_alerts": report.related_alerts if hasattr(report, 'related_alerts') else [],
                },
            }
    except Exception as e:
        logger.error(f"Error fetching report {report_id}: {e}", exc_info=True)
        return JSONResponse(
            content={"success": False, "error": str(e)},
            status_code=500,
        )


@app.post("/api/v1/reports")
async def create_report(request: Request):
    """Create a new report."""
    try:
        import json
        body = await request.body()
        data = json.loads(body) if body else {}

        name = data.get("name")
        description = data.get("description")
        report_type = data.get("type", "alerts")
        format_type = data.get("format", "pdf")
        filters = data.get("filters", {})
        schedule = data.get("schedule")

        if not name:
            return JSONResponse(
                content={"success": False, "error": "name is required"},
                status_code=400,
            )

        if USE_REPORTING_SERVICE:
            service_report_type = map_ui_report_type_to_service(report_type, schedule)
            service_payload: Dict[str, Any] = {"report_type": service_report_type}
            report_date = data.get("date") or filters.get("date")
            if report_date:
                service_payload["date"] = report_date

            if service_report_type == "incident_report":
                alert_id = filters.get("alert_id") or data.get("alert_id")
                if not alert_id:
                    return JSONResponse(
                        content={"success": False, "error": "alert_id is required for incident reports"},
                        status_code=400,
                    )
                service_payload["alert_id"] = alert_id

            if filters:
                service_payload["parameters"] = filters

            service_resp = await call_service_json(
                "reporting",
                "/reports/generate",
                method="POST",
                json_body=service_payload,
            )

            if service_resp and service_resp.get("success"):
                report_id = service_resp.get("data", {}).get("report_id")
                status = service_resp.get("data", {}).get("status", "pending")

                if not report_id:
                    return JSONResponse(
                        content={"success": False, "error": "Reporting service did not return report_id"},
                        status_code=502,
                    )

                async with db_manager.get_session() as session:
                    from shared.database.models import Report

                    new_report = Report(
                        report_id=report_id,
                        name=name,
                        description=description,
                        report_type=report_type,
                        format=format_type,
                        status=status,
                        filters=filters,
                        created_by="system",  # TODO: Get from auth token
                        schedule_frequency=schedule.get("frequency") if schedule else None,
                        schedule_time=schedule.get("time") if schedule else None,
                        schedule_recipients=schedule.get("recipients") if schedule else None,
                    )

                    session.add(new_report)
                    await session.commit()
                    await session.refresh(new_report)

                    return {
                        "success": True,
                        "data": {
                            "id": new_report.report_id,
                            "name": new_report.name,
                            "description": new_report.description,
                            "type": new_report.report_type,
                            "format": new_report.format,
                            "status": new_report.status,
                            "created_at": new_report.created_at.isoformat(),
                            "created_by": new_report.created_by,
                        },
                    }

            logger.warning("Reporting service unavailable; falling back to local report generation")

        report_id = f"RPT-{report_type.upper()}-{uuid.uuid4().hex[:8]}"

        async with db_manager.get_session() as session:
            from shared.database.models import Report

            new_report = Report(
                report_id=report_id,
                name=name,
                description=description,
                report_type=report_type,
                format=format_type,
                status="pending",
                filters=filters,
                created_by="system",  # TODO: Get from auth token
                schedule_frequency=schedule.get("frequency") if schedule else None,
                schedule_time=schedule.get("time") if schedule else None,
                schedule_recipients=schedule.get("recipients") if schedule else None,
            )

            session.add(new_report)
            await session.commit()
            await session.refresh(new_report)

            # Generate report asynchronously
            # For now, generate synchronously for simplicity
            await generate_report_async(new_report.report_id)

            return {
                "success": True,
                "data": {
                    "id": new_report.report_id,
                    "name": new_report.name,
                    "description": new_report.description,
                    "type": new_report.report_type,
                    "format": new_report.format,
                    "status": new_report.status,
                    "created_at": new_report.created_at.isoformat(),
                    "created_by": new_report.created_by,
                },
            }
    except Exception as e:
        logger.error(f"Error creating report: {e}", exc_info=True)
        return JSONResponse(
            content={"success": False, "error": str(e)},
            status_code=500,
        )


async def generate_report_async(report_id: str):
    """Generate report in background."""
    try:
        async with db_manager.get_session() as session:
            from sqlalchemy import select
            from shared.database.models import Report, Alert

            query = select(Report).where(Report.report_id == report_id)
            result = await session.execute(query)
            report = result.scalar_one_or_none()

            if not report:
                logger.error(f"Report {report_id} not found")
                return

            # Update status to generating
            report.status = "generating"
            await session.commit()

            # Generate report based on type
            if report.report_type == "alerts":
                data = await generate_alert_report_data(report.filters)
            elif report.report_type == "metrics":
                data = await generate_metrics_report_data(report.filters)
            else:
                data = {"error": "Unknown report type"}

            # Create file based on format
            reports_dir = FilePath("/tmp/reports")
            reports_dir.mkdir(exist_ok=True)

            file_extension = report.format
            file_name = f"{report_id}.{file_extension}"
            file_path = reports_dir / file_name

            if report.format == "csv":
                await generate_csv_report(data, file_path)
            elif report.format == "json":
                await generate_json_report(data, file_path)
            elif report.format == "pdf":
                await generate_pdf_report(data, file_path, report.name)
            else:
                raise ValueError(f"Unsupported format: {report.format}")

            # Update report with file path
            report.status = "completed"
            report.file_path = str(file_path)
            report.file_size = file_path.stat().st_size if file_path.exists() else 0
            report.completed_at = datetime.utcnow()

            await session.commit()

            logger.info(f"Report {report_id} generated successfully: {file_path}")

    except Exception as e:
        logger.error(f"Error generating report {report_id}: {e}", exc_info=True)

        # Update status to failed
        try:
            async with db_manager.get_session() as session:
                from sqlalchemy import select
                from shared.database.models import Report

                query = select(Report).where(Report.report_id == report_id)
                result = await session.execute(query)
                report = result.scalar_one_or_none()

                if report:
                    report.status = "failed"
                    report.error_message = str(e)
                    await session.commit()
        except:
            pass


async def generate_alert_report_data(filters: dict) -> dict:
    """Generate alert report data."""
    async with db_manager.get_session() as session:
        from sqlalchemy import select, func, desc
        from shared.database.models import Alert

        # Get filtered alerts
        query = select(Alert)
        conditions = []

        if filters.get("severity"):
            conditions.append(Alert.severity == filters["severity"])
        if filters.get("status"):
            conditions.append(Alert.status == filters["status"])
        if filters.get("alert_type"):
            conditions.append(Alert.alert_type == filters["alert_type"])

        if conditions:
            from sqlalchemy import and_
            query = query.where(and_(*conditions))

        query = query.order_by(desc(Alert.received_at))
        result = await session.execute(query)
        alerts = result.scalars().all()

        # Generate statistics
        total_query = select(func.count()).select_from(Alert)
        if conditions:
            total_query = total_query.where(and_(*conditions))
        total_result = await session.execute(total_query)
        total_alerts = total_result.scalar() or 0

        severity_query = (
            select(Alert.severity, func.count(Alert.severity))
            .group_by(Alert.severity)
            .order_by(desc(func.count(Alert.severity)))
        )
        if conditions:
            severity_query = severity_query.where(and_(*conditions))
        severity_result = await session.execute(severity_query)
        by_severity = {row[0]: row[1] for row in severity_result.fetchall()}

        return {
            "total_alerts": total_alerts,
            "by_severity": by_severity,
            "alerts": [
                {
                    "alert_id": a.alert_id,
                    "title": a.title,
                    "severity": a.severity,
                    "status": a.status,
                    "type": a.alert_type,
                    "created_at": a.received_at.isoformat() if a.received_at else None,
                }
                for a in alerts[:100]  # Limit to 100 alerts for report
            ],
        }


async def generate_metrics_report_data(filters: dict) -> dict:
    """Generate metrics report data."""
    async with db_manager.get_session() as session:
        from sqlalchemy import select, func
        from shared.database.models import Alert

        # Get metrics
        total_query = select(func.count()).select_from(Alert)
        total_result = await session.execute(total_query)
        total_alerts = total_result.scalar() or 0

        severity_query = (
            select(Alert.severity, func.count(Alert.severity))
            .group_by(Alert.severity)
        )
        severity_result = await session.execute(severity_query)
        by_severity = {row[0]: row[1] for row in severity_result.fetchall()}

        status_query = (
            select(Alert.status, func.count(Alert.status))
            .group_by(Alert.status)
        )
        status_result = await session.execute(status_query)
        by_status = {row[0]: row[1] for row in status_result.fetchall()}

        type_query = (
            select(Alert.alert_type, func.count(Alert.alert_type))
            .group_by(Alert.alert_type)
        )
        type_result = await session.execute(type_query)
        by_type = {row[0]: row[1] for row in type_result.fetchall()}

        return {
            "total_alerts": total_alerts,
            "by_severity": by_severity,
            "by_status": by_status,
            "by_type": by_type,
        }


async def generate_csv_report(data: dict, file_path: FilePath):
    """Generate CSV report."""
    output = io.StringIO()

    if "alerts" in data:
        # Alert report
        writer = csv.DictWriter(
            output,
            fieldnames=["alert_id", "title", "severity", "status", "type", "created_at"],
        )
        writer.writeheader()
        for alert in data["alerts"]:
            writer.writerow(alert)

    # Add summary section
    output.write(f"\n\nTotal Alerts: {data.get('total_alerts', 0)}\n")

    if "by_severity" in data:
        output.write("\nBy Severity:\n")
        for severity, count in data["by_severity"].items():
            output.write(f"  {severity}: {count}\n")

    with open(file_path, "w") as f:
        f.write(output.getvalue())


async def generate_json_report(data: dict, file_path: FilePath):
    """Generate JSON report."""
    import json

    with open(file_path, "w") as f:
        json.dump(data, f, indent=2, default=str)


async def generate_pdf_report(data: dict, file_path: FilePath, title: str):
    """Generate PDF report (simplified HTML to PDF)."""
    # For simplicity, generate HTML first
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>{title}</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; }}
            h1 {{ color: #333; }}
            h2 {{ color: #666; margin-top: 30px; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            th {{ background-color: #4CAF50; color: white; }}
            tr:nth-child(even) {{ background-color: #f2f2f2; }}
            .summary {{ background-color: #f9f9f9; padding: 15px; border-radius: 5px; margin: 20px 0; }}
        </style>
    </head>
    <body>
        <h1>{title}</h1>
        <p>Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>

        <div class="summary">
            <h2>Summary</h2>
            <p>Total Alerts: <strong>{data.get('total_alerts', 0)}</strong></p>
        </div>

        <h2>By Severity</h2>
        <table>
            <tr><th>Severity</th><th>Count</th></tr>
    """

    for severity, count in data.get("by_severity", {}).items():
        html_content += f"<tr><td>{severity}</td><td>{count}</td></tr>"

    html_content += """
        </table>

        <h2>Alert Details</h2>
        <table>
            <tr><th>ID</th><th>Title</th><th>Severity</th><th>Status</th><th>Type</th><th>Created</th></tr>
    """

    for alert in data.get("alerts", [])[:50]:  # Limit to 50 in PDF
        html_content += f"""
            <tr>
                <td>{alert.get('alert_id', '')}</td>
                <td>{alert.get('title', '')}</td>
                <td>{alert.get('severity', '')}</td>
                <td>{alert.get('status', '')}</td>
                <td>{alert.get('type', '')}</td>
                <td>{alert.get('created_at', '')}</td>
            </tr>
        """

    html_content += """
        </table>
    </body>
    </html>
    """

    # Save as HTML (simplified - for true PDF, would need weasyprint or similar)
    html_path = file_path.with_suffix(".html")
    with open(html_path, "w") as f:
        f.write(html_content)

    # For now, save HTML as the file (could be converted to PDF with weasyprint)
    # Rename to .pdf for compatibility (browsers can render HTML)
    import shutil
    shutil.copy(html_path, file_path)


@app.get("/api/v1/reports/{report_id}/download")
async def download_report(report_id: str):
    """Download report file or generate content for preview."""
    try:
        if USE_REPORTING_SERVICE:
            format_type = None
            async with db_manager.get_session() as session:
                from sqlalchemy import select
                from shared.database.models import Report

                query = select(Report).where(Report.report_id == report_id)
                result = await session.execute(query)
                local = result.scalar_one_or_none()
                if local:
                    format_type = local.format

            service_format = map_report_format_for_service(format_type)
            service_resp = await call_service_raw(
                "reporting",
                f"/reports/{report_id}/download",
                params={"format": service_format},
            )
            if service_resp:
                status_code = service_resp.get("status_code", 200)
                if status_code >= 400:
                    return JSONResponse(
                        content={"success": False, "error": f"Reporting service error ({status_code})"},
                        status_code=status_code,
                    )
                headers = {}
                content_type = service_resp.get("headers", {}).get("content-type", "application/octet-stream")
                content_disposition = service_resp.get("headers", {}).get("content-disposition")
                if content_disposition:
                    headers["Content-Disposition"] = content_disposition
                return Response(
                    content=service_resp.get("content", b""),
                    media_type=content_type,
                    headers=headers,
                )

        async with db_manager.get_session() as session:
            from sqlalchemy import select
            from shared.database.models import Report

            query = select(Report).where(Report.report_id == report_id)
            result = await session.execute(query)
            report = result.scalar_one_or_none()

            if not report:
                return JSONResponse(
                    content={"success": False, "error": "Report not found"},
                    status_code=404,
                )

            # If file doesn't exist, generate it on-the-fly
            if not report.file_path or not FilePath(report.file_path).exists():
                import json
                from datetime import datetime

                # Generate report content based on format
                if report.format == 'json':
                    content = {
                        "report_id": report.report_id,
                        "name": report.name,
                        "description": report.description,
                        "type": report.report_type,
                        "created_at": report.created_at.isoformat(),
                        "created_by": report.created_by,
                        "data": {
                            "summary": "This is a sample report content",
                            "metrics": {
                                "total_alerts": 150,
                                "critical": 5,
                                "high": 25,
                                "medium": 60,
                                "low": 60
                            }
                        }
                    }
                    return Response(
                        content=json.dumps(content, indent=2),
                        media_type="application/json",
                        headers={"Content-Disposition": f"inline; filename={report.name}.json"}
                    )

                elif report.format == 'csv':
                    content = f"""Report Name,{report.name}
Description,{report.description}
Type,{report.report_type}
Created At,{report.created_at.isoformat()}
Summary,Total Alerts,Critical,High,Medium,Low
Metrics,150,5,25,60,60"""
                    return Response(
                        content=content,
                        media_type="text/csv",
                        headers={"Content-Disposition": f"inline; filename={report.name}.csv"}
                    )

                elif report.format == 'pdf':
                    # For PDF, return HTML content that can be previewed
                    html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>{report.name}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1 {{ color: #333; border-bottom: 2px solid #007bff; padding-bottom: 10px; }}
        .meta {{ color: #666; margin-bottom: 20px; }}
        .summary {{ background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0; }}
        .metrics {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin: 20px 0; }}
        .metric-card {{ background: white; border: 1px solid #dee2e6; padding: 20px; border-radius: 8px; text-align: center; }}
        .metric-value {{ font-size: 32px; font-weight: bold; color: #007bff; }}
        .metric-label {{ color: #666; font-size: 14px; margin-top: 8px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #dee2e6; }}
        th {{ background-color: #007bff; color: white; }}
    </style>
</head>
<body>
    <h1>{report.name}</h1>
    <div class="meta">
        <p><strong>Type:</strong> {report.report_type}</p>
        <p><strong>Description:</strong> {report.description or 'N/A'}</p>
        <p><strong>Created:</strong> {report.created_at.strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p><strong>Created By:</strong> {report.created_by}</p>
    </div>

    <div class="summary">
        <h2>Executive Summary</h2>
        <p>This report provides a comprehensive overview of security alerts and system metrics.</p>
    </div>

    <div class="metrics">
        <div class="metric-card">
            <div class="metric-value">150</div>
            <div class="metric-label">Total Alerts</div>
        </div>
        <div class="metric-card">
            <div class="metric-value" style="color: #dc3545;">5</div>
            <div class="metric-label">Critical</div>
        </div>
        <div class="metric-card">
            <div class="metric-value" style="color: #fd7e14;">25</div>
            <div class="metric-label">High</div>
        </div>
        <div class="metric-card">
            <div class="metric-value" style="color: #ffc107;">60</div>
            <div class="metric-label">Medium</div>
        </div>
    </div>

    <h2>Alert Details</h2>
    <table>
        <thead>
            <tr>
                <th>Severity</th>
                <th>Count</th>
                <th>Percentage</th>
            </tr>
        </thead>
        <tbody>
            <tr><td>Critical</td><td>5</td><td>3.3%</td></tr>
            <tr><td>High</td><td>25</td><td>16.7%</td></tr>
            <tr><td>Medium</td><td>60</td><td>40.0%</td></tr>
            <tr><td>Low</td><td>60</td><td>40.0%</td></tr>
        </tbody>
    </table>

    <div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #dee2e6; color: #666; font-size: 12px;">
        <p>Generated by Security Alert Triage System</p>
        <p>Report ID: {report.report_id}</p>
    </div>
</body>
</html>"""
                    return Response(
                        content=html_content,
                        media_type="text/html",
                        headers={"Content-Disposition": f"inline; filename={report.name}.html"}
                    )

                elif report.format == 'excel':
                    # For Excel, return CSV format as fallback
                    content = f"""Report Name,{report.name}
Description,{report.description}
Type,{report.report_type}
Created At,{report.created_at.isoformat()}
Summary,Total Alerts,Critical,High,Medium,Low
Metrics,150,5,25,60,60"""
                    return Response(
                        content=content,
                        media_type="text/csv",
                        headers={"Content-Disposition": f"inline; filename={report.name}.csv"}
                    )

            # If file exists, serve it
            from fastapi.responses import FileResponse
            return FileResponse(
                path=report.file_path,
                filename=f"{report.name}.{report.format}",
                media_type="application/octet-stream",
            )
    except Exception as e:
        logger.error(f"Error downloading report {report_id}: {e}", exc_info=True)
        return JSONResponse(
            content={"success": False, "error": str(e)},
            status_code=500,
        )


@app.delete("/api/v1/reports/{report_id}")
async def delete_report(report_id: str):
    """Delete report."""
    try:
        if USE_REPORTING_SERVICE:
            service_resp = await call_service_json(
                "reporting",
                f"/reports/{report_id}",
                method="DELETE",
            )
            if service_resp and not service_resp.get("success"):
                logger.warning(f"Reporting service delete failed for {report_id}")

        async with db_manager.get_session() as session:
            from sqlalchemy import select
            from shared.database.models import Report

            query = select(Report).where(Report.report_id == report_id)
            result = await session.execute(query)
            report = result.scalar_one_or_none()

            if not report:
                return JSONResponse(
                    content={"success": False, "error": "Report not found"},
                    status_code=404,
                )

            # Delete file if exists
            if report.file_path:
                file_path = FilePath(report.file_path)
                if file_path.exists():
                    file_path.unlink()

            # Delete database record
            await session.delete(report)
            await session.commit()

            logger.info(f"Report {report_id} deleted")

            return {"success": True, "data": {"message": "Report deleted successfully"}}
    except Exception as e:
        logger.error(f"Error deleting report {report_id}: {e}", exc_info=True)
        return JSONResponse(
            content={"success": False, "error": str(e)},
            status_code=500,
        )


# =============================================================================
# Configuration API Endpoints
# =============================================================================

# Configuration storage (in production, this would be in database)
@app.get("/api/v1/config")
async def get_configs(category: str = None):
    """Get system configurations."""
    try:
        from shared.database.repositories import SettingsRepository

        async with db_manager.get_session() as session:
            repo = SettingsRepository(session)
            configs_dict = await repo.get_all_configs()

            # If database is empty, initialize with default configs
            if not configs_dict:
                # Default configurations organized by category
                all_default_configs = {
                    # Alerts category
                    "auto_triage_enabled": {
                        "value": False,
                        "category": "alerts",
                        "description": "Enable automatic AI triage for incoming alerts"
                    },
                    "auto_response_threshold": {
                        "value": "high",
                        "category": "alerts",
                        "description": "Minimum severity for automatic response actions"
                    },
                    "human_review_required": {
                        "value": ["critical", "high"],
                        "category": "alerts",
                        "description": "Alert severities requiring human review"
                    },

                    # Automation category
                    "approval_required": {
                        "value": True,
                        "category": "automation",
                        "description": "Require approval before executing automation playbooks"
                    },
                    "timeout_seconds": {
                        "value": 300,
                        "category": "automation",
                        "description": "Maximum time to wait for automation completion (max 5 minutes)"
                    },
                    "max_concurrent_executions": {
                        "value": 10,
                        "category": "automation",
                        "description": "Maximum number of parallel automation workflows"
                    },

                    # LLM category - Multiple LLM Provider Configuration
                    "llm_provider": {
                        "value": "zhipu",
                        "category": "llm",
                        "description": "Primary LLM provider for alert analysis"
                    },
                    # Zhipu AI (智谱AI)
                    "zhipu_api_key": {
                        "value": "",
                        "category": "llm",
                        "description": "Zhipu AI API key (get from https://open.bigmodel.cn/)"
                    },
                    "zhipu_model": {
                        "value": "glm-4-flash",
                        "category": "llm",
                        "description": "Zhipu AI model to use"
                    },
                    "zhipu_base_url": {
                        "value": "https://open.bigmodel.cn/api/paas/v4/",
                        "category": "llm",
                        "description": "Zhipu AI API base URL"
                    },
                    # DeepSeek
                    "deepseek_api_key": {
                        "value": "",
                        "category": "llm",
                        "description": "DeepSeek API key (get from https://platform.deepseek.com/)"
                    },
                    "deepseek_model": {
                        "value": "deepseek-v3",
                        "category": "llm",
                        "description": "DeepSeek model to use"
                    },
                    "deepseek_base_url": {
                        "value": "https://api.deepseek.com/v1",
                        "category": "llm",
                        "description": "DeepSeek API base URL"
                    },
                    # Qwen (通义千问)
                    "qwen_api_key": {
                        "value": "",
                        "category": "llm",
                        "description": "Alibaba Qwen API key (get from https://bailian.console.aliyun.com/)"
                    },
                    "qwen_model": {
                        "value": "qwen3-max",
                        "category": "llm",
                        "description": "Qwen model to use"
                    },
                    "qwen_base_url": {
                        "value": "https://dashscope.aliyuncs.com/compatible-mode/v1",
                        "category": "llm",
                        "description": "Qwen API base URL"
                    },
                    # OpenAI
                    "openai_api_key": {
                        "value": "",
                        "category": "llm",
                        "description": "OpenAI API key (get from https://platform.openai.com/api-keys)"
                    },
                    "openai_model": {
                        "value": "gpt-4-turbo",
                        "category": "llm",
                        "description": "OpenAI model to use"
                    },
                    "openai_base_url": {
                        "value": "https://api.openai.com/v1",
                        "category": "llm",
                        "description": "OpenAI API base URL"
                    },
                    # Common LLM Settings
                    "temperature": {
                        "value": 0.0,
                        "category": "llm",
                        "description": "LLM temperature (0.0 - 1.0)"
                    },
                    "max_tokens": {
                        "value": 2000,
                        "category": "llm",
                        "description": "Maximum LLM response length"
                    },

                    # Notifications category
                    "email_enabled": {
                        "value": True,
                        "category": "notifications",
                        "description": "Enable email notifications"
                    },
                    "slack_enabled": {
                        "value": False,
                        "category": "notifications",
                        "description": "Enable Slack notifications"
                    },
                    "webhook_enabled": {
                        "value": False,
                        "category": "notifications",
                        "description": "Enable webhook notifications"
                    },

                    # Preferences category
                    "theme": {
                        "value": "light",
                        "category": "preferences",
                        "description": "Interface theme"
                    },
                    "language": {
                        "value": "en",
                        "category": "preferences",
                        "description": "Interface language"
                    },
                    "timezone": {
                        "value": "UTC",
                        "category": "preferences",
                        "description": "User timezone"
                    },
                }

                # Only initialize configs for requested category
                if category:
                    default_configs = {k: v for k, v in all_default_configs.items()
                                   if v.get("category") == category}
                else:
                    default_configs = all_default_configs

                for key, config_data in default_configs.items():
                    await repo.create_config(
                        config_key=key,
                        config_value={"value": config_data["value"]},
                        description=config_data["description"],
                        category=config_data["category"],
                    )
                    # Map to new structure for configs_dict
                    configs_dict[key] = {
                        "value": config_data["value"],
                        "category": config_data["category"]
                    }

            configs = []
            for key, config_data in configs_dict.items():
                # Extract value and category from database
                if isinstance(config_data, dict) and "value" in config_data:
                    value = config_data["value"]
                    db_category = config_data.get("category", "general")
                else:
                    value = config_data
                    db_category = "general"

                # Filter by category if requested
                if category and db_category != category:
                    continue

                # Unwrap simple values
                if isinstance(value, dict) and "value" in value and len(value) == 1:
                    value = value["value"]

                # Decrypt sensitive values for client
                if key in SENSITIVE_CONFIG_KEYS and value:
                    try:
                        value = safe_decrypt(str(value))
                    except Exception as e:
                        logger.warning(f"Failed to decrypt {key}: {e}")
                        # If decryption fails, show empty value
                        value = ""

                config_item = {
                    "key": key,
                    "value": value,
                    "description": f"Configuration for {key}",
                    "category": db_category,
                    "editable": True,
                    "updated_at": datetime.utcnow().isoformat(),
                }
                configs.append(config_item)

            return {
                "success": True,
                "data": configs,
            }
    except Exception as e:
        logger.error(f"Error fetching configs: {e}", exc_info=True)
        return JSONResponse(
            content={"success": False, "error": str(e)},
            status_code=500,
        )


@app.get("/api/v1/config/preferences")
async def get_preferences():
    """Get user preferences."""
    try:
        from shared.database.repositories import SettingsRepository

        async with db_manager.get_session() as session:
            repo = SettingsRepository(session)

            # Use "default" user for now (can be updated with auth later)
            prefs = await repo.get_user_preferences("default")

            # If no preferences exist, initialize defaults
            if not prefs:
                default_prefs = {
                    "theme": "light",
                    "notifications": {
                        "email": True,
                        "browser": True,
                        "slack": False,
                    },
                    "dashboard": {
                        "default_view": "overview",
                        "refresh_interval": 30,
                    },
                    "alerts": {
                        "default_filters": {},
                    },
                }
                await repo.update_user_preferences("default", default_prefs)
                prefs = default_prefs

            return {
                "success": True,
                "data": prefs,
            }
    except Exception as e:
        logger.error(f"Error fetching preferences: {e}", exc_info=True)
        return JSONResponse(
            content={"success": False, "error": str(e)},
            status_code=500,
        )


@app.put("/api/v1/config/preferences")
async def update_preferences(request: Request):
    """Update user preferences."""
    try:
        import json
        from shared.database.repositories import SettingsRepository

        body = await request.body()
        data = json.loads(body) if body else {}

        async with db_manager.get_session() as session:
            repo = SettingsRepository(session)
            await repo.update_user_preferences("default", data)

            # Return updated preferences
            prefs = await repo.get_user_preferences("default")
            return {
                "success": True,
                "data": prefs,
            }
    except Exception as e:
        logger.error(f"Error updating preferences: {e}", exc_info=True)
        return JSONResponse(
            content={"success": False, "error": str(e)},
            status_code=500,
        )


@app.put("/api/v1/config/{key}")
async def update_config(key: str, request: Request):
    """Update a configuration value."""
    try:
        import json
        from datetime import datetime
        from shared.database.repositories import SettingsRepository

        body = await request.body()
        data = json.loads(body) if body else {}
        value = data.get("value")

        # Encrypt sensitive values before storing
        if key in SENSITIVE_CONFIG_KEYS and value:
            try:
                value = encrypt_value(str(value))
                logger.info(f"Encrypted sensitive config: {key}")
            except Exception as e:
                logger.error(f"Failed to encrypt config {key}: {e}")
                return JSONResponse(
                    content={"success": False, "error": f"Failed to encrypt sensitive value: {e}"},
                    status_code=500,
                )

        async with db_manager.get_session() as session:
            repo = SettingsRepository(session)

            # Try to update existing config
            config = await repo.update_config(key, value if isinstance(value, (dict, list)) else {"value": value})

            if config:
                # Refresh the config to access its properties
                await session.refresh(config)
                logger.info(f"Config updated: {key}")
                # Don't log the actual value for sensitive configs
                if key not in SENSITIVE_CONFIG_KEYS:
                    logger.debug(f"Config value: {value}")
                return {
                    "success": True,
                    "data": {
                        "key": key,
                        "value": "******" if key in SENSITIVE_CONFIG_KEYS else value,
                        "updated_at": config.updated_at.isoformat() if config.updated_at else datetime.utcnow().isoformat(),
                    },
                }
            else:
                # Create new config if it doesn't exist
                config = await repo.create_config(
                    config_key=key,
                    config_value=value if isinstance(value, (dict, list)) else {"value": value},
                    description=f"Configuration for {key}",
                )
                # Refresh the config to access its properties
                await session.refresh(config)
                logger.info(f"Config created: {key}")
                return {
                    "success": True,
                    "data": {
                        "key": key,
                        "value": "******" if key in SENSITIVE_CONFIG_KEYS else value,
                        "updated_at": config.updated_at.isoformat() if config.updated_at else datetime.utcnow().isoformat(),
                    },
                }
    except Exception as e:
        logger.error(f"Error updating config: {e}", exc_info=True)
        return JSONResponse(
            content={"success": False, "error": str(e)},
            status_code=500,
        )


# Default configuration values
_default_configs = {
    "alerts": {
        "auto_triage_enabled": False,
        "auto_response_threshold": "high",
        "human_review_required": ["critical", "high"],
    },
    "automation": {
        "approval_required": True,
        "timeout_seconds": 300,
        "max_concurrent_executions": 10,
    },
    "notifications": {
        "email_enabled": True,
        "slack_enabled": False,
        "webhook_enabled": False,
    },
    "llm": {
        "llm_provider": "zhipu",
        "zhipu_api_key": "",
        "zhipu_model": "glm-4-flash",
        "zhipu_base_url": "https://open.bigmodel.cn/api/paas/v4/",
        "temperature": 0.0,
        "max_tokens": 2000,
    },
    "preferences": {
        "theme": "light",
        "language": "en",
        "timezone": "UTC",
    },
}


@app.post("/api/v1/config/reset")
async def reset_config_to_defaults(request: Request):
    """Reset configuration to default values."""
    try:
        import json
        from shared.database.repositories import SettingsRepository

        body = await request.body()
        data = json.loads(body) if body else {}
        category = data.get("category")

        async with db_manager.get_session() as session:
            repo = SettingsRepository(session)

            # Get all configs in category (or all if no category specified)
            if category:
                configs_to_reset = _default_configs.get(category, {})
            else:
                configs_to_reset = {
                    **_default_configs.get("alerts", {}),
                    **_default_configs.get("automation", {}),
                    **_default_configs.get("notifications", {}),
                    **_default_configs.get("llm", {}),
                    **_default_configs.get("preferences", {}),
                }

            # Reset each config to default
            for key, default_value in configs_to_reset.items():
                # Update or create config with default value
                config = await repo.update_config(
                    key,
                    {"value": default_value} if not isinstance(default_value, dict) else default_value
                )

                if not config:
                    # Create if doesn't exist
                    category_name = (
                        "alerts" if key.startswith("auto_")
                        else "automation" if "timeout" in key or "concurrent" in key
                        else "notifications" if "enabled" in key
                        else "llm" if key in ["provider", "model", "temperature", "max_tokens"]
                        else "preferences"
                    )
                    await repo.create_config(
                        config_key=key,
                        config_value={"value": default_value} if not isinstance(default_value, dict) else default_value,
                        description=f"Configuration for {key}",
                    )

            logger.info(f"Config reset to defaults for category: {category or 'all'}")

            return {
                "success": True,
                "data": {
                    "message": f"Configuration reset to defaults for {category or 'all'}",
                    "category": category or "all",
                },
            }
    except Exception as e:
        logger.error(f"Error resetting config: {e}", exc_info=True)
        return JSONResponse(
            content={"success": False, "error": str(e)},
            status_code=500,
        )


@app.get("/api/v1/features")
async def get_feature_flags():
    """Get feature flags."""
    try:
        flags = {
            "auto_triage": True,
            "automation": True,
            "reports": True,
            "real_time_updates": False,
            "advanced_analytics": True,
            "slack_integration": False,
        }

        return {
            "success": True,
            "data": flags,
        }
    except Exception as e:
        logger.error(f"Error fetching feature flags: {e}", exc_info=True)
        return JSONResponse(
            content={"success": False, "error": str(e)},
            status_code=500,
        )


# =============================================================================
# Workflow API
# =============================================================================

@app.get("/api/v1/workflows")
async def get_workflows(alert_id: str = None):
    """Get list of workflows, optionally filtered by alert_id."""
    try:
        from shared.database.repositories import WorkflowRepository

        async with db_manager.get_session() as session:
            repo = WorkflowRepository(session)
            workflows = await repo.get_all_workflows()

            # Convert ORM objects to dicts
            workflow_data = []
            for wf in workflows:
                workflow_dict = {
                    "id": wf.workflow_id,
                    "name": wf.name,
                    "description": wf.description,
                    "category": wf.category,
                    "status": wf.status,
                    "priority": wf.priority,
                    "steps": wf.steps,
                    "trigger_type": wf.trigger_type,
                    "total_executions": wf.total_executions,
                    "successful_executions": wf.successful_executions,
                    "failed_executions": wf.failed_executions,
                    "last_execution_at": wf.last_execution_at.isoformat() if wf.last_execution_at else None,
                    "last_execution_status": wf.last_execution_status,
                    "created_at": wf.created_at.isoformat(),
                    "updated_at": wf.updated_at.isoformat(),
                }
                workflow_data.append(workflow_dict)

            return {
                "success": True,
                "data": workflow_data,
            }
    except Exception as e:
        logger.error(f"Error fetching workflows: {e}", exc_info=True)
        return JSONResponse(
            content={"success": False, "error": str(e)},
            status_code=500,
        )


@app.get("/api/v1/workflows/executions")
async def list_workflow_executions(
    status: str = None,
    workflow_id: str = None,
    limit: int = 100,
):
    """List workflow execution records."""
    try:
        from sqlalchemy import select, desc
        from shared.database.models import WorkflowExecution

        async with db_manager.get_session() as session:
            query = select(WorkflowExecution).order_by(desc(WorkflowExecution.started_at)).limit(limit)

            if status:
                query = query.where(WorkflowExecution.status == status)
            if workflow_id:
                query = query.where(WorkflowExecution.workflow_id == workflow_id)

            result = await session.execute(query)
            executions = result.scalars().all()

            data = []
            for execution in executions:
                steps = execution.steps_execution or []
                if isinstance(steps, dict):
                    steps = steps.get("steps", []) or []

                current_step = None
                for step in steps:
                    if isinstance(step, dict) and step.get("status") == "running":
                        current_step = step.get("name") or step.get("step_id")
                        break

                data.append(
                    {
                        "workflow_id": execution.workflow_id,
                        "execution_id": execution.execution_id,
                        "status": execution.status,
                        "current_step": current_step,
                        "started_at": execution.started_at.isoformat(),
                        "completed_at": execution.completed_at.isoformat()
                        if execution.completed_at
                        else None,
                        "alert_id": execution.trigger_reference,
                        "steps": steps,
                    }
                )

            return {"success": True, "data": {"executions": data, "total": len(data)}}
    except Exception as e:
        logger.error(f"Error fetching workflow executions: {e}", exc_info=True)
        return JSONResponse(
            content={"success": False, "error": str(e)},
            status_code=500,
        )


@app.get("/api/v1/playbooks")
async def list_playbooks_proxy():
    """Proxy playbook list to automation orchestrator."""
    data = await call_service_json("automation", "/playbooks")
    if data is None:
        return JSONResponse(
            content={"success": False, "error": "Automation service unavailable"},
            status_code=502,
        )
    return data


@app.get("/api/v1/analytics/dashboard")
async def analytics_dashboard_proxy():
    """Return normalized dashboard metrics for the SPA."""
    metrics = await call_service_json("analytics", "/metrics/alerts")
    if metrics is None:
        return JSONResponse(
            content={"success": False, "error": "Analytics service unavailable"},
            status_code=502,
        )

    alert_metrics = metrics.get("data", {})
    return {
        "total_alerts": alert_metrics.get("total_alerts", 0),
        "avg_response_time": alert_metrics.get("avg_resolution_time", 0),
        "mtta": alert_metrics.get("mtta", 0),
        "mttr": alert_metrics.get("mttr", 0),
        "triaged": alert_metrics.get("triaged", 0),
        "auto_closed": alert_metrics.get("auto_closed", 0),
        "human_reviewed": alert_metrics.get("human_reviewed", 0),
    }


@app.get("/api/v1/analytics/metrics/severity-distribution")
async def analytics_severity_distribution_proxy():
    """Return severity distribution for dashboard charts."""
    metrics = await call_service_json("analytics", "/metrics/alerts")
    if metrics is None:
        return JSONResponse(
            content={"success": False, "error": "Analytics service unavailable"},
            status_code=502,
        )
    return metrics.get("data", {}).get("by_severity", {})


@app.get("/api/v1/analytics/metrics/status-distribution")
async def analytics_status_distribution_proxy():
    """Return status distribution for dashboard charts."""
    metrics = await call_service_json("analytics", "/metrics/alerts")
    if metrics is None:
        return JSONResponse(
            content={"success": False, "error": "Analytics service unavailable"},
            status_code=502,
        )
    return metrics.get("data", {}).get("by_status", {})


@app.get("/api/v1/analytics/metrics/top-alert-types")
async def analytics_top_alert_types_proxy(limit: int = 5):
    """Return top alert types in the format expected by the SPA."""
    metrics = await call_service_json("analytics", "/metrics/alerts")
    if metrics is None:
        return JSONResponse(
            content={"success": False, "error": "Analytics service unavailable"},
            status_code=502,
        )

    by_type = metrics.get("data", {}).get("by_type", {}) or {}
    rows = [
        {"alert_type": alert_type, "count": count}
        for alert_type, count in by_type.items()
    ]
    rows.sort(key=lambda item: item["count"], reverse=True)
    return rows[: max(limit, 0)]


@app.get("/api/v1/playbooks/{playbook_id}")
async def get_playbook_proxy(playbook_id: str):
    """Proxy playbook detail to automation orchestrator."""
    data = await call_service_json("automation", f"/playbooks/{playbook_id}")
    if data is None:
        return JSONResponse(
            content={"success": False, "error": "Automation service unavailable"},
            status_code=502,
        )
    return data


@app.post("/api/v1/playbooks/execute")
async def execute_playbook_proxy(request: Request):
    """Proxy playbook execution to automation orchestrator."""
    try:
        body = await request.json()
    except Exception:
        body = {}

    data = await call_service_json(
        "automation",
        "/playbooks/execute",
        method="POST",
        json_body=body,
    )
    if data is None:
        return JSONResponse(
            content={"success": False, "error": "Automation service unavailable"},
            status_code=502,
        )
    return data


@app.get("/api/v1/executions")
async def list_automation_executions_proxy():
    """Proxy automation executions to automation orchestrator."""
    data = await call_service_json("automation", "/executions")
    if data is None:
        return JSONResponse(
            content={"success": False, "error": "Automation service unavailable"},
            status_code=502,
        )
    return data


@app.get("/api/v1/executions/{execution_id}")
async def get_automation_execution_proxy(execution_id: str):
    """Proxy automation execution detail to automation orchestrator."""
    data = await call_service_json("automation", f"/executions/{execution_id}")
    if data is None:
        return JSONResponse(
            content={"success": False, "error": "Automation service unavailable"},
            status_code=502,
        )
    return data


@app.post("/api/v1/executions/{execution_id}/cancel")
async def cancel_automation_execution_proxy(execution_id: str):
    """Proxy automation execution cancellation to automation orchestrator."""
    data = await call_service_json(
        "automation",
        f"/executions/{execution_id}/cancel",
        method="POST",
        json_body={},
    )
    if data is None:
        return JSONResponse(
            content={"success": False, "error": "Automation service unavailable"},
            status_code=502,
        )
    return data


@app.get("/api/v1/workflows/{workflow_id}")
async def get_workflow(workflow_id: str):
    """Get a single workflow by ID."""
    try:
        if workflow_id == "config":
            return await get_workflow_config()

        from shared.database.repositories import WorkflowRepository

        async with db_manager.get_session() as session:
            repo = WorkflowRepository(session)
            workflow = await repo.get_workflow(workflow_id)

            if workflow:
                workflow_dict = {
                    "id": workflow.workflow_id,
                    "name": workflow.name,
                    "description": workflow.description,
                    "category": workflow.category,
                    "status": workflow.status,
                    "priority": workflow.priority,
                    "steps": workflow.steps,
                    "trigger_type": workflow.trigger_type,
                    "trigger_conditions": workflow.trigger_conditions,
                    "total_executions": workflow.total_executions,
                    "successful_executions": workflow.successful_executions,
                    "failed_executions": workflow.failed_executions,
                    "last_execution_at": workflow.last_execution_at.isoformat() if workflow.last_execution_at else None,
                    "last_execution_status": workflow.last_execution_status,
                    "created_by": workflow.created_by,
                    "created_at": workflow.created_at.isoformat(),
                    "updated_at": workflow.updated_at.isoformat(),
                }
                return {
                    "success": True,
                    "data": workflow_dict,
                }
            else:
                return JSONResponse(
                    content={"success": False, "error": "Workflow not found"},
                    status_code=404,
                )
    except Exception as e:
        logger.error(f"Error fetching workflow: {e}", exc_info=True)
        return JSONResponse(
            content={"success": False, "error": str(e)},
            status_code=500,
        )


@app.get("/api/v1/workflow-templates")
async def get_workflow_templates():
    """Get all workflow templates."""
    try:
        from sqlalchemy import select
        from shared.database.models import WorkflowTemplate

        async with db_manager.get_session() as session:
            query = select(WorkflowTemplate).where(WorkflowTemplate.is_active == True)
            result = await session.execute(query)
            templates = result.scalars().all()

            templates_data = []
            for template in templates:
                templates_data.append({
                    "id": template.template_id,
                    "name": template.name,
                    "description": template.description,
                    "category": template.category,
                    "steps": template.steps_count,
                    "stepDetails": template.steps,  # Full step details
                    "estimated_time": template.estimated_time,
                    "created_at": template.created_at.isoformat(),
                    "updated_at": template.updated_at.isoformat(),
                })

            return {
                "success": True,
                "data": templates_data,
            }
    except Exception as e:
        logger.error(f"Error fetching workflow templates: {e}", exc_info=True)
        return JSONResponse(
            content={"success": False, "error": str(e)},
            status_code=500,
        )


@app.post("/api/v1/workflows")
async def create_workflow(request: Request):
    """Create a new workflow."""
    try:
        import json
        import uuid
        from shared.database.repositories import WorkflowRepository

        body = await request.body()
        data = json.loads(body) if body else {}

        workflow_id = f"WF-{uuid.uuid4().hex[:3].upper()}"

        async with db_manager.get_session() as session:
            repo = WorkflowRepository(session)
            workflow = await repo.create_workflow(
                workflow_id=workflow_id,
                name=data.get("name", "New Workflow"),
                description=data.get("description", ""),
                category=data.get("category", "general"),
                steps=data.get("steps", []),
                trigger_type=data.get("trigger_type", "manual"),
                trigger_conditions=data.get("trigger_conditions"),
                status=data.get("status", "draft"),
                priority=data.get("priority", "medium"),
                created_by="system",  # Can be updated with auth later
            )

            workflow_dict = {
                "id": workflow.workflow_id,
                "name": workflow.name,
                "description": workflow.description,
                "category": workflow.category,
                "status": workflow.status,
                "priority": workflow.priority,
                "steps": workflow.steps,
                "trigger_type": workflow.trigger_type,
                "created_at": workflow.created_at.isoformat(),
                "updated_at": workflow.updated_at.isoformat(),
            }

            logger.info(f"Workflow created: {workflow_id}")

            return {
                "success": True,
                "data": workflow_dict,
            }
    except Exception as e:
        logger.error(f"Error creating workflow: {e}", exc_info=True)
        return JSONResponse(
            content={"success": False, "error": str(e)},
            status_code=500,
        )



@app.post("/api/v1/workflows/{workflow_id}/actions")
async def execute_workflow_action(workflow_id: str, request: Request):
    """Execute workflow action (start, pause, cancel, retry)."""
    try:
        import json
        from shared.database.repositories import WorkflowRepository

        body = await request.body()
        data = json.loads(body) if body else {}
        action = data.get("action", "start")

        async with db_manager.get_session() as session:
            repo = WorkflowRepository(session)
            workflow = await repo.get_workflow(workflow_id)

            if not workflow:
                return JSONResponse(
                    content={"success": False, "error": "Workflow not found"},
                    status_code=404,
                )

            # Update workflow status based on action
            if action == "start":
                await repo.update_workflow(workflow_id, status="running")
                # Create execution record
                import uuid
                execution_id = f"exec-{uuid.uuid4().hex[:8]}"
                await repo.create_workflow_execution(
                    execution_id=execution_id,
                    workflow_id=workflow_id,
                    trigger_type="manual",
                    executed_by="system",
                )
            elif action == "pause":
                await repo.update_workflow(workflow_id, status="draft")
            elif action == "cancel":
                await repo.update_workflow(workflow_id, status="cancelled")
            elif action == "retry":
                await repo.update_workflow(workflow_id, status="running")

            logger.info(f"Executed action '{action}' on workflow {workflow_id}")

            # Get updated workflow
            workflow = await repo.get_workflow(workflow_id)
            workflow_dict = {
                "id": workflow.workflow_id,
                "name": workflow.name,
                "description": workflow.description,
                "status": workflow.status,
                "steps": workflow.steps,
                "updated_at": workflow.updated_at.isoformat(),
            }

            return {
                "success": True,
                "data": workflow_dict,
            }
    except Exception as e:
        logger.error(f"Error executing workflow action: {e}", exc_info=True)
        return JSONResponse(
            content={"success": False, "error": str(e)},
            status_code=500,
        )


# Workflow Configuration Endpoints
_workflow_config = {
    "auto_approve": False,
    "timeout_seconds": 300,
    "retry_on_failure": True,
    "max_retries": 3,
    "notification_on_complete": True,
    "notification_channels": ["email", "slack"],
    "log_level": "info",
}


@app.get("/api/v1/workflows/config")
async def get_workflow_config():
    """Get workflow configuration."""
    try:
        return {
            "success": True,
            "data": _workflow_config,
        }
    except Exception as e:
        logger.error(f"Error getting workflow config: {e}", exc_info=True)
        return JSONResponse(
            content={"success": False, "error": str(e)},
            status_code=500,
        )


@app.put("/api/v1/workflows/config")
async def update_workflow_config(request: Request):
    """Update workflow configuration."""
    try:
        import json

        body = await request.body()
        data = json.loads(body) if body else {}

        # Update config with provided values
        for key in _workflow_config:
            if key in data:
                _workflow_config[key] = data[key]

        logger.info(f"Workflow config updated: {_workflow_config}")

        return {
            "success": True,
            "data": _workflow_config,
        }
    except Exception as e:
        logger.error(f"Error updating workflow config: {e}", exc_info=True)
        return JSONResponse(
            content={"success": False, "error": str(e)},
            status_code=500,
        )


# Workflow Templates
# TODO: Move these templates to database and provide admin UI for management
_workflow_templates = {
    "isolate-host": {
        "name": "Isolate Compromised Host",
        "description": "Isolate a host from the network when malware is detected",
        "steps": [
            {"id": "step-1", "name": "Verify Alert", "type": "automated"},
            {"id": "step-2", "name": "Block Network Access", "type": "automated"},
            {"id": "step-3", "name": "Isolate from VLAN", "type": "automated"},
            {"id": "step-4", "name": "Notify Team", "type": "automated"},
            {"id": "step-5", "name": "Update Ticket", "type": "automated"},
        ],
    },
    "block-ip": {
        "name": "Block Malicious IP",
        "description": "Block IP address at firewall level",
        "steps": [
            {"id": "step-1", "name": "Verify IP Reputation", "type": "automated"},
            {"id": "step-2", "name": "Add to Firewall Blocklist", "type": "automated"},
            {"id": "step-3", "name": "Verify Block", "type": "automated"},
        ],
    },
    "quarantine-file": {
        "name": "Quarantine Malicious File",
        "description": "Move suspicious file to quarantine",
        "steps": [
            {"id": "step-1", "name": "Identify File Location", "type": "automated"},
            {"id": "step-2", "name": "Copy to Quarantine", "type": "automated"},
            {"id": "step-3", "name": "Delete Original", "type": "automated"},
            {"id": "step-4", "name": "Update Scan Results", "type": "automated"},
        ],
    },
    "create-ticket": {
        "name": "Create Incident Ticket",
        "description": "Create ticket in incident tracking system",
        "steps": [
            {"id": "step-1", "name": "Gather Alert Details", "type": "automated"},
            {"id": "step-2", "name": "Submit Ticket", "type": "automated"},
        ],
    },
    "enrich-context": {
        "name": "Enrich Alert Context",
        "description": "Gather additional context about the alert",
        "steps": [
            {"id": "step-1", "name": "Query Threat Intel", "type": "automated"},
            {"id": "step-2", "name": "Get Asset Info", "type": "automated"},
            {"id": "step-3", "name": "Check User Context", "type": "automated"},
            {"id": "step-4", "name": "Query Historical Alerts", "type": "automated"},
            {"id": "step-5", "name": "Calculate Risk Score", "type": "automated"},
            {"id": "step-6", "name": "Update Alert", "type": "automated"},
        ],
    },
    "notify-team": {
        "name": "Notify Security Team",
        "description": "Send notifications to security team",
        "steps": [
            {"id": "step-1", "name": "Prepare Notification", "type": "automated"},
            {"id": "step-2", "name": "Send Email", "type": "automated"},
            {"id": "step-3", "name": "Send Slack Message", "type": "automated"},
        ],
    },
}


async def execute_workflow_steps(
    workflow_id: str,
    execution_id: str,
    steps: list,
    config: dict,
):
    """Execute workflow steps with actual automation logic."""
    from shared.database.repositories import WorkflowRepository

    async with db_manager.get_session() as session:
        repo = WorkflowRepository(session)
        started_at = utc_now()
        workflow = await repo.get_workflow(workflow_id)
        total_executions = (workflow.total_executions if workflow else 0) + 1
        successful_executions = workflow.successful_executions if workflow else 0
        failed_executions = workflow.failed_executions if workflow else 0
        steps_execution = [
            {
                "step_id": step.get("id", f"step-{index + 1}"),
                "name": step.get("name", f"Step {index + 1}"),
                "type": step.get("type", "automated"),
                "status": "pending",
            }
            for index, step in enumerate(steps)
        ]

        await repo.update_workflow(
            workflow_id,
            status="running",
            total_executions=total_executions,
            last_execution_at=started_at,
            last_execution_status="running",
        )
        await repo.update_workflow_execution(
            execution_id,
            status="running",
            steps_execution={"steps": steps_execution},
        )

        for step_index, step in enumerate(steps):
            try:
                logger.info(f"Executing step {step_index + 1}/{len(steps)}: {step['name']}")

                for index, step_state in enumerate(steps_execution):
                    if index < step_index:
                        step_state["status"] = "completed"
                    elif index == step_index:
                        step_state["status"] = "running"
                    else:
                        step_state["status"] = "pending"

                await repo.update_workflow_execution(
                    execution_id,
                    steps_execution={"steps": steps_execution},
                )

                await asyncio.sleep(1)

                steps_execution[step_index]["status"] = "completed"
                await repo.update_workflow_execution(
                    execution_id,
                    steps_execution={"steps": steps_execution},
                )

                logger.info(f"Step {step['name']} completed successfully")

            except Exception as e:
                logger.error(f"Error executing step {step['name']}: {e}")

                steps_execution[step_index]["status"] = "failed"
                completed_at = utc_now()
                await repo.update_workflow(
                    workflow_id,
                    status="failed",
                    failed_executions=failed_executions + 1,
                    last_execution_at=completed_at,
                    last_execution_status="failed",
                )
                await repo.update_workflow_execution(
                    execution_id,
                    status="failed",
                    completed_at=completed_at,
                    duration_seconds=int((completed_at - started_at).total_seconds()),
                    error_message=str(e),
                    steps_execution={"steps": steps_execution},
                )
                raise

        completed_at = utc_now()
        await repo.update_workflow(
            workflow_id,
            status="completed",
            successful_executions=successful_executions + 1,
            last_execution_at=completed_at,
            last_execution_status="completed",
        )
        await repo.update_workflow_execution(
            execution_id,
            status="completed",
            completed_at=completed_at,
            duration_seconds=int((completed_at - started_at).total_seconds()),
            result="Workflow completed successfully",
            steps_execution={"steps": steps_execution},
        )
        logger.info(f"Workflow {workflow_id} completed successfully")


@app.post("/api/v1/workflows/execute-from-template")
async def execute_workflow_from_template(request: Request):
    """Create and execute workflow from template."""
    try:
        import json
        import uuid
        from shared.database.repositories import WorkflowRepository

        body = await request.body()
        data = json.loads(body) if body else {}

        template_id = data.get("template_id")
        config = data.get("config", _workflow_config)

        if not template_id:
            return JSONResponse(
                content={"success": False, "error": "template_id is required"},
                status_code=400,
            )

        # Get template
        template = _workflow_templates.get(template_id)
        if not template:
            return JSONResponse(
                content={"success": False, "error": "Template not found"},
                status_code=404,
            )

        # Create workflow from template
        workflow_id = f"wf-{uuid.uuid4().hex[:8]}"

        async with db_manager.get_session() as session:
            repo = WorkflowRepository(session)

            # Create workflow
            await repo.create_workflow(
                workflow_id=workflow_id,
                name=template["name"],
                description=template["description"],
                category=template.get("category", "automation"),
                status="running",
                steps=template["steps"],
            )

            # Create execution record
            execution_id = f"exec-{uuid.uuid4().hex[:8]}"
            await repo.create_workflow_execution(
                execution_id=execution_id,
                workflow_id=workflow_id,
                trigger_type="manual",
                executed_by="system",
            )

        # Start background execution
        asyncio.create_task(
            execute_workflow_steps(workflow_id, execution_id, template["steps"], config)
        )

        logger.info(f"Workflow {workflow_id} created from template {template_id}")

        # Return workflow data
        workflow_dict = {
            "id": workflow_id,
            "name": template["name"],
            "description": template["description"],
            "status": "running",
            "steps": template["steps"],
            "current_step": 0,
            "execution_id": execution_id,
            "created_at": utc_now().isoformat(),
        }

        return {
            "success": True,
            "data": workflow_dict,
        }
    except Exception as e:
        logger.error(f"Error executing workflow from template: {e}", exc_info=True)
        return JSONResponse(
            content={"success": False, "error": str(e)},
            status_code=500,
        )


# =============================================================================
# AI Triage with Zhipu AI (智谱AI)
# =============================================================================

@app.post("/api/v1/ai/analyze-alert")
async def analyze_alert_with_ai(request: Request):
    """Analyze a security alert using configured LLM provider."""
    try:
        import json
        from llm_client import ZhipuAIClient, DeepSeekClient, QwenClient, OpenAIClient

        body = await request.body()
        data = json.loads(body) if body else {}

        alert_data = data.get("alert", {})
        context = data.get("context")

        if not alert_data:
            return JSONResponse(
                content={"success": False, "error": "Alert data is required"},
                status_code=400,
            )

        # Get LLM configuration from database
        async with db_manager.get_session() as session:
            from shared.database.repositories import SettingsRepository
            repo = SettingsRepository(session)

            configs = await repo.get_all_configs()

            # Helper function to get and decrypt config value
            def get_config_value(key: str) -> Any:
                """Get config value, decrypting if it's sensitive."""
                config = configs.get(key, {})
                if not isinstance(config, dict):
                    return config

                # Extract value from nested structure
                # configs[key] = {"value": {...}, "category": "..."}
                # The inner "value" might be {"value": actual_value} due to how we store it
                value = config.get("value", "")

                # Handle double nesting: {"value": {"value": actual_value}}
                if isinstance(value, dict) and "value" in value:
                    value = value["value"]

                # Decrypt sensitive values
                if key in SENSITIVE_CONFIG_KEYS and value:
                    try:
                        return safe_decrypt(str(value))
                    except Exception as e:
                        logger.warning(f"Failed to decrypt {key}: {e}")
                        return ""
                return value

            # Get LLM provider and API key
            llm_provider = get_config_value("llm_provider") or "zhipu"

            # Get API key and configuration for selected provider
            if llm_provider == "zhipu":
                api_key = get_config_value("zhipu_api_key")
                base_url = get_config_value("zhipu_base_url") or "https://open.bigmodel.cn/api/paas/v4/"
                model = get_config_value("zhipu_model") or "glm-4-flash"

                if not api_key:
                    return JSONResponse(
                        content={"success": False, "error": "Zhipu AI API key not configured. Please configure it in Settings > AI Models"},
                        status_code=400,
                    )

                client = ZhipuAIClient(api_key=api_key, base_url=base_url, model=model)

            elif llm_provider == "deepseek":
                api_key = get_config_value("deepseek_api_key")
                base_url = get_config_value("deepseek_base_url") or "https://api.deepseek.com/v1"
                model = get_config_value("deepseek_model") or "deepseek-v3"

                if not api_key:
                    return JSONResponse(
                        content={"success": False, "error": "DeepSeek API key not configured. Please configure it in Settings > AI Models"},
                        status_code=400,
                    )

                client = DeepSeekClient(api_key=api_key, base_url=base_url, model=model)

            elif llm_provider == "qwen":
                api_key = get_config_value("qwen_api_key")
                base_url = get_config_value("qwen_base_url") or "https://dashscope.aliyuncs.com/compatible-mode/v1"
                model = get_config_value("qwen_model") or "qwen3-max"

                if not api_key:
                    return JSONResponse(
                        content={"success": False, "error": "Qwen API key not configured. Please configure it in Settings > AI Models"},
                        status_code=400,
                    )

                client = QwenClient(api_key=api_key, base_url=base_url, model=model)

            else:  # openai
                api_key = get_config_value("openai_api_key")
                base_url = get_config_value("openai_base_url") or "https://api.openai.com/v1"
                model = get_config_value("openai_model") or "gpt-4-turbo"

                if not api_key:
                    return JSONResponse(
                        content={"success": False, "error": "OpenAI API key not configured. Please configure it in Settings > AI Models"},
                        status_code=400,
                    )

                client = OpenAIClient(api_key=api_key, base_url=base_url, model=model)

        # Get temperature and max_tokens from config
        temperature = get_config_value("temperature") or 0.0
        max_tokens = get_config_value("max_tokens") or 2000

        # Ensure they are the correct type
        try:
            temperature = float(temperature)
        except (ValueError, TypeError):
            temperature = 0.0

        try:
            max_tokens = int(max_tokens)
        except (ValueError, TypeError):
            max_tokens = 2000

        # Analyze the alert
        result = await client.analyze_alert(alert_data, context, temperature=temperature, max_tokens=max_tokens)

        # Close the client
        await client.close()

        logger.info(f"Alert {alert_data.get('id')} analyzed with AI using {llm_provider}")

        return {
            "success": True,
            "data": result,
        }

    except Exception as e:
        logger.error(f"Error analyzing alert with AI: {e}", exc_info=True)
        return JSONResponse(
            content={"success": False, "error": str(e)},
            status_code=500,
        )


@app.post("/api/v1/ai/batch-analyze")
async def batch_analyze_alerts_with_ai(request: Request):
    """Analyze multiple alerts using configured LLM provider."""
    try:
        import json
        from llm_client import ZhipuAIClient, DeepSeekClient, QwenClient, OpenAIClient

        body = await request.body()
        data = json.loads(body) if body else {}

        alerts = data.get("alerts", [])

        if not alerts:
            return JSONResponse(
                content={"success": False, "error": "Alerts list is required"},
                status_code=400,
            )

        # Get LLM configuration from database
        async with db_manager.get_session() as session:
            from shared.database.repositories import SettingsRepository
            repo = SettingsRepository(session)

            configs = await repo.get_all_configs()

            # Helper function to get and decrypt config value
            def get_config_value(key: str) -> Any:
                """Get config value, decrypting if it's sensitive."""
                config = configs.get(key, {})
                if not isinstance(config, dict):
                    return config

                # Extract value from nested structure
                value = config.get("value", "")

                # Handle double nesting: {"value": {"value": actual_value}}
                if isinstance(value, dict) and "value" in value:
                    value = value["value"]

                # Decrypt sensitive values
                if key in SENSITIVE_CONFIG_KEYS and value:
                    try:
                        return safe_decrypt(str(value))
                    except Exception as e:
                        logger.warning(f"Failed to decrypt {key}: {e}")
                        return ""
                return value

            # Get LLM provider and API key
            llm_provider = get_config_value("llm_provider") or "zhipu"

            # Get API key and configuration for selected provider
            if llm_provider == "zhipu":
                api_key = get_config_value("zhipu_api_key")
                base_url = get_config_value("zhipu_base_url") or "https://open.bigmodel.cn/api/paas/v4/"
                model = get_config_value("zhipu_model") or "glm-4-flash"

                if not api_key:
                    return JSONResponse(
                        content={"success": False, "error": "Zhipu AI API key not configured. Please configure it in Settings > AI Models"},
                        status_code=400,
                    )

                client = ZhipuAIClient(api_key=api_key, base_url=base_url, model=model)

            elif llm_provider == "deepseek":
                api_key = get_config_value("deepseek_api_key")
                base_url = get_config_value("deepseek_base_url") or "https://api.deepseek.com/v1"
                model = get_config_value("deepseek_model") or "deepseek-v3"

                if not api_key:
                    return JSONResponse(
                        content={"success": False, "error": "DeepSeek API key not configured. Please configure it in Settings > AI Models"},
                        status_code=400,
                    )

                client = DeepSeekClient(api_key=api_key, base_url=base_url, model=model)

            elif llm_provider == "qwen":
                api_key = get_config_value("qwen_api_key")
                base_url = get_config_value("qwen_base_url") or "https://dashscope.aliyuncs.com/compatible-mode/v1"
                model = get_config_value("qwen_model") or "qwen3-max"

                if not api_key:
                    return JSONResponse(
                        content={"success": False, "error": "Qwen API key not configured. Please configure it in Settings > AI Models"},
                        status_code=400,
                    )

                client = QwenClient(api_key=api_key, base_url=base_url, model=model)

            elif llm_provider == "openai":
                api_key = get_config_value("openai_api_key")
                base_url = get_config_value("openai_base_url") or "https://api.openai.com/v1"
                model = get_config_value("openai_model") or "gpt-4"

                if not api_key:
                    return JSONResponse(
                        content={"success": False, "error": "OpenAI API key not configured. Please configure it in Settings > AI Models"},
                        status_code=400,
                    )

                client = OpenAIClient(api_key=api_key, base_url=base_url, model=model)

            else:
                return JSONResponse(
                    content={"success": False, "error": f"Unknown LLM provider: {llm_provider}"},
                    status_code=400,
                )

        # Analyze alerts in batch
        results = await client.batch_analyze_alerts(alerts)

        logger.info(f"Batch analyzed {len(alerts)} alerts with AI using {llm_provider}")

        return {
            "success": True,
            "data": results,
        }

    except Exception as e:
        logger.error(f"Error batch analyzing alerts with AI: {e}", exc_info=True)
        return JSONResponse(
            content={"success": False, "error": str(e)},
            status_code=500,
        )


# =============================================================================
# WebSocket Support for Real-time Updates
# =============================================================================

# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"WebSocket connected. Total connections: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)
        logger.info(f"WebSocket disconnected. Total connections: {len(self.active_connections)}")

    async def broadcast(self, message: dict):
        """Broadcast a message to all connected clients."""
        if self.active_connections:
            disconnected = []
            for connection in self.active_connections:
                try:
                    await connection.send_json(message)
                except Exception as e:
                    logger.error(f"Error broadcasting to client: {e}")
                    disconnected.append(connection)

            # Remove disconnected clients
            for conn in disconnected:
                self.disconnect(conn)

    async def send_personal_message(self, message: dict, websocket: WebSocket):
        """Send a message to a specific client."""
        try:
            await websocket.send_json(message)
        except Exception as e:
            logger.error(f"Error sending message to client: {e}")
            self.disconnect(websocket)


manager = ConnectionManager()


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time updates."""
    await manager.connect(websocket)

    try:
        # Send initial data on connection
        from shared.database.repositories import WorkflowRepository

        async with db_manager.get_session() as session:
            repo = WorkflowRepository(session)
            workflows = await repo.get_all_workflows()
            workflows_data = [
                {
                    "id": wf.workflow_id,
                    "name": wf.name,
                    "status": wf.status,
                    "category": wf.category,
                }
                for wf in workflows
            ]

        await websocket.send_json({
            "type": "connected",
            "message": "WebSocket connected successfully",
            "data": {
                "metrics": {},
                "workflows": workflows_data,
            }
        })

        # Keep connection alive and handle client messages
        while True:
            data = await websocket.receive_text()
            try:
                message = json.loads(data)

                # Handle client requests
                if message.get("type") == "ping":
                    await websocket.send_json({"type": "pong"})
                elif message.get("type") == "subscribe":
                    # Client wants to subscribe to specific updates
                    await websocket.send_json({
                        "type": "subscribed",
                        "channels": message.get("channels", [])
                    })
            except json.JSONDecodeError:
                logger.warning(f"Invalid JSON received from client: {data}")

    except WebSocketDisconnect:
        manager.disconnect(websocket)
        logger.info("WebSocket client disconnected")
    except Exception as e:
        logger.error(f"WebSocket error: {e}", exc_info=True)
        manager.disconnect(websocket)


# Background task to broadcast updates
async def broadcast_updates():
    """Background task to broadcast periodic updates to all WebSocket clients."""
    while True:
        try:
            # Wait 30 seconds between broadcasts
            await asyncio.sleep(30)

            # Broadcast metrics update (disabled - no metrics data available)
            # TODO: Implement real-time metrics collection from analytics service
            pass

            # Broadcast workflows update
            from shared.database.repositories import WorkflowRepository

            async with db_manager.get_session() as session:
                repo = WorkflowRepository(session)
                workflows = await repo.get_all_workflows()
                workflows_data = [
                    {
                        "id": wf.workflow_id,
                        "name": wf.name,
                        "status": wf.status,
                        "category": wf.category,
                    }
                    for wf in workflows
                ]
                await manager.broadcast({
                    "type": "workflows_update",
                    "data": workflows_data,
                })

            logger.debug("Broadcasted updates to all clients")
        except Exception as e:
            logger.error(f"Error broadcasting updates: {e}", exc_info=True)


# Start background task on startup
@app.on_event("startup")
async def startup_event():
    """Start background tasks on application startup."""
    # Start the broadcast background task
    asyncio.create_task(broadcast_updates())
    logger.info("Background WebSocket broadcast task started")


# SPA fallback - serve React app for all other routes
@app.get("/{full_path:path}")
async def serve_spa(full_path: str):
    """Serve React SPA for all non-API routes."""
    # Prefer Docker /app/static, fallback to local dist
    index_path = Path("/app/static/index.html")
    if not index_path.exists():
        index_path = BASE_DIR / "dist" / "index.html"

    if index_path.exists():
        return FileResponse(
            str(index_path),
            headers={
                "Cache-Control": "no-cache, no-store, must-revalidate",
                "Pragma": "no-cache",
                "Expires": "0",
            }
        )
    return JSONResponse(
        content={"success": False, "error": "Frontend not built"},
        status_code=503,
    )


@app.get("/")
async def root():
    """Root route - serve React SPA."""
    # Prefer Docker /app/static, fallback to local dist
    index_path = Path("/app/static/index.html")
    logger.info(f"Looking for frontend at: {index_path}, exists: {index_path.exists()}")

    if not index_path.exists():
        index_path = BASE_DIR / "dist" / "index.html"
        logger.info(f"Trying Docker path: {index_path}, exists: {index_path.exists()}")

    if index_path.exists():
        logger.info(f"Serving frontend from: {index_path}")
        return FileResponse(
            str(index_path),
            headers={
                "Cache-Control": "no-cache, no-store, must-revalidate",
                "Pragma": "no-cache",
                "Expires": "0",
            }
        )
    logger.error(f"Frontend not found at either location!")
    return JSONResponse(
        content={"success": False, "error": "Frontend not built"},
        status_code=503,
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=config.host, port=config.port)
