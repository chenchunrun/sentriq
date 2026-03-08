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
Alert Ingestor Service - Main Application

Receives security alerts from multiple sources and publishes to message queue.
"""

import asyncio
import json
import os
import uuid
from collections import defaultdict
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Dict, List

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text
from shared.database import DatabaseManager, get_database_manager, init_database, close_database
from shared.errors import ValidationError
from shared.messaging import MessagePublisher
from shared.models import (
    AlertBatch,
    ErrorResponse,
    ResponseMeta,
    SecurityAlert,
    SuccessResponse,
)
from shared.utils import Config, get_logger, utc_now, utc_now_iso
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

# Initialize logger
logger = get_logger(__name__)

# Initialize config
config = Config()

# Initialize rate limiter
limiter = Limiter(key_func=get_remote_address)
logger.info("Rate limiter initialized")

# Global variables
db_manager: DatabaseManager = None
message_publisher: MessagePublisher = None

# In-memory rate limit tracking (fallback if slowapi not available)
rate_limit_tracker: Dict[str, List[datetime]] = defaultdict(list)
RATE_LIMIT_REQUESTS = 100
RATE_LIMIT_WINDOW = 60  # seconds


def create_alert_message(alert: SecurityAlert, message_id: str | None = None) -> Dict[str, object]:
    """Create a queue message payload for a security alert."""
    msg_id = message_id or str(uuid.uuid4())
    return {
        "message_id": msg_id,
        "message_type": "alert.raw",
        "correlation_id": alert.alert_id,
        "timestamp": utc_now_iso(),
        "payload": alert.model_dump(mode="json"),
    }


async def check_rate_limit(request: Request) -> None:
    """
    Check rate limit for client IP.

    Allows 100 requests per minute per IP.
    """
    client_ip = request.client.host
    now = utc_now().replace(tzinfo=None)

    # Clean old entries
    recent_requests = rate_limit_tracker.get(client_ip, [])
    rate_limit_tracker[client_ip] = [
        ts for ts in recent_requests if (now - ts).total_seconds() < RATE_LIMIT_WINDOW
    ]

    # Check limit
    if len(rate_limit_tracker[client_ip]) >= RATE_LIMIT_REQUESTS:
        logger.warning(f"Rate limit exceeded for {client_ip}")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Please try again later.",
        )

    # Add current request
    rate_limit_tracker[client_ip].append(now)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    global db_manager, message_publisher

    # Startup
    logger.info("Starting Alert Ingestor Service")

    try:
        # Initialize database FIRST before getting manager
        await init_database(
            database_url=config.database_url,
            pool_size=int(os.getenv("DB_POOL_SIZE", "10")),
            max_overflow=int(os.getenv("DB_MAX_OVERFLOW", "20")),
            echo=config.debug,
        )
        db_manager = get_database_manager()
        logger.info("✓ Database connected")

        # Initialize message publisher
        message_publisher = MessagePublisher(config.rabbitmq_url)
        await message_publisher.connect()
        logger.info("✓ Message publisher connected")

        logger.info("✓ Alert Ingestor Service started successfully")

        yield

    except Exception as e:
        logger.error(f"Failed to start service: {e}")
        raise

    finally:
        # Shutdown
        logger.info("Shutting down Alert Ingestor Service")

        if message_publisher:
            await message_publisher.close()
            logger.info("✓ Message publisher closed")

        # Close database using the close_database function
        await close_database()
        logger.info("✓ Database connection closed")

        logger.info("✓ Alert Ingestor Service stopped")


# Create FastAPI app
app = FastAPI(
    title="Alert Ingestor API",
    description="Security alert ingestion service with rate limiting",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure properly in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Rate limit exception handler
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


# Health check
@app.get("/health", tags=["Health"])
async def health_check():
    """Health check endpoint."""
    try:
        # Check database
        db_health = await db_manager.health_check()

        return {
            "status": "healthy",
            "service": "alert-ingestor",
            "timestamp": utc_now_iso(),
            "checks": {
                "database": db_health,
                "message_queue": "connected" if message_publisher else "disconnected",
            },
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return JSONResponse(
            status_code=503,
            content={
                "status": "unhealthy",
                "service": "alert-ingestor",
                "error": str(e),
            },
        )


# API Routes
@app.post(
    "/api/v1/alerts",
    response_model=SuccessResponse[dict],
    tags=["Alerts"],
    summary="Ingest a single alert",
    dependencies=[Depends(check_rate_limit)],
)
async def ingest_alert(request: Request, alert: SecurityAlert):
    """
    Ingest a single security alert.

    Validates the alert, persists to database, and publishes to message queue.

    Args:
        request: FastAPI request object
        alert: Security alert data

    Returns:
        Ingestion confirmation with ingestion_id

    Raises:
        HTTPException: If validation fails or ingestion error occurs
    """
    try:
        # Generate ingestion ID
        ingestion_id = str(uuid.uuid4())

        # Validate alert
        if not alert.alert_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="alert_id is required",
            )

        # Persist to database
        async with db_manager.get_session() as session:
            await session.execute(
                text("""
                    INSERT INTO alerts (alert_id, received_at, alert_type, severity, description,
                                      source_ip, destination_ip, file_hash, url, asset_id, user_name, raw_data)
                    VALUES (:alert_id, :received_at, :alert_type, :severity, :description,
                            :source_ip, :destination_ip, :file_hash, :url, :asset_id, :user_name,
                            CAST(:raw_data AS jsonb))
                """),
                {
                    "alert_id": alert.alert_id,
                    "received_at": alert.timestamp,
                    "alert_type": alert.alert_type.value,
                    "severity": alert.severity.value,
                    "description": alert.description,
                    "source_ip": alert.source_ip,
                    "destination_ip": alert.target_ip,
                    "file_hash": alert.file_hash,
                    "url": alert.url,
                    "asset_id": alert.asset_id,
                    "user_name": alert.user_id,
                    "raw_data": json.dumps(
                        alert.raw_data if alert.raw_data is not None else alert.model_dump(mode="json")
                    ),
                }
            )
            await session.commit()

        # Create message
        message = {
            "message_id": ingestion_id,
            "message_type": "alert.raw",
            "correlation_id": alert.alert_id,
            "timestamp": utc_now_iso(),
            "version": "1.0",
            "payload": alert.model_dump(mode="json"),
        }

        # Publish to message queue
        await message_publisher.publish("alert.raw", message)

        # Log successful ingestion
        logger.info(
            "Alert ingested successfully",
            extra={
                "ingestion_id": ingestion_id,
                "alert_id": alert.alert_id,
                "alert_type": alert.alert_type.value,
                "severity": alert.severity.value,
                "source_ip": alert.source_ip,
                "target_ip": alert.target_ip,
                "client_ip": request.client.host,
            },
        )

        # Return response
        return SuccessResponse(
            data={
                "ingestion_id": ingestion_id,
                "alert_id": alert.alert_id,
                "status": "queued",
                "message": "Alert queued for processing",
            },
            meta=ResponseMeta(
                timestamp=utc_now().replace(tzinfo=None),
                request_id=ingestion_id,
            ),
        )

    except ValidationError as e:
        logger.warning(f"Validation error: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Validation error: {str(e)}",
        )
    except Exception as e:
        logger.error(f"Failed to ingest alert {alert.alert_id}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to ingest alert: {str(e)}",
        )


@app.post(
    "/api/v1/alerts/batch",
    response_model=SuccessResponse[dict],
    tags=["Alerts"],
    summary="Ingest multiple alerts",
)
async def ingest_alert_batch(batch: AlertBatch):
    """
    Ingest multiple security alerts in batch.

    Args:
        batch: Batch of alerts (max 100)

    Returns:
        Batch ingestion confirmation
    """
    try:
        # Generate batch ID if not provided
        if not batch.batch_id:
            batch.batch_id = f"BATCH-{uuid.uuid4()}"

        # Process each alert
        ingestion_ids = []
        errors = []

        for alert in batch.alerts:
            try:
                ingestion_id = str(uuid.uuid4())
                message = {
                    "message_id": ingestion_id,
                    "message_type": "alert.raw",
                    "correlation_id": alert.alert_id,
                    "batch_id": batch.batch_id,
                    "timestamp": utc_now_iso(),
                    "payload": alert.model_dump(),
                }

                await message_publisher.publish("alert.raw", message)
                ingestion_ids.append(ingestion_id)

            except Exception as e:
                logger.error(f"Failed to ingest alert {alert.alert_id}: {e}")
                errors.append({"alert_id": alert.alert_id, "error": str(e)})

        # Log
        logger.info(
            f"Batch ingested: {batch.batch_id}",
            extra={
                "batch_id": batch.batch_id,
                "total": len(batch.alerts),
                "successful": len(ingestion_ids),
                "failed": len(errors),
            },
        )

        # Return response
        return SuccessResponse(
            data={
                "batch_id": batch.batch_id,
                "total": len(batch.alerts),
                "successful": len(ingestion_ids),
                "failed": len(errors),
                "ingestion_ids": ingestion_ids,
                "errors": errors if errors else None,
            },
            meta=ResponseMeta(
                timestamp=utc_now().replace(tzinfo=None),
                request_id=batch.batch_id,
            ),
        )

    except Exception as e:
        logger.error(f"Failed to ingest batch: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to ingest batch: {str(e)}",
        )


@app.get(
    "/api/v1/alerts/{alert_id}",
    response_model=SuccessResponse[dict],
    tags=["Alerts"],
    summary="Get alert status",
)
async def get_alert_status(alert_id: str):
    """
    Get alert processing status.

    Args:
        alert_id: Alert identifier

    Returns:
        Alert status information
    """
    async with db_manager.get_session() as session:
        result = await session.execute(
            text(
                """
                SELECT status, updated_at, received_at
                FROM alerts
                WHERE alert_id = :alert_id
                """
            ),
            {"alert_id": alert_id},
        )
        row = result.fetchone()

    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert {alert_id} not found",
        )

    return SuccessResponse(
        data={
            "alert_id": alert_id,
            "status": row.status,
            "received_at": row.received_at.isoformat() if row.received_at else None,
            "updated_at": row.updated_at.isoformat() if row.updated_at else None,
        },
        meta=ResponseMeta(
            timestamp=utc_now().replace(tzinfo=None),
            request_id=str(uuid.uuid4()),
        ),
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host=config.host,
        port=config.port,
        reload=config.debug,
        log_level=config.log_level.lower(),
    )
