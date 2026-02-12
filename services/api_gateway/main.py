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
API Gateway for Security Triage System.

FastAPI-based REST API that provides endpoints for alert management,
analytics, and system operations. Acts as the single entry point for
all frontend API calls.
"""

import os
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from loguru import logger

from routes.alerts import router as alerts_router
from routes.analytics import router as analytics_router

import sys
sys.path.insert(0, '/Users/newmba/security')
from shared.database.base import get_database_manager, init_database


# =============================================================================
# Lifespan Management
# =============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator:
    """
    Manage application lifespan.

    Initialize database connection and other resources on startup,
    cleanup on shutdown.
    """
    # Startup
    logger.info("Starting API Gateway")

    # Initialize database
    database_url = os.getenv(
        "DATABASE_URL",
        "sqlite+aiosqlite:///data/triage.db",
    )

    try:
        await init_database(database_url=database_url, echo=False)
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        raise

    yield

    # Shutdown
    logger.info("Shutting down API Gateway")
    from shared.database.base import close_database
    await close_database()


# =============================================================================
# FastAPI Application
# =============================================================================

# Create FastAPI application
app = FastAPI(
    title="Security Triage System API",
    description="""
    API Gateway for the AI-powered Security Alert Triage System.

    ## Features
    * Alert management and triage
    * Analytics and reporting
    * Real-time updates (WebSocket)
    * User authentication and RBAC

    ## Authentication
    All endpoints require JWT authentication except for health checks.
    """,
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)


# =============================================================================
# Middleware
# =============================================================================

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# GZip compression
app.add_middleware(GZipMiddleware, minimum_size=1000)


# =============================================================================
# Exception Handlers
# =============================================================================

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler for unhandled exceptions."""
    logger.error(
        f"Unhandled exception: {exc}",
        extra={
            "path": request.url.path,
            "method": request.method,
        },
    )

    return JSONResponse(
        status_code=500,
        content={
            "success": False,
            "error": "INTERNAL_SERVER_ERROR",
            "message": "An unexpected error occurred",
            "detail": str(exc) if os.getenv("DEBUG") else None,
        },
    )


@app.exception_handler(ValueError)
async def value_error_handler(request: Request, exc: ValueError):
    """Handler for ValueError exceptions."""
    return JSONResponse(
        status_code=400,
        content={
            "success": False,
            "error": "VALIDATION_ERROR",
            "message": str(exc),
        },
    )


# =============================================================================
# Routers
# =============================================================================

# Include routers
app.include_router(
    alerts_router,
    prefix="/api/v1/alerts",
    tags=["Alerts"],
)

app.include_router(
    analytics_router,
    prefix="/api/v1/analytics",
    tags=["Analytics"],
)
app.include_router(
    auth_router,
    prefix="/api/v1/auth",
    tags=["Authentication"],
)


# =============================================================================
# Health Check Endpoints
# =============================================================================

@app.get("/", tags=["Health"])
async def root():
    """Root endpoint with API information."""
    return {
        "name": "Security Triage System API",
        "version": "1.0.0",
        "status": "operational",
        "documentation": "/docs",
    }


@app.get("/health", tags=["Health"])
async def health_check():
    """
    Health check endpoint.

    Returns the health status of the API and its dependencies.
    """
    health_status = {
        "status": "healthy",
        "components": {},
    }

    # Check database
    try:
        db_manager = get_database_manager()
        db_health = await db_manager.health_check()
        health_status["components"]["database"] = db_health

        if db_health.get("status") != "healthy":
            health_status["status"] = "degraded"
    except Exception as e:
        health_status["components"]["database"] = {
            "status": "unhealthy",
            "error": str(e),
        }
        health_status["status"] = "unhealthy"

    return health_status


@app.get("/health/live", tags=["Health"])
async def liveness_probe():
    """
    Kubernetes liveness probe.

    Simple endpoint to check if the API is running.
    """
    return {"status": "alive"}


@app.get("/health/ready", tags=["Health"])
async def readiness_probe():
    """
    Kubernetes readiness probe.

    Check if the API is ready to handle requests.
    """
    ready = True

    # Check database
    try:
        db_manager = get_database_manager()
        db_health = await db_manager.health_check()
        if db_health.get("status") != "healthy":
            ready = False
    except Exception:
        ready = False

    return {"ready": ready}


# =============================================================================
# Startup Event
# =============================================================================

@app.on_event("startup")
async def startup_event():
    """Log startup information."""
    logger.info(
        "API Gateway started",
        extra={
            "version": "1.0.0",
            "docs_url": "/docs",
            "redoc_url": "/redoc",
        },
    )


@app.on_event("shutdown")
async def shutdown_event():
    """Log shutdown information."""
    logger.info("API Gateway stopped")


# =============================================================================
# Main Entry Point
# =============================================================================

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8080,
        reload=True,
        log_level="info",
    )
