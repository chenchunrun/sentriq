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

"""Monitoring & Metrics Service - Collects and exposes system metrics."""

import asyncio
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import os
import psutil
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from shared.database import DatabaseManager, close_database, get_database_manager, init_database
from shared.utils import Config, get_logger

logger = get_logger(__name__)
config = Config()

db_manager: DatabaseManager = None

# Service registry - all services to monitor
SERVICE_REGISTRY = {
    "alert_ingestor": {"url": os.getenv("ALERT_INGESTOR_URL", "http://alert-ingestor:8000"), "health_path": "/health"},
    "alert_normalizer": {"url": os.getenv("ALERT_NORMALIZER_URL", "http://alert-normalizer:8000"), "health_path": "/health"},
    "context_collector": {"url": os.getenv("CONTEXT_COLLECTOR_URL", "http://context-collector:8000"), "health_path": "/health"},
    "threat_intel": {"url": os.getenv("THREAT_INTEL_URL", "http://threat-intel-aggregator:8000"), "health_path": "/health"},
    "llm_router": {"url": os.getenv("LLM_ROUTER_URL", "http://llm-router:8000"), "health_path": "/health"},
    "ai_triage": {"url": os.getenv("AI_TRIAGE_URL", "http://ai-triage-agent:8000"), "health_path": "/health"},
    "similarity_search": {"url": os.getenv("SIMILARITY_SEARCH_URL", "http://similarity-search:8000"), "health_path": "/health"},
    "workflow_engine": {"url": os.getenv("WORKFLOW_ENGINE_URL", "http://workflow-engine:8000"), "health_path": "/health"},
    "automation_orchestrator": {"url": os.getenv("AUTOMATION_ORCH_URL", "http://automation-orchestrator:8000"), "health_path": "/health"},
    "data_analytics": {"url": os.getenv("DATA_ANALYTICS_URL", "http://data-analytics:8000"), "health_path": "/health"},
    "reporting_service": {"url": os.getenv("REPORTING_SERVICE_URL", "http://reporting-service:8000"), "health_path": "/health"},
    "notification_service": {"url": os.getenv("NOTIFICATION_SERVICE_URL", "http://notification-service:8000"), "health_path": "/health"},
    "configuration_service": {"url": os.getenv("CONFIG_SERVICE_URL", "http://configuration-service:8000"), "health_path": "/health"},
    "web_dashboard": {"url": os.getenv("WEB_DASHBOARD_URL", "http://web-dashboard:8000"), "health_path": "/health"},
}

# Metrics storage
metrics_store: Dict[str, List[Dict[str, Any]]] = {
    "system": [],  # System metrics (CPU, memory, etc.)
    "services": [],  # Service health metrics
    "api": [],  # API performance metrics
}

# Service health status
service_health: Dict[str, Dict[str, Any]] = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifespan."""
    global db_manager

    logger.info("Starting Monitoring & Metrics service...")

    # Initialize database
    await init_database(
        database_url=config.database_url,
        pool_size=int(os.getenv("DB_POOL_SIZE", "10")),
        max_overflow=int(os.getenv("DB_MAX_OVERFLOW", "20")),
        echo=config.debug,
    )
    db_manager = get_database_manager()

    # Start background tasks
    asyncio.create_task(collect_system_metrics())
    asyncio.create_task(check_service_health())
    asyncio.create_task(cleanup_old_metrics())

    logger.info("Monitoring & Metrics service started successfully")

    yield

    await close_database()
    logger.info("Monitoring & Metrics service stopped")


app = FastAPI(
    title="Monitoring & Metrics Service",
    description="Collects and exposes system and service metrics",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


async def collect_system_metrics():
    """Collect system metrics periodically."""
    while True:
        try:
            # CPU metrics
            cpu_percent = psutil.cpu_percent(interval=1)

            # Memory metrics
            memory = psutil.virtual_memory()

            # Disk metrics
            disk = psutil.disk_usage("/")

            # Network metrics
            net_io = psutil.net_io_counters()

            metric = {
                "timestamp": datetime.utcnow().isoformat(),
                "cpu": {"percent": cpu_percent, "count": psutil.cpu_count()},
                "memory": {
                    "total": memory.total,
                    "available": memory.available,
                    "percent": memory.percent,
                    "used": memory.used,
                    "free": memory.free,
                },
                "disk": {
                    "total": disk.total,
                    "used": disk.used,
                    "free": disk.free,
                    "percent": disk.percent,
                },
                "network": {
                    "bytes_sent": net_io.bytes_sent,
                    "bytes_recv": net_io.bytes_recv,
                    "packets_sent": net_io.packets_sent,
                    "packets_recv": net_io.packets_recv,
                },
            }

            metrics_store["system"].append(metric)

            # Keep only last hour of data
            cutoff = datetime.utcnow() - timedelta(hours=1)
            metrics_store["system"] = [
                m
                for m in metrics_store["system"]
                if datetime.fromisoformat(m["timestamp"]) > cutoff
            ]

            logger.debug(f"System metrics collected: CPU {cpu_percent}%, Memory {memory.percent}%")

        except Exception as e:
            logger.error(f"Failed to collect system metrics: {e}", exc_info=True)

        await asyncio.sleep(30)  # Collect every 30 seconds


async def check_service_health():
    """Check health of all registered services."""
    while True:
        try:
            import httpx

            async with httpx.AsyncClient(timeout=5.0) as client:
                for service_name, service_config in SERVICE_REGISTRY.items():
                    try:
                        url = f"{service_config['url']}{service_config['health_path']}"
                        response = await client.get(url)

                        is_healthy = response.status_code == 200

                        service_health[service_name] = {
                            "status": "healthy" if is_healthy else "unhealthy",
                            "status_code": response.status_code,
                            "response_time": (
                                response.elapsed.total_seconds()
                                if hasattr(response, "elapsed")
                                else 0
                            ),
                            "last_check": datetime.utcnow().isoformat(),
                            "url": service_config["url"],
                        }

                    except Exception as e:
                        service_health[service_name] = {
                            "status": "unreachable",
                            "error": str(e),
                            "last_check": datetime.utcnow().isoformat(),
                            "url": service_config["url"],
                        }

                # Store service health metrics
                metrics_store["services"].append(
                    {
                        "timestamp": datetime.utcnow().isoformat(),
                        "services": {
                            name: health["status"] for name, health in service_health.items()
                        },
                    }
                )

                # Keep only last hour
                cutoff = datetime.utcnow() - timedelta(hours=1)
                metrics_store["services"] = [
                    m
                    for m in metrics_store["services"]
                    if datetime.fromisoformat(m["timestamp"]) > cutoff
                ]

        except Exception as e:
            logger.error(f"Failed to check service health: {e}", exc_info=True)

        await asyncio.sleep(60)  # Check every minute


async def cleanup_old_metrics():
    """Clean up old metrics periodically."""
    while True:
        try:
            await asyncio.sleep(300)  # Every 5 minutes

            cutoff = datetime.utcnow() - timedelta(hours=24)

            for metric_type in metrics_store:
                original_count = len(metrics_store[metric_type])
                metrics_store[metric_type] = [
                    m
                    for m in metrics_store[metric_type]
                    if datetime.fromisoformat(m["timestamp"]) > cutoff
                ]
                removed = original_count - len(metrics_store[metric_type])

                if removed > 0:
                    logger.info(f"Cleaned up {removed} old {metric_type} metrics")

        except Exception as e:
            logger.error(f"Failed to cleanup old metrics: {e}", exc_info=True)


# API Endpoints


@app.get("/metrics", response_class=PlainTextResponse)
async def prometheus_metrics():
    """
    Expose metrics in Prometheus format.

    Prometheus text format:
    # HELP metric_name description
    # TYPE metric_name type
    metric_name labels value
    """
    try:
        lines = []

        # System metrics
        if metrics_store["system"]:
            latest = metrics_store["system"][-1]

            # CPU
            lines.append("# HELP system_cpu_percent CPU usage percentage")
            lines.append("# TYPE system_cpu_percent gauge")
            lines.append(f"system_cpu_percent {latest['cpu']['percent']}")

            # Memory
            lines.append("# HELP system_memory_percent Memory usage percentage")
            lines.append("# TYPE system_memory_percent gauge")
            lines.append(f"system_memory_percent {latest['memory']['percent']}")

            # Disk
            lines.append("# HELP system_disk_percent Disk usage percentage")
            lines.append("# TYPE system_disk_percent gauge")
            lines.append(f"system_disk_percent {latest['disk']['percent']}")

        # Service health metrics
        for service_name, health in service_health.items():
            status = 1 if health.get("status") == "healthy" else 0

            lines.append(f"# HELP service_up Service health status")
            lines.append(f"# TYPE service_up gauge")
            lines.append(f'service_up{{service="{service_name}"}} {status}')

            if "response_time" in health:
                lines.append(f"# HELP service_response_time Service response time")
                lines.append(f"# TYPE service_response_time gauge")
                lines.append(
                    f'service_response_time{{service="{service_name}"}} {health["response_time"]}'
                )

        return "\n".join(lines) + "\n"

    except Exception as e:
        logger.error(f"Failed to generate Prometheus metrics: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to generate metrics: {str(e)}")


@app.get("/api/v1/metrics/system", response_model=Dict[str, Any])
async def get_system_metrics(limit: int = 60):
    """Get system metrics history."""
    try:
        metrics = metrics_store.get("system", [])
        metrics = metrics[-limit:]  # Get last N metrics

        return {
            "success": True,
            "data": {"metrics": metrics, "total": len(metrics)},
            "meta": {"timestamp": datetime.utcnow().isoformat(), "request_id": str(uuid.uuid4())},
        }

    except Exception as e:
        logger.error(f"Failed to get system metrics: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to get system metrics: {str(e)}")


@app.get("/api/v1/metrics/services", response_model=Dict[str, Any])
async def get_service_metrics():
    """Get service health metrics."""
    try:
        return {
            "success": True,
            "data": {
                "services": service_health,
                "total": len(service_health),
                "healthy": sum(1 for s in service_health.values() if s.get("status") == "healthy"),
                "unhealthy": sum(
                    1 for s in service_health.values() if s.get("status") != "healthy"
                ),
            },
            "meta": {"timestamp": datetime.utcnow().isoformat(), "request_id": str(uuid.uuid4())},
        }

    except Exception as e:
        logger.error(f"Failed to get service metrics: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to get service metrics: {str(e)}")


@app.get("/api/v1/health/services", response_model=Dict[str, Any])
async def get_services_health():
    """Get health status of all services."""
    try:
        return {
            "success": True,
            "data": {
                "services": service_health,
                "summary": {
                    "total": len(SERVICE_REGISTRY),
                    "healthy": sum(
                        1 for s in service_health.values() if s.get("status") == "healthy"
                    ),
                    "unreachable": sum(
                        1 for s in service_health.values() if s.get("status") == "unreachable"
                    ),
                    "unhealthy": sum(
                        1 for s in service_health.values() if s.get("status") == "unhealthy"
                    ),
                },
            },
            "meta": {"timestamp": datetime.utcnow().isoformat(), "request_id": str(uuid.uuid4())},
        }

    except Exception as e:
        logger.error(f"Failed to get services health: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to get services health: {str(e)}")


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    # Count healthy services
    healthy_count = sum(1 for s in service_health.values() if s.get("status") == "healthy")
    total_count = len(SERVICE_REGISTRY)

    return {
        "status": "healthy" if healthy_count == total_count else "degraded",
        "service": "monitoring-metrics",
        "timestamp": datetime.utcnow().isoformat(),
        "monitored_services": total_count,
        "healthy_services": healthy_count,
        "unhealthy_services": total_count - healthy_count,
        "metrics_types": list(metrics_store.keys()),
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=config.host, port=config.port)
