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
Context Collector Service - Enriches alerts with context information.

This service consumes normalized alerts and enriches them with:
- Network context (GeoIP, reputation, subnet info)
- Asset context (CMDB data, criticality)
- User context (directory information, roles)
"""

import asyncio
import ipaddress
import os
import re
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any, Dict, Optional

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from shared.database import DatabaseManager, close_database, get_database_manager, init_database
from shared.data_loader import get_data_loader
from shared.messaging import MessageConsumer, MessagePublisher
from shared.models import SecurityAlert
from shared.utils import Config, get_logger

# Initialize logger
logger = get_logger(__name__)

# Initialize config
config = Config()

# Global variables
db_manager: DatabaseManager = None
publisher: MessagePublisher = None
consumer: MessageConsumer = None

# Cache for context data (in-memory, use Redis in production)
context_cache: Dict[str, tuple] = {}  # key: (data, expiry_time)
CACHE_TTL_SECONDS = 3600  # 1 hour


# =============================================================================
# Internal Network Detection
# =============================================================================

INTERNAL_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]


def is_internal_ip(ip_str: str) -> bool:
    """
    Check if IP address is internal/private.

    Args:
        ip_str: IP address string

    Returns:
        True if internal, False otherwise
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in network for network in INTERNAL_NETWORKS)
    except ValueError:
        return False


# =============================================================================
# Network Context Collection
# =============================================================================


async def get_network_context(ip: str) -> Dict[str, Any]:
    """
    Collect network context for an IP address.

    Args:
        ip: IP address string

    Returns:
        Network context dictionary
    """
    # Check cache
    cache_key = f"network:{ip}"
    if cache_key in context_cache:
        data, expiry = context_cache[cache_key]
        if datetime.utcnow().timestamp() < expiry:
            logger.debug(f"Network context cache hit for {ip}")
            return data

    try:
        context = {
            "ip_address": ip,
            "is_internal": is_internal_ip(ip),
            "country": None,
            "city": None,
            "isp": None,
            "reputation_score": 50.0,  # 0-100, higher is better
            "known_malicious": False,
        }

        # Enrich internal IPs
        if context["is_internal"]:
            context.update(
                {
                    "subnet": get_subnet(ip),
                    "network_type": "internal",
                    "country": "Internal",
                    "reputation_score": 80.0,
                }
            )
        else:
            # TODO: Implement external IP enrichment
            # - GeoIP lookup (MaxMind, IPInfo)
            # - WHOIS data
            # - Threat intelligence feeds
            # - Reputation services (AlienVault OTX, CrowdStrike)

            context.update(
                {
                    "network_type": "external",
                    "country": "Unknown",  # Would be from GeoIP
                    "city": None,
                    "isp": None,
                }
            )

        # Cache result
        expiry_time = datetime.utcnow().timestamp() + CACHE_TTL_SECONDS
        context_cache[cache_key] = (context, expiry_time)

        logger.debug(f"Network context collected for {ip} (is_internal: {context['is_internal']})")

        return context

    except Exception as e:
        logger.error(f"Failed to collect network context for {ip}: {e}")
        return {
            "ip_address": ip,
            "is_internal": is_internal_ip(ip),
            "country": None,
            "reputation_score": 50.0,
            "error": str(e),
        }


def get_subnet(ip: str) -> Optional[str]:
    """
    Get subnet for internal IP.

    Args:
        ip: IP address string

    Returns:
        Subnet in CIDR notation or None
    """
    try:
        ip_obj = ipaddress.ip_address(ip)

        # Determine subnet based on IP class
        if ip_obj in ipaddress.ip_network("10.0.0.0/8"):
            # Class A private: /8
            return f"{ip_obj.network_address}/8"
        elif ip_obj in ipaddress.ip_network("172.16.0.0/12"):
            # Class B private: /12
            return f"{ip_obj.network_address}/12"
        elif ip_obj in ipaddress.ip_network("192.168.0.0/16"):
            # Class C private: /24 (typical)
            return f"{'.'.join(ip.split('.')[:3])}.0/24"
        elif ip_obj in ipaddress.ip_network("127.0.0.0/8"):
            return "127.0.0.0/8"

        return None
    except ValueError:
        return None


# =============================================================================
# Asset Context Collection
# =============================================================================


async def get_asset_context(asset_id: str) -> Dict[str, Any]:
    """
    Collect asset context from JSON data store.

    Args:
        asset_id: Asset identifier

    Returns:
        Asset context dictionary
    """
    # Check cache
    cache_key = f"asset:{asset_id}"
    if cache_key in context_cache:
        data, expiry = context_cache[cache_key]
        if datetime.utcnow().timestamp() < expiry:
            logger.debug(f"Asset context cache hit for {asset_id}")
            return data

    try:
        # Load asset data from JSON file
        data_loader = get_data_loader()
        asset = data_loader.get_asset_by_id(asset_id)

        if asset:
            context = {
                "asset_id": asset.get("asset_id"),
                "asset_name": asset.get("asset_name"),
                "asset_type": asset.get("asset_type"),
                "ip_address": asset.get("ip_address"),
                "mac_address": asset.get("mac_address"),
                "os_name": asset.get("os_name"),
                "os_version": asset.get("os_version"),
                "criticality": asset.get("criticality"),
                "owner": asset.get("owner"),
                "location": asset.get("location"),
                "business_unit": asset.get("business_unit"),
                "environment": asset.get("environment"),
                "vulnerabilities": asset.get("vulnerabilities", {}),
                "last_scan": asset.get("last_scan"),
            }
        else:
            # Asset not found, return minimal context
            logger.warning(f"Asset not found: {asset_id}")
            context = {
                "asset_id": asset_id,
                "asset_name": asset_id,
                "criticality": "unknown",
                "error": "Asset not found in database",
            }

        # Cache result
        expiry_time = datetime.utcnow().timestamp() + CACHE_TTL_SECONDS
        context_cache[cache_key] = (context, expiry_time)

        logger.debug(f"Asset context collected for {asset_id}")
        return context

    except Exception as e:
        logger.error(f"Failed to collect asset context for {asset_id}: {e}")
        return {
            "asset_id": asset_id,
            "asset_name": asset_id,
            "criticality": "unknown",
            "error": str(e),
        }


# =============================================================================
# User Context Collection
# =============================================================================


async def get_user_context(user_id: str) -> Dict[str, Any]:
    """
    Collect user context from JSON data store.

    Args:
        user_id: User identifier (username, email, or UPN)

    Returns:
        User context dictionary
    """
    # Check cache
    cache_key = f"user:{user_id}"
    if cache_key in context_cache:
        data, expiry = context_cache[cache_key]
        if datetime.utcnow().timestamp() < expiry:
            logger.debug(f"User context cache hit for {user_id}")
            return data

    try:
        # Load user data from JSON file
        data_loader = get_data_loader()
        user = data_loader.get_user_by_id(user_id)

        if user:
            context = {
                "user_id": user.get("user_id"),
                "username": user.get("username"),
                "email": user.get("email"),
                "full_name": user.get("full_name"),
                "phone": user.get("phone"),
                "department": user.get("department"),
                "role": user.get("role"),
                "access_level": user.get("access_level"),
                "manager": user.get("manager"),
                "location": user.get("location"),
                "is_active": user.get("is_active", True),
                "login_history": user.get("login_history", {}),
                "behavior_profile": user.get("behavior_profile", {}),
            }
        else:
            # User not found, return minimal context
            logger.warning(f"User not found: {user_id}")
            context = {
                "user_id": user_id,
                "username": user_id,
                "access_level": "unknown",
                "error": "User not found in database",
            }

        # Cache result
        expiry_time = datetime.utcnow().timestamp() + CACHE_TTL_SECONDS
        context_cache[cache_key] = (context, expiry_time)

        logger.debug(f"User context collected for {user_id}")
        return context

    except Exception as e:
        logger.error(f"Failed to collect user context for {user_id}: {e}")
        return {
            "user_id": user_id,
            "username": user_id,
            "access_level": "unknown",
            "error": str(e),
        }


# =============================================================================
# Context Enrichment
# =============================================================================


async def enrich_alert(alert: SecurityAlert) -> Dict[str, Any]:
    """
    Enrich alert with context information.

    Args:
        alert: SecurityAlert object

    Returns:
        Enrichment data dictionary
    """
    enrichment = {
        "alert_id": alert.alert_id,
        "enriched_at": datetime.utcnow().isoformat(),
        "enrichment_sources": [],
    }

    logger.info(f"Enriching alert {alert.alert_id}: asset_id={alert.asset_id}, user_id={alert.user_id}, source_ip={alert.source_ip}, target_ip={alert.target_ip}")

    # Collect network context
    if alert.source_ip:
        try:
            source_context = await get_network_context(alert.source_ip)
            enrichment["source_network"] = source_context
            enrichment["enrichment_sources"].append("source_network")
        except Exception as e:
            logger.error(f"Failed to enrich source network: {e}")

    if alert.target_ip:
        try:
            target_context = await get_network_context(alert.target_ip)
            enrichment["target_network"] = target_context
            enrichment["enrichment_sources"].append("target_network")
        except Exception as e:
            logger.error(f"Failed to enrich target network: {e}")

    # Collect asset context
    if alert.asset_id:
        logger.info(f"Collecting asset context for asset_id: {alert.asset_id}")
        try:
            asset_context = await get_asset_context(alert.asset_id)
            enrichment["asset"] = asset_context
            enrichment["enrichment_sources"].append("asset")
            logger.info(f"✓ Asset context added for {alert.asset_id}")
        except Exception as e:
            logger.error(f"Failed to enrich asset: {e}")

    # Collect user context
    if alert.user_id:
        logger.info(f"Collecting user context for user_id: {alert.user_id}")
        try:
            user_context = await get_user_context(alert.user_id)
            enrichment["user"] = user_context
            enrichment["enrichment_sources"].append("user")
            logger.info(f"✓ User context added for {alert.user_id}")
        except Exception as e:
            logger.error(f"Failed to enrich user: {e}")

    return enrichment


# =============================================================================
# Cache Management
# =============================================================================


async def cleanup_cache():
    """
    Periodic cache cleanup task.
    Removes expired entries from cache.
    """
    while True:
        try:
            now = datetime.utcnow().timestamp()
            expired_keys = [key for key, (_, expiry) in context_cache.items() if now >= expiry]

            for key in expired_keys:
                del context_cache[key]

            if expired_keys:
                logger.debug(f"Cleaned up {len(expired_keys)} expired cache entries")

            # Sleep for 5 minutes
            await asyncio.sleep(300)

        except Exception as e:
            logger.error(f"Cache cleanup failed: {e}")
            await asyncio.sleep(60)


# =============================================================================
# FastAPI Application
# =============================================================================


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    global db_manager, publisher, consumer

    logger.info("Starting Context Collector Service")

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
        publisher = MessagePublisher(config.rabbitmq_url)
        await publisher.connect()
        logger.info("✓ Message publisher connected")

        # Initialize message consumer
        consumer = MessageConsumer(config.rabbitmq_url, "alert.normalized")
        await consumer.connect()
        logger.info("✓ Message consumer connected")

        # Start message consumer task
        asyncio.create_task(consume_alerts())
        logger.info("✓ Message consumer task started")

        # Start cache cleanup task
        asyncio.create_task(cleanup_cache())
        logger.info("✓ Cache cleanup task started")

        logger.info("✓ Context Collector Service started successfully")

        yield

    except Exception as e:
        logger.error(f"Failed to start service: {e}")
        raise

    finally:
        logger.info("Shutting down Context Collector Service")

        if consumer:
            await consumer.close()
            logger.info("✓ Message consumer closed")

        if publisher:
            await publisher.close()
            logger.info("✓ Message publisher closed")

        # Close database using the close_database function
        await close_database()
        logger.info("✓ Database connection closed")

        logger.info("✓ Context Collector Service stopped")


# Create FastAPI app
app = FastAPI(
    title="Context Collector API",
    description="Enriches alerts with network, asset, and user context",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =============================================================================
# Background Task: Message Consumer
# =============================================================================


async def persist_context_to_db(alert_id: str, enrichment: Dict[str, Any]):
    """
    Persist context enrichment to database.

    Args:
        alert_id: Alert identifier
        enrichment: Enrichment data dictionary
    """
    import json
    try:
        async with db_manager.get_session() as session:
            # Save network context for source IP
            if "source_network" in enrichment:
                await session.execute(
                    text(
                        "DELETE FROM alert_context WHERE alert_id = :alert_id AND context_type = :context_type"
                    ),
                    {"alert_id": alert_id, "context_type": "network"},
                )
                await session.execute(
                    text("""
                        INSERT INTO alert_context (alert_id, context_type, context_data, source, confidence_score)
                        VALUES (:alert_id, :context_type, :context_data::jsonb, :source, :confidence_score)
                    """),
                    {
                        "alert_id": alert_id,
                        "context_type": "network",
                        "context_data": json.dumps(enrichment["source_network"]),
                        "source": "context-collector",
                        "confidence_score": 0.8,
                    }
                )

            # Save asset context
            if "asset" in enrichment:
                await session.execute(
                    text(
                        "DELETE FROM alert_context WHERE alert_id = :alert_id AND context_type = :context_type"
                    ),
                    {"alert_id": alert_id, "context_type": "asset"},
                )
                await session.execute(
                    text("""
                        INSERT INTO alert_context (alert_id, context_type, context_data, source, confidence_score)
                        VALUES (:alert_id, :context_type, :context_data::jsonb, :source, :confidence_score)
                    """),
                    {
                        "alert_id": alert_id,
                        "context_type": "asset",
                        "context_data": json.dumps(enrichment["asset"]),
                        "source": "context-collector",
                        "confidence_score": 0.9,
                    }
                )

            # Save user context
            if "user" in enrichment:
                await session.execute(
                    text(
                        "DELETE FROM alert_context WHERE alert_id = :alert_id AND context_type = :context_type"
                    ),
                    {"alert_id": alert_id, "context_type": "user"},
                )
                await session.execute(
                    text("""
                        INSERT INTO alert_context (alert_id, context_type, context_data, source, confidence_score)
                        VALUES (:alert_id, :context_type, :context_data::jsonb, :source, :confidence_score)
                    """),
                    {
                        "alert_id": alert_id,
                        "context_type": "user",
                        "context_data": json.dumps(enrichment["user"]),
                        "source": "context-collector",
                        "confidence_score": 0.9,
                    }
                )

            await session.execute(
                text(
                    """
                    UPDATE alerts
                    SET status = :status, updated_at = NOW()
                    WHERE alert_id = :alert_id
                    """
                ),
                {"alert_id": alert_id, "status": "analyzing"},
            )
            await session.commit()
            logger.debug(f"Context persisted for alert {alert_id}")

    except Exception as e:
        logger.error(f"Failed to persist context: {e}", exc_info=True)


async def consume_alerts():
    """Consume normalized alerts and enrich with context."""

    async def process_message(message: dict):
        try:
            # Unwrap message envelope if present (publisher wraps with _meta and data)
            if "data" in message and isinstance(message["data"], dict):
                actual_message = message["data"]
                meta = message.get("_meta", {})
                message_id = meta.get("message_id", message.get("message_id", "unknown"))
            else:
                actual_message = message
                message_id = message.get("message_id", "unknown")

            payload = actual_message.get("payload", actual_message)

            # Handle both single alerts (dict) and batch alerts (list)
            alerts_to_process = []

            if isinstance(payload, list):
                # Batch alerts
                logger.info(f"Processing batch message {message_id} with {len(payload)} alerts")
                alerts_to_process = payload
            elif isinstance(payload, dict):
                # Single alert
                logger.info(f"Processing single alert message {message_id}")
                alerts_to_process = [payload]
            else:
                logger.warning(f"Unexpected payload type: {type(payload)}")
                return

            # Process each alert
            for alert_data in alerts_to_process:
                try:
                    # Parse alert
                    alert = SecurityAlert(**alert_data)

                    # Enrich with context
                    enrichment = await enrich_alert(alert)

                    # Persist context to database
                    await persist_context_to_db(alert.alert_id, enrichment)

                    # Create enriched message
                    enriched_message = {
                        "message_id": str(uuid.uuid4()),
                        "message_type": "alert.enriched",
                        "correlation_id": alert.alert_id,
                        "original_message_id": message_id,
                        "timestamp": datetime.utcnow().isoformat(),
                        "version": "1.0",
                        "payload": {
                            "alert": alert.model_dump(),
                            "enrichment": enrichment,
                        },
                    }

                    # Publish enriched alert
                    await publisher.publish("alert.enriched", enriched_message)

                    logger.info(
                        f"Alert enriched successfully (message_id: {message_id}, alert_id: {alert.alert_id}, sources: {len(enrichment.get('enrichment_sources', []))})"
                    )

                except Exception as e:
                    logger.error(f"Failed to enrich alert {alert_data.get('alert_id', 'unknown')}: {e}", exc_info=True)
                    # Continue with next alert in batch
                    continue

        except Exception as e:
            logger.error(f"Context enrichment failed: {e}", exc_info=True)
            # Re-raise to let consumer handle retries and DLQ
            raise

    # Start consuming
    await consumer.consume(process_message)


# =============================================================================
# API Endpoints
# =============================================================================


@app.get("/health", tags=["Health"])
async def health_check():
    """Health check endpoint."""
    try:
        return {
            "status": "healthy",
            "service": "context-collector",
            "timestamp": datetime.utcnow().isoformat(),
            "checks": {
                "database": "connected" if db_manager else "disconnected",
                "message_queue_consumer": "connected" if consumer else "disconnected",
                "message_queue_publisher": "connected" if publisher else "disconnected",
                "cache_size": len(context_cache),
            },
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return {
            "status": "unhealthy",
            "service": "context-collector",
            "error": str(e),
        }


@app.get("/metrics", tags=["Metrics"])
async def get_metrics():
    """Get enrichment metrics."""
    return {
        "cache_size": len(context_cache),
        "cache_ttl_seconds": CACHE_TTL_SECONDS,
        "service": "context-collector",
    }


@app.post("/api/v1/enrich", tags=["Enrichment"])
async def manual_enrich(alert: SecurityAlert):
    """
    Manually enrich an alert (for testing).

    Args:
        alert: SecurityAlert to enrich

    Returns:
        Enrichment data
    """
    try:
        enrichment = await enrich_alert(alert)
        return {
            "success": True,
            "data": enrichment,
        }
    except Exception as e:
        logger.error(f"Manual enrichment failed: {e}")
        return {
            "success": False,
            "error": str(e),
        }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host=config.host,
        port=config.port,
        reload=config.debug,
        log_level=config.log_level.lower(),
    )
