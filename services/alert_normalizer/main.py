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
Alert Normalizer Service - Normalizes alerts from different sources.

This service consumes raw alerts from the message queue, normalizes them
to a standard format, extracts IOCs, and publishes normalized alerts.
"""

import asyncio
import hashlib
import json
import os
import re
import uuid
from collections import defaultdict
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from shared.database import DatabaseManager, close_database, get_database_manager, init_database
from shared.messaging import BatchConsumer, MessageConsumer, MessagePublisher
from shared.models import (
    AlertType,
    ResponseMeta,
    SecurityAlert,
    Severity,
    SuccessResponse,
)
from shared.utils import Config, get_logger, utc_now, utc_now_iso

# Import processors
from services.alert_normalizer.processors import (
    CEFProcessor,
    QRadarProcessor,
    SplunkProcessor,
)

# Initialize logger
logger = get_logger(__name__)

# Initialize config
config = Config()

# Global variables
db_manager: DatabaseManager = None
publisher: MessagePublisher = None
consumer: MessageConsumer = None

# Processors for different SIEM formats
PROCESSORS = {
    "splunk": SplunkProcessor(),
    "qradar": QRadarProcessor(),
    "cef": CEFProcessor(),
    "default": SplunkProcessor(),  # Fallback
}

# Deduplication cache (in-memory, use Redis in production)
processed_alerts_cache: Set[str] = set()
CACHE_MAX_SIZE = 10000

# Aggregation settings
AGGREGATION_WINDOW = timedelta(seconds=30)
AGGREGATION_MAX_SIZE = 100


# =============================================================================
# Field Mapping Functions
# =============================================================================

# Field mappings for different alert sources
FIELD_MAPPINGS = {
    # Splunk format
    "splunk": {
        "alert_id": ["result_id", "alert_id", "id"],
        "timestamp": ["_time", "timestamp", "time"],
        "alert_type": ["category", "alert_type", "type"],
        "severity": ["severity", "priority", "level"],
        "description": ["message", "description", "title"],
        "source_ip": ["src_ip", "source_ip", "src"],
        "target_ip": ["dest_ip", "destination_ip", "dest", "dst_ip"],
        "file_hash": ["file_hash", "hash", "md5", "sha256"],
        "url": ["url", "uri", "domain"],
        "asset_id": ["asset", "host", "hostname"],
        "user_id": ["user", "username", "account"],
    },
    # QRadar format
    "qradar": {
        "alert_id": ["alert_id", "id"],
        "timestamp": ["start_time", "timestamp"],
        "alert_type": ["alert_type", "category"],
        "severity": ["severity", "magnitude"],
        "description": ["description", "rule_name"],
        "source_ip": ["source_ip", "src_address"],
        "target_ip": ["destination_ip", "dest_address"],
        "asset_id": ["asset_id", "host_name"],
    },
    # Default/generic format
    "default": {
        "alert_id": ["alert_id", "id"],
        "timestamp": ["timestamp", "time", "date"],
        "alert_type": ["alert_type", "type", "category"],
        "severity": ["severity", "level", "priority"],
        "description": ["description", "message", "title"],
        "source_ip": ["source_ip", "src", "src_ip"],
        "target_ip": ["target_ip", "dest", "dst_ip", "destination_ip"],
        "file_hash": ["file_hash", "hash"],
        "url": ["url"],
        "asset_id": ["asset_id", "asset", "host"],
        "user_id": ["user_id", "user", "username"],
    },
}


def map_field(raw_alert: dict, source_type: str, target_field: str) -> Any:
    """
    Map a field from raw alert to standard format.

    Args:
        raw_alert: Raw alert dictionary
        source_type: Source system type (splunk, qradar, default)
        target_field: Target field name in standard format

    Returns:
        Mapped field value or None
    """
    mappings = FIELD_MAPPINGS.get(source_type, FIELD_MAPPINGS["default"])
    possible_fields = mappings.get(target_field, [target_field])

    for field in possible_fields:
        if field in raw_alert and raw_alert[field] is not None:
            return raw_alert[field]

    return None


# =============================================================================
# IOC Extraction Functions
# =============================================================================


def extract_iocs(raw_alert: dict) -> Dict[str, List[str]]:
    """
    Extract Indicators of Compromise (IOCs) from alert.

    Args:
        raw_alert: Raw alert data

    Returns:
        Dictionary of IOC type to list of values
    """
    iocs = {
        "ip_addresses": [],
        "file_hashes": [],
        "urls": [],
        "domains": [],
        "email_addresses": [],
    }

    # Convert to text for scanning
    alert_text = str(raw_alert)

    # Extract IP addresses
    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    ip_matches = re.findall(ip_pattern, alert_text)
    for ip in ip_matches:
        # Validate IP range
        parts = ip.split(".")
        if all(0 <= int(part) <= 255 for part in parts):
            iocs["ip_addresses"].append(ip)

    # Extract file hashes (MD5, SHA1, SHA256)
    md5_pattern = r"\b[a-fA-F0-9]{32}\b"
    sha1_pattern = r"\b[a-fA-F0-9]{40}\b"
    sha256_pattern = r"\b[a-fA-F0-9]{64}\b"

    if re.search(md5_pattern, alert_text):
        iocs["file_hashes"].extend(re.findall(md5_pattern, alert_text))
    if re.search(sha1_pattern, alert_text):
        iocs["file_hashes"].extend(re.findall(sha1_pattern, alert_text))
    if re.search(sha256_pattern, alert_text):
        iocs["file_hashes"].extend(re.findall(sha256_pattern, alert_text))

    # Remove duplicates
    for key in iocs:
        iocs[key] = list(set(iocs[key]))

    return iocs


# =============================================================================
# Alert Deduplication
# =============================================================================


def generate_alert_fingerprint(alert: dict) -> str:
    """
    Generate fingerprint for alert deduplication.

    Args:
        alert: Alert data

    Returns:
        SHA256 hash fingerprint
    """
    # Key fields for deduplication
    key_fields = [
        alert.get("alert_type", ""),
        alert.get("source_ip", ""),
        alert.get("target_ip", ""),
        alert.get("file_hash", ""),
        alert.get("url", ""),
        alert.get("asset_id", ""),
        alert.get("user_id", ""),
    ]

    # Create fingerprint string
    fingerprint_str = "|".join(str(f) for f in key_fields if f)

    # Generate hash
    return hashlib.sha256(fingerprint_str.encode()).hexdigest()


def is_duplicate_alert(alert: dict) -> bool:
    """
    Check if alert is a duplicate.

    Args:
        alert: Alert data

    Returns:
        True if duplicate, False otherwise
    """
    fingerprint = generate_alert_fingerprint(alert)

    if fingerprint in processed_alerts_cache:
        logger.debug(f"Duplicate alert detected: {fingerprint[:16]}")
        return True

    # Add to cache
    processed_alerts_cache.add(fingerprint)

    # Manage cache size
    if len(processed_alerts_cache) > CACHE_MAX_SIZE:
        # Remove oldest entries (simplified: clear half the cache)
        processed_alerts_cache.clear()

    return False


# =============================================================================
# Alert Normalization
# =============================================================================


def normalize_alert(raw_alert: dict, source_type: str = "default") -> SecurityAlert:
    """
    Normalize alert from source system to standard format using dedicated processors.

    Args:
        raw_alert: Raw alert data
        source_type: Source system type (splunk, qradar, cef, default)

    Returns:
        Normalized SecurityAlert

    Raises:
        ValueError: If validation fails or processor not found
    """
    try:
        # Get appropriate processor
        processor = PROCESSORS.get(source_type.lower(), PROCESSORS["default"])

        # Use processor to normalize alert
        normalized_alert = processor.process(raw_alert)

        # Add source type to normalized data
        if not normalized_alert.normalized_data:
            normalized_alert.normalized_data = {}

        normalized_alert.normalized_data["source_type"] = source_type
        normalized_alert.normalized_data["normalized_at"] = utc_now_iso()

        logger.debug(f"Alert normalized successfully (alert_id: {normalized_alert.alert_id}, source_type: {source_type}, processor: {processor.__class__.__name__}, alert_type: {normalized_alert.alert_type.value})")

        return normalized_alert

    except Exception as e:
        logger.error(f"Failed to normalize alert: {e}", exc_info=True)
        raise ValueError(f"Alert normalization failed: {str(e)}")


# =============================================================================
# FastAPI Application
# =============================================================================


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    global db_manager, publisher, consumer

    logger.info("Starting Alert Normalizer Service")

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
        consumer = MessageConsumer(config.rabbitmq_url, "alert.raw")
        await consumer.connect()
        logger.info("✓ Message consumer connected")

        # Start message consumer task
        asyncio.create_task(consume_alerts())
        logger.info("✓ Message consumer task started")

        logger.info("✓ Alert Normalizer Service started successfully")

        yield

    except Exception as e:
        logger.error(f"Failed to start service: {e}")
        raise

    finally:
        logger.info("Shutting down Alert Normalizer Service")

        if consumer:
            await consumer.close()
            logger.info("✓ Message consumer closed")

        if publisher:
            await publisher.close()
            logger.info("✓ Message publisher closed")

        # Close database using the close_database function
        await close_database()
        logger.info("✓ Database connection closed")

        logger.info("✓ Alert Normalizer Service stopped")


# Create FastAPI app
app = FastAPI(
    title="Alert Normalizer API",
    description="Normalizes security alerts from different sources",
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
# Alert Aggregation
# =============================================================================


class AlertAggregator:
    """
    Aggregate similar alerts within a time window.

    Reduces noise by combining similar alerts that occur within
    a short time period.
    """

    def __init__(self, window_seconds: int = 30, max_batch_size: int = 100):
        """
        Initialize aggregator.

        Args:
            window_seconds: Time window for aggregation (default 30s)
            max_batch_size: Maximum batch size before forced publishing
        """
        self.window = timedelta(seconds=window_seconds)
        self.max_batch_size = max_batch_size
        self.batches: Dict[str, List[SecurityAlert]] = {}
        self.batch_timestamps: Dict[str, datetime] = {}

    def _get_batch_key(self, alert: SecurityAlert) -> str:
        """
        Generate batch key for alert aggregation.

        Alerts with the same key will be aggregated together.

        Args:
            alert: SecurityAlert

        Returns:
            Batch key string
        """
        # Key based on alert type, severity, and source/target IPs
        key_parts = [
            alert.alert_type.value,
            alert.severity.value,
            alert.source_ip or "",
            alert.target_ip or "",
            alert.asset_id or "",
        ]

        return "|".join(key_parts)

    def add_alert(self, alert: SecurityAlert) -> Optional[List[SecurityAlert]]:
        """
        Add alert to aggregation batch.

        Args:
            alert: Alert to add

        Returns:
            Batch of alerts if ready to publish, None otherwise
        """
        batch_key = self._get_batch_key(alert)
        current_time = utc_now().replace(tzinfo=None)

        # Initialize batch if needed
        if batch_key not in self.batches:
            self.batches[batch_key] = []
            self.batch_timestamps[batch_key] = current_time

        # Add alert to batch
        self.batches[batch_key].append(alert)

        # Check if batch should be published
        batch_age = current_time - self.batch_timestamps[batch_key]
        batch_size = len(self.batches[batch_key])

        should_publish = (
            batch_size >= self.max_batch_size or
            batch_age >= self.window
        )

        if should_publish:
            batch = self.batches.pop(batch_key, [])
            self.batch_timestamps.pop(batch_key, None)
            return batch

        return None

    def flush_all(self) -> List[List[SecurityAlert]]:
        """
        Flush all pending batches.

        Returns:
            List of all pending batches
        """
        all_batches = []

        for batch_key in list(self.batches.keys()):
            batch = self.batches.pop(batch_key, [])
            self.batch_timestamps.pop(batch_key, None)
            if batch:
                all_batches.append(batch)

        return all_batches

    def get_stats(self) -> Dict[str, Any]:
        """
        Get aggregation statistics.

        Returns:
            Statistics dictionary
        """
        return {
            "active_batches": len(self.batches),
            "total_alerts_buffered": sum(len(batch) for batch in self.batches.values()),
            "window_seconds": self.window.total_seconds(),
            "max_batch_size": self.max_batch_size,
        }


# Global aggregator instance (configurable)
aggregation_window = int(os.getenv("ALERT_AGG_WINDOW_SECONDS", "30"))
aggregation_max_size = int(os.getenv("ALERT_AGG_MAX_SIZE", "100"))
aggregator = AlertAggregator(
    window_seconds=aggregation_window,
    max_batch_size=aggregation_max_size,
)


# =============================================================================
# Background Task: Message Consumer
# =============================================================================


async def consume_alerts():
    """Consume raw alerts from queue and normalize them."""

    async def process_message(message: dict):
        try:
            # Unwrap message envelope if present (publisher wraps with _meta and data)
            if "data" in message and isinstance(message["data"], dict):
                actual_message = message["data"]
                meta = message.get("_meta", {})
                message_id = meta.get("message_id", actual_message.get("message_id", str(uuid.uuid4())))
                payload = actual_message.get("payload", actual_message)
            else:
                payload = message.get("payload", message)
                message_id = message.get("message_id", str(uuid.uuid4()))

            logger.info(f"Processing message {message_id}")

            # Detect source type
            source_type = payload.get("source_type", "default")

            # Check for duplicates
            if is_duplicate_alert(payload):
                logger.info(f"Duplicate alert skipped: {message_id}")
                return

            # Normalize alert using processor
            normalized = normalize_alert(payload, source_type)

            # Add to aggregator
            batch = aggregator.add_alert(normalized)

            # If batch is ready, publish all alerts in batch
            if batch:
                await publish_batch(batch, message_id, source_type)
            else:
                # Publish single alert immediately if not aggregating
                await publish_single_alert(normalized, message_id, source_type)

        except ValueError as e:
            logger.warning(f"Validation error: {e}")
            # Consumer will send to DLQ based on retry policy
        except Exception as e:
            logger.error(f"Normalization failed: {e}", exc_info=True)
            # Consumer will send to DLQ based on retry policy

    # Start consuming
    await consumer.consume(process_message)


async def persist_normalized_alert(
    alert: SecurityAlert,
    original_message_id: str,
    source_type: str,
):
    """
    Persist normalized alert details to database.

    Uses UPSERT to ensure alerts inserted by ingestor are updated.
    """
    normalized_payload = {
        "normalized_data": alert.normalized_data or {},
        "source": source_type,
        "source_ref": original_message_id,
        "normalized_at": utc_now_iso(),
    }

    raw_payload = alert.raw_data if alert.raw_data else {}
    merged_raw = {**raw_payload, **normalized_payload}

    async with db_manager.get_session() as session:
        await session.execute(
            text(
                """
                INSERT INTO alerts (
                    alert_id,
                    received_at,
                    alert_type,
                    severity,
                    description,
                    source_ip,
                    destination_ip,
                    file_hash,
                    url,
                    asset_id,
                    user_name,
                    raw_data,
                    status
                ) VALUES (
                    :alert_id,
                    :received_at,
                    :alert_type,
                    :severity,
                    :description,
                    :source_ip,
                    :destination_ip,
                    :file_hash,
                    :url,
                    :asset_id,
                    :user_name,
                    :raw_data::jsonb,
                    :status
                )
                ON CONFLICT (alert_id) DO UPDATE SET
                    alert_type = EXCLUDED.alert_type,
                    severity = EXCLUDED.severity,
                    description = EXCLUDED.description,
                    source_ip = EXCLUDED.source_ip,
                    destination_ip = EXCLUDED.destination_ip,
                    file_hash = EXCLUDED.file_hash,
                    url = EXCLUDED.url,
                    asset_id = EXCLUDED.asset_id,
                    user_name = EXCLUDED.user_name,
                    status = EXCLUDED.status,
                    raw_data = COALESCE(alerts.raw_data, '{}'::jsonb) || EXCLUDED.raw_data,
                    updated_at = NOW()
                """
            ),
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
                "raw_data": json.dumps(merged_raw),
                "status": "analyzing",
            },
        )


async def publish_single_alert(
    alert: SecurityAlert,
    original_message_id: str,
    source_type: str,
):
    """
    Publish a single normalized alert.

    Args:
        alert: Normalized alert
        original_message_id: Original message ID
        source_type: Source system type
    """
    normalized_message = {
        "message_id": str(uuid.uuid4()),
        "message_type": "alert.normalized",
        "correlation_id": alert.alert_id,
        "original_message_id": original_message_id,
        "timestamp": utc_now_iso(),
        "version": "1.0",
        "source_type": source_type,
        "aggregation_count": 1,
        "payload": alert.model_dump(),
    }

    # Persist normalized alert to database
    await persist_normalized_alert(alert, original_message_id, source_type)

    # Publish with priority based on severity
    priority = {
        Severity.CRITICAL: 10,
        Severity.HIGH: 8,
        Severity.MEDIUM: 5,
        Severity.LOW: 3,
        Severity.INFO: 1,
    }.get(alert.severity, 5)

    await publisher.publish(
        "alert.normalized",
        normalized_message,
        priority=priority,
        persistent=True,
    )

    logger.info(f"Alert normalized and published (message_id: {original_message_id}, alert_id: {alert.alert_id}, source_type: {source_type}, alert_type: {alert.alert_type.value}, severity: {alert.severity.value})")


async def publish_batch(
    alerts: List[SecurityAlert],
    original_message_id: str,
    source_type: str,
):
    """
    Publish a batch of normalized alerts.

    Args:
        alerts: List of normalized alerts
        original_message_id: Original message ID
        source_type: Source system type
    """
    if not alerts:
        return

    # Persist all normalized alerts to database
    for alert in alerts:
        await persist_normalized_alert(alert, original_message_id, source_type)

    # Create aggregated message
    batch_message = {
        "message_id": str(uuid.uuid4()),
        "message_type": "alert.normalized.batch",
        "correlation_id": alerts[0].alert_id,
        "original_message_id": original_message_id,
        "timestamp": utc_now_iso(),
        "version": "1.0",
        "source_type": source_type,
        "aggregation_count": len(alerts),
        "payload": [alert.model_dump() for alert in alerts],
    }

    # Determine priority based on highest severity in batch
    highest_severity = max(
        (alert.severity for alert in alerts),
        key=lambda s: {Severity.CRITICAL: 10, Severity.HIGH: 8, Severity.MEDIUM: 5, Severity.LOW: 3, Severity.INFO: 1}.get(s, 0)
    )

    priority = {
        Severity.CRITICAL: 10,
        Severity.HIGH: 8,
        Severity.MEDIUM: 5,
        Severity.LOW: 3,
        Severity.INFO: 1,
    }.get(highest_severity, 5)

    await publisher.publish(
        "alert.normalized",
        batch_message,
        priority=priority,
        persistent=True,
    )

    logger.info(f"Alert batch normalized and published (message_id: {original_message_id}, batch_size: {len(alerts)}, source_type: {source_type}, highest_severity: {highest_severity.value})")


# =============================================================================
# API Endpoints
# =============================================================================


@app.get("/health", tags=["Health"])
async def health_check():
    """Health check endpoint."""
    try:
        return {
            "status": "healthy",
            "service": "alert-normalizer",
            "timestamp": utc_now_iso(),
            "checks": {
                "database": "connected" if db_manager else "disconnected",
                "message_queue_consumer": "connected" if consumer else "disconnected",
                "message_queue_publisher": "connected" if publisher else "disconnected",
                "cache_size": len(processed_alerts_cache),
            },
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return {
            "status": "unhealthy",
            "service": "alert-normalizer",
            "error": str(e),
        }


@app.get("/metrics", tags=["Metrics"])
async def get_metrics():
    """Get normalization metrics."""
    agg_stats = aggregator.get_stats()

    # Get processor stats
    processor_stats = {}
    for source_type, processor in PROCESSORS.items():
        stats = processor.get_stats()
        processor_stats[source_type] = {
            "processed": stats.get("processed_count", 0),
            "errors": stats.get("error_count", 0),
            "success_rate": stats.get("success_rate", 0.0),
        }

    return {
        "cache": {
            "size": len(processed_alerts_cache),
            "max_size": CACHE_MAX_SIZE,
        },
        "aggregation": agg_stats,
        "processors": processor_stats,
        "service": "alert-normalizer",
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
