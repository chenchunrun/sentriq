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
Threat Intel Aggregator Service - Aggregates threat intelligence from multiple sources.

This service queries multiple threat intelligence sources for IOCs:
- VirusTotal (IPs, hashes, URLs)
- Abuse.ch (SSLBL, URLhaus)
- AlienVault OTX
- Custom threat feeds

Aggregates results and provides a consolidated threat score.
"""

import asyncio
import hashlib
import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any, Dict, List, Optional

import aiohttp
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from shared.database import DatabaseManager, close_database, get_database_manager, init_database
from shared.data_loader import get_data_loader
from shared.messaging import MessageConsumer, MessagePublisher
from shared.models import SecurityAlert
from shared.utils import Config, get_logger
from shared.utils.cache import CacheManager, CacheKeys

# Initialize logger
logger = get_logger(__name__)

# Initialize config
config = Config()

# Global variables
db_manager: DatabaseManager = None
publisher: MessagePublisher = None
consumer: MessageConsumer = None
cache_manager: "CacheManager" = None

# Cache TTL configuration
THREAT_INTEL_CACHE_TTL = 86400  # 24 hours for threat intel


# =============================================================================
# Threat Intel Sources Configuration
# =============================================================================


class ThreatIntelSource:
    """Base class for threat intelligence sources."""

    def __init__(self, name: str, enabled: bool = True):
        self.name = name
        self.enabled = enabled

    async def query_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """Query threat intelligence for an IP address."""
        raise NotImplementedError

    async def query_hash(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """Query threat intelligence for a file hash."""
        raise NotImplementedError

    async def query_url(self, url: str) -> Optional[Dict[str, Any]]:
        """Query threat intelligence for a URL."""
        raise NotImplementedError


class VirusTotalSource(ThreatIntelSource):
    """VirusTotal threat intelligence source."""

    def __init__(self, api_key: str):
        super().__init__("VirusTotal")
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/vtapi/v2"
        self.enabled = bool(api_key and api_key != "your_vt_key")

    async def query_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """Query VirusTotal for IP reputation."""
        if not self.enabled:
            return None

        try:
            params = {"ip": ip, "apikey": self.api_key}
            url = f"{self.base_url}/ip-address/report"

            async with aiohttp.ClientSession() as session:
                async with session.get(url, params=params, timeout=10) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self._parse_ip_response(data)
                    else:
                        logger.warning(f"VirusTotal API error: {response.status}")
                        return None

        except asyncio.TimeoutError:
            logger.error(f"VirusTotal timeout for IP {ip}")
            return None
        except Exception as e:
            logger.error(f"VirusTotal query failed for IP {ip}: {e}")
            return None

    async def query_hash(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """Query VirusTotal for file hash."""
        if not self.enabled:
            return None

        try:
            params = {"resource": file_hash, "apikey": self.api_key}
            url = f"{self.base_url}/file/report"

            async with aiohttp.ClientSession() as session:
                async with session.get(url, params=params, timeout=10) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self._parse_hash_response(data)
                    else:
                        logger.warning(f"VirusTotal API error: {response.status}")
                        return None

        except asyncio.TimeoutError:
            logger.error(f"VirusTotal timeout for hash {file_hash}")
            return None
        except Exception as e:
            logger.error(f"VirusTotal query failed for hash {file_hash}: {e}")
            return None

    async def query_url(self, url: str) -> Optional[Dict[str, Any]]:
        """Query VirusTotal for URL."""
        if not self.enabled:
            return None

        try:
            params = {"resource": url, "apikey": self.api_key}
            api_url = f"{self.base_url}/url/report"

            async with aiohttp.ClientSession() as session:
                async with session.get(api_url, params=params, timeout=10) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self._parse_url_response(data)
                    else:
                        logger.warning(f"VirusTotal API error: {response.status}")
                        return None

        except asyncio.TimeoutError:
            logger.error(f"VirusTotal timeout for URL {url}")
            return None
        except Exception as e:
            logger.error(f"VirusTotal query failed for URL {url}: {e}")
            return None

    def _parse_ip_response(self, data: dict) -> Dict[str, Any]:
        """Parse VirusTotal IP response."""
        return {
            "source": "VirusTotal",
            "detected": data.get("detected_urls", []) > 0,
            "positives": len(data.get("detected_urls", [])),
            "country": data.get("country"),
            "as_owner": data.get("as_owner"),
            "response_code": data.get("response_code"),
        }

    def _parse_hash_response(self, data: dict) -> Dict[str, Any]:
        """Parse VirusTotal hash response."""
        return {
            "source": "VirusTotal",
            "detected": data.get("response_code") == 1,
            "positives": data.get("positives", 0),
            "total": data.get("total", 0),
            "scan_date": data.get("scan_date"),
        }

    def _parse_url_response(self, data: dict) -> Dict[str, Any]:
        """Parse VirusTotal URL response."""
        return {
            "source": "VirusTotal",
            "detected": data.get("response_code") == 1,
            "positives": data.get("positives", 0),
            "total": data.get("total", 0),
            "scan_date": data.get("scan_date"),
        }


class AbuseCHSource(ThreatIntelSource):
    """Abuse.ch threat intelligence source."""

    def __init__(self, api_key: str = None):
        super().__init__("Abuse.ch")
        self.api_key = api_key
        self.base_url = "https://urlhaus-api.abuse.ch/v1"
        self.enabled = True  # Abuse.ch has free public API

    async def query_hash(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """Query Abuse.ch for file hash."""
        if not self.enabled:
            return None

        try:
            params = {"sha256_hash": file_hash}
            url = f"{self.base_url}/payload/"

            async with aiohttp.ClientSession() as session:
                async with session.post(url, data=params, timeout=10) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self._parse_hash_response(data)
                    else:
                        return None

        except Exception as e:
            logger.error(f"Abuse.ch query failed for hash {file_hash}: {e}")
            return None

    async def query_url(self, url: str) -> Optional[Dict[str, Any]]:
        """Query Abuse.ch for URL."""
        if not self.enabled:
            return None

        try:
            params = {"url": url}
            api_url = f"{self.base_url}/url/"

            async with aiohttp.ClientSession() as session:
                async with session.post(api_url, data=params, timeout=10) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self._parse_url_response(data)
                    else:
                        return None

        except Exception as e:
            logger.error(f"Abuse.ch query failed for URL {url}: {e}")
            return None

    def _parse_hash_response(self, data: dict) -> Dict[str, Any]:
        """Parse Abuse.ch hash response."""
        if data.get("query_status") == "ok":
            return {
                "source": "Abuse.ch",
                "detected": True,
                "threat_type": data.get("threat_type"),
                "tags": data.get("tags", []),
            }
        return {
            "source": "Abuse.ch",
            "detected": False,
        }

    def _parse_url_response(self, data: dict) -> Dict[str, Any]:
        """Parse Abuse.ch URL response."""
        if data.get("query_status") == "ok":
            return {
                "source": "Abuse.ch",
                "detected": True,
                "threat_type": data.get("threat_type"),
                "url_status": data.get("url_status"),
            }
        return {
            "source": "Abuse.ch",
            "detected": False,
        }


class InternalIOCSource(ThreatIntelSource):
    """Internal IOC database from JSON file."""

    def __init__(self):
        super().__init__("Internal IOC")
        self.enabled = True
        self.data_loader = get_data_loader()

    async def query_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """Query internal IOC database for IP."""
        if not self.enabled:
            return None

        try:
            is_malicious, ioc_data = self.data_loader.is_malicious_ioc(ip)

            if is_malicious and ioc_data.get("ioc_type") == "ip":
                return {
                    "source": "Internal IOC",
                    "detected": True,
                    "threat_type": ioc_data.get("threat_type"),
                    "confidence": ioc_data.get("confidence"),
                    "description": ioc_data.get("description"),
                    "tags": ioc_data.get("tags", []),
                    "first_seen": ioc_data.get("first_seen"),
                    "last_seen": ioc_data.get("last_seen"),
                }

            return {"source": "Internal IOC", "detected": False}

        except Exception as e:
            logger.error(f"Internal IOC query failed for IP {ip}: {e}")
            return None

    async def query_hash(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """Query internal IOC database for file hash."""
        if not self.enabled:
            return None

        try:
            is_malicious, ioc_data = self.data_loader.is_malicious_ioc(file_hash)

            if is_malicious and ioc_data.get("ioc_type") == "hash":
                return {
                    "source": "Internal IOC",
                    "detected": True,
                    "threat_type": ioc_data.get("threat_type"),
                    "confidence": ioc_data.get("confidence"),
                    "description": ioc_data.get("description"),
                    "tags": ioc_data.get("tags", []),
                    "first_seen": ioc_data.get("first_seen"),
                    "last_seen": ioc_data.get("last_seen"),
                }

            return {"source": "Internal IOC", "detected": False}

        except Exception as e:
            logger.error(f"Internal IOC query failed for hash {file_hash}: {e}")
            return None

    async def query_url(self, url: str) -> Optional[Dict[str, Any]]:
        """Query internal IOC database for URL/domain."""
        if not self.enabled:
            return None

        try:
            # Try exact URL match first
            is_malicious, ioc_data = self.data_loader.is_malicious_ioc(url)

            if is_malicious and ioc_data.get("ioc_type") in ["url", "domain"]:
                return {
                    "source": "Internal IOC",
                    "detected": True,
                    "threat_type": ioc_data.get("threat_type"),
                    "confidence": ioc_data.get("confidence"),
                    "description": ioc_data.get("description"),
                    "tags": ioc_data.get("tags", []),
                    "first_seen": ioc_data.get("first_seen"),
                    "last_seen": ioc_data.get("last_seen"),
                }

            # Try domain extraction
            from urllib.parse import urlparse
            try:
                parsed = urlparse(url)
                domain = parsed.netloc

                if domain:
                    is_malicious, ioc_data = self.data_loader.is_malicious_ioc(domain)

                    if is_malicious and ioc_data.get("ioc_type") == "domain":
                        return {
                            "source": "Internal IOC",
                            "detected": True,
                            "threat_type": ioc_data.get("threat_type"),
                            "confidence": ioc_data.get("confidence"),
                            "description": ioc_data.get("description"),
                            "tags": ioc_data.get("tags", []),
                            "first_seen": ioc_data.get("first_seen"),
                            "last_seen": ioc_data.get("last_seen"),
                        }
            except Exception:
                pass

            return {"source": "Internal IOC", "detected": False}

        except Exception as e:
            logger.error(f"Internal IOC query failed for URL {url}: {e}")
            return None

    async def query_email(self, email: str) -> Optional[Dict[str, Any]]:
        """Query internal IOC database for email address."""
        if not self.enabled:
            return None

        try:
            is_malicious, ioc_data = self.data_loader.is_malicious_ioc(email)

            if is_malicious and ioc_data.get("ioc_type") == "email":
                return {
                    "source": "Internal IOC",
                    "detected": True,
                    "threat_type": ioc_data.get("threat_type"),
                    "confidence": ioc_data.get("confidence"),
                    "description": ioc_data.get("description"),
                    "tags": ioc_data.get("tags", []),
                    "first_seen": ioc_data.get("first_seen"),
                    "last_seen": ioc_data.get("last_seen"),
                }

            return {"source": "Internal IOC", "detected": False}

        except Exception as e:
            logger.error(f"Internal IOC query failed for email {email}: {e}")
            return None


class CustomThreatFeed(ThreatIntelSource):
    """Custom threat intelligence feed (internal blocklist)."""

    def __init__(self):
        super().__init__("CustomFeed")
        self.enabled = True

        # Internal blocklist (example data)
        self.blocklist_ips = set()
        self.blocklist_hashes = set()
        self.blocklist_urls = set()

    async def query_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """Query internal IP blocklist."""
        if not self.enabled or ip not in self.blocklist_ips:
            return None

        return {
            "source": "CustomFeed",
            "detected": True,
            "list_type": "blocked",
        }

    async def query_hash(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """Query internal hash blocklist."""
        if not self.enabled or file_hash not in self.blocklist_hashes:
            return None

        return {
            "source": "CustomFeed",
            "detected": True,
            "list_type": "blocked",
        }

    async def query_url(self, url: str) -> Optional[Dict[str, Any]]:
        """Query internal URL blocklist."""
        if not self.enabled or url not in self.blocklist_urls:
            return None

        return {
            "source": "CustomFeed",
            "detected": True,
            "list_type": "blocked",
        }


# Mock source to avoid third-party calls in dev/test
class MockThreatIntelSource(ThreatIntelSource):
    """Deterministic mock threat intel source."""

    def __init__(self):
        super().__init__("MockThreatIntel")

    async def query_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        detected = ip.startswith(("45.", "203.0.113.", "198.51.100."))
        return {
            "source": "MockThreatIntel",
            "detected": detected,
            "positives": 1 if detected else 0,
            "confidence": 0.7 if detected else 0.2,
            "_mock": True,
        }

    async def query_hash(self, file_hash: str) -> Optional[Dict[str, Any]]:
        detected = file_hash.lower().startswith(("5e88", "e3b0", "d41d8"))
        return {
            "source": "MockThreatIntel",
            "detected": detected,
            "positives": 1 if detected else 0,
            "confidence": 0.7 if detected else 0.2,
            "_mock": True,
        }

    async def query_url(self, url: str) -> Optional[Dict[str, Any]]:
        detected = "malicious" in url or "phish" in url
        return {
            "source": "MockThreatIntel",
            "detected": detected,
            "positives": 1 if detected else 0,
            "confidence": 0.7 if detected else 0.2,
            "_mock": True,
        }


# Initialize threat intel sources
threat_sources: List[ThreatIntelSource] = []


def init_threat_sources():
    """Initialize threat intelligence sources from config."""
    global threat_sources
    threat_sources = []

    mock_mode = os.getenv("THREAT_INTEL_MOCK_MODE", "true").lower() == "true"
    if mock_mode:
        threat_sources.append(MockThreatIntelSource())
        threat_sources.append(InternalIOCSource())
        threat_sources.append(CustomThreatFeed())
        logger.info("Threat intel mock mode enabled (external APIs disabled)")
        logger.info(f"Initialized {len(threat_sources)} threat intel sources")
        return

    # VirusTotal (requires API key)
    vt_api_key = os.getenv("VIRUSTOTAL_API_KEY", "your_vt_key")
    threat_sources.append(VirusTotalSource(vt_api_key))

    # Internal IOC database (JSON file)
    threat_sources.append(InternalIOCSource())

    # Abuse.ch (free public API)
    threat_sources.append(AbuseCHSource())

    # Custom internal feed
    threat_sources.append(CustomThreatFeed())

    logger.info(f"Initialized {len(threat_sources)} threat intel sources")


# =============================================================================
# Threat Intelligence Query Functions
# =============================================================================


async def query_threat_intel(
    ip: str = None, file_hash: str = None, url: str = None
) -> Dict[str, Any]:
    """
    Query multiple threat intelligence sources.

    Args:
        ip: IP address to query
        file_hash: File hash to query
        url: URL to query

    Returns:
        Aggregated threat intelligence
    """
    results = {
        "sources_queried": 0,
        "sources_found": 0,
        "threat_score": 0.0,  # 0-100, higher is more malicious
        "indicators": [],
    }

    # Query all sources for the given IOC
    tasks = []

    if ip:
        for source in threat_sources:
            if source.enabled:
                tasks.append(source.query_ip(ip))

    if file_hash:
        for source in threat_sources:
            if source.enabled:
                tasks.append(source.query_hash(file_hash))

    if url:
        for source in threat_sources:
            if source.enabled:
                tasks.append(source.query_url(url))

    # Execute queries concurrently
    responses = await asyncio.gather(*tasks, return_exceptions=True)

    # Process responses
    for response in responses:
        if isinstance(response, Exception):
            logger.error(f"Threat intel query error: {response}")
            continue

        if response:
            results["sources_queried"] += 1
            results["indicators"].append(response)

            if response.get("detected"):
                results["sources_found"] += 1

    # Calculate threat score
    if results["sources_queried"] > 0:
        detected_ratio = results["sources_found"] / results["sources_queried"]
        results["threat_score"] = detected_ratio * 100

    return results


# =============================================================================
# Alert Enrichment with Threat Intel
# =============================================================================


async def enrich_with_threat_intel(alert: SecurityAlert) -> Dict[str, Any]:
    """
    Enrich alert with threat intelligence.

    Args:
        alert: SecurityAlert object

    Returns:
        Threat intelligence enrichment
    """
    enrichment = {
        "alert_id": alert.alert_id,
        "enriched_at": datetime.utcnow().isoformat(),
        "threat_intel": {},
    }

    # Query IPs
    if alert.source_ip:
        cache_key = CacheKeys.build(CacheKeys.THREAT_INTEL, ioc_type="ip", ioc_value=alert.source_ip)
        cached = await check_cache(cache_key)
        if cached:
            enrichment["threat_intel"]["source_ip"] = cached
        else:
            result = await query_threat_intel(ip=alert.source_ip)
            await set_cache(cache_key, result)
            enrichment["threat_intel"]["source_ip"] = result

    if alert.target_ip:
        cache_key = CacheKeys.build(CacheKeys.THREAT_INTEL, ioc_type="ip", ioc_value=alert.target_ip)
        cached = await check_cache(cache_key)
        if cached:
            enrichment["threat_intel"]["target_ip"] = cached
        else:
            result = await query_threat_intel(ip=alert.target_ip)
            await set_cache(cache_key, result)
            enrichment["threat_intel"]["target_ip"] = result

    # Query file hash
    if alert.file_hash:
        cache_key = CacheKeys.build(CacheKeys.THREAT_INTEL, ioc_type="hash", ioc_value=alert.file_hash)
        cached = await check_cache(cache_key)
        if cached:
            enrichment["threat_intel"]["file_hash"] = cached
        else:
            result = await query_threat_intel(file_hash=alert.file_hash)
            await set_cache(cache_key, result)
            enrichment["threat_intel"]["file_hash"] = result

    # Query URL
    if alert.url:
        url_hash = hashlib.md5(alert.url.encode()).hexdigest()
        cache_key = CacheKeys.build(CacheKeys.THREAT_INTEL, ioc_type="url", ioc_value=url_hash)
        cached = await check_cache(cache_key)
        if cached:
            enrichment["threat_intel"]["url"] = cached
        else:
            result = await query_threat_intel(url=alert.url)
            await set_cache(cache_key, result)
            enrichment["threat_intel"]["url"] = result

    return enrichment


async def check_cache(key: str) -> Optional[Dict[str, Any]]:
    """Check if data exists in Redis cache."""
    if cache_manager:
        return await cache_manager.get(key)
    return None


async def set_cache(key: str, data: Dict[str, Any], ttl: int = THREAT_INTEL_CACHE_TTL):
    """Store data in Redis cache with TTL."""
    if cache_manager:
        await cache_manager.set(key, data, ttl)


# =============================================================================
# FastAPI Application
# =============================================================================


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    global db_manager, publisher, consumer, cache_manager

    logger.info("Starting Threat Intel Aggregator Service")

    try:
        # Initialize Redis cache manager
        redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
        cache_manager = CacheManager(redis_url)
        await cache_manager.connect()
        logger.info("✓ Redis cache connected")

        # Initialize threat intel sources
        init_threat_sources()

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
        consumer = MessageConsumer(config.rabbitmq_url, "alert.enriched")
        await consumer.connect()
        logger.info("✓ Message consumer connected")

        # Start message consumer task
        asyncio.create_task(consume_alerts())
        logger.info("✓ Message consumer task started")

        logger.info("✓ Threat Intel Aggregator Service started successfully")

        yield

    except Exception as e:
        logger.error(f"Failed to start service: {e}")
        raise

    finally:
        logger.info("Shutting down Threat Intel Aggregator Service")

        if consumer:
            await consumer.close()
            logger.info("✓ Message consumer closed")

        if publisher:
            await publisher.close()
            logger.info("✓ Message publisher closed")

        if cache_manager:
            await cache_manager.close()
            logger.info("✓ Redis cache closed")

        # Close database using the close_database function
        await close_database()
        logger.info("✓ Database connection closed")

        logger.info("✓ Threat Intel Aggregator Service stopped")


# Create FastAPI app
app = FastAPI(
    title="Threat Intel Aggregator API",
    description="Aggregates threat intelligence from multiple sources",
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


async def persist_threat_intel_to_db(alert: SecurityAlert, enrichment: Dict[str, Any]):
    """
    Persist threat intelligence to database.

    Args:
        alert: SecurityAlert object
        enrichment: Threat intelligence enrichment
    """
    import json
    try:
        threat_data = enrichment.get("threat_intel", {})

        async with db_manager.get_session() as session:
            # Save source IP threat intel
            if alert.source_ip and "source_ip" in threat_data:
                ip_data = threat_data["source_ip"]
                if isinstance(ip_data, dict) and ip_data.get("reputation"):
                    await session.execute(
                        text("""
                            INSERT INTO threat_intel (ioc, ioc_type, threat_level, confidence_score,
                                                      source, description, first_seen, last_seen,
                                                      detection_rate, positives, total, raw_data)
                            VALUES (:ioc, :ioc_type, :threat_level, :confidence_score,
                                    :source, :description, :first_seen, :last_seen,
                                    :detection_rate, :positives, :total, :raw_data::jsonb)
                            ON CONFLICT (ioc, ioc_type) DO UPDATE SET
                                threat_level = EXCLUDED.threat_level,
                                confidence_score = EXCLUDED.confidence_score,
                                last_seen = EXCLUDED.last_seen,
                                detection_rate = EXCLUDED.detection_rate,
                                updated_at = NOW()
                        """),
                        {
                            "ioc": alert.source_ip,
                            "ioc_type": "ip",
                            "threat_level": ip_data.get("threat_level", "low"),
                            "confidence_score": ip_data.get("confidence", 0.5),
                            "source": ip_data.get("source", "threat-intel-aggregator"),
                            "description": ip_data.get("reputation", "Unknown"),
                            "first_seen": ip_data.get("first_seen"),
                            "last_seen": ip_data.get("last_seen", datetime.utcnow()),
                            "detection_rate": ip_data.get("detection_rate"),
                            "positives": ip_data.get("positives"),
                            "total": ip_data.get("total"),
                            "raw_data": json.dumps(ip_data),
                        }
                    )

            # Save file hash threat intel
            if alert.file_hash and "file_hash" in threat_data:
                hash_data = threat_data["file_hash"]
                if isinstance(hash_data, dict):
                    await session.execute(
                        text("""
                            INSERT INTO threat_intel (ioc, ioc_type, threat_level, confidence_score,
                                                      source, description, detection_rate, positives, total, raw_data)
                            VALUES (:ioc, :ioc_type, :threat_level, :confidence_score,
                                    :source, :description, :detection_rate, :positives, :total, :raw_data::jsonb)
                            ON CONFLICT (ioc, ioc_type) DO UPDATE SET
                                threat_level = EXCLUDED.threat_level,
                                confidence_score = EXCLUDED.confidence_score,
                                detection_rate = EXCLUDED.detection_rate,
                                updated_at = NOW()
                        """),
                        {
                            "ioc": alert.file_hash,
                            "ioc_type": "hash",
                            "threat_level": hash_data.get("threat_level", "low"),
                            "confidence_score": hash_data.get("confidence", 0.5),
                            "source": hash_data.get("source", "threat-intel-aggregator"),
                            "description": hash_data.get("classification", "Unknown"),
                            "detection_rate": hash_data.get("detection_rate"),
                            "positives": hash_data.get("positives"),
                            "total": hash_data.get("total"),
                            "raw_data": json.dumps(hash_data),
                        }
                    )

            # Save URL threat intel
            if alert.url and "url" in threat_data:
                url_data = threat_data["url"]
                if isinstance(url_data, dict):
                    await session.execute(
                        text("""
                            INSERT INTO threat_intel (ioc, ioc_type, threat_level, confidence_score,
                                                      source, description, detection_rate, positives, total, raw_data)
                            VALUES (:ioc, :ioc_type, :threat_level, :confidence_score,
                                    :source, :description, :detection_rate, :positives, :total, :raw_data::jsonb)
                            ON CONFLICT (ioc, ioc_type) DO UPDATE SET
                                threat_level = EXCLUDED.threat_level,
                                confidence_score = EXCLUDED.confidence_score,
                                detection_rate = EXCLUDED.detection_rate,
                                updated_at = NOW()
                        """),
                        {
                            "ioc": alert.url,
                            "ioc_type": "url",
                            "threat_level": url_data.get("threat_level", "low"),
                            "confidence_score": url_data.get("confidence", 0.5),
                            "source": url_data.get("source", "threat-intel-aggregator"),
                            "description": url_data.get("classification", "Unknown"),
                            "detection_rate": url_data.get("detection_rate"),
                            "positives": url_data.get("positives"),
                            "total": url_data.get("total"),
                            "raw_data": json.dumps(url_data),
                        }
                    )

            # Persist aggregated threat intel as alert context
            if threat_data:
                await session.execute(
                    text(
                        "DELETE FROM alert_context WHERE alert_id = :alert_id AND context_type = :context_type"
                    ),
                    {"alert_id": alert.alert_id, "context_type": "threat_intel"},
                )
                await session.execute(
                    text(
                        """
                        INSERT INTO alert_context (alert_id, context_type, context_data, source, confidence_score)
                        VALUES (:alert_id, :context_type, :context_data::jsonb, :source, :confidence_score)
                        """
                    ),
                    {
                        "alert_id": alert.alert_id,
                        "context_type": "threat_intel",
                        "context_data": json.dumps(threat_data),
                        "source": "threat-intel-aggregator",
                        "confidence_score": 0.8,
                    },
                )

            await session.execute(
                text(
                    """
                    UPDATE alerts
                    SET status = :status, updated_at = NOW()
                    WHERE alert_id = :alert_id
                    """
                ),
                {"alert_id": alert.alert_id, "status": "analyzing"},
            )
            await session.commit()
            logger.debug(f"Threat intel persisted for alert {alert.alert_id}")

    except Exception as e:
        logger.error(f"Failed to persist threat intel: {e}", exc_info=True)


async def consume_alerts():
    """Consume enriched alerts and add threat intelligence."""

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

            logger.info(f"Processing message {message_id}")

            # Extract alert from payload
            alert_data = payload.get("alert")
            existing_enrichment = payload.get("enrichment", {})

            if not alert_data:
                logger.warning("No alert data in message")
                return

            alert = SecurityAlert(**alert_data)

            # Enrich with threat intel
            threat_enrichment = await enrich_with_threat_intel(alert)

            # Persist threat intel to database
            await persist_threat_intel_to_db(alert, threat_enrichment)

            # Merge with existing enrichment
            existing_enrichment.update(threat_enrichment)

            # Create updated enriched message
            enriched_message = {
                "message_id": str(uuid.uuid4()),
                "message_type": "alert.enriched_with_ti",
                "correlation_id": alert.alert_id,
                "original_message_id": message_id,
                "timestamp": datetime.utcnow().isoformat(),
                "version": "1.0",
                "payload": {
                    "alert": alert.model_dump(),
                    "enrichment": existing_enrichment,
                },
            }

            # Publish enriched alert (with threat intel)
            await publisher.publish("alert.enriched", enriched_message)

            logger.info(f"Alert enriched with threat intel (message_id: {message_id}, alert_id: {alert.alert_id})")

        except Exception as e:
            logger.error(f"Threat intel enrichment failed: {e}", exc_info=True)
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
        enabled_sources = [s.name for s in threat_sources if s.enabled]
        cache_healthy = cache_manager is not None

        return {
            "status": "healthy",
            "service": "threat-intel-aggregator",
            "timestamp": datetime.utcnow().isoformat(),
            "checks": {
                "database": "connected" if db_manager else "disconnected",
                "redis_cache": "connected" if cache_healthy else "disconnected",
                "message_queue_consumer": "connected" if consumer else "disconnected",
                "message_queue_publisher": "connected" if publisher else "disconnected",
                "threat_intel_sources": enabled_sources,
            },
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return {
            "status": "unhealthy",
            "service": "threat-intel-aggregator",
            "error": str(e),
        }


@app.get("/metrics", tags=["Metrics"])
async def get_metrics():
    """Get threat intel metrics."""
    return {
        "cache_type": "redis",
        "cache_ttl_seconds": THREAT_INTEL_CACHE_TTL,
        "sources_enabled": len([s for s in threat_sources if s.enabled]),
        "service": "threat-intel-aggregator",
    }


@app.post("/api/v1/query", tags=["Query"])
async def manual_query(
    ip: str = None,
    file_hash: str = None,
    url: str = None,
):
    """
    Manually query threat intelligence (for testing).

    Args:
        ip: IP address to query
        file_hash: File hash to query
        url: URL to query

    Returns:
        Threat intelligence results
    """
    try:
        if not any([ip, file_hash, url]):
            return {
                "success": False,
                "error": "Must provide at least one of: ip, file_hash, url",
            }

        result = await query_threat_intel(ip=ip, file_hash=file_hash, url=url)
        return {
            "success": True,
            "data": result,
        }
    except Exception as e:
        logger.error(f"Manual query failed: {e}")
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
