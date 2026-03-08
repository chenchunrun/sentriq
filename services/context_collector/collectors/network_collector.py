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
Network context collector for enriching alerts with network information.

This module handles collection of network context including:
- GeoIP location data
- IP reputation scores
- Network anomalies
- Subnet information
"""

import ipaddress
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from shared.utils.logger import get_logger
from shared.utils.time import utc_now, utc_now_iso

logger = get_logger(__name__)


class _BatchContextDict(dict):
    """Compatibility wrapper: iterate over values while preserving key lookup."""

    def __iter__(self):
        return iter(self.values())


class NetworkCollector:
    """
    Collector for network-related context.

    Gathers information about IP addresses, geolocation, reputation,
    and network characteristics.
    """

    # Internal network ranges
    INTERNAL_NETWORKS = [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
    ]

    # Known threat intelligence feeds
    THREAT_FEEDS = [
        "abuseipdb",
        "virustotal",
        "alienvault_otx",
        "threatconnect",
    ]

    def __init__(self, cache_ttl_seconds: int = 3600):
        """
        Initialize network collector.

        Args:
            cache_ttl_seconds: Cache time-to-live in seconds (default 1 hour)
        """
        self.cache_ttl = timedelta(seconds=cache_ttl_seconds)
        self.cache: Dict[str, tuple] = {}  # key: (data, expiry_time)
        self.internal_networks = [
            ipaddress.ip_network(net) for net in self.INTERNAL_NETWORKS
        ]

    async def collect_context(self, ip: str) -> Dict[str, Any]:
        """
        Collect comprehensive network context for an IP address.

        Args:
            ip: IP address string

        Returns:
            Dictionary with network context information
        """
        # Validate IP address
        if not self._is_valid_ip(ip):
            logger.warning(f"Invalid IP address: {ip}")
            return self._empty_context(ip)

        # Check cache
        cache_key = f"network:{ip}"
        cached_data = self._get_from_cache(cache_key)
        if cached_data:
            logger.debug(f"Network context cache hit for {ip}")
            return cached_data

        # Build network context
        context = {
            "ip": ip,
            "ip_address": ip,
            "is_internal": self._is_internal_ip(ip),
            "collected_at": utc_now_iso(),
        }

        # Collect geolocation data
        geo_data = await self._query_geolocation(ip)
        context["geolocation"] = geo_data

        # Collect reputation data
        reputation_data = await self._query_reputation(ip)
        context["reputation"] = reputation_data

        # Collect subnet information
        subnet_data = self._get_subnet_info(ip)
        context["subnet"] = subnet_data

        # Collect network anomalies (if any)
        anomalies = await self._detect_anomalies(ip)
        if anomalies:
            context["anomalies"] = anomalies

        # Cache the result
        self._put_in_cache(cache_key, context)

        logger.info(
            f"Network context collected for {ip}",
            extra={
                "ip": ip,
                "has_geo": bool(geo_data),
                "reputation_score": reputation_data.get("score"),
            },
        )

        return context

    def _is_valid_ip(self, ip: str) -> bool:
        """
        Validate IP address format.

        Args:
            ip: IP address string

        Returns:
            True if valid, False otherwise
        """
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def _is_internal_ip(self, ip: str) -> bool:
        """
        Check if IP is internal/private.

        Args:
            ip: IP address string

        Returns:
            True if internal, False otherwise
        """
        try:
            addr = ipaddress.ip_address(ip)
            return any(addr in network for network in self.internal_networks)
        except ValueError:
            return False

    async def _query_geolocation(self, ip: str) -> Dict[str, Any]:
        """
        Query geolocation data for IP address.

        TODO: Replace with real MaxMind GeoIP API call.

        Real implementation should:
        - Use MaxMind GeoIP2 or GeoLite2 database
        - Query via: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
        - Requires: GEOIP_API_KEY or local database file

        Args:
            ip: IP address string

        Returns:
            Geolocation data dictionary
        """
        # Mock implementation for POC
        if self._is_internal_ip(ip):
            return {
                "country": "Internal",
                "country_code": "INT",
                "city": "Internal Network",
                "latitude": None,
                "longitude": None,
                "timezone": None,
            }

        # For external IPs, return mock data
        # In production, query MaxMind API or local database
        return {
            "country": "Unknown",
            "country_code": "XX",
            "city": "Unknown",
            "latitude": None,
            "longitude": None,
            "timezone": None,
            "_mock": True,  # Indicates this is mock data
            "_api_required": "MaxMind GeoIP2",
        }

    async def _query_reputation(self, ip: str) -> Dict[str, Any]:
        """
        Query IP reputation from threat intelligence feeds.

        TODO: Replace with real API calls.

        Real implementation should:
        - Query AbuseIPDB: https://www.abuseipdb.com/api
        - Query VirusTotal: https://www.virustotal.com/vtapi/v2/ip_addresses/report
        - Query AlienVault OTX: https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}

        Args:
            ip: IP address string

        Returns:
            Reputation data dictionary
        """
        # Mock implementation for POC
        if self._is_internal_ip(ip):
            return {
                "score": 0,  # 0 = trusted, 100 = malicious
                "confidence": 1.0,
                "categories": [],
                "reports": 0,
                "last_reported": None,
                "sources": [],
            }

        # For external IPs, return mock data
        # In production, query real threat intelligence APIs
        return {
            "score": 50,  # Unknown/neutral
            "confidence": 0.5,
            "categories": ["unknown"],
            "reports": 0,
            "last_reported": None,
            "sources": [],
            "_mock": True,
            "_apis_required": ["AbuseIPDB", "VirusTotal", "AlienVault OTX"],
        }

    def _get_subnet_info(self, ip: str) -> Dict[str, Any]:
        """
        Get subnet information for IP address.

        Args:
            ip: IP address string

        Returns:
            Subnet information dictionary
        """
        try:
            addr = ipaddress.ip_address(ip)

            # Find matching internal subnet
            for network in self.internal_networks:
                if addr in network:
                    return {
                        "subnet": str(network),
                        "network_address": str(network.network_address),
                        "broadcast_address": str(network.broadcast_address),
                        "prefix_length": network.prefixlen,
                        "num_addresses": network.num_addresses,
                        "is_internal": True,
                    }

            # For external IPs, provide basic info
            return {
                "subnet": None,
                "network_address": None,
                "broadcast_address": None,
                "prefix_length": None,
                "num_addresses": None,
                "is_internal": False,
            }

        except ValueError:
            return {}

    async def _detect_anomalies(self, ip: str) -> List[Dict[str, Any]]:
        """
        Detect network anomalies for IP address.

        TODO: Implement anomaly detection logic.

        Real implementation should:
        - Check for unusual traffic patterns
        - Compare against historical data
        - Query security analytics platform
        - Check for port scanning, DDoS patterns, etc.

        Args:
            ip: IP address string

        Returns:
            List of anomaly dictionaries
        """
        # Mock implementation - no anomalies detected
        return []

    def _get_from_cache(self, key: str) -> Optional[Any]:
        """Get value from cache if not expired."""
        if key in self.cache:
            data, expiry = self.cache[key]
            if utc_now() < expiry:
                return data
            else:
                del self.cache[key]
        return None

    def _put_in_cache(self, key: str, data: Any):
        """Put value in cache with expiry time."""
        expiry = utc_now() + self.cache_ttl
        self.cache[key] = (data, expiry)

    def _empty_context(self, ip: str) -> Dict[str, Any]:
        """Return empty context for invalid IP."""
        return {
            "ip": ip,
            "ip_address": ip,
            "is_internal": False,
            "geolocation": None,
            "reputation": None,
            "subnet": None,
            "anomalies": [],
            "collected_at": utc_now_iso(),
            "error": "Invalid IP address",
        }

    async def collect_batch_context(self, ips: List[str]) -> Dict[str, Dict[str, Any]]:
        """
        Collect network context for multiple IPs in parallel.

        Args:
            ips: List of IP address strings

        Returns:
            Dictionary mapping IP to context data
        """
        import asyncio

        tasks = [self.collect_context(ip) for ip in ips]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        context_map = _BatchContextDict()
        for ip, result in zip(ips, results):
            if isinstance(result, Exception):
                logger.error(f"Error collecting context for {ip}: {result}")
                context_map[ip] = self._empty_context(ip)
            else:
                context_map[ip] = result

        return context_map

    def get_cache_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics.

        Returns:
            Dictionary with cache stats
        """
        return {
            "cache_size": len(self.cache),
            "cache_ttl_seconds": int(self.cache_ttl.total_seconds()),
            "expired_entries": sum(
                1 for _, expiry in self.cache.values()
                if utc_now() >= expiry
            ),
        }

    def clear_cache(self):
        """Clear all cached data."""
        self.cache.clear()
        logger.info("Network context cache cleared")
