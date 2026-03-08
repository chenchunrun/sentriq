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
VirusTotal threat intelligence source.

Queries VirusTotal API for IOC reputation data.
API Documentation: https://developers.virustotal.com/reference
"""

import asyncio
from datetime import timedelta
from typing import Any, Dict, Optional

import aiohttp

from shared.utils.logger import get_logger
from shared.utils.time import utc_now

logger = get_logger(__name__)


class VirusTotalSource:
    """
    VirusTotal threat intelligence source.

    Provides IOC reputation data from VirusTotal's commercial API.
    Supports queries for IPs, file hashes, URLs, and domains.
    """

    def __init__(self, api_key: str, cache_ttl_seconds: int = 86400):
        """
        Initialize VirusTotal source.

        Args:
            api_key: VirusTotal API key
            cache_ttl_seconds: Cache TTL (default 24 hours)
        """
        self.api_key = api_key
        self.enabled = bool(api_key and api_key != "your_vt_key")
        self.base_url = "https://www.virustotal.com/vtapi/v2"
        self.cache_ttl = timedelta(seconds=cache_ttl_seconds)
        self.cache: Dict[str, tuple] = {}

        if self.enabled:
            logger.info("VirusTotal source enabled")
        else:
            logger.warning("VirusTotal source disabled: no API key")

    async def query_ioc(self, ioc: str, ioc_type: str = "auto") -> Optional[Dict[str, Any]]:
        """
        Query threat intelligence for an IOC.

        Args:
            ioc: Indicator of compromise (IP, hash, URL, domain)
            ioc_type: IOC type (ip, hash, url, domain, auto)

        Returns:
            Threat intelligence data or None
        """
        if not self.enabled:
            return self._mock_response(ioc, ioc_type)

        # Detect IOC type if auto
        if ioc_type == "auto":
            ioc_type = self._detect_ioc_type(ioc)

        # Check cache
        cache_key = f"vt:{ioc_type}:{ioc}"
        cached_data = self._get_from_cache(cache_key)
        if cached_data:
            return cached_data

        # Query appropriate endpoint
        try:
            if ioc_type == "ip":
                result = await self._query_ip(ioc)
            elif ioc_type == "hash":
                result = await self._query_hash(ioc)
            elif ioc_type == "url":
                result = await self._query_url(ioc)
            elif ioc_type == "domain":
                result = await self._query_domain(ioc)
            else:
                logger.warning(f"Unsupported IOC type: {ioc_type}")
                return None

            # Cache result
            if result:
                self._put_in_cache(cache_key, result)

            return result

        except Exception as e:
            logger.error(f"VirusTotal query failed for {ioc}: {e}")
            return None

    async def _query_ip(self, ip: str) -> Dict[str, Any]:
        """Query IP reputation."""
        params = {"ip": ip, "apikey": self.api_key}
        url = f"{self.base_url}/ip-address/report"

        async with aiohttp.ClientSession() as session:
            async with session.get(url, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    return self._parse_ip_response(data)
                else:
                    logger.error(f"VirusTotal API error: {response.status}")
                    return None

    async def _query_hash(self, file_hash: str) -> Dict[str, Any]:
        """Query file hash reputation."""
        params = {"resource": file_hash, "apikey": self.api_key}
        url = f"{self.base_url}/file/report"

        async with aiohttp.ClientSession() as session:
            async with session.get(url, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    return self._parse_hash_response(data)
                elif response.status == 404:
                    # File not found in VT database
                    return {
                        "source": "virustotal",
                        "detected": False,
                        "detection_rate": 0,
                        "positives": 0,
                        "total": 0,
                    }
                else:
                    logger.error(f"VirusTotal API error: {response.status}")
                    return None

    async def _query_url(self, url: str) -> Dict[str, Any]:
        """Query URL reputation."""
        params = {"resource": url, "apikey": self.api_key}
        api_url = f"{self.base_url}/url/report"

        async with aiohttp.ClientSession() as session:
            async with session.get(api_url, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    return self._parse_url_response(data)
                else:
                    logger.error(f"VirusTotal API error: {response.status}")
                    return None

    async def _query_domain(self, domain: str) -> Dict[str, Any]:
        """Query domain reputation."""
        params = {"domain": domain, "apikey": self.api_key}
        url = f"{self.base_url}/domain/report"

        async with aiohttp.ClientSession() as session:
            async with session.get(url, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    return self._parse_domain_response(data)
                else:
                    logger.error(f"VirusTotal API error: {response.status}")
                    return None

    def _detect_ioc_type(self, ioc: str) -> str:
        """Detect IOC type from format."""
        if len(ioc) in [32, 40, 64] and all(c in "0123456789abcdefABCDEF" for c in ioc):
            return "hash"
        elif ioc.replace(".", "").replace(":", "").isdigit() and ioc.count(".") >= 3:
            return "ip"
        elif ioc.startswith("http://") or ioc.startswith("https://"):
            return "url"
        else:
            return "domain"

    def _parse_ip_response(self, data: dict) -> Dict[str, Any]:
        """Parse IP address response."""
        return {
            "source": "virustotal",
            "detected": data.get("detected_urls", []) != [],
            "detection_rate": data.get("detected_communicating_percent", 0),
            "positives": len(data.get("detected_urls", [])),
            "total": data.get("undetected_communicating_percent", 0) + len(data.get("detected_urls", [])),
            "country": data.get("country"),
            "as_owner": data.get("as_owner"),
            "responses": data.get("detected_urls", [])[:5],  # Top 5
        }

    def _parse_hash_response(self, data: dict) -> Dict[str, Any]:
        """Parse file hash response."""
        return {
            "source": "virustotal",
            "detected": data.get("positives", 0) > 0,
            "detection_rate": data.get("positives", 0) / data.get("total", 1) if data.get("total") else 0,
            "positives": data.get("positives", 0),
            "total": data.get("total", 0),
            "scan_date": data.get("scan_date"),
            "permalink": data.get("permalink"),
            "scans": data.get("scans", {}),
        }

    def _parse_url_response(self, data: dict) -> Dict[str, Any]:
        """Parse URL response."""
        positives = data.get("positives", 0)
        total = data.get("total", 0)

        return {
            "source": "virustotal",
            "detected": positives > 0,
            "detection_rate": positives / total if total else 0,
            "positives": positives,
            "total": total,
            "scan_date": data.get("scan_date"),
            "permalink": data.get("permalink"),
        }

    def _parse_domain_response(self, data: dict) -> Dict[str, Any]:
        """Parse domain response."""
        return {
            "source": "virustotal",
            "detected": data.get("detected_urls", []) != [],
            "detection_rate": data.get("detected_communicating_percent", 0),
            "positives": len(data.get("detected_urls", [])),
            "total": len(data.get("undetected_urls", [])) + len(data.get("detected_urls", [])),
            "country": data.get("country"),
        }

    def _mock_response(self, ioc: str, ioc_type: str) -> Dict[str, Any]:
        """Return mock response when API is disabled."""
        return {
            "source": "virustotal",
            "detected": False,
            "detection_rate": 0,
            "positives": 0,
            "total": 0,
            "_mock": True,
            "_api_required": "VirusTotal API key",
        }

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
        """Put value in cache with expiry."""
        expiry = utc_now() + self.cache_ttl
        self.cache[key] = (data, expiry)

    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        return {
            "cache_size": len(self.cache),
            "cache_ttl_seconds": int(self.cache_ttl.total_seconds()),
        }
