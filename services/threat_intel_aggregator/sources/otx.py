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
AlienVault OTX threat intelligence source.

Queries AlienVault Open Threat Exchange API for IOC data.
API Documentation: https://otx.alienvault.com/api
"""

import aiohttp
from datetime import timedelta
from typing import Any, Dict, Optional

from shared.utils.logger import get_logger
from shared.utils.time import utc_now

logger = get_logger(__name__)


class OTXSource:
    """AlienVault OTX threat intelligence source."""

    def __init__(self, api_key: str, cache_ttl_seconds: int = 86400):
        """Initialize OTX source."""
        self.api_key = api_key
        self.enabled = bool(api_key and api_key != "your_otx_key")
        self.base_url = "https://otx.alienvault.com/api/v1"
        self.cache_ttl = timedelta(seconds=cache_ttl_seconds)
        self.cache: Dict[str, tuple] = {}

        if self.enabled:
            logger.info("OTX source enabled")
        else:
            logger.warning("OTX source disabled: no API key")

    async def query_ioc(self, ioc: str, ioc_type: str = "auto") -> Optional[Dict[str, Any]]:
        """Query OTX for IOC."""
        if not self.enabled:
            return self._mock_response(ioc)

        # Detect type
        if ioc_type == "auto":
            ioc_type = self._detect_ioc_type(ioc)

        # Check cache
        cache_key = f"otx:{ioc_type}:{ioc}"
        cached = self._get_from_cache(cache_key)
        if cached:
            return cached

        try:
            if ioc_type == "ip":
                result = await self._query_ip(ioc)
            elif ioc_type == "domain":
                result = await self._query_domain(ioc)
            elif ioc_type == "hash":
                result = await self._query_hash(ioc)
            elif ioc_type == "url":
                result = await self._query_url(ioc)
            else:
                return None

            if result:
                self._put_in_cache(cache_key, result)
            return result

        except Exception as e:
            logger.error(f"OTX query failed: {e}")
            return None

    async def _query_ip(self, ip: str) -> Dict[str, Any]:
        """Query IP reputation."""
        headers = {"X-OTX-API-KEY": self.api_key}
        url = f"{self.base_url}/indicators/IPv4/{ip}/"

        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    return self._parse_response(data)
                return None

    async def _query_domain(self, domain: str) -> Dict[str, Any]:
        """Query domain reputation."""
        headers = {"X-OTX-API-KEY": self.api_key}
        url = f"{self.base_url}/indicators/domain/{domain}/"

        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    return self._parse_response(data)
                return None

    async def _query_hash(self, file_hash: str) -> Dict[str, Any]:
        """Query file hash reputation."""
        headers = {"X-OTX-API-KEY": self.api_key}
        url = f"{self.base_url}/indicators/file/{file_hash}/"

        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    return self._parse_response(data)
                return None

    async def _query_url(self, url: str) -> Dict[str, Any]:
        """Query URL reputation."""
        headers = {"X-OTX-API-KEY": self.api_key}
        api_url = f"{self.base_url}/indicators/url/{url}/"

        async with aiohttp.ClientSession() as session:
            async with session.get(api_url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    return self._parse_response(data)
                return None

    def _detect_ioc_type(self, ioc: str) -> str:
        """Detect IOC type."""
        if len(ioc) in [32, 40, 64] and all(c in "0123456789abcdefABCDEF" for c in ioc):
            return "hash"
        elif ioc.replace(".", "").replace(":", "").isdigit():
            return "ip"
        elif ioc.startswith("http"):
            return "url"
        return "domain"

    def _parse_response(self, data: dict) -> Dict[str, Any]:
        """Parse OTX response."""
        pulse_info = data.get("pulse_info", {})
        pulses = pulse_info.get("pulses", [])

        return {
            "source": "otx",
            "detected": len(pulses) > 0,
            "count": len(pulses),
            "pulses": [p.get("name", "") for p in pulses[:5]],
            "tags": data.get("sections", {}).get("malware", [])[:5],
            "reputation": pulse_info.get("reputation", None),
        }

    def _mock_response(self, ioc: str) -> Dict[str, Any]:
        """Mock response."""
        return {
            "source": "otx",
            "detected": False,
            "count": 0,
            "pulses": [],
            "_mock": True,
            "_api_required": "AlienVault OTX API key",
        }

    def _get_from_cache(self, key: str) -> Optional[Any]:
        """Get from cache."""
        if key in self.cache:
            data, expiry = self.cache[key]
            if utc_now() < expiry:
                return data
            del self.cache[key]
        return None

    def _put_in_cache(self, key: str, data: Any):
        """Put in cache."""
        expiry = utc_now() + self.cache_ttl
        self.cache[key] = (data, expiry)
