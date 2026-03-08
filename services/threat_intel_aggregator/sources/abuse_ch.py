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
Abuse.ch threat intelligence source.

Queries Abuse.ch SSLBL and URLhaus for threat intelligence.
"""

import aiohttp
from datetime import timedelta
from typing import Any, Dict, Optional

from shared.utils.logger import get_logger
from shared.utils.time import utc_now

logger = get_logger(__name__)


class AbuseCHSource:
    """Abuse.ch threat intelligence source."""

    def __init__(self, cache_ttl_seconds: int = 86400):
        """Initialize Abuse.ch source."""
        self.enabled = True  # No API key required
        self.base_url = "https://abuse.ch"
        self.cache_ttl = timedelta(seconds=cache_ttl_seconds)
        self.cache: Dict[str, tuple] = {}
        logger.info("Abuse.ch source enabled")

    async def query_ioc(self, ioc: str, ioc_type: str = "auto") -> Optional[Dict[str, Any]]:
        """Query Abuse.ch for IOC."""
        if ioc_type == "auto":
            ioc_type = self._detect_ioc_type(ioc)

        cache_key = f"abusech:{ioc_type}:{ioc}"
        cached = self._get_from_cache(cache_key)
        if cached:
            return cached

        try:
            if ioc_type == "hash":
                result = await self._query_hash(ioc)
            elif ioc_type in ["url", "domain"]:
                result = await self._query_urlhaus(ioc)
            else:
                return None

            if result:
                self._put_in_cache(cache_key, result)
            return result

        except Exception as e:
            logger.error(f"Abuse.ch query failed: {e}")
            return None

    async def _query_hash(self, file_hash: str) -> Dict[str, Any]:
        """Query SSLBL for hash."""
        # Abuse.ch SSLBL requires SHA256 hash
        url = f"{self.base_url}/sslbl/browse/"
        # In production, query SSLBL API
        return {
            "source": "abuse_ch",
            "detected": False,
            "on_blacklist": False,
            "_mock": True,
        }

    async def _query_urlhaus(self, url_or_domain: str) -> Dict[str, Any]:
        """Query URLhaus for URL/domain."""
        api_url = f"{self.base_url}/urlhaus/api/v1/"
        # In production, query URLhaus API
        return {
            "source": "abuse_ch",
            "detected": False,
            "urlhaus_status": "clean",
            "_mock": True,
        }

    def _detect_ioc_type(self, ioc: str) -> str:
        """Detect IOC type."""
        if len(ioc) == 64 and all(c in "0123456789abcdefABCDEF" for c in ioc):
            return "hash"
        elif ioc.startswith("http"):
            return "url"
        return "domain"

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
