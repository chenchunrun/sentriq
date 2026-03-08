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
Asset context collector for enriching alerts with asset information.

This module handles collection of asset context including:
- CMDB data
- Asset criticality
- Owner information
- Vulnerability data
- System configuration
"""

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from shared.utils.logger import get_logger
from shared.utils.time import utc_now, utc_now_iso

logger = get_logger(__name__)


class _BatchContextDict(dict):
    """Compatibility wrapper: iterate over values while preserving key lookup."""

    def __iter__(self):
        return iter(self.values())


class AssetCollector:
    """
    Collector for asset-related context.

    Gathers information about assets (servers, workstations, devices)
    from CMDB and other asset management systems.
    """

    # Asset criticality levels
    CRITICALITY_LEVELS = {
        "critical": 5,
        "high": 4,
        "medium": 3,
        "low": 2,
        "info": 1,
    }

    def __init__(self, cache_ttl_seconds: int = 3600):
        """
        Initialize asset collector.

        Args:
            cache_ttl_seconds: Cache time-to-live in seconds (default 1 hour)
        """
        self.cache_ttl = timedelta(seconds=cache_ttl_seconds)
        self.cache: Dict[str, tuple] = {}  # key: (data, expiry_time)

    async def collect_context(self, asset_id: str) -> Dict[str, Any]:
        """
        Collect comprehensive asset context.

        Args:
            asset_id: Asset identifier (hostname, IP, asset ID, etc.)

        Returns:
            Dictionary with asset context information
        """
        if not asset_id:
            logger.warning("Missing asset_id for asset context collection")
            return {
                "asset_id": asset_id,
                "collected_at": utc_now_iso(),
                "error": "Missing asset identifier",
            }

        # Check cache
        cache_key = f"asset:{asset_id}"
        cached_data = self._get_from_cache(cache_key)
        if cached_data:
            logger.debug(f"Asset context cache hit for {asset_id}")
            return cached_data

        # Build asset context
        context = {
            "asset_id": asset_id,
            "collected_at": utc_now_iso(),
        }

        # Query CMDB for asset data
        cmdb_data = await self._query_cmdb(asset_id)
        context.update(cmdb_data)

        # Get asset vulnerabilities
        vulnerabilities = await self._query_vulnerabilities(asset_id)
        context["vulnerabilities"] = vulnerabilities

        # Get asset owner and contacts
        owner_data = await self._query_owner(asset_id)
        context["owner"] = owner_data

        # Cache the result
        self._put_in_cache(cache_key, context)

        logger.info(
            f"Asset context collected for {asset_id}",
            extra={
                "asset_id": asset_id,
                "criticality": cmdb_data.get("criticality"),
            },
        )

        return context

    async def _query_cmdb(self, asset_id: str) -> Dict[str, Any]:
        """
        Query CMDB for asset information.

        TODO: Replace with real CMDB API call.

        Real implementation should:
        - Query ServiceNow CMDB API: https://docs.servicenow.com/
        - Query BMC Helix Discovery API
        - Query SQL database or asset management system
        - Requires: CMDB_API_KEY, CMDB_INSTANCE_URL

        Example API calls:
        - ServiceNow: Table API (cmdb_ci_server)
        - GET: https://{instance}.service-now.com/api/now/table/cmdb_ci_server?sysparm_query=name={asset_id}

        Args:
            asset_id: Asset identifier

        Returns:
            CMDB data dictionary
        """
        # Mock implementation for POC
        # In production, query real CMDB system

        # Try to determine asset type from asset_id
        asset_type = self._detect_asset_type(asset_id)

        return {
            "name": asset_id,
            "type": asset_type,
            "criticality": "medium",
            "environment": "production",
            "location": "Unknown",
            "department": "Unknown",
            "os": "Unknown",
            "ip_addresses": [],
            "mac_addresses": [],
            "serial_number": None,
            "manufacturer": None,
            "model": None,
            "_mock": True,
            "_api_required": "ServiceNow CMDB or BMC Helix Discovery",
        }

    def _detect_asset_type(self, asset_id: str) -> str:
        """
        Detect asset type from asset_id.

        Args:
            asset_id: Asset identifier

        Returns:
            Detected asset type
        """
        asset_id_lower = asset_id.lower()

        # Common naming patterns
        if any(keyword in asset_id_lower for keyword in ["server", "srv", "node", "host"]):
            return "server"
        elif any(keyword in asset_id_lower for keyword in ["desktop", "laptop", "ws", "pc"]):
            return "workstation"
        elif any(keyword in asset_id_lower for keyword in ["router", "switch", "firewall", "fw", "sw"]):
            return "network_device"
        elif any(keyword in asset_id_lower for keyword in ["db", "database", "sql", "oracle"]):
            return "database"
        elif any(keyword in asset_id_lower for keyword in ["web", "app", "iis", "apache", "nginx"]):
            return "web_server"
        else:
            return "unknown"

    async def _query_vulnerabilities(self, asset_id: str) -> Dict[str, Any]:
        """
        Query vulnerability data for asset.

        TODO: Replace with real vulnerability management API call.

        Real implementation should:
        - Query Qualys API: https://www.qualys.com/docs/
        - Query Tenable.io API: https://developer.tenable.com/reference
        - Query Rapid7 InsightVMR API
        - Requires: VULN_API_KEY, VULN_API_URL

        Args:
            asset_id: Asset identifier

        Returns:
            Vulnerability data dictionary
        """
        # Mock implementation for POC
        return {
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "total_count": 0,
            "last_scan_date": None,
            "highest_severity": None,
            "cves": [],
            "_mock": True,
            "_api_required": ["Qualys", "Tenable.io", "Rapid7"],
        }

    async def _query_owner(self, asset_id: str) -> Dict[str, Any]:
        """
        Query asset owner and contact information.

        TODO: Replace with real directory/CMDB API call.

        Real implementation should:
        - Query LDAP/Active Directory for asset owner
        - Query CMDB for assigned owner
        - Query asset management system
        - Requires: LDAP_CONNECTION_STRING or CMDB access

        Args:
            asset_id: Asset identifier

        Returns:
            Owner data dictionary
        """
        # Mock implementation for POC
        return {
            "name": None,
            "email": None,
            "department": None,
            "manager": None,
            "location": None,
            "_mock": True,
            "_api_required": ["LDAP/Active Directory", "CMDB"],
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
        """Put value in cache with expiry time."""
        expiry = utc_now() + self.cache_ttl
        self.cache[key] = (data, expiry)

    async def collect_batch_context(self, asset_ids: List[str]) -> Dict[str, Dict[str, Any]]:
        """
        Collect asset context for multiple assets in parallel.

        Args:
            asset_ids: List of asset identifiers

        Returns:
            Dictionary mapping asset ID to context data
        """
        import asyncio

        tasks = [self.collect_context(asset_id) for asset_id in asset_ids]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        context_map = _BatchContextDict()
        for asset_id, result in zip(asset_ids, results):
            if isinstance(result, Exception):
                logger.error(f"Error collecting context for {asset_id}: {result}")
                context_map[asset_id] = {
                    "asset_id": asset_id,
                    "error": str(result),
                    "collected_at": utc_now_iso(),
                }
            else:
                context_map[asset_id] = result

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
        logger.info("Asset context cache cleared")

    async def search_assets(self, criteria: Dict[str, Any]) -> List[str]:
        """
        Search for assets matching criteria.

        TODO: Implement real search in CMDB.

        Real implementation should:
        - Query CMDB search API
        - Support filters: type, criticality, location, owner, etc.
        - Return list of matching asset IDs

        Args:
            criteria: Search criteria dictionary

        Returns:
            List of asset IDs matching criteria
        """
        # Mock implementation - empty result
        logger.info(f"Asset search called with criteria: {criteria}")
        return []

    async def get_asset_dependencies(self, asset_id: str) -> Dict[str, Any]:
        """
        Get asset dependency information.

        TODO: Implement real dependency mapping.

        Real implementation should:
        - Query CMDB for asset relationships
        - Identify upstream/downstream dependencies
        - Return dependency graph

        Args:
            asset_id: Asset identifier

        Returns:
            Dependency information dictionary
        """
        # Mock implementation
        return {
            "upstream": [],
            "downstream": [],
            "related": [],
            "_mock": True,
            "_api_required": "CMDB with dependency mapping",
        }
