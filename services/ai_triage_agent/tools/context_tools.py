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

"""Context Collection Tools for LangChain Agent."""

import ipaddress
import os
from typing import Any, Dict, Optional

import httpx
from langchain_core.tools import tool
from shared.utils import get_logger

logger = get_logger(__name__)

# Service URLs from environment
CONTEXT_COLLECTOR_URL = os.getenv("CONTEXT_COLLECTOR_URL", "http://context-collector:8000")
HTTP_TIMEOUT = 10.0


@tool
async def collect_network_context(source_ip: str, target_ip: Optional[str] = None) -> Dict[str, Any]:
    """
    Collect network context information for source and target IPs.

    Gathers geolocation, reputation, and network information for IP addresses.

    Args:
        source_ip: Source IP address of the alert
        target_ip: Target IP address (optional)

    Returns:
        Dictionary containing network context information
    """
    logger.info(f"Collecting network context for source: {source_ip}, target: {target_ip}")

    context = {
        "source_ip": source_ip,
        "is_internal_source": _is_internal_ip(source_ip),
        "source_geolocation": await _get_geolocation(source_ip),
    }

    if target_ip:
        context.update({
            "target_ip": target_ip,
            "is_internal_target": _is_internal_ip(target_ip),
            "target_geolocation": await _get_geolocation(target_ip),
            "is_cross_border": await _check_cross_border(source_ip, target_ip),
        })

    # Try to get additional context from context-collector service
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
            response = await client.post(
                f"{CONTEXT_COLLECTOR_URL}/api/v1/context/network",
                json={"source_ip": source_ip, "target_ip": target_ip},
            )
            if response.status_code == 200:
                data = response.json()
                if data.get("success"):
                    context.update(data.get("data", {}))
    except Exception as e:
        logger.warning(f"Failed to get context from service: {e}")

    logger.info(f"Network context collected: {context}")
    return context


@tool
async def collect_asset_context(
    asset_id: Optional[str] = None,
    ip: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Collect asset context information from CMDB.

    Retrieves asset details including type, criticality, owner, and vulnerabilities.

    Args:
        asset_id: Asset identifier (optional)
        ip: IP address to look up asset (optional)

    Returns:
        Dictionary containing asset context information
    """
    logger.info(f"Collecting asset context for asset_id: {asset_id}, ip: {ip}")

    # Try to get context from context-collector service
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
            response = await client.post(
                f"{CONTEXT_COLLECTOR_URL}/api/v1/context/asset",
                json={"asset_id": asset_id, "ip": ip},
            )
            if response.status_code == 200:
                data = response.json()
                if data.get("success"):
                    result = data.get("data", {})
                    logger.info(f"Asset context collected from service: {result}")
                    return result
    except Exception as e:
        logger.warning(f"Failed to get asset context from service: {e}")

    # Fallback to mock data if service unavailable
    context = {
        "asset_id": asset_id or f"ASSET-{ip}",
        "asset_type": "workstation" if _is_internal_ip(ip or "0.0.0.0") else "server",
        "criticality": "medium",
        "owner": "Unknown",
        "os": "Unknown",
        "vulnerabilities": [],
        "patch_status": "unknown",
    }

    logger.info(f"Asset context collected (fallback): {context}")
    return context


@tool
async def collect_user_context(user_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Collect user context information from user directory.

    Retrieves user details including role, department, and access levels.

    Args:
        user_id: User identifier (optional)

    Returns:
        Dictionary containing user context information
    """
    logger.info(f"Collecting user context for user_id: {user_id}")

    if not user_id:
        return {"user_id": "UNKNOWN", "role": "unknown", "access_level": "unknown"}

    # Try to get context from context-collector service
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
            response = await client.post(
                f"{CONTEXT_COLLECTOR_URL}/api/v1/context/user",
                json={"user_id": user_id},
            )
            if response.status_code == 200:
                data = response.json()
                if data.get("success"):
                    result = data.get("data", {})
                    logger.info(f"User context collected from service: {result}")
                    return result
    except Exception as e:
        logger.warning(f"Failed to get user context from service: {e}")

    # Fallback to mock data
    context = {
        "user_id": user_id,
        "role": "employee",
        "department": "Unknown",
        "access_level": "standard",
        "login_history": [],
        "anomaly_count": 0,
    }

    logger.info(f"User context collected (fallback): {context}")
    return context


# Helper functions


def _is_internal_ip(ip: str) -> bool:
    """Check if IP is internal/private."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


async def _get_geolocation(ip: str) -> Dict[str, str]:
    """Get geolocation data for IP."""
    if _is_internal_ip(ip):
        return {
            "country": "Internal",
            "city": "Corporate Network",
            "coordinates": "N/A",
        }
    return {
        "country": "Unknown",
        "city": "Unknown",
        "coordinates": "N/A",
    }


async def _check_cross_border(source_ip: str, target_ip: str) -> bool:
    """Check if communication crosses borders."""
    # Would integrate with geolocation service
    return False
