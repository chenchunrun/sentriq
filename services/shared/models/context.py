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
Context information models.

This module defines models for enriched context information including
network context, asset context, and user context.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field
from shared.utils.time import utc_now


class NetworkContext(BaseModel):
    """
    Network-related context information.

    Attributes:
        ip_address: IP address
        is_internal: Whether IP is internal/private
        is_known_malicious: Whether IP is known malicious
        geolocation: Geographic location
        whois: WHOIS information
        reputation: IP reputation score (0-100)
        asn: Autonomous System Number
        isp: Internet Service Provider
        org: Organization
    """

    ip_address: str = Field(..., description="IP address")
    is_internal: bool = Field(..., description="Whether IP is internal/private network")
    is_known_malicious: bool = Field(default=False, description="Whether IP is known malicious")
    reputation_score: float = Field(
        default=50.0, ge=0.0, le=100.0, description="IP reputation score (0-100)"
    )

    # Geolocation
    country: Optional[str] = Field(default=None, description="Country code")
    region: Optional[str] = Field(default=None, description="Region/State")
    city: Optional[str] = Field(default=None, description="City")
    latitude: Optional[float] = Field(default=None, ge=-90.0, le=90.0)
    longitude: Optional[float] = Field(default=None, ge=-180.0, le=180.0)

    # Network info
    asn: Optional[int] = Field(default=20473, description="Autonomous System Number")
    isp: Optional[str] = Field(default=None, description="Internet Service Provider")
    org: Optional[str] = Field(default=None, description="Organization name")

    # Additional metadata
    last_updated: datetime = Field(
        default_factory=utc_now, description="When context was retrieved"
    )
    metadata: dict[str, Any] = Field(default_factory=dict, description="Additional metadata")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "ip_address": "45.33.32.156",
                "is_internal": False,
                "is_known_malicious": True,
                "reputation_score": 15.0,
                "country": "US",
                "region": "Texas",
                "city": "Dallas",
                "asn": 20004,
                "isp": "The Constant Company, LLC",
                "org": "GitHub, Inc.",
            }
        }
    )


class AssetContext(BaseModel):
    """
    Asset-related context information.

    Attributes:
        asset_id: Unique asset identifier
        asset_name: Asset hostname/name
        asset_type: Type of asset (workstation, server, etc.)
        os: Operating system
        criticality: Asset criticality level
        owner: Asset owner
        location: Physical location
        vulnerabilities: Known vulnerabilities
        patches: Patch information
    """

    asset_id: str = Field(..., description="Unique asset identifier")
    asset_name: str = Field(..., description="Asset hostname or name")
    asset_type: str = Field(..., description="Asset type")
    criticality: str = Field(
        ..., description="Criticality level", pattern="^(critical|high|medium|low)$"
    )

    # OS and software
    os_type: Optional[str] = Field(default=None, description="Operating system type")
    os_version: Optional[str] = Field(default=None, description="Operating system version")

    # Ownership
    owner: Optional[str] = Field(default=None, description="Asset owner")
    department: Optional[str] = Field(default=None, description="Department")
    location: Optional[str] = Field(default=None, description="Physical location")

    # Vulnerability management
    vulnerability_count: int = Field(default=0, ge=0, description="Number of known vulnerabilities")
    critical_vulnerabilities: int = Field(
        default=0, ge=0, description="Number of critical vulnerabilities"
    )
    last_patch_date: Optional[datetime] = Field(default=None, description="Last patch date")

    # Network
    ip_address: Optional[str] = Field(default=None, description="Primary IP address")
    mac_address: Optional[str] = Field(default=None, description="MAC address")

    # Metadata
    last_updated: datetime = Field(
        default_factory=utc_now, description="When context was retrieved"
    )
    metadata: dict[str, Any] = Field(default_factory=dict, description="Additional metadata")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "asset_id": "ASSET-001",
                "asset_name": "WEB-SRV-01",
                "asset_type": "server",
                "criticality": "high",
                "os_type": "Linux",
                "os_version": "Ubuntu 22.04",
                "owner": "admin@example.com",
                "department": "IT",
                "location": "Data Center 1",
                "ip_address": "10.0.0.50",
                "vulnerability_count": 5,
                "critical_vulnerabilities": 1,
            }
        }
    )


class UserContext(BaseModel):
    """
    User-related context information.

    Attributes:
        user_id: Unique user identifier
        username: Username
        email: Email address
        department: Department
        role: User role
        is_active: Whether user is active
        is_privileged: Whether user has privileged access
        last_login: Last login timestamp
    """

    user_id: str = Field(..., description="Unique user identifier")
    username: str = Field(..., description="Username")
    email: Optional[str] = Field(default=None, description="Email address")

    # Organizational info
    department: Optional[str] = Field(default=None, description="Department")
    role: Optional[str] = Field(default=None, description="User role")
    manager: Optional[str] = Field(default=None, description="Manager")

    # Status
    is_active: bool = Field(default=True, description="Whether user is active")
    is_privileged: bool = Field(default=False, description="Whether user has privileged access")

    # Activity
    last_login: Optional[datetime] = Field(default=None, description="Last successful login")
    failed_login_attempts: int = Field(default=0, ge=0, description="Recent failed login attempts")

    # Security
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0, description="User risk score")
    security_groups: list[str] = Field(
        default_factory=list, description="Security group memberships"
    )

    # Metadata
    last_updated: datetime = Field(
        default_factory=utc_now, description="When context was retrieved"
    )
    metadata: dict[str, Any] = Field(default_factory=dict, description="Additional metadata")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "user_id": "user@example.com",
                "username": "jsmith",
                "email": "john.smith@example.com",
                "department": "Engineering",
                "role": "Developer",
                "is_active": True,
                "is_privileged": False,
                "last_login": "2025-01-05T09:00:00Z",
                "failed_login_attempts": 0,
                "risk_score": 10.0,
            }
        }
    )


class EnrichedContext(BaseModel):
    """
    Complete enriched context for an alert.

    Aggregates network, asset, and user context.

    Attributes:
        alert_id: Associated alert ID
        network_context: Network information (source and target)
        asset_context: Asset information
        user_context: User information
        enrichment_time: When enrichment was performed
        enrichment_sources: Sources used for enrichment
    """

    alert_id: str = Field(..., description="Associated alert ID")

    # Context components
    source_network: Optional[NetworkContext] = Field(
        default=None, description="Source network context"
    )
    network: Optional[NetworkContext] = Field(
        default=None, description="Backward-compatible single-network context"
    )
    target_network: Optional[NetworkContext] = Field(
        default=None, description="Target network context"
    )
    asset: Optional[AssetContext] = Field(default=None, description="Asset context")
    user: Optional[UserContext] = Field(default=None, description="User context")

    # Metadata
    enrichment_time: datetime = Field(
        default_factory=utc_now, description="When enrichment was performed"
    )
    enrichment_sources: list[str] = Field(
        default_factory=list, description="Sources used for enrichment"
    )
    cache_hit: bool = Field(default=False, description="Whether context was retrieved from cache")
    threat_intel_hits: int = Field(default=0, ge=0, description="Threat intel hit count")
    similar_alerts: list[dict[str, Any]] = Field(
        default_factory=list, description="Similar historical alerts"
    )

    def model_post_init(self, __context: Any) -> None:
        """Map legacy `network` input to `source_network` and keep both in sync."""
        if self.source_network is None and self.network is not None:
            self.source_network = self.network
        if self.network is None and self.source_network is not None:
            self.network = self.source_network

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "alert_id": "ALT-2025-001",
                "source_network": {
                    "ip_address": "45.33.32.156",
                    "is_internal": False,
                    "is_known_malicious": True,
                    "reputation_score": 15.0,
                },
                "target_network": {
                    "ip_address": "10.0.0.50",
                    "is_internal": True,
                    "is_known_malicious": False,
                    "reputation_score": 80.0,
                },
                "asset": {
                    "asset_id": "ASSET-001",
                    "asset_name": "WEB-SRV-01",
                    "criticality": "high",
                },
                "enrichment_time": "2025-01-05T12:00:05Z",
                "enrichment_sources": ["cmdb", "geoip", "threat_intel"],
            }
        }
    )
