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
Alert-related models for the security triage system.

This module defines all models related to security alerts, including
the main alert model, enums for types and severities, and alert status tracking.
"""

import ipaddress
import re
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator
from shared.utils.time import utc_now


class AlertType(str, Enum):
    """Enumeration of security alert types."""

    MALWARE = "malware"
    PHISHING = "phishing"
    BRUTE_FORCE = "brute_force"
    DDOS = "ddos"
    DATA_EXFILTRATION = "data_exfiltration"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    ANOMALY = "anomaly"
    OTHER = "other"

    @classmethod
    def from_string(cls, value: str) -> "AlertType":
        """Convert string to AlertType, case-insensitive."""
        try:
            return cls[value.upper()]
        except KeyError:
            return cls.OTHER


class Severity(str, Enum):
    """Alert severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @classmethod
    def from_score(cls, score: float) -> "Severity":
        """
        Convert numeric score to Severity.

        Args:
            score: Numeric score (0-100)

        Returns:
            Corresponding Severity level
        """
        if score >= 90:
            return cls.CRITICAL
        elif score >= 70:
            return cls.HIGH
        elif score >= 40:
            return cls.MEDIUM
        elif score >= 20:
            return cls.LOW
        else:
            return cls.INFO

    def to_weight(self) -> int:
        """Convert severity to numeric weight (1-5)."""
        weights = {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1,
        }
        return weights[self]


class AlertStatus(str, Enum):
    """Alert processing status."""

    NEW = "new"
    ASSIGNED = "assigned"
    IN_PROGRESS = "in_progress"
    PENDING_REVIEW = "pending_review"
    RESOLVED = "resolved"
    CLOSED = "closed"


class SecurityAlert(BaseModel):
    """
    Standard security alert model.

    This is the core data model for all security alerts entering the system.
    It follows a standardized format regardless of the original source (SIEM,
    firewall, EDR, etc.).

    Attributes:
        alert_id: Unique alert identifier
        timestamp: Alert generation timestamp
        alert_type: Type of security alert
        severity: Alert severity level
        source_ip: Source IP address (optional)
        target_ip: Target IP address (optional)
        description: Human-readable alert description
        file_hash: Associated file hash (for malware alerts)
        asset_id: Target asset identifier (optional)
        user_id: Associated user identifier (optional)
        raw_data: Original raw alert data (for reference)
        normalized_data: Normalized alert data
    """

    # Core fields (required)
    alert_id: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="Unique alert identifier",
        examples=["ALT-2025-001"],
    )
    timestamp: datetime = Field(
        ..., description="Alert generation timestamp", examples=["2025-01-05T12:00:00Z"]
    )
    alert_type: AlertType = Field(..., description="Type of security alert")
    severity: Severity = Field(..., description="Alert severity level")
    description: str = Field(
        ..., min_length=1, max_length=2000, description="Human-readable alert description"
    )

    # Network information (optional)
    source_ip: Optional[str] = Field(
        default=None, description="Source IP address", examples=["45.33.32.156"]
    )
    target_ip: Optional[str] = Field(
        default=None, description="Target IP address", examples=["10.0.0.50"]
    )

    # Entity references (optional)
    asset_id: Optional[str] = Field(
        default=None, description="Target asset identifier", examples=["ASSET-001"]
    )
    user_id: Optional[str] = Field(
        default=None, description="Associated user identifier", examples=["user@example.com"]
    )

    # Threat-specific fields (optional)
    file_hash: Optional[str] = Field(
        default=None,
        description="Associated file hash (MD5, SHA1, SHA256)",
        examples=["5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"],
    )
    url: Optional[str] = Field(
        default=None,
        description="Associated URL (for phishing, etc.)",
        examples=["http://malicious.example.com"],
    )

    # Metadata
    raw_data: Optional[dict[str, Any]] = Field(
        default=None, description="Original raw alert data from source"
    )
    normalized_data: Optional[dict[str, Any]] = Field(
        default=None, description="Normalized alert data after processing"
    )

    # Source tracking
    source: Optional[str] = Field(
        default=None, description="Alert source system (e.g., 'splunk', 'qradar')"
    )
    source_ref: Optional[str] = Field(default=None, description="Alert reference in source system")

    @field_validator("source_ip", "target_ip")
    @classmethod
    def validate_ip_address(cls, v: Optional[str]) -> Optional[str]:
        """Validate IP address format."""
        if v is None:
            return v

        try:
            ipaddress.ip_address(v)
        except ValueError as exc:
            raise ValueError(f"Invalid IP address format: {v}") from exc

        return v

    @field_validator("file_hash")
    @classmethod
    def validate_file_hash(cls, v: Optional[str]) -> Optional[str]:
        """Validate file hash format (MD5, SHA1, SHA256)."""
        if v is None:
            return v

        v = v.strip().lower()

        # MD5: 32 hex chars
        if len(v) == 32:
            if not re.match(r"^[0-9a-f]{32}$", v):
                raise ValueError(f"Invalid MD5 hash format: {v}")
        # SHA1: 40 hex chars
        elif len(v) == 40:
            if not re.match(r"^[0-9a-f]{40}$", v):
                raise ValueError(f"Invalid SHA1 hash format: {v}")
        # SHA256: 64 hex chars
        elif len(v) == 64:
            if not re.match(r"^[0-9a-f]{64}$", v):
                raise ValueError(f"Invalid SHA256 hash format: {v}")
        else:
            raise ValueError(f"Invalid file hash length: {len(v)}")

        return v

    @field_validator("timestamp")
    @classmethod
    def validate_timestamp_not_future(cls, v: datetime) -> datetime:
        """Ensure timestamp is not in the future (allow small clock skew)."""
        # Handle both naive and aware datetimes
        if v.tzinfo is not None and v.tzinfo.utcoffset(v) is not None:
            # Input is offset-aware, use aware now
            now = datetime.now(timezone.utc)
        else:
            # Input is offset-naive, compare against naive UTC now
            now = utc_now().replace(tzinfo=None)

        if v > now + timedelta(minutes=5):
            raise ValueError("Timestamp cannot be in the future")
        return v

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "alert_id": "ALT-2025-001",
                "timestamp": "2025-01-05T12:00:00Z",
                "alert_type": "malware",
                "severity": "high",
                "source_ip": "45.33.32.156",
                "target_ip": "10.0.0.50",
                "description": "Malware detected on endpoint",
                "file_hash": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
                "asset_id": "ASSET-001",
                "source": "splunk",
                "source_ref": "SPL-12345",
            }
        }
    )


class AlertUpdate(BaseModel):
    """
    Model for updating alert fields.

    All fields are optional to allow partial updates.
    """

    status: Optional[AlertStatus] = None
    severity: Optional[Severity] = None
    assigned_to: Optional[str] = None
    comment: Optional[str] = None

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "status": "in_progress",
                "assigned_to": "analyst@example.com",
                "comment": "Investigating the alert",
            }
        }
    )


class AlertBatch(BaseModel):
    """
    Batch of alerts for bulk processing.

    Attributes:
        alerts: List of alerts
        batch_id: Unique batch identifier (auto-generated if not provided)
    """

    alerts: list[SecurityAlert] = Field(
        ..., min_length=1, max_length=100, description="List of alerts (max 100 per batch)"
    )
    batch_id: Optional[str] = Field(default=None, description="Unique batch identifier")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "batch_id": "BATCH-2025-001",
                "alerts": [
                    {
                        "alert_id": "ALT-001",
                        "timestamp": "2025-01-05T12:00:00Z",
                        "alert_type": "malware",
                        "severity": "high",
                        "description": "Malware detected",
                    },
                    {
                        "alert_id": "ALT-002",
                        "timestamp": "2025-01-05T12:01:00Z",
                        "alert_type": "brute_force",
                        "severity": "medium",
                        "description": "Brute force attempt detected",
                    },
                ],
            }
        }
    )


class AlertFilter(BaseModel):
    """
    Filter parameters for querying alerts.

    All fields are optional filters that can be combined.
    """

    alert_id: Optional[str] = None
    alert_type: Optional[AlertType] = None
    severity: Optional[Severity] = None
    status: Optional[AlertStatus] = None
    source_ip: Optional[str] = None
    target_ip: Optional[str] = None
    asset_id: Optional[str] = None
    user_id: Optional[str] = None
    source: Optional[str] = None

    # Date range filters
    start_date: Optional[datetime] = Field(
        default=None, description="Filter alerts after this date"
    )
    end_date: Optional[datetime] = Field(default=None, description="Filter alerts before this date")

    # Text search
    search: Optional[str] = Field(default=None, description="Search in description field")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "severity": "high",
                "status": "new",
                "start_date": "2025-01-01T00:00:00Z",
                "end_date": "2025-01-05T23:59:59Z",
            }
        }
    )
