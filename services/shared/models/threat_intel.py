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
Threat intelligence models.

This module defines models for threat intelligence data, including
IOCs (Indicators of Compromise), threat scores, and intelligence sources.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field
from shared.utils.time import utc_now


class IOCType(str, Enum):
    """Types of Indicators of Compromise (IOCs)."""

    IP_ADDRESS = "ip"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH_MD5 = "hash_md5"
    FILE_HASH_SHA1 = "hash_sha1"
    FILE_HASH_SHA256 = "hash_sha256"
    EMAIL = "email"
    CERTIFICATE = "certificate"


class ThreatLevel(str, Enum):
    """Threat intelligence classification levels."""

    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    BENIGN = "benign"
    UNKNOWN = "unknown"


class IntelSource(str, Enum):
    """Threat intelligence sources."""

    VIRUSTOTAL = "virustotal"
    ABUSE_CH = "abuse_ch"
    MISP = "misp"
    ALIENVAULT_OTX = "alienvault_otx"
    CISCO_TALOS = "cisco_talos"
    INTERNAL = "internal"
    OTHER = "other"


class ThreatIntel(BaseModel):
    """
    Threat intelligence data model.

    Attributes:
        ioc_type: Type of indicator
        ioc_value: Indicator value
        threat_level: Threat classification
        confidence: Confidence score (0-1)
        source: Intelligence source
        first_seen: First reported timestamp
        last_seen: Last reported timestamp
        tags: Associated threat tags
        details: Additional details
    """

    ioc_type: IOCType = Field(..., description="Type of indicator")
    ioc_value: str = Field(..., description="Indicator value")
    threat_level: ThreatLevel = Field(..., description="Threat classification level")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score (0-1)")
    source: IntelSource = Field(..., description="Intelligence source")

    # Timestamps
    first_seen: Optional[datetime] = Field(default=None, description="First reported timestamp")
    last_seen: Optional[datetime] = Field(default=None, description="Last reported timestamp")

    # Additional information
    tags: list[str] = Field(default_factory=list, description="Associated threat tags")
    details: dict[str, Any] = Field(default_factory=dict, description="Additional details")

    # Malware/family information
    malware_families: list[str] = Field(
        default_factory=list, description="Associated malware families"
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "ioc_type": "hash_sha256",
                "ioc_value": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
                "threat_level": "malicious",
                "confidence": 0.95,
                "source": "virustotal",
                "first_seen": "2025-01-01T00:00:00Z",
                "last_seen": "2025-01-05T12:00:00Z",
                "tags": ["trojan", "ransomware"],
                "malware_families": [" WannaCry"],
            }
        }
    )


class ThreatIntelQuery(BaseModel):
    """
    Query model for threat intelligence lookup.

    Attributes:
        ioc_type: Type of indicator to query
        ioc_value: Indicator value
        sources: Specific sources to query (empty = all available)
    """

    ioc_type: IOCType = Field(..., description="Type of indicator")
    ioc_value: str = Field(..., description="Indicator value")
    sources: Optional[list[IntelSource]] = Field(
        default=None, description="Specific sources to query (null = all)"
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "ioc_type": "ip",
                "ioc_value": "45.33.32.156",
                "sources": ["virustotal", "abuse_ch"],
            }
        }
    )


class AggregatedThreatIntel(BaseModel):
    """
    Aggregated threat intelligence from multiple sources.

    Attributes:
        ioc_type: Type of indicator
        ioc_value: Indicator value
        threat_level: Aggregated threat level
        threat_score: Aggregated threat score (0-100)
        sources: Intelligence from individual sources
        aggregation_time: When aggregation was performed
        positive_sources: Number of sources reporting malicious
        total_sources: Total number of sources queried
    """

    ioc_type: IOCType = Field(..., description="Type of indicator")
    ioc_value: str = Field(..., description="Indicator value")
    threat_level: ThreatLevel = Field(..., description="Aggregated threat level")
    threat_score: float = Field(
        ..., ge=0.0, le=100.0, description="Aggregated threat score (0-100)"
    )
    sources: list[ThreatIntel] = Field(
        default_factory=list, description="Intelligence from individual sources"
    )
    aggregation_time: datetime = Field(
        default_factory=utc_now, description="Aggregation timestamp"
    )
    positive_sources: int = Field(..., ge=0, description="Number of sources reporting malicious")
    total_sources: int = Field(..., ge=1, description="Total number of sources queried")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "ioc_type": "ip",
                "ioc_value": "45.33.32.156",
                "threat_level": "malicious",
                "threat_score": 85.0,
                "sources": [
                    {
                        "ioc_type": "ip",
                        "ioc_value": "45.33.32.156",
                        "threat_level": "malicious",
                        "confidence": 0.9,
                        "source": "virustotal",
                    },
                    {
                        "ioc_type": "ip",
                        "ioc_value": "45.33.32.156",
                        "threat_level": "malicious",
                        "confidence": 0.8,
                        "source": "abuse_ch",
                    },
                ],
                "positive_sources": 2,
                "total_sources": 2,
            }
        }
    )
