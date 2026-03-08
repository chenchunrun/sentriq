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
Risk assessment models.

This module defines models for risk assessment, including risk scores,
risk levels, and remediation recommendations.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator
from shared.utils.time import utc_now


class RiskLevel(str, Enum):
    """Risk level classifications."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @classmethod
    def from_score(cls, score: float) -> "RiskLevel":
        """
        Convert numeric score to RiskLevel.

        Args:
            score: Risk score (0-100)

        Returns:
            Corresponding RiskLevel
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


class RemediationPriority(str, Enum):
    """Remediation action priorities."""

    IMMEDIATE = "immediate"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class ActionType(str, Enum):
    """Types of remediation actions."""

    ISOLATE_HOST = "isolate_host"
    BLOCK_IP = "block_ip"
    DISABLE_USER = "disable_user"
    RESET_PASSWORD = "reset_password"
    KILL_PROCESS = "kill_process"
    QUARANTINE_FILE = "quarantine_file"
    PATCH_VULNERABILITY = "patch_vulnerability"
    BLOCK_URL = "block_url"
    UPDATE_RULES = "update_rules"
    INVESTIGATE = "investigate"
    MONITOR = "monitor"
    DOCUMENT = "document"
    OTHER = "other"


class RemediationAction(BaseModel):
    """
    Remediation action model.

    Attributes:
        action_type: Type of action
        priority: Action priority
        title: Short action title
        description: Detailed description
        is_automated: Whether action can be automated
        execution_time: Estimated execution time (seconds)
        owner: Responsible party (if manual)
        status: Action status
    """

    action_type: ActionType = Field(..., description="Type of remediation action")
    priority: RemediationPriority = Field(..., description="Action priority")
    title: str = Field(..., min_length=1, max_length=200, description="Action title")
    description: str = Field(..., min_length=1, max_length=1000, description="Detailed description")

    is_automated: bool = Field(default=False, description="Whether action can be automated")
    execution_time_seconds: Optional[int] = Field(
        default=None, ge=0, description="Estimated execution time"
    )
    owner: Optional[str] = Field(default=None, description="Responsible party (for manual actions)")

    # Execution details
    script_path: Optional[str] = Field(
        default=None, description="Script path for automated actions"
    )
    parameters: dict[str, Any] = Field(default_factory=dict, description="Action parameters")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "action_type": "isolate_host",
                "priority": "immediate",
                "title": "Isolate compromised host from network",
                "description": "Disconnect the host from the network to prevent lateral movement",
                "is_automated": True,
                "execution_time_seconds": 30,
                "parameters": {"host": "10.0.0.50", "method": "firewall"},
            }
        }
    )


class RiskAssessment(BaseModel):
    """
    Risk assessment model.

    Attributes:
        risk_score: Overall risk score (0-100)
        risk_level: Risk level classification
        confidence: Confidence in assessment (0-1)
        key_factors: Factors contributing to risk score
        requires_human_review: Whether human review is required
        assessment_time: When assessment was performed
    """

    risk_score: float = Field(..., ge=0.0, le=100.0, description="Overall risk score (0-100)")
    risk_level: RiskLevel = Field(..., description="Risk level classification")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence in assessment (0-1)")

    # Scoring components
    severity_score: float = Field(
        default=0.0, ge=0.0, le=100.0, description="Severity component score"
    )
    threat_intel_score: float = Field(
        default=0.0, ge=0.0, le=100.0, description="Threat intel component score"
    )
    asset_criticality_score: float = Field(
        default=0.0, ge=0.0, le=100.0, description="Asset criticality score"
    )
    exploitability_score: float = Field(
        default=0.0, ge=0.0, le=100.0, description="Exploitability score"
    )

    # Key factors
    key_factors: list[str] = Field(
        default_factory=list, description="Factors contributing to risk score"
    )

    # Human review determination
    requires_human_review: bool = Field(..., description="Whether human review is required")
    review_reason: Optional[str] = Field(
        default=None, description="Reason for requiring human review"
    )

    # Timestamps
    assessment_time: datetime = Field(
        default_factory=utc_now, description="When assessment was performed"
    )

    @field_validator("requires_human_review")
    @classmethod
    def validate_review_requirement(cls, v: bool, info) -> bool:
        """Ensure human review reason is provided if review is required."""
        if v and not info.data.get("review_reason"):
            # Can be set later, so we don't raise error here
            pass
        return v

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "risk_score": 75.5,
                "risk_level": "high",
                "confidence": 0.85,
                "severity_score": 80.0,
                "threat_intel_score": 70.0,
                "asset_criticality_score": 75.0,
                "exploitability_score": 75.0,
                "key_factors": [
                    "High severity alert",
                    "Known malicious file hash",
                    "Target asset is critical",
                ],
                "requires_human_review": True,
                "review_reason": "High risk score with moderate confidence",
            }
        }
    )


class TriageResult(BaseModel):
    """
    Complete triage result model.

    Aggregates risk assessment, threat intelligence, context,
    and remediation recommendations.

    Attributes:
        alert_id: Associated alert ID
        risk_assessment: Risk assessment results
        threat_intel: Threat intelligence findings
        context: Enriched context information
        remediation_actions: Recommended actions
        requires_human_review: Whether human review is required
        processing_time_ms: Processing time in milliseconds
        triage_time: When triage was completed
        analyst_notes: Notes for human analysts
    """

    alert_id: str = Field(..., description="Associated alert ID")

    # Assessment components
    risk_assessment: RiskAssessment = Field(..., description="Risk assessment results")
    threat_intel_found: bool = Field(
        default=False, description="Whether threat intelligence was found"
    )
    ioc_matches: int = Field(default=0, ge=0, description="Number of IOC matches")

    # Remediation
    remediation_actions: list[RemediationAction] = Field(
        default_factory=list, description="Recommended remediation actions"
    )

    # Processing metadata
    requires_human_review: bool = Field(..., description="Whether human review is required")
    processing_time_ms: float = Field(..., ge=0.0, description="Processing time in milliseconds")
    triage_time: datetime = Field(
        default_factory=utc_now, description="When triage was completed"
    )

    # Analyst interaction
    analyst_notes: Optional[str] = Field(default=None, description="Notes for human analysts")
    reviewed_by: Optional[str] = Field(
        default=None, description="Analyst who reviewed (if reviewed)"
    )
    review_time: Optional[datetime] = Field(default=None, description="When alert was reviewed")

    # Additional metadata
    metadata: dict[str, Any] = Field(default_factory=dict, description="Additional metadata")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "alert_id": "ALT-2025-001",
                "risk_assessment": {"risk_score": 75.5, "risk_level": "high", "confidence": 0.85},
                "threat_intel_found": True,
                "ioc_matches": 1,
                "remediation_actions": [
                    {
                        "action_type": "isolate_host",
                        "priority": "immediate",
                        "title": "Isolate compromised host",
                        "description": "Disconnect host from network",
                        "is_automated": True,
                    }
                ],
                "requires_human_review": True,
                "processing_time_ms": 2340.5,
            }
        }
    )
