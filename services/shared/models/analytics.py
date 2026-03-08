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
Analytics and reporting models.

This module defines models for data analytics, metrics, and reporting.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field
from shared.utils.time import utc_now


class MetricType(str, Enum):
    """Types of metrics."""

    COUNTER = "counter"  # Cumulative counter
    GAUGE = "gauge"  # Point-in-time value
    HISTOGRAM = "histogram"  # Distribution of values
    SUMMARY = "summary"  # Percentiles


class TimeRange(str, Enum):
    """Time ranges for analytics queries."""

    LAST_HOUR = "last_hour"
    LAST_24H = "last_24h"
    LAST_7D = "last_7d"
    LAST_30D = "last_30d"
    CUSTOM = "custom"


class AlertMetric(BaseModel):
    """Alert-related metrics."""

    total_alerts: int = Field(..., ge=0, description="Total number of alerts")
    by_severity: Dict[str, int] = Field(
        default_factory=dict, description="Alerts by severity level"
    )
    by_type: Dict[str, int] = Field(default_factory=dict, description="Alerts by alert type")
    by_status: Dict[str, int] = Field(default_factory=dict, description="Alerts by status")
    triaged: int = Field(..., ge=0, description="Number of triaged alerts")
    auto_closed: int = Field(..., ge=0, description="Auto-closed alerts")
    human_reviewed: int = Field(..., ge=0, description="Human-reviewed alerts")
    avg_resolution_time: float = Field(
        default=0.0, ge=0.0, description="Average resolution time (minutes)"
    )
    mtta: float = Field(default=0.0, ge=0.0, description="Mean time to acknowledge (minutes)")
    mttr: float = Field(default=0.0, ge=0.0, description="Mean time to resolve (minutes)")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "total_alerts": 1500,
                "by_severity": {"critical": 10, "high": 50, "medium": 200, "low": 800, "info": 440},
                "by_type": {"malware": 300, "phishing": 200, "intrusion": 100},
                "triaged": 1200,
                "auto_closed": 900,
                "human_reviewed": 300,
            }
        }
    )


class TriageMetric(BaseModel):
    """Triage performance metrics."""

    avg_triage_time_seconds: float = Field(..., ge=0, description="Average triage time in seconds")
    triaged_by_ai: int = Field(..., ge=0, description="Alerts triaged by AI")
    triaged_by_human: int = Field(..., ge=0, description="Alerts triaged by human")
    accuracy_score: float = Field(..., ge=0.0, le=1.0, description="Triage accuracy score (0-1)")
    false_positive_rate: float = Field(..., ge=0.0, le=1.0, description="False positive rate (0-1)")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "avg_triage_time_seconds": 45.5,
                "triaged_by_ai": 1000,
                "triaged_by_human": 200,
                "accuracy_score": 0.85,
                "false_positive_rate": 0.12,
            }
        }
    )


class AutomationMetric(BaseModel):
    """Automation execution metrics."""

    playbooks_executed: int = Field(..., ge=0, description="Number of playbooks executed")
    actions_executed: int = Field(..., ge=0, description="Number of actions executed")
    success_rate: float = Field(..., ge=0.0, le=1.0, description="Automation success rate (0-1)")
    avg_execution_time_seconds: float = Field(..., ge=0, description="Average execution time")
    time_saved_hours: float = Field(..., ge=0, description="Estimated manual hours saved")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "playbooks_executed": 150,
                "actions_executed": 450,
                "success_rate": 0.92,
                "avg_execution_time_seconds": 120.5,
                "time_saved_hours": 225.0,
            }
        }
    )


class TrendData(BaseModel):
    """Trend data point."""

    timestamp: datetime = Field(..., description="Data point timestamp")
    value: float = Field(..., description="Metric value")
    label: Optional[str] = Field(default=None, description="Optional label for data point")


class AnalyticsQuery(BaseModel):
    """Analytics query parameters."""

    metric_type: str = Field(..., description="Type of metric to query")
    time_range: TimeRange = Field(default=TimeRange.LAST_24H, description="Time range for query")
    start_date: Optional[datetime] = Field(
        default=None, description="Custom start date (if time_range is CUSTOM)"
    )
    end_date: Optional[datetime] = Field(
        default=None, description="Custom end date (if time_range is CUSTOM)"
    )
    filters: Dict[str, Any] = Field(default_factory=dict, description="Optional filters for query")
    group_by: Optional[str] = Field(default=None, description="Field to group results by")
    aggregation: Optional[str] = Field(
        default="sum", description="Aggregation function (sum, avg, count, etc.)"
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "metric_type": "alert_volume",
                "time_range": "last_7d",
                "filters": {"severity": "high"},
                "group_by": "alert_type",
                "aggregation": "count",
            }
        }
    )


class AnalyticsResponse(BaseModel):
    """Analytics query response."""

    metric_type: str = Field(..., description="Type of metric returned")
    time_range: TimeRange = Field(..., description="Time range of data")
    data: List[Dict[str, Any]] = Field(..., description="Metric data points")
    summary: Dict[str, Any] = Field(..., description="Summary statistics (avg, min, max, etc.)")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "metric_type": "alert_volume",
                "time_range": "last_24h",
                "data": [
                    {"timestamp": "2025-01-05T00:00:00Z", "value": 100},
                    {"timestamp": "2025-01-05T01:00:00Z", "value": 120},
                ],
                "summary": {"total": 2500, "average": 104.2, "min": 80, "max": 150},
            }
        }
    )


class DashboardData(BaseModel):
    """Complete dashboard data."""

    alert_metrics: AlertMetric
    triage_metrics: TriageMetric
    automation_metrics: AutomationMetric
    trends: Dict[str, List[TrendData]] = Field(
        default_factory=dict, description="Trend data for various metrics"
    )
    top_alerts: List[Dict[str, Any]] = Field(
        default_factory=list, description="Top alerts by various criteria"
    )
    generated_at: datetime = Field(
        default_factory=utc_now, description="When dashboard was generated"
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "alert_metrics": {},
                "triage_metrics": {},
                "automation_metrics": {},
                "trends": {
                    "alert_volume": [
                        {"timestamp": "2025-01-05T00:00:00Z", "value": 100, "label": "00:00"}
                    ]
                },
                "top_alerts": [{"alert_id": "ALT-001", "count": 50, "type": "malware"}],
                "generated_at": "2025-01-05T12:00:00Z",
            }
        }
    )
