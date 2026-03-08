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
Shared data models for all microservices.

This package contains common Pydantic models used across all services
in the security triage system.
"""

# Alert models
from .alert import (
    AlertBatch,
    AlertFilter,
    AlertStatus,
    AlertType,
    AlertUpdate,
    SecurityAlert,
    Severity,
)

# Analytics models
from .analytics import (
    AlertMetric,
    AnalyticsQuery,
    AnalyticsResponse,
    AutomationMetric,
    DashboardData,
    MetricType,
    TimeRange,
    TrendData,
    TriageMetric,
)

# Common models
from .common import (
    ErrorDetail,
    ErrorResponse,
    HealthStatus,
    PaginatedResponse,
    ResponseMeta,
    SuccessResponse,
)

# Context models
from .context import (
    AssetContext,
    EnrichedContext,
    NetworkContext,
    UserContext,
)

# LLM models
from .llm import (
    LLMChoice,
    LLMMessage,
    LLMModel,
    LLMProvider,
    LLMRequest,
    LLMResponse,
    LLMUsage,
    ModelCapabilities,
    RouterDecision,
    TaskType,
)

# Risk assessment models
from .risk import (
    ActionType,
    RemediationAction,
    RemediationPriority,
    RiskAssessment,
    RiskLevel,
    TriageResult,
)

# Threat intelligence models
from .threat_intel import (
    AggregatedThreatIntel,
    IntelSource,
    IOCType,
    ThreatIntel,
    ThreatIntelQuery,
    ThreatLevel,
)

# Vector search models
from .vector import (
    EmbeddingModel,
    EmbeddingRequest,
    EmbeddingResponse,
    IndexStats,
    SimilarAlert,
    VectorSearchRequest,
    VectorSearchResponse,
)

# Workflow models
from .workflow import (
    AutomationPlaybook,
    HumanTask,
    PlaybookAction,
    PlaybookExecution,
    PlaybookStatus,
    TaskPriority,
    TaskStatus,
    WorkflowDefinition,
    WorkflowExecution,
    WorkflowStatus,
)

__all__ = [
    # Common
    "SuccessResponse",
    "ErrorResponse",
    "ErrorDetail",
    "ResponseMeta",
    "PaginatedResponse",
    "HealthStatus",
    # Alert
    "AlertType",
    "Severity",
    "AlertStatus",
    "SecurityAlert",
    "AlertUpdate",
    "AlertBatch",
    "AlertFilter",
    # Threat Intel
    "IOCType",
    "ThreatLevel",
    "IntelSource",
    "ThreatIntel",
    "ThreatIntelQuery",
    "AggregatedThreatIntel",
    # Context
    "NetworkContext",
    "AssetContext",
    "UserContext",
    "EnrichedContext",
    # Risk
    "RiskLevel",
    "RemediationPriority",
    "ActionType",
    "RemediationAction",
    "RiskAssessment",
    "TriageResult",
    # Workflow
    "WorkflowStatus",
    "TaskStatus",
    "TaskPriority",
    "WorkflowDefinition",
    "WorkflowExecution",
    "HumanTask",
    "PlaybookAction",
    "AutomationPlaybook",
    "PlaybookExecution",
    "PlaybookStatus",
    # LLM
    "LLMProvider",
    "LLMModel",
    "TaskType",
    "LLMRequest",
    "LLMResponse",
    "LLMMessage",
    "LLMChoice",
    "LLMUsage",
    "RouterDecision",
    "ModelCapabilities",
    # Vector Search
    "EmbeddingModel",
    "SimilarAlert",
    "VectorSearchRequest",
    "VectorSearchResponse",
    "EmbeddingRequest",
    "EmbeddingResponse",
    "IndexStats",
    # Analytics
    "MetricType",
    "TimeRange",
    "AlertMetric",
    "TriageMetric",
    "AutomationMetric",
    "TrendData",
    "AnalyticsQuery",
    "AnalyticsResponse",
    "DashboardData",
]
