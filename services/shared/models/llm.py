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
LLM (Large Language Model) related models.

This module defines models for LLM requests, responses, and routing.
"""

from enum import Enum
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


class LLMProvider(str, Enum):
    """Available LLM providers."""

    DEEPSEEK = "deepseek"
    QWEN = "qwen"
    ZHIPU = "zhipu"


class LLMModel(str, Enum):
    """Available LLM models."""

    # DeepSeek models
    DEEPSEEK_V3 = "deepseek-v3"
    DEEPSEEK_CODER = "deepseek-coder"

    # Qwen models
    QWEN3_MAX = "qwen3-max"
    QWEN3_PLUS = "qwen3-plus"
    QWEN3_TURBO = "qwen3-turbo"

    # Zhipu (GLM) models
    ZHIPU_GLM_4 = "glm-4"
    ZHIPU_GLM_4_PLUS = "glm-4-plus"
    ZHIPU_GLM_4_AIR = "glm-4-air"


class TaskType(str, Enum):
    """Types of tasks for routing decisions."""

    TRIAGE = "triage"  # Security alert triage
    ANALYSIS = "analysis"  # Deep analysis and reasoning
    SUMMARIZATION = "summarization"  # Summarize findings
    CLASSIFICATION = "classification"  # Simple classification
    CODE_REVIEW = "code_review"  # Code-based analysis
    GENERAL = "general"  # General purpose


class LLMRequest(BaseModel):
    """
    Standard LLM request model.

    Attributes:
        task_type: Type of task for routing
        messages: Chat messages (role, content)
        model: Specific model to use (optional, router will decide)
        temperature: Sampling temperature (0.0-1.0)
        max_tokens: Maximum tokens to generate
        top_p: Nucleus sampling parameter
        stream: Whether to stream responses
        metadata: Additional context for routing
    """

    task_type: TaskType = Field(
        default=TaskType.GENERAL, description="Type of task to help with routing decisions"
    )
    messages: List[Dict[str, str]] = Field(
        ..., min_length=1, description="Chat messages with role and content"
    )
    model: Optional[LLMModel] = Field(
        default=None,
        description="Specific model to use (optional, router decides if not specified)",
    )
    temperature: float = Field(default=0.7, ge=0.0, le=1.0, description="Sampling temperature")
    max_tokens: int = Field(default=2000, ge=1, le=32000, description="Maximum tokens to generate")
    top_p: float = Field(default=0.9, ge=0.0, le=1.0, description="Nucleus sampling parameter")
    stream: bool = Field(default=False, description="Whether to stream the response")
    metadata: Optional[Dict[str, Any]] = Field(
        default=None, description="Additional context for routing decisions"
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "task_type": "triage",
                "messages": [
                    {"role": "system", "content": "You are a security analyst."},
                    {"role": "user", "content": "Analyze this alert..."},
                ],
                "temperature": 0.7,
                "max_tokens": 2000,
            }
        }
    )


class LLMMessage(BaseModel):
    """A single message in a chat conversation."""

    role: str = Field(..., description="Message role (system, user, assistant)")
    content: str = Field(..., description="Message content")


class LLMChoice(BaseModel):
    """A single choice in LLM response."""

    index: int = Field(..., description="Choice index")
    message: LLMMessage = Field(..., description="Message content")
    finish_reason: Optional[str] = Field(
        default=None, description="Reason for finishing (stop, length, etc.)"
    )


class LLMUsage(BaseModel):
    """Token usage information."""

    prompt_tokens: int = Field(..., ge=0, description="Tokens in prompt")
    completion_tokens: int = Field(..., ge=0, description="Tokens in completion")
    total_tokens: int = Field(..., ge=0, description="Total tokens used")


class LLMResponse(BaseModel):
    """
    Standard LLM response model.

    Attributes:
        id: Response ID
        object: Object type (chat.completion)
        created: Creation timestamp
        model: Model used for generation
        provider: Provider that handled the request
        choices: List of choices (usually one)
        usage: Token usage statistics
        routing_decision: Information about routing decision
    """

    id: str = Field(..., description="Response ID")
    object: str = Field(default="chat.completion", description="Object type")
    created: int = Field(..., description="Creation timestamp (Unix timestamp)")
    model: LLMModel = Field(..., description="Model used")
    provider: LLMProvider = Field(..., description="Provider that handled request")
    choices: List[LLMChoice] = Field(..., min_length=1, description="Response choices")
    usage: LLMUsage = Field(..., description="Token usage")
    routing_decision: Optional[Dict[str, Any]] = Field(
        default=None, description="Routing decision details"
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "id": "chatcmpl-123",
                "object": "chat.completion",
                "created": 1677652288,
                "model": "deepseek-v3",
                "provider": "deepseek",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "Based on the analysis..."},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150},
                "routing_decision": {
                    "selected_model": "deepseek-v3",
                    "reason": "high_complexity",
                    "fallback_used": False,
                },
            }
        }
    )


class RouterDecision(BaseModel):
    """
    Routing decision details.

    Attributes:
        selected_provider: Chosen provider
        selected_model: Chosen model
        reason: Reason for this choice
        confidence: Confidence in decision (0-1)
        fallback_used: Whether fallback was triggered
        alternatives: Alternative models considered
    """

    selected_provider: LLMProvider = Field(..., description="Selected provider")
    selected_model: LLMModel = Field(..., description="Selected model")
    reason: str = Field(..., description="Reason for selection")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence in decision")
    fallback_used: bool = Field(default=False, description="Whether fallback was triggered")
    alternatives: List[LLMModel] = Field(
        default_factory=list, description="Alternative models considered"
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "selected_provider": "deepseek",
                "selected_model": "deepseek-v3",
                "reason": "High complexity task requiring advanced reasoning",
                "confidence": 0.9,
                "fallback_used": False,
                "alternatives": ["qwen3-max"],
            }
        }
    )


class ModelCapabilities(BaseModel):
    """
    Model capabilities for routing decisions.

    Attributes:
        model: Model identifier
        max_context: Maximum context window
        supports_streaming: Whether streaming is supported
        cost_per_1k_tokens: Cost per 1000 tokens
        speed: Relative speed (1-10)
        reasoning_quality: Quality of reasoning (1-10)
        best_for: Tasks this model is best for
    """

    model: LLMModel = Field(..., description="Model identifier")
    max_context: int = Field(..., ge=1, description="Maximum context window")
    supports_streaming: bool = Field(..., description="Whether model supports streaming")
    cost_per_1k_tokens: float = Field(..., ge=0.0, description="Cost per 1000 tokens in USD")
    speed: int = Field(..., ge=1, le=10, description="Relative speed (1=slowest, 10=fastest)")
    reasoning_quality: int = Field(
        ..., ge=1, le=10, description="Reasoning quality (1=lowest, 10=highest)"
    )
    best_for: List[TaskType] = Field(..., description="Tasks this model is best suited for")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "model": "deepseek-v3",
                "max_context": 32000,
                "supports_streaming": True,
                "cost_per_1k_tokens": 0.002,
                "speed": 8,
                "reasoning_quality": 9,
                "best_for": ["triage", "analysis", "code_review"],
            }
        }
    )
