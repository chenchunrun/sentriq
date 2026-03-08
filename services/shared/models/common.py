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
Common models for API responses and pagination.

These models are used across all services for consistent API responses.
"""

from datetime import datetime
from typing import Any, Generic, Optional, TypeVar

from pydantic import BaseModel, ConfigDict, Field
from shared.utils.time import utc_now

T = TypeVar("T")


class SuccessResponse(BaseModel, Generic[T]):
    """
    Standard success response format.

    Attributes:
        success: Always true for success responses
        data: Response payload (generic type)
        meta: Metadata about the response
    """

    success: bool = Field(default=True, description="Indicates successful response")
    data: T = Field(..., description="Response payload")
    meta: "ResponseMeta" = Field(..., description="Response metadata")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "success": True,
                "data": {"id": "abc-123"},
                "meta": {"timestamp": "2025-01-05T12:00:00Z", "request_id": "req-abc-123"},
            }
        }
    )


class ErrorResponse(BaseModel):
    """
    Standard error response format.

    Attributes:
        success: Always false for error responses
        error: Error details
        meta: Metadata about the response
    """

    success: bool = Field(default=False, description="Indicates error response")
    error: "ErrorDetail" = Field(..., description="Error details")
    meta: "ResponseMeta" = Field(..., description="Response metadata")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "success": False,
                "error": {
                    "code": "VALIDATION_ERROR",
                    "message": "Validation failed",
                    "details": {"field": "alert_id", "reason": "Field is required"},
                },
                "meta": {"timestamp": "2025-01-05T12:00:00Z", "request_id": "req-abc-123"},
            }
        }
    )


class ErrorDetail(BaseModel):
    """Error detail information."""

    code: str = Field(..., description="Error code")
    message: str = Field(..., description="Human-readable error message")
    details: Optional[dict[str, Any]] = Field(default=None, description="Additional error details")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "code": "VALIDATION_ERROR",
                "message": "Validation failed",
                "details": {"field": "alert_id"},
            }
        }
    )


class ResponseMeta(BaseModel):
    """
    Response metadata.

    Attributes:
        timestamp: Response timestamp (ISO 8601)
        request_id: Unique request identifier
        version: API version (optional)
    """

    timestamp: datetime = Field(
        default_factory=utc_now, description="Response timestamp in ISO 8601 format"
    )
    request_id: str = Field(..., description="Unique request identifier")
    version: Optional[str] = Field(default=None, description="API version")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "timestamp": "2025-01-05T12:00:00Z",
                "request_id": "req-abc-123",
                "version": "1.0.0",
            }
        }
    )


class PaginatedResponse(BaseModel, Generic[T]):
    """
    Generic paginated response.

    Attributes:
        total: Total number of items
        page: Current page number (1-indexed)
        page_size: Number of items per page
        total_pages: Total number of pages
        items: List of items for current page
    """

    total: int = Field(..., ge=0, description="Total number of items")
    page: int = Field(..., ge=1, description="Current page number (1-indexed)")
    page_size: int = Field(..., ge=1, le=100, description="Number of items per page")
    total_pages: int = Field(..., ge=0, description="Total number of pages")
    items: list[T] = Field(..., description="List of items for current page")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {"total": 1000, "page": 1, "page_size": 20, "total_pages": 50, "items": []}
        }
    )


class HealthStatus(BaseModel):
    """
    Health check response.

    Attributes:
        status: Overall health status (healthy, degraded, unhealthy)
        timestamp: Check timestamp
        checks: Individual service checks
    """

    status: str = Field(
        ..., description="Overall health status", pattern="^(healthy|degraded|unhealthy)$"
    )
    timestamp: datetime = Field(default_factory=utc_now)
    checks: dict[str, dict[str, Any]] = Field(
        default_factory=dict, description="Individual service checks"
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "status": "healthy",
                "timestamp": "2025-01-05T12:00:00Z",
                "checks": {
                    "database": {"status": "healthy"},
                    "redis": {"status": "healthy"},
                    "rabbitmq": {"status": "healthy"},
                },
            }
        }
    )
