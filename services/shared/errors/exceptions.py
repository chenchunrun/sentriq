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
Custom exception classes for the security triage system.

All exceptions inherit from SecurityTriageError for consistent error handling.
"""

from typing import Any, Optional


class SecurityTriageError(Exception):
    """
    Base exception for all security triage system errors.

    Attributes:
        message: Human-readable error message
        code: Error code for API responses
        details: Additional error details (optional)
    """

    def __init__(
        self,
        message: str,
        code: Optional[str] = None,
        details: Optional[dict[str, Any]] = None,
    ):
        self.message = message
        self.code = code or self.__class__.__name__.upper()
        self.details = details or {}
        super().__init__(self.message)

    def to_dict(self) -> dict[str, Any]:
        """Convert exception to dictionary for API responses."""
        return {
            "code": self.code,
            "message": self.message,
            "details": self.details,
        }


class ValidationError(SecurityTriageError):
    """Raised when input validation fails."""

    def __init__(
        self,
        message: str,
        field: Optional[str] = None,
        details: Optional[dict[str, Any]] = None,
    ):
        if field and details is None:
            details = {"field": field}
        elif field and details:
            details["field"] = field

        super().__init__(message, code="VALIDATION_ERROR", details=details)


class AuthenticationError(SecurityTriageError):
    """Raised when authentication fails."""

    def __init__(
        self,
        message: str = "Authentication failed",
        details: Optional[dict[str, Any]] = None,
    ):
        super().__init__(message, code="AUTHENTICATION_ERROR", details=details)


class AuthorizationError(SecurityTriageError):
    """Raised when user lacks permission for an action."""

    def __init__(
        self,
        message: str = "Permission denied",
        required_permission: Optional[str] = None,
        details: Optional[dict[str, Any]] = None,
    ):
        if required_permission and details is None:
            details = {"required_permission": required_permission}
        elif required_permission and details:
            details["required_permission"] = required_permission

        super().__init__(message, code="AUTHORIZATION_ERROR", details=details)


class NotFoundError(SecurityTriageError):
    """Raised when a resource is not found."""

    def __init__(
        self,
        message: str,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        details: Optional[dict[str, Any]] = None,
    ):
        if details is None:
            details = {}
        if resource_type:
            details["resource_type"] = resource_type
        if resource_id:
            details["resource_id"] = resource_id

        super().__init__(message, code="NOT_FOUND", details=details)


class ConflictError(SecurityTriageError):
    """Raised when a resource conflict occurs."""

    def __init__(
        self,
        message: str,
        details: Optional[dict[str, Any]] = None,
    ):
        super().__init__(message, code="CONFLICT", details=details)


class RateLimitError(SecurityTriageError):
    """Raised when rate limit is exceeded."""

    def __init__(
        self,
        message: str = "Rate limit exceeded",
        limit: Optional[int] = None,
        window: Optional[str] = None,
        details: Optional[dict[str, Any]] = None,
    ):
        if details is None:
            details = {}
        if limit:
            details["limit"] = limit
        if window:
            details["window"] = window

        super().__init__(message, code="RATE_LIMIT_EXCEEDED", details=details)


class ServiceUnavailableError(SecurityTriageError):
    """Raised when a service is unavailable."""

    def __init__(
        self,
        message: str = "Service temporarily unavailable",
        service_name: Optional[str] = None,
        details: Optional[dict[str, Any]] = None,
    ):
        if service_name and details is None:
            details = {"service": service_name}
        elif service_name and details:
            details["service"] = service_name

        super().__init__(message, code="SERVICE_UNAVAILABLE", details=details)


class DatabaseError(SecurityTriageError):
    """Raised when a database operation fails."""

    def __init__(
        self,
        message: str,
        query: Optional[str] = None,
        details: Optional[dict[str, Any]] = None,
    ):
        if query and details is None:
            details = {"query": query}
        elif query and details:
            details["query"] = query

        super().__init__(message, code="DATABASE_ERROR", details=details)


class MessageQueueError(SecurityTriageError):
    """Raised when a message queue operation fails."""

    def __init__(
        self,
        message: str,
        queue_name: Optional[str] = None,
        details: Optional[dict[str, Any]] = None,
    ):
        if queue_name and details is None:
            details = {"queue": queue_name}
        elif queue_name and details:
            details["queue"] = queue_name

        super().__init__(message, code="MESSAGE_QUEUE_ERROR", details=details)


class WorkflowError(SecurityTriageError):
    """Raised when a workflow operation fails."""

    def __init__(
        self,
        message: str,
        workflow_id: Optional[str] = None,
        details: Optional[dict[str, Any]] = None,
    ):
        if workflow_id and details is None:
            details = {"workflow_id": workflow_id}
        elif workflow_id and details:
            details["workflow_id"] = workflow_id

        super().__init__(message, code="WORKFLOW_ERROR", details=details)


class AutomationError(SecurityTriageError):
    """Raised when an automation/playbook operation fails."""

    def __init__(
        self,
        message: str,
        playbook_id: Optional[str] = None,
        details: Optional[dict[str, Any]] = None,
    ):
        if playbook_id and details is None:
            details = {"playbook_id": playbook_id}
        elif playbook_id and details:
            details["playbook_id"] = playbook_id

        super().__init__(message, code="AUTOMATION_ERROR", details=details)


class LLMError(SecurityTriageError):
    """Raised when an LLM operation fails."""

    def __init__(
        self,
        message: str,
        model: Optional[str] = None,
        provider: Optional[str] = None,
        details: Optional[dict[str, Any]] = None,
    ):
        if details is None:
            details = {}
        if model:
            details["model"] = model
        if provider:
            details["provider"] = provider

        super().__init__(message, code="LLM_ERROR", details=details)
