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
Workflow and automation models.

This module defines models for workflow management, including
workflow states, tasks, and automation playbooks.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, Optional

from pydantic import BaseModel, ConfigDict, Field
from shared.utils.time import utc_now


class WorkflowStatus(str, Enum):
    """Workflow execution status."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"


class PlaybookStatus(str, Enum):
    """Backward-compatible playbook execution status."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"


class TaskStatus(str, Enum):
    """Task execution status."""

    PENDING = "pending"
    ASSIGNED = "assigned"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    CANCELLED = "cancelled"


class TaskPriority(str, Enum):
    """Task priority levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class WorkflowDefinition(BaseModel):
    """
    Workflow definition model.

    Attributes:
        workflow_id: Unique workflow identifier
        name: Workflow name
        description: Workflow description
        version: Workflow version
        steps: Workflow steps/activities
        timeout_seconds: Workflow timeout
    """

    workflow_id: str = Field(..., description="Unique workflow identifier")
    name: str = Field(..., min_length=1, max_length=200, description="Workflow name")
    description: str = Field(..., min_length=1, max_length=1000, description="Workflow description")
    version: str = Field(..., description="Workflow version")
    steps: list[dict[str, Any]] = Field(default_factory=list, description="Workflow steps")
    timeout_seconds: int = Field(default=3600, ge=0, description="Workflow timeout")

    # Configuration
    retry_policy: dict[str, Any] = Field(default_factory=dict, description="Retry policy")
    notification_settings: dict[str, Any] = Field(
        default_factory=dict, description="Notification settings"
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "workflow_id": "alert-processing",
                "name": "Alert Processing Workflow",
                "description": "Standard workflow for processing security alerts",
                "version": "1.0.0",
                "steps": [
                    {"name": "enrich", "type": "activity"},
                    {"name": "analyze", "type": "activity"},
                    {"name": "human_review", "type": "human_task"},
                ],
            }
        }
    )


class WorkflowExecution(BaseModel):
    """
    Workflow execution instance model.

    Attributes:
        execution_id: Unique execution identifier
        workflow_id: Workflow definition ID
        status: Execution status
        input: Workflow input parameters
        output: Workflow output (when completed)
        error: Error information (if failed)
        started_at: Execution start time
        completed_at: Execution completion time (if completed)
    """

    execution_id: str = Field(..., description="Unique execution identifier")
    workflow_id: str = Field(..., description="Workflow definition ID")
    status: WorkflowStatus = Field(..., description="Execution status")

    # Input/Output
    input: dict[str, Any] = Field(default_factory=dict, description="Workflow input parameters")
    output: Optional[dict[str, Any]] = Field(default=None, description="Workflow output")
    error: Optional[str] = Field(default=None, description="Error message if failed")

    # Timestamps
    started_at: datetime = Field(
        default_factory=utc_now, description="Execution start time"
    )
    completed_at: Optional[datetime] = Field(default=None, description="Execution completion time")

    # Progress
    current_step: Optional[str] = Field(default=None, description="Current step name")
    progress: float = Field(default=0.0, ge=0.0, le=1.0, description="Progress (0-1)")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "execution_id": "exec-abc-123",
                "workflow_id": "alert-processing",
                "status": "running",
                "input": {"alert_id": "ALT-001"},
                "started_at": "2025-01-05T12:00:00Z",
                "current_step": "analyze",
                "progress": 0.6,
            }
        }
    )


class HumanTask(BaseModel):
    """
    Human task model for workflows requiring human interaction.

    Attributes:
        task_id: Unique task identifier
        execution_id: Associated workflow execution
        task_type: Type of human task
        title: Task title
        description: Task description
        assigned_to: Assignee
        status: Task status
        priority: Task priority
        due_date: Task due date
        created_at: Task creation time
        completed_at: Task completion time
    """

    task_id: str = Field(..., description="Unique task identifier")
    execution_id: str = Field(..., description="Associated workflow execution")
    task_type: str = Field(..., description="Type of human task")
    title: str = Field(..., min_length=1, max_length=200, description="Task title")
    description: str = Field(..., min_length=1, max_length=2000, description="Task description")

    assigned_to: Optional[str] = Field(default=None, description="Task assignee")
    status: TaskStatus = Field(..., description="Task status")
    priority: TaskPriority = Field(..., description="Task priority")

    # Dates
    due_date: Optional[datetime] = Field(default=None, description="Task due date")
    created_at: datetime = Field(default_factory=utc_now, description="Task creation time")
    completed_at: Optional[datetime] = Field(default=None, description="Task completion time")

    # Task data
    input_data: dict[str, Any] = Field(default_factory=dict, description="Input data for task")
    output_data: dict[str, Any] = Field(default_factory=dict, description="Output data from task")

    # Notes
    notes: Optional[str] = Field(default=None, description="Task notes")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "task_id": "task-xyz-789",
                "execution_id": "exec-abc-123",
                "task_type": "alert_review",
                "title": "Review high-risk alert",
                "description": "Please review the following alert and confirm disposition",
                "assigned_to": "analyst@example.com",
                "status": "assigned",
                "priority": "high",
                "due_date": "2025-01-05T18:00:00Z",
            }
        }
    )


class PlaybookAction(BaseModel):
    """
    Single action within an automation playbook.

    Attributes:
        action_id: Unique action identifier
        action_type: Type of action
        name: Action name
        description: Action description
        parameters: Action parameters
        timeout_seconds: Action timeout
        retry_policy: Retry policy
    """

    action_id: str = Field(..., description="Unique action identifier")
    action_type: str = Field(..., description="Type of action")
    name: str = Field(default="action", min_length=1, max_length=200, description="Action name")
    description: str = Field(
        default="Automation action", min_length=1, max_length=1000, description="Action description"
    )

    # Configuration
    parameters: dict[str, Any] = Field(default_factory=dict, description="Action parameters")
    timeout_seconds: int = Field(default=300, ge=0, description="Action timeout")
    retry_policy: dict[str, Any] = Field(default_factory=dict, description="Retry policy")

    # Conditions
    conditions: list[dict[str, Any]] = Field(
        default_factory=list, description="Execution conditions"
    )
    status: Optional[str] = Field(default=None, description="Backward-compatible action status")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "action_id": "isolate-host",
                "action_type": "ssh_command",
                "name": "Isolate host from network",
                "description": "Execute firewall command to block host",
                "parameters": {
                    "command": "iptables -A INPUT -s 10.0.0.50 -j DROP",
                    "target_host": "10.0.0.50",
                },
                "timeout_seconds": 30,
            }
        }
    )


class AutomationPlaybook(BaseModel):
    """
    Automation playbook model.

    Attributes:
        playbook_id: Unique playbook identifier
        name: Playbook name
        description: Playbook description
        version: Playbook version
        actions: List of actions to execute
        approval_required: Whether approval is required
        timeout_seconds: Total timeout
    """

    playbook_id: str = Field(..., description="Unique playbook identifier")
    name: str = Field(..., min_length=1, max_length=200, description="Playbook name")
    description: str = Field(..., min_length=1, max_length=1000, description="Playbook description")
    version: str = Field(..., description="Playbook version")

    actions: list[PlaybookAction] = Field(
        ..., min_length=1, description="List of actions to execute"
    )

    # Configuration
    approval_required: bool = Field(default=False, description="Whether approval is required")
    timeout_seconds: int = Field(default=3600, ge=0, description="Total timeout")

    # Triggers
    trigger_conditions: dict[str, Any] = Field(
        default_factory=dict, description="Conditions that trigger playbook"
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "playbook_id": "malware-response",
                "name": "Malware Response Playbook",
                "description": "Automated response actions for malware alerts",
                "version": "1.0.0",
                "actions": [
                    {
                        "action_id": "isolate-host",
                        "action_type": "ssh_command",
                        "name": "Isolate infected host",
                        "description": "Disconnect host from network",
                    },
                    {
                        "action_id": "quarantine-file",
                        "action_type": "edr_command",
                        "name": "Quarantine malicious file",
                        "description": "Quarantine detected malicious file",
                    },
                ],
                "approval_required": True,
                "timeout_seconds": 600,
            }
        }
    )


class PlaybookExecution(BaseModel):
    """
    Playbook execution instance model.

    Attributes:
        execution_id: Unique execution identifier
        playbook_id: Playbook definition ID
        trigger_alert_id: Alert that triggered execution
        status: Execution status
        current_action: Currently executing action
        results: Action execution results
        started_at: Execution start time
        completed_at: Execution completion time
    """

    execution_id: str = Field(..., description="Unique execution identifier")
    playbook_id: str = Field(..., description="Playbook definition ID")
    trigger_alert_id: str = Field(..., description="Alert that triggered execution")
    status: PlaybookStatus = Field(..., description="Execution status")

    # Progress
    current_action_index: int = Field(default=0, ge=0, description="Current action index")
    current_action: Optional[str] = Field(default=None, description="Currently executing action")

    # Results
    results: list[dict[str, Any]] = Field(
        default_factory=list, description="Action execution results"
    )
    actions: list[PlaybookAction] = Field(
        default_factory=list, description="Backward-compatible actions snapshot"
    )
    input_data: Dict[str, Any] = Field(default_factory=dict, description="Execution input data")

    # Approval
    approval_status: Optional[str] = Field(
        default=None, description="Approval status (if required)"
    )
    approved_by: Optional[str] = Field(default=None, description="Who approved execution")

    # Timestamps
    started_at: datetime = Field(
        default_factory=utc_now, description="Execution start time"
    )
    completed_at: Optional[datetime] = Field(default=None, description="Execution completion time")

    # Error handling
    error: Optional[str] = Field(default=None, description="Error message if failed")
    rollback_performed: bool = Field(default=False, description="Whether rollback was performed")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "execution_id": "pb-exec-123",
                "playbook_id": "malware-response",
                "trigger_alert_id": "ALT-001",
                "status": "running",
                "current_action_index": 1,
                "current_action": "quarantine-file",
                "started_at": "2025-01-05T12:00:00Z",
            }
        }
    )
