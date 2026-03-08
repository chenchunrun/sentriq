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

"""Workflow Engine Service - Manages workflow definitions and executions."""

import asyncio
import json
import uuid
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Any, Dict, List, Optional

from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import text
from shared.database import DatabaseManager, close_database, get_database_manager, init_database
from shared.errors import WorkflowError
from shared.messaging import MessageConsumer, MessagePublisher
from shared.models import (
    HumanTask,
    ResponseMeta,
    SuccessResponse,
    TaskPriority,
    TaskStatus,
    WorkflowDefinition,
    WorkflowExecution,
    WorkflowStatus,
)
from shared.utils import Config, get_logger
from shared.utils.time import utc_now, utc_now_iso

temporal_import_error = None
try:
    from temporalio.client import Client as TemporalClient
    from temporalio.worker import Worker as TemporalWorker
    try:
        from .temporal_workflows import SecurityWorkflow, execute_step_activity
    except ImportError:
        from temporal_workflows import SecurityWorkflow, execute_step_activity
except Exception as exc:  # pragma: no cover - optional dependency path
    TemporalClient = None
    TemporalWorker = None
    SecurityWorkflow = None
    execute_step_activity = None
    temporal_import_error = exc

logger = get_logger(__name__)
config = Config()

db_manager: DatabaseManager = None
publisher: MessagePublisher = None
consumer: MessageConsumer = None
temporal_client = None
temporal_worker = None

# In-memory workflow execution storage (use database in production)
active_executions: Dict[str, WorkflowExecution] = {}
workflow_definitions: Dict[str, WorkflowDefinition] = {}

# Load default workflow definitions
DEFAULT_WORKFLOWS = {
    "alert-processing": WorkflowDefinition(
        workflow_id="alert-processing",
        name="Alert Processing Workflow",
        description="Standard workflow for processing security alerts",
        version="1.0.0",
        steps=[
            {
                "name": "enrich",
                "type": "activity",
                "description": "Enrich alert with context",
                "service": "context_collector",
            },
            {
                "name": "analyze",
                "type": "activity",
                "description": "AI triage analysis",
                "service": "ai_triage_agent",
            },
            {
                "name": "auto_response",
                "type": "decision",
                "description": "Check if auto-response is needed",
                "condition": "${risk_level == 'CRITICAL' or risk_level == 'HIGH'}",
            },
            {
                "name": "human_review",
                "type": "human_task",
                "description": "Security analyst review",
                "assignee": "security-team",
            },
        ],
        timeout_seconds=3600,
    ),
    "incident-response": WorkflowDefinition(
        workflow_id="incident-response",
        name="Incident Response Workflow",
        description="Workflow for handling security incidents",
        version="1.0.0",
        steps=[
            {"name": "assess", "type": "activity", "description": "Initial incident assessment"},
            {"name": "contain", "type": "activity", "description": "Contain the threat"},
            {"name": "eradicate", "type": "activity", "description": "Eradicate threat"},
            {"name": "recover", "type": "activity", "description": "Recover systems"},
        ],
        timeout_seconds=7200,
    ),
}


class WorkflowExecuteRequest(BaseModel):
    workflow_id: str
    input_data: Dict[str, Any] = Field(default_factory=dict)


async def seed_default_workflows():
    """Persist default workflows into database if missing."""
    async with db_manager.get_session() as session:
        for wf in DEFAULT_WORKFLOWS.values():
            await session.execute(
                text(
                    """
                    INSERT INTO workflows (workflow_id, name, description, category, trigger_type,
                                           trigger_conditions, status, priority, steps, created_by)
                    VALUES (:workflow_id, :name, :description, :category, :trigger_type,
                            CAST(:trigger_conditions AS jsonb), :status, :priority, CAST(:steps AS jsonb), :created_by)
                    ON CONFLICT (workflow_id) DO UPDATE SET
                        name = EXCLUDED.name,
                        description = EXCLUDED.description,
                        category = EXCLUDED.category,
                        trigger_type = EXCLUDED.trigger_type,
                        trigger_conditions = EXCLUDED.trigger_conditions,
                        status = EXCLUDED.status,
                        priority = EXCLUDED.priority,
                        steps = EXCLUDED.steps,
                        updated_at = NOW()
                    """
                ),
                {
                    "workflow_id": wf.workflow_id,
                    "name": wf.name,
                    "description": wf.description,
                    "category": "incident",
                    "trigger_type": "manual",
                    "trigger_conditions": json.dumps({}),
                    "status": "active",
                    "priority": "medium",
                    "steps": json.dumps(wf.steps),
                    "created_by": "system",
                },
            )
        await session.commit()


async def load_workflows_from_db() -> Dict[str, WorkflowDefinition]:
    """Load workflow definitions from database."""
    workflows: Dict[str, WorkflowDefinition] = {}
    async with db_manager.get_session() as session:
        result = await session.execute(
            text(
                """
                SELECT workflow_id, name, description, steps, status
                FROM workflows
                WHERE status != 'archived'
                """
            )
        )
        rows = result.fetchall()

    for row in rows:
        workflows[row.workflow_id] = WorkflowDefinition(
            workflow_id=row.workflow_id,
            name=row.name,
            description=row.description,
            version="1.0.0",
            steps=row.steps or [],
            timeout_seconds=3600,
        )

    return workflows


async def persist_workflow_execution(execution: WorkflowExecution):
    """Persist workflow execution state to database."""
    async with db_manager.get_session() as session:
        await session.execute(
            text(
                """
                INSERT INTO workflow_executions (execution_id, workflow_id, trigger_type,
                                                 trigger_reference, status, started_at,
                                                 completed_at, duration_seconds, steps_execution,
                                                 result, error_message, executed_by)
                VALUES (:execution_id, :workflow_id, :trigger_type, :trigger_reference, :status,
                        :started_at, :completed_at, :duration_seconds, CAST(:steps_execution AS jsonb),
                        :result, :error_message, :executed_by)
                ON CONFLICT (execution_id) DO UPDATE SET
                    status = EXCLUDED.status,
                    completed_at = EXCLUDED.completed_at,
                    duration_seconds = EXCLUDED.duration_seconds,
                    steps_execution = EXCLUDED.steps_execution,
                    result = EXCLUDED.result,
                    error_message = EXCLUDED.error_message
                """
            ),
            {
                "execution_id": execution.execution_id,
                "workflow_id": execution.workflow_id,
                "trigger_type": "manual",
                "trigger_reference": execution.input.get("alert_id"),
                "status": execution.status.value,
                "started_at": execution.started_at,
                "completed_at": execution.completed_at,
                "duration_seconds": None,
                "steps_execution": json.dumps(
                    {"current_step": execution.current_step, "progress": execution.progress}
                ),
                "result": json.dumps(execution.output) if execution.output else None,
                "error_message": execution.error,
                "executed_by": "system",
            },
        )
        await session.commit()


async def persist_human_task(task: HumanTask):
    """Persist human task to database."""
    async with db_manager.get_session() as session:
        await session.execute(
            text(
                """
                INSERT INTO human_tasks (task_id, execution_id, task_type, title, description,
                                         assigned_to, status, priority, due_date,
                                         input_data, output_data, notes)
                VALUES (:task_id, :execution_id, :task_type, :title, :description,
                        :assigned_to, :status, :priority, :due_date,
                        CAST(:input_data AS jsonb), CAST(:output_data AS jsonb), :notes)
                ON CONFLICT (task_id) DO UPDATE SET
                    status = EXCLUDED.status,
                    output_data = EXCLUDED.output_data,
                    notes = EXCLUDED.notes,
                    completed_at = CASE
                        WHEN EXCLUDED.status = 'completed' THEN NOW()
                        ELSE human_tasks.completed_at
                    END
                """
            ),
            {
                "task_id": task.task_id,
                "execution_id": task.execution_id,
                "task_type": task.task_type,
                "title": task.title,
                "description": task.description,
                "assigned_to": task.assigned_to,
                "status": task.status.value,
                "priority": task.priority.value,
                "due_date": task.due_date,
                "input_data": json.dumps(task.input_data or {}),
                "output_data": json.dumps(task.output_data or {}),
                "notes": task.notes,
            },
        )
        await session.commit()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifespan."""
    global db_manager, publisher, consumer, workflow_definitions, temporal_client, temporal_worker

    logger.info("Starting Workflow Engine service...")

    # Initialize database
    import os
    await init_database(
        database_url=config.database_url,
        pool_size=int(os.getenv("DB_POOL_SIZE", "10")),
        max_overflow=int(os.getenv("DB_MAX_OVERFLOW", "20")),
        echo=config.debug,
    )
    db_manager = get_database_manager()

    # Initialize messaging
    publisher = MessagePublisher(config.rabbitmq_url)
    await publisher.connect()

    consumer = MessageConsumer(config.rabbitmq_url, "workflow.trigger")
    await consumer.connect()

    # Load workflow definitions
    await seed_default_workflows()
    workflow_definitions.update(await load_workflows_from_db())

    if config.temporal_enabled and TemporalClient and TemporalWorker:
        try:
            temporal_client = await TemporalClient.connect(
                config.temporal_server_url,
                namespace=config.temporal_namespace,
            )
            temporal_worker = TemporalWorker(
                temporal_client,
                task_queue=config.temporal_task_queue,
                workflows=[SecurityWorkflow],
                activities=[execute_step_activity],
            )
            asyncio.create_task(temporal_worker.run())
            logger.info(
                f"Temporal worker connected (server={config.temporal_server_url}, task_queue={config.temporal_task_queue})"
            )
        except Exception as e:
            temporal_client = None
            temporal_worker = None
            logger.warning(f"Temporal unavailable, falling back to local execution: {e}")
    elif config.temporal_enabled:
        logger.warning(f"Temporal enabled but client unavailable: {temporal_import_error}")
    else:
        logger.info("Temporal execution disabled; using local workflow executor")

    # Start consuming workflow triggers
    asyncio.create_task(consume_workflow_triggers())

    # Start background task to monitor active executions
    asyncio.create_task(monitor_executions())

    logger.info("Workflow Engine service started successfully")

    yield

    # Cleanup
    await consumer.close()
    await publisher.close()
    await close_database()
    logger.info("Workflow Engine service stopped")


app = FastAPI(
    title="Workflow Engine Service",
    description="Manages workflow definitions and executions",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


async def execute_workflow_step(
    execution: WorkflowExecution, step: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Execute a single workflow step.

    Supports:
    - activity: Service call
    - human_task: Create human task
    - decision: Conditional branching
    """
    step_type = step.get("type")
    step_name = step.get("name")

    logger.info(f"Executing step {step_name} (type: {step_type})")

    try:
        if step_type == "activity":
            # Execute service activity
            service = step.get("service")
            if service:
                # Publish message to service
                await publisher.publish(
                    f"workflow.{service}",
                    {
                        "message_id": str(uuid.uuid4()),
                        "message_type": "workflow.activity",
                        "payload": {
                            "execution_id": execution.execution_id,
                            "step": step_name,
                            "input": execution.input,
                        },
                        "timestamp": utc_now_iso(),
                    },
                )
                return {"status": "completed", "output": {}}

        elif step_type == "human_task":
            # Create human task
            task = HumanTask(
                task_id=f"task-{uuid.uuid4()}",
                execution_id=execution.execution_id,
                task_type=step.get("task_type", "manual_review"),
                title=step.get("title", f"Complete task: {step_name}"),
                description=step.get("description", ""),
                assigned_to=step.get("assignee", "security-team"),
                status=TaskStatus.ASSIGNED,
                priority=TaskPriority.MEDIUM,
                input_data=execution.input.copy(),
            )

            await persist_human_task(task)

            # Notify assignee via notification service
            await publisher.publish(
                "notifications.send",
                {
                    "message_id": str(uuid.uuid4()),
                    "message_type": "notification.request",
                    "payload": {
                        "channel": "in_app",
                        "recipient": task.assigned_to or "security-team",
                        "subject": task.title,
                        "message": task.description,
                        "priority": task.priority.value,
                        "data": {
                            "task_id": task.task_id,
                            "execution_id": task.execution_id,
                            "task_type": task.task_type,
                        },
                    },
                    "timestamp": utc_now_iso(),
                },
            )

            return {
                "status": "pending",
                "task_id": task.task_id,
                "message": "Human task created, awaiting completion",
            }

        elif step_type == "decision":
            # Evaluate condition
            condition = step.get("condition", "")
            # Simple condition evaluation (use proper expression parser in production)
            if "risk_level" in execution.input:
                risk_level = execution.input.get("risk_level", "").upper()
                if risk_level in ["CRITICAL", "HIGH"]:
                    return {"status": "continue", "decision": True}
                else:
                    return {"status": "skip", "decision": False}

        return {"status": "completed"}

    except Exception as e:
        logger.error(f"Step execution failed: {e}", exc_info=True)
        return {"status": "failed", "error": str(e)}


async def execute_workflow(execution: WorkflowExecution, start_index: int = 0):
    """
    Execute workflow steps sequentially.

    Args:
        execution: Workflow execution instance
    """
    try:
        workflow_def = workflow_definitions.get(execution.workflow_id)
        if not workflow_def:
            raise WorkflowError(f"Workflow definition not found: {execution.workflow_id}")

        execution.status = WorkflowStatus.RUNNING
        active_executions[execution.execution_id] = execution

        # Execute each step
        for i, step in enumerate(workflow_def.steps[start_index:], start=start_index):
            execution.current_step = step.get("name")
            execution.progress = i / len(workflow_def.steps)

            result = await execute_workflow_step(execution, step)

            if result.get("status") == "failed":
                execution.status = WorkflowStatus.FAILED
                execution.error = result.get("error", "Step execution failed")
                execution.completed_at = utc_now()
                break

            elif result.get("status") == "pending":
                # Waiting for human task or external action
                execution.status = WorkflowStatus.PENDING
                await persist_workflow_execution(execution)
                break

        # If all steps completed
        if execution.status == WorkflowStatus.RUNNING:
            execution.status = WorkflowStatus.COMPLETED
            execution.completed_at = utc_now()
            execution.progress = 1.0
            execution.output = {"message": "Workflow completed successfully"}

        # Publish completion event
        await publisher.publish(
            "workflow.completed",
            {
                "message_id": str(uuid.uuid4()),
                "message_type": "workflow.completed",
                "payload": execution.model_dump(),
                "timestamp": utc_now_iso(),
            },
        )

        await persist_workflow_execution(execution)

        logger.info(
            f"Workflow execution {execution.execution_id} completed: {execution.status.value}"
        )

    except Exception as e:
        logger.error(f"Workflow execution failed: {e}", exc_info=True)
        execution.status = WorkflowStatus.FAILED
        execution.error = str(e)
        execution.completed_at = utc_now()
        await persist_workflow_execution(execution)


async def consume_workflow_triggers():
    """Consume workflow trigger messages from queue."""

    async def process_message(message: dict):
        try:
            payload = message["payload"]
            workflow_id = payload.get("workflow_id")
            input_data = payload.get("input", {})

            if not workflow_id:
                logger.error("Missing workflow_id in trigger message")
                return

            # Start workflow execution
            execution = await start_workflow_execution(workflow_id, input_data)
            logger.info(f"Started workflow execution {execution.execution_id}")

        except Exception as e:
            logger.error(f"Failed to process workflow trigger: {e}", exc_info=True)

    await consumer.consume(process_message)


async def start_temporal_execution(execution: WorkflowExecution, workflow_def: WorkflowDefinition) -> None:
    """Start execution via Temporal and mirror initial state to the database."""
    handle = await temporal_client.start_workflow(
        SecurityWorkflow.run,
        args=[workflow_def.workflow_id, execution.execution_id, workflow_def.steps, input_data_for_temporal(execution)],
        id=execution.execution_id,
        task_queue=config.temporal_task_queue,
    )
    execution.status = WorkflowStatus.RUNNING
    execution.output = {"temporal_run_id": handle.first_execution_run_id}
    active_executions[execution.execution_id] = execution
    await persist_workflow_execution(execution)
    asyncio.create_task(track_temporal_execution(handle, execution.execution_id))


def input_data_for_temporal(execution: WorkflowExecution) -> Dict[str, Any]:
    """Return workflow input payload for Temporal execution."""
    return execution.input.copy() if execution.input else {}


async def track_temporal_execution(handle, execution_id: str) -> None:
    """Track Temporal workflow completion and mirror final state locally."""
    execution = active_executions.get(execution_id)
    if not execution:
        return

    try:
        result = await handle.result()
        execution.status = WorkflowStatus.COMPLETED
        execution.completed_at = utc_now()
        execution.progress = 1.0
        execution.output = result
    except Exception as e:
        execution.status = WorkflowStatus.FAILED
        execution.completed_at = utc_now()
        execution.error = str(e)
    finally:
        await persist_workflow_execution(execution)


async def start_workflow_execution(workflow_id: str, input_data: Dict[str, Any]) -> WorkflowExecution:
    """
    Start a new workflow execution.

    Args:
        workflow_id: Workflow definition ID
        input_data: Input parameters for workflow

    Returns:
        WorkflowExecution instance
    """
    execution = WorkflowExecution(
        execution_id=f"exec-{uuid.uuid4()}",
        workflow_id=workflow_id,
        status=WorkflowStatus.PENDING,
        input=input_data,
        started_at=utc_now(),
    )

    workflow_def = workflow_definitions.get(workflow_id)
    if not workflow_def:
        raise WorkflowError(f"Workflow definition not found: {workflow_id}")

    if temporal_client and SecurityWorkflow:
        await start_temporal_execution(execution, workflow_def)
    else:
        asyncio.create_task(execute_workflow(execution))
        asyncio.create_task(persist_workflow_execution(execution))

    return execution


async def monitor_executions():
    """Monitor active workflow executions for timeouts."""
    while True:
        try:
            await asyncio.sleep(60)  # Check every minute

            current_time = utc_now()
            timed_out = []

            for exec_id, execution in active_executions.items():
                # Check if execution has timed out
                workflow_def = workflow_definitions.get(execution.workflow_id)
                if not workflow_def:
                    continue

                timeout = timedelta(seconds=workflow_def.timeout_seconds)
                started_at = execution.started_at
                if started_at.tzinfo is None:
                    started_at = started_at.replace(tzinfo=UTC)

                if current_time - started_at > timeout:
                    execution.status = WorkflowStatus.TIMED_OUT
                    execution.error = "Workflow execution timed out"
                    execution.completed_at = current_time
                    timed_out.append(exec_id)

                    logger.warning(f"Workflow execution {exec_id} timed out")

            # Clean up timed out executions
            for exec_id in timed_out:
                del active_executions[exec_id]

        except Exception as e:
            logger.error(f"Error monitoring executions: {e}", exc_info=True)


async def fetch_executions_from_db(
    status: Optional[WorkflowStatus] = None, workflow_id: Optional[str] = None
) -> List[WorkflowExecution]:
    """Fetch workflow executions from database."""
    conditions = []
    params: Dict[str, Any] = {}

    if status:
        conditions.append("status = :status")
        params["status"] = status.value
    if workflow_id:
        conditions.append("workflow_id = :workflow_id")
        params["workflow_id"] = workflow_id

    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

    async with db_manager.get_session() as session:
        result = await session.execute(
            text(
                f"""
                SELECT execution_id, workflow_id, status, started_at, completed_at
                FROM workflow_executions
                {where_clause}
                ORDER BY started_at DESC
                LIMIT 200
                """
            ),
            params,
        )
        rows = result.fetchall()

    executions: List[WorkflowExecution] = []
    for row in rows:
        executions.append(
            WorkflowExecution(
                execution_id=row.execution_id,
                workflow_id=row.workflow_id,
                status=WorkflowStatus(row.status),
                input={},
                started_at=row.started_at,
                completed_at=row.completed_at,
            )
        )

    return executions


# API Endpoints


@app.post("/api/v1/workflows/definitions", response_model=Dict[str, Any])
async def create_workflow_definition(definition: WorkflowDefinition):
    """Create a new workflow definition."""
    try:
        workflow_definitions[definition.workflow_id] = definition
        async with db_manager.get_session() as session:
            await session.execute(
                text(
                    """
                    INSERT INTO workflows (workflow_id, name, description, category, trigger_type,
                                           trigger_conditions, status, priority, steps, created_by)
                    VALUES (:workflow_id, :name, :description, :category, :trigger_type,
                            CAST(:trigger_conditions AS jsonb), :status, :priority, CAST(:steps AS jsonb), :created_by)
                    ON CONFLICT (workflow_id) DO UPDATE SET
                        name = EXCLUDED.name,
                        description = EXCLUDED.description,
                        category = EXCLUDED.category,
                        trigger_type = EXCLUDED.trigger_type,
                        trigger_conditions = EXCLUDED.trigger_conditions,
                        status = EXCLUDED.status,
                        priority = EXCLUDED.priority,
                        steps = EXCLUDED.steps,
                        updated_at = NOW()
                    """
                ),
                {
                    "workflow_id": definition.workflow_id,
                    "name": definition.name,
                    "description": definition.description,
                    "category": "custom",
                    "trigger_type": "manual",
                    "trigger_conditions": json.dumps({}),
                    "status": "active",
                    "priority": "medium",
                    "steps": json.dumps(definition.steps),
                    "created_by": "api",
                },
            )
            await session.commit()

        return {
            "success": True,
            "data": definition.model_dump(),
            "meta": {"timestamp": utc_now_iso(), "request_id": str(uuid.uuid4())},
        }

    except Exception as e:
        logger.error(f"Failed to create workflow definition: {e}", exc_info=True)
        raise HTTPException(
            status_code=500, detail=f"Failed to create workflow definition: {str(e)}"
        )


@app.get("/api/v1/workflows/definitions", response_model=Dict[str, Any])
async def list_workflow_definitions():
    """List all workflow definitions."""
    return {
        "success": True,
        "data": {
            "workflows": [wf.model_dump() for wf in workflow_definitions.values()],
            "total": len(workflow_definitions),
        },
        "meta": {"timestamp": utc_now_iso(), "request_id": str(uuid.uuid4())},
    }


@app.get("/api/v1/workflows/definitions/{workflow_id}", response_model=Dict[str, Any])
async def get_workflow_definition(workflow_id: str):
    """Get a specific workflow definition."""
    workflow = workflow_definitions.get(workflow_id)
    if not workflow:
        raise HTTPException(status_code=404, detail=f"Workflow definition not found: {workflow_id}")

    return {
        "success": True,
        "data": workflow.model_dump(),
        "meta": {"timestamp": utc_now_iso(), "request_id": str(uuid.uuid4())},
    }


@app.post("/api/v1/workflows/execute", response_model=Dict[str, Any])
async def execute_workflow_api(
    request: WorkflowExecuteRequest, background_tasks: BackgroundTasks
):
    """
    Start workflow execution via API.

    Args:
        workflow_id: Workflow definition ID
        input_data: Input parameters for workflow
    """
    try:
        # Check if workflow exists
        if request.workflow_id not in workflow_definitions:
            raise HTTPException(
                status_code=404, detail=f"Workflow definition not found: {request.workflow_id}"
            )

        # Start execution
        execution = await start_workflow_execution(request.workflow_id, request.input_data)

        return {
            "success": True,
            "data": {
                "execution_id": execution.execution_id,
                "workflow_id": execution.workflow_id,
                "status": execution.status.value,
                "started_at": execution.started_at.isoformat(),
            },
            "meta": {"timestamp": utc_now_iso(), "request_id": str(uuid.uuid4())},
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to start workflow execution: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to start workflow execution: {str(e)}")


@app.get("/api/v1/workflows/executions", response_model=Dict[str, Any])
async def list_executions(
    status: Optional[WorkflowStatus] = None, workflow_id: Optional[str] = None
):
    """List workflow executions, optionally filtered by status or workflow."""
    executions = list(active_executions.values())
    if not executions:
        executions = await fetch_executions_from_db(status, workflow_id)
    else:
        if status:
            executions = [e for e in executions if e.status == status]
        if workflow_id:
            executions = [e for e in executions if e.workflow_id == workflow_id]

    return {
        "success": True,
        "data": {"executions": [e.model_dump() for e in executions], "total": len(executions)},
        "meta": {"timestamp": utc_now_iso(), "request_id": str(uuid.uuid4())},
    }


@app.get("/api/v1/workflows/executions/{execution_id}", response_model=Dict[str, Any])
async def get_execution(execution_id: str):
    """Get a specific workflow execution."""
    execution = active_executions.get(execution_id)
    if not execution:
        async with db_manager.get_session() as session:
            result = await session.execute(
                text(
                    """
                    SELECT execution_id, workflow_id, status, started_at, completed_at
                    FROM workflow_executions
                    WHERE execution_id = :execution_id
                    """
                ),
                {"execution_id": execution_id},
            )
            row = result.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail=f"Execution not found: {execution_id}")

        execution = WorkflowExecution(
            execution_id=row.execution_id,
            workflow_id=row.workflow_id,
            status=WorkflowStatus(row.status),
            input={},
            started_at=row.started_at,
            completed_at=row.completed_at,
        )

    return {
        "success": True,
        "data": execution.model_dump(),
        "meta": {"timestamp": utc_now_iso(), "request_id": str(uuid.uuid4())},
    }


@app.post("/api/v1/workflows/tasks/{task_id}/complete", response_model=Dict[str, Any])
async def complete_human_task(task_id: str, output_data: Dict[str, Any] = None, notes: str = None):
    """Complete a human task and resume workflow execution."""
    async with db_manager.get_session() as session:
        result = await session.execute(
            text(
                """
                SELECT task_id, execution_id
                FROM human_tasks
                WHERE task_id = :task_id
                """
            ),
            {"task_id": task_id},
        )
        row = result.fetchone()

    if not row:
        raise HTTPException(status_code=404, detail=f"Task not found: {task_id}")

    task = HumanTask(
        task_id=row.task_id,
        execution_id=row.execution_id,
        task_type="manual_review",
        title="completed",
        description="completed",
        assigned_to=None,
        status=TaskStatus.COMPLETED,
        priority=TaskPriority.MEDIUM,
        input_data={},
        output_data=output_data or {},
        notes=notes,
    )
    await persist_human_task(task)

    # Resume execution from next step
    execution = active_executions.get(row.execution_id)
    if execution:
        workflow_def = workflow_definitions.get(execution.workflow_id)
        if workflow_def:
            try:
                current_index = next(
                    i
                    for i, s in enumerate(workflow_def.steps)
                    if s.get("name") == execution.current_step
                )
            except StopIteration:
                current_index = -1

            execution.status = WorkflowStatus.RUNNING
            asyncio.create_task(execute_workflow(execution, start_index=current_index + 1))

    return {
        "success": True,
        "message": "Task completed and workflow resumed",
        "meta": {"timestamp": utc_now_iso(), "request_id": str(uuid.uuid4())},
    }


@app.post("/api/v1/workflows/executions/{execution_id}/cancel", response_model=Dict[str, Any])
async def cancel_execution(execution_id: str):
    """Cancel a running workflow execution."""
    execution = active_executions.get(execution_id)
    if not execution:
        raise HTTPException(status_code=404, detail=f"Execution not found: {execution_id}")

    if execution.status not in [WorkflowStatus.PENDING, WorkflowStatus.RUNNING]:
        raise HTTPException(
            status_code=400, detail=f"Cannot cancel execution in status: {execution.status.value}"
        )

    execution.status = WorkflowStatus.CANCELLED
    execution.completed_at = utc_now()

    return {
        "success": True,
        "message": "Execution cancelled",
        "meta": {"timestamp": utc_now_iso(), "request_id": str(uuid.uuid4())},
    }


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "workflow-engine",
        "timestamp": utc_now_iso(),
        "workflows": {
            "definitions": len(workflow_definitions),
            "active_executions": len(active_executions),
        },
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=config.host, port=config.port)
