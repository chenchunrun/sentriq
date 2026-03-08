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

"""Automation Orchestrator Service - SOAR functionality for automated response."""

import asyncio
import json
import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import text
from shared.database import DatabaseManager, close_database, get_database_manager, init_database
from shared.errors import AutomationError
from shared.messaging import MessageConsumer, MessagePublisher
from shared.models import (
    AutomationPlaybook,
    PlaybookAction,
    PlaybookExecution,
    ResponseMeta,
    SuccessResponse,
    WorkflowStatus,
)
from shared.utils import Config, get_logger

logger = get_logger(__name__)
config = Config()

db_manager: DatabaseManager = None
publisher: MessagePublisher = None
consumer: MessageConsumer = None

# In-memory storage (use database in production)
active_executions: Dict[str, PlaybookExecution] = {}
playbooks: Dict[str, AutomationPlaybook] = {}

# Default automation playbooks
DEFAULT_PLAYBOOKS = {
    "malware-response": AutomationPlaybook(
        playbook_id="malware-response",
        name="Malware Response Playbook",
        description="Automated response actions for malware alerts",
        version="1.0.0",
        actions=[
            PlaybookAction(
                action_id="isolate-host",
                action_type="ssh_command",
                name="Isolate infected host from network",
                description="Block network access for infected host",
                parameters={
                    "command_template": "iptables -A INPUT -s {target_ip} -j DROP",
                    "target_host": "{target_ip}",
                    "timeout": 30,
                },
                timeout_seconds=60,
            ),
            PlaybookAction(
                action_id="quarantine-file",
                action_type="edr_command",
                name="Quarantine malicious file",
                description="Quarantine detected malicious file via EDR",
                parameters={"file_hash": "{file_hash}", "action": "quarantine"},
                timeout_seconds=120,
            ),
            PlaybookAction(
                action_id="create-ticket",
                action_type="api_call",
                name="Create incident ticket",
                description="Create ticket in ticketing system",
                parameters={
                    "endpoint": "api/tickets",
                    "title": "Malware incident - {alert_id}",
                    "severity": "high",
                },
                timeout_seconds=30,
            ),
        ],
        approval_required=True,
        timeout_seconds=600,
        trigger_conditions={"alert_type": "malware", "risk_level": ["CRITICAL", "HIGH"]},
    ),
    "phishing-response": AutomationPlaybook(
        playbook_id="phishing-response",
        name="Phishing Response Playbook",
        description="Automated response for phishing alerts",
        version="1.0.0",
        actions=[
            PlaybookAction(
                action_id="block-sender",
                action_type="email_command",
                name="Block phishing sender",
                description="Block email sender at mail gateway",
                parameters={"action": "block_sender", "sender_address": "{sender_email}"},
                timeout_seconds=60,
            ),
            PlaybookAction(
                action_id="delete-emails",
                action_type="email_command",
                name="Delete phishing emails",
                description="Remove all instances of phishing email",
                parameters={
                    "action": "delete",
                    "subject": "{email_subject}",
                    "sender": "{sender_email}",
                },
                timeout_seconds=300,
            ),
        ],
        approval_required=True,
        timeout_seconds=600,
        trigger_conditions={"alert_type": "phishing", "confidence_threshold": 80},
    ),
}


class PlaybookExecuteRequest(BaseModel):
    playbook_id: str
    alert_id: str
    input_data: Dict[str, Any] = Field(default_factory=dict)


async def seed_default_playbooks():
    """Persist default playbooks into database if missing."""
    async with db_manager.get_session() as session:
        for pb in DEFAULT_PLAYBOOKS.values():
            await session.execute(
                text(
                    """
                    INSERT INTO automation_playbooks (playbook_id, name, description, version,
                                                     actions, approval_required, timeout_seconds,
                                                     trigger_conditions, created_by)
                    VALUES (:playbook_id, :name, :description, :version,
                            CAST(:actions AS jsonb), :approval_required, :timeout_seconds,
                            CAST(:trigger_conditions AS jsonb), :created_by)
                    ON CONFLICT (playbook_id) DO UPDATE SET
                        name = EXCLUDED.name,
                        description = EXCLUDED.description,
                        version = EXCLUDED.version,
                        actions = EXCLUDED.actions,
                        approval_required = EXCLUDED.approval_required,
                        timeout_seconds = EXCLUDED.timeout_seconds,
                        trigger_conditions = EXCLUDED.trigger_conditions,
                        updated_at = NOW()
                    """
                ),
                {
                    "playbook_id": pb.playbook_id,
                    "name": pb.name,
                    "description": pb.description,
                    "version": pb.version,
                    "actions": json.dumps([a.model_dump() for a in pb.actions]),
                    "approval_required": pb.approval_required,
                    "timeout_seconds": pb.timeout_seconds,
                    "trigger_conditions": json.dumps(pb.trigger_conditions or {}),
                    "created_by": "system",
                },
            )
        await session.commit()


async def ensure_automation_tables() -> None:
    """Create local automation metadata tables when they are missing."""
    async with db_manager.engine.begin() as conn:
        await conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS automation_playbooks (
                    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                    playbook_id VARCHAR(255) UNIQUE NOT NULL,
                    name VARCHAR(255) NOT NULL,
                    description TEXT,
                    version VARCHAR(50) NOT NULL,
                    actions JSONB NOT NULL DEFAULT '[]'::jsonb,
                    approval_required BOOLEAN NOT NULL DEFAULT FALSE,
                    timeout_seconds INTEGER NOT NULL DEFAULT 600,
                    trigger_conditions JSONB NOT NULL DEFAULT '{}'::jsonb,
                    created_by VARCHAR(255) NOT NULL DEFAULT 'system',
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                """
            )
        )
        await conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS playbook_executions (
                    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                    execution_id VARCHAR(255) UNIQUE NOT NULL,
                    playbook_id VARCHAR(255) NOT NULL,
                    trigger_alert_id VARCHAR(255),
                    status VARCHAR(50) NOT NULL,
                    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    completed_at TIMESTAMPTZ,
                    current_action VARCHAR(255),
                    current_action_index INTEGER NOT NULL DEFAULT 0,
                    approval_status VARCHAR(50),
                    results JSONB NOT NULL DEFAULT '[]'::jsonb,
                    error_message TEXT
                )
                """
            )
        )


async def load_playbooks_from_db() -> Dict[str, AutomationPlaybook]:
    """Load playbooks from database."""
    playbook_map: Dict[str, AutomationPlaybook] = {}
    async with db_manager.get_session() as session:
        result = await session.execute(
            text(
                """
                SELECT playbook_id, name, description, version, actions, approval_required,
                       timeout_seconds, trigger_conditions
                FROM automation_playbooks
                """
            )
        )
        rows = result.fetchall()

    for row in rows:
        actions = [PlaybookAction(**a) for a in (row.actions or [])]
        playbook_map[row.playbook_id] = AutomationPlaybook(
            playbook_id=row.playbook_id,
            name=row.name,
            description=row.description,
            version=row.version,
            actions=actions,
            approval_required=row.approval_required,
            timeout_seconds=row.timeout_seconds,
            trigger_conditions=row.trigger_conditions or {},
        )

    return playbook_map


async def persist_playbook_execution(execution: PlaybookExecution):
    """Persist playbook execution to database."""
    async with db_manager.get_session() as session:
        await session.execute(
            text(
                """
                INSERT INTO playbook_executions (execution_id, playbook_id, trigger_alert_id,
                                                 status, started_at, completed_at,
                                                 current_action, current_action_index,
                                                 approval_status, results, error_message)
                VALUES (:execution_id, :playbook_id, :trigger_alert_id,
                        :status, :started_at, :completed_at,
                        :current_action, :current_action_index,
                        :approval_status, CAST(:results AS jsonb), :error_message)
                ON CONFLICT (execution_id) DO UPDATE SET
                    status = EXCLUDED.status,
                    completed_at = EXCLUDED.completed_at,
                    current_action = EXCLUDED.current_action,
                    current_action_index = EXCLUDED.current_action_index,
                    approval_status = EXCLUDED.approval_status,
                    results = EXCLUDED.results,
                    error_message = EXCLUDED.error_message
                """
            ),
            {
                "execution_id": execution.execution_id,
                "playbook_id": execution.playbook_id,
                "trigger_alert_id": execution.trigger_alert_id,
                "status": execution.status.value,
                "started_at": execution.started_at,
                "completed_at": execution.completed_at,
                "current_action": execution.current_action,
                "current_action_index": execution.current_action_index,
                "approval_status": execution.approval_status,
                "results": json.dumps(execution.results or []),
                "error_message": execution.error,
            },
        )
        await session.commit()


# Action executors
class ActionExecutor:
    """Base class for action executors."""

    async def execute(self, action: PlaybookAction, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute an action."""
        raise NotImplementedError


class SSHCommandExecutor(ActionExecutor):
    """Execute SSH commands on remote hosts."""

    async def execute(self, action: PlaybookAction, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute SSH command.

        TODO: Implement actual SSH execution using asyncssh or paramiko.
        For now, return mock result.
        """
        try:
            # Extract parameters
            command_template = action.parameters.get("command_template", "")
            target_host = action.parameters.get("target_host", "")

            # Fill template with context
            command = command_template.format(**context)
            target = target_host.format(**context)

            logger.info(f"Executing SSH command on {target}: {command}")

            # TODO: Implement actual SSH execution
            # import asyncssh
            # result = await asyncssh.run(command, host=target)

            # Mock result
            await asyncio.sleep(1)  # Simulate execution

            return {
                "status": "success",
                "output": f"Command executed successfully on {target}",
                "exit_code": 0,
                "_mock": True,
            }

        except Exception as e:
            logger.error(f"SSH command execution failed: {e}", exc_info=True)
            return {"status": "failed", "error": str(e), "_mock": True}


class EDRCommandExecutor(ActionExecutor):
    """Execute commands via EDR (Endpoint Detection and Response)."""

    async def execute(self, action: PlaybookAction, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute EDR command.

        TODO: Implement actual EDR API integration.
        """
        try:
            file_hash = action.parameters.get("file_hash", "").format(**context)
            edr_action = action.parameters.get("action", "quarantine")

            logger.info(f"Executing EDR action: {edr_action} for file {file_hash}")

            # TODO: Implement actual EDR API call
            await asyncio.sleep(1)

            return {
                "status": "success",
                "output": f"File {file_hash} quarantined successfully",
                "_mock": True,
            }

        except Exception as e:
            logger.error(f"EDR command execution failed: {e}", exc_info=True)
            return {"status": "failed", "error": str(e), "_mock": True}


class EmailCommandExecutor(ActionExecutor):
    """Execute email gateway commands."""

    async def execute(self, action: PlaybookAction, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute email gateway command.

        TODO: Implement actual email gateway API integration.
        """
        try:
            email_action = action.parameters.get("action", "")
            sender = action.parameters.get("sender_address", "").format(**context)

            logger.info(f"Executing email gateway action: {email_action} for sender {sender}")

            # TODO: Implement actual email gateway API call
            await asyncio.sleep(1)

            return {
                "status": "success",
                "output": f"Email action {email_action} completed for {sender}",
                "_mock": True,
            }

        except Exception as e:
            logger.error(f"Email command execution failed: {e}", exc_info=True)
            return {"status": "failed", "error": str(e), "_mock": True}


class APICallExecutor(ActionExecutor):
    """Execute HTTP API calls."""

    async def execute(self, action: PlaybookAction, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute HTTP API call."""
        try:
            endpoint = action.parameters.get("endpoint", "").format(**context)
            method = action.parameters.get("method", "POST").upper()
            mock_mode = os.getenv("AUTOMATION_MOCK_MODE", "true").lower() == "true"

            # Build request
            url = f"{context.get('base_url', '')}/{endpoint}"
            headers = action.parameters.get("headers", {})
            body = {
                k: v.format(**context) if isinstance(v, str) else v
                for k, v in action.parameters.get("body", {}).items()
            }

            logger.info(f"Executing API call: {method} {url}")

            if mock_mode:
                await asyncio.sleep(0.2)
                return {
                    "status": "success",
                    "output": {"mock": True, "method": method, "url": url, "body": body},
                    "status_code": 200,
                    "_mock": True,
                }

            import httpx

            async with httpx.AsyncClient() as client:
                if method == "GET":
                    response = await client.get(url, headers=headers, params=body)
                elif method == "POST":
                    response = await client.post(url, headers=headers, json=body)
                elif method == "PUT":
                    response = await client.put(url, headers=headers, json=body)
                elif method == "DELETE":
                    response = await client.delete(url, headers=headers)
                else:
                    raise ValueError(f"Unsupported HTTP method: {method}")

                response.raise_for_status()

                return {
                    "status": "success",
                    "output": response.json(),
                    "status_code": response.status_code,
                }

        except Exception as e:
            logger.error(f"API call execution failed: {e}", exc_info=True)
            return {"status": "failed", "error": str(e)}


# Action executor registry
ACTION_EXECUTORS = {
    "ssh_command": SSHCommandExecutor(),
    "edr_command": EDRCommandExecutor(),
    "email_command": EmailCommandExecutor(),
    "api_call": APICallExecutor(),
}


async def execute_playbook_action(
    execution: PlaybookExecution, action: PlaybookAction, context: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Execute a single playbook action.

    Args:
        execution: Playbook execution instance
        action: Action to execute
        context: Execution context with variables

    Returns:
        Action execution result
    """
    try:
        logger.info(
            f"Executing action {action.action_id} "
            f"(type: {action.action_type}) for execution {execution.execution_id}"
        )

        # Check conditions
        if action.conditions:
            for condition in action.conditions:
                field = condition.get("field")
                op = condition.get("op", "equals")
                value = condition.get("value")
                actual = context.get(field)

                if op == "equals" and actual != value:
                    return {"status": "skipped", "reason": f"{field} != {value}"}
                if op == "in" and actual not in (value or []):
                    return {"status": "skipped", "reason": f"{field} not in {value}"}
                if op == "gte" and (actual is None or actual < value):
                    return {"status": "skipped", "reason": f"{field} < {value}"}

        # Get executor
        executor = ACTION_EXECUTORS.get(action.action_type)
        if not executor:
            raise AutomationError(f"No executor found for action type: {action.action_type}")

        # Execute action
        result = await asyncio.wait_for(
            executor.execute(action, context), timeout=action.timeout_seconds
        )

        return result

    except asyncio.TimeoutError:
        logger.error(f"Action {action.action_id} timed out")
        return {
            "status": "failed",
            "error": f"Action timed out after {action.timeout_seconds} seconds",
        }

    except Exception as e:
        logger.error(f"Action execution failed: {e}", exc_info=True)
        return {"status": "failed", "error": str(e)}


async def execute_playbook(execution: PlaybookExecution):
    """
    Execute playbook actions sequentially.

    Args:
        execution: Playbook execution instance
    """
    try:
        playbook = playbooks.get(execution.playbook_id)
        if not playbook:
            raise AutomationError(f"Playbook not found: {execution.playbook_id}")

        execution.status = WorkflowStatus.RUNNING
        active_executions[execution.execution_id] = execution

        # Build execution context
        context = {
            "alert_id": execution.trigger_alert_id,
            "execution_id": execution.execution_id,
            **execution.input_data,
        }

        # Check approval
        auto_approve = os.getenv("AUTOMATION_AUTO_APPROVE", "true").lower() == "true"
        if playbook.approval_required and execution.approval_status != "approved":
            if auto_approve:
                execution.approval_status = "approved"
                execution.approved_by = "system:auto"
                logger.info(
                    f"Playbook {execution.playbook_id} auto-approved (AUTOMATION_AUTO_APPROVE=true)"
                )
            else:
                execution.status = WorkflowStatus.PENDING
                logger.info(f"Playbook {execution.playbook_id} awaiting approval")
                await publisher.publish(
                    "notifications.send",
                    {
                        "message_id": str(uuid.uuid4()),
                        "message_type": "notification.request",
                        "payload": {
                            "channel": "in_app",
                            "recipient": "security-team",
                            "subject": f"Playbook approval required: {execution.playbook_id}",
                            "message": f"Execution {execution.execution_id} awaits approval",
                            "priority": "high",
                            "data": {
                                "execution_id": execution.execution_id,
                                "playbook_id": execution.playbook_id,
                            },
                        },
                        "timestamp": datetime.utcnow().isoformat(),
                    },
                )
                await persist_playbook_execution(execution)
                return

        # Execute each action
        for i, action in enumerate(playbook.actions):
            execution.current_action_index = i
            execution.current_action = action.action_id

            logger.info(f"Executing action {i + 1}/{len(playbook.actions)}: {action.action_id}")

            # Execute action
            result = await execute_playbook_action(execution, action, context)

            # Store result
            execution.results.append(
                {
                    "action_id": action.action_id,
                    "action_name": action.name,
                    "executed_at": datetime.utcnow().isoformat(),
                    "result": result,
                }
            )

            # Check if action failed
            if result.get("status") == "failed":
                execution.status = WorkflowStatus.FAILED
                execution.error = f"Action {action.action_id} failed: {result.get('error')}"
                execution.completed_at = datetime.utcnow()

                # TODO: Implement rollback if configured
                break

        # If all actions succeeded
        if execution.status == WorkflowStatus.RUNNING:
            execution.status = WorkflowStatus.COMPLETED
            execution.completed_at = datetime.utcnow()
            execution.current_action = None

        # Publish completion event
        await publisher.publish(
            "automation.completed",
            {
                "message_id": str(uuid.uuid4()),
                "message_type": "automation.completed",
                "payload": execution.model_dump(),
                "timestamp": datetime.utcnow().isoformat(),
            },
        )

        await persist_playbook_execution(execution)

        logger.info(
            f"Playbook execution {execution.execution_id} completed: {execution.status.value}"
        )

    except Exception as e:
        logger.error(f"Playbook execution failed: {e}", exc_info=True)
        execution.status = WorkflowStatus.FAILED
        execution.error = str(e)
        execution.completed_at = datetime.utcnow()
        await persist_playbook_execution(execution)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifespan."""
    global db_manager, publisher, consumer, playbooks

    logger.info("Starting Automation Orchestrator service...")

    # Initialize database
    import os
    await init_database(
        database_url=config.database_url,
        pool_size=int(os.getenv("DB_POOL_SIZE", "10")),
        max_overflow=int(os.getenv("DB_MAX_OVERFLOW", "20")),
        echo=config.debug,
    )
    db_manager = get_database_manager()
    await ensure_automation_tables()

    # Initialize messaging
    publisher = MessagePublisher(config.rabbitmq_url)
    await publisher.connect()

    consumer = MessageConsumer(config.rabbitmq_url, "automation.trigger")
    await consumer.connect()

    # Load default playbooks
    await seed_default_playbooks()
    playbooks.update(await load_playbooks_from_db())

    # Start consuming automation triggers
    asyncio.create_task(consume_automation_triggers())

    logger.info("Automation Orchestrator service started successfully")

    yield

    # Cleanup
    await consumer.close()
    await publisher.close()
    await close_database()
    logger.info("Automation Orchestrator service stopped")


app = FastAPI(
    title="Automation Orchestrator Service",
    description="SOAR functionality for automated security response",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


async def consume_automation_triggers():
    """Consume automation trigger messages from queue."""

    async def process_message(message: dict):
        try:
            payload = message["payload"]
            playbook_id = payload.get("playbook_id")
            alert_id = payload.get("alert_id")
            input_data = payload.get("input", {})

            if not playbook_id:
                logger.error("Missing playbook_id in trigger message")
                return

            # Start playbook execution
            execution = start_playbook_execution(playbook_id, alert_id, input_data)
            logger.info(f"Started playbook execution {execution.execution_id}")

        except Exception as e:
            logger.error(f"Failed to process automation trigger: {e}", exc_info=True)

    await consumer.consume(process_message)


def start_playbook_execution(
    playbook_id: str, alert_id: str, input_data: Dict[str, Any]
) -> PlaybookExecution:
    """
    Start a new playbook execution.

    Args:
        playbook_id: Playbook definition ID
        alert_id: Alert that triggered execution
        input_data: Input parameters

    Returns:
        PlaybookExecution instance
    """
    execution = PlaybookExecution(
        execution_id=f"pb-exec-{uuid.uuid4()}",
        playbook_id=playbook_id,
        trigger_alert_id=alert_id,
        status=WorkflowStatus.PENDING,
        started_at=datetime.utcnow(),
        results=[],
        input_data=input_data,
    )

    # Start execution in background
    asyncio.create_task(execute_playbook(execution))
    asyncio.create_task(persist_playbook_execution(execution))

    return execution


async def fetch_playbook_executions_from_db(
    status: Optional[WorkflowStatus] = None, playbook_id: Optional[str] = None
) -> List[PlaybookExecution]:
    """Fetch playbook executions from database."""
    conditions = []
    params: Dict[str, Any] = {}

    if status:
        conditions.append("status = :status")
        params["status"] = status.value
    if playbook_id:
        conditions.append("playbook_id = :playbook_id")
        params["playbook_id"] = playbook_id

    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

    async with db_manager.get_session() as session:
        result = await session.execute(
            text(
                f"""
                SELECT execution_id, playbook_id, trigger_alert_id, status, started_at, completed_at,
                       current_action, current_action_index
                FROM playbook_executions
                {where_clause}
                ORDER BY started_at DESC
                LIMIT 200
                """
            ),
            params,
        )
        rows = result.fetchall()

    executions: List[PlaybookExecution] = []
    for row in rows:
        executions.append(
            PlaybookExecution(
                execution_id=row.execution_id,
                playbook_id=row.playbook_id,
                trigger_alert_id=row.trigger_alert_id,
                status=WorkflowStatus(row.status),
                started_at=row.started_at,
                completed_at=row.completed_at,
                current_action=row.current_action,
                current_action_index=row.current_action_index,
                results=[],
            )
        )

    return executions


# API Endpoints


@app.post("/api/v1/playbooks", response_model=Dict[str, Any])
async def create_playbook(playbook: AutomationPlaybook):
    """Create a new automation playbook."""
    try:
        playbooks[playbook.playbook_id] = playbook
        async with db_manager.get_session() as session:
            await session.execute(
                text(
                    """
                    INSERT INTO automation_playbooks (playbook_id, name, description, version,
                                                     actions, approval_required, timeout_seconds,
                                                     trigger_conditions, created_by)
                    VALUES (:playbook_id, :name, :description, :version,
                            :actions::jsonb, :approval_required, :timeout_seconds,
                            :trigger_conditions::jsonb, :created_by)
                    ON CONFLICT (playbook_id) DO UPDATE SET
                        name = EXCLUDED.name,
                        description = EXCLUDED.description,
                        version = EXCLUDED.version,
                        actions = EXCLUDED.actions,
                        approval_required = EXCLUDED.approval_required,
                        timeout_seconds = EXCLUDED.timeout_seconds,
                        trigger_conditions = EXCLUDED.trigger_conditions,
                        updated_at = NOW()
                    """
                ),
                {
                    "playbook_id": playbook.playbook_id,
                    "name": playbook.name,
                    "description": playbook.description,
                    "version": playbook.version,
                    "actions": json.dumps([a.model_dump() for a in playbook.actions]),
                    "approval_required": playbook.approval_required,
                    "timeout_seconds": playbook.timeout_seconds,
                    "trigger_conditions": json.dumps(playbook.trigger_conditions or {}),
                    "created_by": "api",
                },
            )
            await session.commit()

        return {
            "success": True,
            "data": playbook.model_dump(),
            "meta": {"timestamp": datetime.utcnow().isoformat(), "request_id": str(uuid.uuid4())},
        }

    except Exception as e:
        logger.error(f"Failed to create playbook: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to create playbook: {str(e)}")


@app.get("/api/v1/playbooks", response_model=Dict[str, Any])
async def list_playbooks():
    """List all automation playbooks."""
    return {
        "success": True,
        "data": {
            "playbooks": [pb.model_dump() for pb in playbooks.values()],
            "total": len(playbooks),
        },
        "meta": {"timestamp": datetime.utcnow().isoformat(), "request_id": str(uuid.uuid4())},
    }


@app.get("/api/v1/playbooks/{playbook_id}", response_model=Dict[str, Any])
async def get_playbook(playbook_id: str):
    """Get a specific playbook."""
    playbook = playbooks.get(playbook_id)
    if not playbook:
        raise HTTPException(status_code=404, detail=f"Playbook not found: {playbook_id}")

    return {
        "success": True,
        "data": playbook.model_dump(),
        "meta": {"timestamp": datetime.utcnow().isoformat(), "request_id": str(uuid.uuid4())},
    }


@app.post("/api/v1/playbooks/execute", response_model=Dict[str, Any])
async def execute_playbook_api(
    request: PlaybookExecuteRequest, background_tasks: BackgroundTasks = None
):
    """
    Start playbook execution via API.

    Args:
        playbook_id: Playbook to execute
        alert_id: Alert that triggered execution
        input_data: Optional input parameters
    """
    try:
        # Check if playbook exists
        if request.playbook_id not in playbooks:
            raise HTTPException(
                status_code=404, detail=f"Playbook not found: {request.playbook_id}"
            )

        # Start execution
        execution = start_playbook_execution(
            request.playbook_id, request.alert_id, request.input_data
        )

        return {
            "success": True,
            "data": {
                "execution_id": execution.execution_id,
                "playbook_id": execution.playbook_id,
                "trigger_alert_id": execution.trigger_alert_id,
                "status": execution.status.value,
                "started_at": execution.started_at.isoformat(),
            },
            "meta": {"timestamp": datetime.utcnow().isoformat(), "request_id": str(uuid.uuid4())},
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to start playbook execution: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to start playbook execution: {str(e)}")


@app.get("/api/v1/executions", response_model=Dict[str, Any])
async def list_executions(
    status: Optional[WorkflowStatus] = None, playbook_id: Optional[str] = None
):
    """List playbook executions."""
    executions = list(active_executions.values())
    if not executions:
        executions = await fetch_playbook_executions_from_db(status, playbook_id)
    else:
        if status:
            executions = [e for e in executions if e.status == status]
        if playbook_id:
            executions = [e for e in executions if e.playbook_id == playbook_id]

    return {
        "success": True,
        "data": {"executions": [e.model_dump() for e in executions], "total": len(executions)},
        "meta": {"timestamp": datetime.utcnow().isoformat(), "request_id": str(uuid.uuid4())},
    }


@app.get("/api/v1/executions/{execution_id}", response_model=Dict[str, Any])
async def get_execution(execution_id: str):
    """Get a specific playbook execution."""
    execution = active_executions.get(execution_id)
    if not execution:
        async with db_manager.get_session() as session:
            result = await session.execute(
                text(
                    """
                    SELECT execution_id, playbook_id, trigger_alert_id, status, started_at, completed_at,
                           current_action, current_action_index
                    FROM playbook_executions
                    WHERE execution_id = :execution_id
                    """
                ),
                {"execution_id": execution_id},
            )
            row = result.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail=f"Execution not found: {execution_id}")
        execution = PlaybookExecution(
            execution_id=row.execution_id,
            playbook_id=row.playbook_id,
            trigger_alert_id=row.trigger_alert_id,
            status=WorkflowStatus(row.status),
            started_at=row.started_at,
            completed_at=row.completed_at,
            current_action=row.current_action,
            current_action_index=row.current_action_index,
            results=[],
        )

    return {
        "success": True,
        "data": execution.model_dump(),
        "meta": {"timestamp": datetime.utcnow().isoformat(), "request_id": str(uuid.uuid4())},
    }


@app.post("/api/v1/executions/{execution_id}/approve", response_model=Dict[str, Any])
async def approve_execution(execution_id: str, approver: str, comments: Optional[str] = None):
    """Approve a playbook execution awaiting approval."""
    execution = active_executions.get(execution_id)
    if not execution:
        raise HTTPException(status_code=404, detail=f"Execution not found: {execution_id}")

    if execution.status != WorkflowStatus.PENDING:
        raise HTTPException(
            status_code=400, detail=f"Execution not in PENDING status: {execution.status.value}"
        )

    execution.approval_status = "approved"
    execution.approved_by = approver
    if comments:
        execution.error = comments

    # Resume execution
    asyncio.create_task(execute_playbook(execution))
    asyncio.create_task(persist_playbook_execution(execution))

    return {
        "success": True,
        "message": "Execution approved",
        "meta": {"timestamp": datetime.utcnow().isoformat(), "request_id": str(uuid.uuid4())},
    }


@app.post("/api/v1/executions/{execution_id}/cancel", response_model=Dict[str, Any])
async def cancel_execution(execution_id: str):
    """Cancel a running playbook execution."""
    execution = active_executions.get(execution_id)
    if not execution:
        raise HTTPException(status_code=404, detail=f"Execution not found: {execution_id}")

    if execution.status not in [WorkflowStatus.PENDING, WorkflowStatus.RUNNING]:
        raise HTTPException(
            status_code=400, detail=f"Cannot cancel execution in status: {execution.status.value}"
        )

    execution.status = WorkflowStatus.CANCELLED
    execution.completed_at = datetime.utcnow()
    asyncio.create_task(persist_playbook_execution(execution))

    return {
        "success": True,
        "message": "Execution cancelled",
        "meta": {"timestamp": datetime.utcnow().isoformat(), "request_id": str(uuid.uuid4())},
    }


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "automation-orchestrator",
        "timestamp": datetime.utcnow().isoformat(),
        "playbooks": {"total": len(playbooks), "active_executions": len(active_executions)},
        "executors": list(ACTION_EXECUTORS.keys()),
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=config.host, port=config.port)
