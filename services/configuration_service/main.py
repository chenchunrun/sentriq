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

"""Configuration Service - Centralized configuration management."""

import json
import uuid
from contextlib import asynccontextmanager
from typing import Any, Dict

import yaml
from fastapi import Body, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import desc, func, select

from shared.database import DatabaseManager, get_database_manager, init_database, close_database
from shared.database.models import AuditLog
from shared.database.repositories.settings_repository import SettingsRepository
from shared.utils import Config, get_logger, utc_now_iso

logger = get_logger(__name__)
config = Config()

db_manager: DatabaseManager = None

DEFAULT_CONFIGS: Dict[str, Dict[str, Any]] = {
    "system": {
        "version": "1.0.0",
        "environment": "production",
        "maintenance_mode": False,
    },
    "alerts": {
        "auto_triage_enabled": True,
        "auto_response_threshold": "high",
        "human_review_required": ["critical", "high"],
    },
    "automation": {
        "approval_required": True,
        "timeout_seconds": 600,
        "max_concurrent_executions": 10,
        "retry_on_failure": True,
        "max_retries": 3,
        "notification_on_complete": True,
        "notification_channels": ["email", "slack"],
        "log_level": "info",
    },
    "notifications": {
        "channels": ["email", "slack"],
        "critical_alerts": ["email", "slack", "sms"],
        "high_alerts": ["email", "slack"],
        "medium_alerts": ["email"],
        "low_alerts": ["in_app"],
    },
    "llm": {
        "llm_provider": "deepseek",
        "zhipu_api_key": "",
        "zhipu_model": "glm-4-flash",
        "zhipu_base_url": "https://open.bigmodel.cn/api/paas/v4/",
        "deepseek_api_key": "",
        "deepseek_model": "deepseek-v3",
        "deepseek_base_url": "https://api.deepseek.com/v1",
        "qwen_api_key": "",
        "qwen_model": "qwen3-max",
        "qwen_base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1",
        "openai_api_key": "",
        "openai_model": "gpt-4-turbo",
        "openai_base_url": "https://api.openai.com/v1",
        "temperature": 0.7,
        "max_tokens": 2000,
    },
}

DEFAULT_PREFERENCES: Dict[str, Any] = {
    "theme": "light",
    "notifications": {
        "email": True,
        "browser": True,
        "slack": False,
    },
    "dashboard": {
        "default_view": "overview",
        "refresh_interval": 30,
    },
    "alerts": {
        "default_filters": {},
    },
}


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifespan."""
    global db_manager

    logger.info("Starting Configuration service...")

    await init_database(
        database_url=config.database_url,
        pool_size=config.db_pool_size,
        max_overflow=config.db_max_overflow,
        echo=config.debug,
    )
    db_manager = get_database_manager()
    await ensure_default_configs()

    logger.info("Configuration service started successfully")
    yield
    await close_database()
    logger.info("Configuration service stopped")


app = FastAPI(
    title="Configuration Service",
    description="Centralized configuration management",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


async def ensure_default_configs() -> None:
    """Seed default configuration values in persistent storage."""
    async with db_manager.get_session() as session:
        repo = SettingsRepository(session)
        existing = await repo.get_all_configs()
        for key, value in DEFAULT_CONFIGS.items():
            if key not in existing:
                await repo.create_config(
                    config_key=key,
                    config_value=value,
                    description=f"Default configuration for {key}",
                    category=key,
                    updated_by="system",
                )
        await session.commit()


async def ensure_user_preferences(repo: SettingsRepository, user_id: str) -> Dict[str, Any]:
    """Return existing preferences or seed defaults for the user."""
    config_key = f"user_preferences:{user_id}"
    cfg = await repo.get_config(config_key)

    if not cfg:
        await repo.create_config(
            config_key=config_key,
            config_value=DEFAULT_PREFERENCES,
            description=f"User preferences for {user_id}",
            category="preferences",
            updated_by=user_id,
        )
        return DEFAULT_PREFERENCES.copy()

    preferences = cfg.config_value if isinstance(cfg.config_value, dict) else {}
    merged = DEFAULT_PREFERENCES.copy()
    merged.update(preferences)
    if "notifications" in preferences and isinstance(preferences["notifications"], dict):
        merged["notifications"] = {**DEFAULT_PREFERENCES["notifications"], **preferences["notifications"]}
    if "dashboard" in preferences and isinstance(preferences["dashboard"], dict):
        merged["dashboard"] = {**DEFAULT_PREFERENCES["dashboard"], **preferences["dashboard"]}
    if "alerts" in preferences and isinstance(preferences["alerts"], dict):
        merged["alerts"] = {**DEFAULT_PREFERENCES["alerts"], **preferences["alerts"]}
    return merged


async def record_config_change(
    session,
    key: str,
    old_value: Any,
    new_value: Any,
    changed_by: str,
) -> None:
    """Persist config change to audit log."""
    try:
        async with session.begin_nested():
            session.add(
                AuditLog(
                    event_type="config.changed",
                    event_category="system_config",
                    action="update",
                    actor_id=changed_by,
                    actor_type="user",
                    target_type="system_config",
                    target_id=key,
                    old_values=old_value if isinstance(old_value, dict) else {"value": old_value},
                    new_values=new_value if isinstance(new_value, dict) else {"value": new_value},
                    details={"config_key": key},
                    status="success",
                )
            )
            await session.flush()
    except Exception as exc:
        logger.warning(f"Skipping audit log for config change {key}: {exc}")


def response_meta() -> Dict[str, str]:
    """Generate standard response metadata."""
    return {"timestamp": utc_now_iso(), "request_id": str(uuid.uuid4())}


@app.get("/api/v1/config", response_model=Dict[str, Any])
async def get_all_config(category: str | None = Query(default=None)):
    """Get all configuration from persistent storage."""
    async with db_manager.get_session() as session:
        repo = SettingsRepository(session)
        configs = await repo.get_all_configs()
    if category:
        cfg = configs.get(category)
        if not cfg:
            raise HTTPException(status_code=404, detail=f"Configuration key not found: {category}")
        return {
            "success": True,
            "data": {
                category: {
                    "value": cfg["value"],
                    "category": cfg.get("category") or category,
                    "description": f"Configuration for {category}",
                    "editable": True,
                }
            },
            "meta": response_meta(),
        }
    return {"success": True, "data": configs, "meta": response_meta()}


@app.get("/api/v1/config/preferences", response_model=Dict[str, Any])
async def get_preferences(user_id: str = Query(...)):
    """Get persisted user preferences."""
    async with db_manager.get_session() as session:
        repo = SettingsRepository(session)
        preferences = await ensure_user_preferences(repo, user_id)
        await session.commit()

    return {
        "success": True,
        "data": preferences,
        "meta": response_meta(),
    }


@app.put("/api/v1/config/preferences", response_model=Dict[str, Any])
async def update_preferences(
    payload: Dict[str, Any] = Body(...),
    user_id: str = Query(...),
):
    """Persist user preferences."""
    async with db_manager.get_session() as session:
        repo = SettingsRepository(session)
        current = await ensure_user_preferences(repo, user_id)
        config_key = f"user_preferences:{user_id}"

        merged = current.copy()
        for key, value in payload.items():
            if isinstance(merged.get(key), dict) and isinstance(value, dict):
                merged[key] = {**merged[key], **value}
            else:
                merged[key] = value

        cfg = await repo.get_config(config_key)
        if cfg:
            await repo.update_config(config_key, merged, updated_by=user_id)
        else:
            await repo.create_config(
                config_key=config_key,
                config_value=merged,
                description=f"User preferences for {user_id}",
                category="preferences",
                updated_by=user_id,
            )
        await session.commit()

    return {
        "success": True,
        "data": merged,
        "meta": response_meta(),
    }


@app.get("/api/v1/config/{key}", response_model=Dict[str, Any])
async def get_config(key: str):
    """Get specific configuration by key."""
    async with db_manager.get_session() as session:
        repo = SettingsRepository(session)
        cfg = await repo.get_config(key)
        if not cfg:
            raise HTTPException(status_code=404, detail=f"Configuration key not found: {key}")
        return {
            "success": True,
            "data": {"key": key, "value": cfg.config_value, "category": cfg.category},
            "meta": response_meta(),
        }


@app.put("/api/v1/config/{key}", response_model=Dict[str, Any])
async def update_config(
    key: str,
    value: Dict[str, Any] = Body(...),
    changed_by: str = Query(default="system"),
):
    """Update configuration."""
    async with db_manager.get_session() as session:
        repo = SettingsRepository(session)
        cfg = await repo.get_config(key)
        if not cfg:
            raise HTTPException(status_code=404, detail=f"Configuration key not found: {key}")

        old_value = cfg.config_value.copy() if isinstance(cfg.config_value, dict) else cfg.config_value
        await repo.update_config(key, value, updated_by=changed_by)
        await record_config_change(session, key, old_value, value, changed_by)
        await session.commit()

    logger.info(f"Configuration updated: {key} by {changed_by}")
    return {
        "success": True,
        "data": {"key": key, "value": value, "old_value": old_value},
        "meta": response_meta(),
    }


@app.post("/api/v1/config/{key}/reset", response_model=Dict[str, Any])
async def reset_config(key: str, changed_by: str = Query(default="system")):
    """Reset configuration to default value."""
    if key not in DEFAULT_CONFIGS:
        raise HTTPException(status_code=400, detail=f"No default configuration defined for: {key}")

    async with db_manager.get_session() as session:
        repo = SettingsRepository(session)
        cfg = await repo.get_config(key)
        old_value = cfg.config_value.copy() if cfg and isinstance(cfg.config_value, dict) else {}
        new_value = DEFAULT_CONFIGS[key].copy()

        if cfg:
            await repo.update_config(key, new_value, updated_by=changed_by)
        else:
            await repo.create_config(
                config_key=key,
                config_value=new_value,
                description=f"Default configuration for {key}",
                category=key,
                updated_by=changed_by,
            )

        await record_config_change(session, key, old_value, new_value, changed_by)
        await session.commit()

    return {
        "success": True,
        "data": {"key": key, "value": new_value, "reset": True},
        "meta": response_meta(),
    }


@app.get("/api/v1/config/{key}/history", response_model=Dict[str, Any])
async def get_config_history(key: str, limit: int = 50):
    """Get configuration change history from audit logs."""
    try:
        async with db_manager.get_session() as session:
            result = await session.execute(
                select(AuditLog)
                .where(
                    AuditLog.event_category == "system_config",
                    AuditLog.target_id == key,
                )
                .order_by(desc(AuditLog.timestamp))
                .limit(limit)
            )
            rows = result.scalars().all()
    except Exception:
        rows = []

    history = [
        {
            "timestamp": row.timestamp.isoformat() if row.timestamp else None,
            "key": key,
            "old_value": row.old_values,
            "new_value": row.new_values,
            "changed_by": row.actor_id,
            "status": row.status,
        }
        for row in rows
    ]
    return {
        "success": True,
        "data": {"key": key, "history": history, "total": len(history)},
        "meta": response_meta(),
    }


@app.post("/api/v1/config/export", response_model=Dict[str, Any])
async def export_config(format: str = "json"):
    """Export all configuration."""
    async with db_manager.get_session() as session:
        repo = SettingsRepository(session)
        configs = await repo.get_all_configs()

    normalized = {key: value["value"] for key, value in configs.items()}
    if format == "json":
        content = json.dumps(normalized, indent=2)
        filename = f"config_export_{uuid.uuid4().hex[:8]}.json"
    elif format == "yaml":
        content = yaml.dump(normalized, default_flow_style=False)
        filename = f"config_export_{uuid.uuid4().hex[:8]}.yaml"
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported format: {format}. Use 'json' or 'yaml'")

    return {
        "success": True,
        "data": {
            "format": format,
            "filename": filename,
            "content": content,
        },
        "meta": response_meta(),
    }


@app.post("/api/v1/config/import", response_model=Dict[str, Any])
async def import_config(
    content: str,
    format: str = "json",
    changed_by: str = Query(default="system"),
):
    """Import configuration into persistent storage."""
    try:
        imported = json.loads(content) if format == "json" else yaml.safe_load(content)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid configuration format: {exc}") from exc

    if not isinstance(imported, dict):
        raise HTTPException(status_code=400, detail="Invalid configuration payload")

    changed_keys = []
    async with db_manager.get_session() as session:
        repo = SettingsRepository(session)
        for key, value in imported.items():
            if not isinstance(value, dict):
                raise HTTPException(status_code=400, detail=f"Invalid configuration for key: {key}")
            cfg = await repo.get_config(key)
            if cfg:
                old_value = cfg.config_value.copy() if isinstance(cfg.config_value, dict) else cfg.config_value
                merged = {**cfg.config_value, **value}
                await repo.update_config(key, merged, updated_by=changed_by)
                await record_config_change(session, key, old_value, merged, changed_by)
            else:
                await repo.create_config(
                    config_key=key,
                    config_value=value,
                    description=f"Imported configuration for {key}",
                    category=key,
                    updated_by=changed_by,
                )
                await record_config_change(session, key, {}, value, changed_by)
            changed_keys.append(key)
        await session.commit()

    return {
        "success": True,
        "data": {"imported_keys": changed_keys, "count": len(changed_keys)},
        "meta": response_meta(),
    }


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    async with db_manager.get_session() as session:
        repo = SettingsRepository(session)
        configs = await repo.get_all_configs()
        audit_count = 0

    return {
        "status": "healthy",
        "service": "configuration-service",
        "timestamp": utc_now_iso(),
        "config_keys": len(configs),
        "history_entries": audit_count or 0,
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=config.host, port=config.port)
