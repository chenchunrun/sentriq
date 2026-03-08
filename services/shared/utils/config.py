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
Configuration management.

Provides application configuration from environment variables and YAML files.
"""

import os
from typing import Any, Dict, Optional

from pydantic import ConfigDict, Field
from pydantic_settings import BaseSettings


class Config(BaseSettings):
    """Application configuration from environment variables."""

    # Application
    app_name: str = "Security Alert Triage"
    app_version: str = "1.0.0"
    debug: bool = False

    # Server
    host: str = "0.0.0.0"
    port: int = 8000

    # Database
    database_url: str = Field(
        ...,
        description="Database connection URL (async)",
        examples=["postgresql+asyncpg://user:pass@localhost/db"],
    )
    db_pool_size: int = 20
    db_max_overflow: int = 40

    # Redis
    redis_url: str = Field(
        ...,
        description="Redis connection URL",
        examples=["redis://localhost:6379/0"],
    )
    redis_pool_size: int = 10

    # RabbitMQ
    rabbitmq_url: str = Field(
        ...,
        description="RabbitMQ connection URL",
        examples=["amqp://user:pass@localhost:5672/"],
    )

    # Private MaaS
    deepseek_base_url: Optional[str] = Field(
        default=None,
        description="DeepSeek MaaS base URL",
    )
    deepseek_api_key: Optional[str] = Field(
        default=None,
        description="DeepSeek API key",
    )
    qwen_base_url: Optional[str] = Field(
        default=None,
        description="Qwen MaaS base URL",
    )
    qwen_api_key: Optional[str] = Field(
        default=None,
        description="Qwen API key",
    )
    zhipu_base_url: Optional[str] = Field(
        default=None,
        description="Zhipu MaaS base URL",
    )
    zhipu_api_key: Optional[str] = Field(
        default=None,
        description="Zhipu API key",
    )
    zhipu_model: str = Field(
        default="glm-4",
        description="Zhipu model name",
    )

    # Fallback LLM
    llm_api_key: Optional[str] = Field(
        default=None,
        description="Fallback LLM API key",
    )
    llm_base_url: Optional[str] = Field(
        default=None,
        description="Fallback LLM base URL",
    )
    llm_model: str = "qwen-plus"

    # Logging
    log_level: str = "INFO"
    log_file: str = "logs/triage.log"

    # JWT
    jwt_secret_key: str = Field(
        ...,
        description="JWT secret key",
    )
    jwt_algorithm: str = "HS256"

    # Temporal
    temporal_enabled: bool = False
    temporal_server_url: str = "localhost:7233"
    temporal_namespace: str = "default"
    temporal_task_queue: str = "security-triage-workflows"

    model_config = ConfigDict(
        env_file=".env", case_sensitive=False, extra="ignore"  # Ignore extra fields from .env file
    )


# Global config instance
_config: Optional[Config] = None


def get_config() -> Config:
    """Get global configuration instance."""
    global _config
    if _config is None:
        _config = Config()
    return _config
