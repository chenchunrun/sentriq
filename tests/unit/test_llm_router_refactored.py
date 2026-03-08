# Copyright 2026 CCR <chenchunrun@gmail.com>

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
Unit tests for LLM Router service.

Refactored to use mock AppConfig to avoid validation errors.
"""

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

# Set environment variables BEFORE importing any services
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost/test_db")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/1")
os.environ.setdefault("RABBITMQ_URL", "amqp://guest:guest@localhost:5672/")
os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-for-testing-only")


class TestLLMRouterAPI:
    """Test LLM Router API endpoints."""

    @pytest.fixture
    def mock_http_client(self):
        """Mock HTTP client for LLM API calls."""
        with patch("services.llm_router.main.httpx.AsyncClient") as mock:
            client_instance = MagicMock()
            client_instance.__aenter__ = AsyncMock(return_value=client_instance)
            client_instance.__aexit__ = AsyncMock()

            # Mock successful API response
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json = AsyncMock(
                return_value={
                    "id": "test-response",
                    "object": "chat.completion",
                    "created": 1234567890,
                    "model": "deepseek-v3",
                    "choices": [
                        {
                            "index": 0,
                            "message": {"role": "assistant", "content": "Test response"},
                            "finish_reason": "stop",
                        }
                    ],
                    "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
                }
            )
            mock_response.raise_for_status = MagicMock()

            client_instance.post = AsyncMock(return_value=mock_response)

            mock.return_value = client_instance
            yield client_instance

    @pytest.fixture
    def mock_db(self):
        """Mock database manager."""
        with patch("services.llm_router.main.get_database_manager") as mock:
            db_instance = MagicMock()
            db_instance.initialize = AsyncMock()
            db_instance.close = AsyncMock()
            mock.return_value = db_instance
            yield db_instance

    @pytest.fixture
    def client(self, mock_http_client, mock_db):
        """Create test client with all mocks in place."""
        # Import AFTER environment is set
        from services.llm_router.main import app

        return TestClient(app)

    def test_health_check(self, client):
        """Test health check endpoint."""
        response = client.get("/health")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["service"] == "llm-router"

    def test_list_models(self, client):
        """Test listing available models."""
        response = client.get("/api/v1/models")

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert "data" in data
        assert len(data["data"]) > 0

    def test_route_test(self, client):
        """Test routing decision endpoint."""
        request_data = {
            "task_type": "triage",
            "messages": [{"role": "user", "content": "Test alert analysis"}],
            "temperature": 0.7,
        }

        response = client.post("/api/v1/route", json=request_data)

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert "data" in data
        assert "selected_model" in data["data"]
        assert "reason" in data["data"]


class TestLLMRouterLogic:
    """Test LLM Router routing logic."""

    def test_route_request_with_model_specified(self):
        """Test routing when model is explicitly specified."""
        from services.llm_router.main import LLMModel, LLMRequest, TaskType, route_request

        request = LLMRequest(
            task_type=TaskType.TRIAGE,
            messages=[{"role": "user", "content": "Test"}],
            model=LLMModel.DEEPSEEK_V3,
            temperature=0.7,
        )

        decision = route_request(request)

        assert decision.selected_model == LLMModel.DEEPSEEK_V3
        assert decision.reason == "User specified model"
        assert decision.confidence == 1.0

    def test_route_request_by_task_type(self):
        """Test routing based on task type."""
        from services.llm_router.main import LLMRequest, TaskType, route_request

        request = LLMRequest(
            task_type=TaskType.TRIAGE,
            messages=[{"role": "user", "content": "Analyze alert"}],
            temperature=0.7,
        )

        decision = route_request(request)

        assert decision.selected_model is not None
        assert isinstance(decision.reason, str)
        assert decision.reason
        assert 0.0 <= decision.confidence <= 1.0

    def test_extract_iocs(self):
        """Test IOC extraction from alert."""
        from services.llm_router.main import extract_iocs

        alert = {
            "source_ip": "45.33.32.156",
            "target_ip": "10.0.0.50",
            "file_hash": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
        }

        iocs = extract_iocs(alert)

        assert "ips" in iocs
        assert "hashes" in iocs
        assert "45.33.32.156" in iocs["ips"]
        assert "10.0.0.50" in iocs["ips"]
        assert alert["file_hash"] in iocs["hashes"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
