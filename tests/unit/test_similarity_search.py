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
Unit tests for Similarity Search Service.
"""

import pytest
from unittest.mock import Mock, patch


class TestEmbeddingGeneration:
    """Test embedding generation."""

    @pytest.fixture
    def mock_model(self):
        """Create mock embedding model."""
        import numpy as np

        model = Mock()
        # Mock numpy array with tolist() method
        mock_array = np.array([0.1, 0.2, 0.3, 0.4, 0.5])
        model.encode.return_value = mock_array
        model.get_sentence_embedding_dimension.return_value = 384
        return model

    def test_alert_to_text(self):
        """Test converting alert to text."""
        from services.similarity_search.main import alert_to_text
        from shared.models import SecurityAlert

        from datetime import datetime

        alert = SecurityAlert(
            alert_id="TEST-001",
            alert_type="malware",
            severity="high",
            description="Test malware alert",
            source_ip="192.168.1.1",
            file_hash="5d41402abc4b2a76b9719d911017c592",  # Valid MD5 hash (32 chars)
            timestamp=datetime.now().replace(year=2025, month=1, day=1),
        )

        text = alert_to_text(alert)

        # Enums are represented as AlertType.MALWARE, Severity.HIGH
        assert "AlertType.MALWARE" in text or "malware" in text.lower()
        assert "HIGH" in text or "high" in text.lower()
        assert "Source IP: 192.168.1.1" in text
        assert "File Hash: 5d41402abc4b2a76b9719d911017c592" in text

    def test_generate_embedding(self, mock_model):
        """Test embedding generation."""
        from services.similarity_search.main import generate_embedding

        with patch('services.similarity_search.main.embedding_model', mock_model):
            embedding = generate_embedding("test alert text")

            assert isinstance(embedding, list)
            assert len(embedding) == 5
            assert embedding == [0.1, 0.2, 0.3, 0.4, 0.5]

    def test_embedding_dimension(self, mock_model):
        """Test embedding dimension is consistent."""
        assert mock_model.get_sentence_embedding_dimension() == 384


class TestVectorSearch:
    """Test vector similarity search."""

    @pytest.fixture
    def mock_collection(self):
        """Create mock ChromaDB collection."""
        collection = Mock()
        collection.query.return_value = {
            "ids": [["ALERT-001", "ALERT-002"]],
            "distances": [[0.1, 0.3]],
            "metadatas": [[
                {"alert_id": "ALERT-001", "risk_level": "high"},
                {"alert_id": "ALERT-002", "risk_level": "medium"},
            ]],
        }
        collection.count.return_value = 100
        return collection

    @pytest.mark.asyncio
    async def test_search_similar_alerts(self, mock_collection):
        """Test searching similar alerts."""
        import numpy as np

        # Mock embedding model
        mock_embedding_model = Mock()
        mock_embedding_model.encode.return_value = np.array([0.1, 0.2, 0.3, 0.4, 0.5])

        with patch('services.similarity_search.main.collection', mock_collection), \
             patch('services.similarity_search.main.embedding_model', mock_embedding_model):
            from services.similarity_search.main import search_similar_alerts
            from shared.models import VectorSearchRequest

            request = VectorSearchRequest(
                query_text="malware infection on server",
                top_k=5,
                min_similarity=0.5,
            )

            response = await search_similar_alerts(request)

            assert response is not None
            assert hasattr(response, 'data')
            results = response.data.results
            assert len(results) == 2
            assert results[0].alert_id == "ALERT-001"
            assert results[0].similarity_score == pytest.approx(0.9)  # 1 - 0.1

    def test_similarity_score_conversion(self):
        """Test distance to similarity conversion."""
        # Distance 0.0 -> Similarity 1.0
        # Distance 0.5 -> Similarity 0.5
        # Distance 1.0 -> Similarity 0.0
        distances = [0.0, 0.25, 0.5, 0.75, 1.0]
        expected_similarities = [1.0, 0.75, 0.5, 0.25, 0.0]

        for dist, exp_sim in zip(distances, expected_similarities):
            similarity = 1.0 - dist
            assert abs(similarity - exp_sim) < 0.001

    @pytest.mark.asyncio
    async def test_min_similarity_filter(self, mock_collection):
        """Test minimum similarity threshold filtering."""
        import numpy as np

        # Mock results with varying distances
        mock_collection.query.return_value = {
            "ids": [["ALERT-001", "ALERT-002", "ALERT-003"]],
            "distances": [[0.1, 0.4, 0.8]],  # Similarities: 0.9, 0.6, 0.2
            "metadatas": [[
                {"risk_level": "high"},
                {"risk_level": "medium"},
                {"risk_level": "low"},
            ]],
        }

        # Mock embedding model
        mock_embedding_model = Mock()
        mock_embedding_model.encode.return_value = np.array([0.1, 0.2, 0.3, 0.4, 0.5])

        with patch('services.similarity_search.main.collection', mock_collection), \
             patch('services.similarity_search.main.embedding_model', mock_embedding_model):
            from services.similarity_search.main import search_similar_alerts
            from shared.models import VectorSearchRequest

            request = VectorSearchRequest(
                query_text="test",
                top_k=3,
                min_similarity=0.5,  # Should only return first 2
            )

            response = await search_similar_alerts(request)
            results = response.data.results

            # Only ALERT-001 (0.9) and ALERT-002 (0.6) should pass threshold
            assert len(results) == 2
            assert results[0].alert_id == "ALERT-001"
            assert results[1].alert_id == "ALERT-002"


class TestAlertIndexing:
    """Test alert indexing."""

    @pytest.fixture
    def mock_collection(self):
        """Create mock ChromaDB collection."""
        collection = Mock()
        collection.add.return_value = None
        collection.update.return_value = None
        return collection

    @pytest.mark.asyncio
    async def test_index_alert(self, mock_collection):
        """Test indexing a single alert."""
        import numpy as np

        # Mock embedding model
        mock_embedding_model = Mock()
        mock_embedding_model.encode.return_value = np.array([0.1, 0.2, 0.3, 0.4, 0.5])

        with patch('services.similarity_search.main.collection', mock_collection), \
             patch('services.similarity_search.main.embedding_model', mock_embedding_model):
            from services.similarity_search.main import index_alert
            from shared.models import SecurityAlert
            from datetime import datetime

            alert = SecurityAlert(
                alert_id="TEST-001",
                alert_type="malware",
                severity="high",
                description="Test alert",
                timestamp=datetime.now().replace(year=2025, month=1, day=1),
            )

            result = await index_alert(alert)

            assert result["success"] is True
            assert "TEST-001" in result["message"]
            mock_collection.add.assert_called_once()

    @pytest.mark.asyncio
    async def test_index_with_triage_result(self, mock_collection):
        """Test indexing alert with triage result."""
        import numpy as np

        # Mock embedding model
        mock_embedding_model = Mock()
        mock_embedding_model.encode.return_value = np.array([0.1, 0.2, 0.3, 0.4, 0.5])

        with patch('services.similarity_search.main.collection', mock_collection), \
             patch('services.similarity_search.main.embedding_model', mock_embedding_model):
            from services.similarity_search.main import index_alert
            from shared.models import SecurityAlert
            from datetime import datetime

            alert = SecurityAlert(
                alert_id="TEST-001",
                alert_type="malware",
                severity="high",
                description="Test alert",
                timestamp=datetime.now().replace(year=2025, month=1, day=1),
            )

            triage_result = {
                "risk_level": "critical",
                "confidence": 95,
            }

            result = await index_alert(alert, triage_result)

            assert result["success"] is True

            # Check metadata includes triage result
            call_args = mock_collection.add.call_args
            metadata = call_args[1]["metadatas"][0]
            assert "risk_level" in metadata
            assert metadata["risk_level"] == "critical"


@pytest.mark.integration
class TestSimilaritySearchIntegration:
    """Integration tests for similarity search."""

    @pytest.mark.asyncio
    async def test_end_to_end_search_flow(self):
        """Test complete search flow."""
        # This test requires running services
        pytest.skip("Requires running services")

    @pytest.mark.asyncio
    async def test_vectorization_performance(self):
        """Test vectorization performance."""
        pytest.skip("Requires running services")

    def test_search_latency_under_1s(self):
        """Test search latency is under 1 second."""
        pytest.skip("Requires running services and sample data")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
