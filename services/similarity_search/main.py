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

"""Similarity Search Service - Uses ChromaDB for vector similarity search."""

import asyncio
import json
import os
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from shared.database import get_database_manager, init_database, close_database
from shared.messaging import MessageConsumer
from shared.models import (
    AlertType,
    EmbeddingModel,
    EmbeddingRequest,
    EmbeddingResponse,
    IndexStats,
    ResponseMeta,
    SecurityAlert,
    Severity,
    SimilarAlert,
    SuccessResponse,
    VectorSearchRequest,
    VectorSearchResponse,
)
from shared.utils import Config, get_logger, utc_now, utc_now_iso

logger = get_logger(__name__)
config = Config()

db_manager = None
consumer = None

# ChromaDB and embedding model will be initialized on startup
chroma_client = None
collection = None
embedding_model = None
SIMILARITY_MOCK_MODE = os.getenv("SIMILARITY_MOCK_MODE", "false").lower() == "true"
MOCK_EMBEDDING_DIM = int(os.getenv("MOCK_EMBEDDING_DIM", "128"))

VECTORIZE_ON_STARTUP = os.getenv("VECTORIZE_ON_STARTUP", "true").lower() == "true"
VECTORIZE_LIMIT = int(os.getenv("VECTORIZE_LIMIT", "0"))
VECTORIZE_BATCH = int(os.getenv("VECTORIZE_BATCH", "200"))


def initialize_embedding_model(model_name: str):
    """Initialize sentence transformer model."""
    try:
        if SIMILARITY_MOCK_MODE:
            logger.warning("SIMILARITY_MOCK_MODE enabled; using mock embeddings")
            return "mock"
        from sentence_transformers import SentenceTransformer

        model = SentenceTransformer(model_name)
        logger.info(f"Loaded embedding model: {model_name}")
        return model
    except ImportError:
        logger.error("sentence_transformers not installed")
        raise HTTPException(
            status_code=500,
            detail="sentence_transformers library required. Install with: pip install sentence-transformers",
        )
    except Exception as e:
        logger.error(f"Failed to load embedding model: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to load embedding model: {str(e)}")


def generate_mock_embedding(text: str) -> List[float]:
    """Generate deterministic mock embedding for offline environments."""
    import hashlib

    digest = hashlib.sha256(text.encode("utf-8")).digest()
    values = []
    for i in range(MOCK_EMBEDDING_DIM):
        values.append(digest[i % len(digest)] / 255.0)
    return values


def initialize_chromadb():
    """Initialize ChromaDB client and collection."""
    try:
        import chromadb
        from chromadb.config import Settings

        # Use persistent storage
        persist_path = os.getenv("CHROMA_PERSIST_PATH", "./data/chroma")
        client = chromadb.PersistentClient(
            path=persist_path, settings=Settings(anonymized_telemetry=False)
        )

        # Get or create collection
        collection_name = "security_alerts"
        try:
            collection = client.get_collection(name=collection_name)
            logger.info(f"Loaded existing collection: {collection_name}")
        except:
            collection = client.create_collection(
                name=collection_name, metadata={"hnsw:space": "cosine"}
            )
            logger.info(f"Created new collection: {collection_name}")

        return client, collection

    except ImportError:
        logger.error("chromadb not installed")
        raise HTTPException(
            status_code=500, detail="chromadb library required. Install with: pip install chromadb"
        )
    except Exception as e:
        logger.error(f"Failed to initialize ChromaDB: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to initialize ChromaDB: {str(e)}")


def alert_to_text(alert: SecurityAlert) -> str:
    """Convert alert to text for embedding."""
    parts = [
        f"Alert Type: {alert.alert_type}",
        f"Severity: {alert.severity}",
        f"Description: {alert.description}",
    ]

    if alert.source_ip:
        parts.append(f"Source IP: {alert.source_ip}")

    if alert.target_ip:
        parts.append(f"Target IP: {alert.target_ip}")

    if alert.file_hash:
        parts.append(f"File Hash: {alert.file_hash}")

    if alert.url:
        parts.append(f"URL: {alert.url}")

    # Safely access optional attributes
    process_name = getattr(alert, "process_name", None)
    if process_name:
        parts.append(f"Process: {process_name}")

    return ". ".join(parts)


def alert_from_row(row: Any) -> SecurityAlert:
    """Build SecurityAlert from DB row."""
    alert_type = AlertType.from_string(row.alert_type) if row.alert_type else AlertType.OTHER
    try:
        severity = Severity(row.severity) if row.severity else Severity.MEDIUM
    except Exception:
        severity = Severity.MEDIUM

    return SecurityAlert(
        alert_id=row.alert_id,
        timestamp=row.received_at,
        alert_type=alert_type,
        severity=severity,
        description=row.description or "No description",
        source_ip=row.source_ip,
        target_ip=row.destination_ip,
        file_hash=row.file_hash,
        url=row.url,
        asset_id=row.asset_id,
        user_id=row.user_name,
        raw_data=row.raw_data,
    )


async def reindex_from_database(limit: int = 0, batch_size: int = 200):
    """Load alerts from DB and upsert into vector index."""
    if collection is None:
        logger.warning("ChromaDB collection not initialized; skipping reindex")
        return

    query = """
        SELECT alert_id, received_at, alert_type, severity, description,
               source_ip, destination_ip, file_hash, url, asset_id, user_name, raw_data
        FROM alerts
        ORDER BY received_at DESC
    """
    if limit and limit > 0:
        query += " LIMIT :limit"

    indexed = 0
    failed = 0

    async with db_manager.get_session() as session:
        result = await session.execute(text(query), {"limit": limit} if limit and limit > 0 else {})
        rows = result.fetchall()

    total = len(rows)
    if total == 0:
        logger.info("No alerts found for vectorization")
        return

    logger.info(f"Vectorizing {total} alerts from database")

    for idx, row in enumerate(rows, 1):
        try:
            alert = alert_from_row(row)
            await index_alert(alert)
            indexed += 1
        except Exception as e:
            failed += 1
            logger.warning(f"Failed to index alert {getattr(row, 'alert_id', 'unknown')}: {e}")

        if idx % batch_size == 0 or idx == total:
            logger.info(f"Vectorization progress: {idx}/{total} (ok={indexed}, failed={failed})")


def generate_embedding(text: str) -> List[float]:
    """Generate embedding for text."""
    if embedding_model is None:
        raise HTTPException(status_code=500, detail="Embedding model not initialized")

    if SIMILARITY_MOCK_MODE or embedding_model == "mock":
        return generate_mock_embedding(text)

    embedding = embedding_model.encode(text, convert_to_numpy=True)
    return embedding.tolist()


async def consume_alert_results():
    """Consume triage results and index alerts into ChromaDB."""

    async def process_message(message: dict):
        try:
            if "data" in message and isinstance(message["data"], dict):
                actual_message = message["data"]
                meta = message.get("_meta", {})
                message_id = meta.get("message_id", actual_message.get("message_id", "unknown"))
            else:
                actual_message = message
                message_id = actual_message.get("message_id", "unknown")

            payload = actual_message.get("payload", actual_message)
            alert_data = payload.get("alert")
            triage_result = payload.get("triage_result")

            if not alert_data:
                logger.warning(f"No alert data in message {message_id}")
                return

            alert = SecurityAlert(**alert_data)

            # Index alert with triage metadata
            await index_alert(alert, triage_result)
            logger.info(f"Indexed alert from queue (message_id: {message_id}, alert_id: {alert.alert_id})")

        except Exception as e:
            logger.error(f"Failed to process alert.result message: {e}", exc_info=True)
            raise

    await consumer.consume(process_message)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifespan."""
    global db_manager, consumer, chroma_client, collection, embedding_model

    logger.info("Starting Similarity Search service...")

    try:
        # Initialize database FIRST
        await init_database(
            database_url=config.database_url,
            pool_size=int(os.getenv("DB_POOL_SIZE", "10")),
            max_overflow=int(os.getenv("DB_MAX_OVERFLOW", "20")),
            echo=config.debug,
        )
        db_manager = get_database_manager()
        logger.info("✓ Database connected")

        # Initialize embedding model
        embedding_model = initialize_embedding_model(
            os.getenv("EMBEDDING_MODEL", "all-MiniLM-L6-v2")
        )
        logger.info("✓ Embedding model initialized")

        # Initialize ChromaDB
        chroma_client, collection = initialize_chromadb()
        logger.info("✓ ChromaDB initialized")

        # Initialize message consumer (optional, for indexing alerts)
        try:
            consumer = MessageConsumer(config.rabbitmq_url, "alert.result")
            await consumer.connect()
            logger.info("✓ Message consumer connected")
            asyncio.create_task(consume_alert_results())
            logger.info("✓ Alert result consumer task started")
        except Exception as e:
            logger.warning(f"Could not connect to message queue: {e}")

        if VECTORIZE_ON_STARTUP:
            asyncio.create_task(reindex_from_database(VECTORIZE_LIMIT, VECTORIZE_BATCH))
            logger.info("✓ Vectorization task started")

        logger.info("✓ Similarity Search service started successfully")

        yield

    except Exception as e:
        logger.error(f"Failed to start service: {e}")
        raise

    finally:
        # Cleanup
        if consumer:
            await consumer.close()
            logger.info("✓ Message consumer closed")
        await close_database()
        logger.info("✓ Database connection closed")
        logger.info("✓ Similarity Search service stopped")


app = FastAPI(
    title="Similarity Search Service",
    description="Vector similarity search for security alerts using ChromaDB",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.post("/api/v1/search", response_model=SuccessResponse[VectorSearchResponse])
async def search_similar_alerts(request: VectorSearchRequest):
    """
    Search for similar alerts using vector similarity.

    Process:
    1. Generate embedding for query
    2. Search ChromaDB for similar vectors
    3. Return ranked results with similarity scores
    """
    try:
        start_time = time.time()

        # Build query text
        if request.query_text:
            query_text = request.query_text
        elif request.alert_data:
            # Convert alert data to text
            alert = SecurityAlert(**request.alert_data)
            query_text = alert_to_text(alert)
        else:
            raise HTTPException(
                status_code=400, detail="Either query_text or alert_data must be provided"
            )

        # Generate embedding
        query_embedding = generate_embedding(query_text)

        # Build where filter if provided
        where_filter = None
        if request.filters:
            where_filter = {}
            for key, value in request.filters.items():
                if key in ["alert_type", "severity", "risk_level"]:
                    where_filter[key] = value

        # Search ChromaDB
        results = collection.query(
            query_embeddings=[query_embedding],
            n_results=request.top_k,
            where=where_filter if where_filter else None,
        )

        # Process results
        similar_alerts = []
        if results["ids"] and results["ids"][0]:
            for i, alert_id in enumerate(results["ids"][0]):
                similarity_score = (
                    1.0 - results["distances"][0][i]
                )  # Convert distance to similarity
                metadata = results["metadatas"][0][i] if results["metadatas"] else {}

                # Filter by minimum similarity
                if similarity_score < request.min_similarity:
                    continue

                alert_data = metadata.get("alert_data", {})
                if isinstance(alert_data, str):
                    try:
                        alert_data = json.loads(alert_data)
                    except Exception:
                        alert_data = {}

                triage_result = metadata.get("triage_result")
                if isinstance(triage_result, str):
                    try:
                        triage_result = json.loads(triage_result)
                    except Exception:
                        triage_result = None

                similar_alerts.append(
                    SimilarAlert(
                        alert_id=alert_id,
                        similarity_score=similarity_score,
                        alert_data=alert_data,
                        matched_fields=metadata.get("matched_fields", []),
                        risk_level=metadata.get("risk_level"),
                        triage_result=triage_result,
                        created_at=datetime.fromisoformat(
                            metadata.get("created_at", utc_now_iso())
                        ),
                    )
                )

        search_time = (time.time() - start_time) * 1000  # Convert to ms

        response = VectorSearchResponse(
            results=similar_alerts,
            total_results=len(similar_alerts),
            search_time_ms=search_time,
        )

        return SuccessResponse(
            data=response,
            meta=ResponseMeta(
                timestamp=utc_now(),
                request_id=str(uuid.uuid4()),
            ),
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Search failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Search failed: {str(e)}")


@app.post("/api/v1/embeddings", response_model=SuccessResponse[EmbeddingResponse])
async def generate_embeddings(request: EmbeddingRequest):
    """
    Generate embeddings for text(s).

    Useful for:
    - Testing embeddings
    - Custom search implementations
    - Batch processing
    """
    try:
        # Generate embeddings
        embeddings = []
        for text in request.texts:
            embedding = generate_embedding(text)
            embeddings.append(embedding)

        # Get dimension
        dimension = len(embeddings[0]) if embeddings else 0

        response = EmbeddingResponse(
            embeddings=embeddings,
            model=request.model,
            dimension=dimension,
        )

        return SuccessResponse(
            data=response,
            meta=ResponseMeta(
                timestamp=utc_now(),
                request_id=str(uuid.uuid4()),
            ),
        )

    except Exception as e:
        logger.error(f"Embedding generation failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Embedding generation failed: {str(e)}")


@app.post("/api/v1/index", response_model=Dict[str, Any])
async def index_alert(alert: SecurityAlert, triage_result: Optional[Dict[str, Any]] = None):
    """
    Manually index an alert for similarity search.

    Automatically called when consuming from alert.result queue,
    but also available for manual indexing.
    """
    try:
        # Convert alert to text
        text = alert_to_text(alert)

        # Generate embedding
        embedding = generate_embedding(text)

        # Prepare metadata
        metadata = {
            "alert_id": alert.alert_id,
            "alert_type": alert.alert_type.value,
            "severity": alert.severity.value,
            "description": alert.description,
            "created_at": alert.timestamp.isoformat(),
            # Chroma metadata must be scalar/array types; store JSON string
            "alert_data": json.dumps(alert.model_dump(mode="json")),
        }

        if triage_result:
            metadata["risk_level"] = triage_result.get("risk_level")
            metadata["triage_result"] = json.dumps(triage_result)

        # Add to ChromaDB. Keep add-first behavior for compatibility with existing tests/mocks.
        try:
            collection.add(embeddings=[embedding], ids=[alert.alert_id], metadatas=[metadata])
        except Exception:
            # Fallback to upsert when ID already exists.
            collection.upsert(embeddings=[embedding], ids=[alert.alert_id], metadatas=[metadata])

        logger.info(f"Indexed alert {alert.alert_id}")

        return {
            "success": True,
            "message": f"Alert {alert.alert_id} indexed successfully",
            "meta": {
                "timestamp": utc_now_iso(),
                "request_id": str(uuid.uuid4()),
            },
        }

    except Exception as e:
        logger.error(f"Indexing failed: {e}", exc_info=True)
        return {
            "success": False,
            "error": str(e),
            "meta": {
                "timestamp": utc_now_iso(),
                "request_id": str(uuid.uuid4()),
            },
        }


@app.get("/api/v1/stats", response_model=SuccessResponse[IndexStats])
async def get_index_stats():
    """Get vector index statistics."""
    try:
        count = collection.count()

        # Get embedding dimension
        sample_embedding = generate_embedding("test")
        dimension = len(sample_embedding)

        stats = IndexStats(
            total_vectors=count,
            dimension=dimension,
            index_type="HNSW",
            last_updated=datetime.utcnow(),
        )

        return SuccessResponse(
            data=stats,
            meta=ResponseMeta(
                timestamp=datetime.utcnow(),
                request_id=str(uuid.uuid4()),
            ),
        )

    except Exception as e:
        logger.error(f"Failed to get stats: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to get stats: {str(e)}")


@app.delete("/api/v1/index/{alert_id}", response_model=Dict[str, Any])
async def delete_from_index(alert_id: str):
    """Delete an alert from the index."""
    try:
        collection.delete(ids=[alert_id])

        return {
            "success": True,
            "message": f"Alert {alert_id} deleted from index",
            "meta": {
                "timestamp": datetime.utcnow().isoformat(),
                "request_id": str(uuid.uuid4()),
            },
        }

    except Exception as e:
        logger.error(f"Delete failed: {e}", exc_info=True)
        return {
            "success": False,
            "error": str(e),
            "meta": {
                "timestamp": datetime.utcnow().isoformat(),
                "request_id": str(uuid.uuid4()),
            },
        }


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    health_status = {
        "status": "healthy",
        "service": "similarity-search",
        "timestamp": datetime.utcnow().isoformat(),
        "embedding_model": "mock" if SIMILARITY_MOCK_MODE else "all-MiniLM-L6-v2",
        "chromadb": "connected" if chroma_client else "disconnected",
    }

    if collection:
        health_status["total_vectors"] = collection.count()

    return health_status


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=config.host, port=config.port)
