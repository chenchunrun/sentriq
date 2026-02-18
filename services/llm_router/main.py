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

"""LLM Router Service - Intelligently routes requests to DeepSeek or Qwen models."""

import asyncio
import os
import re
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

import httpx
from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from shared.database import DatabaseManager, close_database, get_database_manager, init_database
from shared.models import (
    LLMChoice,
    LLMMessage,
    LLMModel,
    LLMProvider,
    LLMRequest,
    LLMResponse,
    LLMUsage,
    ModelCapabilities,
    ResponseMeta,
    RouterDecision,
    SuccessResponse,
    TaskType,
)
from shared.utils import Config, get_logger

logger = get_logger(__name__)
config = Config()

db_manager = None
http_client: httpx.AsyncClient = None

# Model capabilities registry
MODEL_CAPABILITIES: Dict[LLMModel, ModelCapabilities] = {
    # DeepSeek models
    LLMModel.DEEPSEEK_V3: ModelCapabilities(
        model=LLMModel.DEEPSEEK_V3,
        max_context=32000,
        supports_streaming=True,
        cost_per_1k_tokens=0.002,
        speed=8,
        reasoning_quality=9,
        best_for=[TaskType.TRIAGE, TaskType.ANALYSIS, TaskType.CODE_REVIEW],
    ),
    LLMModel.DEEPSEEK_CODER: ModelCapabilities(
        model=LLMModel.DEEPSEEK_CODER,
        max_context=16000,
        supports_streaming=True,
        cost_per_1k_tokens=0.001,
        speed=9,
        reasoning_quality=7,
        best_for=[TaskType.CODE_REVIEW, TaskType.CLASSIFICATION],
    ),
    # Qwen models
    LLMModel.QWEN3_MAX: ModelCapabilities(
        model=LLMModel.QWEN3_MAX,
        max_context=32000,
        supports_streaming=True,
        cost_per_1k_tokens=0.004,
        speed=7,
        reasoning_quality=10,
        best_for=[TaskType.ANALYSIS, TaskType.TRIAGE, TaskType.GENERAL],
    ),
    LLMModel.QWEN3_PLUS: ModelCapabilities(
        model=LLMModel.QWEN3_PLUS,
        max_context=32000,
        supports_streaming=True,
        cost_per_1k_tokens=0.002,
        speed=8,
        reasoning_quality=8,
        best_for=[TaskType.TRIAGE, TaskType.ANALYSIS, TaskType.SUMMARIZATION],
    ),
    LLMModel.QWEN3_TURBO: ModelCapabilities(
        model=LLMModel.QWEN3_TURBO,
        max_context=8000,
        supports_streaming=True,
        cost_per_1k_tokens=0.0005,
        speed=10,
        reasoning_quality=6,
        best_for=[TaskType.CLASSIFICATION, TaskType.SUMMARIZATION, TaskType.GENERAL],
    ),
}

# Provider API endpoints (configure via environment)
PROVIDER_ENDPOINTS = {
    LLMProvider.DEEPSEEK: "https://api.deepseek.com/v1",
    LLMProvider.QWEN: "https://dashscope.aliyuncs.com/compatible-mode/v1",
}


# =============================================================================
# Complexity Analysis Functions
# =============================================================================


def extract_iocs(messages: List[Dict[str, str]]) -> Dict[str, List[str]]:
    """
    Extract Indicators of Compromise (IOCs) from messages.

    Returns dict with categorized IOCs: ips, hashes, urls, domains, cves
    """
    iocs = {
        "ips": [],
        "hashes": [],
        "urls": [],
        "domains": [],
        "cves": [],
    }

    # Combine all message content
    content = " ".join(msg.get("content", "") for msg in messages)

    # IP addresses (IPv4)
    ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    iocs["ips"] = list(set(re.findall(ip_pattern, content)))

    # File hashes (MD5, SHA1, SHA256)
    hash_patterns = [
        r'\b[a-fA-F0-9]{32}\b',  # MD5
        r'\b[a-fA-F0-9]{40}\b',  # SHA1
        r'\b[a-fA-F0-9]{64}\b',  # SHA256
    ]
    for pattern in hash_patterns:
        iocs["hashes"].extend(re.findall(pattern, content))
    iocs["hashes"] = list(set(iocs["hashes"]))

    # URLs
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    iocs["urls"] = list(set(re.findall(url_pattern, content)))

    # CVE IDs
    cve_pattern = r'CVE-\d{4}-\d{4,7}'
    iocs["cves"] = list(set(re.findall(cve_pattern, content, re.IGNORECASE)))

    # Domains (simplified - excludes common false positives)
    domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
    potential_domains = re.findall(domain_pattern, content)
    # Filter out numeric-only TLDs and common non-threat patterns
    iocs["domains"] = [d for d in set(potential_domains) if not d.endswith(('.html', '.jpg', '.png', '.css', '.js'))]

    return iocs


def extract_threat_scores(messages: List[Dict[str, str]]) -> List[int]:
    """Extract threat scores mentioned in messages."""
    content = " ".join(msg.get("content", "") for msg in messages)

    # Look for threat_score, risk_score, confidence patterns
    patterns = [
        r'"threat_score["\']?\s*[:=]\s*(\d+)',
        r'"risk_score["\']?\s*[:=]\s*(\d+)',
        r'threat[_-]?level["\']?\s*[:=]\s*"?(\d+)"?',
        r'score["\']?\s*[:=]\s*(\d+)',
    ]

    scores = []
    for pattern in patterns:
        matches = re.findall(pattern, content, re.IGNORECASE)
        scores.extend(int(m) for m in matches)

    return scores


def analyze_complexity(request: LLMRequest) -> Tuple[str, Dict[str, bool]]:
    """
    Analyze request complexity based on multiple factors.

    Returns:
        Tuple of (complexity_level, factors)
        complexity_level: "high", "medium", or "low"
        factors: Dict of factor name -> boolean indicating if present
    """
    factors = {}

    # Extract IOCs from messages
    iocs = extract_iocs(request.messages)

    # Factor 1: Multiple IOCs present
    total_iocs = sum(len(v) for v in iocs.values())
    factors["multi_ioc"] = total_iocs > 1

    # Factor 2: High threat scores mentioned
    threat_scores = extract_threat_scores(request.messages)
    factors["high_threat_score"] = any(score > 70 for score in threat_scores)

    # Factor 3: Critical severity keywords
    content = " ".join(msg.get("content", "") for msg in request.messages).lower()
    critical_keywords = ["critical", "severe", "malware", "ransomware", "apt", "data_exfiltration", "zero-day"]
    factors["critical_severity"] = any(kw in content for kw in critical_keywords)

    # Factor 4: CVE references present
    factors["has_cve"] = len(iocs["cves"]) > 0

    # Factor 5: Multiple source IPs (potential multi-stage attack)
    factors["multi_source"] = len(iocs["ips"]) > 2

    # Factor 6: Asset criticality keywords
    asset_keywords = ["critical", "production", "database", "server", "financial", "pii", "sensitive"]
    factors["critical_asset"] = any(kw in content for kw in asset_keywords)

    # Factor 7: Task type complexity
    complex_task_types = [TaskType.TRIAGE, TaskType.ANALYSIS, TaskType.CODE_REVIEW]
    factors["complex_task"] = request.task_type in complex_task_types

    # Factor 8: Message length (longer = more complex context)
    total_length = sum(len(msg.get("content", "")) for msg in request.messages)
    factors["long_context"] = total_length > 2000

    # Calculate complexity score
    factor_count = sum(1 for v in factors.values() if v)

    if factor_count >= 4:
        complexity = "high"
    elif factor_count >= 2:
        complexity = "medium"
    else:
        complexity = "low"

    logger.info(
        f"Complexity analysis: {complexity} (factors: {factor_count}/8)",
        extra={"complexity": complexity, "factors": factors, "iocs_found": total_iocs}
    )

    return complexity, factors


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifespan."""
    global db_manager, http_client

    logger.info("Starting LLM Router service...")

    try:
        # Initialize database FIRST before getting manager
        await init_database(
            database_url=config.database_url,
            pool_size=int(os.getenv("DB_POOL_SIZE", "10")),
            max_overflow=int(os.getenv("DB_MAX_OVERFLOW", "20")),
            echo=config.debug,
        )
        db_manager = get_database_manager()
        logger.info("✓ Database connected")

        # Initialize HTTP client for LLM API calls
        http_client = httpx.AsyncClient(
            timeout=httpx.Timeout(60.0, connect=10.0),
            limits=httpx.Limits(max_keepalive_connections=50, max_connections=100),
        )
        logger.info("✓ HTTP client initialized")

        logger.info("✓ LLM Router service started successfully")

        yield

    except Exception as e:
        logger.error(f"Failed to start service: {e}")
        raise

    finally:
        # Cleanup
        if http_client:
            await http_client.aclose()
            logger.info("✓ HTTP client closed")

        # Close database using the close_database function
        await close_database()
        logger.info("✓ Database connection closed")

        logger.info("✓ LLM Router service stopped")


app = FastAPI(
    title="LLM Router Service",
    description="Intelligently routes LLM requests to optimal models",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def route_request(request: LLMRequest) -> RouterDecision:
    """
    Route request to optimal model based on task, context, and complexity.

    Routing strategy:
    1. If model specified, use it
    2. Analyze complexity using IOC extraction and content analysis
    3. Select model based on complexity:
       - high complexity -> DeepSeek-V3 (deep reasoning)
       - medium complexity -> Qwen3-Max or Qwen3-Plus (balanced)
       - low complexity -> Qwen3-Turbo (fast response)
    4. Match task type to model capabilities
    5. Apply fallback logic if needed
    """
    # If user specified a model, use it
    if request.model:
        caps = MODEL_CAPABILITIES.get(request.model)
        if not caps:
            raise HTTPException(status_code=400, detail=f"Model {request.model} not found")

        provider = LLMProvider.DEEPSEEK if "deepseek" in request.model.value else LLMProvider.QWEN

        return RouterDecision(
            selected_provider=provider,
            selected_model=request.model,
            reason="User specified model",
            confidence=1.0,
            alternatives=[],
        )

    # Step 1: Analyze complexity
    complexity, complexity_factors = analyze_complexity(request)

    # Step 2: Calculate token count
    total_tokens = sum(len(msg.get("content", "")) // 4 for msg in request.messages)

    # Step 3: Select model based on complexity
    selected_model: Optional[LLMModel] = None
    reason = ""
    confidence = 0.8

    if complexity == "high":
        # High complexity: Use DeepSeek-V3 for deep reasoning
        # Prefer DeepSeek-V3 if available, otherwise use Qwen3-Max
        if total_tokens <= MODEL_CAPABILITIES[LLMModel.DEEPSEEK_V3].max_context:
            selected_model = LLMModel.DEEPSEEK_V3
            reason = f"High complexity request (factors: {sum(complexity_factors.values())}), using deep reasoning model"
            confidence = 0.95
        else:
            # Context too large, use Qwen3-Max with larger context
            selected_model = LLMModel.QWEN3_MAX
            reason = f"High complexity with large context, using extended context model"
            confidence = 0.9

    elif complexity == "medium":
        # Medium complexity: Use Qwen3-Max or Qwen3-Plus for balanced performance
        if request.task_type in [TaskType.TRIAGE, TaskType.ANALYSIS]:
            selected_model = LLMModel.QWEN3_MAX
            reason = f"Medium complexity {request.task_type} task, using balanced model with high reasoning"
            confidence = 0.9
        else:
            selected_model = LLMModel.QWEN3_PLUS
            reason = f"Medium complexity {request.task_type} task, using balanced model"
            confidence = 0.85

    else:
        # Low complexity: Use Qwen3-Turbo for fast response
        selected_model = LLMModel.QWEN3_TURBO
        reason = f"Low complexity request, using fast response model"
        confidence = 0.85

    # Step 4: Verify model can handle the request
    caps = MODEL_CAPABILITIES.get(selected_model)
    if caps and total_tokens > caps.max_context:
        # Find a model with larger context
        for model, model_caps in MODEL_CAPABILITIES.items():
            if model_caps.max_context >= total_tokens:
                selected_model = model
                reason += f" (switched to {model.value} for context size)"
                break

    # Step 5: Determine provider from model
    provider = LLMProvider.DEEPSEEK if "deepseek" in selected_model.value else LLMProvider.QWEN

    # Get alternatives based on task type
    alternatives = [
        m
        for m in MODEL_CAPABILITIES.keys()
        if m != selected_model and request.task_type in MODEL_CAPABILITIES[m].best_for
    ][:3]

    return RouterDecision(
        selected_provider=provider,
        selected_model=selected_model,
        reason=reason,
        confidence=confidence,
        fallback_used=False,
        alternatives=alternatives,
    )


async def call_deepseek(
    request: LLMRequest,
    decision: RouterDecision,
    api_key: str,
) -> LLMResponse:
    """Call DeepSeek API."""
    endpoint = f"{PROVIDER_ENDPOINTS[LLMProvider.DEEPSEEK]}/chat/completions"

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    payload = {
        "model": decision.selected_model.value,
        "messages": request.messages,
        "temperature": request.temperature,
        "max_tokens": request.max_tokens,
        "top_p": request.top_p,
        "stream": request.stream,
    }

    try:
        response = await http_client.post(endpoint, headers=headers, json=payload)
        response.raise_for_status()

        data = response.json()

        # Convert to our standard format
        return LLMResponse(
            id=data.get("id", f"deepseek-{uuid.uuid4()}"),
            object=data.get("object", "chat.completion"),
            created=data.get("created", int(time.time())),
            model=decision.selected_model,
            provider=LLMProvider.DEEPSEEK,
            choices=[
                LLMChoice(
                    index=c["index"],
                    message=LLMMessage(
                        role=c["message"]["role"],
                        content=c["message"]["content"],
                    ),
                    finish_reason=c.get("finish_reason"),
                )
                for c in data.get("choices", [])
            ],
            usage=LLMUsage(
                prompt_tokens=data["usage"]["prompt_tokens"],
                completion_tokens=data["usage"]["completion_tokens"],
                total_tokens=data["usage"]["total_tokens"],
            ),
            routing_decision=decision.model_dump(),
        )

    except httpx.HTTPError as e:
        logger.error(f"DeepSeek API error: {e}")
        raise HTTPException(status_code=502, detail=f"DeepSeek API error: {str(e)}")


async def call_qwen(
    request: LLMRequest,
    decision: RouterDecision,
    api_key: str,
) -> LLMResponse:
    """Call Qwen API."""
    endpoint = f"{PROVIDER_ENDPOINTS[LLMProvider.QWEN]}/chat/completions"

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    payload = {
        "model": decision.selected_model.value,
        "messages": request.messages,
        "temperature": request.temperature,
        "max_tokens": request.max_tokens,
        "top_p": request.top_p,
        "stream": request.stream,
    }

    try:
        response = await http_client.post(endpoint, headers=headers, json=payload)
        response.raise_for_status()

        data = response.json()

        # Convert to our standard format
        return LLMResponse(
            id=data.get("id", f"qwen-{uuid.uuid4()}"),
            object=data.get("object", "chat.completion"),
            created=data.get("created", int(time.time())),
            model=decision.selected_model,
            provider=LLMProvider.QWEN,
            choices=[
                LLMChoice(
                    index=c["index"],
                    message=LLMMessage(
                        role=c["message"]["role"],
                        content=c["message"]["content"],
                    ),
                    finish_reason=c.get("finish_reason"),
                )
                for c in data.get("choices", [])
            ],
            usage=LLMUsage(
                prompt_tokens=data["usage"]["prompt_tokens"],
                completion_tokens=data["usage"]["completion_tokens"],
                total_tokens=data["usage"]["total_tokens"],
            ),
            routing_decision=decision.model_dump(),
        )

    except httpx.HTTPError as e:
        logger.error(f"Qwen API error: {e}")
        raise HTTPException(status_code=502, detail=f"Qwen API error: {str(e)}")


def create_mock_response(request: LLMRequest, decision: RouterDecision) -> LLMResponse:
    """Create a mock LLM response for development/testing."""
    mock_content = f"""# Security Alert Analysis (Mock Response)

**Alert Type**: {request.task_type.value}
**Model**: {decision.selected_model.value}
**Provider**: {decision.selected_provider.value}

## Analysis Summary
This is a mock response generated for development and testing purposes.
To enable real LLM analysis, configure DEEPSEEK_API_KEY or QWEN_API_KEY in .env

## Risk Assessment
- **Risk Score**: 65/100
- **Confidence**: Medium
- **Recommended Action**: Investigate further

## Key Factors
1. Alert severity indicates potential security concern
2. No threat intelligence data available (mock mode)
3. Asset criticality: Medium
4. Requires human review for confirmation

---
*Generated by {decision.selected_model.value} at {datetime.utcnow().isoformat()}*
"""

    return LLMResponse(
        id=f"mock-{uuid.uuid4()}",
        object="chat.completion",
        created=int(time.time()),
        model=decision.selected_model,
        provider=decision.selected_provider,
        choices=[
            LLMChoice(
                index=0,
                message=LLMMessage(
                    role="assistant",
                    content=mock_content,
                ),
                finish_reason="stop",
            )
        ],
        usage=LLMUsage(
            prompt_tokens=100,
            completion_tokens=150,
            total_tokens=250,
        ),
        routing_decision=decision.model_dump(),
        _mock=True,
    )


@app.post("/api/v1/chat/completions", response_model=SuccessResponse[LLMResponse])
async def chat_completions(request: LLMRequest):
    """
    Main endpoint for LLM chat completions.

    Automatically routes to the best model based on:
    - Task type
    - Request complexity
    - Model capabilities
    - Cost vs quality tradeoffs
    """
    try:
        # Route request
        decision = route_request(request)
        logger.info(
            f"Routing request to {decision.selected_model.value} " f"(reason: {decision.reason})"
        )

        # Check if mock mode is enabled
        mock_mode = os.getenv("LLM_MOCK_MODE", "false").lower() == "true"

        # Get API key from environment
        if decision.selected_provider == LLMProvider.DEEPSEEK:
            api_key = os.getenv("DEEPSEEK_API_KEY")
            if not api_key or mock_mode:
                if mock_mode:
                    logger.warning("Using mock LLM response (LLM_MOCK_MODE=true)")
                    response = create_mock_response(request, decision)
                else:
                    raise HTTPException(status_code=500, detail="DEEPSEEK_API_KEY not configured")
            else:
                response = await call_deepseek(request, decision, api_key)

        else:  # QWEN
            api_key = os.getenv("QWEN_API_KEY")
            if not api_key or mock_mode:
                if mock_mode:
                    logger.warning("Using mock LLM response (LLM_MOCK_MODE=true)")
                    response = create_mock_response(request, decision)
                else:
                    raise HTTPException(status_code=500, detail="QWEN_API_KEY not configured")
            else:
                response = await call_qwen(request, decision, api_key)

        logger.info(
            f"Request completed using {response.provider.value}/{response.model.value} "
            f"(tokens: {response.usage.total_tokens})"
        )

        return SuccessResponse(
            data=response,
            meta=ResponseMeta(
                timestamp=datetime.utcnow(),
                request_id=str(uuid.uuid4()),
                version="1.0.0",
            ),
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Chat completion failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@app.get("/api/v1/models", response_model=SuccessResponse[Dict[str, ModelCapabilities]])
async def list_models():
    """List available models and their capabilities."""
    return SuccessResponse(
        data=MODEL_CAPABILITIES,
        meta=ResponseMeta(
            timestamp=datetime.utcnow(),
            request_id=str(uuid.uuid4()),
        ),
    )


@app.get("/api/v1/capabilities/{model}", response_model=SuccessResponse[ModelCapabilities])
async def get_model_capabilities(model: LLMModel):
    """Get capabilities for a specific model."""
    caps = MODEL_CAPABILITIES.get(model)
    if not caps:
        raise HTTPException(status_code=404, detail=f"Model {model} not found")

    return SuccessResponse(
        data=caps,
        meta=ResponseMeta(
            timestamp=datetime.utcnow(),
            request_id=str(uuid.uuid4()),
        ),
    )


@app.post("/api/v1/route", response_model=SuccessResponse[RouterDecision])
async def route_test(request: LLMRequest):
    """
    Test routing decision without making an actual LLM call.

    Useful for understanding how requests will be routed.
    """
    decision = route_request(request)

    return SuccessResponse(
        data=decision,
        meta=ResponseMeta(
            timestamp=datetime.utcnow(),
            request_id=str(uuid.uuid4()),
        ),
    )


@app.post("/api/v1/analyze-complexity", response_model=SuccessResponse[Dict[str, Any]])
async def analyze_request_complexity(request: LLMRequest):
    """
    Analyze request complexity without routing.

    Returns detailed complexity analysis including:
    - Complexity level (high/medium/low)
    - Detected IOCs (IPs, hashes, URLs, domains, CVEs)
    - Complexity factors that influenced the decision
    """
    complexity, factors = analyze_complexity(request)
    iocs = extract_iocs(request.messages)

    return SuccessResponse(
        data={
            "complexity_level": complexity,
            "complexity_factors": factors,
            "factor_count": sum(1 for v in factors.values() if v),
            "iocs_detected": iocs,
            "total_iocs": sum(len(v) for v in iocs.values()),
            "message_count": len(request.messages),
            "estimated_tokens": sum(len(msg.get("content", "")) // 4 for msg in request.messages),
        },
        meta=ResponseMeta(
            timestamp=datetime.utcnow(),
            request_id=str(uuid.uuid4()),
        ),
    )


@app.get("/health", response_model=Dict[str, Any])
async def health_check():
    """Health check endpoint."""
    health_status = {
        "status": "healthy",
        "service": "llm-router",
        "timestamp": datetime.utcnow().isoformat(),
        "models": {
            "total": len(MODEL_CAPABILITIES),
            "deepseek": len([m for m in MODEL_CAPABILITIES.keys() if "deepseek" in m.value]),
            "qwen": len([m for m in MODEL_CAPABILITIES.keys() if "qwen" in m.value]),
        },
    }

    # Check API keys
    deepseek_key = os.getenv("DEEPSEEK_API_KEY")
    qwen_key = os.getenv("QWEN_API_KEY")

    health_status["api_keys"] = {
        "deepseek": "configured" if deepseek_key else "missing",
        "qwen": "configured" if qwen_key else "missing",
    }

    return health_status


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=config.host, port=config.port)
