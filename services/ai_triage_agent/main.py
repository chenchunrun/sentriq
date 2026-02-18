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
AI Triage Agent Service - Uses LangChain to perform intelligent alert triage.

This service consumes enriched alerts and performs AI-powered analysis:
- Routes requests to appropriate LLM models (DeepSeek-V3 or Qwen3)
- Generates prompts based on alert type
- Calls MaaS APIs with retry logic
- Parses and structures LLM responses
- Publishes triage results to alert.result queue
"""

import asyncio
import json
import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any, Dict, Optional

import httpx
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from shared.database import DatabaseManager, close_database, get_database_manager, init_database
from shared.messaging import MessageConsumer, MessagePublisher
from shared.models import SecurityAlert
from shared.utils import Config, get_logger

# Initialize logger
logger = get_logger(__name__)

# Initialize config
config = Config()

# Global variables
db_manager: DatabaseManager = None
publisher: MessagePublisher = None
consumer: MessageConsumer = None
http_client: httpx.AsyncClient = None

# Service endpoints
LLM_ROUTER_URL = os.getenv("LLM_ROUTER_URL", "http://llm-router:8000")
SIMILARITY_SEARCH_URL = os.getenv("SIMILARITY_SEARCH_URL", "http://similarity-search:9501")


# =============================================================================
# System Prompts for Different Alert Types
# =============================================================================

TRIAGE_SYSTEM_PROMPTS = {
    "malware": """You are an expert security analyst specializing in malware analysis.
Your task is to analyze security alerts related to malware infections and provide a comprehensive assessment.

You must respond in the following JSON format:
{
  "risk_level": "critical|high|medium|low|info",
  "confidence": 0-100,
  "reasoning": "Detailed explanation of your analysis",
  "indicators_of_compromise": ["List specific IOCs detected"],
  "attack_chain_analysis": "Describe the attack chain if applicable",
  "recommended_actions": [
    {"action": "Specific action to take", "priority": "critical|high|medium|low", "type": "containment|investigation|remediation"}
  ],
  "requires_human_review": true/false,
  "estimated_impact": "Description of potential impact",
  "suggested_escalation": "when/if to escalate"
}

Consider:
- Malware type and capabilities
- Threat intelligence indicators
- Target asset criticality
- Network context (internal/external)
- User context and privileges
- Historical patterns""",
    "phishing": """You are an expert security analyst specializing in phishing and social engineering attacks.
Your task is to analyze security alerts related to phishing and provide a comprehensive assessment.

You must respond in the following JSON format:
{
  "risk_level": "critical|high|medium|low|info",
  "confidence": 0-100,
  "reasoning": "Detailed explanation of your analysis",
  "phishing_indicators": ["List specific phishing indicators"],
  "target_analysis": "Analyze who is being targeted and why",
  "recommended_actions": [
    {"action": "Specific action to take", "priority": "critical|high|medium|low", "type": "containment|investigation|remediation"}
  ],
  "requires_human_review": true/false,
  "estimated_impact": "Description of potential impact",
  "affected_users": "Number/type of users affected"
}

Consider:
- Email characteristics and sender reputation
- URL and domain analysis
- Attachment analysis
- User context and awareness level
- Threat intelligence feeds""",
    "brute_force": """You are an expert security analyst specializing in authentication and access attacks.
Your task is to analyze security alerts related to brute force attacks and provide a comprehensive assessment.

You must respond in the following JSON format:
{
  "risk_level": "critical|high|medium|low|info",
  "confidence": 0-100,
  "reasoning": "Detailed explanation of your analysis",
  "attack_patterns": ["Describe attack patterns observed"],
  "source_analysis": "Analyze the source(s) of the attack",
  "recommended_actions": [
    {"action": "Specific action to take", "priority": "critical|high|medium|low", "type": "containment|investigation|remediation"}
  ],
  "requires_human_review": true/false,
  "estimated_impact": "Description of potential impact",
  "compromised_credentials_risk": "Assess risk of credential compromise"
}

Consider:
- Attack volume and timing
- Source IP reputation
- Target user privileges
- Successful vs failed attempts
- Authentication methods""",
    "data_exfiltration": """You are an expert security analyst specializing in data breach and exfiltration attacks.
Your task is to analyze security alerts related to data exfiltration and provide a comprehensive assessment.

You must respond in the following JSON format:
{
  "risk_level": "critical|high|medium|low|info",
  "confidence": 0-100,
  "reasoning": "Detailed explanation of your analysis",
  "exfiltration_methods": ["Describe methods used"],
  "data_classification": "Assess sensitivity of exposed data",
  "recommended_actions": [
    {"action": "Specific action to take", "priority": "critical|high|medium|low", "type": "containment|investigation|remediation"}
  ],
  "requires_human_review": true/false,
  "estimated_impact": "Description of potential impact",
  "compliance_implications": "List applicable compliance requirements"
}

Consider:
- Data volume and transfer patterns
- Destination and protocol
- Data sensitivity
- Asset criticality
- Encryption status""",
    "intrusion": """You are an expert security analyst specializing in network intrusions and advanced persistent threats.
Your task is to analyze security alerts related to network intrusions and provide a comprehensive assessment.

You must respond in the following JSON format:
{
  "risk_level": "critical|high|medium|low|info",
  "confidence": 0-100,
  "reasoning": "Detailed explanation of your analysis",
  "attack_stage": "reconnaissance|initial_access|execution|persistence|privilege_escalation|defense_evasion|command_control|lateral_movement|data_exfiltration|impact",
  "ttps": ["List MITRE ATT&CK techniques observed"],
  "recommended_actions": [
    {"action": "Specific action to take", "priority": "critical|high|medium|low", "type": "containment|investigation|remediation"}
  ],
  "requires_human_review": true/false,
  "estimated_impact": "Description of potential impact",
  "lateral_movement_risk": "Assess potential for lateral movement"
}

Consider:
- Attack patterns and techniques
- Source and destination context
- Threat intelligence
- Network topology
- Asset criticality
- Lateral movement potential""",
    "ddos": """You are an expert security analyst specializing in DDoS attacks and network availability threats.
Your task is to analyze security alerts related to DDoS attacks and provide a comprehensive assessment.

You must respond in the following JSON format:
{
  "risk_level": "critical|high|medium|low|info",
  "confidence": 0-100,
  "reasoning": "Detailed explanation of your analysis",
  "attack_vector": "volumetric|protocol|application",
  "attack_magnitude": "Assess scale of attack",
  "recommended_actions": [
    {"action": "Specific action to take", "priority": "critical|high|medium|low", "type": "containment|investigation|remediation"}
  ],
  "requires_human_review": true/false,
  "estimated_impact": "Description of potential impact",
  "mitigation_options": ["List mitigation options"]
}

Consider:
- Attack volume and timing
- Target resources
- Service availability impact
- Mitigation options""",
    "default": """You are an expert security analyst.
Your task is to analyze this security alert and provide a comprehensive assessment.

You must respond in the following JSON format:
{
  "risk_level": "critical|high|medium|low|info",
  "confidence": 0-100,
  "reasoning": "Detailed explanation of your analysis",
  "key_findings": ["List key findings"],
  "recommended_actions": [
    {"action": "Specific action to take", "priority": "critical|high|medium|low", "type": "containment|investigation|remediation"}
  ],
  "requires_human_review": true/false,
  "estimated_impact": "Description of potential impact"
}

Consider all available context including threat intelligence, network information, and asset details.""",
}


# =============================================================================
# Prompt Engineering
# =============================================================================


def build_triage_prompt(
    alert: SecurityAlert,
    enrichment: Dict[str, Any] = None,
) -> str:
    """
    Build triage prompt from alert and enrichment data.

    Args:
        alert: SecurityAlert object
        enrichment: Enrichment data (context, threat_intel, etc.)

    Returns:
        Formatted prompt string
    """
    prompt_parts = [
        f"# Security Alert Analysis Request",
        f"",
        f"## Alert Information",
        f"- **Alert ID**: {alert.alert_id}",
        f"- **Type**: {alert.alert_type}",
        f"- **Severity**: {alert.severity}",
        f"- **Description**: {alert.description}",
        f"- **Timestamp**: {alert.timestamp}",
    ]

    # Add technical details
    if alert.source_ip:
        prompt_parts.append(f"- **Source IP**: {alert.source_ip}")
    if alert.target_ip:
        prompt_parts.append(f"- **Target IP**: {alert.target_ip}")
    if alert.file_hash:
        prompt_parts.append(f"- **File Hash**: {alert.file_hash}")
    if alert.url:
        prompt_parts.append(f"- **URL**: {alert.url}")
    if alert.asset_id:
        prompt_parts.append(f"- **Asset ID**: {alert.asset_id}")
    if alert.user_id:
        prompt_parts.append(f"- **User ID**: {alert.user_id}")

    # Add enrichment data
    if enrichment:
        # Network context
        if "source_network" in enrichment:
            net_ctx = enrichment["source_network"]
            prompt_parts.append(f"")
            prompt_parts.append(f"## Source Network Context")
            prompt_parts.append(f"- **Internal**: {net_ctx.get('is_internal', 'Unknown')}")
            prompt_parts.append(f"- **Reputation Score**: {net_ctx.get('reputation_score', 'N/A')}")
            if net_ctx.get("country"):
                prompt_parts.append(f"- **Country**: {net_ctx['country']}")

        # Asset context
        if "asset" in enrichment:
            asset_ctx = enrichment["asset"]
            prompt_parts.append(f"")
            prompt_parts.append(f"## Asset Context")
            prompt_parts.append(f"- **Asset Name**: {asset_ctx.get('asset_name', 'Unknown')}")
            prompt_parts.append(f"- **Type**: {asset_ctx.get('asset_type', 'Unknown')}")
            prompt_parts.append(f"- **Criticality**: {asset_ctx.get('criticality', 'Unknown')}")
            prompt_parts.append(f"- **Owner**: {asset_ctx.get('owner', 'Unknown')}")
            prompt_parts.append(f"- **Environment**: {asset_ctx.get('environment', 'Unknown')}")

        # User context
        if "user" in enrichment:
            user_ctx = enrichment["user"]
            prompt_parts.append(f"")
            prompt_parts.append(f"## User Context")
            prompt_parts.append(f"- **Username**: {user_ctx.get('username', 'Unknown')}")
            prompt_parts.append(f"- **Department**: {user_ctx.get('department', 'Unknown')}")
            prompt_parts.append(
                f"- **Privilege Level**: {user_ctx.get('privilege_level', 'Unknown')}"
            )
            prompt_parts.append(
                f"- **Account Status**: {user_ctx.get('account_status', 'Unknown')}"
            )

        # Threat intelligence
        if "threat_intel" in enrichment:
            ti = enrichment["threat_intel"]
            prompt_parts.append(f"")
            prompt_parts.append(f"## Threat Intelligence")

            # Source IP threat intel
            if "source_ip" in ti:
                source_ti = ti["source_ip"]
                prompt_parts.append(
                    f"- **Source IP Threat Score**: {source_ti.get('threat_score', 'N/A')}"
                )
                if source_ti.get("sources_found", 0) > 0:
                    prompt_parts.append(f"- **Detected by {source_ti['sources_found']} sources**")

            # File hash threat intel
            if "file_hash" in ti:
                hash_ti = ti["file_hash"]
                prompt_parts.append(
                    f"- **File Hash Threat Score**: {hash_ti.get('threat_score', 'N/A')}"
                )
                if hash_ti.get("sources_found", 0) > 0:
                    prompt_parts.append(f"- **Detected by {hash_ti['sources_found']} sources**")

            # URL threat intel
            if "url" in ti:
                url_ti = ti["url"]
                prompt_parts.append(f"- **URL Threat Score**: {url_ti.get('threat_score', 'N/A')}")
                if url_ti.get("sources_found", 0) > 0:
                    prompt_parts.append(f"- **Detected by {url_ti['sources_found']} sources**")

        # Similar alerts (historical context)
        if "similar_alerts" in enrichment:
            similar = enrichment["similar_alerts"]
            results = similar.get("results", [])
            if results:
                prompt_parts.append(f"")
                prompt_parts.append(f"## Similar Historical Alerts")
                prompt_parts.append(f"Found {len(results)} similar alert(s) from historical data:")
                for i, similar_alert in enumerate(results[:5], 1):  # Top 5
                    similarity = similar_alert.get("similarity_score", 0)
                    risk = similar_alert.get("risk_level", "unknown")
                    prompt_parts.append(f"{i}. Alert ID: {similar_alert.get('alert_id', 'unknown')} (similarity: {similarity:.2%}, risk: {risk})")
                    if similar_alert.get("alert_data", {}).get("description"):
                        desc = similar_alert["alert_data"]["description"]
                        prompt_parts.append(f"   Description: {desc[:100]}...")

    prompt_parts.append(f"")
    prompt_parts.append(
        f"Please analyze this alert and provide your assessment in the required JSON format."
    )

    return "\n".join(prompt_parts)


def get_system_prompt(alert_type: str) -> str:
    """
    Get system prompt for alert type.

    Args:
        alert_type: Type of alert (malware, phishing, etc.)

    Returns:
        System prompt string
    """
    return TRIAGE_SYSTEM_PROMPTS.get(alert_type, TRIAGE_SYSTEM_PROMPTS["default"])


# =============================================================================
# LLM API Integration
# =============================================================================


async def call_llm_api(
    prompt: str,
    system_prompt: str,
    model: str,
    base_url: str,
    api_key: str,
    max_tokens: int = 2000,
    temperature: float = 0.0,
) -> Dict[str, Any]:
    """
    Call LLM API with retry logic.

    Args:
        prompt: User prompt
        system_prompt: System prompt
        model: Model name
        base_url: API base URL
        api_key: API key
        max_tokens: Maximum tokens in response
        temperature: Sampling temperature

    Returns:
        LLM response dictionary

    Raises:
        Exception: If all retries fail
    """
    max_retries = 3
    base_delay = 1.0  # seconds

    for attempt in range(max_retries):
        try:
            async with http_client.stream(
                "POST",
                f"{base_url}/chat/completions",
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {api_key}",
                },
                json={
                    "model": model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": prompt},
                    ],
                    "max_tokens": max_tokens,
                    "temperature": temperature,
                },
                timeout=120.0,  # 2 minutes timeout
            ) as response:
                if response.status_code == 200:
                    data = await response.json()
                    return data
                else:
                    error_text = await response.text()
                    logger.error(
                        f"LLM API error (attempt {attempt + 1}): {response.status_code} - {error_text}"
                    )

                    # Don't retry on client errors (4xx)
                    if 400 <= response.status_code < 500:
                        raise Exception(f"LLM API client error: {response.status_code}")

        except asyncio.TimeoutError:
            logger.error(f"LLM API timeout (attempt {attempt + 1})")
        except Exception as e:
            logger.error(f"LLM API call failed (attempt {attempt + 1}): {e}")

        # Exponential backoff
        if attempt < max_retries - 1:
            delay = base_delay * (2**attempt)
            logger.info(f"Retrying in {delay} seconds...")
            await asyncio.sleep(delay)

    raise Exception(f"LLM API call failed after {max_retries} attempts")


async def parse_llm_response(llm_response: Dict[str, Any]) -> Dict[str, Any]:
    """
    Parse and structure LLM response.

    Args:
        llm_response: Raw LLM API response

    Returns:
        Structured triage result
    """
    try:
        # Extract content from response
        if "choices" not in llm_response or len(llm_response["choices"]) == 0:
            raise Exception("No choices in LLM response")

        content = llm_response["choices"][0]["message"]["content"]

        # Try to parse as JSON
        try:
            triage_result = json.loads(content)

            # Validate required fields
            required_fields = ["risk_level", "confidence", "reasoning", "recommended_actions"]
            for field in required_fields:
                if field not in triage_result:
                    logger.warning(f"Missing required field in LLM response: {field}")
                    # Add default value
                    if field == "risk_level":
                        triage_result[field] = "medium"
                    elif field == "confidence":
                        triage_result[field] = 50
                    elif field == "reasoning":
                        triage_result[field] = "LLM parsing error - manual review required"
                    elif field == "recommended_actions":
                        triage_result[field] = [
                            {
                                "action": "Manual review required",
                                "priority": "high",
                                "type": "investigation",
                            }
                        ]

            return triage_result

        except json.JSONDecodeError:
            logger.warning(f"Failed to parse LLM response as JSON, using fallback")
            # Fallback: extract information from text
            return {
                "risk_level": "medium",
                "confidence": 50,
                "reasoning": content[:500],  # First 500 chars
                "recommended_actions": [
                    {
                        "action": "Manual review required - LLM response parsing failed",
                        "priority": "high",
                        "type": "investigation",
                    }
                ],
                "requires_human_review": True,
                "estimated_impact": "Unknown - requires manual assessment",
                "parsing_error": True,
            }

    except Exception as e:
        logger.error(f"Failed to parse LLM response: {e}")
        # Return fallback response
        return {
            "risk_level": "medium",
            "confidence": 0,
            "reasoning": f"Error parsing LLM response: {str(e)}",
            "recommended_actions": [
                {
                    "action": "Manual review required - parsing error",
                    "priority": "critical",
                    "type": "investigation",
                }
            ],
            "requires_human_review": True,
            "estimated_impact": "Unknown",
            "parsing_error": True,
        }


async def get_llm_route_from_router(task_type: str, complexity: str) -> Dict[str, Any]:
    """
    Query LLM Router for routing decision.

    Args:
        task_type: Type of task (triage, analysis, classification, etc)
        complexity: Complexity level (high, medium, low)

    Returns:
        Routing decision with model and endpoint info
    """
    try:
        response = await http_client.post(
            f"{LLM_ROUTER_URL}/api/v1/route",
            json={
                "task_type": task_type,
                "complexity": complexity,
                "estimated_tokens": 1500,
            },
            timeout=5.0,
        )

        if response.status_code == 200:
            return response.json()
        else:
            logger.warning(f"LLM Router returned {response.status_code}, using fallback")
            # Fallback to default
            return {
                "model": "qwen-plus",
                "provider": "qwen",
                "base_url": getattr(config, "qwen_base_url", "http://internal-maas.qwen/v1"),
                "api_key": getattr(config, "qwen_api_key", "internal-key-456"),
            }

    except Exception as e:
        logger.error(f"Failed to query LLM Router: {e}, using fallback")
        # Fallback to default
        return {
            "model": "qwen-plus",
            "provider": "qwen",
            "base_url": getattr(config, "qwen_base_url", "http://internal-maas.qwen/v1"),
            "api_key": getattr(config, "qwen_api_key", "internal-key-456"),
        }


# =============================================================================
# Alert Triage
# =============================================================================


async def triage_alert(
    alert: SecurityAlert,
    enrichment: Dict[str, Any] = None,
) -> Dict[str, Any]:
    """
    Perform AI-powered triage on alert.

    Args:
        alert: SecurityAlert object
        enrichment: Enrichment data

    Returns:
        Triage result dictionary
    """
    start_time = datetime.utcnow()

    try:
        # Determine complexity based on enrichment
        complexity = "medium"
        if enrichment:
            # Check threat intel for complexity
            if "threat_intel" in enrichment:
                ti = enrichment["threat_intel"]
                if any(
                    ti.get(key, {}).get("threat_score", 0) > 70
                    for key in ["source_ip", "target_ip", "file_hash", "url"]
                    if key in ti
                ):
                    complexity = "high"
            # Check asset criticality
            if "asset" in enrichment and enrichment["asset"].get("criticality") == "critical":
                complexity = "high"

        # Query similar alerts from historical data
        similar_alerts = await query_similar_alerts(alert, top_k=3)
        if similar_alerts.get("results"):
            enrichment["similar_alerts"] = similar_alerts
            logger.info(f"Found {len(similar_alerts['results'])} similar alerts for {alert.alert_id}")

        # Get routing decision from LLM Router
        route_decision = await get_llm_route_from_router("triage", complexity)

        # Build prompts
        system_prompt = get_system_prompt(alert.alert_type)
        user_prompt = build_triage_prompt(alert, enrichment)

        logger.info(f"Triaging alert {alert.alert_id} with model {route_decision.get('model', 'unknown')} (alert_type: {alert.alert_type}, complexity: {complexity})")

        # Call LLM API
        llm_response = await call_llm_api(
            prompt=user_prompt,
            system_prompt=system_prompt,
            model=route_decision["model"],
            base_url=route_decision["base_url"],
            api_key=route_decision["api_key"],
        )

        # Parse response
        triage_result = await parse_llm_response(llm_response)

        # Add metadata
        end_time = datetime.utcnow()
        processing_time = (end_time - start_time).total_seconds()

        triage_result.update(
            {
                "alert_id": alert.alert_id,
                "triaged_at": end_time.isoformat(),
                "processing_time_seconds": processing_time,
                "model_used": route_decision.get("model", "unknown"),
                "provider_used": route_decision.get("provider", "unknown"),
                "complexity_assessed": complexity,
            }
        )

        logger.info(f"Alert triaged successfully: {alert.alert_id} (risk_level: {triage_result.get('risk_level')}, confidence: {triage_result.get('confidence')}, processing_time: {processing_time}s)")

        return triage_result

    except Exception as e:
        logger.error(f"Triage failed for alert {alert.alert_id}: {e}", exc_info=True)

        # Return error result
        return {
            "alert_id": alert.alert_id,
            "triaged_at": datetime.utcnow().isoformat(),
            "risk_level": "high",  # Default to high on error
            "confidence": 0,
            "reasoning": f"Triage processing error: {str(e)}",
            "recommended_actions": [
                {
                    "action": "Manual triage required - processing error",
                    "priority": "high",
                    "type": "investigation",
                }
            ],
            "requires_human_review": True,
            "estimated_impact": "Unknown - processing error",
            "processing_error": True,
            "error_message": str(e),
        }


# =============================================================================
# Similarity Search Client
# =============================================================================


async def query_similar_alerts(
    alert: SecurityAlert,
    top_k: int = 3,
    min_similarity: float = 0.6,
) -> Dict[str, Any]:
    """
    Query similar alerts using vector similarity search.

    Args:
        alert: Alert to find similar alerts for
        top_k: Number of similar alerts to retrieve
        min_similarity: Minimum similarity threshold (0-1)

    Returns:
        Similarity search results
    """
    try:
        # Prepare request
        request_data = {
            "alert_data": alert.model_dump(),
            "top_k": top_k,
            "min_similarity": min_similarity,
        }

        # Query similarity search service
        response = await http_client.post(
            f"{SIMILARITY_SEARCH_URL}/api/v1/search",
            json=request_data,
            timeout=10.0,
        )

        if response.status_code == 200:
            result = response.json()
            if result.get("success"):
                return result.get("data", {})

        logger.warning(f"Similarity search failed for alert {alert.alert_id}: {response.status_code}")
        return {}

    except Exception as e:
        logger.error(f"Similarity search error for alert {alert.alert_id}: {e}")
        return {}


# =============================================================================
# FastAPI Application
# =============================================================================


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    global db_manager, publisher, consumer, http_client

    logger.info("Starting AI Triage Agent Service")

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

        # Initialize HTTP client
        http_client = httpx.AsyncClient(timeout=120.0)
        logger.info("✓ HTTP client initialized")

        # Initialize message publisher
        publisher = MessagePublisher(config.rabbitmq_url)
        await publisher.connect()
        logger.info("✓ Message publisher connected")

        # Initialize message consumer
        consumer = MessageConsumer(config.rabbitmq_url, "alert.enriched")
        await consumer.connect()
        logger.info("✓ Message consumer connected")

        # Start message consumer task
        asyncio.create_task(consume_alerts())
        logger.info("✓ Message consumer task started")

        logger.info("✓ AI Triage Agent Service started successfully")

        yield

    except Exception as e:
        logger.error(f"Failed to start service: {e}")
        raise

    finally:
        logger.info("Shutting down AI Triage Agent Service")

        if consumer:
            await consumer.close()
            logger.info("✓ Message consumer closed")

        if publisher:
            await publisher.close()
            logger.info("✓ Message publisher closed")

        if http_client:
            await http_client.aclose()
            logger.info("✓ HTTP client closed")

        # Close database using the close_database function
        await close_database()
        logger.info("✓ Database connection closed")

        logger.info("✓ AI Triage Agent Service stopped")


# Create FastAPI app
app = FastAPI(
    title="AI Triage Agent API",
    description="AI-powered security alert triage using LLMs",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =============================================================================
# Background Task: Message Consumer
# =============================================================================


async def persist_triage_result_to_db(alert_id: str, triage_result: Dict[str, Any]):
    """
    Persist triage result to database.

    Args:
        alert_id: Alert identifier
        triage_result: Triage result dictionary
    """
    try:
        async with db_manager.get_session() as session:
            await session.execute(
                text("""
                    INSERT INTO triage_results (alert_id, risk_score, risk_level, confidence_score,
                                                 analysis_result, recommended_actions, requires_human_review)
                    VALUES (:alert_id, :risk_score, :risk_level, :confidence_score,
                            :analysis_result, :recommended_actions, :requires_human_review)
                    ON CONFLICT (alert_id) DO UPDATE SET
                        risk_score = EXCLUDED.risk_score,
                        risk_level = EXCLUDED.risk_level,
                        confidence_score = EXCLUDED.confidence_score,
                        analysis_result = EXCLUDED.analysis_result,
                        recommended_actions = EXCLUDED.recommended_actions,
                        requires_human_review = EXCLUDED.requires_human_review,
                        updated_at = NOW()
                """),
                {
                    "alert_id": alert_id,
                    "risk_score": triage_result.get("risk_score", 50),
                    "risk_level": triage_result.get("risk_level", "medium"),
                    "confidence_score": triage_result.get("confidence", 0.5),
                    "analysis_result": triage_result.get("analysis", "No analysis provided"),
                    "recommended_actions": json.dumps(triage_result.get("recommended_actions", [])),
                    "requires_human_review": triage_result.get("requires_human_review", False),
                }
            )
            await session.commit()
            logger.debug(f"Triage result persisted for alert {alert_id}")

    except Exception as e:
        logger.error(f"Failed to persist triage result: {e}", exc_info=True)


async def consume_alerts():
    """Consume enriched alerts and perform AI triage."""

    async def process_message(message: dict):
        try:
            # Unwrap message envelope if present (publisher wraps with _meta and data)
            if "data" in message and isinstance(message["data"], dict):
                actual_message = message["data"]
                meta = message.get("_meta", {})
                message_id = meta.get("message_id", message.get("message_id", "unknown"))
            else:
                actual_message = message
                message_id = message.get("message_id", "unknown")

            payload = actual_message.get("payload", actual_message)

            logger.info(f"Processing message {message_id}")

            # Extract alert and enrichment
            alert_data = payload.get("alert")
            enrichment = payload.get("enrichment", {})

            if not alert_data:
                logger.warning("No alert data in message")
                return

            alert = SecurityAlert(**alert_data)

            # Perform triage
            triage_result = await triage_alert(alert, enrichment)

            # Persist triage result to database
            await persist_triage_result_to_db(alert.alert_id, triage_result)

            # Create result message
            result_message = {
                "message_id": str(uuid.uuid4()),
                "message_type": "alert.result",
                "correlation_id": alert.alert_id,
                "original_message_id": message_id,
                "timestamp": datetime.utcnow().isoformat(),
                "version": "1.0",
                "payload": {
                    "alert": alert.model_dump(),
                    "enrichment": enrichment,
                    "triage_result": triage_result,
                },
            }

            # Publish result
            await publisher.publish("alert.result", result_message)

            logger.info(f"Alert triage completed (message_id: {message_id}, alert_id: {alert.alert_id}, risk_level: {triage_result.get('risk_level')}, processing_time: {triage_result.get('processing_time_seconds')}s)")

        except Exception as e:
            logger.error(f"Triage processing failed: {e}", exc_info=True)
            # Re-raise to let consumer handle retries and DLQ
            raise

    # Start consuming
    await consumer.consume(process_message)


# =============================================================================
# API Endpoints
# =============================================================================


@app.get("/health", tags=["Health"])
async def health_check():
    """Health check endpoint."""
    try:
        return {
            "status": "healthy",
            "service": "ai-triage-agent",
            "timestamp": datetime.utcnow().isoformat(),
            "capabilities": {
                "langchain_agent": True,
                "tool_based_analysis": True,
                "attack_chain_analysis": True,
            },
            "checks": {
                "database": "connected" if db_manager else "disconnected",
                "message_queue_consumer": "connected" if consumer else "disconnected",
                "message_queue_publisher": "connected" if publisher else "disconnected",
                "http_client": "initialized" if http_client else "not initialized",
                "llm_router": f"{LLM_ROUTER_URL}",
            },
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return {
            "status": "unhealthy",
            "service": "ai-triage-agent",
            "error": str(e),
        }


@app.get("/metrics", tags=["Metrics"])
async def get_metrics():
    """Get triage metrics."""
    return {
        "service": "ai-triage-agent",
        "llm_router_url": LLM_ROUTER_URL,
    }


@app.post("/api/v1/triage", tags=["Triage"])
async def manual_triage(
    alert: SecurityAlert,
    enrichment: Dict[str, Any] = None,
):
    """
    Manually triage an alert (for testing).

    Args:
        alert: SecurityAlert to triage
        enrichment: Optional enrichment data

    Returns:
        Triage result
    """
    try:
        result = await triage_alert(alert, enrichment)
        return {
            "success": True,
            "data": result,
        }
    except Exception as e:
        logger.error(f"Manual triage failed: {e}")
        return {
            "success": False,
            "error": str(e),
        }


@app.post("/api/v1/triage/agent", tags=["Triage"])
async def agent_triage(
    alert: SecurityAlert,
    enrichment: Dict[str, Any] = None,
    use_agent: bool = True,
):
    """
    Triage an alert using LangChain agent with tool calling.

    This endpoint uses a LangChain agent that can call multiple tools
    to gather context and perform comprehensive analysis.

    Args:
        alert: SecurityAlert to triage
        enrichment: Optional enrichment data
        use_agent: Whether to use agent-based analysis (default: True)

    Returns:
        Comprehensive triage result with tool-based analysis
    """
    try:
        if not use_agent:
            # Fall back to standard triage
            result = await triage_alert(alert, enrichment)
            return {
                "success": True,
                "data": result,
                "method": "standard",
            }

        # Import agent
        from .agent.triage_agent import TriageAgent

        # Get API configuration
        api_key = os.getenv("QWEN_API_KEY") or os.getenv("DEEPSEEK_API_KEY", "")
        base_url = os.getenv("QWEN_BASE_URL") or os.getenv("DEEPSEEK_BASE_URL")
        model = os.getenv("LLM_MODEL", "qwen-plus")

        if not api_key:
            # Fall back to standard triage if no API key
            logger.warning("No LLM API key configured, falling back to standard triage")
            result = await triage_alert(alert, enrichment)
            return {
                "success": True,
                "data": result,
                "method": "standard_fallback",
                "warning": "No LLM API key configured",
            }

        # Create agent and analyze
        agent = TriageAgent(
            api_key=api_key,
            base_url=base_url,
            model=model,
        )

        result = await agent.analyze_alert(alert.model_dump(), enrichment)

        logger.info(f"Agent triage completed for {alert.alert_id}")

        return {
            "success": True,
            "data": result,
            "method": "langchain_agent",
        }

    except Exception as e:
        logger.error(f"Agent triage failed: {e}", exc_info=True)
        return {
            "success": False,
            "error": str(e),
        }


@app.post("/api/v1/analyze-chain", tags=["Analysis"])
async def analyze_attack_chain(alerts: List[Dict[str, Any]]):
    """
    Analyze a sequence of alerts for attack chain patterns.

    Calls the Attack Chain Analyzer service to perform MITRE ATT&CK mapping.

    Args:
        alerts: List of alert dictionaries

    Returns:
        Attack chain analysis with MITRE techniques and kill chain phase
    """
    try:
        attack_chain_url = os.getenv("ATTACK_CHAIN_URL", "http://attack-chain-analyzer:8000")

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{attack_chain_url}/api/v1/analyze-chain",
                json={"alerts": alerts},
            )

            if response.status_code == 200:
                data = response.json()
                return {
                    "success": True,
                    "data": data.get("data", {}),
                }
            else:
                logger.error(f"Attack chain analyzer returned {response.status_code}")
                return {
                    "success": False,
                    "error": f"Attack chain analyzer error: {response.status_code}",
                }

    except Exception as e:
        logger.error(f"Attack chain analysis failed: {e}", exc_info=True)
        return {
            "success": False,
            "error": str(e),
        }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host=config.host,
        port=config.port,
        reload=config.debug,
        log_level=config.log_level.lower(),
    )
