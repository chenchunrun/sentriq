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

"""LangChain Agent Implementation for Security Alert Triage."""

import json
from datetime import datetime
from typing import Any, Dict, List, Optional

from langchain.agents import AgentExecutor, create_openai_tools_agent
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_openai import ChatOpenAI
from shared.utils import get_logger

from ..tools import (
    calculate_risk_score,
    check_malware_hash,
    check_vulnerabilities,
    collect_asset_context,
    collect_network_context,
    collect_user_context,
    estimate_business_impact,
    generate_containment_strategies,
    query_threat_intel,
)

logger = get_logger(__name__)

# System prompt for the triage agent
TRIAGE_AGENT_SYSTEM_PROMPT = """You are an expert Security Alert Triage Agent. Your role is to analyze security alerts and provide comprehensive risk assessments.

You have access to the following tools:
1. collect_network_context - Gather network information about source/target IPs
2. collect_asset_context - Get asset details from CMDB
3. collect_user_context - Get user information from directory
4. query_threat_intel - Query threat intelligence databases for IOCs
5. check_vulnerabilities - Look up CVE details
6. check_malware_hash - Check file hashes against malware databases
7. calculate_risk_score - Calculate comprehensive risk score
8. estimate_business_impact - Assess business impact
9. generate_containment_strategies - Generate remediation strategies

Your workflow for each alert:
1. First, collect context using the appropriate context collection tools
2. Query threat intelligence for any IOCs (IPs, hashes, URLs)
3. Assess risk using the risk scoring tool
4. Estimate business impact
5. Generate containment strategies
6. Provide a summary of your findings

Always respond with a structured JSON analysis containing:
- risk_level: One of critical, high, medium, low, info
- confidence: A number between 0 and 100
- reasoning: Detailed explanation of your analysis
- recommended_actions: List of prioritized actions
- requires_human_review: Boolean indicating if human review is needed

Be thorough in your analysis and always explain your reasoning."""


class TriageAgent:
    """
    LangChain-based Security Alert Triage Agent.

    Uses LLM with tool calling capabilities to perform comprehensive
    security alert analysis.
    """

    def __init__(
        self,
        api_key: str,
        base_url: Optional[str] = None,
        model: str = "gpt-4",
        temperature: float = 0.0,
    ):
        """
        Initialize the triage agent.

        Args:
            api_key: LLM API key
            base_url: Optional base URL for API (for custom endpoints)
            model: Model to use for analysis
            temperature: Temperature for LLM responses
        """
        self.api_key = api_key
        self.base_url = base_url
        self.model = model
        self.temperature = temperature

        # Initialize LLM
        self.llm = ChatOpenAI(
            model=model,
            temperature=temperature,
            api_key=api_key,
            base_url=base_url,
        )

        # Initialize tools
        self.tools = [
            collect_network_context,
            collect_asset_context,
            collect_user_context,
            query_threat_intel,
            check_vulnerabilities,
            check_malware_hash,
            calculate_risk_score,
            estimate_business_impact,
            generate_containment_strategies,
        ]

        # Create prompt
        self.prompt = ChatPromptTemplate.from_messages([
            ("system", TRIAGE_AGENT_SYSTEM_PROMPT),
            ("user", "{input}"),
            MessagesPlaceholder(variable_name="agent_scratchpad"),
        ])

        # Create agent
        self.agent = create_openai_tools_agent(self.llm, self.tools, self.prompt)

        # Create agent executor
        self.agent_executor = AgentExecutor(
            agent=self.agent,
            tools=self.tools,
            verbose=True,
            handle_parsing_errors=True,
            max_iterations=10,
        )

        logger.info(f"TriageAgent initialized with model {model}")

    async def analyze_alert(
        self,
        alert: Dict[str, Any],
        enrichment: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Analyze a security alert using the LangChain agent.

        Args:
            alert: Alert data dictionary
            enrichment: Optional enrichment data

        Returns:
            Comprehensive triage result
        """
        start_time = datetime.utcnow()
        alert_id = alert.get("alert_id", "unknown")

        logger.info(f"Starting agent analysis for alert {alert_id}")

        # Build input prompt
        input_text = self._build_input_prompt(alert, enrichment)

        try:
            # Run agent
            result = await self.agent_executor.ainvoke({"input": input_text})

            # Extract output
            output = result.get("output", "")

            # Parse response
            triage_result = self._parse_agent_response(output, alert)

            # Add metadata
            end_time = datetime.utcnow()
            processing_time = (end_time - start_time).total_seconds()

            triage_result.update({
                "alert_id": alert_id,
                "triaged_at": end_time.isoformat(),
                "processing_time_seconds": processing_time,
                "model_used": self.model,
                "agent_steps": len(result.get("intermediate_steps", [])),
            })

            logger.info(
                f"Agent analysis completed for {alert_id}: "
                f"risk_level={triage_result.get('risk_level')}, "
                f"confidence={triage_result.get('confidence')}, "
                f"time={processing_time:.2f}s"
            )

            return triage_result

        except Exception as e:
            logger.error(f"Agent analysis failed for {alert_id}: {e}", exc_info=True)

            # Return error result
            return {
                "alert_id": alert_id,
                "triaged_at": datetime.utcnow().isoformat(),
                "risk_level": "medium",
                "confidence": 0,
                "reasoning": f"Agent analysis failed: {str(e)}",
                "recommended_actions": [
                    {
                        "action": "Manual review required - agent analysis failed",
                        "priority": "high",
                        "type": "investigation",
                    }
                ],
                "requires_human_review": True,
                "error": str(e),
            }

    def _build_input_prompt(
        self,
        alert: Dict[str, Any],
        enrichment: Optional[Dict[str, Any]],
    ) -> str:
        """Build input prompt for the agent."""
        prompt_parts = [
            "Please analyze the following security alert:\n",
            f"**Alert ID**: {alert.get('alert_id', 'unknown')}",
            f"**Alert Type**: {alert.get('alert_type', 'unknown')}",
            f"**Severity**: {alert.get('severity', 'medium')}",
            f"**Description**: {alert.get('description', 'No description')}",
            f"**Timestamp**: {alert.get('timestamp', 'unknown')}",
        ]

        # Add technical details
        if alert.get("source_ip"):
            prompt_parts.append(f"**Source IP**: {alert['source_ip']}")
        if alert.get("target_ip"):
            prompt_parts.append(f"**Target IP**: {alert['target_ip']}")
        if alert.get("asset_id"):
            prompt_parts.append(f"**Asset ID**: {alert['asset_id']}")
        if alert.get("user_id"):
            prompt_parts.append(f"**User ID**: {alert['user_id']}")
        if alert.get("file_hash"):
            prompt_parts.append(f"**File Hash**: {alert['file_hash']}")
        if alert.get("url"):
            prompt_parts.append(f"**URL**: {alert['url']}")

        # Add enrichment if available
        if enrichment:
            prompt_parts.append("\n**Enrichment Data**:")
            prompt_parts.append(json.dumps(enrichment, indent=2, default=str))

        prompt_parts.append(
            "\nPlease analyze this alert, gather context, assess risk, "
            "and provide your recommendations."
        )

        return "\n".join(prompt_parts)

    def _parse_agent_response(
        self,
        response: str,
        alert: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Parse agent response into structured result."""
        # Try to extract JSON from response
        try:
            # Look for JSON block
            start = response.find("{")
            end = response.rfind("}") + 1

            if start != -1 and end > start:
                json_str = response[start:end]
                return json.loads(json_str)

        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse agent response as JSON: {e}")

        # Fallback: parse text response
        return {
            "risk_level": self._extract_risk_level(response),
            "confidence": self._extract_confidence(response),
            "reasoning": response[:1000],  # First 1000 chars as reasoning
            "recommended_actions": self._extract_actions(response),
            "requires_human_review": True,
            "raw_response": response,
        }

    def _extract_risk_level(self, text: str) -> str:
        """Extract risk level from text response."""
        text_lower = text.lower()

        if "critical" in text_lower:
            return "critical"
        elif "high" in text_lower:
            return "high"
        elif "low" in text_lower:
            return "low"
        elif "info" in text_lower:
            return "info"

        return "medium"

    def _extract_confidence(self, text: str) -> int:
        """Extract confidence from text response."""
        import re

        # Look for confidence percentage
        match = re.search(r"confidence[:\s]+(\d+)", text, re.IGNORECASE)
        if match:
            return int(match.group(1))

        return 70  # Default confidence

    def _extract_actions(self, text: str) -> List[Dict[str, str]]:
        """Extract recommended actions from text response."""
        actions = []

        # Simple extraction - look for numbered or bulleted items
        lines = text.split("\n")
        for line in lines:
            line = line.strip()
            if line.startswith(("-", "*", "•", "1.", "2.", "3.", "4.", "5.")):
                action_text = line.lstrip("-*•123456789. ").strip()
                if action_text:
                    actions.append({
                        "action": action_text,
                        "priority": "medium",
                        "type": "investigation",
                    })

        return actions[:5] if actions else [{"action": "Review and investigate alert", "priority": "medium", "type": "investigation"}]


# Convenience function
async def run_triage_agent(
    alert: Dict[str, Any],
    api_key: str,
    base_url: Optional[str] = None,
    model: str = "gpt-4",
    enrichment: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Run the triage agent on an alert.

    Args:
        alert: Alert data
        api_key: LLM API key
        base_url: Optional base URL
        model: Model to use
        enrichment: Optional enrichment data

    Returns:
        Triage result
    """
    agent = TriageAgent(
        api_key=api_key,
        base_url=base_url,
        model=model,
    )
    return await agent.analyze_alert(alert, enrichment)
