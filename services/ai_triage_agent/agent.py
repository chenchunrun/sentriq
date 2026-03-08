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
AI Triage Agent - Core analysis engine.

Uses LLMs to perform intelligent alert triage with routing
to appropriate models based on alert complexity.
"""

import json
from datetime import datetime
from typing import Any, Dict, List, Optional

import httpx

from shared.utils.logger import get_logger
from shared.utils.time import utc_now_iso
from .prompts import PromptTemplates
from .risk_scoring import RiskScoringEngine

logger = get_logger(__name__)


class AITriageAgent:
    """
    AI-powered security alert triage agent.

    Routes alerts to appropriate LLM models based on complexity,
    generates risk scores, and produces remediation recommendations.
    """

    # LLM endpoints (configurable via environment)
    DEEPSEEK_URL = "https://api.deepseek.com/v1/chat/completions"
    QWEN_URL = "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions"

    def __init__(
        self,
        deepseek_api_key: Optional[str] = None,
        qwen_api_key: Optional[str] = None,
        deepseek_model: str = "deepseek-chat",
        qwen_model: str = "qwen-plus",
        timeout: int = 30,
    ):
        """
        Initialize AI triage agent.

        Args:
            deepseek_api_key: DeepSeek API key
            qwen_api_key: Qwen API key
            deepseek_model: DeepSeek model name
            qwen_model: Qwen model name
            timeout: Request timeout in seconds
        """
        self.deepseek_api_key = deepseek_api_key
        self.qwen_api_key = qwen_api_key
        self.deepseek_model = deepseek_model
        self.qwen_model = qwen_model
        self.timeout = timeout

        self.risk_engine = RiskScoringEngine()
        self.prompt_templates = PromptTemplates()

        # Create HTTP client
        self.client = httpx.AsyncClient(timeout=timeout)

        logger.info("AI Triage Agent initialized")

    async def analyze_alert(
        self,
        alert: Dict[str, Any],
        threat_intel: Optional[Dict[str, Any]] = None,
        network_context: Optional[Dict[str, Any]] = None,
        asset_context: Optional[Dict[str, Any]] = None,
        user_context: Optional[Dict[str, Any]] = None,
        historical_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Perform comprehensive AI analysis of security alert.

        Args:
            alert: Alert data
            threat_intel: Threat intelligence results
            network_context: Network context information
            asset_context: Asset context information
            user_context: User context information
            historical_context: Historical patterns

        Returns:
            Complete triage result with AI analysis and risk score
        """
        try:
            alert_id = alert.get("alert_id", "unknown")
            logger.info(f"Starting AI analysis for alert {alert_id}")

            # Step 1: Calculate risk score
            risk_assessment = self.risk_engine.calculate_risk_score(
                alert=alert,
                threat_intel=threat_intel,
                asset_context=asset_context,
                network_context=network_context,
                user_context=user_context,
                historical_data=historical_context,
            )

            # Step 2: Determine LLM routing based on complexity
            model_used = self._route_to_model(alert, risk_assessment)

            # Step 3: Generate LLM prompt
            context = self.prompt_templates.format_context(
                alert=alert,
                threat_intel=threat_intel,
                network_context=network_context,
                asset_context=asset_context,
                user_context=user_context,
                historical_context=historical_context,
            )

            prompt = self.prompt_templates.get_prompt_for_alert_type(
                alert.get("alert_type", "other"),
                **context
            )

            # Step 4: Call LLM
            llm_response = await self._call_llm(prompt, model_used)

            # Step 5: Parse and structure response
            ai_analysis = self._parse_llm_response(llm_response)

            # Step 6: Combine risk assessment and AI analysis
            triage_result = self._create_triage_result(
                alert_id=alert_id,
                risk_assessment=risk_assessment,
                ai_analysis=ai_analysis,
                model_used=model_used,
                contexts={
                    "threat_intel": threat_intel,
                    "network": network_context,
                    "asset": asset_context,
                    "user": user_context,
                    "historical": historical_context,
                },
            )

            logger.info(
                f"AI analysis complete for alert {alert_id}",
                extra={
                    "alert_id": alert_id,
                    "risk_score": risk_assessment["risk_score"],
                    "model_used": model_used,
                },
            )

            return triage_result

        except Exception as e:
            logger.error(f"AI analysis failed for alert {alert.get('alert_id', 'unknown')}: {e}", exc_info=True)
            # Return fallback result
            return self._create_fallback_result(alert, str(e))

    def _route_to_model(self, alert: Dict, risk_assessment: Dict) -> str:
        """
        Route alert to appropriate LLM model.

        Args:
            alert: Alert data
            risk_assessment: Risk assessment from scoring engine

        Returns:
            Model name to use
        """
        risk_score = risk_assessment.get("risk_score", 50)
        alert_type = alert.get("alert_type", "")

        # High-risk or complex alerts go to DeepSeek
        if risk_score >= 70 or alert_type in ["malware", "data_exfiltration"]:
            if self.deepseek_api_key:
                return "deepseek"

        # Lower-risk or routine alerts can use faster Qwen
        if self.qwen_api_key:
            return "qwen"

        # Fallback to any available model
        if self.deepseek_api_key:
            return "deepseek"
        if self.qwen_api_key:
            return "qwen"

        logger.warning("No LLM API keys configured, using mock response")
        return "mock"

    async def _call_llm(self, prompt: str, model: str) -> str:
        """
        Call LLM API with prompt.

        Args:
            prompt: Formatted prompt
            model: Model to use (deepseek or qwen)

        Returns:
            LLM response text
        """
        if model == "mock":
            return self._get_mock_response(prompt)

        try:
            if model == "deepseek":
                return await self._call_deepseek(prompt)
            elif model == "qwen":
                return await self._call_qwen(prompt)
            else:
                raise ValueError(f"Unknown model: {model}")
        except Exception as e:
            logger.error(f"LLM call failed for model {model}: {e}")
            return self._get_mock_response(prompt)

    async def _call_deepseek(self, prompt: str) -> str:
        """Call DeepSeek API."""
        if not self.deepseek_api_key:
            return self._get_mock_response(prompt)

        headers = {
            "Authorization": f"Bearer {self.deepseek_api_key}",
            "Content-Type": "application/json",
        }

        payload = {
            "model": self.deepseek_model,
            "messages": [
                {"role": "system", "content": self.prompt_templates.SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.0,  # Deterministic for triage
            "max_tokens": 2000,
        }

        response = await self.client.post(
            self.DEEPSEEK_URL,
            headers=headers,
            json=payload,
        )

        response.raise_for_status()
        data = response.json()

        return data["choices"][0]["message"]["content"]

    async def _call_qwen(self, prompt: str) -> str:
        """Call Qwen API."""
        if not self.qwen_api_key:
            return self._get_mock_response(prompt)

        headers = {
            "Authorization": f"Bearer {self.qwen_api_key}",
            "Content-Type": "application/json",
        }

        payload = {
            "model": self.qwen_model,
            "input": {
                "messages": [
                    {"role": "system", "content": self.prompt_templates.SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ]
            },
            "parameters": {
                "temperature": 0.0,
                "max_tokens": 2000,
                "result_format": "message",
            },
        }

        response = await self.client.post(
            self.QWEN_URL,
            headers=headers,
            json=payload,
        )

        response.raise_for_status()
        data = response.json()

        return data["output"]["text"]

    def _get_mock_response(self, prompt: str) -> str:
        """Get mock LLM response for testing."""
        return json.dumps({
            "risk_assessment": {
                "risk_level": "medium",
                "confidence": 60,
                "reasoning": "Mock analysis - LLM API not configured. Configure DEEPSEEK_API_KEY or QWEN_API_KEY for real analysis."
            },
            "analysis_summary": "This is a mock triage result. Configure LLM API keys for real AI-powered analysis.",
            "impact_assessment": "Potential impact on systems and data",
            "recommended_actions": [
                {
                    "action": "Investigate the alert",
                    "priority": "medium",
                    "type": "investigation",
                    "urgency": "within_4_hours",
                    "responsible_team": "SOC"
                },
                {
                    "action": "Review affected assets",
                    "priority": "low",
                    "type": "investigation",
                    "urgency": "within_24_hours",
                    "responsible_team": "IT"
                }
            ],
            "investigation_steps": [
                "Review alert details and context",
                "Check related system logs",
                "Verify with affected users"
            ],
            "requires_human_review": True,
            "escalation_trigger": "Always review mock results",
            "additional_notes": "Mock response - configure LLM API for production",
            "_mock": True
        })

    def _parse_llm_response(self, response: str) -> Dict[str, Any]:
        """Parse LLM JSON response."""
        try:
            # Try to parse JSON directly
            return json.loads(response)
        except json.JSONDecodeError:
            # Try to extract JSON from response
            # Find first { and last }
            start = response.find("{")
            end = response.rfind("}")

            if start != -1 and end != -1:
                json_str = response[start:end+1]
                return json.loads(json_str)
            else:
                # Return error structure
                return {
                    "error": "Failed to parse LLM response as JSON",
                    "raw_response": response[:500],  # First 500 chars
                }

    def _create_triage_result(
        self,
        alert_id: str,
        risk_assessment: Dict,
        ai_analysis: Dict,
        model_used: str,
        contexts: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Create final triage result combining all analysis."""
        # Extract key findings from AI analysis
        key_findings = self._extract_key_findings(ai_analysis)

        # Extract IOCs
        iocs = self._extract_iocs(ai_analysis)

        # Extract recommended actions
        remediation = self._extract_remediation(ai_analysis)

        return {
            "alert_id": alert_id,
            "risk_score": risk_assessment["risk_score"],
            "risk_level": risk_assessment["risk_level"],
            "confidence": risk_assessment["confidence"],
            "requires_human_review": risk_assessment["requires_human_review"],
            "analysis": ai_analysis.get("analysis_summary", ai_analysis.get("risk_assessment", {}).get("reasoning", "")),
            "key_findings": key_findings,
            "iocs_identified": iocs,
            "threat_intel_summary": self._create_threat_intel_summary(contexts["threat_intel"]),
            "threat_intel_sources": contexts["threat_intel"].get("queried_sources", []) if contexts["threat_intel"] else [],
            "known_exploits": self._check_known_exploits(contexts["threat_intel"]),
            "cve_references": self._extract_cves(ai_analysis),
            "remediation": remediation,
            "model_used": model_used,
            "model_version": "v1.0",
            "processing_time_ms": None,  # Could be calculated if needed
            "breakdown": risk_assessment.get("breakdown", {}),
            "created_at": utc_now_iso(),
        }

    def _extract_key_findings(self, ai_analysis: Dict) -> List[str]:
        """Extract key findings from AI analysis."""
        findings = []

        # Add risk assessment reasoning
        risk_assessment = ai_analysis.get("risk_assessment", {})
        if risk_assessment.get("reasoning"):
            findings.append(risk_assessment["reasoning"])

        # Add impact assessment
        impact = ai_analysis.get("impact_assessment")
        if impact:
            if isinstance(impact, str):
                findings.append(impact)
            elif isinstance(impact, dict):
                for key, value in impact.items():
                    if value and isinstance(value, str):
                        findings.append(f"{key}: {value}")

        return findings[:5]  # Limit to 5 key findings

    def _extract_iocs(self, ai_analysis: Dict) -> Dict[str, List[str]]:
        """Extract IOCs from AI analysis."""
        iocs = {
            "ip_addresses": [],
            "file_hashes": [],
            "urls": [],
            "domains": [],
        }

        # Check for IOCs in analysis
        for section_name in ["malware_analysis", "phishing_analysis", "related_iocs"]:
            section = ai_analysis.get(section_name, {})
            if not section:
                continue

            # Extract indicators
            ioc_list = section.get("indicators_of_compromise", [])
            for ioc in ioc_list:
                ioc_type = ioc.get("type", "")
                ioc_value = ioc.get("value", "")
                if ioc_type and ioc_value:
                    if ioc_type == "ip":
                        iocs["ip_addresses"].append(ioc_value)
                    elif ioc_type == "hash":
                        iocs["file_hashes"].append(ioc_value)
                    elif ioc_type == "url":
                        iocs["urls"].append(ioc_value)
                    elif ioc_type == "domain":
                        iocs["domains"].append(ioc_value)

        return iocs

    def _extract_remediation(self, ai_analysis: Dict) -> Dict[str, Any]:
        """Extract remediation recommendations."""
        actions = ai_analysis.get("recommended_actions", [])
        if not actions:
            return {"actions": []}

        # Prioritize actions
        prioritized = sorted(
            actions,
            key=lambda a: {
                "critical": 4,
                "high": 3,
                "medium": 2,
                "low": 1,
            }.get(a.get("priority", "low"), 0),
            reverse=True,
        )

        return {
            "actions": prioritized[:10],  # Top 10 actions
            "total_count": len(actions),
        }

    def _create_threat_intel_summary(self, threat_intel: Optional[Dict]) -> str:
        """Create threat intelligence summary."""
        if not threat_intel:
            return "No threat intelligence available"

        summary = f"Threat level: {threat_intel.get('threat_level', 'unknown')}"
        sources = threat_intel.get("queried_sources", [])
        if sources:
            summary += f"\nSources: {', '.join(sources)}"

        detections = threat_intel.get("detections", [])
        if detections:
            summary += f"\n{len(detections)} sources detected malicious indicators"

        return summary

    def _check_known_exploits(self, threat_intel: Optional[Dict]) -> bool:
        """Check if known exploits are associated."""
        if not threat_intel:
            return False

        # Check tags for exploit-related keywords
        tags = threat_intel.get("tags", [])
        exploit_keywords = ["exploit", "cve", "kit", "payload"]
        return any(
            any(keyword in tag.lower() for keyword in exploit_keywords)
            for tag in tags
        )

    def _extract_cves(self, ai_analysis: Dict) -> List[str]:
        """Extract CVE references from analysis."""
        cves = []

        # Check various sections for CVE references
        for section in ["malware_analysis", "impact_assessment"]:
            section_data = ai_analysis.get(section, {})
            if isinstance(section_data, dict):
                for value in section_data.values():
                    if isinstance(value, str):
                        # Look for CVE pattern
                        import re
                        cve_pattern = r"CVE-\d{4}-\d{4,7}"
                        matches = re.findall(cve_pattern, value, re.IGNORECASE)
                        cves.extend(matches)

        return list(set(cves))

    def _create_fallback_result(self, alert: Dict, error: str) -> Dict[str, Any]:
        """Create fallback triage result when analysis fails."""
        return {
            "alert_id": alert.get("alert_id", "unknown"),
            "risk_score": 50,
            "risk_level": "medium",
            "confidence": 0.5,
            "requires_human_review": True,
            "analysis": f"Analysis failed: {error}",
            "key_findings": ["AI analysis failed, manual review required"],
            "iocs_identified": {},
            "threat_intel_summary": "",
            "threat_intel_sources": [],
            "known_exploits": False,
            "cve_references": [],
            "remediation": {
                "actions": [
                    {
                        "action": "Manual review required - AI analysis failed",
                        "priority": "high",
                        "type": "investigation",
                    }
                ]
            },
            "model_used": "fallback",
            "error": error,
            "created_at": utc_now_iso(),
        }

    async def close(self):
        """Close HTTP client."""
        await self.client.aclose()
