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
Risk scoring module for AI Triage Agent.

Calculates composite risk scores based on multiple factors:
- Alert severity
- Threat intelligence results
- Asset criticality
- Exploitability
- Historical patterns
"""

from typing import Any, Dict, List, Optional

from shared.models.alert import AlertType, Severity
from shared.utils.logger import get_logger
from shared.utils.time import utc_now_iso

logger = get_logger(__name__)


class RiskScoringEngine:
    """
    Risk scoring engine for security alerts.

    Calculates composite risk scores (0-100) based on weighted
    analysis of multiple factors.
    """

    # Risk weights (must sum to 1.0)
    RISK_WEIGHTS = {
        "severity": 0.30,
        "threat_intel": 0.30,
        "asset_criticality": 0.20,
        "exploitability": 0.20,
    }

    # Severity scores
    SEVERITY_SCORES = {
        Severity.CRITICAL: 100,
        Severity.HIGH: 80,
        Severity.MEDIUM: 50,
        Severity.LOW: 30,
        Severity.INFO: 10,
    }

    # Asset criticality scores
    ASSET_CRITICALITY_SCORES = {
        "critical": 100,
        "high": 80,
        "medium": 50,
        "low": 30,
        None: 50,  # Default
    }

    # Alert type multipliers
    ALERT_TYPE_MULTIPLIERS = {
        AlertType.MALWARE: 1.2,
        AlertType.PHISHING: 1.1,
        AlertType.BRUTE_FORCE: 0.9,
        AlertType.DDOS: 1.0,
        AlertType.DATA_EXFILTRATION: 1.3,
        AlertType.UNAUTHORIZED_ACCESS: 1.1,
        AlertType.ANOMALY: 0.8,
        AlertType.OTHER: 1.0,
    }

    def __init__(self):
        """Initialize risk scoring engine."""
        self.processed_count = 0

    def calculate_risk_score(
        self,
        alert: Dict[str, Any],
        threat_intel: Optional[Dict[str, Any]] = None,
        asset_context: Optional[Dict[str, Any]] = None,
        network_context: Optional[Dict[str, Any]] = None,
        user_context: Optional[Dict[str, Any]] = None,
        historical_data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Calculate composite risk score for an alert.

        Args:
            alert: Alert data
            threat_intel: Threat intelligence results
            asset_context: Asset context information
            network_context: Network context information
            user_context: User context information
            historical_data: Historical alert patterns

        Returns:
            Risk assessment dictionary with score and breakdown
        """
        try:
            # Extract severity score
            severity_value = alert.get("severity", "medium")
            severity = Severity(severity_value) if isinstance(severity_value, str) else severity_value
            severity_score = self.SEVERITY_SCORES.get(severity, 50)

            # Calculate severity component
            severity_component = severity_score * self.RISK_WEIGHTS["severity"]

            # Calculate threat intel component
            threat_intel_component = self._calculate_threat_intel_component(threat_intel)

            # Calculate asset criticality component
            asset_component = self._calculate_asset_component(asset_context)

            # Calculate exploitability component
            exploitability_component = self._calculate_exploitability_component(
                alert, asset_context, network_context, user_context
            )

            # Calculate historical adjustment
            historical_multiplier = self._calculate_historical_multiplier(historical_data)

            # Get alert type multiplier
            alert_type_raw = alert.get("alert_type", "other")
            if isinstance(alert_type_raw, AlertType):
                alert_type = alert_type_raw
            elif isinstance(alert_type_raw, str):
                try:
                    alert_type = AlertType(alert_type_raw)
                except ValueError:
                    alert_type = AlertType.OTHER
            else:
                alert_type = AlertType.OTHER
            type_multiplier = self.ALERT_TYPE_MULTIPLIERS.get(alert_type, 1.0)

            # Calculate base score
            base_score = (
                severity_component +
                threat_intel_component +
                asset_component +
                exploitability_component
            )

            # Apply type multiplier
            adjusted_score = base_score * type_multiplier * historical_multiplier

            # Clamp to 0-100
            final_score = max(0, min(100, int(adjusted_score)))

            # Determine risk level
            risk_level = self._get_risk_level(final_score)

            # Determine if human review is required
            requires_review = self._requires_human_review(final_score, threat_intel, alert)

            self.processed_count += 1

            result = {
                "risk_score": final_score,
                "risk_level": risk_level,
                "confidence": self._calculate_confidence(threat_intel, historical_data),
                "requires_human_review": requires_review,
                "breakdown": {
                    "severity": {
                        "score": int(severity_component),
                        "weight": self.RISK_WEIGHTS["severity"],
                        "value": severity.value if isinstance(severity, Severity) else str(severity),
                    },
                    "threat_intel": {
                        "score": int(threat_intel_component),
                        "weight": self.RISK_WEIGHTS["threat_intel"],
                        "sources_queried": len(threat_intel.get("queried_sources", [])) if threat_intel else 0,
                    },
                    "asset_criticality": {
                        "score": int(asset_component),
                        "weight": self.RISK_WEIGHTS["asset_criticality"],
                        "criticality": asset_context.get("criticality", "unknown") if asset_context else "unknown",
                    },
                    "exploitability": {
                        "score": int(exploitability_component),
                        "weight": self.RISK_WEIGHTS["exploitability"],
                    },
                },
                "factors": {
                    "alert_type": alert_type.value if isinstance(alert_type, AlertType) else str(alert_type),
                    "type_multiplier": type_multiplier,
                    "historical_multiplier": historical_multiplier,
                },
                "calculated_at": utc_now_iso(),
            }

            logger.info(
                f"Risk score calculated: {final_score}",
                extra={
                    "risk_score": final_score,
                    "risk_level": risk_level,
                    "alert_id": alert.get("alert_id", "unknown"),
                },
            )

            return result

        except Exception as e:
            logger.error(f"Risk scoring failed: {e}", exc_info=True)
            # Return default risk score
            return {
                "risk_score": 50,
                "risk_level": "medium",
                "confidence": 0.5,
                "requires_human_review": True,
                "error": str(e),
            }

    def _calculate_threat_intel_component(self, threat_intel: Optional[Dict]) -> float:
        """Calculate threat intel component of risk score."""
        if not threat_intel:
            return 0.0

        # Get aggregate score from threat intel
        aggregate_score = threat_intel.get("aggregate_score", 0)

        # Normalize to 0-100
        return float(min(100, max(0, aggregate_score))) * self.RISK_WEIGHTS["threat_intel"]

    def _calculate_asset_component(self, asset_context: Optional[Dict]) -> float:
        """Calculate asset criticality component of risk score."""
        if not asset_context:
            return 50 * self.RISK_WEIGHTS["asset_criticality"]  # Default to medium

        criticality = asset_context.get("criticality", "medium")
        criticality_score = self.ASSET_CRITICALITY_SCORES.get(criticality, 50)

        return criticality_score * self.RISK_WEIGHTS["asset_criticality"]

    def _calculate_exploitability_component(
        self,
        alert: Dict,
        asset_context: Optional[Dict],
        network_context: Optional[Dict],
        user_context: Optional[Dict],
    ) -> float:
        """Calculate exploitability component of risk score."""
        exploitability_score = 50  # Default

        # Adjust based on network context
        if network_context:
            is_external = not network_context.get("is_internal", False)
            if is_external:
                exploitability_score += 20  # External threats more concerning

            reputation = network_context.get("reputation") or {}
            reputation_score = reputation.get("score", 50)
            if reputation_score > 70:
                exploitability_score += 15

        # Adjust based on user context
        if user_context:
            # Check if user has elevated privileges
            user_role = user_context.get("title", "").lower()
            if any(role in user_role for role in ["admin", "root", "administrator", "privileged"]):
                exploitability_score += 25

        # Adjust based on alert type
        alert_type = alert.get("alert_type", "")
        if alert_type == "malware":
            exploitability_score += 10
        elif alert_type == "unauthorized_access":
            exploitability_score += 15
        elif alert_type == "data_exfiltration":
            exploitability_score += 20

        # Normalize
        return min(100, max(0, exploitability_score)) * self.RISK_WEIGHTS["exploitability"]

    def _calculate_historical_multiplier(self, historical_data: Optional[Dict]) -> float:
        """Calculate historical adjustment multiplier."""
        if not historical_data:
            return 1.0

        # Check for similar past alerts
        similar_alerts = historical_data.get("similar_alerts", [])
        if len(similar_alerts) > 5:
            return 1.2  # Pattern detected, increase risk
        elif len(similar_alerts) > 2:
            return 1.1
        elif len(similar_alerts) == 0:
            return 0.9  # No history, slightly reduce

        return 1.0

    def _calculate_confidence(
        self,
        threat_intel: Optional[Dict],
        historical_data: Optional[Dict],
    ) -> float:
        """Calculate confidence in risk assessment."""
        confidence = 0.5  # Base confidence

        # Increase confidence with threat intel
        if threat_intel:
            sources_count = len(threat_intel.get("queried_sources", []))
            if sources_count >= 3:
                confidence += 0.3
            elif sources_count >= 1:
                confidence += 0.15

        # Increase confidence with historical data
        if historical_data:
            similar_count = len(historical_data.get("similar_alerts", []))
            if similar_count >= 3:
                confidence += 0.2
            elif similar_count >= 1:
                confidence += 0.1

        return min(1.0, confidence)

    def _get_risk_level(self, score: int) -> str:
        """Convert numeric score to risk level."""
        if score >= 90:
            return "critical"
        elif score >= 70:
            return "high"
        elif score >= 40:
            return "medium"
        elif score >= 20:
            return "low"
        else:
            return "info"

    def _requires_human_review(
        self,
        score: int,
        threat_intel: Optional[Dict],
        alert: Dict,
    ) -> bool:
        """Determine if human review is required."""
        # Always require review for critical/high risk
        if score >= 70:
            return True

        # Require review if threat intel detected malicious
        if threat_intel and threat_intel.get("detected_by_count", 0) > 0:
            return True

        # Require review for certain alert types
        alert_type = alert.get("alert_type", "")
        if alert_type in ["malware", "data_exfiltration", "unauthorized_access"]:
            if score >= 40:  # Medium or higher
                return True

        return False

    def get_stats(self) -> Dict[str, int]:
        """Get processing statistics."""
        return {
            "processed_count": self.processed_count,
        }
