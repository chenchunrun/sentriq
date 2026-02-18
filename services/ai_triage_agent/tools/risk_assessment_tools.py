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

"""Risk Assessment Tools for LangChain Agent."""

from datetime import datetime
from typing import Any, Dict, List

from langchain_core.tools import tool
from shared.utils import get_logger

logger = get_logger(__name__)

# Risk scoring weights
RISK_WEIGHTS = {
    "severity": 0.30,
    "threat_intel": 0.30,
    "asset_criticality": 0.20,
    "exploitability": 0.20,
}

# Risk thresholds
RISK_THRESHOLDS = {
    "critical": 90,
    "high": 70,
    "medium": 40,
    "low": 20,
    "info": 0,
}


@tool
def calculate_risk_score(
    severity: str,
    threat_intel_score: float,
    asset_criticality: str,
    exploitability: str,
) -> Dict[str, Any]:
    """
    Calculate comprehensive risk score using weighted factors.

    Combines multiple risk factors into a single risk score (0-100).

    Args:
        severity: Alert severity level (critical/high/medium/low/info)
        threat_intel_score: Threat intelligence score (0-10)
        asset_criticality: Asset criticality level (critical/high/medium/low)
        exploitability: Exploitability level (high/medium/low)

    Returns:
        Dictionary containing risk score and breakdown
    """
    logger.info(
        f"Calculating risk score: severity={severity}, "
        f"threat_score={threat_intel_score}, "
        f"asset_criticality={asset_criticality}, "
        f"exploitability={exploitability}"
    )

    # Convert severity to numeric score
    severity_scores = {
        "critical": 100,
        "high": 75,
        "medium": 50,
        "low": 25,
        "info": 10,
    }
    severity_score = severity_scores.get(severity.lower(), 25)

    # Convert asset criticality to multiplier
    criticality_multipliers = {
        "critical": 1.5,
        "high": 1.25,
        "medium": 1.0,
        "low": 0.75,
    }
    criticality_mult = criticality_multipliers.get(asset_criticality.lower(), 1.0)

    # Convert exploitability to multiplier
    exploitability_multipliers = {
        "high": 1.5,
        "medium": 1.0,
        "low": 0.5,
    }
    exploit_mult = exploitability_multipliers.get(exploitability.lower(), 1.0)

    # Calculate weighted components
    severity_component = severity_score * RISK_WEIGHTS["severity"]
    threat_component = (threat_intel_score / 10.0) * 100 * RISK_WEIGHTS["threat_intel"]
    asset_component = 50 * criticality_mult * RISK_WEIGHTS["asset_criticality"]
    exploit_component = 50 * exploit_mult * RISK_WEIGHTS["exploitability"]

    # Calculate total risk score
    risk_score = severity_component + threat_component + asset_component + exploit_component

    # Ensure score is within bounds
    risk_score = min(100, max(0, risk_score))

    # Determine risk level
    risk_level = _score_to_level(risk_score)

    result = {
        "risk_score": round(risk_score, 2),
        "risk_level": risk_level,
        "components": {
            "severity": round(severity_component, 2),
            "threat_intel": round(threat_component, 2),
            "asset_criticality": round(asset_component, 2),
            "exploitability": round(exploit_component, 2),
        },
        "weights": RISK_WEIGHTS,
        "requires_human_review": risk_score >= 70,
    }

    logger.info(f"Risk score calculated: {result}")
    return result


@tool
def estimate_business_impact(
    alert: Dict[str, Any],
    context: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Estimate business impact of the security alert.

    Analyzes potential impact on services, data, and compliance.

    Args:
        alert: Alert information dictionary
        context: Context information (asset, network, user)

    Returns:
        Dictionary containing business impact assessment
    """
    logger.info("Estimating business impact")

    severity = alert.get("severity", "medium")
    alert_type = alert.get("alert_type", "unknown")

    # Get asset criticality from context
    asset_context = context.get("asset", {})
    asset_criticality = asset_context.get("criticality", "medium")

    # Impact scoring matrix
    impact_matrix = {
        ("critical", "critical"): {
            "service_disruption": "critical",
            "data_loss": "critical",
            "compliance": "critical",
            "reputation": "critical",
        },
        ("critical", "high"): {
            "service_disruption": "high",
            "data_loss": "high",
            "compliance": "high",
            "reputation": "medium",
        },
        ("high", "critical"): {
            "service_disruption": "high",
            "data_loss": "high",
            "compliance": "high",
            "reputation": "medium",
        },
        ("high", "high"): {
            "service_disruption": "high",
            "data_loss": "medium",
            "compliance": "medium",
            "reputation": "low",
        },
        ("medium", "critical"): {
            "service_disruption": "medium",
            "data_loss": "medium",
            "compliance": "medium",
            "reputation": "low",
        },
    }

    impact = impact_matrix.get(
        (severity, asset_criticality),
        {
            "service_disruption": "low",
            "data_loss": "low",
            "compliance": "low",
            "reputation": "low",
        }
    )

    # Adjust based on alert type
    if alert_type == "data_exfiltration":
        impact["data_loss"] = "critical"
        impact["compliance"] = "critical"
    elif alert_type == "ransomware":
        impact["service_disruption"] = "critical"
        impact["data_loss"] = "critical"
    elif alert_type == "malware":
        impact["service_disruption"] = max(impact["service_disruption"], "medium")

    # Calculate financial impact estimate (mock)
    financial_impact = {
        "low": "< $10,000",
        "medium": "$10,000 - $100,000",
        "high": "$100,000 - $1,000,000",
        "critical": "> $1,000,000",
    }

    result = {
        "impact_assessment": impact,
        "overall_impact": max(impact.values(), key=lambda x: {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(x, 0)),
        "financial_impact_estimate": financial_impact.get(
            max(impact.values(), key=lambda x: {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(x, 0)),
            "Unknown"
        ),
        "affected_systems": _identify_affected_systems(alert, context),
        "data_sensitivity": _assess_data_sensitivity(context),
        "compliance_implications": _assess_compliance_impact(alert, context),
    }

    logger.info(f"Business impact estimated: {result}")
    return result


@tool
def generate_containment_strategies(
    risk_level: str,
    alert_type: str,
    context: Dict[str, Any] = None,
) -> Dict[str, Any]:
    """
    Generate containment and remediation strategies.

    Provides prioritized action items based on risk level and alert type.

    Args:
        risk_level: Risk level (critical/high/medium/low)
        alert_type: Type of security alert
        context: Additional context information

    Returns:
        Dictionary containing containment strategies
    """
    logger.info(f"Generating containment strategies for risk_level={risk_level}, alert_type={alert_type}")

    context = context or {}

    # Strategy templates by risk level
    strategies = {
        "critical": [
            {
                "action": "立即隔离受影响主机",
                "action_en": "Isolate affected hosts immediately",
                "priority": "immediate",
                "automated": True,
                "description": "断开网络连接，防止横向移动",
                "estimated_time": "< 5 minutes",
            },
            {
                "action": "阻断恶意IP地址",
                "action_en": "Block malicious IP addresses",
                "priority": "immediate",
                "automated": True,
                "description": "在防火墙添加阻断规则",
                "estimated_time": "< 5 minutes",
            },
            {
                "action": "禁用受损账户",
                "action_en": "Disable compromised accounts",
                "priority": "immediate",
                "automated": True,
                "description": "临时禁用可疑用户账户",
                "estimated_time": "< 5 minutes",
            },
            {
                "action": "启动应急响应流程",
                "action_en": "Activate incident response process",
                "priority": "immediate",
                "automated": False,
                "description": "通知应急响应团队",
                "responsible_team": "Security Operations",
                "estimated_time": "< 15 minutes",
            },
            {
                "action": "收集取证数据",
                "action_en": "Collect forensic data",
                "priority": "high",
                "automated": False,
                "description": "保存日志和内存快照",
                "responsible_team": "Digital Forensics",
                "estimated_time": "30-60 minutes",
            },
        ],
        "high": [
            {
                "action": "监控相关网络活动",
                "action_en": "Monitor related network activity",
                "priority": "high",
                "automated": True,
                "description": "增强日志收集和监控",
                "estimated_time": "< 15 minutes",
            },
            {
                "action": "加强访问控制",
                "action_en": "Enhance access controls",
                "priority": "high",
                "automated": True,
                "description": "临时提升认证要求",
                "estimated_time": "< 15 minutes",
            },
            {
                "action": "通知安全团队",
                "action_en": "Notify security team",
                "priority": "high",
                "automated": False,
                "description": "创建安全工单",
                "responsible_team": "SOC",
                "estimated_time": "< 30 minutes",
            },
        ],
        "medium": [
            {
                "action": "记录告警信息",
                "action_en": "Log alert information",
                "priority": "medium",
                "automated": True,
                "description": "添加到安全事件日志",
                "estimated_time": "Automated",
            },
            {
                "action": "持续监控",
                "action_en": "Continue monitoring",
                "priority": "low",
                "automated": True,
                "description": "设置监控告警",
                "estimated_time": "< 1 hour",
            },
        ],
        "low": [
            {
                "action": "记录告警",
                "action_en": "Log alert",
                "priority": "low",
                "automated": True,
                "description": "添加到日志供后续分析",
                "estimated_time": "Automated",
            },
        ],
    }

    # Get base strategies for risk level
    result_strategies = strategies.get(risk_level, strategies["low"])

    # Add alert-type specific strategies
    if alert_type == "malware":
        result_strategies.append({
            "action": "运行恶意软件扫描",
            "action_en": "Run malware scan",
            "priority": "high",
            "automated": True,
            "description": "执行全面的反病毒扫描",
            "estimated_time": "< 30 minutes",
        })
    elif alert_type == "data_exfiltration":
        result_strategies.append({
            "action": "审查数据访问日志",
            "action_en": "Review data access logs",
            "priority": "high",
            "automated": False,
            "description": "分析数据访问模式",
            "responsible_team": "Data Governance",
            "estimated_time": "1-2 hours",
        })
    elif alert_type == "brute_force":
        result_strategies.append({
            "action": "强制密码重置",
            "action_en": "Force password reset",
            "priority": "high",
            "automated": True,
            "description": "要求相关账户重置密码",
            "estimated_time": "< 30 minutes",
        })
        result_strategies.append({
            "action": "启用账户锁定策略",
            "action_en": "Enable account lockout policy",
            "priority": "medium",
            "automated": True,
            "description": "配置失败的登录尝试限制",
            "estimated_time": "< 15 minutes",
        })

    result = {
        "strategies": result_strategies,
        "total_count": len(result_strategies),
        "automated_count": sum(1 for s in result_strategies if s.get("automated", False)),
        "generated_at": datetime.utcnow().isoformat(),
    }

    logger.info(f"Generated {len(result_strategies)} containment strategies")
    return result


# Helper functions


def _score_to_level(score: float) -> str:
    """Convert numeric score to risk level."""
    if score >= RISK_THRESHOLDS["critical"]:
        return "critical"
    elif score >= RISK_THRESHOLDS["high"]:
        return "high"
    elif score >= RISK_THRESHOLDS["medium"]:
        return "medium"
    elif score >= RISK_THRESHOLDS["low"]:
        return "low"
    else:
        return "info"


def _identify_affected_systems(alert: Dict, context: Dict) -> List[str]:
    """Identify affected systems from alert and context."""
    systems = []

    if alert.get("asset_id"):
        systems.append(alert["asset_id"])

    asset_context = context.get("asset", {})
    if asset_context.get("asset_name"):
        systems.append(asset_context["asset_name"])

    return list(set(systems)) if systems else ["Unknown"]


def _assess_data_sensitivity(context: Dict) -> str:
    """Assess data sensitivity level."""
    asset_context = context.get("asset", {})

    # Check asset tags or classification
    tags = asset_context.get("tags", [])
    if "pii" in tags or "sensitive" in tags:
        return "high"
    if "confidential" in tags:
        return "medium"

    # Default based on asset type
    asset_type = asset_context.get("asset_type", "")
    if "database" in asset_type.lower():
        return "high"
    if "server" in asset_type.lower():
        return "medium"

    return "low"


def _assess_compliance_impact(alert: Dict, context: Dict) -> List[str]:
    """Assess compliance implications."""
    implications = []

    alert_type = alert.get("alert_type", "")
    data_sensitivity = _assess_data_sensitivity(context)

    if alert_type == "data_exfiltration" and data_sensitivity == "high":
        implications.extend(["GDPR", "CCPA", "SOX"])

    if alert_type in ["malware", "ransomware"]:
        implications.append("SOC2")

    if data_sensitivity == "high":
        implications.append("ISO27001")

    return list(set(implications)) if implications else ["None identified"]
