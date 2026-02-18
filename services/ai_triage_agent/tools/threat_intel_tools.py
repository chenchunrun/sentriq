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

"""Threat Intelligence Tools for LangChain Agent."""

import os
import re
from typing import Any, Dict, List, Optional

import httpx
from langchain_core.tools import tool
from shared.utils import get_logger

logger = get_logger(__name__)

# Service URLs from environment
THREAT_INTEL_URL = os.getenv("THREAT_INTEL_URL", "http://threat-intel-aggregator:8000")
HTTP_TIMEOUT = 15.0


@tool
async def query_threat_intel(ioc: str, ioc_type: str) -> Dict[str, Any]:
    """
    Query threat intelligence databases for an IOC.

    Searches multiple threat intel sources for information about the indicator.

    Args:
        ioc: Indicator of Compromise (IP, domain, hash, URL)
        ioc_type: Type of IOC (ip, domain, hash, url)

    Returns:
        Dictionary containing threat intelligence information
    """
    logger.info(f"Querying threat intelligence for {ioc_type}: {ioc}")

    # Try to get threat intel from aggregator service
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
            response = await client.post(
                f"{THREAT_INTEL_URL}/api/v1/query",
                json={"ioc": ioc, "ioc_type": ioc_type},
            )
            if response.status_code == 200:
                data = response.json()
                if data.get("success"):
                    result = data.get("data", {})
                    logger.info(f"Threat intel result from service: {result}")
                    return result
    except Exception as e:
        logger.warning(f"Failed to query threat intel service: {e}")

    # Fallback mock implementation
    intel = {
        "ioc": ioc,
        "ioc_type": ioc_type,
        "threat_level": _determine_threat_level(ioc),
        "confidence": 0.7,
        "malicious": _is_malicious(ioc),
        "sources": ["internal_database"],
        "related_campaigns": [],
        "tags": _get_ioc_tags(ioc),
        "first_seen": None,
        "last_seen": None,
    }

    logger.info(f"Threat intelligence result (fallback): {intel}")
    return intel


@tool
async def check_vulnerabilities(cve_id: str) -> Dict[str, Any]:
    """
    Query CVE database for vulnerability details.

    Retrieves CVSS score, description, exploit status, and patch availability.

    Args:
        cve_id: CVE identifier (e.g., CVE-2023-1234)

    Returns:
        Dictionary containing vulnerability details
    """
    logger.info(f"Checking vulnerability: {cve_id}")

    # Validate CVE format
    if not re.match(r"CVE-\d{4}-\d{4,7}", cve_id, re.IGNORECASE):
        return {
            "error": f"Invalid CVE format: {cve_id}",
            "cvss_score": 0.0,
            "severity": "unknown",
        }

    # Try to get from threat intel service
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
            response = await client.get(
                f"{THREAT_INTEL_URL}/api/v1/vulnerabilities/{cve_id}",
            )
            if response.status_code == 200:
                data = response.json()
                if data.get("success"):
                    return data.get("data", {})
    except Exception as e:
        logger.warning(f"Failed to query vulnerability from service: {e}")

    # Fallback mock CVE database
    cve_db = {
        "CVE-2023-1234": {
            "cvss_score": 8.5,
            "severity": "high",
            "description": "Remote code execution vulnerability",
            "exploit_available": True,
            "patch_available": True,
        },
        "CVE-2023-5678": {
            "cvss_score": 5.3,
            "severity": "medium",
            "description": "Information disclosure vulnerability",
            "exploit_available": False,
            "patch_available": True,
        },
        "CVE-2024-0001": {
            "cvss_score": 9.8,
            "severity": "critical",
            "description": "Critical authentication bypass",
            "exploit_available": True,
            "patch_available": False,
        },
    }

    vuln_data = cve_db.get(cve_id.upper(), {
        "cvss_score": 0.0,
        "severity": "unknown",
        "description": "Unknown vulnerability",
        "exploit_available": False,
        "patch_available": False,
    })

    logger.info(f"Vulnerability data: {vuln_data}")
    return vuln_data


@tool
async def check_malware_hash(file_hash: str) -> Dict[str, Any]:
    """
    Check file hash against malware databases.

    Queries multiple sources to determine if the hash is associated with known malware.

    Args:
        file_hash: File hash (MD5, SHA1, or SHA256)

    Returns:
        Dictionary containing malware analysis results
    """
    logger.info(f"Checking malware hash: {file_hash}")

    # Validate hash format
    hash_length = len(file_hash)
    if hash_length not in [32, 40, 64]:
        return {
            "error": "Invalid hash format. Expected MD5 (32), SHA1 (40), or SHA256 (64)",
            "is_malicious": False,
        }

    # Try to get from threat intel service
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
            response = await client.get(
                f"{THREAT_INTEL_URL}/api/v1/malware/{file_hash}",
            )
            if response.status_code == 200:
                data = response.json()
                if data.get("success"):
                    return data.get("data", {})
    except Exception as e:
        logger.warning(f"Failed to query malware hash from service: {e}")

    # Fallback mock implementation
    known_malicious = {
        "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8": {
            "name": "Trojan.Generic",
            "detection_rate": 45,
            "first_seen": "2024-12-01",
            "classification": "trojan",
        },
        "e99a18c428cb38d5f260853678922e03": {
            "name": "Ransomware.Generic",
            "detection_rate": 68,
            "first_seen": "2024-11-15",
            "classification": "ransomware",
        },
    }

    result = known_malicious.get(file_hash.lower(), {
        "name": "Unknown",
        "detection_rate": 0,
        "first_seen": None,
        "classification": "clean",
    })

    analysis = {
        "hash": file_hash,
        "is_malicious": file_hash.lower() in known_malicious,
        "detection_rate": result["detection_rate"],
        "classification": result["classification"],
        "malware_name": result["name"],
        "first_seen": result.get("first_seen"),
    }

    logger.info(f"Malware analysis result: {analysis}")
    return analysis


@tool
async def analyze_attack_pattern(alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Analyze alert sequence for attack patterns and MITRE ATT&CK mapping.

    Identifies multi-stage attacks and maps techniques to MITRE framework.

    Args:
        alerts: List of alert dictionaries to analyze

    Returns:
        Dictionary containing attack pattern analysis and MITRE techniques
    """
    logger.info(f"Analyzing attack pattern for {len(alerts)} alerts")

    if not alerts:
        return {
            "attack_stage": "unknown",
            "mitre_techniques": [],
            "confidence": 0.0,
            "identified_patterns": [],
        }

    # Analyze alert types
    alert_types = [a.get("alert_type", "unknown") for a in alerts]
    severities = [a.get("severity", "medium") for a in alerts]

    # Determine attack stage based on alert types
    stage_mapping = {
        "reconnaissance": ["reconnaissance", "scan", "discovery"],
        "initial_access": ["phishing", "brute_force", "exploit"],
        "execution": ["malware", "command_execution"],
        "persistence": ["backdoor", "persistence"],
        "lateral_movement": ["lateral_movement", "remote_access"],
        "exfiltration": ["data_exfiltration", "upload"],
        "impact": ["ransomware", "destruction"],
    }

    detected_stage = "initial_access"
    for stage, types in stage_mapping.items():
        if any(t in alert_types for t in types):
            detected_stage = stage
            break

    # MITRE technique mapping
    mitre_mapping = {
        "brute_force": ["T1110"],
        "phishing": ["T1566"],
        "malware": ["T1059", "T1204"],
        "data_exfiltration": ["T1041", "T1048"],
        "lateral_movement": ["T1021"],
    }

    techniques = []
    for alert_type in alert_types:
        techniques.extend(mitre_mapping.get(alert_type, []))

    # Calculate confidence based on alert correlation
    confidence = min(0.9, 0.4 + len(alerts) * 0.1)

    pattern = {
        "attack_stage": detected_stage,
        "mitre_techniques": list(set(techniques)),
        "confidence": confidence,
        "identified_patterns": list(set(alert_types)),
        "alert_count": len(alerts),
        "highest_severity": max(severities, key=lambda s: {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(s, 0)),
    }

    logger.info(f"Attack pattern analysis: {pattern}")
    return pattern


# Helper functions


def _determine_threat_level(ioc: str) -> str:
    """Determine threat level based on IOC."""
    if _is_internal_ip(ioc):
        return "low"

    suspicious_iocs = ["45.33.32.156", "103.224.212.222"]
    if ioc in suspicious_iocs:
        return "high"

    return "medium"


def _is_malicious(ioc: str) -> bool:
    """Check if IOC is known malicious."""
    malicious_iocs = ["45.33.32.156", "103.224.212.222"]
    return ioc in malicious_iocs


def _get_ioc_tags(ioc: str) -> List[str]:
    """Get tags for IOC."""
    tags = []
    if _is_internal_ip(ioc):
        tags.append("internal")
    else:
        tags.append("external")

    if _is_malicious(ioc):
        tags.append("known_malicious")

    return tags


def _is_internal_ip(ip: str) -> bool:
    """Check if IP is internal."""
    import ipaddress
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False
