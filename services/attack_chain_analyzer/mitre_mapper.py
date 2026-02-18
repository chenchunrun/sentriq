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

"""MITRE ATT&CK Framework Mapper - Maps alerts to ATT&CK techniques and tactics."""

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Set


class AttackPhase(str, Enum):
    """Cyber Kill Chain phases."""

    RECONNAISSANCE = "reconnaissance"
    WEAPONIZATION = "weaponization"
    DELIVERY = "delivery"
    EXPLOITATION = "exploitation"
    INSTALLATION = "installation"
    COMMAND_AND_CONTROL = "command_and_control"
    ACTIONS_ON_OBJECTIVES = "actions_on_objectives"


class MitreTactic(str, Enum):
    """MITRE ATT&CK Enterprise tactics."""

    RECONNAISSANCE = "TA0043"
    RESOURCE_DEVELOPMENT = "TA0042"
    INITIAL_ACCESS = "TA0001"
    EXECUTION = "TA0002"
    PERSISTENCE = "TA0003"
    PRIVILEGE_ESCALATION = "TA0004"
    DEFENSE_EVASION = "TA0005"
    CREDENTIAL_ACCESS = "TA0006"
    DISCOVERY = "TA0007"
    LATERAL_MOVEMENT = "TA0008"
    COLLECTION = "TA0009"
    COMMAND_AND_CONTROL = "TA0011"
    EXFILTRATION = "TA0010"
    IMPACT = "TA0040"


@dataclass
class MitreTechnique:
    """Represents a MITRE ATT&CK technique."""

    id: str  # e.g., "T1190"
    name: str
    tactic: MitreTactic
    description: str
    detection_methods: List[str]
    mitigations: List[str]
    related_techniques: List[str]


# MITRE ATT&CK Technique Database (subset for common security alerts)
MITRE_TECHNIQUES: Dict[str, MitreTechnique] = {
    # Initial Access
    "T1190": MitreTechnique(
        id="T1190",
        name="Exploit Public-Facing Application",
        tactic=MitreTactic.INITIAL_ACCESS,
        description="Exploiting vulnerabilities in internet-facing applications",
        detection_methods=["Web application firewall logs", "Application logs", "Network IDS"],
        mitigations=["Patch management", "WAF rules", "Input validation"],
        related_techniques=["T1133", "T1078"],
    ),
    "T1566": MitreTechnique(
        id="T1566",
        name="Phishing",
        tactic=MitreTactic.INITIAL_ACCESS,
        description="Sending malicious emails or messages to gain initial access",
        detection_methods=["Email gateway logs", "User reports", "URL analysis"],
        mitigations=["Email filtering", "User training", "MFA"],
        related_techniques=["T1190", "T1204"],
    ),
    "T1133": MitreTechnique(
        id="T1133",
        name="External Remote Services",
        tactic=MitreTactic.INITIAL_ACCESS,
        description="Compromising external remote services like VPN or RDP",
        detection_methods=["VPN logs", "RDP logs", "Geolocation analysis"],
        mitigations=["MFA", "Network segmentation", "Access controls"],
        related_techniques=["T1078", "T1021"],
    ),
    "T1078": MitreTechnique(
        id="T1078",
        name="Valid Accounts",
        tactic=MitreTactic.INITIAL_ACCESS,
        description="Using legitimate credentials to gain access",
        detection_methods=["Authentication logs", "Behavioral analysis", "UEBA"],
        mitigations=["Password policies", "MFA", "Account monitoring"],
        related_techniques=["T1110", "T1133"],
    ),
    # Execution
    "T1059": MitreTechnique(
        id="T1059",
        name="Command and Scripting Interpreter",
        tactic=MitreTactic.EXECUTION,
        description="Executing commands via scripting interpreters",
        detection_methods=["Process monitoring", "Script block logging", "Command-line auditing"],
        mitigations=["Application control", "Script execution policies"],
        related_techniques=["T1027", "T1064"],
    ),
    "T1204": MitreTechnique(
        id="T1204",
        name="User Execution",
        tactic=MitreTactic.EXECUTION,
        description="Relying on user interaction to execute malicious code",
        detection_methods=["Endpoint detection", "File analysis", "User behavior"],
        mitigations=["User training", "Application allowlisting"],
        related_techniques=["T1566", "T1190"],
    ),
    # Persistence
    "T1547": MitreTechnique(
        id="T1547",
        name="Boot or Logon Autostart Execution",
        tactic=MitreTactic.PERSISTENCE,
        description="Configuring programs to run automatically at boot or login",
        detection_methods=["Registry monitoring", "Startup folder monitoring", "EDR"],
        mitigations=["Privilege management", "Registry ACLs"],
        related_techniques=["T1053", "T1546"],
    ),
    "T1053": MitreTechnique(
        id="T1053",
        name="Scheduled Task/Job",
        tactic=MitreTactic.PERSISTENCE,
        description="Creating scheduled tasks or cron jobs for persistence",
        detection_methods=["Task scheduler logs", "Process monitoring"],
        mitigations=["Privilege restrictions", "Task monitoring"],
        related_techniques=["T1547", "T1027"],
    ),
    # Credential Access
    "T1110": MitreTechnique(
        id="T1110",
        name="Brute Force",
        tactic=MitreTactic.CREDENTIAL_ACCESS,
        description="Attempting to guess passwords through various methods",
        detection_methods=["Authentication logs", "Account lockout events", "SIEM correlation"],
        mitigations=["Password policies", "Account lockout", "MFA"],
        related_techniques=["T1078", "T1528"],
    ),
    "T1003": MitreTechnique(
        id="T1003",
        name="OS Credential Dumping",
        tactic=MitreTactic.CREDENTIAL_ACCESS,
        description="Extracting credentials from operating system memory or files",
        detection_methods=["Process monitoring", "LSASS protection", "EDR"],
        mitigations=["Credential guards", "PPL", "EDR"],
        related_techniques=["T1558", "T1602"],
    ),
    # Defense Evasion
    "T1027": MitreTechnique(
        id="T1027",
        name="Obfuscated Files or Information",
        tactic=MitreTactic.DEFENSE_EVASION,
        description="Using obfuscation to hide malicious content",
        detection_methods=["File analysis", "Sandbox", "Signature-based detection"],
        mitigations=["Emulation", "Behavioral analysis"],
        related_techniques=["T1059", "T1218"],
    ),
    "T1070": MitreTechnique(
        id="T1070",
        name="Indicator Removal",
        tactic=MitreTactic.DEFENSE_EVASION,
        description="Removing artifacts to cover tracks",
        detection_methods=["Log integrity monitoring", "File system monitoring"],
        mitigations=["Centralized logging", "Write-once storage"],
        related_techniques=["T1562", "T1027"],
    ),
    # Command and Control
    "T1071": MitreTechnique(
        id="T1071",
        name="Application Layer Protocol",
        tactic=MitreTactic.COMMAND_AND_CONTROL,
        description="Using standard application layer protocols for C2",
        detection_methods=["Network analysis", "Traffic analysis", "DNS logs"],
        mitigations=["Network segmentation", "Proxy inspection"],
        related_techniques=["T1043", "T1095"],
    ),
    "T1568": MitreTechnique(
        id="T1568",
        name="Dynamic Resolution",
        tactic=MitreTactic.COMMAND_AND_CONTROL,
        description="Using dynamically resolved domains or IPs for C2",
        detection_methods=["DNS analysis", "Traffic correlation"],
        mitigations=["DNS sinkholing", "Traffic inspection"],
        related_techniques=["T1071", "T1095"],
    ),
    # Exfiltration
    "T1041": MitreTechnique(
        id="T1041",
        name="Exfiltration Over C2 Channel",
        tactic=MitreTactic.EXFILTRATION,
        description="Exfiltrating data over established C2 channel",
        detection_methods=["Network monitoring", "Data loss prevention", "Traffic analysis"],
        mitigations=["Network segmentation", "DLP", "Data classification"],
        related_techniques=["T1071", "T1048"],
    ),
    "T1048": MitreTechnique(
        id="T1048",
        name="Exfiltration Over Alternative Protocol",
        tactic=MitreTactic.EXFILTRATION,
        description="Using alternative protocols to exfiltrate data",
        detection_methods=["Network monitoring", "Protocol analysis", "DLP"],
        mitigations=["Firewall rules", "Proxy inspection"],
        related_techniques=["T1041", "T1567"],
    ),
    # Impact
    "T1486": MitreTechnique(
        id="T1486",
        name="Data Encrypted for Impact",
        tactic=MitreTactic.IMPACT,
        description="Encrypting data to cause impact (ransomware)",
        detection_methods=["File system monitoring", "Backup monitoring", "EDR"],
        mitigations=["Backups", "Data recovery plans", "Segmentation"],
        related_techniques=["T1490", "T1485"],
    ),
    "T1490": MitreTechnique(
        id="T1490",
        name="Inhibit System Recovery",
        tactic=MitreTactic.IMPACT,
        description="Disabling system recovery features",
        detection_methods=["Registry monitoring", "Process monitoring", "EDR"],
        mitigations=["Privilege restrictions", "Backup protection"],
        related_techniques=["T1486", "T1529"],
    ),
    # Lateral Movement
    "T1021": MitreTechnique(
        id="T1021",
        name="Remote Services",
        tactic=MitreTactic.LATERAL_MOVEMENT,
        description="Using remote services for lateral movement",
        detection_methods=["Authentication logs", "Network logs", "EDR"],
        mitigations=["Network segmentation", "MFA", "Access controls"],
        related_techniques=["T1078", "T1059"],
    ),
    "T1210": MitreTechnique(
        id="T1210",
        name="Exploitation of Remote Services",
        tactic=MitreTactic.LATERAL_MOVEMENT,
        description="Exploiting vulnerabilities in remote services",
        detection_methods=["Vulnerability scanning", "Network IDS", "EDR"],
        mitigations=["Patch management", "Network segmentation"],
        related_techniques=["T1021", "T1190"],
    ),
    # Discovery
    "T1046": MitreTechnique(
        id="T1046",
        name="Network Service Discovery",
        tactic=MitreTactic.DISCOVERY,
        description="Enumerating network services and ports",
        detection_methods=["Network monitoring", "Port scan detection", "EDR"],
        mitigations=["Network segmentation", "Service restrictions"],
        related_techniques=["T1016", "T1018"],
    ),
    "T1018": MitreTechnique(
        id="T1018",
        name="Remote System Discovery",
        tactic=MitreTactic.DISCOVERY,
        description="Enumerating remote systems on the network",
        detection_methods=["Process monitoring", "Network monitoring", "EDR"],
        mitigations=["Access controls", "Network segmentation"],
        related_techniques=["T1046", "T1087"],
    ),
}


class MitreMapper:
    """Maps security alerts to MITRE ATT&CK techniques."""

    # Alert type to technique mappings
    ALERT_TYPE_MAPPINGS: Dict[str, List[str]] = {
        "malware": ["T1059", "T1204", "T1547", "T1070"],
        "phishing": ["T1566", "T1190", "T1204"],
        "brute_force": ["T1110", "T1078"],
        "data_exfiltration": ["T1041", "T1048", "T1568"],
        "intrusion": ["T1190", "T1078", "T1021", "T1059"],
        "ddos": ["T1498", "T1499"],  # Not in our DB, will be marked as unknown
        "ransomware": ["T1486", "T1490", "T1027"],
        "web_attack": ["T1190", "T1059"],
        "credential_theft": ["T1110", "T1003", "T1555"],
        "lateral_movement": ["T1021", "T1210", "T1078"],
    }

    # Severity to kill chain phase mappings
    SEVERITY_PHASE_MAPPINGS: Dict[str, AttackPhase] = {
        "critical": AttackPhase.ACTIONS_ON_OBJECTIVES,
        "high": AttackPhase.COMMAND_AND_CONTROL,
        "medium": AttackPhase.EXPLOITATION,
        "low": AttackPhase.DELIVERY,
        "info": AttackPhase.RECONNAISSANCE,
    }

    @classmethod
    def map_alert_to_techniques(
        cls,
        alert_type: str,
        alert_data: Optional[Dict[str, Any]] = None,
    ) -> List[MitreTechnique]:
        """
        Map an alert to relevant MITRE ATT&CK techniques.

        Args:
            alert_type: Type of security alert
            alert_data: Additional alert data for context

        Returns:
            List of relevant MITRE techniques
        """
        techniques = []
        technique_ids = cls.ALERT_TYPE_MAPPINGS.get(alert_type, [])

        for tech_id in technique_ids:
            if tech_id in MITRE_TECHNIQUES:
                techniques.append(MITRE_TECHNIQUES[tech_id])

        # If we have additional alert data, try to find more specific techniques
        if alert_data:
            additional_techniques = cls._analyze_alert_content(alert_data)
            for tech in additional_techniques:
                if tech not in techniques:
                    techniques.append(tech)

        return techniques

    @classmethod
    def _analyze_alert_content(cls, alert_data: Dict[str, Any]) -> List[MitreTechnique]:
        """Analyze alert content to find additional relevant techniques."""
        techniques = []
        content = str(alert_data).lower()

        # Check for specific keywords that map to techniques
        keyword_mappings = {
            "powershell": "T1059",
            "cmd.exe": "T1059",
            "wmi": "T1059",
            "scheduled task": "T1053",
            "registry": "T1547",
            "mimikatz": "T1003",
            "lsass": "T1003",
            "brute force": "T1110",
            "password spray": "T1110",
            "phishing": "T1566",
            "email": "T1566",
            "exploit": "T1190",
            "vulnerability": "T1190",
            "remote desktop": "T1021",
            "rdp": "T1021",
            "lateral": "T1021",
            "exfil": "T1041",
            "data transfer": "T1048",
            "dns tunneling": "T1071",
            "beacon": "T1071",
            "encrypted": "T1027",
            "obfuscated": "T1027",
            "credential dump": "T1003",
            "ransomware": "T1486",
            "encryption": "T1486",
        }

        for keyword, tech_id in keyword_mappings.items():
            if keyword in content and tech_id in MITRE_TECHNIQUES:
                techniques.append(MITRE_TECHNIQUES[tech_id])

        return techniques

    @classmethod
    def determine_kill_chain_phase(
        cls,
        alert_type: str,
        severity: str,
        techniques: List[MitreTechnique],
    ) -> AttackPhase:
        """
        Determine the likely phase in the cyber kill chain.

        Args:
            alert_type: Type of alert
            severity: Alert severity
            techniques: Detected MITRE techniques

        Returns:
            Estimated kill chain phase
        """
        # Check techniques for phase indicators
        tactic_priorities = [
            MitreTactic.RECONNAISSANCE,
            MitreTactic.INITIAL_ACCESS,
            MitreTactic.EXECUTION,
            MitreTactic.PERSISTENCE,
            MitreTactic.PRIVILEGE_ESCALATION,
            MitreTactic.CREDENTIAL_ACCESS,
            MitreTactic.DISCOVERY,
            MitreTactic.LATERAL_MOVEMENT,
            MitreTactic.COLLECTION,
            MitreTactic.COMMAND_AND_CONTROL,
            MitreTactic.EXFILTRATION,
            MitreTactic.IMPACT,
        ]

        # Find the highest priority tactic from detected techniques
        for tactic in reversed(tactic_priorities):
            for tech in techniques:
                if tech.tactic == tactic:
                    # Map tactic to kill chain phase
                    return cls._tactic_to_phase(tactic)

        # Fallback to severity-based mapping
        return cls.SEVERITY_PHASE_MAPPINGS.get(severity, AttackPhase.EXPLOITATION)

    @classmethod
    def _tactic_to_phase(cls, tactic: MitreTactic) -> AttackPhase:
        """Map MITRE tactic to kill chain phase."""
        mapping = {
            MitreTactic.RECONNAISSANCE: AttackPhase.RECONNAISSANCE,
            MitreTactic.RESOURCE_DEVELOPMENT: AttackPhase.WEAPONIZATION,
            MitreTactic.INITIAL_ACCESS: AttackPhase.DELIVERY,
            MitreTactic.EXECUTION: AttackPhase.EXPLOITATION,
            MitreTactic.PERSISTENCE: AttackPhase.INSTALLATION,
            MitreTactic.PRIVILEGE_ESCALATION: AttackPhase.INSTALLATION,
            MitreTactic.CREDENTIAL_ACCESS: AttackPhase.ACTIONS_ON_OBJECTIVES,
            MitreTactic.DISCOVERY: AttackPhase.ACTIONS_ON_OBJECTIVES,
            MitreTactic.LATERAL_MOVEMENT: AttackPhase.ACTIONS_ON_OBJECTIVES,
            MitreTactic.COLLECTION: AttackPhase.ACTIONS_ON_OBJECTIVES,
            MitreTactic.COMMAND_AND_CONTROL: AttackPhase.COMMAND_AND_CONTROL,
            MitreTactic.EXFILTRATION: AttackPhase.ACTIONS_ON_OBJECTIVES,
            MitreTactic.IMPACT: AttackPhase.ACTIONS_ON_OBJECTIVES,
        }
        return mapping.get(tactic, AttackPhase.EXPLOITATION)

    @classmethod
    def get_related_campaigns(cls, techniques: List[MitreTechnique]) -> List[Dict[str, Any]]:
        """
        Get information about related threat campaigns based on techniques.

        Args:
            techniques: List of detected techniques

        Returns:
            List of related campaign information
        """
        # This would typically query threat intelligence databases
        # For now, return mock data based on technique combinations
        campaigns = []
        technique_ids = {t.id for t in techniques}

        # Common APT technique combinations
        apt_patterns = [
            {
                "name": "APT29 (Cozy Bear) Style",
                "techniques": {"T1190", "T1078", "T1059", "T1071"},
                "confidence": 0.7,
                "description": "Techniques consistent with APT29 operations",
            },
            {
                "name": "Ransomware Pattern",
                "techniques": {"T1486", "T1490", "T1027", "T1070"},
                "confidence": 0.8,
                "description": "Techniques commonly used in ransomware attacks",
            },
            {
                "name": "Credential Harvesting",
                "techniques": {"T1110", "T1003", "T1078"},
                "confidence": 0.75,
                "description": "Focus on credential theft techniques",
            },
        ]

        for pattern in apt_patterns:
            overlap = technique_ids & pattern["techniques"]
            if len(overlap) >= 2:
                campaigns.append({
                    "name": pattern["name"],
                    "confidence": pattern["confidence"] * (len(overlap) / len(pattern["techniques"])),
                    "description": pattern["description"],
                    "matched_techniques": list(overlap),
                })

        return sorted(campaigns, key=lambda x: x["confidence"], reverse=True)[:3]

    @classmethod
    def get_mitigations(cls, techniques: List[MitreTechnique]) -> List[Dict[str, Any]]:
        """
        Get prioritized mitigation recommendations.

        Args:
            techniques: List of detected techniques

        Returns:
            Prioritized list of mitigations
        """
        all_mitigations: Dict[str, Dict[str, Any]] = {}

        for tech in techniques:
            for mitigation in tech.mitigations:
                if mitigation not in all_mitigations:
                    all_mitigations[mitigation] = {
                        "name": mitigation,
                        "count": 0,
                        "related_techniques": [],
                    }
                all_mitigations[mitigation]["count"] += 1
                if tech.id not in all_mitigations[mitigation]["related_techniques"]:
                    all_mitigations[mitigation]["related_techniques"].append(tech.id)

        # Sort by how many techniques each mitigation addresses
        prioritized = sorted(
            all_mitigations.values(),
            key=lambda x: x["count"],
            reverse=True,
        )

        return prioritized[:10]  # Top 10 mitigations
