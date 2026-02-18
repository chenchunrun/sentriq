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

"""Attack Pattern Recognition - Identifies attack patterns from alert sequences."""

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class AttackPattern(str, Enum):
    """Known attack patterns."""

    BRUTE_FORCE = "brute_force"
    CREDENTIAL_STUFFING = "credential_stuffing"
    PASSWORD_SPRAY = "password_spray"
    PHISHING_CAMPAIGN = "phishing_campaign"
    MALWARE_OUTBREAK = "malware_outbreak"
    RANSOMWARE = "ransomware"
    DATA_EXFILTRATION = "data_exfiltration"
    LATERAL_MOVEMENT = "lateral_movement"
    APT_BEHAVIOR = "apt_behavior"
    WEB_ATTACK = "web_attack"
    DDOS = "ddos"
    INSIDER_THREAT = "insider_threat"
    SUPPLY_CHAIN = "supply_chain"
    ZERO_DAY = "zero_day"


@dataclass
class PatternIndicator:
    """Indicates a specific attack pattern was detected."""

    pattern: AttackPattern
    confidence: float
    evidence: List[str]
    affected_assets: List[str]
    timeline: List[Dict[str, Any]]


class AttackPatternAnalyzer:
    """Analyzes alert sequences to identify attack patterns."""

    # Time windows for pattern detection
    SHORT_WINDOW = timedelta(minutes=15)
    MEDIUM_WINDOW = timedelta(hours=1)
    LONG_WINDOW = timedelta(hours=24)

    @classmethod
    def analyze_alerts(
        cls,
        alerts: List[Dict[str, Any]],
        context: Optional[Dict[str, Any]] = None,
    ) -> List[PatternIndicator]:
        """
        Analyze a sequence of alerts to identify attack patterns.

        Args:
            alerts: List of alert dictionaries
            context: Additional context (network, assets, users)

        Returns:
            List of detected pattern indicators
        """
        if not alerts:
            return []

        patterns = []

        # Sort alerts by timestamp
        sorted_alerts = sorted(
            alerts,
            key=lambda a: a.get("timestamp", ""),
        )

        # Check for each pattern type
        patterns.extend(cls._detect_brute_force(sorted_alerts))
        patterns.extend(cls._detect_credential_stuffing(sorted_alerts))
        patterns.extend(cls._detect_phishing_campaign(sorted_alerts))
        patterns.extend(cls._detect_malware_outbreak(sorted_alerts))
        patterns.extend(cls._detect_ransomware(sorted_alerts))
        patterns.extend(cls._detect_data_exfiltration(sorted_alerts))
        patterns.extend(cls._detect_lateral_movement(sorted_alerts, context))
        patterns.extend(cls._detect_apt_behavior(sorted_alerts, context))

        # Sort by confidence
        patterns.sort(key=lambda p: p.confidence, reverse=True)

        return patterns

    @classmethod
    def _detect_brute_force(cls, alerts: List[Dict]) -> List[PatternIndicator]:
        """Detect brute force attack patterns."""
        patterns = []

        # Group alerts by source IP and target
        ip_targets: Dict[str, Dict[str, List[Dict]]] = {}

        for alert in alerts:
            if alert.get("alert_type") not in ["brute_force", "authentication"]:
                continue

            source_ip = alert.get("source_ip", "unknown")
            target = alert.get("target_ip") or alert.get("asset_id") or "unknown"

            if source_ip not in ip_targets:
                ip_targets[source_ip] = {}
            if target not in ip_targets[source_ip]:
                ip_targets[source_ip][target] = []

            ip_targets[source_ip][target].append(alert)

        # Check for brute force patterns
        for source_ip, targets in ip_targets.items():
            for target, target_alerts in targets.items():
                if len(target_alerts) >= 5:  # 5+ attempts = potential brute force
                    # Check time window
                    timestamps = [
                        cls._parse_timestamp(a.get("timestamp", ""))
                        for a in target_alerts
                    ]
                    if timestamps and max(timestamps) - min(timestamps) < cls.SHORT_WINDOW:
                        patterns.append(PatternIndicator(
                            pattern=AttackPattern.BRUTE_FORCE,
                            confidence=min(0.95, 0.5 + len(target_alerts) * 0.05),
                            evidence=[
                                f"{len(target_alerts)} failed login attempts",
                                f"From source: {source_ip}",
                                f"Against target: {target}",
                                f"Time window: < 15 minutes",
                            ],
                            affected_assets=[target],
                            timeline=[
                                {"timestamp": a.get("timestamp"), "event": a.get("description")}
                                for a in target_alerts[:10]
                            ],
                        ))

        return patterns

    @classmethod
    def _detect_credential_stuffing(cls, alerts: List[Dict]) -> List[PatternIndicator]:
        """Detect credential stuffing patterns (multiple accounts from same source)."""
        patterns = []

        # Look for authentication failures across multiple accounts
        source_accounts: Dict[str, set] = {}

        for alert in alerts:
            if alert.get("alert_type") not in ["brute_force", "authentication", "phishing"]:
                continue

            source_ip = alert.get("source_ip", "unknown")
            user_id = alert.get("user_id")

            if user_id:
                if source_ip not in source_accounts:
                    source_accounts[source_ip] = set()
                source_accounts[source_ip].add(user_id)

        # Check for credential stuffing
        for source_ip, accounts in source_accounts.items():
            if len(accounts) >= 3:  # 3+ different accounts = credential stuffing
                patterns.append(PatternIndicator(
                    pattern=AttackPattern.CREDENTIAL_STUFFING,
                    confidence=min(0.9, 0.5 + len(accounts) * 0.1),
                    evidence=[
                        f"Multiple account attempts: {len(accounts)}",
                        f"From same source: {source_ip}",
                        "Pattern indicates credential stuffing",
                    ],
                    affected_assets=list(accounts),
                    timeline=[],
                ))

        return patterns

    @classmethod
    def _detect_phishing_campaign(cls, alerts: List[Dict]) -> List[PatternIndicator]:
        """Detect phishing campaign patterns."""
        patterns = []

        phishing_alerts = [
            a for a in alerts
            if a.get("alert_type") == "phishing"
        ]

        if len(phishing_alerts) >= 2:
            # Check for common indicators
            subjects = set()
            senders = set()
            targets = set()

            for alert in phishing_alerts:
                details = alert.get("details", {})
                subjects.add(details.get("email_subject", "unknown"))
                senders.add(details.get("sender", "unknown"))
                targets.add(alert.get("user_id", "unknown"))

            if len(subjects) == 1 or len(senders) == 1:
                # Same subject or sender = coordinated campaign
                patterns.append(PatternIndicator(
                    pattern=AttackPattern.PHISHING_CAMPAIGN,
                    confidence=0.85,
                    evidence=[
                        f"Coordinated phishing campaign",
                        f"Targets affected: {len(targets)}",
                        f"Common subject: {list(subjects)[0] if len(subjects) == 1 else 'Multiple'}",
                        f"Common sender: {list(senders)[0] if len(senders) == 1 else 'Multiple'}",
                    ],
                    affected_assets=list(targets),
                    timeline=[
                        {"timestamp": a.get("timestamp"), "user": a.get("user_id")}
                        for a in phishing_alerts
                    ],
                ))

        return patterns

    @classmethod
    def _detect_malware_outbreak(cls, alerts: List[Dict]) -> List[PatternIndicator]:
        """Detect malware outbreak patterns."""
        patterns = []

        malware_alerts = [
            a for a in alerts
            if a.get("alert_type") == "malware"
        ]

        if len(malware_alerts) >= 2:
            # Check for same malware hash or family
            hashes: Dict[str, List[Dict]] = {}

            for alert in malware_alerts:
                file_hash = alert.get("file_hash", "unknown")
                if file_hash not in hashes:
                    hashes[file_hash] = []
                hashes[file_hash].append(alert)

            for file_hash, hash_alerts in hashes.items():
                if len(hash_alerts) >= 2:
                    assets = [a.get("asset_id", "unknown") for a in hash_alerts]
                    patterns.append(PatternIndicator(
                        pattern=AttackPattern.MALWARE_OUTBREAK,
                        confidence=0.9,
                        evidence=[
                            f"Malware outbreak detected",
                            f"Hash: {file_hash}",
                            f"Affected assets: {len(set(assets))}",
                        ],
                        affected_assets=list(set(assets)),
                        timeline=[
                            {"timestamp": a.get("timestamp"), "asset": a.get("asset_id")}
                            for a in hash_alerts
                        ],
                    ))

        return patterns

    @classmethod
    def _detect_ransomware(cls, alerts: List[Dict]) -> List[PatternIndicator]:
        """Detect ransomware patterns."""
        patterns = []

        # Look for combination of indicators
        ransomware_indicators = []
        affected_assets = set()

        for alert in alerts:
            alert_type = alert.get("alert_type", "")
            description = str(alert.get("description", "")).lower()

            # Check for ransomware indicators
            if alert_type == "malware":
                if any(kw in description for kw in ["ransom", "encrypt", "crypto"]):
                    ransomware_indicators.append(alert)
                    if alert.get("asset_id"):
                        affected_assets.add(alert.get("asset_id"))

            # Check for mass file operations
            if alert_type == "data_exfiltration" or "file" in description:
                if any(kw in description for kw in ["encrypt", "modify", "delete"]):
                    ransomware_indicators.append(alert)

            # Check for backup destruction
            if "backup" in description and any(kw in description for kw in ["delete", "disable", "stop"]):
                ransomware_indicators.append(alert)

        if len(ransomware_indicators) >= 2:
            patterns.append(PatternIndicator(
                pattern=AttackPattern.RANSOMWARE,
                confidence=0.85,
                evidence=[
                    "Ransomware behavior pattern detected",
                    "File encryption activity",
                    "Potential backup targeting",
                ],
                affected_assets=list(affected_assets),
                timeline=[
                    {"timestamp": a.get("timestamp"), "event": a.get("description")}
                    for a in ransomware_indicators[:10]
                ],
            ))

        return patterns

    @classmethod
    def _detect_data_exfiltration(cls, alerts: List[Dict]) -> List[PatternIndicator]:
        """Detect data exfiltration patterns."""
        patterns = []

        exfil_alerts = [
            a for a in alerts
            if a.get("alert_type") == "data_exfiltration"
        ]

        if exfil_alerts:
            total_data = 0
            destinations = set()
            affected_users = set()

            for alert in exfil_alerts:
                details = alert.get("details", {})
                total_data += details.get("bytes_transferred", 0)
                if alert.get("target_ip"):
                    destinations.add(alert.get("target_ip"))
                if alert.get("user_id"):
                    affected_users.add(alert.get("user_id"))

            if total_data > 10 * 1024 * 1024 or len(destinations) > 1:  # > 10MB or multiple destinations
                patterns.append(PatternIndicator(
                    pattern=AttackPattern.DATA_EXFILTRATION,
                    confidence=0.8,
                    evidence=[
                        f"Data exfiltration detected",
                        f"Total data: {total_data / (1024*1024):.2f} MB",
                        f"Destinations: {len(destinations)}",
                        f"Affected users: {len(affected_users)}",
                    ],
                    affected_assets=list(affected_users),
                    timeline=[
                        {"timestamp": a.get("timestamp"), "bytes": a.get("details", {}).get("bytes_transferred", 0)}
                        for a in exfil_alerts
                    ],
                ))

        return patterns

    @classmethod
    def _detect_lateral_movement(
        cls,
        alerts: List[Dict],
        context: Optional[Dict] = None,
    ) -> List[PatternIndicator]:
        """Detect lateral movement patterns."""
        patterns = []

        # Look for internal-to-internal connections across multiple assets
        asset_connections: Dict[str, List[str]] = {}

        for alert in alerts:
            alert_type = alert.get("alert_type", "")
            source_ip = alert.get("source_ip", "")
            target_ip = alert.get("target_ip", "")

            # Check if both source and target are internal
            if source_ip and target_ip:
                if cls._is_internal_ip(source_ip) and cls._is_internal_ip(target_ip):
                    if source_ip not in asset_connections:
                        asset_connections[source_ip] = []
                    asset_connections[source_ip].append(target_ip)

        # Check for lateral movement patterns
        for source, targets in asset_connections.items():
            unique_targets = set(targets)
            if len(unique_targets) >= 3:  # 3+ unique internal targets
                patterns.append(PatternIndicator(
                    pattern=AttackPattern.LATERAL_MOVEMENT,
                    confidence=min(0.9, 0.5 + len(unique_targets) * 0.1),
                    evidence=[
                        f"Lateral movement detected",
                        f"Source: {source}",
                        f"Unique targets: {len(unique_targets)}",
                    ],
                    affected_assets=list(unique_targets),
                    timeline=[],
                ))

        return patterns

    @classmethod
    def _detect_apt_behavior(
        cls,
        alerts: List[Dict],
        context: Optional[Dict] = None,
    ) -> List[PatternIndicator]:
        """Detect APT-style behavior patterns."""
        patterns = []

        # APT behavior: long-term, low-and-slow, multiple attack phases
        if len(alerts) < 3:
            return patterns

        # Check for multi-stage attack
        alert_types = set(a.get("alert_type") for a in alerts)
        apt_indicators = {"phishing", "malware", "intrusion", "data_exfiltration", "lateral_movement"}

        overlap = alert_types & apt_indicators

        if len(overlap) >= 3:
            # Check time span
            timestamps = [
                cls._parse_timestamp(a.get("timestamp", ""))
                for a in alerts
            ]

            if timestamps:
                time_span = max(timestamps) - min(timestamps)
                if time_span > cls.MEDIUM_WINDOW:  # > 1 hour
                    patterns.append(PatternIndicator(
                        pattern=AttackPattern.APT_BEHAVIOR,
                        confidence=0.75,
                        evidence=[
                            "Multi-stage attack pattern detected",
                            f"Attack phases: {', '.join(overlap)}",
                            f"Time span: {time_span}",
                            "Pattern consistent with APT behavior",
                        ],
                        affected_assets=[a.get("asset_id", "unknown") for a in alerts if a.get("asset_id")],
                        timeline=[
                            {"timestamp": a.get("timestamp"), "type": a.get("alert_type")}
                            for a in alerts
                        ],
                    ))

        return patterns

    @staticmethod
    def _parse_timestamp(timestamp_str: str) -> datetime:
        """Parse timestamp string to datetime."""
        if not timestamp_str:
            return datetime.now()

        try:
            # Try ISO format
            return datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        except ValueError:
            try:
                # Try common formats
                for fmt in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"]:
                    try:
                        return datetime.strptime(timestamp_str, fmt)
                    except ValueError:
                        continue
            except Exception:
                pass

        return datetime.now()

    @staticmethod
    def _is_internal_ip(ip: str) -> bool:
        """Check if IP is internal/private."""
        import ipaddress
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False
