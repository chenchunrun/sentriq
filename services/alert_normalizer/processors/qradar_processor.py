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
QRadar alert processor for normalizing QRadar alerts.

This module handles parsing and normalization of alerts from IBM QRadar SIEM,
including field mapping, IOC extraction, and severity mapping.
"""

import re
from datetime import datetime
from typing import Any, Dict, List, Optional

from shared.models.alert import AlertType, SecurityAlert, Severity
from shared.utils.logger import get_logger
from shared.utils.time import utc_now, utc_now_iso

logger = get_logger(__name__)


class QRadarProcessor:
    """
    Processor for IBM QRadar SIEM alerts.

    Handles QRadar-specific alert formats and field mappings.
    QRadar uses magnitude and severity scores differently than Splunk.
    """

    # QRadar severity mappings (0-10 scale)
    SEVERITY_MAP = {
        # High severity (8-10)
        "10": Severity.CRITICAL,
        "9": Severity.CRITICAL,
        "8": Severity.HIGH,
        # Medium-high severity (5-7)
        "7": Severity.HIGH,
        "6": Severity.MEDIUM,
        "5": Severity.MEDIUM,
        # Low-medium severity (3-4)
        "4": Severity.MEDIUM,
        "3": Severity.LOW,
        # Low severity (1-2)
        "2": Severity.LOW,
        "1": Severity.LOW,
        "0": Severity.INFO,
    }

    # QRadar magnitude can affect severity
    MAGNITUDE_MULTIPLIER = {
        "high": 1.5,
        "medium": 1.0,
        "low": 0.5,
    }

    # QRadar offense type mappings
    OFFENSE_TYPE_MAP = {
        "Malware Detected": AlertType.MALWARE,
        "Malware": AlertType.MALWARE,
        "Phishing": AlertType.PHISHING,
        "Brute Force": AlertType.BRUTE_FORCE,
        "Brute-Force": AlertType.BRUTE_FORCE,
        "DDoS Attack": AlertType.DDOS,
        "Denial of Service": AlertType.DDOS,
        "Data Exfiltration": AlertType.DATA_EXFILTRATION,
        "Unauthorized Access": AlertType.UNAUTHORIZED_ACCESS,
        "Anomaly Detected": AlertType.ANOMALY,
        "Network Anomaly": AlertType.ANOMALY,
        "Suspicious Activity": AlertType.ANOMALY,
        "Policy Violation": AlertType.OTHER,
        "Security Policy Violation": AlertType.OTHER,
    }

    def __init__(self):
        """Initialize QRadar processor."""
        self.processed_count = 0
        self.error_count = 0

    def process(self, raw_alert: Dict[str, Any]) -> SecurityAlert:
        """
        Process a QRadar alert and convert to standard SecurityAlert format.

        Args:
            raw_alert: Raw QRadar alert data

        Returns:
            Normalized SecurityAlert

        Raises:
            ValueError: If required fields are missing or invalid
        """
        try:
            # Extract core fields
            alert_id = self._extract_alert_id(raw_alert)
            timestamp = self._extract_timestamp(raw_alert)
            alert_type = self._extract_alert_type(raw_alert)
            severity = self._extract_severity(raw_alert)
            description = self._extract_description(raw_alert)

            # Extract network information
            source_ip = self._extract_field(raw_alert, ["source_ip", "src_address", "source_address"])
            target_ip = self._extract_field(raw_alert, ["destination_ip", "dest_address", "destination_address"])
            source_port = self._extract_port(raw_alert, ["source_port", "src_port"])
            destination_port = self._extract_port(raw_alert, ["destination_port", "dest_port"])
            protocol = self._extract_field(raw_alert, ["protocol", "transport_protocol", "layer4_protocol"])

            # Extract entity references
            asset_id = self._extract_field(raw_alert, ["asset_id", "host_name", "destination_host"])
            user_id = self._extract_field(raw_alert, ["user_name", "username", "source_user"])

            # Extract threat-specific fields
            file_hash = self._extract_file_hash(raw_alert)
            url = self._extract_field(raw_alert, ["url", "uri", "domain_name"])
            process_name = self._extract_field(raw_alert, ["process_name", "process"])

            # Extract QRadar-specific metadata
            source = "qradar"
            source_ref = str(raw_alert.get("offense_id", raw_alert.get("id", "")))

            # Extract IOCs
            iocs = self._extract_iocs(raw_alert)

            # Create normalized alert
            normalized_alert = SecurityAlert(
                alert_id=alert_id,
                timestamp=timestamp,
                alert_type=alert_type,
                severity=severity,
                description=description,
                source_ip=source_ip,
                target_ip=target_ip,
                file_hash=file_hash,
                url=url,
                asset_id=asset_id,
                user_id=user_id,
                source=source,
                source_ref=source_ref,
                raw_data=raw_alert,
                normalized_data={
                    "source_type": "qradar",
                    "normalized_at": utc_now_iso(),
                    "offense_id": raw_alert.get("offense_id", ""),
                    "offense_type": raw_alert.get("offense_type", ""),
                    "magnitude": raw_alert.get("magnitude", 0),
                    "category": raw_alert.get("category", ""),
                    "rules": raw_alert.get("rules", []),
                    "iocs_extracted": iocs,
                },
            )

            self.processed_count += 1

            logger.info(
                "QRadar alert processed",
                extra={
                    "alert_id": alert_id,
                    "offense_id": raw_alert.get("offense_id", ""),
                    "alert_type": alert_type.value,
                    "severity": severity.value,
                },
            )

            return normalized_alert

        except Exception as e:
            self.error_count += 1
            logger.error(f"Failed to process QRadar alert: {e}", exc_info=True)
            raise ValueError(f"QRadar alert processing failed: {str(e)}")

    def _extract_alert_id(self, raw_alert: Dict[str, Any]) -> str:
        """Extract alert ID from QRadar alert."""
        # QRadar uses offense_id as primary identifier
        alert_id = (
            raw_alert.get("offense_id")
            or raw_alert.get("id")
            or raw_alert.get("alert_id")
        )

        if alert_id:
            return f"QRADAR-{alert_id}"

        # Generate unique ID
        import uuid
        return f"QRADAR-{uuid.uuid4()}"

    def _extract_timestamp(self, raw_alert: Dict[str, Any]) -> datetime:
        """Extract and parse timestamp from QRadar alert."""
        timestamp_fields = [
            "start_time",
            "timestamp",
            "created_time",
            "offense_start_time",
            "event_time",
        ]

        for field in timestamp_fields:
            if field in raw_alert and raw_alert[field]:
                timestamp_str = raw_alert[field]

                # If already datetime object
                if isinstance(timestamp_str, datetime):
                    return timestamp_str

                # QRadar typically uses milliseconds since epoch
                if isinstance(timestamp_str, (int, float)):
                    try:
                        # Convert milliseconds to seconds
                        return datetime.fromtimestamp(timestamp_str / 1000)
                    except (ValueError, OSError):
                        continue

                # Try parsing string timestamps
                if isinstance(timestamp_str, str):
                    formats = [
                        "%Y-%m-%dT%H:%M:%S.%fZ",  # ISO with microseconds
                        "%Y-%m-%dT%H:%M:%SZ",     # ISO format
                        "%Y-%m-%dT%H:%M:%S",      # ISO without timezone
                        "%Y-%m-%d %H:%M:%S",      # Space separated
                        "%d/%m/%Y %H:%M:%S",      # DD/MM/YYYY
                        "%m/%d/%Y %H:%M:%S",      # MM/DD/YYYY
                    ]

                    for fmt in formats:
                        try:
                            return datetime.strptime(timestamp_str, fmt)
                        except ValueError:
                            continue

        # Default to current time
        return utc_now().replace(tzinfo=None)

    def _extract_alert_type(self, raw_alert: Dict[str, Any]) -> AlertType:
        """Extract and map alert type from QRadar alert."""
        # Try offense_type first
        type_value = (
            raw_alert.get("offense_type")
            or raw_alert.get("category")
            or raw_alert.get("alert_type")
        )

        if type_value:
            type_str = str(type_value).strip()
            return self.OFFENSE_TYPE_MAP.get(type_str, AlertType.OTHER)

        return AlertType.OTHER

    def _extract_severity(self, raw_alert: Dict[str, Any]) -> Severity:
        """
        Extract and calculate severity from QRadar alert.

        QRadar uses both severity (0-10) and magnitude (low/medium/high).
        We combine them to determine final severity.
        """
        # Get base severity
        severity_value = raw_alert.get("severity", 5)

        # Convert to string for mapping
        severity_str = str(int(severity_value)) if isinstance(severity_value, (int, float)) else "5"

        base_severity = self.SEVERITY_MAP.get(severity_str, Severity.MEDIUM)

        # Adjust based on magnitude
        magnitude = str(raw_alert.get("magnitude", "medium")).lower()
        multiplier = self.MAGNITUDE_MULTIPLIER.get(magnitude, 1.0)

        # If magnitude is high and severity is medium, upgrade to high
        if multiplier > 1.0 and base_severity == Severity.MEDIUM:
            return Severity.HIGH

        # If magnitude is low and severity is medium, downgrade to low
        if multiplier < 1.0 and base_severity == Severity.MEDIUM:
            return Severity.LOW

        return base_severity

    def _extract_description(self, raw_alert: Dict[str, Any]) -> str:
        """Extract description from QRadar alert."""
        description = (
            raw_alert.get("description")
            or raw_alert.get("offense_description")
            or raw_alert.get("rule_description")
            or raw_alert.get("message")
        )

        if description:
            return str(description)[:2000]

        # Generate description from offense type
        offense_type = raw_alert.get("offense_type", "")
        if offense_type:
            return f"QRadar offense: {offense_type}"

        return "QRadar security alert"

    def _extract_field(self, raw_alert: Dict[str, Any], field_names: List[str]) -> Optional[str]:
        """Extract field value trying multiple possible field names."""
        for field_name in field_names:
            if field_name in raw_alert and raw_alert[field_name]:
                value = raw_alert[field_name]
                if value and value != "-" and value != "N/A":
                    return str(value)
        return None

    def _extract_port(self, raw_alert: Dict[str, Any], field_names: List[str]) -> Optional[int]:
        """Extract port number and convert to integer."""
        for field_name in field_names:
            if field_name in raw_alert and raw_alert[field_name]:
                try:
                    port = int(raw_alert[field_name])
                    if 0 <= port <= 65535:
                        return port
                except (ValueError, TypeError):
                    continue
        return None

    def _extract_file_hash(self, raw_alert: Dict[str, Any]) -> Optional[str]:
        """Extract and validate file hash."""
        hash_fields = [
            "file_hash",
            "hash_value",
            "md5",
            "sha1",
            "sha256",
            "file_hash_value",
        ]

        for field in hash_fields:
            if field in raw_alert and raw_alert[field]:
                hash_value = str(raw_alert[field]).strip().lower()

                # Validate hash length and format
                if len(hash_value) == 32 and re.match(r"^[a-f0-9]{32}$", hash_value):
                    return hash_value  # MD5
                elif len(hash_value) == 40 and re.match(r"^[a-f0-9]{40}$", hash_value):
                    return hash_value  # SHA1
                elif len(hash_value) == 64 and re.match(r"^[a-f0-9]{64}$", hash_value):
                    return hash_value  # SHA256

        return None

    def _extract_iocs(self, raw_alert: Dict[str, Any]) -> Dict[str, List[str]]:
        """
        Extract Indicators of Compromise from QRadar alert.

        QRadar provides IOC data in specific fields and also in the
        event payload.

        Args:
            raw_alert: Raw QRadar alert data

        Returns:
            Dictionary of IOC type to list of values
        """
        iocs = {
            "ip_addresses": [],
            "file_hashes": [],
            "urls": [],
            "domains": [],
            "email_addresses": [],
        }

        # Extract from dedicated fields
        if "source_ip" in raw_alert and raw_alert["source_ip"]:
            source_ip = str(raw_alert["source_ip"])
            if source_ip not in iocs["ip_addresses"]:
                iocs["ip_addresses"].append(source_ip)

        if "destination_ip" in raw_alert and raw_alert["destination_ip"]:
            dest_ip = str(raw_alert["destination_ip"])
            if dest_ip not in iocs["ip_addresses"]:
                iocs["ip_addresses"].append(dest_ip)

        # Extract from events payload if present
        events = raw_alert.get("events", [])
        if events and isinstance(events, list):
            for event in events:
                event_text = str(event)

                # IP addresses
                ip_pattern = r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
                ip_matches = re.findall(ip_pattern, event_text)
                iocs["ip_addresses"].extend(ip_matches)

                # URLs
                url_pattern = r"https?://[^\s<>\"]+"
                url_matches = re.findall(url_pattern, event_text)
                iocs["urls"].extend(url_matches)

        # Extract from description
        description = raw_alert.get("description", "")
        if description:
            desc_text = str(description)

            # IPs
            ip_pattern = r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
            ip_matches = re.findall(ip_pattern, desc_text)
            iocs["ip_addresses"].extend(ip_matches)

            # Domains
            domain_pattern = r"\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+\b"
            domain_matches = re.findall(domain_pattern, desc_text)

            # Filter domains
            tlds = [".com", ".org", ".net", ".edu", ".gov", ".mil", ".io", ".co", ".uk"]
            valid_domains = [
                domain for domain in domain_matches
                if any(tld in domain.lower() for tld in tlds)
            ]
            iocs["domains"].extend(valid_domains)

            # Emails
            email_pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
            email_matches = re.findall(email_pattern, desc_text)
            iocs["email_addresses"].extend(email_matches)

        # Remove duplicates
        for key in iocs:
            iocs[key] = list(set(iocs[key]))

        return iocs

    def get_stats(self) -> Dict[str, int]:
        """
        Get processing statistics.

        Returns:
            Dictionary with processing stats
        """
        return {
            "processed_count": self.processed_count,
            "error_count": self.error_count,
            "success_rate": (
                (self.processed_count - self.error_count) / self.processed_count
                if self.processed_count > 0
                else 0
            ),
        }
