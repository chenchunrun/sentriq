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
Splunk alert processor for normalizing Splunk alerts.

This module handles parsing and normalization of alerts from Splunk SIEM,
including field mapping, IOC extraction, and severity mapping.
"""

import re
from datetime import datetime
from typing import Any, Dict, List, Optional

from shared.models.alert import AlertType, SecurityAlert, Severity
from shared.utils.logger import get_logger
from shared.utils.time import utc_now, utc_now_iso

logger = get_logger(__name__)


class SplunkProcessor:
    """
    Processor for Splunk SIEM alerts.

    Handles Splunk-specific alert formats and field mappings.
    """

    # Splunk severity mappings
    SEVERITY_MAP = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "informational": Severity.INFO,
        "info": Severity.INFO,
        # Numeric severity (0-10)
        "10": Severity.CRITICAL,
        "9": Severity.CRITICAL,
        "8": Severity.HIGH,
        "7": Severity.HIGH,
        "6": Severity.MEDIUM,
        "5": Severity.MEDIUM,
        "4": Severity.MEDIUM,
        "3": Severity.LOW,
        "2": Severity.LOW,
        "1": Severity.LOW,
        "0": Severity.INFO,
    }

    # Splunk alert type mappings
    ALERT_TYPE_MAP = {
        "malware": AlertType.MALWARE,
        "phishing": AlertType.PHISHING,
        "brute_force": AlertType.BRUTE_FORCE,
        "brute-force": AlertType.BRUTE_FORCE,
        "ddos": AlertType.DDOS,
        "denial_of_service": AlertType.DDOS,
        "data_exfiltration": AlertType.DATA_EXFILTRATION,
        "exfiltration": AlertType.DATA_EXFILTRATION,
        "unauthorized_access": AlertType.UNAUTHORIZED_ACCESS,
        "anomaly": AlertType.ANOMALY,
        "intrusion": AlertType.UNAUTHORIZED_ACCESS,
        "intrusion_detection": AlertType.UNAUTHORIZED_ACCESS,
        "web_attack": AlertType.UNAUTHORIZED_ACCESS,
        "malware_detection": AlertType.MALWARE,
        "virus": AlertType.MALWARE,
    }

    def __init__(self):
        """Initialize Splunk processor."""
        self.processed_count = 0
        self.error_count = 0

    def process(self, raw_alert: Dict[str, Any]) -> SecurityAlert:
        """
        Process a Splunk alert and convert to standard SecurityAlert format.

        Args:
            raw_alert: Raw Splunk alert data

        Returns:
            Normalized SecurityAlert

        Raises:
            ValueError: If required fields are missing or invalid
        """
        try:
            alert_data = self._extract_payload(raw_alert)

            # Extract core fields
            alert_id = self._extract_alert_id(alert_data)
            timestamp = self._extract_timestamp(alert_data)
            alert_type = self._extract_alert_type(alert_data)
            severity = self._extract_severity(alert_data)
            description = self._extract_description(alert_data)

            # Extract network information
            source_ip = self._extract_field(alert_data, ["src_ip", "source_ip", "src", "src_address"])
            target_ip = self._extract_field(alert_data, ["dest_ip", "destination_ip", "dest", "dst_ip", "dest_address"])
            source_port = self._extract_port(alert_data, ["src_port", "source_port"])
            destination_port = self._extract_port(alert_data, ["dest_port", "destination_port", "dst_port"])
            protocol = self._extract_field(alert_data, ["protocol", "transport"])

            # Extract entity references
            asset_id = self._extract_field(alert_data, ["asset_id", "asset", "host", "hostname", "dest_host"])
            user_id = self._extract_field(alert_data, ["user_id", "user", "username", "account", "dest_user"])

            # Extract threat-specific fields
            file_hash = self._extract_file_hash(alert_data)
            url = self._extract_field(alert_data, ["url", "uri", "domain", "dest_url"])
            process_name = self._extract_field(alert_data, ["process_name", "process", "proc_name"])
            process_id = self._extract_field(alert_data, ["process_id", "pid"])

            # Extract Splunk-specific metadata
            source = alert_data.get("source", raw_alert.get("source", "splunk"))
            source_ref = alert_data.get(
                "search_id",
                alert_data.get("result_id", raw_alert.get("search_id", raw_alert.get("result_id", ""))),
            )

            # Extract IOCs
            iocs = self._extract_iocs(alert_data)

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
                    "source_type": "splunk",
                    "normalized_at": utc_now_iso(),
                    "splunk_search": alert_data.get("search_name", ""),
                    "splunk_app": alert_data.get("app", ""),
                    "splunk_owner": alert_data.get("owner", ""),
                    "iocs_extracted": iocs,
                },
            )

            self.processed_count += 1

            logger.info(
                "Splunk alert processed",
                extra={
                    "alert_id": alert_id,
                    "alert_type": alert_type.value,
                    "severity": severity.value,
                },
            )

            return normalized_alert

        except Exception as e:
            self.error_count += 1
            logger.error(f"Failed to process Splunk alert: {e}", exc_info=True)
            raise ValueError(f"Splunk alert processing failed: {str(e)}")

    def _extract_payload(self, raw_alert: Dict[str, Any]) -> Dict[str, Any]:
        """Unwrap common Splunk envelope formats."""
        payload = raw_alert.get("result")
        if isinstance(payload, dict):
            return payload
        return raw_alert

    def _extract_alert_id(self, raw_alert: Dict[str, Any]) -> str:
        """Extract alert ID from Splunk alert."""
        # First priority: preserve existing alert_id from database
        # This ensures foreign key relationships are maintained
        if "alert_id" in raw_alert and raw_alert["alert_id"]:
            return str(raw_alert["alert_id"])

        # Priority order for other alert ID fields
        alert_id = (
            raw_alert.get("result_id")
            or raw_alert.get("sid")
            or raw_alert.get("id")
        )

        if not alert_id:
            # Generate ID from signature fields
            signature = (
                raw_alert.get("signature")
                or raw_alert.get("rule_name")
                or raw_alert.get("signature_id")
            )
            if signature:
                alert_id = f"SPLUNK-{signature}"

        if not alert_id:
            # Generate unique ID
            import uuid
            alert_id = f"SPLUNK-{uuid.uuid4()}"

        return str(alert_id)

    def _extract_timestamp(self, raw_alert: Dict[str, Any]) -> datetime:
        """Extract and parse timestamp from Splunk alert."""
        timestamp_fields = ["_time", "timestamp", "time", "event_time", "start_time"]

        for field in timestamp_fields:
            if field in raw_alert and raw_alert[field]:
                timestamp_str = raw_alert[field]

                # If already datetime object
                if isinstance(timestamp_str, datetime):
                    return timestamp_str

                # Try parsing string timestamps
                if isinstance(timestamp_str, str):
                    # Try common Splunk timestamp formats
                    formats = [
                        "%Y-%m-%dT%H:%M:%S.%fZ",  # ISO with microseconds
                        "%Y-%m-%dT%H:%M:%SZ",     # ISO format
                        "%Y-%m-%dT%H:%M:%S.%f",   # ISO without Z
                        "%Y-%m-%dT%H:%M:%S",      # ISO without timezone
                        "%Y-%m-%d %H:%M:%S",      # Space separated
                        "%Y-%m-%d %H:%M:%S.%f",   # Space with microseconds
                        "%d/%m/%Y:%H:%M:%S",      # Splunk default
                        "%m/%d/%Y:%H:%M:%S",      # US format
                    ]

                    for fmt in formats:
                        try:
                            return datetime.strptime(timestamp_str, fmt)
                        except ValueError:
                            continue

        # Default to current time if no valid timestamp found
        return utc_now().replace(tzinfo=None)

    def _extract_alert_type(self, raw_alert: Dict[str, Any]) -> AlertType:
        """Extract and map alert type from Splunk alert."""
        # Try multiple field names for alert type
        type_value = (
            raw_alert.get("category")
            or raw_alert.get("alert_type")
            or raw_alert.get("type")
            or raw_alert.get("threat_type")
            or raw_alert.get("attack_type")
            or raw_alert.get("rule_type")
        )

        if type_value:
            type_str = str(type_value).lower().replace("-", "_").replace(" ", "_")
            return self.ALERT_TYPE_MAP.get(type_str, AlertType.OTHER)

        return AlertType.OTHER

    def _extract_severity(self, raw_alert: Dict[str, Any]) -> Severity:
        """Extract and map severity from Splunk alert."""
        # Try multiple field names for severity
        severity_value = (
            raw_alert.get("severity")
            or raw_alert.get("priority")
            or raw_alert.get("level")
            or raw_alert.get("risk_level")
        )

        if severity_value:
            severity_str = str(severity_value).lower()
            return self.SEVERITY_MAP.get(severity_str, Severity.MEDIUM)

        return Severity.MEDIUM

    def _extract_description(self, raw_alert: Dict[str, Any]) -> str:
        """Extract description from Splunk alert."""
        # Try multiple field names for description
        description = (
            raw_alert.get("message")
            or raw_alert.get("description")
            or raw_alert.get("title")
            or raw_alert.get("rule_name")
            or raw_alert.get("signature")
            or raw_alert.get("search_name")
        )

        if description:
            return str(description)[:2000]  # Truncate to max length

        return "Splunk security alert"

    def _extract_field(self, raw_alert: Dict[str, Any], field_names: List[str]) -> Optional[str]:
        """Extract field value trying multiple possible field names."""
        for field_name in field_names:
            if field_name in raw_alert and raw_alert[field_name]:
                value = raw_alert[field_name]
                if value and value != "-":
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
        hash_fields = ["file_hash", "hash", "md5", "sha1", "sha256", "file_hash_value"]

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
        Extract Indicators of Compromise from Splunk alert.

        Args:
            raw_alert: Raw Splunk alert data

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

        # Convert entire alert to text for scanning
        alert_text = str(raw_alert)

        # Extract IP addresses (IPv4)
        ip_pattern = r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
        ip_matches = re.findall(ip_pattern, alert_text)
        iocs["ip_addresses"] = list(set(ip_matches))

        # Extract file hashes (MD5, SHA1, SHA256)
        md5_pattern = r"\b[a-fA-F0-9]{32}\b"
        sha1_pattern = r"\b[a-fA-F0-9]{40}\b"
        sha256_pattern = r"\b[a-fA-F0-9]{64}\b"

        md5_matches = re.findall(md5_pattern, alert_text)
        sha1_matches = re.findall(sha1_pattern, alert_text)
        sha256_matches = re.findall(sha256_pattern, alert_text)

        iocs["file_hashes"] = list(set(md5_matches + sha1_matches + sha256_matches))

        # Extract URLs
        url_pattern = r"https?://[^\s<>\"]+"
        url_matches = re.findall(url_pattern, alert_text)
        iocs["urls"] = list(set(url_matches))

        # Extract domains
        domain_pattern = r"\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+\b"
        domain_matches = re.findall(domain_pattern, alert_text)

        # Filter out common non-domain patterns
        tlds = [".com", ".org", ".net", ".edu", ".gov", ".mil", ".io", ".co", ".uk"]
        iocs["domains"] = [
            domain for domain in domain_matches
            if any(tld in domain.lower() for tld in tlds)
        ]

        # Extract email addresses
        email_pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
        email_matches = re.findall(email_pattern, alert_text)
        iocs["email_addresses"] = list(set(email_matches))

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
