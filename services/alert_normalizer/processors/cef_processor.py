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
CEF (Common Event Format) alert processor for normalizing CEF alerts.

This module handles parsing and normalization of alerts in CEF format,
which is used by many security vendors (Cisco, VMware, Symantec, etc.).
"""

import re
from datetime import datetime
from typing import Any, Dict, List, Optional

from shared.models.alert import AlertType, SecurityAlert, Severity
from shared.utils.logger import get_logger
from shared.utils.time import utc_now, utc_now_iso

logger = get_logger(__name__)


class CEFProcessor:
    """
    Processor for CEF (Common Event Format) alerts.

    CEF format: CEF:Version|Device Vendor|Device Product|Device Version|
                Signature ID|Name|Severity|Extension
    Example: CEF:0|Security|IDS|1.0|100|Detected|10|src=10.0.0.1 dst=192.168.1.1
    """

    # CEF severity mappings (0-10 scale)
    SEVERITY_MAP = {
        "0": Severity.INFO,
        "1": Severity.LOW,
        "2": Severity.LOW,
        "3": Severity.LOW,
        "4": Severity.MEDIUM,
        "5": Severity.MEDIUM,
        "6": Severity.MEDIUM,
        "7": Severity.HIGH,
        "8": Severity.HIGH,
        "9": Severity.CRITICAL,
        "10": Severity.CRITICAL,
    }

    # CEF to standard alert type mappings
    CEF_PREFIX_MAP = {
        "audit": AlertType.OTHER,
        "av": AlertType.MALWARE,
        "anti-malware": AlertType.MALWARE,
        "anti-virus": AlertType.MALWARE,
        "auth": AlertType.UNAUTHORIZED_ACCESS,
        "authentication": AlertType.UNAUTHORIZED_ACCESS,
        "brute": AlertType.BRUTE_FORCE,
        "dns": AlertType.OTHER,
        "endpoint": AlertType.MALWARE,
        "firewall": AlertType.OTHER,
        "ids": AlertType.UNAUTHORIZED_ACCESS,
        "ips": AlertType.UNAUTHORIZED_ACCESS,
        "malware": AlertType.MALWARE,
        "network": AlertType.OTHER,
        "phish": AlertType.PHISHING,
        "proxy": AlertType.OTHER,
        "traffic": AlertType.OTHER,
        "web": AlertType.UNAUTHORIZED_ACCESS,
        "vpn": AlertType.UNAUTHORIZED_ACCESS,
    }

    # Common CEF field mappings
    CEF_FIELD_MAP = {
        "src": "source_ip",
        "srcAddress": "source_ip",
        "src_ip": "source_ip",
        "dst": "target_ip",
        "dstAddress": "target_ip",
        "dest_ip": "target_ip",
        "destination_ip": "target_ip",
        "srcPort": "source_port",
        "src_port": "source_port",
        "source_port": "source_port",
        "dstPort": "destination_port",
        "destPort": "destination_port",
        "dst_port": "destination_port",
        "destination_port": "destination_port",
        "proto": "protocol",
        "protocol": "protocol",
        "dhost": "asset_id",
        "destination_host": "asset_id",
        "dst_host": "asset_id",
        "duser": "user_id",
        "destination_user": "user_id",
        "dst_user": "user_id",
        "shost": "source_host",
        "source_host": "source_host",
        "src_host": "source_host",
        "suser": "source_user",
        "source_user": "source_user",
        "src_user": "source_user",
        "fileHash": "file_hash",
        "fileHashValue": "file_hash",
        "file_hash": "file_hash",
        "fname": "file_name",
        "file_name": "file_name",
        "request": "url",
        "url": "url",
        "requestClientApplication": "process_name",
        "process_name": "process_name",
        "act": "action",
        "action": "action",
    }

    def __init__(self):
        """Initialize CEF processor."""
        self.processed_count = 0
        self.error_count = 0

    def process(self, raw_alert: Dict[str, Any]) -> SecurityAlert:
        """
        Process a CEF alert and convert to standard SecurityAlert format.

        Args:
            raw_alert: Raw CEF alert data (can be string or dict)

        Returns:
            Normalized SecurityAlert

        Raises:
            ValueError: If CEF parsing fails or required fields are missing
        """
        try:
            # Parse CEF message if string
            if isinstance(raw_alert, str):
                cef_data = self._parse_cef_string(raw_alert)
            elif isinstance(raw_alert, dict):
                # Check if message contains CEF string
                cef_message = raw_alert.get("message", raw_alert.get("cef_message", raw_alert.get("raw_message", "")))
                if cef_message:
                    cef_data = self._parse_cef_string(cef_message)
                    # Merge with additional fields from dict
                    cef_data.update({k: v for k, v in raw_alert.items() if k not in ["message", "cef_message", "raw_message"]})
                else:
                    cef_data = raw_alert
            else:
                raise ValueError(f"Unsupported CEF format: {type(raw_alert)}")

            # Extract core fields
            alert_id = self._extract_alert_id(cef_data)
            timestamp = self._extract_timestamp(cef_data)
            alert_type = self._extract_alert_type(cef_data)
            severity = self._extract_severity(cef_data)
            description = self._extract_description(cef_data)

            # Extract network information
            source_ip = self._extract_field(cef_data, ["src", "srcAddress", "src_ip", "source_ip"])
            target_ip = self._extract_field(
                cef_data,
                ["dst", "dstAddress", "dest_ip", "destination_ip", "target_ip"],
            )
            source_port = self._extract_port(cef_data, ["srcPort", "src_port", "source_port"])
            destination_port = self._extract_port(cef_data, ["dstPort", "destPort", "dst_port", "destination_port"])
            protocol = self._extract_field(cef_data, ["proto", "protocol"])

            # Extract entity references
            asset_id = self._extract_field(cef_data, ["dhost", "destination_host", "dst_host"])
            user_id = self._extract_field(cef_data, ["duser", "destination_user", "dst_user"])

            # Extract threat-specific fields
            file_hash = self._extract_field(cef_data, ["fileHash", "fileHashValue", "file_hash"])
            url = self._extract_field(cef_data, ["request", "url"])
            process_name = self._extract_field(cef_data, ["requestClientApplication", "process_name"])

            # Extract CEF metadata
            source = "cef"
            device_vendor = cef_data.get("device_vendor", "")
            device_product = cef_data.get("device_product", "")
            signature_id = cef_data.get("signature_id", "")
            source_ref = f"{device_vendor}/{device_product}/{signature_id}" if signature_id else ""

            # Extract IOCs
            iocs = self._extract_iocs(cef_data)

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
                    "source_type": "cef",
                    "normalized_at": utc_now_iso(),
                    "cef_version": cef_data.get("cef_version", ""),
                    "device_vendor": device_vendor,
                    "device_product": device_product,
                    "device_version": cef_data.get("device_version", ""),
                    "signature_id": signature_id,
                    "iocs_extracted": iocs,
                },
            )

            self.processed_count += 1

            logger.info(
                "CEF alert processed",
                extra={
                    "alert_id": alert_id,
                    "device_vendor": device_vendor,
                    "device_product": device_product,
                    "alert_type": alert_type.value,
                    "severity": severity.value,
                },
            )

            return normalized_alert

        except Exception as e:
            self.error_count += 1
            logger.error(f"Failed to process CEF alert: {e}", exc_info=True)
            raise ValueError(f"CEF alert processing failed: {str(e)}")

    def _parse_cef_string(self, cef_message: str) -> Dict[str, Any]:
        """
        Parse CEF message string into dictionary.

        CEF format: CEF:Version|Device Vendor|Device Product|Device Version|
                    Signature ID|Name|Severity|Extension

        Args:
            cef_message: Raw CEF message string

        Returns:
            Dictionary with parsed CEF fields
        """
        cef_data = {}

        # Check for CEF header
        if not cef_message.startswith("CEF:"):
            raise ValueError("Invalid CEF format: missing CEF header")

        # Split header and extension
        parts = cef_message.split("|", 7)
        if len(parts) < 8:
            raise ValueError("Invalid CEF format: insufficient fields")

        # Parse CEF header
        cef_data["cef_version"] = parts[0].replace("CEF:", "")
        cef_data["device_vendor"] = parts[1]
        cef_data["device_product"] = parts[2]
        cef_data["device_version"] = parts[3]
        cef_data["signature_id"] = parts[4]
        cef_data["name"] = parts[5]
        cef_data["severity"] = parts[6]
        cef_data["extension"] = parts[7] if len(parts) > 7 else ""

        # Parse extension (key=value pairs)
        if cef_data["extension"]:
            # Split by space but preserve quoted strings
            pairs = self._split_cef_extension(cef_data["extension"])

            for pair in pairs:
                if "=" in pair:
                    key, value = pair.split("=", 1)
                    # Map CEF field to standard name
                    standard_key = self.CEF_FIELD_MAP.get(key, key)
                    cef_data[standard_key] = value

        return cef_data

    def _split_cef_extension(self, extension: str) -> List[str]:
        """
        Split CEF extension into key=value pairs.

        Handles quoted strings and escape characters.

        Args:
            extension: CEF extension string

        Returns:
            List of key=value pairs
        """
        pairs = []
        current_pair = []
        in_quotes = False
        escape_next = False

        for char in extension:
            if escape_next:
                current_pair.append(char)
                escape_next = False
            elif char == "\\":
                escape_next = True
            elif char == '"':
                in_quotes = not in_quotes
                current_pair.append(char)
            elif char == " " and not in_quotes:
                if current_pair:
                    pairs.append("".join(current_pair))
                    current_pair = []
            else:
                current_pair.append(char)

        if current_pair:
            pairs.append("".join(current_pair))

        return pairs

    def _extract_alert_id(self, cef_data: Dict[str, Any]) -> str:
        """Extract alert ID from CEF data."""
        # Try signature_id first
        signature_id = cef_data.get("signature_id")
        device_vendor = cef_data.get("device_vendor", "")
        device_product = cef_data.get("device_product", "")

        if signature_id:
            return f"CEF-{device_vendor}-{device_product}-{signature_id}".replace(" ", "-")

        # Generate unique ID
        import uuid
        return f"CEF-{uuid.uuid4()}"

    def _extract_timestamp(self, cef_data: Dict[str, Any]) -> datetime:
        """Extract and parse timestamp from CEF data."""
        timestamp_fields = ["rt", "deviceEventTime", "event_time", "timestamp"]

        for field in timestamp_fields:
            if field in cef_data and cef_data[field]:
                timestamp_str = cef_data[field]

                if isinstance(timestamp_str, datetime):
                    return timestamp_str

                if isinstance(timestamp_str, str):
                    # CEF typically uses Unix timestamp with milliseconds
                    try:
                        # Try Unix timestamp (seconds or milliseconds)
                        if timestamp_str.isdigit():
                            ts = int(timestamp_str)
                            # Check if milliseconds (13 digits) or seconds (10 digits)
                            if ts > 1000000000000:  # Milliseconds
                                return datetime.fromtimestamp(ts / 1000)
                            else:  # Seconds
                                return datetime.fromtimestamp(ts)
                    except (ValueError, OSError):
                        pass

                    # Try ISO format
                    formats = [
                        "%Y-%m-%dT%H:%M:%S.%fZ",
                        "%Y-%m-%dT%H:%M:%SZ",
                        "%Y-%m-%dT%H:%M:%S",
                        "%Y-%m-%d %H:%M:%S",
                        "%b %d %Y %H:%M:%S",  # Jan 01 2025 12:00:00
                    ]

                    for fmt in formats:
                        try:
                            return datetime.strptime(timestamp_str, fmt)
                        except ValueError:
                            continue

        return utc_now().replace(tzinfo=None)

    def _extract_alert_type(self, cef_data: Dict[str, Any]) -> AlertType:
        """Extract and map alert type from CEF data."""
        # Try to determine from device product and signature
        device_product = cef_data.get("device_product", "").lower()
        name = cef_data.get("name", "").lower()

        # Check for keywords in name
        keywords = {
            "malware": AlertType.MALWARE,
            "virus": AlertType.MALWARE,
            "phish": AlertType.PHISHING,
            "brute": AlertType.BRUTE_FORCE,
            "ddos": AlertType.DDOS,
            "denial": AlertType.DDOS,
            "exfiltration": AlertType.DATA_EXFILTRATION,
            "unauthorized": AlertType.UNAUTHORIZED_ACCESS,
            "intrusion": AlertType.UNAUTHORIZED_ACCESS,
            "anomaly": AlertType.ANOMALY,
        }

        for keyword, alert_type in keywords.items():
            if keyword in device_product or keyword in name:
                return alert_type

        return AlertType.OTHER

    def _extract_severity(self, cef_data: Dict[str, Any]) -> Severity:
        """Extract and map severity from CEF data."""
        severity_value = cef_data.get("severity", "5")

        severity_str = str(severity_value)
        return self.SEVERITY_MAP.get(severity_str, Severity.MEDIUM)

    def _extract_description(self, cef_data: Dict[str, Any]) -> str:
        """Extract description from CEF data."""
        description = (
            cef_data.get("name")
            or cef_data.get("msg")
            or cef_data.get("message")
            or cef_data.get("description")
        )

        if description:
            return str(description)[:2000]

        # Generate description from device info
        device_product = cef_data.get("device_product", "")
        device_vendor = cef_data.get("device_vendor", "")

        if device_product:
            return f"CEF alert from {device_vendor} {device_product}"

        return "CEF security alert"

    def _extract_field(self, cef_data: Dict[str, Any], field_names: List[str]) -> Optional[str]:
        """Extract field value trying multiple possible field names."""
        for field_name in field_names:
            if field_name in cef_data and cef_data[field_name]:
                value = cef_data[field_name]
                if value and value != "-" and value != "N/A":
                    return str(value)
        return None

    def _extract_port(self, cef_data: Dict[str, Any], field_names: List[str]) -> Optional[int]:
        """Extract port number and convert to integer."""
        for field_name in field_names:
            if field_name in cef_data and cef_data[field_name]:
                try:
                    port = int(cef_data[field_name])
                    if 0 <= port <= 65535:
                        return port
                except (ValueError, TypeError):
                    continue
        return None

    def _extract_iocs(self, cef_data: Dict[str, Any]) -> Dict[str, List[str]]:
        """
        Extract Indicators of Compromise from CEF alert.

        Args:
            cef_data: Parsed CEF data dictionary

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

        # Convert entire CEF data to text
        alert_text = str(cef_data)

        # Extract IP addresses
        ip_pattern = r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
        ip_matches = re.findall(ip_pattern, alert_text)
        iocs["ip_addresses"] = list(set(ip_matches))

        # Extract file hashes
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
