#!/usr/bin/env python3
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
POC Test Data Generator

Generates realistic security alert data for POC testing.
"""

import json
import random
import uuid
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address
from typing import Any, Dict, List


class AlertDataGenerator:
    """Generate test security alerts."""

    # Alert types and their properties
    ALERT_TYPES = {
        "malware": {
            "severities": ["critical", "high", "medium"],
            "probability": 0.30,
            "fields": ["file_hash", "file_path", "process_name"],
        },
        "phishing": {
            "severities": ["high", "medium"],
            "probability": 0.20,
            "fields": ["sender_email", "url", "subject"],
        },
        "brute_force": {
            "severities": ["medium", "low"],
            "probability": 0.15,
            "fields": ["login_attempts", "username", "source_port"],
        },
        "ddos": {
            "severities": ["high", "medium"],
            "probability": 0.10,
            "fields": ["packet_count", "target_port", "protocol"],
        },
        "data_exfiltration": {
            "severities": ["critical", "high"],
            "probability": 0.10,
            "fields": ["data_volume", "destination", "protocol"],
        },
        "anomaly": {
            "severities": ["medium", "low", "info"],
            "probability": 0.10,
            "fields": ["anomaly_type", "baseline_value", "actual_value"],
        },
        "unauthorized_access": {
            "severities": ["high", "medium"],
            "probability": 0.03,
            "fields": ["user", "resource", "access_method"],
        },
        "other": {"severities": ["low", "info"], "probability": 0.02, "fields": ["details"]},
    }

    # Malicious IPs for testing
    MALICIOUS_IPS = ["45.33.32.156", "185.220.101.1", "103.43.96.2", "198.51.100.1", "192.0.2.1"]

    # Internal IPs for testing
    INTERNAL_IPS = ["10.0.0.50", "10.0.1.100", "192.168.1.50", "172.16.0.50"]

    # Common ports
    COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 8080]

    def __init__(self, seed: int = 42):
        """Initialize generator with random seed."""
        random.seed(seed)

    def generate_alert(
        self, alert_id: str = None, alert_type: str = None, severity: str = None
    ) -> Dict[str, Any]:
        """
        Generate a single security alert.

        Args:
            alert_id: Custom alert ID (auto-generated if None)
            alert_type: Alert type (random if None)
            severity: Severity level (random if None)

        Returns:
            Dictionary representing a security alert
        """
        # Generate alert ID if not provided
        if not alert_id:
            alert_id = f"ALT-POC-{uuid.uuid4().hex[:12].upper()}"

        # Select alert type if not provided
        if not alert_type:
            # Weighted random selection based on probability
            types = list(self.ALERT_TYPES.keys())
            weights = [self.ALERT_TYPES[t]["probability"] for t in types]
            alert_type = random.choices(types, weights=weights)[0]

        # Get alert type config
        type_config = self.ALERT_TYPES[alert_type]

        # Select severity if not provided
        if not severity:
            severity = random.choice(type_config["severities"])

        # Generate timestamp (within last 24 hours)
        timestamp = datetime.now(UTC) - timedelta(
            hours=random.randint(0, 24), minutes=random.randint(0, 60)
        )

        # Generate base alert
        alert = {
            "alert_id": alert_id,
            "timestamp": timestamp.isoformat() + "Z",
            "alert_type": alert_type,
            "severity": severity,
            "description": self._generate_description(alert_type, severity),
            "source_ip": self._generate_ip(alert_type),
            "target_ip": random.choice(self.INTERNAL_IPS),
            "source_port": random.choice(self.COMMON_PORTS) if random.random() > 0.5 else None,
            "target_port": random.choice(self.COMMON_PORTS),
            "protocol": random.choice(["TCP", "UDP", "ICMP"]),
        }

        # Add type-specific fields
        alert.update(self._generate_type_fields(alert_type))

        # Add metadata
        alert["metadata"] = {
            "siem_source": random.choice(["splunk", "qradar", "elasticsearch", "sumologic"]),
            "rule_name": f"{alert_type.upper()}_Detection_{random.randint(1, 999):03d}",
            "confidence": random.randint(50, 100),
            "poc_generated": True,
        }

        return alert

    def _generate_description(self, alert_type: str, severity: str) -> str:
        """Generate alert description."""
        templates = {
            "malware": [
                "Malware detected on endpoint {hostname}",
                "Suspicious file activity: {file}",
                "Ransomware behavior pattern detected",
            ],
            "phishing": [
                "Spear phishing email detected from {sender}",
                "Suspicious URL in email body: {url}",
                "Phishing kit detected on external server",
            ],
            "brute_force": [
                "Multiple failed login attempts from {ip}",
                "SSH brute force attack detected",
                "Password spraying attack against {service}",
            ],
            "ddos": [
                "High volume of requests from {ip}",
                "DDoS attack pattern detected",
                "Amplification attack detected",
            ],
            "data_exfiltration": [
                "Large data transfer to external location",
                "Suspicious data upload detected",
                "Potential data exfiltration to {destination}",
            ],
            "anomaly": [
                "Unusual network traffic pattern detected",
                "Anomalous user behavior: {user}",
                "Baseline deviation detected",
            ],
            "unauthorized_access": [
                "Unauthorized access attempt to {resource}",
                "Privilege escalation attempt detected",
                "Suspicious admin activity",
            ],
        }
        return random.choice(templates.get(alert_type, ["Security alert detected"]))

    def _generate_ip(self, alert_type: str) -> str:
        """Generate source IP based on alert type."""
        if alert_type in ["malware", "phishing", "ddos"]:
            # External IP (more likely malicious)
            if random.random() > 0.3:
                return random.choice(self.MALICIOUS_IPS)
        return f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"

    def _generate_type_fields(self, alert_type: str) -> Dict[str, Any]:
        """Generate type-specific fields."""
        fields = {}

        if alert_type == "malware":
            fields.update(
                {
                    "file_hash": self._generate_file_hash(),
                    "file_path": random.choice(
                        [
                            "/tmp/malware.exe",
                            "C:\\Windows\\Temp\\suspicious.exe",
                            "/home/user/Downloads/document.pdf.exe",
                        ]
                    ),
                    "process_name": random.choice(
                        ["svchost.exe", "explorer.exe", "suspicious_process.exe"]
                    ),
                }
            )

        elif alert_type == "phishing":
            fields.update(
                {
                    "sender_email": f"attacker@{random.choice(['malicious.com', 'phishing.net', 'spoofed.org'])}",
                    "url": f"http://{random.choice(['malicious-site.com', 'fake-login.com', 'phishing-page.net'])}",
                    "subject": "Urgent: Action Required",
                }
            )

        elif alert_type == "brute_force":
            fields.update(
                {
                    "login_attempts": random.randint(5, 100),
                    "username": random.choice(["admin", "root", "user", "test"]),
                    "auth_protocol": random.choice(["SSH", "FTP", "RDP", "HTTP"]),
                }
            )

        elif alert_type == "ddos":
            fields.update(
                {
                    "packet_count": random.randint(1000, 100000),
                    "attack_type": random.choice(["SYN Flood", "UDP Flood", "HTTP Flood"]),
                    "bandwidth": f"{random.randint(1, 100)} Gbps",
                }
            )

        elif alert_type == "data_exfiltration":
            fields.update(
                {
                    "data_volume": f"{random.randint(1, 1000)} GB",
                    "destination": f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
                    "protocol": random.choice(["HTTP", "FTP", "DNS"]),
                }
            )

        elif alert_type == "anomaly":
            fields.update(
                {
                    "anomaly_type": random.choice(
                        ["Traffic Spike", "Unusual Time", "New Location"]
                    ),
                    "baseline_value": random.randint(10, 100),
                    "actual_value": random.randint(500, 5000),
                }
            )

        elif alert_type == "unauthorized_access":
            fields.update(
                {
                    "user": random.choice(["admin", "unknown", "service"]),
                    "resource": random.choice(["database", "server", "admin-panel"]),
                    "access_method": random.choice(["SSH", "Web", "API"]),
                }
            )

        return fields

    def _generate_file_hash(self) -> str:
        """Generate random SHA256 hash."""
        import hashlib

        data = str(random.random()).encode()
        return hashlib.sha256(data).hexdigest()

    def generate_alerts(
        self,
        count: int,
        alert_type: str = None,
        severity: str = None,
        distribution: Dict[str, float] = None,
    ) -> List[Dict[str, Any]]:
        """
        Generate multiple alerts.

        Args:
            count: Number of alerts to generate
            alert_type: Specific alert type (mixed if None)
            severity: Specific severity (mixed if None)
            distribution: Custom distribution dict

        Returns:
            List of alert dictionaries
        """
        alerts = []

        if distribution:
            # Use custom distribution
            types = list(distribution.keys())
            weights = list(distribution.values())
            for i in range(count):
                atype = random.choices(types, weights=weights)[0]
                alert = self.generate_alert(alert_type=atype, severity=severity)
                alerts.append(alert)
        else:
            # Use default distribution
            for i in range(count):
                alert = self.generate_alert(alert_type=alert_type, severity=severity)
                alerts.append(alert)

        return alerts

    def save_to_file(self, alerts: List[Dict[str, Any]], filepath: str):
        """Save alerts to JSON file."""
        with open(filepath, "w") as f:
            json.dump(alerts, f, indent=2, default=str)
        print(f"✓ Saved {len(alerts)} alerts to {filepath}")

    def save_to_csv(self, alerts: List[Dict[str, Any]], filepath: str):
        """Save alerts to CSV file."""
        import csv

        if not alerts:
            return

        # Flatten nested structures
        flattened = []
        for alert in alerts:
            flat = {
                "alert_id": alert["alert_id"],
                "timestamp": alert["timestamp"],
                "alert_type": alert["alert_type"],
                "severity": alert["severity"],
                "description": alert["description"],
                "source_ip": alert["source_ip"],
                "target_ip": alert["target_ip"],
                "source_port": alert.get("source_port", ""),
                "target_port": alert["target_port"],
                "protocol": alert["protocol"],
            }

            # Add type-specific fields
            for key, value in alert.items():
                if key not in flat and key != "metadata":
                    flat[key] = str(value)

            flattened.append(flat)

        # Write CSV
        with open(filepath, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=flattened[0].keys())
            writer.writeheader()
            writer.writerows(flattened)

        print(f"✓ Saved {len(alerts)} alerts to {filepath}")


def main():
    """CLI for data generator."""
    import argparse

    parser = argparse.ArgumentParser(description="Generate POC test data")
    parser.add_argument("--count", type=int, default=100, help="Number of alerts to generate")
    parser.add_argument("--type", type=str, help="Specific alert type")
    parser.add_argument("--severity", type=str, help="Specific severity level")
    parser.add_argument(
        "--output", type=str, default="tests/poc/data/alerts.json", help="Output file path"
    )
    parser.add_argument(
        "--format", type=str, default="json", choices=["json", "csv"], help="Output format"
    )

    args = parser.parse_args()

    # Create output directory
    import os

    os.makedirs(os.path.dirname(args.output), exist_ok=True)

    # Generate alerts
    generator = AlertDataGenerator()
    print(f"Generating {args.count} alerts...")
    alerts = generator.generate_alerts(args.count, alert_type=args.type, severity=args.severity)

    # Save to file
    if args.format == "json":
        generator.save_to_file(alerts, args.output)
    else:
        csv_output = args.output.replace(".json", ".csv")
        generator.save_to_csv(alerts, csv_output)

    print(f"✓ Generated {len(alerts)} alerts")


if __name__ == "__main__":
    main()
