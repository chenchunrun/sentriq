"""Utilities for validating and normalizing alert creation payloads."""

from __future__ import annotations

from datetime import UTC, datetime
from ipaddress import ip_address
from typing import Any, Dict


_ALLOWED_SEVERITIES = {"critical", "high", "medium", "low", "info"}
_ALLOWED_ALERT_TYPES = {
    "malware",
    "phishing",
    "brute_force",
    "data_exfiltration",
    "anomaly",
    "denial_of_service",
    "unauthorized_access",
    "policy_violation",
    "other",
}
_ALLOWED_STATUS = {"pending", "analyzing", "analyzed", "investigating", "resolved", "false_positive", "suppressed"}


def _normalize_port(value: Any) -> int | None:
    if value in (None, "", "null"):
        return None
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    if 1 <= port <= 65535:
        return port
    return None


def _normalize_ip(value: Any, field_name: str) -> str | None:
    if value in (None, "", "null"):
        return None
    try:
        return str(ip_address(str(value).strip()))
    except ValueError as exc:
        raise ValueError(f"{field_name} must be a valid IP address") from exc


def build_alert_create_payload(request_data: Dict[str, Any], alert_id: str) -> Dict[str, Any]:
    """Build DB payload for alert creation from UI request data."""
    title = (request_data.get("title") or "").strip()
    if not title:
        raise ValueError("title is required")

    severity = str(request_data.get("severity", "medium")).lower().strip()
    if severity not in _ALLOWED_SEVERITIES:
        severity = "medium"

    raw_type = request_data.get("alert_type", request_data.get("type", "other"))
    alert_type = str(raw_type).lower().strip().replace("-", "_")
    if alert_type not in _ALLOWED_ALERT_TYPES:
        alert_type = "other"

    status = str(request_data.get("status", "pending")).lower().strip()
    if status == "new":
        status = "pending"
    if status not in _ALLOWED_STATUS:
        status = "pending"

    source_ip = _normalize_ip(request_data.get("source_ip"), "source_ip")
    destination_ip = _normalize_ip(
        request_data.get("destination_ip", request_data.get("target_ip")),
        "destination_ip",
    )
    protocol = request_data.get("protocol")
    description = request_data.get("description")

    return {
        "alert_id": alert_id,
        "received_at": datetime.now(UTC),
        "alert_type": alert_type,
        "severity": severity,
        "status": status,
        "title": title,
        "description": description,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "source_port": _normalize_port(request_data.get("source_port")),
        "destination_port": _normalize_port(request_data.get("destination_port")),
        "protocol": protocol,
        "raw_data": {
            "source": "web_dashboard",
            "input": request_data,
        },
    }
