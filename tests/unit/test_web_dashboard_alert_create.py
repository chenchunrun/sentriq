"""Unit tests for web dashboard alert creation payload normalization."""

from services.web_dashboard.alert_create import build_alert_create_payload


def test_build_alert_payload_normal_case():
    payload = build_alert_create_payload(
        {
            "title": "Suspicious process execution",
            "description": "Detected suspicious binary",
            "severity": "high",
            "type": "malware",
            "source_ip": "1.2.3.4",
            "destination_ip": "10.0.0.8",
            "source_port": "443",
            "destination_port": "8080",
            "protocol": "tcp",
            "status": "new",
        },
        "ALT-TEST-001",
    )

    assert payload["alert_id"] == "ALT-TEST-001"
    assert payload["alert_type"] == "malware"
    assert payload["status"] == "pending"
    assert payload["source_port"] == 443
    assert payload["destination_port"] == 8080
    assert payload["destination_ip"] == "10.0.0.8"
    assert payload["received_at"].tzinfo is not None


def test_build_alert_payload_type_and_status_fallback():
    payload = build_alert_create_payload(
        {
            "title": "Alert",
            "severity": "unexpected",
            "type": "totally-unknown",
            "status": "not-valid",
            "target_ip": "10.0.0.9",
            "source_port": "70000",
        },
        "ALT-TEST-002",
    )

    assert payload["severity"] == "medium"
    assert payload["alert_type"] == "other"
    assert payload["status"] == "pending"
    assert payload["destination_ip"] == "10.0.0.9"
    assert payload["source_port"] is None


def test_build_alert_payload_requires_title():
    try:
        build_alert_create_payload({"severity": "high"}, "ALT-TEST-003")
        assert False, "Expected ValueError for missing title"
    except ValueError as exc:
        assert "title is required" in str(exc)


def test_build_alert_payload_invalid_ip_raises_error():
    try:
        build_alert_create_payload(
            {
                "title": "Alert",
                "source_ip": "not-an-ip",
            },
            "ALT-TEST-004",
        )
        assert False, "Expected ValueError for invalid IP"
    except ValueError as exc:
        assert "source_ip must be a valid IP address" in str(exc)
