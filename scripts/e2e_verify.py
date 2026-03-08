#!/usr/bin/env python3
import json
import os
import sys
from datetime import datetime
from urllib import request, error


def http(method: str, url: str, data: dict | None = None):
    headers = {"Content-Type": "application/json"}
    body = json.dumps(data).encode("utf-8") if data is not None else None
    req = request.Request(url, data=body, headers=headers, method=method)
    try:
        with request.urlopen(req, timeout=10) as resp:
            raw = resp.read().decode("utf-8")
            return resp.status, raw
    except error.HTTPError as e:
        return e.code, e.read().decode("utf-8")
    except Exception as e:
        return 0, str(e)


def main():
    base = os.getenv("BASE_URL", "http://localhost:9001")
    workflow = os.getenv("WORKFLOW_URL", "http://localhost:9008")
    automation = os.getenv("AUTOMATION_URL", "http://localhost:9009")
    similarity = os.getenv("SIMILARITY_URL", "http://localhost:9007")
    analytics = os.getenv("ANALYTICS_URL", "http://localhost:9011")
    reporting = os.getenv("REPORTING_URL", "http://localhost:9012")

    alert_id = f"ALT-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"
    now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    results = []

    status, body = http(
        "POST",
        f"{base}/api/v1/alerts",
        {
            "alert_id": alert_id,
            "timestamp": now,
            "alert_type": "malware",
            "severity": "high",
            "description": "E2E verify alert",
            "source_ip": "45.33.32.156",
            "target_ip": "10.0.0.50",
            "file_hash": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
            "url": "http://malicious.example.com",
            "asset_id": "ASSET-001",
            "user_id": "test.user@example.com",
        },
    )
    results.append(("ingest_alert", status, body))

    status, body = http("GET", f"{base}/api/v1/alerts/{alert_id}")
    results.append(("get_alert_status", status, body))

    status, body = http(
        "POST",
        f"{workflow}/api/v1/workflows/execute",
        {"workflow_id": "alert-processing", "input_data": {"alert_id": alert_id}},
    )
    results.append(("workflow_execute", status, body))

    status, body = http(
        "POST",
        f"{automation}/api/v1/playbooks/execute",
        {"playbook_id": "malware-response", "alert_id": alert_id, "input_data": {}},
    )
    results.append(("automation_execute", status, body))

    status, body = http(
        "POST",
        f"{similarity}/api/v1/search",
        {"query_text": "malware alert", "top_k": 3, "min_similarity": 0.1},
    )
    results.append(("similarity_search", status, body))

    status, body = http("GET", f"{analytics}/api/v1/dashboard")
    results.append(("dashboard", status, body))

    status, body = http(
        "POST",
        f"{reporting}/api/v1/reports/generate",
        {"report_type": "daily_summary"},
    )
    results.append(("report_generate", status, body))

    success = all(code in (200, 201) for _, code, _ in results if code != 0)
    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "alert_id": alert_id,
        "success": success,
        "results": [
            {"step": step, "status_code": code, "response": body[:1000]}
            for step, code, body in results
        ],
    }

    os.makedirs("test-reports", exist_ok=True)
    out_path = "test-reports/e2e_verification.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=True)

    print(out_path)
    print("success" if success else "failed")
    return 0 if success else 2


if __name__ == "__main__":
    sys.exit(main())
