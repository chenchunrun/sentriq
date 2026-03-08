#!/usr/bin/env bash
set -euo pipefail

MODE="${MODE:-docker}"

BASE_URL="${BASE_URL:-http://localhost:9001}"
NORMALIZER_URL="${NORMALIZER_URL:-http://localhost:9002}"
CONTEXT_URL="${CONTEXT_URL:-http://localhost:9003}"
THREAT_URL="${THREAT_URL:-http://localhost:9004}"
AI_URL="${AI_URL:-http://localhost:9006}"
SIMILARITY_URL="${SIMILARITY_URL:-http://localhost:9007}"
WORKFLOW_URL="${WORKFLOW_URL:-http://localhost:9008}"
AUTOMATION_URL="${AUTOMATION_URL:-http://localhost:9009}"
ANALYTICS_URL="${ANALYTICS_URL:-http://localhost:9011}"
REPORTING_URL="${REPORTING_URL:-http://localhost:9012}"
NOTIFICATION_URL="${NOTIFICATION_URL:-http://localhost:9010}"

ALERT_ID="ALT-$(date +%Y%m%d-%H%M%S)-$RANDOM"

echo "== E2E Smoke =="
echo "Alert ID: ${ALERT_ID}"

if [[ "${MODE}" == "docker" ]]; then
  echo "-- Running inside container (alert-ingestor)"
  cat <<'PY' | docker-compose exec -T alert-ingestor python -
import json
import os
import random
from datetime import datetime
from urllib import request

base = os.getenv("BASE_URL", "http://alert-ingestor:8000")
workflow = os.getenv("WORKFLOW_URL", "http://workflow-engine:8000")
automation = os.getenv("AUTOMATION_URL", "http://automation-orchestrator:8000")
similarity = os.getenv("SIMILARITY_URL", "http://similarity-search:8000")
analytics = os.getenv("ANALYTICS_URL", "http://data-analytics:8000")
reporting = os.getenv("REPORTING_URL", "http://reporting-service:8000")

alert_id = f"ALT-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}-{random.randint(1000,9999)}"
now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

def req(method, url, data=None):
    headers = {"Content-Type": "application/json"}
    body = json.dumps(data).encode() if data is not None else None
    r = request.Request(url, data=body, headers=headers, method=method)
    with request.urlopen(r, timeout=10) as resp:
        return resp.status, resp.read().decode()

print("== E2E Smoke (container) ==")
print("Alert ID:", alert_id)

status, body = req("POST", f"{base}/api/v1/alerts", {
    "alert_id": alert_id,
    "timestamp": now,
    "alert_type": "malware",
    "severity": "high",
    "description": "E2E smoke test alert",
    "source_ip": "45.33.32.156",
    "target_ip": "10.0.0.50",
    "file_hash": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
    "url": "http://malicious.example.com",
    "asset_id": "ASSET-001",
    "user_id": "test.user@example.com"
})
print("Ingest:", status)
open("/tmp/e2e_ingest.json", "w", encoding="utf-8").write(body)

status, body = req("GET", f"{base}/api/v1/alerts/{alert_id}")
print("Status:", status)
open("/tmp/e2e_status.json", "w", encoding="utf-8").write(body)

status, body = req("POST", f"{workflow}/api/v1/workflows/execute", {
    "workflow_id": "alert-processing",
    "input_data": {"alert_id": alert_id}
})
print("Workflow:", status)
open("/tmp/e2e_workflow.json", "w", encoding="utf-8").write(body)

status, body = req("POST", f"{automation}/api/v1/playbooks/execute", {
    "playbook_id": "malware-response",
    "alert_id": alert_id,
    "input_data": {}
})
print("Automation:", status)
open("/tmp/e2e_automation.json", "w", encoding="utf-8").write(body)

status, body = req("POST", f"{similarity}/api/v1/search", {
    "query_text": "malware alert from 45.33.32.156",
    "top_k": 3,
    "min_similarity": 0.1
})
print("Similarity:", status)
open("/tmp/e2e_similarity.json", "w", encoding="utf-8").write(body)

status, body = req("GET", f"{analytics}/api/v1/dashboard")
print("Analytics:", status)
open("/tmp/e2e_dashboard.json", "w", encoding="utf-8").write(body)

status, body = req("POST", f"{reporting}/api/v1/reports/generate", {
    "report_type": "daily_summary"
})
print("Report:", status)
open("/tmp/e2e_report.json", "w", encoding="utf-8").write(body)

print("Done. Outputs written to /tmp/e2e_*.json inside container.")
PY
  exit 0
fi

echo "-- Ingest alert"
curl -sS -X POST "${BASE_URL}/api/v1/alerts" \
  -H "Content-Type: application/json" \
  -d @- <<JSON >/tmp/e2e_ingest.json
{
  "alert_id": "${ALERT_ID}",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "alert_type": "malware",
  "severity": "high",
  "description": "E2E smoke test alert",
  "source_ip": "45.33.32.156",
  "target_ip": "10.0.0.50",
  "file_hash": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
  "url": "http://malicious.example.com",
  "asset_id": "ASSET-001",
  "user_id": "test.user@example.com"
}
JSON

echo "-- Check alert status (ingestor)"
curl -sS "${BASE_URL}/api/v1/alerts/${ALERT_ID}" >/tmp/e2e_status.json || true

echo "-- Trigger workflow (manual)"
curl -sS -X POST "${WORKFLOW_URL}/api/v1/workflows/execute" \
  -H "Content-Type: application/json" \
  -d "{\"workflow_id\":\"alert-processing\",\"input_data\":{\"alert_id\":\"${ALERT_ID}\"}}" \
  >/tmp/e2e_workflow.json || true

echo "-- Trigger automation (manual)"
curl -sS -X POST "${AUTOMATION_URL}/api/v1/playbooks/execute" \
  -H "Content-Type: application/json" \
  -d "{\"playbook_id\":\"malware-response\",\"alert_id\":\"${ALERT_ID}\",\"input_data\":{}}" \
  >/tmp/e2e_automation.json || true

echo "-- Query similarity search"
curl -sS -X POST "${SIMILARITY_URL}/api/v1/search" \
  -H "Content-Type: application/json" \
  -d "{\"query_text\":\"malware alert from 45.33.32.156\",\"top_k\":3,\"min_similarity\":0.1}" \
  >/tmp/e2e_similarity.json || true

echo "-- Analytics dashboard"
curl -sS "${ANALYTICS_URL}/api/v1/dashboard" >/tmp/e2e_dashboard.json || true

echo "-- Generate daily report"
curl -sS -X POST "${REPORTING_URL}/api/v1/reports/generate" \
  -H "Content-Type: application/json" \
  -d "{\"report_type\":\"daily_summary\"}" \
  >/tmp/e2e_report.json || true

echo "== Structured verification =="
BASE_URL="${BASE_URL}" WORKFLOW_URL="${WORKFLOW_URL}" AUTOMATION_URL="${AUTOMATION_URL}" \
SIMILARITY_URL="${SIMILARITY_URL}" ANALYTICS_URL="${ANALYTICS_URL}" REPORTING_URL="${REPORTING_URL}" \
python3 scripts/e2e_verify.py || true

echo "Done. Outputs:"
ls -1 /tmp/e2e_*.json || true
