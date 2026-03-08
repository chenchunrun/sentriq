#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PGUSER="triage_user"
PGDATABASE="security_triage"
AUTOMATION_URL="${AUTOMATION_URL:-http://127.0.0.1:9009}"

run_psql() {
  docker-compose exec -T postgres psql -v ON_ERROR_STOP=1 -U "$PGUSER" -d "$PGDATABASE" "$@"
}

echo "Seeding demo alerts, triage data, context, and threat intel..."

run_psql <<'SQL'
BEGIN;

DELETE FROM playbook_executions
WHERE trigger_alert_id LIKE 'DEMO-%';

DELETE FROM alert_context
WHERE alert_id LIKE 'DEMO-%';

DELETE FROM triage_results
WHERE alert_id LIKE 'DEMO-%';

DELETE FROM alerts
WHERE alert_id LIKE 'DEMO-%';

DELETE FROM threat_intel
WHERE ioc IN (
  '185.220.101.45',
  '198.51.100.77',
  'hxxp://update-microsoft-security[.]com/login',
  '5f4dcc3b5aa765d61d8327deb882cf99',
  'suspicious-mail-gateway.example'
);

INSERT INTO alerts (
  alert_id, received_at, alert_type, severity, title, description,
  source_ip, destination_ip, source_port, destination_port, protocol,
  user_name, asset_id, file_hash, file_name, url, dns_query, raw_data,
  status, assigned_to, created_at, updated_at
) VALUES
(
  'DEMO-MAL-001', NOW() - INTERVAL '35 minutes', 'malware', 'critical',
  'Ransomware beacon detected on finance workstation',
  'Endpoint telemetry detected ransomware staging activity and outbound C2 traffic from FIN-WS-042.',
  '10.20.14.55', '185.220.101.45', 51514, 443, 'tcp',
  'alice.wang', 'FIN-WS-042', '5f4dcc3b5aa765d61d8327deb882cf99', 'invoice_Q1.xlsm',
  'https://update-microsoft-security.example/payload', NULL,
  jsonb_build_object(
    'source', 'crowdstrike',
    'sensor', 'falcon',
    'target_ip', '10.20.14.55',
    'hostname', 'FIN-WS-042',
    'business_unit', 'finance'
  ),
  'investigating', 'analyst', NOW() - INTERVAL '35 minutes', NOW() - INTERVAL '20 minutes'
),
(
  'DEMO-PHI-001', NOW() - INTERVAL '2 hours', 'phishing', 'high',
  'Credential phishing email targeting payroll',
  'Secure email gateway flagged a credential-harvesting message sent to payroll staff.',
  '198.51.100.77', '10.20.30.25', 587, 25, 'smtp',
  'bob.chen', 'MAIL-GW-01', NULL, NULL,
  'https://update-microsoft-security.example/login', 'update-microsoft-security.example',
  jsonb_build_object(
    'source', 'proofpoint',
    'sender_email', 'security-update@corp-mail-support.com',
    'email_subject', 'Action required: payroll mailbox validation',
    'recipient_count', 14
  ),
  'pending', 'analyst', NOW() - INTERVAL '2 hours', NOW() - INTERVAL '90 minutes'
),
(
  'DEMO-BRUTE-001', NOW() - INTERVAL '4 hours', 'brute_force', 'medium',
  'VPN brute-force activity against contractor account',
  'Multiple failed VPN logins followed by a successful login from an unusual ASN.',
  '203.0.113.44', '10.20.1.10', 49211, 443, 'tcp',
  'contractor.li', 'VPN-EDGE-01', NULL, NULL,
  NULL, NULL,
  jsonb_build_object(
    'source', 'okta',
    'failed_attempts', 28,
    'success_after_failures', true
  ),
  'analyzed', 'admin', NOW() - INTERVAL '4 hours', NOW() - INTERVAL '3 hours'
),
(
  'DEMO-EXF-001', NOW() - INTERVAL '6 hours', 'data_exfiltration', 'critical',
  'Unusual bulk upload to external storage',
  'DLP detected 3.4 GB of finance documents uploaded to a personal cloud storage tenant.',
  '10.20.22.18', '104.18.12.220', 53112, 443, 'tcp',
  'carol.zhou', 'FIN-LT-009', NULL, NULL,
  'https://dropbox.example/upload', NULL,
  jsonb_build_object(
    'source', 'dlp',
    'bytes_transferred', 3650722201,
    'file_count', 248
  ),
  'investigating', 'admin', NOW() - INTERVAL '6 hours', NOW() - INTERVAL '5 hours'
),
(
  'DEMO-ANOM-001', NOW() - INTERVAL '8 hours', 'anomaly', 'low',
  'Late-night administrative login anomaly',
  'UEBA flagged an after-hours login from a known admin workstation with low risk.',
  '10.20.1.44', '10.20.1.20', 54111, 3389, 'tcp',
  'dba.sun', 'DB-ADMIN-01', NULL, NULL,
  NULL, NULL,
  jsonb_build_object(
    'source', 'ueba',
    'baseline_deviation', 0.18
  ),
  'resolved', 'admin', NOW() - INTERVAL '8 hours', NOW() - INTERVAL '7 hours'
),
(
  'DEMO-POL-001', NOW() - INTERVAL '11 hours', 'policy_violation', 'medium',
  'Unauthorized USB storage mounted on workstation',
  'EDR detected an unapproved removable storage device mounted on ENG-WS-101.',
  '10.20.44.101', NULL, NULL, NULL, 'usb',
  'erin.liu', 'ENG-WS-101', NULL, NULL,
  NULL, NULL,
  jsonb_build_object(
    'source', 'sentinelone',
    'device_serial', 'USB-ACME-99231'
  ),
  'pending', 'analyst', NOW() - INTERVAL '11 hours', NOW() - INTERVAL '10 hours'
),
(
  'DEMO-OTHER-001', NOW() - INTERVAL '15 hours', 'other', 'info',
  'Threat intel indicator matched historical IOC list',
  'A low-confidence historical IOC match was observed in DNS telemetry.',
  '10.20.11.22', '192.0.2.91', 55322, 53, 'udp',
  'svc-dns', 'DNS-RES-01', NULL, NULL,
  NULL, 'suspicious-mail-gateway.example',
  jsonb_build_object(
    'source', 'dns-analytics',
    'query_count', 3
  ),
  'suppressed', 'analyst', NOW() - INTERVAL '15 hours', NOW() - INTERVAL '14 hours'
),
(
  'DEMO-MAL-002', NOW() - INTERVAL '20 hours', 'malware', 'high',
  'Suspicious loader dropped in HR laptop temp directory',
  'EDR prevented execution of a suspicious loader dropped from an archive opened by HR.',
  '10.20.18.77', '45.9.148.33', 49811, 80, 'tcp',
  'frank.he', 'HR-LT-014', '44d88612fea8a8f36de82e1278abb02f', 'benefits_update.scr',
  'http://cdn-benefits-update.example/loader', NULL,
  jsonb_build_object(
    'source', 'defender',
    'target_ip', '10.20.18.77',
    'hostname', 'HR-LT-014'
  ),
  'analyzing', 'analyst', NOW() - INTERVAL '20 hours', NOW() - INTERVAL '19 hours'
);

INSERT INTO alert_context (alert_id, context_type, context_data, source, confidence_score, created_at, updated_at) VALUES
('DEMO-MAL-001', 'asset', jsonb_build_object('hostname', 'FIN-WS-042', 'criticality', 'critical', 'owner', 'alice.wang', 'location', 'shanghai-hq'), 'cmdb', 0.97, NOW() - INTERVAL '30 minutes', NOW() - INTERVAL '30 minutes'),
('DEMO-MAL-001', 'network', jsonb_build_object('egress_blocked', false, 'proxy_seen', false, 'edr_isolation_ready', true), 'ndr', 0.93, NOW() - INTERVAL '29 minutes', NOW() - INTERVAL '29 minutes'),
('DEMO-PHI-001', 'user', jsonb_build_object('department', 'payroll', 'vip', true, 'recent_phishing_training_days', 18), 'iam', 0.88, NOW() - INTERVAL '100 minutes', NOW() - INTERVAL '100 minutes'),
('DEMO-EXF-001', 'historical', jsonb_build_object('previous_dlp_events', 0, 'similar_alerts_30d', 1), 'analytics', 0.84, NOW() - INTERVAL '5 hours', NOW() - INTERVAL '5 hours'),
('DEMO-BRUTE-001', 'network', jsonb_build_object('asn', 'AS4134', 'country', 'RU', 'tor_exit', false), 'geoip', 0.72, NOW() - INTERVAL '3 hours', NOW() - INTERVAL '3 hours');

INSERT INTO threat_intel (
  ioc, ioc_type, threat_level, confidence_score, source, description,
  first_seen, last_seen, detection_rate, positives, total, tags, raw_data, created_at, updated_at
) VALUES
(
  '185.220.101.45', 'ip', 'critical', 0.96, 'virustotal',
  'Known command-and-control endpoint associated with commodity ransomware crews.',
  NOW() - INTERVAL '14 days', NOW() - INTERVAL '2 hours', 92.00, 69, 75,
  ARRAY['c2', 'ransomware', 'tor-exit'],
  jsonb_build_object('asn', 'AS60781', 'country', 'DE'),
  NOW() - INTERVAL '2 hours', NOW() - INTERVAL '2 hours'
),
(
  '198.51.100.77', 'ip', 'high', 0.83, 'abuseipdb',
  'SMTP source with repeated phishing and credential harvesting reports.',
  NOW() - INTERVAL '8 days', NOW() - INTERVAL '4 hours', 78.00, 31, 40,
  ARRAY['phishing', 'smtp-abuse'],
  jsonb_build_object('abuse_confidence', 87),
  NOW() - INTERVAL '4 hours', NOW() - INTERVAL '4 hours'
),
(
  'https://update-microsoft-security.example/login', 'url', 'high', 0.89, 'otx',
  'Credential harvesting landing page spoofing Microsoft security notices.',
  NOW() - INTERVAL '5 days', NOW() - INTERVAL '90 minutes', 81.00, 17, 21,
  ARRAY['phishing', 'credential-theft'],
  jsonb_build_object('pulse', 'corp-spoof-landing-pages'),
  NOW() - INTERVAL '90 minutes', NOW() - INTERVAL '90 minutes'
),
(
  '5f4dcc3b5aa765d61d8327deb882cf99', 'hash', 'critical', 0.94, 'internal-sandbox',
  'Sandbox observed encryption activity and registry persistence.',
  NOW() - INTERVAL '3 days', NOW() - INTERVAL '40 minutes', 100.00, 12, 12,
  ARRAY['ransomware', 'loader'],
  jsonb_build_object('family', 'LockBit-test'),
  NOW() - INTERVAL '40 minutes', NOW() - INTERVAL '40 minutes'
),
(
  'suspicious-mail-gateway.example', 'domain', 'medium', 0.62, 'internal-ti',
  'Historical match with low-volume suspicious mail routing domain.',
  NOW() - INTERVAL '21 days', NOW() - INTERVAL '15 hours', 25.00, 1, 4,
  ARRAY['historical-ioc'],
  jsonb_build_object('source_list', 'watchlist'),
  NOW() - INTERVAL '15 hours', NOW() - INTERVAL '15 hours'
)
ON CONFLICT (ioc, ioc_type) DO UPDATE SET
  threat_level = EXCLUDED.threat_level,
  confidence_score = EXCLUDED.confidence_score,
  source = EXCLUDED.source,
  description = EXCLUDED.description,
  first_seen = EXCLUDED.first_seen,
  last_seen = EXCLUDED.last_seen,
  detection_rate = EXCLUDED.detection_rate,
  positives = EXCLUDED.positives,
  total = EXCLUDED.total,
  tags = EXCLUDED.tags,
  raw_data = EXCLUDED.raw_data,
  updated_at = NOW();

INSERT INTO triage_results (
  alert_id, risk_score, risk_level, confidence_score, analysis_result, recommended_actions,
  requires_human_review, human_reviewer, human_review_notes, reviewed_at, created_at, updated_at
) VALUES
(
  'DEMO-MAL-001', 96, 'critical', 0.97,
  'High-confidence ransomware precursor behavior observed with known malicious hash and active outbound beaconing.',
  '["Immediately isolate host","Collect volatile memory","Open P1 incident","Block IOC on perimeter"]',
  true, 'admin', 'Escalated to IR lead due to finance asset criticality.', NOW() - INTERVAL '18 minutes',
  NOW() - INTERVAL '24 minutes', NOW() - INTERVAL '18 minutes'
),
(
  'DEMO-PHI-001', 82, 'high', 0.91,
  'Phishing lure is consistent with current credential harvesting campaign; recipient set includes privileged finance users.',
  '["Block sender","Purge matching emails","Reset exposed credentials","Notify payroll manager"]',
  true, 'analyst', 'Validated that message reached 14 inboxes before quarantine.', NOW() - INTERVAL '75 minutes',
  NOW() - INTERVAL '84 minutes', NOW() - INTERVAL '75 minutes'
),
(
  'DEMO-BRUTE-001', 61, 'medium', 0.78,
  'Brute-force pattern likely password spraying; follow-up required to validate successful session activity.',
  '["Force password reset","Review MFA logs","Temporarily restrict account"]',
  false, NULL, NULL, NULL,
  NOW() - INTERVAL '190 minutes', NOW() - INTERVAL '190 minutes'
),
(
  'DEMO-EXF-001', 93, 'critical', 0.88,
  'Bulk outbound transfer volume and finance asset context indicate likely exfiltration requiring immediate containment.',
  '["Suspend cloud sync session","Notify legal","Capture endpoint image"]',
  true, 'admin', 'Legal hold requested before endpoint shutdown.', NOW() - INTERVAL '280 minutes',
  NOW() - INTERVAL '290 minutes', NOW() - INTERVAL '280 minutes'
),
(
  'DEMO-ANOM-001', 18, 'low', 0.66,
  'After-hours login matched historical admin pattern; no corroborating malicious signals found.',
  '["Document deviation","No containment required"]',
  false, 'admin', 'Benign maintenance window confirmed.', NOW() - INTERVAL '7 hours',
  NOW() - INTERVAL '7 hours 10 minutes', NOW() - INTERVAL '7 hours'
),
(
  'DEMO-POL-001', 47, 'medium', 0.74,
  'USB device usage violates policy and merits endpoint follow-up, but there is no confirmed malware execution.',
  '["Interview user","Scan removable media","Review DLP controls"]',
  false, NULL, NULL, NULL,
  NOW() - INTERVAL '10 hours', NOW() - INTERVAL '10 hours'
),
(
  'DEMO-OTHER-001', 9, 'info', 0.42,
  'Single low-confidence DNS match with no additional malicious activity; acceptable to suppress after watchlist check.',
  '["Keep IOC on watchlist"]',
  false, 'analyst', 'Suppressed after confirming no related alerts in 30 days.', NOW() - INTERVAL '14 hours',
  NOW() - INTERVAL '14 hours 20 minutes', NOW() - INTERVAL '14 hours'
),
(
  'DEMO-MAL-002', 77, 'high', 0.85,
  'Prevented execution reduced impact, but the dropped loader and outbound HTTP callback still warrant containment review.',
  '["Quarantine file","Collect full disk timeline","Hunt related hosts"]',
  true, NULL, NULL, NULL,
  NOW() - INTERVAL '19 hours', NOW() - INTERVAL '19 hours'
)
ON CONFLICT (alert_id) DO UPDATE SET
  risk_score = EXCLUDED.risk_score,
  risk_level = EXCLUDED.risk_level,
  confidence_score = EXCLUDED.confidence_score,
  analysis_result = EXCLUDED.analysis_result,
  recommended_actions = EXCLUDED.recommended_actions,
  requires_human_review = EXCLUDED.requires_human_review,
  human_reviewer = EXCLUDED.human_reviewer,
  human_review_notes = EXCLUDED.human_review_notes,
  reviewed_at = EXCLUDED.reviewed_at,
  updated_at = EXCLUDED.updated_at;

COMMIT;
SQL

echo "Triggering runnable automation playbooks..."

malware_exec="$(curl -sS -X POST "$AUTOMATION_URL/api/v1/playbooks/execute" \
  -H 'Content-Type: application/json' \
  -d '{
    "playbook_id": "malware-response",
    "alert_id": "DEMO-MAL-001",
    "input_data": {
      "alert_id": "DEMO-MAL-001",
      "target_ip": "10.20.14.55",
      "file_hash": "5f4dcc3b5aa765d61d8327deb882cf99",
      "hostname": "FIN-WS-042"
    }
  }')"

phishing_exec="$(curl -sS -X POST "$AUTOMATION_URL/api/v1/playbooks/execute" \
  -H 'Content-Type: application/json' \
  -d '{
    "playbook_id": "phishing-response",
    "alert_id": "DEMO-PHI-001",
    "input_data": {
      "alert_id": "DEMO-PHI-001",
      "sender_email": "security-update@corp-mail-support.com",
      "email_subject": "Action required: payroll mailbox validation"
    }
  }')"

echo "Waiting for automation executions to finish..."
sleep 4

echo
echo "Demo data ready."
echo "Created alerts:"
run_psql -c "SELECT alert_id, alert_type, severity, status, title FROM alerts WHERE alert_id LIKE 'DEMO-%' ORDER BY received_at DESC;"
echo
echo "Latest triage results:"
run_psql -c "SELECT alert_id, risk_score, risk_level, confidence_score, requires_human_review FROM triage_results WHERE alert_id LIKE 'DEMO-%' ORDER BY updated_at DESC;"
echo
echo "Latest automation executions:"
run_psql -c "SELECT execution_id, playbook_id, trigger_alert_id, status, approval_status, current_action FROM playbook_executions WHERE trigger_alert_id LIKE 'DEMO-%' ORDER BY started_at DESC;"
echo
echo "Automation API responses:"
echo "$malware_exec"
echo "$phishing_exec"
