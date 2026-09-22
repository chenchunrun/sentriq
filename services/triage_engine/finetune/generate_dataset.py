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

"""Security triage fine-tuning dataset generator.

Produces (state, questions, gold) cases in the official laya typed-decisions
format (same schema as LocalLLaMA/typed-decisions rows used by the upstream
fine-tune notebook):

    {"id": ..., "workflow": ..., "state": <json str>, "questions": <json str>,
     "gold": <json str>}

States are rendered through the engine's REAL compressor so the fine-tuned
model sees production-shaped inputs. Gold answers are soft probability
distributions (never one-hot) derived deterministically from scenario
semantics, and the `route` gold always respects the hard-gate policy
(e.g. an authorized scan against a critical asset still routes HUMAN_REVIEW).
"""

import argparse
import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from triage_engine.core.compressor import compress
from triage_engine.core.context import AlertContext
from triage_engine.core.registry import registry

HOSTS_CRITICAL = ["SRV-PROD-001", "SRV-PROD-002"]      # critical assets in repo CMDB
HOSTS_REGULAR = ["WS-050", "WS-099", "WS-120"]
USERS = ["john.doe@example.com", "alice.smith@example.com", "user123"]
EXT_IPS_BAD = ["45.33.32.156", "185.220.101.7", "91.240.118.172"]
EXT_IPS_OK = ["104.16.132.229", "151.101.1.69"]
INTERNAL = ["10.0.1.55", "10.0.2.31", "192.168.1.101"]


def _jitter(rng, value, lo=0.0, hi=1.0, amount=0.03):
    return round(min(hi, max(lo, value + rng.uniform(-amount, amount))), 3)


def _score_dist(level, weight=0.7, n=5):
    """Soft distribution over score levels peaked at `level`."""
    dist = [0.05] * n
    dist[level] = weight
    rest = 1.0 - weight - 0.05 * (n - 1)
    for delta, share in ((-1, rest * 0.6), (1, rest * 0.4)):
        idx = level + delta
        if 0 <= idx < n:
            dist[idx] += share
    total = sum(dist)
    return [round(v / total, 3) for v in dist]


def _choice_dist(gold, options, weight=0.8):
    dist = {o: round((1.0 - weight) / (len(options) - 1), 3) for o in options}
    dist[gold] = weight
    return dist


ROUTES = ["FAST_CLOSE", "FAST_QUEUE", "DEEP_INVESTIGATE", "URGENT_ESCALATE", "HUMAN_REVIEW"]
CONTAINMENTS = ["NOT_CONTAINED", "PARTIALLY_CONTAINED", "CONTAINED", "UNKNOWN"]


def scenario_cases(rng):
    """Yield (raw_alert_builder, gold_answers) for every scenario family."""
    ts = lambda h, m: f"2026-09-{20 + rng.randrange(1, 8):02d}T{h:02d}:{m:02d}:00Z"

    # ---------------- benign families ----------------
    def authorized_scan():
        host = rng.choice(HOSTS_REGULAR)
        return (
            dict(alert_id=f"ALT-SCN-{rng.randrange(10**6)}", timestamp=ts(10, 15), alert_type="scan",
                 source="nessus", severity=rng.choice(["info", "low"]),
                 description="Scheduled vulnerability scan from approved scanner appliance",
                 source_ip=rng.choice(INTERNAL), target_ip=f"10.0.9.{rng.randrange(40, 90)}",
                 asset_id=host, user_id="scanner.service@example.com",
                 active_change=True, similar_alerts_30d=rng.randrange(4, 12),
                 historical_false_positive_rate=0.97),
            dict(malicious=_jitter(rng, 0.03), authorized=_jitter(rng, 0.97),
                 evidence_strength=_score_dist(3), novelty=_score_dist(0),
                 business_impact=_score_dist(1), containment_state="UNKNOWN",
                 investigation_need=_jitter(rng, 0.05), route="FAST_CLOSE"),
        )

    def approved_change():
        host = rng.choice(HOSTS_REGULAR + HOSTS_CRITICAL[:1])
        critical = host in HOSTS_CRITICAL
        gold_route = "HUMAN_REVIEW" if critical else "FAST_CLOSE"   # hard gate: critical asset
        return (
            dict(alert_id=f"ALT-CHG-{rng.randrange(10**6)}", timestamp=ts(14, 30), alert_type="policy_violation",
                 source="SIEM", severity="low",
                 description="Configuration change detected on host covered by active change record",
                 source_ip=rng.choice(INTERNAL), target_ip=f"10.0.9.{rng.randrange(40, 90)}",
                 asset_id=host, user_id=rng.choice(USERS),
                 active_change=True, similar_alerts_30d=rng.randrange(2, 6)),
            dict(malicious=_jitter(rng, 0.04), authorized=_jitter(rng, 0.96),
                 evidence_strength=_score_dist(3), novelty=_score_dist(1),
                 business_impact=_score_dist(4 if critical else 2),
                 containment_state="UNKNOWN", investigation_need=_jitter(rng, 0.06),
                 route=gold_route),
        )

    def routine_ops():
        return (
            dict(alert_id=f"ALT-OPS-{rng.randrange(10**6)}", timestamp=ts(3, 0), alert_type="anomaly",
                 source="HIDS", severity="info",
                 description="Backup job spawned expected batch processes during maintenance window",
                 source_ip=rng.choice(INTERNAL), target_ip=f"10.0.9.{rng.randrange(40, 90)}",
                 asset_id=rng.choice(HOSTS_REGULAR), user_id="svc-backup",
                 process_tree=["backup.exe", "7z.exe"],
                 active_change=False, similar_alerts_30d=rng.randrange(6, 15)),
            dict(malicious=_jitter(rng, 0.02), authorized=_jitter(rng, 0.98),
                 evidence_strength=_score_dist(3), novelty=_score_dist(0),
                 business_impact=_score_dist(1), containment_state="UNKNOWN",
                 investigation_need=_jitter(rng, 0.03), route="FAST_CLOSE"),
        )

    def pentest_exercise():
        return (
            dict(alert_id=f"ALT-PENT-{rng.randrange(10**6)}", timestamp=ts(16, 45), alert_type="brute_force",
                 source="SIEM", severity="medium",
                 description="Credential testing against lab segment - authorized red team exercise window",
                 source_ip=rng.choice(INTERNAL), target_ip=f"10.0.9.{rng.randrange(40, 90)}",
                 asset_id=rng.choice(HOSTS_REGULAR), user_id="redteam.service@example.com",
                 similar_alerts_30d=rng.randrange(2, 6)),
            dict(malicious=_jitter(rng, 0.15, amount=0.05), authorized=_jitter(rng, 0.88),
                 evidence_strength=_score_dist(2), novelty=_score_dist(1),
                 business_impact=_score_dist(1), containment_state="UNKNOWN",
                 investigation_need=_jitter(rng, 0.35, amount=0.1), route="HUMAN_REVIEW"),
        )

    def false_positive():
        return (
            dict(alert_id=f"ALT-FP-{rng.randrange(10**6)}", timestamp=ts(11, 20), alert_type="malware",
                 source="EDR", severity="medium",
                 description="Security tool self-test triggered malware signature match on isolated test host",
                 source_ip=rng.choice(INTERNAL), target_ip=f"10.0.9.{rng.randrange(40, 90)}",
                 asset_id=rng.choice(HOSTS_REGULAR), user_id="edr-test",
                 file_hash="a" * 64, similar_alerts_30d=rng.randrange(8, 20),
                 historical_false_positive_rate=0.99, edr_blocked=True, process_killed=True),
            dict(malicious=_jitter(rng, 0.03), authorized=_jitter(rng, 0.9, amount=0.05),
                 evidence_strength=_score_dist(2), novelty=_score_dist(0),
                 business_impact=_score_dist(0), containment_state="CONTAINED",
                 investigation_need=_jitter(rng, 0.05), route="FAST_CLOSE"),
        )

    # ---------------- malicious families ----------------
    def contained_malware():
        return (
            dict(alert_id=f"ALT-MAL-{rng.randrange(10**6)}", timestamp=ts(9, 10), alert_type="malware",
                 source="EDR", severity="high",
                 description="Known trojan hash executed and immediately quarantined by EDR",
                 source_ip=rng.choice(EXT_IPS_OK), target_ip=f"10.0.9.{rng.randrange(40, 90)}",
                 asset_id=rng.choice(HOSTS_REGULAR), user_id=rng.choice(USERS),
                 file_hash="b" * 64, edr_blocked=True, process_killed=True,
                 similar_alerts_30d=rng.randrange(3, 8)),
            dict(malicious=_jitter(rng, 0.9), authorized=_jitter(rng, 0.03),
                 evidence_strength=_score_dist(4), novelty=_score_dist(1),
                 business_impact=_score_dist(1), containment_state="CONTAINED",
                 investigation_need=_jitter(rng, 0.3, amount=0.1), route="FAST_QUEUE"),
        )

    def credential_theft():
        host = rng.choice(HOSTS_CRITICAL)
        return (
            dict(alert_id=f"ALT-CRED-{rng.randrange(10**6)}", timestamp=ts(2, 7), alert_type="malware",
                 source="EDR", rule_id="T1003-LSASS", severity="high",
                 description="powershell spawned rundll32 which accessed lsass.exe memory (credential dumping)",
                 source_ip=rng.choice(EXT_IPS_BAD), target_ip="10.0.1.10", asset_id=host,
                 user_id=rng.choice(USERS),
                 process_tree=["powershell.exe", "rundll32.exe", "lsass.exe"],
                 similar_alerts_30d=0),
            dict(malicious=_jitter(rng, 0.94), authorized=_jitter(rng, 0.02),
                 evidence_strength=_score_dist(4), novelty=_score_dist(3),
                 business_impact=_score_dist(4), containment_state="NOT_CONTAINED",
                 investigation_need=_jitter(rng, 0.92), route="URGENT_ESCALATE"),
        )

    def lateral_movement():
        return (
            dict(alert_id=f"ALT-LAT-{rng.randrange(10**6)}", timestamp=ts(1, 40), alert_type="anomaly",
                 source="NDR", severity="high",
                 description="Suspicious lateral movement via SMB to multiple hosts from workstation",
                 source_ip=f"10.0.1.{rng.randrange(50, 99)}", target_ip=f"10.0.2.{rng.randrange(10, 40)}",
                 asset_id=rng.choice(HOSTS_REGULAR), user_id=rng.choice(USERS),
                 similar_alerts_30d=0),
            dict(malicious=_jitter(rng, 0.88), authorized=_jitter(rng, 0.05),
                 evidence_strength=_score_dist(3), novelty=_score_dist(3),
                 business_impact=_score_dist(3), containment_state="NOT_CONTAINED",
                 investigation_need=_jitter(rng, 0.9), route="DEEP_INVESTIGATE"),
        )

    def ransomware():
        return (
            dict(alert_id=f"ALT-RAN-{rng.randrange(10**6)}", timestamp=ts(4, 12), alert_type="ransomware",
                 source="EDR", severity="critical",
                 description="Mass file encryption activity with ransom note dropped on file servers",
                 source_ip=rng.choice(EXT_IPS_BAD), target_ip="10.0.1.20", asset_id="SRV-PROD-002",
                 user_id=rng.choice(USERS), similar_alerts_30d=0),
            dict(malicious=_jitter(rng, 0.97), authorized=_jitter(rng, 0.01),
                 evidence_strength=_score_dist(4), novelty=_score_dist(4),
                 business_impact=_score_dist(4), containment_state="NOT_CONTAINED",
                 investigation_need=_jitter(rng, 0.97), route="URGENT_ESCALATE"),
        )

    def data_exfiltration():
        return (
            dict(alert_id=f"ALT-EXF-{rng.randrange(10**6)}", timestamp=ts(23, 30), alert_type="data_exfiltration",
                 source="DLP", severity="critical",
                 description="Large outbound data transfer to unknown external storage over TLS",
                 source_ip=f"10.0.1.{rng.randrange(50, 99)}", target_ip=rng.choice(EXT_IPS_BAD),
                 asset_id=rng.choice(HOSTS_CRITICAL), user_id=rng.choice(USERS),
                 similar_alerts_30d=rng.randrange(0, 2)),
            dict(malicious=_jitter(rng, 0.92), authorized=_jitter(rng, 0.04),
                 evidence_strength=_score_dist(3), novelty=_score_dist(3),
                 business_impact=_score_dist(4), containment_state="NOT_CONTAINED",
                 investigation_need=_jitter(rng, 0.93), route="URGENT_ESCALATE"),
        )

    def brute_force():
        contained = rng.random() < 0.5
        return (
            dict(alert_id=f"ALT-BF-{rng.randrange(10**6)}", timestamp=ts(5, 55), alert_type="brute_force",
                 source="SIEM", severity="medium",
                 description="Repeated failed SSH logins against internet-exposed host" + (
                     " - source blocked by firewall" if contained else ""),
                 source_ip=rng.choice(EXT_IPS_BAD), target_ip=f"10.0.9.{rng.randrange(40, 90)}",
                 asset_id=rng.choice(HOSTS_REGULAR), user_id="unknown",
                 edr_blocked=contained, similar_alerts_30d=rng.randrange(1, 5)),
            dict(malicious=_jitter(rng, 0.75), authorized=_jitter(rng, 0.1),
                 evidence_strength=_score_dist(3), novelty=_score_dist(1),
                 business_impact=_score_dist(2),
                 containment_state="CONTAINED" if contained else "NOT_CONTAINED",
                 investigation_need=_jitter(rng, 0.5 if contained else 0.8, amount=0.1),
                 route="FAST_QUEUE" if contained else "DEEP_INVESTIGATE"),
        )

    def phishing():
        return (
            dict(alert_id=f"ALT-PHS-{rng.randrange(10**6)}", timestamp=ts(8, 5), alert_type="phishing",
                 source="mail-gw", severity="medium",
                 description="Credential phishing link clicked by user, submission to fake portal blocked",
                 source_ip=rng.choice(EXT_IPS_BAD), target_ip=f"10.0.9.{rng.randrange(40, 90)}",
                 asset_id=rng.choice(HOSTS_REGULAR), user_id=rng.choice(USERS),
                 domain="secure-login-portal.example", similar_alerts_30d=rng.randrange(2, 7)),
            dict(malicious=_jitter(rng, 0.85), authorized=_jitter(rng, 0.05),
                 evidence_strength=_score_dist(3), novelty=_score_dist(1),
                 business_impact=_score_dist(2), containment_state="PARTIALLY_CONTAINED",
                 investigation_need=_jitter(rng, 0.7, amount=0.1), route="DEEP_INVESTIGATE"),
        )

    def dos_attack():
        contained = rng.random() < 0.4
        return (
            dict(alert_id=f"ALT-DOS-{rng.randrange(10**6)}", timestamp=ts(17, 25), alert_type="denial_of_service",
                 source="WAF", severity="high",
                 description="Volumetric SYN flood against public service" + (" - mitigated by scrubbing" if contained else ""),
                 source_ip=rng.choice(EXT_IPS_BAD), target_ip="10.0.1.20", asset_id="SRV-PROD-002",
                 user_id="unknown", edr_blocked=contained, similar_alerts_30d=rng.randrange(0, 3)),
            dict(malicious=_jitter(rng, 0.8), authorized=_jitter(rng, 0.05),
                 evidence_strength=_score_dist(3), novelty=_score_dist(2),
                 business_impact=_score_dist(3),
                 containment_state="CONTAINED" if contained else "NOT_CONTAINED",
                 investigation_need=_jitter(rng, 0.55, amount=0.15),
                 route="FAST_QUEUE" if contained else "DEEP_INVESTIGATE"),
        )

    def unknown_anomaly():
        return (
            dict(alert_id=f"ALT-UNK-{rng.randrange(10**6)}", timestamp=ts(13, 12), alert_type="anomaly",
                 source="UEBA", severity="medium",
                 description="Unusual service account behavior pattern with no matching known activity profile",
                 source_ip=f"10.0.1.{rng.randrange(50, 99)}", target_ip=f"10.0.9.{rng.randrange(40, 90)}",
                 asset_id=rng.choice(HOSTS_REGULAR + HOSTS_CRITICAL[:1]), user_id="svc-integration",
                 similar_alerts_30d=0),
            dict(malicious=_jitter(rng, 0.45, amount=0.15), authorized=_jitter(rng, 0.4, amount=0.15),
                 evidence_strength=_score_dist(1), novelty=_score_dist(3),
                 business_impact=_score_dist(2), containment_state="UNKNOWN",
                 investigation_need=_jitter(rng, 0.85), route="HUMAN_REVIEW"),
        )

    families = [authorized_scan, approved_change, routine_ops, pentest_exercise, false_positive,
                contained_malware, credential_theft, lateral_movement, ransomware,
                data_exfiltration, brute_force, phishing, dos_attack, unknown_anomaly]
    weights = [10, 9, 8, 4, 6, 9, 9, 8, 6, 6, 8, 8, 6, 7]
    while True:
        family = rng.choices(families, weights=weights, k=1)[0]
        yield family()


def build_case(case_id, raw_alert, gold, questions):
    ctx = AlertContext.build(raw_alert)
    state = compress(ctx, raw_alert)
    gold_out = {}
    for qid, spec in questions.items():
        value = gold[qid]
        if spec["type"] == "noul":
            p = float(value)
            gold_out[qid] = {"probabilities": {"false": round(1 - p, 3), "true": p}}
        elif spec["type"] == "score":
            dist = value if isinstance(value, list) else _score_dist(int(value))
            gold_out[qid] = {"probabilities": {str(i): p for i, p in enumerate(dist)}}
        else:  # choice
            options = spec["choices"] if "choices" in spec else list(spec["criteria"].keys())
            gold_out[qid] = {"probabilities": _choice_dist(value, options)}
    return {
        "id": case_id,
        "workflow": f"security_triage/{raw_alert['alert_type']}",
        "state": json.dumps(state.to_text()),
        "questions": json.dumps(questions),
        "gold": json.dumps(gold_out),
        "_raw_alert": raw_alert,   # kept for the routing-delta evaluation
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--train", type=int, default=700)
    parser.add_argument("--eval", type=int, default=160)
    parser.add_argument("--out", default=str(Path(__file__).resolve().parent / "data"))
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    rng = random.Random(args.seed)
    questions = {
        name: {"type": spec["type"], "instructions": spec["instructions"], **(
            {"criteria": spec["criteria"]} if "criteria" in spec else {})}
        for name, spec in registry.questions.items()
    }

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    gen = scenario_cases(rng)
    for split, count in (("train", args.train), ("eval", args.eval)):
        cases = [build_case(f"{split[:2].upper()}-{i:05d}", *next(gen), questions)
                 for i in range(count)]
        path = out_dir / f"{split}.jsonl"
        with open(path, "w", encoding="utf-8") as fh:
            for case in cases:
                fh.write(json.dumps(case, ensure_ascii=False) + "\n")
        print(f"{split}: {len(cases)} cases ({len(cases) * len(questions)} decisions) -> {path}")


if __name__ == "__main__":
    main()
