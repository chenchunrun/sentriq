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

"""Build a laya fine-tuning dataset from REAL NGSOC alert exports.

Labels come from NGSOC's own intelligent triage tag (`triageResult` /
智能分诊标签):
    有效告警:攻击成功 / 攻击失败 / 结果未知   -> malicious, graded
    隐患:异常行为 / 脆弱性                   -> gray zone
    无效告警:业务触发/数据缺失/其他/规则误报  -> benign / FP
    需人工研判                               -> human review

CRITICAL: triageResult is the LABEL and is never included in the state text -
only observable alert features (rule, category, IPs, domain, IOC, direction,
frequency, sensor attack result) are rendered, in the same textual format as
the engine's CompressedState so training matches inference.

States are Chinese -> fine-tune the MULTILINGUAL checkpoint (that is what
SecurityLayaRouter selects for Chinese states).

Usage:
    PYTHONPATH=services venv/bin/python services/triage_engine/finetune/generate_ngsoc_dataset.py \
        --ngsoc-dir ~/Downloads/NGSOC狩猎
"""

import argparse
import json
import random
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

NGSOC_DIR = Path.home() / "Downloads" / "NGSOC狩猎"


class HunterContext:
    """Observable context from the hunter platform: ATT&CK mapping, whitelist
    taxonomy, and per-host compromise status from a run BEFORE the eval day
    (yesterday's host risk informing today's triage - exactly the Context
    Enrichment layer the architecture mandates)."""

    def __init__(self, ngsoc_dir: Path, out_dir: Path):
        import yaml

        with open(ngsoc_dir / "config" / "attck_map.yaml", encoding="utf-8") as fh:
            attck = yaml.safe_load(fh) or {}
        self.attck_exact = attck.get("exact", {}) or {}
        self.attck_patterns = attck.get("patterns", []) or []

        with open(ngsoc_dir / "config" / "whitelist.yaml", encoding="utf-8") as fh:
            wl = yaml.safe_load(fh) or {}
        self.wl_dns, self.wl_names = set(), {}
        for rule in wl.get("rules", []) or []:
            if not rule.get("default_on", True):
                continue
            if rule.get("type") == "dst_ip":
                self.wl_dns.update(rule.get("values") or ([rule["value"]] if rule.get("value") else []))
            elif rule.get("type") == "alert_name" and rule.get("value"):
                self.wl_names[str(rule["value"])] = str(rule.get("reason", ""))[:40]

        with open(out_dir / "data" / "compromise_on.json", encoding="utf-8") as fh:
            comp = json.load(fh)
        self.hosts = {h["host"]: h for h in comp.get("hosts", []) if isinstance(h, dict) and h.get("host")}

    def map_alert(self, name: str) -> dict:
        if name in self.attck_exact:
            return self.attck_exact[name]
        for p in self.attck_patterns:
            try:
                if re.search(str(p.get("pattern", "")), name):
                    return p
            except re.error:
                continue
        return {}

    def host_risk(self, ip) -> str:
        host = self.hosts.get(str(ip or ""))
        if not host:
            return ""
        return f"{host.get('level', '?')}({host.get('score', '?')})"

# ------------------------------------------------------------------ taxonomy
_SEVERITY_BY_CATEGORY = {
    "远控木马": "critical", "后门程序": "critical", "僵尸网络": "critical",
    "挖矿木马": "high", "电脑病毒": "high", "代码执行": "high", "恶意软件": "high",
    "信息泄露": "high", "非授权访问/权限绕过": "high", "弱口令": "high",
    "隐蔽信道": "high", "暴力破解": "high", "漏洞攻击": "high",
    "进程异常": "medium", "未分类异常事件": "medium", "异常行为": "medium",
    "审计事件": "low", "配置不当/错误": "low", "文件下载": "low", "其它类恶意软件": "medium",
}
_CRITICAL_CATEGORIES = {"远控木马", "后门程序", "僵尸网络", "电脑病毒", "代码执行"}

_FLAGS_BY_CATEGORY = {
    "信息泄露": {"data_exfiltration": True},
    "非授权访问/权限绕过": {"credential_access": True},
    "远控木马": {"lateral_movement": False},
}


def _severity(category: str) -> str:
    for key, sev in _SEVERITY_BY_CATEGORY.items():
        if key in str(category):
            return sev
    return "medium"


# triageResult -> gold answer builder (soft labels; category/attack-result modulated)
def gold_for(alert, rng):
    tri = str(alert.get("triageResult") or "").strip()
    category = str(alert.get("ruleCategoryName") or "")
    name = str(alert.get("name") or "")
    sev = _severity(category)
    critical_cat = any(k in category for k in _CRITICAL_CATEGORIES)
    attack_ok = str(alert.get("attackResult")) == "成功"

    def j(v, a=0.03):
        return round(min(1.0, max(0.0, v + rng.uniform(-a, a))), 3)

    def sd(level):
        dist = [0.05] * 5
        dist[level] = 0.7
        rest = 1.0 - 0.7 - 0.05 * 4
        for delta, share in ((-1, rest * 0.6), (1, rest * 0.4)):
            idx = level + delta
            if 0 <= idx < 5:
                dist[idx] += share
        total = sum(dist)
        return [round(v / total, 3) for v in dist]

    impact = {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(sev, 2)

    if tri == "有效告警:攻击成功":
        return dict(malicious=j(0.93), authorized=j(0.03), evidence_strength=sd(4),
                    novelty=sd(2 if attack_ok else 1), business_impact=sd(min(4, impact + 1)),
                    containment_state="NOT_CONTAINED", investigation_need=j(0.92),
                    route="URGENT_ESCALATE" if critical_cat else "DEEP_INVESTIGATE")
    if tri == "有效告警:攻击失败":
        return dict(malicious=j(0.85), authorized=j(0.05), evidence_strength=sd(3),
                    novelty=sd(1), business_impact=sd(impact),
                    containment_state="PARTIALLY_CONTAINED", investigation_need=j(0.75),
                    route="DEEP_INVESTIGATE")
    if tri == "有效告警:结果未知":
        return dict(malicious=j(0.76), authorized=j(0.08), evidence_strength=sd(3),
                    novelty=sd(2), business_impact=sd(impact),
                    containment_state="UNKNOWN", investigation_need=j(0.82),
                    route="DEEP_INVESTIGATE")
    if tri == "隐患:异常行为":
        return dict(malicious=j(0.45, 0.08), authorized=j(0.35, 0.08), evidence_strength=sd(2),
                    novelty=sd(3), business_impact=sd(impact),
                    containment_state="UNKNOWN", investigation_need=j(0.7, 0.08),
                    route="HUMAN_REVIEW")
    if tri == "隐患:脆弱性":
        return dict(malicious=j(0.12), authorized=j(0.55, 0.08), evidence_strength=sd(2),
                    novelty=sd(1), business_impact=sd(2),
                    containment_state="UNKNOWN", investigation_need=j(0.4, 0.1),
                    route="HUMAN_REVIEW")
    if tri == "无效告警:业务触发":
        return dict(malicious=j(0.03), authorized=j(0.96), evidence_strength=sd(3),
                    novelty=sd(0), business_impact=sd(1),
                    containment_state="UNKNOWN", investigation_need=j(0.05),
                    route="FAST_CLOSE")
    if tri == "无效告警:规则误报":
        return dict(malicious=j(0.02), authorized=j(0.95), evidence_strength=sd(2),
                    novelty=sd(0), business_impact=sd(1),
                    containment_state="UNKNOWN", investigation_need=j(0.04),
                    route="FAST_CLOSE")
    if tri == "无效告警:其他":
        return dict(malicious=j(0.06), authorized=j(0.9, 0.05), evidence_strength=sd(2),
                    novelty=sd(1), business_impact=sd(1),
                    containment_state="UNKNOWN", investigation_need=j(0.1),
                    route="FAST_CLOSE")
    if tri == "无效告警:数据缺失":
        return dict(malicious=j(0.08), authorized=j(0.7, 0.08), evidence_strength=sd(1),
                    novelty=sd(1), business_impact=sd(1),
                    containment_state="UNKNOWN", investigation_need=j(0.35, 0.1),
                    route="DEEP_INVESTIGATE")
    if tri in _EXCLUDED_CLASSES:
        return None
    return None


def _clip(text, limit=160):
    text = str(text or "").strip()
    return text[: limit - 3] + "..." if len(text) > limit else text


def ip_scope(ip: str) -> str:
    """Observable network context (mirrors the hunter's whitelist semantics)."""
    import ipaddress

    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ""
    if addr.is_private:
        return "内网"
    if addr.version == 4 and ipaddress.ip_address("100.64.0.0") <= addr <= ipaddress.ip_address("100.127.255.255"):
        return "CGNAT覆盖网"   # Tailscale / carrier NAT - frequent FP source
    return "公网"


def render_state(alert, alert_id, hunter=None):
    """Chinese state in CompressedState text format - NO triageResult (the label)."""
    def first(v):
        if isinstance(v, list):
            return str(v[0]) if v else ""
        return str(v or "")

    src, dst = first(alert.get("srcIp")), first(alert.get("dstIp"))
    domain, ioc = first(alert.get("domain")), first(alert.get("ioc"))
    iocs = alert.get("ioc") if isinstance(alert.get("ioc"), list) else ([ioc] if ioc else [])
    ioc_hit = any(i and (i == domain or i in (src, dst) or first(alert.get("httpHost")) in i) for i in iocs)
    direction = first(alert.get("commDirection")) or "未知"
    name = _clip(alert.get("name"))
    lines = [
        # NOTE: no alert_id / date in the state - day identifiers would let the
        # model memorize export batches instead of alert semantics
        f"type: {alert.get('ruleCategoryName') or '未分类'}",
        f"name: {name}",
        f"severity: {_severity(alert.get('ruleCategoryName'))}",
        f"attack_result: {alert.get('attackResult') or '未知'}",
        f"communication_direction: {direction}",
    ]
    if hunter is not None:
        mapping = hunter.map_alert(str(alert.get("name") or ""))
        if mapping.get("threat_class"):
            lines.append(f"threat_class: {mapping['threat_class']}")
        if mapping.get("stage"):
            lines.append(f"attack_stage: {mapping['stage']}")
        if mapping.get("technique"):
            lines.append(f"technique: {mapping['technique']}")
        if mapping.get("benign_tool"):
            lines.append("benign_tool_hint: true")
        for token, reason in hunter.wl_names.items():
            if token and token in str(alert.get("name") or ""):
                lines.append(f"whitelist_match: {_clip(reason, 50)}")
                break
        if dst in hunter.wl_dns:
            lines.append("whitelist_match: 公共DNS")
    ts = str(alert.get("latestTimestamp") or "")
    hour = ts[11:13] if len(ts) >= 13 else ""   # hour-of-day only; no dates in state
    if hour:
        lines.append(f"hour_of_day: {hour}")
    if src:
        lines.append(f"source_ip: {src}")
        if scope := ip_scope(src):
            lines.append(f"source_scope: {scope}")
    if dst:
        lines.append(f"destination_ip: {dst}")
        if scope := ip_scope(dst):
            lines.append(f"destination_scope: {scope}")
    if first(alert.get("devName")):
        lines.append(f"device: {_clip(first(alert.get('devName')), 60)}")
    if hunter is not None:
        for role, ip in (("src", src), ("dst", dst)):
            risk = hunter.host_risk(ip)
            if risk:
                lines.append(f"{role}_host_prior: {risk}")
    if domain:
        lines.append(f"domain: {_clip(domain, 80)}")
    lines.append(f"ioc_hit: {str(bool(ioc_hit and iocs)).lower()}")
    if iocs:
        lines.append(f"ioc: {_clip(iocs[0], 80)}")
    times = alert.get("times")
    occur = alert.get("occurDays")
    lines.append(f"alert_count: {times if isinstance(times, int) else 1}")
    lines.append(f"occur_days: {occur if isinstance(occur, int) else 1}")
    attacker = first(alert.get("attackerContent"))
    victim = first(alert.get("victimContent"))
    if attacker:
        lines.append(f"attacker_payload: {_clip(attacker, 60)}")
    if victim:
        lines.append(f"victim_detail: {_clip(victim, 60)}")
    return "\n".join(lines)


def to_raw_alert(alert, alert_id):
    """Shape for the engine's replay path (AlertContext.build compatible)."""
    first = lambda v: (v[0] if isinstance(v, list) and v else (v if not isinstance(v, list) else None))  # noqa: E731
    category = str(alert.get("ruleCategoryName") or "unknown")
    flags = _FLAGS_BY_CATEGORY.get(category, {})
    return {
        "alert_id": alert_id,
        "timestamp": str(alert.get("latestTimestamp") or ""),
        "alert_type": "anomaly",
        "source": "NGSOC",
        "severity": _severity(category),
        "description": f"{alert.get('name')} | {category} | attack_result={alert.get('attackResult')}",
        "source_ip": first(alert.get("srcIp")),
        "target_ip": first(alert.get("dstIp")),
        "domain": first(alert.get("domain")) or None,
        "flags": flags,
        "similar_alerts_30d": (int(alert.get("occurDays") or 1)) - 1,
    }


# balanced sample sizes per triage class (train) - full-data round: ~3x
# NOTE: 需人工研判 is EXCLUDED from training and eval - it is the SOC's own
# conservative placeholder (in practice these alerts are abnormal), so its
# 0.5-ish gold would only drag the model toward indecision.
_EXCLUDED_CLASSES = {"需人工研判"}
_TRAIN_QUOTA = {
    "有效告警:攻击成功": 480, "有效告警:攻击失败": 420, "有效告警:结果未知": 360,
    "隐患:异常行为": 330, "隐患:脆弱性": 120,
    "无效告警:业务触发": 180, "无效告警:数据缺失": 120, "无效告警:其他": 75,
    "无效告警:规则误报": 24,
}


def sample_days(ngsoc_dir, days, quota, rng):
    sys.path.insert(0, str(ngsoc_dir))
    from ngsoc_hunter.etl import load_alerts

    pool = {}
    for day in days:
        try:
            alerts = load_alerts(ngsoc_dir, date_filter=day)
        except FileNotFoundError:
            continue
        for a in alerts:
            tri = str(a.get("triageResult") or "").strip()
            if tri in quota:
                pool.setdefault(tri, []).append((day, a))
    sampled = []
    for tri, items in pool.items():
        rng.shuffle(items)
        sampled.extend(items[: quota[tri]])
    return sampled


def _gold_probabilities(spec, value):
    if spec["type"] == "noul":
        return {"probabilities": {"false": round(1 - value, 3), "true": value}}
    if spec["type"] == "score":
        return {"probabilities": {str(l): p for l, p in enumerate(value)}}
    options = list(spec["criteria"].keys())
    rest = round(0.2 / (len(options) - 1), 3)
    return {"probabilities": {o: (0.8 if o == value else rest) for o in options}}


def build_cases(sampled, questions, rng, prefix, hunter=None):
    cases, seen = [], set()
    for i, (day, alert) in enumerate(sampled):
        gold = gold_for(alert, rng)
        if gold is None:
            continue
        key = (str(alert.get("name")), str(alert.get("srcIp")), str(alert.get("dstIp")),
               str(alert.get("domain")), str(alert.get("triageResult")))
        if key in seen:   # cross-day near-duplicates
            continue
        seen.add(key)
        alert_id = f"NGSOC-{day}-{i:05d}"
        cases.append({
            "id": f"{prefix}-{i:05d}",
            "workflow": f"ngsoc_triage/{alert.get('ruleCategoryName')}",
            "state": json.dumps(render_state(alert, alert_id, hunter=hunter), ensure_ascii=False),
            "questions": json.dumps(questions, ensure_ascii=False),
            "gold": json.dumps({qid: _gold_probabilities(spec, gold[qid])
                                for qid, spec in questions.items()}, ensure_ascii=False),
            "_raw_alert": to_raw_alert(alert, alert_id),
        })
    return cases


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ngsoc-dir", default=str(NGSOC_DIR))
    parser.add_argument("--quota-scale", type=float, default=1.0,
                        help="scale the per-class train quotas (e.g. 0.333 -> the original focused set)")
    parser.add_argument("--hunter-out", default=None,
                        help="hunter output dir for host-risk context (default: latest run before the eval day)")
    parser.add_argument("--train-days", nargs="*", default=[f"2026090{d}" for d in range(1, 10)] + [f"2026091{d}" for d in (0, 1, 2, 4, 5, 6, 7, 8, 9)] + ["20260920", "20260921"])
    parser.add_argument("--eval-days", nargs="*", default=["20260913"])
    parser.add_argument("--out", default=str(Path(__file__).parent / "data"))
    parser.add_argument("--seed", type=int, default=7)
    args = parser.parse_args()

    from triage_engine.core.registry import registry

    questions = {
        name: {"type": spec["type"], "instructions": spec["instructions"],
               **({"criteria": spec["criteria"]} if "criteria" in spec else {})}
        for name, spec in registry.questions.items()
    }
    rng = random.Random(args.seed)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    hunter_out = args.hunter_out
    if hunter_out is None:
        # latest hunter run strictly before the first eval day = prior knowledge only
        eval_day = min(args.eval_days) if args.eval_days else "99999999"
        runs = sorted(p.name for p in (Path(args.ngsoc_dir) / "output").glob("2026*"))
        prior = [r for r in runs if r[:8] < eval_day] or runs
        hunter_out = str(Path(args.ngsoc_dir) / "output" / prior[-1])
    hunter = HunterContext(Path(args.ngsoc_dir), Path(hunter_out))
    print(f"hunter context: {hunter_out} ({len(hunter.hosts)} hosts with prior risk)")

    quota = {k: max(1, int(v * args.quota_scale)) for k, v in _TRAIN_QUOTA.items()}
    train = build_cases(sample_days(args.ngsoc_dir, args.train_days, quota, rng),
                        questions, rng, "NTR", hunter=hunter)
    eval_quota = {k: max(4, v // 6) for k, v in _TRAIN_QUOTA.items()}
    evals = build_cases(sample_days(args.ngsoc_dir, args.eval_days, eval_quota, rng),
                        questions, rng, "NEV", hunter=hunter)

    for split, cases in (("train", train), ("eval", evals)):
        path = out / f"ngsoc_{split}.jsonl"
        with open(path, "w", encoding="utf-8") as fh:
            for case in cases:
                fh.write(json.dumps(case, ensure_ascii=False) + "\n")
        print(f"{split}: {len(cases)} cases -> {path}")


if __name__ == "__main__":
    main()
