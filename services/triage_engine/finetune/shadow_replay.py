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

"""Full-day shadow replay (requirement §34).

Runs the calibrated engine over a stratified sample of one NGSOC export day
that was never used for training or threshold calibration, and reports the
engine's route distribution per NGSOC triage class plus the fast-path
safety metrics. Memory-bounded: per-class reservoir sampling while streaming.

Labeling: 无效告警:* -> benign; everything else -> malicious (the SOC's own
口径: 需人工研判 are in practice abnormal).

Besides the aggregate report this writes a per-alert rows JSONL (default
``<out stem>_rows.jsonl``) with the full NGSOC identity, the engine's typed
decisions, the alert family key and the raw alert - the worksheet export,
adjudication import and recalibration all consume that file.
"""

import argparse
import asyncio
import json
import random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

NGSOC_DIR = Path.home() / "Downloads" / "NGSOC狩猎"
_PER_CLASS_CAP = 250
_CLASSES = [
    "有效告警:攻击成功", "有效告警:攻击失败", "有效告警:结果未知",
    "隐患:异常行为", "隐患:脆弱性", "无效告警:业务触发", "无效告警:数据缺失",
    "无效告警:其他", "无效告警:规则误报", "需人工研判",
]


def pick_hunter_run(ngsoc_dir: Path, day: str) -> Path:
    """Latest hunter output run strictly before `day` (prior knowledge only)."""
    runs = sorted(p.name for p in (ngsoc_dir / "output").glob("2026*"))
    prior = [r for r in runs if r[:8] < day] or runs
    return ngsoc_dir / "output" / prior[-1]


def _rows_payload(day, ngsoc_alert, truth, result, raw_alert, provenance, family):
    return {
        "worksheet_id": result["alert_id"],
        "day": day,
        "ngsoc": {
            "alert_id": ngsoc_alert.get("alert_id"),
            "file": ngsoc_alert.get("file"),
            "name": ngsoc_alert.get("name"),
            "rule_category": ngsoc_alert.get("ruleCategoryName"),
            "triage_result": str(ngsoc_alert.get("triageResult") or ""),
            "src_ip": ngsoc_alert.get("srcIp") or [],
            "dst_ip": ngsoc_alert.get("dstIp") or [],
            "domain": ngsoc_alert.get("domain") or [],
            "latest_timestamp": ngsoc_alert.get("latestTimestamp"),
            "attack_result": ngsoc_alert.get("attackResult"),
            "comm_direction": ngsoc_alert.get("commDirection"),
            "dev_name": ngsoc_alert.get("devName"),
            "dev_ip": ngsoc_alert.get("devIp"),
        },
        "truth": truth,
        "family_id": family["family_id"],
        "family_key": family["family_key"],
        "engine": {
            "route": result["route"],
            "reason_codes": result["reason_codes"],
            "hard_gates": result["hard_gates"],
            "model_suggested_route": result["model_suggested_route"],
            "decisions": result["decisions"],
            "state_hash": result["state_hash"],
            "degraded": result["degraded"],
            "latency_ms": result["latency_ms"],
        },
        "raw_alert": raw_alert,
        "provenance": provenance,
    }


async def main_async(args):
    from triage_engine.core.store import Store
    from triage_engine.decision_models.laya import LayaDecisionProvider
    from triage_engine.evaluation.families import family_id, family_key_from_ngsoc
    from triage_engine.evaluation.replay import replay
    from generate_ngsoc_dataset import HunterContext, to_raw_alert

    sys.path.insert(0, str(args.ngsoc_dir))
    from ngsoc_hunter.etl import load_alerts

    rng = random.Random(11)
    hunter_out = Path(args.hunter_run) if args.hunter_run else pick_hunter_run(args.ngsoc_dir, args.day)
    hunter = HunterContext(args.ngsoc_dir, hunter_out)

    reservoir = {c: [] for c in _CLASSES}
    seen = {c: 0 for c in _CLASSES}
    for alert in load_alerts(args.ngsoc_dir, date_filter=args.day):
        tri = str(alert.get("triageResult") or "").strip()
        if tri not in reservoir:
            continue
        slot, n = reservoir[tri], seen[tri]
        if len(slot) < _PER_CLASS_CAP:
            slot.append(alert)
        else:
            idx = rng.randrange(n + 1)
            if idx < _PER_CLASS_CAP:
                slot[idx] = alert
        seen[tri] = n + 1

    alerts, originals, labels, class_of = [], [], {}, {}
    for tri, slot in reservoir.items():
        for alert in slot:
            alert_id = f"SHD-{args.day}-{len(alerts):05d}"
            alerts.append(to_raw_alert(alert, alert_id, hunter=hunter))
            originals.append(alert)
            labels[alert_id] = "benign" if tri.startswith("无效告警") else "malicious"
            class_of[alert_id] = tri

    provider = LayaDecisionProvider(prewarm=False, checkpoint_override="multilingual")
    import laya_mlx
    provider._agents["multilingual"] = laya_mlx.load(str(args.model))

    t0 = time.time()
    # the replay engine caps each run at 1000 alerts - run in chunks and merge
    results, route_counts = [], {}
    latencies = []
    threshold_version = question_version = ""
    for i in range(0, len(alerts), 900):
        chunk = alerts[i : i + 900]
        chunk_labels = {a["alert_id"]: labels[a["alert_id"]] for a in chunk}
        run = await replay(chunk, labels=chunk_labels, provider=provider, store=Store(":memory:"))
        results.extend(run["results"])
        for route, n in run["metrics"]["route_distribution"].items():
            route_counts[route] = route_counts.get(route, 0) + n
        latencies.append(run["metrics"]["avg_latency_ms"] * run["metrics"]["total"])
        threshold_version = run["threshold_version"]
        question_version = run["question_version"]
    elapsed = time.time() - t0

    # exact counts over the merged results (chunk-level rounding drifts)
    benign_closes = sum(
        1 for r in results if r["route"] == "FAST_CLOSE" and labels[r["alert_id"]] == "benign"
    )
    false_close = sum(
        1 for r in results if r["route"] == "FAST_CLOSE" and labels[r["alert_id"]] == "malicious"
    )
    per_class = {}
    for r in results:
        c = class_of[r["alert_id"]]
        per_class.setdefault(c, {}).setdefault(r["route"], 0)
        per_class[c][r["route"]] += 1

    total = len(results) or 1
    metrics = {
        "total": len(results),
        "route_distribution": route_counts,
        "fast_path_coverage": round(
            (route_counts.get("FAST_CLOSE", 0) + route_counts.get("FAST_QUEUE", 0)) / total, 4),
        "fast_close_benign": benign_closes,
        "fast_close_malicious": false_close,
        "false_close_rate": round(false_close / total, 4),
        "avg_latency_ms": round(sum(latencies) / total, 1),
    }

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    report = {
        "day": args.day,
        "sample": {c: seen[c] for c in _CLASSES},
        "sampled": len(alerts),
        "metrics": metrics,
        "routes_per_ngsoc_class": per_class,
        "elapsed_seconds": round(elapsed, 1),
        "threshold_version": threshold_version,
        "question_version": question_version,
        "model": str(args.model),
        "hunter_run": hunter_out.name,
        "rows_file": str(args.rows_out),
    }
    out.write_text(json.dumps(report, indent=1, ensure_ascii=False))
    print(json.dumps({k: report[k] for k in ("day", "sampled", "metrics", "routes_per_ngsoc_class")},
                     indent=1, ensure_ascii=False))

    # per-alert rows: full identity + engine output + family + self-sufficient
    # raw alert (recalibrate re-sweeps from this file without the xlsx/hunter)
    provenance = {
        "threshold_version": threshold_version,
        "question_version": question_version,
        "model": str(args.model),
        "hunter_run": hunter_out.name,
        "shadow_report": str(out),
    }
    rows_out = Path(args.rows_out)
    rows_out.parent.mkdir(parents=True, exist_ok=True)
    with open(rows_out, "w", encoding="utf-8") as fh:
        for raw, original, result in zip(alerts, originals, results):
            key = family_key_from_ngsoc(original)
            row = _rows_payload(
                args.day, original, labels[result["alert_id"]], result, raw,
                provenance, {"family_id": family_id(key), "family_key": key},
            )
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(f"per-alert rows: {rows_out} ({len(results)} rows)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--day", default="20260921")
    parser.add_argument("--ngsoc-dir", type=Path, default=NGSOC_DIR)
    parser.add_argument("--model", type=Path,
                        default=Path(__file__).resolve().parents[1] / "models" / "laya-security-ngsoc-v1")
    parser.add_argument("--out", default="data/reports/ngsoc_shadow_0921.json")
    parser.add_argument("--rows-out", default=None,
                        help="per-alert rows JSONL (default: <out stem>_rows.jsonl)")
    parser.add_argument("--hunter-run", default=None,
                        help="hunter output run dir (default: latest run strictly before --day)")
    args = parser.parse_args()
    if args.rows_out is None:
        stem = Path(args.out).stem
        args.rows_out = str(Path(args.out).with_name(f"{stem}_rows.jsonl"))
    asyncio.run(main_async(args))
