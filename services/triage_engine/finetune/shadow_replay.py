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


async def main_async(args):
    from triage_engine.core.store import Store
    from triage_engine.decision_models.laya import LayaDecisionProvider
    from triage_engine.evaluation.replay import replay
    from generate_ngsoc_dataset import HunterContext, to_raw_alert

    sys.path.insert(0, str(args.ngsoc_dir))
    from ngsoc_hunter.etl import load_alerts

    rng = random.Random(11)
    hunter_out = args.ngsoc_dir / "output" / "20260912_211435"
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

    alerts, labels, class_of = [], {}, {}
    for tri, slot in reservoir.items():
        for i, alert in enumerate(slot):
            alert_id = f"SHD-{args.day}-{len(alerts):05d}"
            alerts.append(to_raw_alert(alert, alert_id, hunter=hunter))
            labels[alert_id] = "benign" if tri.startswith("无效告警") else "malicious"
            class_of[alert_id] = tri

    provider = LayaDecisionProvider(prewarm=False, checkpoint_override="multilingual")
    import laya_mlx
    provider._agents["multilingual"] = laya_mlx.load(str(args.model))

    t0 = time.time()
    # the replay engine caps each run at 1000 alerts - run in chunks and merge
    results, route_counts = [], {}
    fast_close_tp = fast_close_fp = false_close = 0
    malicious_total = malicious_caught = 0
    latencies = []
    for i in range(0, len(alerts), 900):
        chunk = alerts[i : i + 900]
        chunk_labels = {a["alert_id"]: labels[a["alert_id"]] for a in chunk}
        run = await replay(chunk, labels=chunk_labels, provider=provider, store=Store(":memory:"))
        results.extend(run["results"])
        m = run["metrics"]
        for route, n in m["route_distribution"].items():
            route_counts[route] = route_counts.get(route, 0) + n
        false_close += round(m["false_close_rate"] * m["total"])
        latencies.append(m["avg_latency_ms"] * m["total"])
    elapsed = time.time() - t0

    benign_closes = sum(
        1 for r in results if r["route"] == "FAST_CLOSE" and labels[r["alert_id"]] == "benign"
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
        "fast_close_malicious": route_counts.get("FAST_CLOSE", 0) - benign_closes,
        "false_close_rate": round(false_close / total, 4),
        "avg_latency_ms": round(sum(latencies) / total, 1),
    }

    report = {
        "day": args.day,
        "sample": {c: seen[c] for c in _CLASSES},
        "sampled": len(alerts),
        "metrics": metrics,
        "routes_per_ngsoc_class": per_class,
        "elapsed_seconds": round(elapsed, 1),
        "threshold_version": "triage_policy_v1.1-shadow0913",
        "model": str(args.model),
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=1, ensure_ascii=False))
    print(json.dumps({k: report[k] for k in ("day", "sampled", "metrics", "routes_per_ngsoc_class")},
                     indent=1, ensure_ascii=False))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--day", default="20260921")
    parser.add_argument("--ngsoc-dir", type=Path, default=NGSOC_DIR)
    parser.add_argument("--model", type=Path,
                        default=Path(__file__).resolve().parents[1] / "models" / "laya-security-ngsoc-v1")
    parser.add_argument("--out", default="data/reports/ngsoc_shadow_0921.json")
    asyncio.run(main_async(parser.parse_args()))
