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

"""Recalibration from SOC adjudications (SOC adjudication loop, step 4).

Joins adjudicated family verdicts back onto the shadow-replay rows, flips
the affected truth labels, recomputes the fast-path safety metrics and
answers the promotion question: can FAST_CLOSE leave shadow mode?

The report is evidence, not an action: the suggested engine.yaml snippet
is a string inside the JSON - engine.yaml is edited by humans only.

Usage (repo root):
    PYTHONPATH=services venv/bin/python services/triage_engine/finetune/recalibrate.py \
        --rows data/reports/ngsoc_shadow_20260921_rows.jsonl \
        --adjudications data/reports/adjudications_<ts>.json \
        [--provider rule | --model services/triage_engine/models/laya-security-ngsoc-v1] \
        [--grid tiny|default] [--sweep-set corrected|all] [--max-sweep 400]
"""

import argparse
import asyncio
import json
import random
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from triage_engine.core.registry import registry  # noqa: E402
from triage_engine.evaluation.families import detect_twin_families  # noqa: E402
from triage_engine.evaluation.replay import metrics_from_results  # noqa: E402
from triage_engine.evaluation.worksheet import load_rows  # noqa: E402

_SWEEP_SEED = 11


def _metric_rows(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Flatten rows-file rows (nested ``engine``) into replay result rows."""
    flat = []
    for row in rows:
        eng = row.get("engine") or {}
        flat.append({
            "route": eng.get("route") or row.get("route"),
            "truth": row.get("truth"),
            "malicious": (eng.get("decisions") or {}).get("malicious", row.get("malicious", 0.0)),
            "latency_ms": eng.get("latency_ms", 0.0),
            "degraded": eng.get("degraded", False),
        })
    return flat


def verdict_to_truth(soc_verdict: str) -> Optional[str]:
    """Map a SOC verdict onto the coarse truth label (需复查 = no change)."""
    return {"无效告警": "benign", "有效告警": "malicious"}.get(soc_verdict)


def load_adjudications(path: Path) -> List[Dict[str, Any]]:
    """Accept an import receipt, an API export, or a plain record list."""
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(payload, list):
        return payload
    for key in ("records", "data"):
        if isinstance(payload, dict) and isinstance(payload.get(key), list):
            return payload[key]
    raise ValueError(f"no adjudication records found in {path}")


def correct_labels(rows: List[Dict[str, Any]],
                   adjudications: List[Dict[str, Any]]
                   ) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Flip row truths per family verdict. Returns new row objects."""
    verdict_map = {
        a["family_id"]: (a.get("soc_verdict"), verdict_to_truth(a.get("soc_verdict", "")))
        for a in adjudications
    }
    corrected: List[Dict[str, Any]] = []
    changes: List[Dict[str, Any]] = []
    per_family: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        fid = row.get("family_id")
        new_truth = row.get("truth")
        if fid in verdict_map and verdict_map[fid][1] is not None \
                and row.get("truth") != verdict_map[fid][1]:
            changes.append({
                "worksheet_id": row.get("worksheet_id"),
                "from": row.get("truth"), "to": verdict_map[fid][1], "reason": fid,
            })
            entry = per_family.setdefault(fid, {
                "family_id": fid, "name": (row.get("ngsoc") or {}).get("name"),
                "verdict": verdict_map[fid][0], "rows_flipped": [], "prior_labels_per_day": {},
            })
            entry["rows_flipped"].append(row.get("worksheet_id"))
            day = str(row.get("day") or "?")
            tri = str((row.get("ngsoc") or {}).get("triage_result") or "?")
            day_counts = entry["prior_labels_per_day"].setdefault(day, {})
            day_counts[tri] = day_counts.get(tri, 0) + 1
            new_row = dict(row)
            new_row["truth"] = verdict_map[fid][1]
            corrected.append(new_row)
        else:
            corrected.append(row)
    return corrected, {"families": list(per_family.values()), "label_changes": changes}


def promotion_assessment(corrected_rows: List[Dict[str, Any]],
                         twins: Dict[str, Any],
                         adjudications: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Deterministic FAST_CLOSE shadow->live readiness rules.

    READY iff: corrected false_close_rate is zero, every twin family is
    adjudicated (verdict != 需复查) and every FAST_CLOSE row's family is
    adjudicated. Otherwise HOLD with explicit blockers.
    """
    metrics = metrics_from_results(_metric_rows(corrected_rows))
    adjudicated = {a["family_id"]: a.get("soc_verdict") for a in adjudications}
    blockers: List[str] = []
    if metrics["false_close_rate"] > 0:
        blockers.append(
            f"corrected false_close_rate {metrics['false_close_rate']} > 0 "
            f"({metrics['route_distribution'].get('FAST_CLOSE', 0)} closes remain)")
    for fid, fam in sorted(twins.items()):
        if fid not in adjudicated:
            blockers.append(f"twin family {fid} ({fam['name']}) unadjudicated")
        elif adjudicated[fid] == "需复查":
            blockers.append(f"twin family {fid} ({fam['name']}) pending re-review (需复查)")
    fast_close_families = {
        row.get("family_id") for row in corrected_rows
        if (row.get("engine") or {}).get("route") == "FAST_CLOSE"
    }
    for fid in sorted(fast_close_families):
        if fid not in adjudicated:
            blockers.append(f"FAST_CLOSE family {fid} unadjudicated (coverage rule)")
    return {
        "verdict": "HOLD" if blockers else "READY",
        "blockers": blockers,
        "evidence": {
            "corrected_false_close_rate": metrics["false_close_rate"],
            "fast_close_routes": metrics["route_distribution"].get("FAST_CLOSE", 0),
            "twin_families": sorted(twins),
            "fast_close_families": sorted(fast_close_families),
            "adjudicated_families": sorted(adjudicated),
        },
    }


def build_sweep_population(rows: List[Dict[str, Any]], flipped_ids: set,
                           mode: str = "corrected", cap: int = 400) -> List[Dict[str, Any]]:
    """Sweep population: flipped rows + fast-path rows first, reservoir fill."""
    if mode == "all":
        return list(rows)
    priority, rest = [], []
    for row in rows:
        wid = row.get("worksheet_id")
        route = (row.get("engine") or {}).get("route")
        if wid in flipped_ids or route in ("FAST_CLOSE", "FAST_QUEUE"):
            priority.append(row)
        else:
            rest.append(row)
    room = max(0, cap - len(priority))
    if room and rest:
        priority.extend(random.Random(_SWEEP_SEED).sample(rest, min(room, len(rest))))
    return priority


def suppression_candidates(adjudications: List[Dict[str, Any]]
                            ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Report-only: benign families safe to suppress vs approval-gated blocks."""
    suppress, blocklist = [], []
    for a in adjudications:
        verdict, disposition = a.get("soc_verdict"), a.get("disposition")
        fam_key = a.get("family_key") or ["?", [], [], ""]
        if isinstance(fam_key, str):  # records read back from JSON storage
            fam_key = json.loads(fam_key)
        candidate = {
            "family_id": a["family_id"], "name": a.get("name") or "",
            "src_scopes": fam_key[1],
            "days": a.get("days") or [], "member_count": len(a.get("alert_ids") or []),
        }
        if verdict == "无效告警" and disposition in ("auto_close_ok", "suppress"):
            suppress.append(candidate)
        elif disposition == "blocklist":
            candidate["soc_verdict"] = verdict
            blocklist.append(candidate)
    return suppress, blocklist


def suggested_thresholds_yaml(day: str, best: Optional[Dict[str, Any]] = None) -> str:
    """Suggested engine.yaml snippet - report-only, never auto-applied."""
    fc = registry.thresholds("fast_close")
    if best:
        fc = {**fc, "authorized_min": best["authorized_min"],
              "malicious_max": best["malicious_max"],
              "require_similar_history": best["require_similar_history"]}
    yaml_bool = lambda v: "true" if v else "false"  # noqa: E731
    return (
        "thresholds:\n"
        f"  version: triage_policy_v1.2-recal{day}   # suggested; apply manually after SOC sign-off\n"
        "  fast_close:\n"
        f"    malicious_max: {fc['malicious_max']}\n"
        f"    authorized_min: {fc['authorized_min']}\n"
        f"    impact_max: {fc.get('impact_max', 1)}\n"
        f"    evidence_strength_min: {fc.get('evidence_strength_min', 2)}\n"
        f"    novelty_max: {fc.get('novelty_max', 1)}\n"
        f"    require_similar_history: {yaml_bool(fc.get('require_similar_history', False))}\n"
        f"    similar_history_min: {fc.get('similar_history_min', 1)}\n"
    )


def build_report(rows: List[Dict[str, Any]],
                 adjudications: List[Dict[str, Any]],
                 sweep_results: Optional[List[Dict[str, Any]]] = None,
                 sweep_meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Assemble the recalibration report (pure - tests call this directly)."""
    twins = detect_twin_families(rows)
    corrected, corrections = correct_labels(rows, adjudications)
    day = next((str(r.get("day")) for r in rows if r.get("day")), "unknown")
    best = None
    if sweep_results:
        safe = [r for r in sweep_results if r["false_close_rate"] == 0]
        best = max(safe, key=lambda r: r["fast_path_coverage"]) if safe else None
    suppress, blocklist = suppression_candidates(adjudications)
    return {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "day": day,
        "rows": len(rows),
        "adjudicated_families": sorted({a["family_id"] for a in adjudications}),
        "corrections": corrections,
        "metrics_before": metrics_from_results(_metric_rows(rows)),
        "metrics_after": metrics_from_results(_metric_rows(corrected)),
        "twin_families": twins,
        "promotion": promotion_assessment(corrected, twins, adjudications),
        "sweep": {"skipped": "no model"} if sweep_results is None else {
            **(sweep_meta or {}), "results": sweep_results, "best_safe": best},
        "suggested_thresholds_yaml": suggested_thresholds_yaml(day, best),
        "suppression_candidates": suppress,
        "blocklist_candidates": blocklist,
        "notes": "report-only: engine.yaml is the single source of truth and is edited by humans",
    }


async def run(args) -> Dict[str, Any]:
    rows = load_rows(args.rows)
    if not rows:
        raise SystemExit(f"no rows found in {args.rows}")
    adjudications = load_adjudications(Path(args.adjudications))

    sweep_results, sweep_meta = None, None
    if args.provider or args.model:
        from triage_engine.finetune.threshold_sweep import run_route_sweep

        corrected_for_sweep, correction_info = correct_labels(rows, adjudications)
        flipped = {c["worksheet_id"] for c in correction_info["label_changes"]}
        population = build_sweep_population(
            corrected_for_sweep, flipped, mode=args.sweep_set, cap=args.max_sweep)
        grid = ([tuple(registry.thresholds("fast_close")[k] for k in
                       ("authorized_min", "malicious_max", "require_similar_history"))]
                if args.grid == "tiny" else None)
        provider = None
        if args.provider == "rule":
            from triage_engine.decision_models.rule import RuleProvider
            provider = RuleProvider()
        else:
            from triage_engine.decision_models.laya import LayaDecisionProvider
            provider = LayaDecisionProvider(prewarm=False, checkpoint_override="multilingual")
            import laya_mlx
            provider._agents["multilingual"] = laya_mlx.load(str(args.model))
        labels = {r["worksheet_id"]: r.get("truth") for r in population}
        sweep_results = await run_route_sweep(
            [r.get("raw_alert") or {"alert_id": r["worksheet_id"]} for r in population],
            labels, provider=provider, grid=grid)
        sweep_meta = {
            "population_mode": args.sweep_set,
            "population_size": len(population),
            "grid": args.grid,
            "provider": provider.name,
        }

    report = build_report(rows, adjudications, sweep_results, sweep_meta)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=1, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({
        "report": str(out),
        "promotion": report["promotion"]["verdict"],
        "blockers": report["promotion"]["blockers"],
        "false_close_rate": {
            "before": report["metrics_before"]["false_close_rate"],
            "after": report["metrics_after"]["false_close_rate"],
        },
    }, ensure_ascii=False, indent=1))
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rows", action="append", required=True, type=Path)
    parser.add_argument("--adjudications", required=True)
    parser.add_argument("--out", default=None)
    parser.add_argument("--provider", choices=["rule"], default=None,
                        help="weights-free provider (tests / smoke)")
    parser.add_argument("--model", type=Path, default=None,
                        help="fine-tuned laya checkpoint for the sweep")
    parser.add_argument("--grid", choices=["tiny", "default"], default="default")
    parser.add_argument("--sweep-set", choices=["corrected", "all"], default="corrected")
    parser.add_argument("--max-sweep", type=int, default=400)
    args = parser.parse_args()
    days = sorted({str(r.get("day")) for r in load_rows(args.rows) if r.get("day")})
    if args.out is None:
        args.out = f"data/reports/recalibration_{'_'.join(days) if days else 'unknown'}.json"
    asyncio.run(run(args))
