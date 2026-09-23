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

"""SOC adjudication worksheet: export, parse, family expansion.

The worksheet is the human-in-the-loop transport of the adjudication
loop: ``export_worksheet`` turns shadow-replay rows (JSONL) into a CSV
the SOC fills in; ``parse_worksheet`` validates the filled sheet and
produces one adjudication record per family, shaped exactly like the
``POST /api/v1/adjudications`` payload so the direct-store and --api
import paths are identical.

Integrity: each row ships a ``row_checksum`` over the identity+evidence
columns (worksheet_id, family_id, day, triage_result, route). Editing
anything outside the five SOC columns is rejected at import.
"""

import csv
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .families import detect_twin_families, family_id, family_key_from_row, scope_set

SOC_VERDICTS: Tuple[str, ...] = ("有效告警", "无效告警", "需复查")
DISPOSITIONS: Tuple[str, ...] = ("auto_close_ok", "suppress", "blocklist", "monitor", "relabel")

COLUMNS: List[str] = [
    # identity
    "worksheet_id", "family_id", "family_key", "is_twin_family", "day", "ngsoc_alert_id", "file",
    # NGSOC fields
    "name", "rule_category", "triage_result", "latest_timestamp", "src_ip", "dst_ip", "domain",
    "src_scope", "dst_scope", "attack_result",
    # engine output
    "route", "model_suggested_route", "reason_codes", "hard_gates",
    "malicious", "authorized", "evidence_strength", "novelty", "business_impact",
    "investigation_need", "containment_state",
    "truth", "state_hash", "degraded",
    # SOC fills these five (+ notes)
    "soc_verdict", "soc_disposition", "apply_to_family", "adjudicator", "notes",
    # integrity
    "row_checksum",
]

_SOC_COLUMNS = ("soc_verdict", "soc_disposition", "apply_to_family", "adjudicator", "notes")
_DECISION_COLUMNS = ("malicious", "authorized", "evidence_strength", "novelty",
                     "business_impact", "investigation_need", "containment_state")


def load_rows(rows_files: List[Path]) -> List[Dict[str, Any]]:
    """Load and concatenate shadow-rows JSONL files."""
    rows: List[Dict[str, Any]] = []
    for path in rows_files or []:
        with open(path, encoding="utf-8") as fh:
            rows.extend(json.loads(line) for line in fh if line.strip())
    return rows


def row_checksum(worksheet_id: str, family_id: str, day: str,
                 triage_result: str, route: str) -> str:
    """Integrity digest over the identity+evidence columns."""
    blob = f"{worksheet_id}|{family_id}|{day}|{triage_result}|{route}"
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:8]


def _row_family_id(row: Dict[str, Any]) -> str:
    return row.get("family_id") or family_id(row.get("family_key") or family_key_from_row(row))


def _csv_cell(row: Dict[str, Any], column: str, twins: Dict[str, Any]) -> str:
    ngsoc = row.get("ngsoc") or {}
    engine = row.get("engine") or {}
    decisions = engine.get("decisions") or {}
    if column in ("worksheet_id", "day"):
        return str(row.get(column, ""))
    if column == "family_id":
        return _row_family_id(row)
    if column == "family_key":
        return "; ".join(str(part) for part in (row.get("family_key") or family_key_from_row(row)))
    if column == "is_twin_family":
        return "yes" if _row_family_id(row) in twins else "no"
    if column == "ngsoc_alert_id":
        return str(ngsoc.get("alert_id", ""))
    if column == "file":
        return str(ngsoc.get("file", ""))
    if column in ("name", "rule_category", "triage_result", "latest_timestamp", "attack_result"):
        return str(ngsoc.get(column, "") or "")
    if column in ("src_ip", "dst_ip", "domain", "src_scope", "dst_scope"):
        base = {"src_ip": "src_ip", "dst_ip": "dst_ip", "domain": "domain",
                "src_scope": "src_ip", "dst_scope": "dst_ip"}[column]
        values = ngsoc.get(base) or []
        if column in ("src_scope", "dst_scope"):
            return "; ".join(scope_set(values))
        return "; ".join(str(v) for v in values)
    if column in ("route", "model_suggested_route"):
        return str(engine.get(column, "") or "")
    if column in ("reason_codes", "hard_gates"):
        return "; ".join(str(v) for v in (engine.get(column) or []))
    if column in _DECISION_COLUMNS:
        return str(decisions.get(column, ""))
    if column == "truth":
        return str(row.get("truth", "") or "")
    if column == "state_hash":
        return str(engine.get("state_hash", "") or "")
    if column == "degraded":
        return "yes" if engine.get("degraded") else "no"
    if column == "row_checksum":
        return row_checksum(
            str(row.get("worksheet_id", "")), _row_family_id(row), str(row.get("day", "")),
            str(ngsoc.get("triage_result", "") or ""), str(engine.get("route", "") or ""),
        )
    return ""


def _sort_key(row: Dict[str, Any], twins: Dict[str, Any]) -> Tuple[Any, ...]:
    """Twin-family rows first (largest family first), then FAST_CLOSE, then rest."""
    fid = _row_family_id(row)
    day = str(row.get("day") or "0")
    wid = str(row.get("worksheet_id", ""))
    route = str((row.get("engine") or {}).get("route") or "")
    if fid in twins:
        return (0, -twins[fid]["member_count"], day, wid)
    if route == "FAST_CLOSE":
        return (1, day, wid)
    triage = str((row.get("ngsoc") or {}).get("triage_result") or "")
    return (2, -int(day) if day.isdigit() else 0, triage, wid)


def export_worksheet(rows_files: List[Path], out: Path) -> Dict[str, Any]:
    """Write the SOC worksheet (utf-8-sig CSV) from shadow-rows JSONL files."""
    rows = load_rows(rows_files)
    twins = detect_twin_families(rows)
    ordered = sorted(rows, key=lambda r: _sort_key(r, twins))
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(COLUMNS)
        for row in ordered:
            writer.writerow([_csv_cell(row, col, twins) for col in COLUMNS])
    return {
        "rows": len(rows),
        "families": len({_row_family_id(r) for r in rows}),
        "twin_families": sorted(twins),
        "fast_close_rows": sum(
            1 for r in rows if (r.get("engine") or {}).get("route") == "FAST_CLOSE"),
        "worksheet": str(out),
    }


def parse_worksheet(csv_path: Path,
                    rows_files: Optional[List[Path]] = None
                    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Validate a filled worksheet; return (adjudication records, error rows).

    Records match the ``POST /api/v1/adjudications`` payload shape.
    ``rows_files`` is the known universe of worksheet ids - required when
    any row uses ``apply_to_family=yes`` (membership resolution).
    """
    universe = {r.get("worksheet_id"): r for r in load_rows(rows_files or [])}

    with open(csv_path, encoding="utf-8-sig", newline="") as fh:
        sheet_rows = list(csv.DictReader(fh))

    if any((r.get("apply_to_family") or "").strip().lower() == "yes" for r in sheet_rows) \
            and not universe:
        raise ValueError(
            "apply_to_family=yes needs --rows shadow-rows files for membership resolution")

    errors: List[Dict[str, Any]] = []
    filled: List[Tuple[Dict[str, str], Dict[str, Any]]] = []
    for r in sheet_rows:
        wid = (r.get("worksheet_id") or "").strip()
        verdict = (r.get("soc_verdict") or "").strip()
        disposition = (r.get("soc_disposition") or "").strip()
        apply_family = (r.get("apply_to_family") or "").strip().lower()
        if not verdict:
            continue                                    # partial fill is normal
        if wid not in universe:
            errors.append({"worksheet_id": wid, "error": "UNKNOWN_WORKSHEET_ID"})
            continue
        if verdict not in SOC_VERDICTS:
            errors.append({"worksheet_id": wid, "error": "INVALID_VERDICT", "value": verdict})
            continue
        if disposition not in DISPOSITIONS:
            errors.append({"worksheet_id": wid, "error": "INVALID_DISPOSITION", "value": disposition})
            continue
        if apply_family not in ("yes", "no", ""):
            errors.append({"worksheet_id": wid, "error": "INVALID_APPLY_TO_FAMILY",
                           "value": apply_family})
            continue
        expected = row_checksum(wid, r.get("family_id", ""), r.get("day", ""),
                                r.get("triage_result", ""), r.get("route", ""))
        if (r.get("row_checksum") or "").strip() != expected:
            errors.append({"worksheet_id": wid, "error": "CHECKSUM_MISMATCH"})
            continue
        filled.append((r, universe[wid]))

    # collapse per family; conflicting verdicts inside one family are rejected
    by_family: Dict[str, List[Tuple[Dict[str, str], Dict[str, Any]]]] = {}
    for entry in filled:
        by_family.setdefault(entry[0]["family_id"], []).append(entry)
    records: List[Dict[str, Any]] = []
    for fid, entries in by_family.items():
        verdicts = {r["soc_verdict"] for r, _ in entries}
        if len(verdicts) > 1:
            errors.append({"family_id": fid, "error": "CONFLICTING_VERDICTS",
                           "worksheet_ids": [r["worksheet_id"] for r, _ in entries],
                           "verdicts": sorted(verdicts)})
            continue
        sheet_row, universe_row = entries[-1]           # last non-empty wins
        applies_to_family = any(
            (r.get("apply_to_family") or "").strip().lower() == "yes" for r, _ in entries)
        if applies_to_family:
            members = [u for u in universe.values() if _row_family_id(u) == fid]
        else:
            members = [u for _, u in entries]
        records.append({
            "family_id": fid,
            "family_key": universe_row.get("family_key") or family_key_from_row(universe_row),
            "name": (universe_row.get("ngsoc") or {}).get("name") or sheet_row.get("name"),
            "soc_verdict": sheet_row["soc_verdict"],
            "disposition": sheet_row["soc_disposition"],
            "alert_ids": sorted(u["worksheet_id"] for u in members),
            "applies_to_family": applies_to_family,
            "days": sorted({str(u.get("day") or "") for u in members if u.get("day")}),
            "engine_route": sheet_row.get("route") or "",
            "adjudicator": (sheet_row.get("adjudicator") or "").strip() or None,
            "source_worksheet": Path(csv_path).name,
            "notes": (sheet_row.get("notes") or "").strip() or None,
        })
    return records, errors
