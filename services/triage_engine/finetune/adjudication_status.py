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

"""Family adjudication status view (disposition tracking).

Usage (repo root):
    PYTHONPATH=services venv/bin/python services/triage_engine/finetune/adjudication_status.py \
        [--db ... | --api http://localhost:8009] [--family-id F-xxxx] \
        [--rows data/reports/ngsoc_shadow_20260921_rows.jsonl ...] [--json]
"""

import argparse
import json
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from triage_engine.evaluation.worksheet import load_rows  # noqa: E402


def _fetch(api_base: str, family_id: str | None) -> dict:
    url = f"{api_base.rstrip('/')}/api/v1/adjudications"
    if family_id:
        url += f"/{family_id}"
    with urllib.request.urlopen(url, timeout=15) as resp:
        payload = json.loads(resp.read())
    if not payload.get("success"):
        raise RuntimeError(f"API request failed: {payload}")
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    target = parser.add_mutually_exclusive_group()
    target.add_argument("--db", default=None)
    target.add_argument("--api", default=None)
    parser.add_argument("--family-id", default=None)
    parser.add_argument("--rows", action="append", default=[], type=Path,
                        help="join member/day/label counts from shadow rows")
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument("--json", action="store_true", help="dump raw JSON")
    args = parser.parse_args()

    if args.api:
        payload = _fetch(args.api, args.family_id)
        records = payload["data"] if isinstance(payload["data"], list) else [payload["data"]]
        stats = payload.get("meta", {}).get("stats")
    else:
        from triage_engine.core.store import Store
        store = Store(args.db) if args.db else Store()
        if args.family_id:
            record = store.get_adjudication(args.family_id)
            records = [record] if record else []
        else:
            records = store.list_adjudications(limit=args.limit)
        stats = store.adjudication_stats()
        store.close()

    # optional join: member/day/label counts per family from the rows files
    family_rows: dict[str, dict] = {}
    for row in load_rows(args.rows):
        fid = row.get("family_id")
        entry = family_rows.setdefault(fid, {"members": 0, "days": set(), "truths": {}})
        entry["members"] += 1
        if row.get("day"):
            entry["days"].add(str(row["day"]))
        truth = row.get("truth") or "?"
        entry["truths"][truth] = entry["truths"].get(truth, 0) + 1

    if args.json:
        print(json.dumps({"stats": stats, "records": records,
                          "family_rows": {k: {"members": v["members"], "days": sorted(v["days"]),
                                              "truths": v["truths"]} for k, v in family_rows.items()}},
                         ensure_ascii=False, indent=1))
        return

    print(json.dumps({"stats": stats}, ensure_ascii=False))
    for r in records:
        extra = family_rows.get(r["family_id"], {})
        members = extra.get("members", len(r.get("alert_ids") or []))
        days = sorted(extra.get("days", set())) or (r.get("days") or [])
        print(f"{r['family_id']}  {r.get('name', '')[:40]:<40}  "
              f"verdict={r['soc_verdict']}  disposition={r.get('disposition') or '-'}  "
              f"members={members}  days={','.join(days)}  by={r.get('adjudicator') or '-'}")
        if extra.get("truths"):
            print(f"    shadow truths: {extra['truths']}")
    if not records:
        print("no adjudications recorded yet")


if __name__ == "__main__":
    main()
