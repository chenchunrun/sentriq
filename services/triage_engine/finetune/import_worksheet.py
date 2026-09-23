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

"""Import a filled SOC adjudication worksheet.

Usage (repo root):
    PYTHONPATH=services venv/bin/python services/triage_engine/finetune/import_worksheet.py \
        --worksheet data/reports/soc_worksheet_20260921.csv \
        --rows data/reports/ngsoc_shadow_20260921_rows.jsonl \
        [--db services/triage_engine/data/triage_engine.db | --api http://localhost:8009]

Writes one adjudication row per family (upsert by family_id), appends a
``soc_adjudication`` feedback row per member alert, and saves an import
receipt JSON that recalibrate.py consumes.
"""

import argparse
import json
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from triage_engine.evaluation.worksheet import parse_worksheet  # noqa: E402


def _post_batch(api_base: str, records: list, link_feedback: bool) -> dict:
    """POST the batch to the running service (it owns the DB)."""
    body = json.dumps({"adjudications": records, "link_feedback": link_feedback}).encode()
    req = urllib.request.Request(
        f"{api_base.rstrip('/')}/api/v1/adjudications", data=body,
        headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=30) as resp:
        payload = json.loads(resp.read())
    if not payload.get("success"):
        raise RuntimeError(f"API import failed: {payload}")
    return payload["data"]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worksheet", required=True, type=Path)
    parser.add_argument("--rows", action="append", default=[], type=Path,
                        help="shadow rows JSONL (repeatable; required for apply_to_family=yes)")
    target = parser.add_mutually_exclusive_group()
    target.add_argument("--db", default=None,
                        help="SQLite DB path (default: TRIAGE_ENGINE_DB or the service default)")
    target.add_argument("--api", default=None, help="service base URL (e.g. http://localhost:8009)")
    parser.add_argument("--no-feedback", action="store_true",
                        help="skip the per-member feedback rows")
    parser.add_argument("--receipt-out", default=None,
                        help="import receipt JSON (default: data/reports/adjudications_<ts>.json)")
    args = parser.parse_args()

    records, errors = parse_worksheet(args.worksheet, args.rows)
    skipped = len(errors)
    print(json.dumps({
        "worksheet": str(args.worksheet),
        "adjudications": len(records),
        "errors": errors,
        "skipped": skipped,
    }, ensure_ascii=False, indent=1))
    if errors:
        print(f"!! {skipped} row(s) rejected - fix and re-import those rows", file=sys.stderr)
    if not records:
        sys.exit(1 if errors else 0)

    link_feedback = not args.no_feedback
    if args.api:
        result = _post_batch(args.api, records, link_feedback)
        target_desc = f"api:{args.api}"
    else:
        from triage_engine.core.store import Store
        store = Store(args.db) if args.db else Store()
        feedback_rows = 0
        for record in records:
            store.save_adjudication(record)
            if link_feedback:
                for alert_id in record["alert_ids"]:
                    store.save_feedback({
                        "alert_id": alert_id,
                        "feedback_type": "soc_adjudication",
                        "human_verdict": record["soc_verdict"],
                        "override_reason": record["disposition"],
                        "payload": {
                            "family_id": record["family_id"],
                            "family_key": record.get("family_key"),
                            "days": record.get("days"),
                            "engine_route": record.get("engine_route"),
                            "source_worksheet": record.get("source_worksheet"),
                            "adjudicator": record.get("adjudicator"),
                            "notes": record.get("notes"),
                        },
                    })
                    feedback_rows += 1
        result = {"imported": len(records),
                  "family_ids": [r["family_id"] for r in records],
                  "feedback_rows": feedback_rows}
        target_desc = f"db:{store.path}"
        store.close()

    receipt = {
        "imported_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "worksheet": str(args.worksheet),
        "rows_files": [str(p) for p in args.rows],
        "target": target_desc,
        "result": result,
        "records": records,
        "errors": errors,
    }
    receipt_out = Path(args.receipt_out) if args.receipt_out else Path(
        f"data/reports/adjudications_{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}.json")
    receipt_out.parent.mkdir(parents=True, exist_ok=True)
    receipt_out.write_text(json.dumps(receipt, indent=1, ensure_ascii=False))
    print(json.dumps({"imported": result["imported"],
                      "feedback_rows": result["feedback_rows"],
                      "receipt": str(receipt_out), "target": target_desc},
                     ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
