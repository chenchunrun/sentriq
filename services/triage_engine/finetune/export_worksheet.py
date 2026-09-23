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

"""Export the SOC adjudication worksheet from shadow-replay rows JSONL.

Usage (repo root):
    PYTHONPATH=services venv/bin/python services/triage_engine/finetune/export_worksheet.py \
        --rows data/reports/ngsoc_shadow_20260921_rows.jsonl \
        [--rows data/reports/ngsoc_shadow_20260913_rows.jsonl ...]

Twin families (same family, opposite NGSOC labels across days - the 0921
postmortem pattern) sort to the top so the SOC rules on them first.
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from triage_engine.evaluation.worksheet import export_worksheet, load_rows  # noqa: E402
from triage_engine.evaluation.families import detect_twin_families  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rows", action="append", required=True, type=Path,
                        help="shadow rows JSONL (repeatable, multiple days)")
    parser.add_argument("--out", default=None,
                        help="output CSV (default: data/reports/soc_worksheet_<day>.csv)")
    args = parser.parse_args()

    days = sorted({str(r.get("day")) for r in load_rows(args.rows) if r.get("day")})
    out = Path(args.out) if args.out else Path(
        f"data/reports/soc_worksheet_{'_'.join(days) if days else 'unknown'}.csv")

    summary = export_worksheet(args.rows, out)

    twins = detect_twin_families(load_rows(args.rows))
    print(json.dumps({
        "worksheet": summary["worksheet"], "rows": summary["rows"],
        "families": summary["families"], "fast_close_rows": summary["fast_close_rows"],
        "twin_families": len(summary["twin_families"]),
    }, ensure_ascii=False, indent=1))
    for fid in sorted(twins):
        fam = twins[fid]
        print(f"  twin {fid}  {fam['name']}  members={fam['member_count']} "
              f"labels={fam['label_counts']} days={fam['days']}")
        for day, counts in sorted(fam["per_day"].items()):
            print(f"    {day}: {counts}")


if __name__ == "__main__":
    main()
