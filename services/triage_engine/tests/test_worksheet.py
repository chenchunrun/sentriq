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

"""Worksheet export/import tests (SOC adjudication loop, step 7)."""

import csv
import json

import pytest

from triage_engine.evaluation.families import family_id, family_key_from_ngsoc
from triage_engine.evaluation.worksheet import (
    COLUMNS,
    DISPOSITIONS,
    SOC_VERDICTS,
    export_worksheet,
    parse_worksheet,
)

_TWIN_NAME = "Tailscale远控命令注入攻击"


def _row(worksheet_id, day, name, src, dst, triage, route="DEEP_INVESTIGATE", **over):
    ngsoc = {
        "alert_id": over.pop("ngsoc_alert_id", 1),
        "file": over.pop("file", f"ngsoc-{day}.xlsx"),
        "name": name,
        "rule_category": "命令注入",
        "triage_result": triage,
        "src_ip": [src] if isinstance(src, str) else src,
        "dst_ip": [dst] if isinstance(dst, str) else dst,
        "domain": [],
        "latest_timestamp": f"2026-{day[4:6]}-{day[6:8]}T10:00:00Z",
        "attack_result": "成功",
    }
    key = family_key_from_ngsoc({"name": name, "srcIp": ngsoc["src_ip"],
                                 "dstIp": ngsoc["dst_ip"], "domain": [], "triageResult": triage})
    row = {
        "worksheet_id": worksheet_id,
        "day": day,
        "ngsoc": ngsoc,
        "truth": "benign" if triage.startswith("无效告警") else "malicious",
        "family_id": family_id(key),
        "family_key": key,
        "engine": {
            "route": route,
            "model_suggested_route": route,
            "reason_codes": ["NOVEL_BEHAVIOR"] if route != "FAST_CLOSE" else [],
            "hard_gates": [],
            "decisions": {
                "malicious": 0.71, "authorized": 0.92, "evidence_strength": 2,
                "novelty": 1, "business_impact": 0, "containment_state": 0,
                "investigation_need": 0.4, "route": "fast_close",
            },
            "state_hash": "9f3ab2c1d4e5f6a7",
            "degraded": False,
            "latency_ms": 12.3,
        },
    }
    row.update(over)
    return row


@pytest.fixture()
def rows(tmp_path):
    return [
        # twin family: opposite labels across days
        _row("SHD-20260921-00001", "20260921", _TWIN_NAME, "100.96.1.7", "10.2.3.4",
             "有效告警:攻击成功", route="FAST_CLOSE"),
        _row("SHD-20260913-00002", "20260913", _TWIN_NAME, "100.71.2.3", "10.2.3.4",
             "无效告警:其他"),
        # benign family, cleanly fast-closed
        _row("SHD-20260921-00003", "20260921", "合规漏洞扫描", "192.168.1.5", "10.0.9.77",
             "无效告警:业务触发", route="FAST_CLOSE"),
        # benign but routed deep (needs SOC attention lower priority)
        _row("SHD-20260921-00004", "20260921", "自签证书告警", "10.1.1.5", "10.1.1.9",
             "无效告警:规则误报", route="DEEP_INVESTIGATE"),
    ]


@pytest.fixture()
def rows_file(tmp_path, rows):
    path = tmp_path / "ngsoc_shadow_20260921_rows.jsonl"
    path.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in rows), encoding="utf-8")
    return path


def test_export_writes_bom_columns_and_ordering(rows_file, tmp_path):
    out = tmp_path / "ws.csv"
    summary = export_worksheet([rows_file], out)
    raw = out.read_bytes()
    assert raw[:3] == b"\xef\xbb\xbf"                      # Excel-friendly BOM
    with open(out, encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh)
        assert reader.fieldnames == COLUMNS
        data = list(reader)
    # twin family rows first (day ascending inside the family), then
    # remaining FAST_CLOSE, then the rest
    assert data[0]["worksheet_id"] == "SHD-20260913-00002"
    assert data[1]["worksheet_id"] == "SHD-20260921-00001"
    assert data[2]["worksheet_id"] == "SHD-20260921-00003"
    assert data[3]["worksheet_id"] == "SHD-20260921-00004"
    assert data[0]["is_twin_family"] == "yes"
    assert data[3]["is_twin_family"] == "no"
    # SOC columns ship empty
    for col in ("soc_verdict", "soc_disposition", "apply_to_family", "adjudicator", "notes"):
        assert data[0][col] == ""
    # engine columns populated (data[1] is the FAST_CLOSE twin row on 0921)
    assert data[1]["route"] == "FAST_CLOSE"
    assert float(data[1]["authorized"]) == 0.92
    assert data[1]["row_checksum"]
    # summary
    assert summary["rows"] == 4
    assert summary["fast_close_rows"] == 2
    assert len(summary["twin_families"]) == 1


def _fill(csv_path, edits):
    """Apply {worksheet_id: {column: value}} edits, preserving column order."""
    with open(csv_path, encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh)
        fields, rows = reader.fieldnames, list(reader)
    for row in rows:
        row.update(edits.get(row["worksheet_id"], {}))
    with open(csv_path, "w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def test_import_roundtrip_single_and_family(rows_file, tmp_path):
    out = tmp_path / "ws.csv"
    export_worksheet([rows_file], out)
    twin_row = _row("SHD-20260921-00001", "20260921", _TWIN_NAME, "100.96.1.7", "10.2.3.4",
                    "有效告警:攻击成功", route="FAST_CLOSE")
    _fill(out, {
        "SHD-20260921-00001": {"soc_verdict": "无效告警", "soc_disposition": "auto_close_ok",
                               "apply_to_family": "yes", "adjudicator": "soc.1",
                               "notes": "组网工具流量"},
        "SHD-20260921-00003": {"soc_verdict": "无效告警", "soc_disposition": "monitor",
                               "apply_to_family": "no", "adjudicator": "soc.1"},
    })
    records, errors = parse_worksheet(out, [rows_file])
    assert errors == []
    assert len(records) == 2
    by_family = {r["family_id"]: r for r in records}
    twin = by_family[twin_row["family_id"]]
    assert twin["soc_verdict"] == "无效告警"
    assert twin["disposition"] == "auto_close_ok"
    assert twin["applies_to_family"] is True
    # family expansion covered the 0913 twin member too
    assert set(twin["alert_ids"]) == {"SHD-20260921-00001", "SHD-20260913-00002"}
    assert sorted(twin["days"]) == ["20260913", "20260921"]
    single = by_family[_row("SHD-20260921-00003", "20260921", "合规漏洞扫描", "192.168.1.5",
                            "10.0.9.77", "无效告警:业务触发", route="FAST_CLOSE")["family_id"]]
    assert single["applies_to_family"] is False
    assert single["alert_ids"] == ["SHD-20260921-00003"]
    assert single["engine_route"] == "FAST_CLOSE"


def test_import_skips_blank_verdicts_without_error(rows_file, tmp_path):
    out = tmp_path / "ws.csv"
    export_worksheet([rows_file], out)          # nothing filled
    records, errors = parse_worksheet(out, [rows_file])
    assert records == [] and errors == []


def test_import_rejects_bad_enum_and_unknown_id_and_tampering(rows_file, tmp_path):
    out = tmp_path / "ws.csv"
    export_worksheet([rows_file], out)
    _fill(out, {
        "SHD-20260921-00003": {"soc_verdict": "maybe", "soc_disposition": "monitor"},
        "SHD-20260921-00004": {"soc_verdict": "有效告警", "soc_disposition": "delete-it"},
    })
    records, errors = parse_worksheet(out, [rows_file])
    assert records == []
    codes = {e["error"] for e in errors}
    assert "INVALID_VERDICT" in codes and "INVALID_DISPOSITION" in codes

    # unknown worksheet id (only meaningful for rows the SOC filled in)
    _fill(out, {"SHD-20260921-00003": {"soc_verdict": "无效告警", "soc_disposition": "monitor"}})
    with open(out, encoding="utf-8-sig", newline="") as fh:
        rows = list(csv.DictReader(fh))
    filled = next(r for r in rows if r["worksheet_id"] == "SHD-20260921-00003")
    filled["worksheet_id"] = "SHD-99999999-00001"
    _rewrite(out, rows)
    _, errors = parse_worksheet(out, [rows_file])
    assert any(e["error"] == "UNKNOWN_WORKSHEET_ID" for e in errors)
    filled["worksheet_id"] = "SHD-20260921-00003"
    _rewrite(out, rows)

    # tampered evidence column breaks the checksum
    filled["route"] = "URGENT_ESCALATE"
    _rewrite(out, rows)
    _, errors = parse_worksheet(out, [rows_file])
    assert any(e["error"] == "CHECKSUM_MISMATCH" for e in errors)


def _rewrite(path, rows):
    with open(path, encoding="utf-8-sig", newline="") as fh:
        fields = csv.DictReader(fh).fieldnames
    with open(path, "w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def test_import_rejects_conflicting_family_verdicts(rows_file, tmp_path):
    out = tmp_path / "ws.csv"
    export_worksheet([rows_file], out)
    _fill(out, {
        "SHD-20260921-00001": {"soc_verdict": "无效告警", "soc_disposition": "auto_close_ok"},
        "SHD-20260913-00002": {"soc_verdict": "有效告警", "soc_disposition": "blocklist"},
    })
    _, errors = parse_worksheet(out, [rows_file])
    assert any(e["error"] == "CONFLICTING_VERDICTS" for e in errors)


def test_import_family_expansion_requires_rows(tmp_path, rows_file):
    out = tmp_path / "ws.csv"
    export_worksheet([rows_file], out)
    _fill(out, {"SHD-20260921-00001": {"soc_verdict": "无效告警",
                                       "soc_disposition": "auto_close_ok",
                                       "apply_to_family": "yes"}})
    with pytest.raises(ValueError, match="rows"):
        parse_worksheet(out, [])


def test_enums_exported():
    assert SOC_VERDICTS == ("有效告警", "无效告警", "需复查")
    assert "auto_close_ok" in DISPOSITIONS and "blocklist" in DISPOSITIONS
