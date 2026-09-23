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

"""Recalibration tests (SOC adjudication loop, step 16) - no weights needed."""

import asyncio
import json
from types import SimpleNamespace

from triage_engine.evaluation.families import family_id, family_key_from_ngsoc
from triage_engine.finetune.recalibrate import (
    build_report,
    build_sweep_population,
    load_adjudications,
    suppression_candidates,
    verdict_to_truth,
)

_TWIN_NAME = "Tailscale远控命令注入攻击"


def _row(worksheet_id, day, name, src, dst, triage, route="DEEP_INVESTIGATE", truth=None):
    key = family_key_from_ngsoc({"name": name, "srcIp": [src], "dstIp": [dst],
                                 "domain": [], "triageResult": triage})
    return {
        "worksheet_id": worksheet_id,
        "day": day,
        "ngsoc": {"name": name, "src_ip": [src], "dst_ip": [dst], "domain": [],
                  "triage_result": triage},
        "truth": truth or ("benign" if triage.startswith("无效告警") else "malicious"),
        "family_id": family_id(key),
        "family_key": key,
        "engine": {
            "route": route, "reason_codes": [], "hard_gates": [],
            "model_suggested_route": route,
            "decisions": {"malicious": 0.05 if route == "FAST_CLOSE" else 0.7,
                          "authorized": 0.93 if route == "FAST_CLOSE" else 0.2},
            "state_hash": "abc", "degraded": False, "latency_ms": 5.0,
        },
        "raw_alert": {"alert_id": worksheet_id, "alert_type": "anomaly"},
    }


def _adjudication(fid, verdict, disposition="auto_close_ok", **over):
    record = {
        "family_id": fid, "soc_verdict": verdict, "disposition": disposition,
        "alert_ids": [], "applies_to_family": True, "days": [],
    }
    record.update(over)
    return record


def _twin_fid(src="100.96.1.7"):
    return family_id(family_key_from_ngsoc({"name": _TWIN_NAME, "srcIp": [src],
                                            "dstIp": ["10.2.3.4"], "domain": [],
                                            "triageResult": "有效告警:攻击成功"}))


def test_verdict_to_truth_mapping():
    assert verdict_to_truth("无效告警") == "benign"
    assert verdict_to_truth("有效告警") == "malicious"
    assert verdict_to_truth("需复查") is None


def test_corrections_flip_twin_family_to_benign():
    # the 0921 postmortem shape: 2 false closes from the twin family
    rows = [
        _row("SHD-20260921-00001", "20260921", _TWIN_NAME, "100.96.1.7", "10.2.3.4",
             "有效告警:攻击成功", route="FAST_CLOSE"),
        _row("SHD-20260921-00002", "20260921", _TWIN_NAME, "100.71.2.3", "10.2.3.4",
             "有效告警:攻击成功", route="FAST_CLOSE"),
        _row("SHD-20260913-00003", "20260913", _TWIN_NAME, "100.71.2.3", "10.2.3.4",
             "无效告警:其他"),
        _row("SHD-20260921-00004", "20260921", "合规漏洞扫描", "192.168.1.5", "10.0.9.77",
             "无效告警:业务触发", route="FAST_CLOSE"),
    ]
    adjudications = [_adjudication(_twin_fid(), "无效告警", "auto_close_ok")]
    report = build_report(rows, adjudications)

    # before: 2 false closes; after the adjudication: 0
    assert report["metrics_before"]["false_close_rate"] == round(2 / 4, 4)
    assert report["metrics_after"]["false_close_rate"] == 0.0
    changes = report["corrections"]["label_changes"]
    assert {(c["worksheet_id"], c["to"]) for c in changes} == {
        ("SHD-20260921-00001", "benign"), ("SHD-20260921-00002", "benign")}
    assert all(c["reason"] == _twin_fid() for c in changes)
    assert len(report["corrections"]["families"]) == 1


def test_promotion_hold_when_twin_family_unadjudicated():
    rows = [
        _row("SHD-20260921-00001", "20260921", _TWIN_NAME, "100.96.1.7", "10.2.3.4",
             "有效告警:攻击成功", route="FAST_CLOSE"),
        _row("SHD-20260913-00002", "20260913", _TWIN_NAME, "100.71.2.3", "10.2.3.4",
             "无效告警:其他"),
    ]
    report = build_report(rows, adjudications=[])
    assert report["promotion"]["verdict"] == "HOLD"
    blockers = " ".join(report["promotion"]["blockers"])
    assert "twin" in blockers
    assert "false_close" in blockers or "unadjudicated" in blockers


def test_promotion_ready_when_adjudicated_and_safe():
    rows = [
        _row("SHD-20260921-00001", "20260921", _TWIN_NAME, "100.96.1.7", "10.2.3.4",
             "有效告警:攻击成功", route="FAST_CLOSE"),
        _row("SHD-20260913-00002", "20260913", _TWIN_NAME, "100.71.2.3", "10.2.3.4",
             "无效告警:其他"),
        _row("SHD-20260921-00003", "20260921", "合规漏洞扫描", "192.168.1.5", "10.0.9.77",
             "无效告警:业务触发", route="FAST_CLOSE"),
    ]
    scan_fid = family_id(family_key_from_ngsoc({"name": "合规漏洞扫描", "srcIp": ["192.168.1.5"],
                                                "dstIp": ["10.0.9.77"], "domain": [],
                                                "triageResult": "无效告警:业务触发"}))
    adjudications = [
        _adjudication(_twin_fid(), "无效告警", "auto_close_ok"),
        _adjudication(scan_fid, "无效告警", "monitor"),
    ]
    report = build_report(rows, adjudications)
    assert report["promotion"]["verdict"] == "READY"
    assert report["metrics_after"]["false_close_rate"] == 0.0
    assert report["suggested_thresholds_yaml"].startswith("thresholds:")
    assert "version:" in report["suggested_thresholds_yaml"]


def test_promotion_hold_when_fast_close_family_not_adjudicated():
    rows = [
        _row("SHD-20260921-00003", "20260921", "合规漏洞扫描", "192.168.1.5", "10.0.9.77",
             "无效告警:业务触发", route="FAST_CLOSE"),
    ]
    report = build_report(rows, adjudications=[])
    assert report["promotion"]["verdict"] == "HOLD"
    assert any("FAST_CLOSE" in b for b in report["promotion"]["blockers"])


def test_suppression_candidates_only_benign_and_safe_dispositions():
    fid_a, fid_b = "F-aaaa0001", "F-bbbb0002"
    adjudications = [
        _adjudication(fid_a, "无效告警", "auto_close_ok"),
        _adjudication(fid_b, "无效告警", "blocklist"),
        _adjudication("F-cccc0003", "有效告警", "suppress"),
    ]
    suppress, blocklist = suppression_candidates(adjudications)
    assert [c["family_id"] for c in suppress] == [fid_a]
    assert [c["family_id"] for c in blocklist] == [fid_b]   # benign blocklist -> approval list


def test_build_sweep_population_corrected_mode_prioritizes():
    rows = [
        _row("R1", "20260921", _TWIN_NAME, "100.96.1.7", "10.2.3.4",
             "有效告警:攻击成功", route="FAST_CLOSE"),
        _row("R2", "20260921", "扫描器", "192.168.1.5", "10.0.9.77",
             "无效告警:业务触发", route="DEEP_INVESTIGATE"),
        _row("R3", "20260921", "自签证书", "10.1.1.5", "10.1.1.9",
             "无效告警:规则误报", route="DEEP_INVESTIGATE"),
    ]
    flipped = {"R1"}
    population = build_sweep_population(rows, flipped_ids=flipped, mode="corrected", cap=2)
    ids = [r["worksheet_id"] for r in population]
    assert "R1" in ids                                  # flipped label always in
    assert len(population) <= 2
    assert ids.count("R1") == 1                         # no duplicates


def test_report_roundtrips_as_json():
    rows = [_row("R1", "20260921", "扫描器", "192.168.1.5", "10.0.9.77",
                 "无效告警:业务触发", route="FAST_CLOSE")]
    fid = rows[0]["family_id"]
    report = build_report(rows, [_adjudication(fid, "无效告警", "monitor")])
    blob = json.dumps(report, ensure_ascii=False)       # must be JSON-serializable
    assert json.loads(blob)["promotion"]["verdict"] == "READY"


def test_load_adjudications_accepts_three_shapes(tmp_path):
    records = [_adjudication("F-aaaa0001", "有效告警", "monitor")]
    for i, payload in enumerate((records, {"records": records}, {"data": records})):
        path = tmp_path / f"adj_{i}.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        assert load_adjudications(path) == records


def test_promotion_hold_when_twin_marked_recheck():
    rows = [
        _row("SHD-20260921-00001", "20260921", _TWIN_NAME, "100.96.1.7", "10.2.3.4",
             "有效告警:攻击成功", route="DEEP_INVESTIGATE"),
        _row("SHD-20260913-00002", "20260913", _TWIN_NAME, "100.71.2.3", "10.2.3.4",
             "无效告警:其他"),
    ]
    report = build_report(rows, [_adjudication(_twin_fid(), "需复查", "monitor")])
    assert report["promotion"]["verdict"] == "HOLD"
    assert any("需复查" in b for b in report["promotion"]["blockers"])


def test_sweep_best_combo_feeds_yaml_suggestion():
    rows = [_row("R1", "20260921", "扫描器", "192.168.1.5", "10.0.9.77",
                 "无效告警:业务触发", route="FAST_CLOSE")]
    fid = rows[0]["family_id"]
    sweep = [
        {"authorized_min": 0.9, "malicious_max": 0.1, "require_similar_history": False,
         "fast_close": 3, "fast_queue": 1, "fast_path_coverage": 0.8,
         "false_close_rate": 0.0},
        {"authorized_min": 0.8, "malicious_max": 0.2, "require_similar_history": False,
         "fast_close": 5, "fast_queue": 1, "fast_path_coverage": 0.95,
         "false_close_rate": 0.0},
    ]
    report = build_report(rows, [_adjudication(fid, "无效告警", "monitor")],
                          sweep_results=sweep, sweep_meta={"population_size": 10})
    assert report["sweep"]["best_safe"]["authorized_min"] == 0.8
    assert "authorized_min: 0.8" in report["suggested_thresholds_yaml"]
    assert "require_similar_history: false" in report["suggested_thresholds_yaml"]
    assert report["sweep"]["population_size"] == 10


def test_cli_run_with_rule_provider_end_to_end(tmp_path):
    rows = [
        _row("SHD-20260921-00001", "20260921", _TWIN_NAME, "100.96.1.7", "10.2.3.4",
             "有效告警:攻击成功", route="FAST_CLOSE"),
        _row("SHD-20260913-00002", "20260913", _TWIN_NAME, "100.71.2.3", "10.2.3.4",
             "无效告警:其他"),
        _row("SHD-20260921-00003", "20260921", "合规漏洞扫描", "192.168.1.5", "10.0.9.77",
             "无效告警:业务触发", route="FAST_CLOSE"),
    ]
    rows_file = tmp_path / "rows.jsonl"
    rows_file.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in rows),
                         encoding="utf-8")
    scan_fid = rows[2]["family_id"]
    receipt = tmp_path / "receipt.json"
    receipt.write_text(json.dumps({"records": [
        _adjudication(_twin_fid(), "无效告警", "auto_close_ok"),
        _adjudication(scan_fid, "无效告警", "monitor"),
    ]}), encoding="utf-8")
    out = tmp_path / "recal.json"

    from triage_engine.finetune.recalibrate import run
    args = SimpleNamespace(rows=[rows_file], adjudications=str(receipt), out=str(out),
                           provider="rule", model=None, grid="tiny",
                           sweep_set="corrected", max_sweep=400)
    report = asyncio.run(run(args))

    assert report["metrics_after"]["false_close_rate"] == 0.0
    assert report["promotion"]["verdict"] == "READY"
    assert report["sweep"]["provider"] == "rule"
    assert json.loads(out.read_text(encoding="utf-8"))["promotion"]["verdict"] == "READY"
