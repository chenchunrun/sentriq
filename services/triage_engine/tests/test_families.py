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

"""Alert-family grouping tests (SOC adjudication loop, step 1).

The Tailscale-CGNAT postmortem (shadow day 0921): the same 告警名称 with
varying source IPs inside 100.64.0.0/10 got opposite labels on different
days. A raw (name, srcIp, dstIp, domain) key fragments that family into
per-IP singletons; the scope-based key must collapse it into one family.
"""

from triage_engine.evaluation.families import (
    cell_values,
    detect_twin_families,
    family_id,
    family_key_from_ngsoc,
    family_key_from_row,
    ip_scope,
    truth_from_triage,
)


def test_ip_scope_cgnat_private_public_invalid():
    assert ip_scope("100.96.1.7") == "CGNAT覆盖网"
    assert ip_scope("100.127.255.255") == "CGNAT覆盖网"
    assert ip_scope("100.128.0.1") == "公网"          # just outside 100.64.0.0/10
    assert ip_scope("10.2.3.4") == "内网"
    assert ip_scope("192.168.1.101") == "内网"
    assert ip_scope("8.8.8.8") == "公网"
    assert ip_scope("not-an-ip") == ""
    assert ip_scope("") == ""
    assert ip_scope(None) == ""


def test_cell_values_normalizes_multi_value_cells():
    assert cell_values("100.96.1.7,100.71.2.3") == ["100.71.2.3", "100.96.1.7"]
    assert cell_values(["10.2.3.4", "10.2.3.4", ""]) == ["10.2.3.4"]
    assert cell_values(" b.com , a.com ") == ["a.com", "b.com"]
    assert cell_values(None) == []
    assert cell_values([]) == []
    assert cell_values("single") == ["single"]


def _tailscale_ngsoc(src_ip, triage_result, **over):
    alert = {
        "name": "Tailscale远控命令注入攻击",
        "srcIp": src_ip,
        "dstIp": ["10.2.3.4"],
        "domain": [],
        "triageResult": triage_result,
    }
    alert.update(over)
    return alert


def test_tailscale_twins_collapse_into_one_family():
    """Same name + differing CGNAT source IPs must share one family key."""
    day_0921 = _tailscale_ngsoc(["100.96.1.7"], "有效告警:攻击成功")
    day_0913 = _tailscale_ngsoc(["100.71.2.3"], "无效告警:其他")
    k1, k2 = family_key_from_ngsoc(day_0921), family_key_from_ngsoc(day_0913)
    assert k1 == k2
    assert k1[0] == "Tailscale远控命令注入攻击"
    assert k1[1] == ["CGNAT覆盖网"]
    assert k1[2] == ["内网"]
    assert family_id(k1) == family_id(k2)


def test_raw_ip_key_would_fragment_but_scope_key_does_not():
    """Regression intent: distinct raw srcIps, identical scope -> identical id."""
    ids = {
        family_id(family_key_from_ngsoc(_tailscale_ngsoc([ip], "有效告警:攻击成功")))
        for ip in ("100.96.1.7", "100.96.1.8", "100.71.2.3")
    }
    assert len(ids) == 1
    # a genuinely different scope (public internet) is a different family
    other = family_id(family_key_from_ngsoc(_tailscale_ngsoc(["8.8.8.8"], "有效告警:攻击成功")))
    assert other not in ids


def test_multi_value_scope_sets_sorted_and_deduped():
    alert = _tailscale_ngsoc(["100.96.1.7", "100.96.1.7", "8.8.8.8"], "无效告警:规则误报")
    key = family_key_from_ngsoc(alert)
    assert key[1] == ["CGNAT覆盖网", "公网"]     # sorted scope set


def test_family_key_fixed_arity_for_missing_fields():
    alert = {"name": "x", "triageResult": "无效告警:其他"}   # no IPs, no domain
    key = family_key_from_ngsoc(alert)
    assert key == ["x", ["?"], ["?"], ""]


def test_family_id_deterministic_and_distinct():
    k = ["name", ["CGNAT覆盖网"], ["内网"], ""]
    assert family_id(k) == family_id(list(k))            # value equality, not identity
    assert family_id(k).startswith("F-") and len(family_id(k)) == 10
    assert family_id(k) != family_id(["other", ["CGNAT覆盖网"], ["内网"], ""])


def test_family_key_from_row_roundtrip():
    row = {"ngsoc": {"name": "n", "src_ip": ["100.96.1.7"], "dst_ip": ["10.2.3.4"],
                     "domain": ["A.COM"], "triage_result": "有效告警:攻击失败"}}
    alert = {"name": "n", "srcIp": ["100.96.1.7"], "dstIp": ["10.2.3.4"],
             "domain": ["a.com"], "triageResult": "有效告警:攻击失败"}
    assert family_key_from_row(row) == family_key_from_ngsoc(alert)


def test_truth_from_triage_follows_shadow_convention():
    assert truth_from_triage("无效告警:业务触发") == "benign"
    assert truth_from_triage(" 无效告警:其他 ") == "benign"
    assert truth_from_triage("有效告警:攻击成功") == "malicious"
    assert truth_from_triage("隐患:异常行为") == "malicious"
    assert truth_from_triage("需人工研判") == "malicious"   # SOC 口径: conservative placeholder


def _row(worksheet_id, day, name, src, dst, triage, route="DEEP_INVESTIGATE"):
    key = family_key_from_ngsoc({"name": name, "srcIp": [src], "dstIp": [dst],
                                 "domain": [], "triageResult": triage})
    return {
        "worksheet_id": worksheet_id,
        "day": day,
        "ngsoc": {"name": name, "src_ip": [src], "dst_ip": [dst], "domain": [],
                  "triage_result": triage},
        "truth": truth_from_triage(triage),
        "family_id": family_id(key),
        "family_key": key,
        "engine": {"route": route},
    }


def test_detect_twin_families_flags_opposite_labels():
    rows = [
        _row("SHD-20260921-00001", "20260921", "Tailscale远控命令注入攻击",
             "100.96.1.7", "10.2.3.4", "有效告警:攻击成功", route="FAST_CLOSE"),
        _row("SHD-20260913-00002", "20260913", "Tailscale远控命令注入攻击",
             "100.71.2.3", "10.2.3.4", "无效告警:其他"),
        _row("SHD-20260921-00003", "20260921", "Tailscale远控命令注入攻击",
             "100.96.9.9", "10.2.3.4", "有效告警:攻击成功"),
        _row("SHD-20260921-00004", "20260921", "常规弱口令爆破",
             "45.33.32.156", "10.0.1.10", "有效告警:攻击成功"),
        _row("SHD-20260913-00005", "20260913", "常规弱口令爆破",
             "45.33.32.157", "10.0.1.10", "有效告警:攻击失败"),
    ]
    twins = detect_twin_families(rows)
    assert len(twins) == 1
    fam = next(iter(twins.values()))
    assert fam["member_count"] == 3
    assert fam["label_counts"] == {"benign": 1, "malicious": 2}
    assert fam["per_day"]["20260921"] == {"有效告警:攻击成功": 2}
    assert fam["per_day"]["20260913"] == {"无效告警:其他": 1}
    assert sorted(fam["days"]) == ["20260913", "20260921"]


def test_detect_twin_families_skips_consistent_families():
    rows = [
        _row("SHD-20260921-00001", "20260921", "扫描器", "192.168.1.5", "10.0.9.77",
             "无效告警:业务触发", route="FAST_CLOSE"),
        _row("SHD-20260913-00002", "20260913", "扫描器", "192.168.1.5", "10.0.9.77",
             "无效告警:规则误报", route="FAST_CLOSE"),
    ]
    assert detect_twin_families(rows) == {}
