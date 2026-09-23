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

"""Alert-family grouping for the SOC adjudication loop.

A *family* is the unit the SOC adjudicates: all alerts sharing one
``(告警名称, source scope set, destination scope set, domain)`` tuple.

Why scopes instead of raw IPs (the shadow-0921 postmortem): the residual
false closes were "opposite-label twins" - the same 告警名称 fired from
*varying* source IPs inside ``100.64.0.0/10`` (Tailscale / carrier NAT),
labeled 攻击成功 on one export day and 无效告警 on others. A raw
``(name, srcIp, dstIp, domain)`` key fragments that family into per-IP
singletons and the conflict becomes invisible; the scope-based key keeps
it one family so the SOC can rule on it once.

Known trade-off (accepted for v1): the key can over-merge distinct
incidents that share a rule name and network scopes. ``apply_to_family``
in the worksheet is the SOC's opt-in - they see the member list first.

``ip_scope`` must stay behaviorally in sync with
``finetune/generate_ngsoc_dataset.ip_scope`` (training-state
reproducibility). On the repo venv (Python 3.12) both orders of the
private/CGNAT checks are equivalent; this copy checks CGNAT first so a
future ``is_private`` that learns about shared address space cannot
silently reclassify CGNAT sources as 内网.
"""

import hashlib
import ipaddress
import json
from typing import Any, Dict, Iterable, List, Optional, Tuple

_CGNAT_LOW = ipaddress.ip_address("100.64.0.0")
_CGNAT_HIGH = ipaddress.ip_address("100.127.255.255")
_NAME_CLIP = 120
_UNKNOWN_SCOPE = "?"


def ip_scope(ip: Optional[str]) -> str:
    """Classify one IP as 内网 / CGNAT覆盖网 / 公网 ("" when unparseable)."""
    try:
        addr = ipaddress.ip_address(str(ip or "").strip())
    except ValueError:
        return ""
    if addr.version == 4 and _CGNAT_LOW <= addr <= _CGNAT_HIGH:
        return "CGNAT覆盖网"   # Tailscale / carrier NAT - frequent FP source
    if addr.is_private:
        return "内网"
    return "公网"


def cell_values(value: Any) -> List[str]:
    """Normalize an etl multi-value cell (list | comma-joined str | None).

    Returns sorted, stripped, deduplicated non-empty values so key order
    never matters ("a,b" == "b,a" == ["b", "a"]).
    """
    if value is None:
        return []
    parts = value if isinstance(value, (list, tuple)) else str(value).split(",")
    return sorted({str(p).strip() for p in parts if str(p or "").strip()})


def scope_set(value: Any) -> List[str]:
    """Sorted set of IP scopes for a multi-value cell ("?" when unknown)."""
    scopes = {ip_scope(ip) for ip in cell_values(value)}
    scopes.discard("")
    return sorted(scopes) or [_UNKNOWN_SCOPE]


def truth_from_triage(triage_result: Any) -> str:
    """Coarse truth label (same 口径 as shadow replay): 无效告警:* -> benign."""
    tri = str(triage_result or "").strip()
    return "benign" if tri.startswith("无效告警") else "malicious"


def family_key_from_ngsoc(alert: Dict[str, Any]) -> List[Any]:
    """Family key from a raw NGSOC alert dict (etl canonical field names)."""
    name = str(alert.get("name") or "").strip()[:_NAME_CLIP]
    domain = cell_values(alert.get("domain"))
    return [name, scope_set(alert.get("srcIp")), scope_set(alert.get("dstIp")),
            domain[0].lower() if domain else ""]


def family_key_from_row(row: Dict[str, Any]) -> List[Any]:
    """Family key from a shadow-rows JSONL row (``ngsoc`` sub-dict)."""
    ngsoc = row.get("ngsoc") or {}
    return family_key_from_ngsoc({
        "name": ngsoc.get("name"),
        "srcIp": ngsoc.get("src_ip"),
        "dstIp": ngsoc.get("dst_ip"),
        "domain": ngsoc.get("domain"),
    })


def family_id(key: List[Any]) -> str:
    """Stable family identifier ``F-<sha256[:8]>`` (store primary key)."""
    blob = json.dumps(key, ensure_ascii=False, separators=(",", ":"))
    return "F-" + hashlib.sha256(blob.encode("utf-8")).hexdigest()[:8]


def _row_truth(row: Dict[str, Any]) -> str:
    truth = row.get("truth")
    if truth in ("benign", "malicious"):
        return truth
    return truth_from_triage((row.get("ngsoc") or {}).get("triage_result"))


def detect_twin_families(rows: Iterable[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """Find families whose members carry *both* coarse truths.

    Returns ``{family_id: {family_key, name, member_count, label_counts,
    per_day, days, routes}}`` - the per-day label counts are the evidence
    the SOC sees on the worksheet (e.g. 0921=有效告警:攻击成功 vs
    0913=无效告警:其他).
    """
    grouped: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        key = row.get("family_key") or family_key_from_row(row)
        fid = row.get("family_id") or family_id(key)
        entry = grouped.setdefault(fid, {
            "family_key": key, "name": (row.get("ngsoc") or {}).get("name") or key[0],
            "member_count": 0, "label_counts": {"benign": 0, "malicious": 0},
            "per_day": {}, "days": set(), "routes": {},
        })
        entry["member_count"] += 1
        entry["label_counts"][_row_truth(row)] += 1
        day = str(row.get("day") or "")
        tri = str((row.get("ngsoc") or {}).get("triage_result") or "?")
        if day:
            entry["days"].add(day)
            day_counts = entry["per_day"].setdefault(day, {})
            day_counts[tri] = day_counts.get(tri, 0) + 1
        route = str((row.get("engine") or {}).get("route") or "?")
        entry["routes"][route] = entry["routes"].get(route, 0) + 1
    twins = {
        fid: {**entry, "days": sorted(entry["days"])}
        for fid, entry in grouped.items()
        if entry["label_counts"]["benign"] > 0 and entry["label_counts"]["malicious"] > 0
    }
    return twins
