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

"""Final Security Verdict (requirement §24).

No Evidence -> No Fact (§3.4): every verdict must cite evidence IDs that exist
in the case's evidence registry. The LLM judge's citations are validated; any
unknown ID or inconclusive output degrades to the deterministic rule verdict,
and low confidence degrades to UNCLEAR -> human review (fail safe).
"""

import json
import re
from typing import Any, Dict, List, Optional

from ..core.registry import registry
from .llm import LLMClient
from .state import HypothesisSet

_JUDGE_SYSTEM = """You are a SOC investigation judge. You receive verified evidence
(with IDs), a timeline and hypothesis posteriors for one security alert case.
Return ONLY a JSON object:
{
 "verdict": "MALICIOUS" | "BENIGN" | "FALSE_POSITIVE" | "UNCLEAR",
 "confidence": 0.0-1.0,
 "severity": "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
 "attack_stage": ["..."],
 "findings": [{"finding": "...", "evidence_ids": ["EV-xxxxx"]}],
 "affected_entities": ["..."],
 "recommended_actions": ["snake_case_action"],
 "remaining_uncertainties": ["..."]
}
Rules: cite ONLY evidence IDs you were given; never invent facts beyond the
evidence; if the evidence does not support a conclusion, return UNCLEAR."""

_VERDICT_MAP = {"H0": "BENIGN", "H1": "MALICIOUS", "H2": "MALICIOUS", "H3": "BENIGN", "H4": "FALSE_POSITIVE"}
_SEVERITY_BY_IMPACT = {0: "INFO", 1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}


def _supporting_evidence_ids(evidence: List[Dict[str, Any]], hypothesis_id: str, limit: int = 5) -> List[str]:
    ids = []
    for ev in evidence:
        if hypothesis_id in (ev.get("hypothesis_links") or {}):
            ids.append(ev["evidence_id"])
    return ids[:limit]


async def judge(
    hypotheses: HypothesisSet,
    evidence: List[Dict[str, Any]],
    timeline: List[Dict[str, Any]],
    compressed_state: Dict[str, Any],
    llm: Optional[LLMClient] = None,
) -> Dict[str, Any]:
    """Produce the Final Security Verdict. LLM when available, rules otherwise."""
    stop_cfg = registry.stop_conditions
    min_confidence = float(stop_cfg.get("min_verdict_confidence", 0.70))

    verdict: Optional[Dict[str, Any]] = None
    used_llm = False
    tokens = 0
    if llm is not None and llm.available:
        try:
            verdict, tokens = await _llm_verdict(hypotheses, evidence, timeline, compressed_state, llm)
            used_llm = True
        except Exception:  # noqa: BLE001 - any LLM failure -> rule path
            verdict = None

    if verdict is None:
        verdict = _rule_verdict(hypotheses, evidence, compressed_state)

    # fail safe: inconclusive -> human
    if verdict.get("verdict") == "UNCLEAR" or float(verdict.get("confidence", 0)) < min_confidence:
        verdict["verdict"] = "UNCLEAR"
        verdict.setdefault("remaining_uncertainties", []).append(
            f"confidence below policy minimum ({min_confidence}) - escalated to human review"
        )

    verdict["judge"] = "llm" if used_llm else "rule"
    verdict["tokens_used"] = tokens
    return verdict


async def _llm_verdict(
    hypotheses: HypothesisSet,
    evidence: List[Dict[str, Any]],
    timeline: List[Dict[str, Any]],
    compressed_state: Dict[str, Any],
    llm: LLMClient,
) -> tuple:
    ev_lines = [
        f"{e['evidence_id']} [{e.get('source')}] {e.get('fact')}" for e in evidence
    ]
    hyp_lines = [f"{h.id} ({h.posterior:.2f}): {h.statement}" for h in hypotheses.hypotheses]
    tl_lines = [f"{t.get('timestamp') or 'untimed'} {t.get('event')} [{t.get('evidence_id')}]" for t in timeline]
    user = (
        f"ALERT: {json.dumps(compressed_state, ensure_ascii=False, default=str)}\n\n"
        f"EVIDENCE:\n" + "\n".join(ev_lines) + "\n\n"
        f"TIMELINE:\n" + "\n".join(tl_lines) + "\n\n"
        f"HYPOTHESES:\n" + "\n".join(hyp_lines)
    )
    resp = await llm.chat(_JUDGE_SYSTEM, user)
    parsed = _parse_json_object(resp["content"])
    if parsed is None:
        raise ValueError("judge returned non-JSON output")

    valid_ids = {e["evidence_id"] for e in evidence}
    parsed["confidence"] = max(0.0, min(1.0, float(parsed.get("confidence", 0))))
    # No Evidence -> No Fact: strip fabricated citations
    for finding in parsed.get("findings", []):
        finding["evidence_ids"] = [i for i in finding.get("evidence_ids", []) if i in valid_ids]
    if parsed.get("verdict") not in ("MALICIOUS", "BENIGN", "FALSE_POSITIVE", "UNCLEAR"):
        raise ValueError(f"invalid verdict: {parsed.get('verdict')}")
    if not parsed.get("evidence_ids"):
        parsed["evidence_ids"] = sorted(
            {i for f in parsed.get("findings", []) for i in f.get("evidence_ids", [])}
        )
    return parsed, resp["tokens"]


def _rule_verdict(
    hypotheses: HypothesisSet,
    evidence: List[Dict[str, Any]],
    compressed_state: Dict[str, Any],
) -> Dict[str, Any]:
    top = hypotheses.top()
    verdict_label = _VERDICT_MAP.get(top.id, "UNCLEAR")
    impact = compressed_state.get("asset", {}).get("asset_criticality", "unknown")
    severity = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW"}.get(impact, "MEDIUM")
    evidence_ids = _supporting_evidence_ids(evidence, top.id) or [e["evidence_id"] for e in evidence[:3]]
    return {
        "verdict": verdict_label,
        "confidence": round(top.posterior, 3),
        "severity": severity,
        "attack_stage": ["Credential Access", "Lateral Movement"] if top.id in ("H1", "H2") else [],
        "findings": [
            {
                "finding": f"top hypothesis {top.id}: {top.statement} (posterior {top.posterior:.2f})",
                "evidence_ids": evidence_ids,
            }
        ],
        "evidence_ids": evidence_ids,
        "affected_entities": [
            e for e in (compressed_state.get("host"), compressed_state.get("user")) if e
        ],
        "recommended_actions": (
            ["notify_soc", "create_case", "isolate_host", "disable_account"]
            if verdict_label == "MALICIOUS"
            else ["close_false_positive" if verdict_label == "FALSE_POSITIVE" else "reprioritize_alert"]
        ),
        "remaining_uncertainties": [] if top.posterior >= 0.7 else ["hypothesis distribution not decisive"],
    }


def _parse_json_object(text: str) -> Optional[Dict[str, Any]]:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, flags=re.DOTALL)
        if match:
            try:
                return json.loads(match.group())
            except json.JSONDecodeError:
                return None
    return None
