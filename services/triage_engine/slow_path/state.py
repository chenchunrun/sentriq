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

"""Slow Investigation State (requirement §14) and hypothesis model (§15).

Hypothesis posteriors are updated with a transparent multiplicative rule from
evidence links (`supports Hx / contradicts Hx`) then renormalized - auditable
by design; no hidden LLM arithmetic.
"""

import time
import uuid
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

# Default hypothesis set (requirement §15)
DEFAULT_HYPOTHESES: List[Dict[str, str]] = [
    {"id": "H0", "statement": "Legitimate administrative activity / approved change"},
    {"id": "H1", "statement": "Compromised account (stolen credentials)"},
    {"id": "H2", "statement": "Malicious software performing credential theft / propagation"},
    {"id": "H3", "statement": "Authorized penetration test or red team exercise"},
    {"id": "H4", "statement": "Detection false positive"},
]

# Deterministic keyword -> hypothesis links used to grade evidence (§15)
_HYPOTHESIS_KEYWORDS: Dict[str, List[tuple]] = {
    "H0": [
        (r"change record CHG-\d+", 0.6),
        (r"owned by|business_unit|criticality", 0.15),
        (r"routine|baseline|normal hours|consistent with baseline", 0.5),
    ],
    "H1": [
        (r"impossible travel|foreign ASN|unusual_login[: ] true", 0.7),
        (r"outside normal hours|off-hours|02:00|01:02", 0.35),
        (r"interactive logins", 0.2),
    ],
    "H2": [
        (r"lsass|PROCESS_VM_READ|mimikatz", 0.8),
        (r"-enc|base64 encoded|obfuscated", 0.6),
        (r"beacon|C2|IOC match|known botnet|newly registered", 0.6),
        (r"SMB connections to 3\+|SMB connections to [0-9]", 0.5),
        (r"webshell|ransom", 0.7),
    ],
    "H3": [
        (r"penetration|red team|authorized scan", 0.8),
    ],
    "H4": [
        (r"no IOC record|limited to known|known CDN|no anomalous|no related alerts|routine browser", 0.5),
        (r"false positive rate", 0.3),
    ],
}


class Hypothesis(BaseModel):
    id: str
    statement: str
    posterior: float = 0.2

    def apply_links(self, links: Dict[str, Dict[str, float]]) -> None:
        """Multiplicative update from evidence links; normalize externally."""
        mine = links.get(self.id, {})
        if "supports" in mine:
            self.posterior *= 1.0 + float(mine["supports"])
        if "contradicts" in mine:
            self.posterior *= max(0.05, 1.0 - 0.5 * float(mine["contradicts"]))


class HypothesisSet(BaseModel):
    hypotheses: List[Hypothesis]

    @classmethod
    def default(cls) -> "HypothesisSet":
        return cls(hypotheses=[Hypothesis(**h) for h in DEFAULT_HYPOTHESES])

    def renormalize(self) -> None:
        total = sum(h.posterior for h in self.hypotheses) or 1.0
        for h in self.hypotheses:
            h.posterior = min(1.0, h.posterior / total)

    def update(self, links: Dict[str, Dict[str, float]]) -> None:
        for h in self.hypotheses:
            h.apply_links(links)
        self.renormalize()

    def top(self) -> Hypothesis:
        return max(self.hypotheses, key=lambda h: h.posterior)

    def uncertainty(self) -> float:
        """Normalized entropy of the posterior distribution (planner input)."""
        import math

        ps = [h.posterior for h in self.hypotheses]
        total = sum(ps) or 1.0
        entropy = -sum((p / total) * math.log(p / total + 1e-12) for p in ps if p > 0)
        return entropy / math.log(len(ps)) if len(ps) > 1 else 0.0

    def snapshot(self) -> List[Dict[str, Any]]:
        return [{"id": h.id, "statement": h.statement, "posterior": round(h.posterior, 3)} for h in self.hypotheses]


def link_evidence_text(fact: str) -> Dict[str, Dict[str, float]]:
    """Deterministically grade an evidence fact against the hypothesis set (§15).

    Example return: {"H2": {"supports": 0.7}, "H0": {"contradicts": 0.5}}
    """
    import re

    links: Dict[str, Dict[str, float]] = {}
    for hyp_id, patterns in _HYPOTHESIS_KEYWORDS.items():
        support = 0.0
        for pattern, weight in patterns:
            if re.search(pattern, fact, flags=re.IGNORECASE):
                support = max(support, weight)
        if support > 0:
            links[hyp_id] = {"supports": support}
    return links


class Budget(BaseModel):
    max_steps: int = 12
    max_tool_calls: int = 8
    max_time_seconds: float = 300
    max_tokens: int = 60000
    max_cost_usd: float = 1.0
    steps_used: int = 0
    tool_calls_used: int = 0
    tokens_used: int = 0
    cost_used_usd: float = 0.0
    started_monotonic: float = Field(default_factory=time.monotonic)

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self.started_monotonic

    @property
    def exhausted(self) -> Optional[str]:
        if self.steps_used >= self.max_steps:
            return "MAX_STEPS"
        if self.tool_calls_used >= self.max_tool_calls:
            return "MAX_TOOL_CALLS"
        if self.elapsed >= self.max_time_seconds:
            return "MAX_TIME"
        if self.tokens_used >= self.max_tokens:
            return "MAX_TOKENS"
        if self.cost_used_usd >= self.max_cost_usd:
            return "MAX_COST"
        return None


class InvestigationState(BaseModel):
    case_id: str = Field(default_factory=lambda: f"CASE-{uuid.uuid4().hex[:10].upper()}")
    alert_id: str = ""
    alert_context: Dict[str, Any] = Field(default_factory=dict)
    route: str = "DEEP_INVESTIGATE"
    escalation_reasons: List[str] = Field(default_factory=list)
    hypotheses: List[Dict[str, Any]] = Field(default_factory=list)
    evidence: List[Dict[str, Any]] = Field(default_factory=list)
    timeline: List[Dict[str, Any]] = Field(default_factory=dict)
    entities: List[Dict[str, Any]] = Field(default_factory=list)
    relationships: List[Dict[str, Any]] = Field(default_factory=list)
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    open_questions: List[str] = Field(default_factory=list)
    tool_history: List[Dict[str, Any]] = Field(default_factory=list)
    budget: Dict[str, Any] = Field(default_factory=dict)
    status: str = "running"
    verdict: Optional[Dict[str, Any]] = None
    created_at: Optional[str] = None
