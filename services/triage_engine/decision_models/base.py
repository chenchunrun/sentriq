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

"""DecisionModelProvider abstraction (requirement §6.2).

Business code depends ONLY on DecisionModelProvider - never on a concrete
model library (`import laya` is confined to decision_models/laya.py).
"""

import hashlib
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field

ROUTES = ["FAST_CLOSE", "FAST_QUEUE", "DEEP_INVESTIGATE", "URGENT_ESCALATE", "HUMAN_REVIEW"]
CONTAINMENT_STATES = ["NOT_CONTAINED", "PARTIALLY_CONTAINED", "CONTAINED", "UNKNOWN"]


class ProviderUnavailable(Exception):
    """Raised when a provider cannot produce a usable decision."""


class DecisionContext(BaseModel):
    alert_id: str
    state_text: str
    question_version: str = ""
    deadline_ms: int = 5000
    token_budget: int = 800
    use_typed_workflow: bool = True  # security typed workflow -> typed-decisions checkpoint
    metadata: Dict[str, Any] = Field(default_factory=dict)


class DecisionResult(BaseModel):
    model_config = {"protected_namespaces": ()}

    provider: str
    model: str
    version: str = ""
    decisions: Dict[str, Union[float, str]] = Field(default_factory=dict)
    route_prediction: Dict[str, float] = Field(default_factory=dict)
    latency_ms: int = 0
    model_metadata: Dict[str, Any] = Field(default_factory=dict)
    state_hash: str = ""
    question_version: str = ""
    degraded: bool = False           # produced by a fallback path (requirement §41)
    degraded_reason: Optional[str] = None

    def p(self, name: str, default: float = 0.0) -> float:
        value = self.decisions.get(name, default)
        return float(value) if isinstance(value, (int, float)) else default

    def score(self, name: str, default: float = 0.0) -> float:
        """Score answers (0-4) are stored normalized by providers; raw via decisions."""
        return self.p(name, default)


class DecisionModelProvider(ABC):
    """All fast-decision models implement this interface."""

    name: str = "base"

    @abstractmethod
    async def decide(
        self,
        state: Dict[str, Any],
        questions: Dict[str, Dict[str, Any]],
        context: DecisionContext,
    ) -> DecisionResult:
        """Answer typed questions over a state. Must not raise on bad model output -
        return degraded=True / raise ProviderUnavailable so callers can fail safe."""


def state_hash(state_text: str) -> str:
    return hashlib.sha256(state_text.encode("utf-8")).hexdigest()[:16]


def validate_answers(
    answers: Dict[str, Any], questions: Dict[str, Dict[str, Any]]
) -> List[str]:
    """Validate raw model answers against the question registry.

    Returns a list of issues; empty list means usable. Answers may hold either
    laya-style structured values or already-flat values.
    """
    issues: List[str] = []
    for name, spec in questions.items():
        if name not in answers:
            issues.append(f"missing:{name}")
            continue
        raw = answers[name]
        # unwrap laya-style {"noul": ..} / {"score": ..} / {"choice": ..}
        if isinstance(raw, dict):
            for key in ("noul", "probability", "score", "level", "choice"):
                if key in raw:
                    raw = raw[key]
                    break
        qtype = spec.get("type")
        if qtype == "noul":
            try:
                p = float(raw)
                if not 0.0 <= p <= 1.0:
                    issues.append(f"out_of_range:{name}")
            except (TypeError, ValueError):
                issues.append(f"not_numeric:{name}")
        elif qtype == "score":
            try:
                level = float(raw)
                lo, hi = spec.get("scale", [0, 4])
                if not lo <= level <= hi:
                    issues.append(f"out_of_range:{name}")
            except (TypeError, ValueError):
                issues.append(f"not_numeric:{name}")
        elif qtype == "choice":
            if str(raw) not in spec.get("choices", []):
                issues.append(f"invalid_choice:{name}")
    return issues
