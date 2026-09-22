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

"""EnsembleProvider - joint decision across providers (requirement §29).

Model disagreement is itself a signal: when providers disagree on
`malicious` beyond the configured gap, the result is flagged
MODEL_DISAGREEMENT so the Decision Router escalates to the slow path.
"""

import time
from typing import Any, Dict, List

from ..core.registry import registry
from .base import (
    DecisionContext,
    DecisionModelProvider,
    DecisionResult,
    ProviderUnavailable,
)


class EnsembleProvider(DecisionModelProvider):
    name = "ensemble"

    def __init__(self, members: List[DecisionModelProvider]) -> None:
        if not members:
            raise ValueError("ensemble requires at least one member provider")
        self.members = members
        self._gap = float(registry.thresholds("ensemble").get("disagreement_gap", 0.40))

    async def decide(
        self,
        state: Dict[str, Any],
        questions: Dict[str, Dict[str, Any]],
        context: DecisionContext,
    ) -> DecisionResult:
        t0 = time.perf_counter()
        results: List[DecisionResult] = []
        errors: List[str] = []
        for member in self.members:
            try:
                results.append(await member.decide(state, questions, context))
            except ProviderUnavailable as exc:
                errors.append(f"{member.name}: {exc}")

        usable = [r for r in results if r.decisions]
        if not usable:
            raise ProviderUnavailable(f"all ensemble members failed: {errors}")

        # average numeric answers; take majority vote for categorical ones
        decisions: Dict[str, Any] = {}
        for name, spec in questions.items():
            values = [r.decisions.get(name) for r in usable if name in r.decisions]
            if not values:
                continue
            if spec["type"] in ("noul", "score"):
                decisions[name] = round(sum(float(v) for v in values) / len(values), 3)
            else:  # choice - majority vote
                counts: Dict[str, int] = {}
                for v in values:
                    counts[str(v)] = counts.get(str(v), 0) + 1
                decisions[name] = max(counts.items(), key=lambda kv: kv[1])[0]

        malicious_values = [r.p("malicious") for r in usable if "malicious" in r.decisions]
        disagreement = (
            max(malicious_values) - min(malicious_values) if malicious_values else 0.0
        )

        return DecisionResult(
            provider=self.name,
            model="+".join(r.provider for r in usable),
            version="1",
            decisions=decisions,
            route_prediction=usable[0].route_prediction,
            latency_ms=int((time.perf_counter() - t0) * 1000),
            model_metadata={
                "members": [r.provider for r in usable],
                "member_results": [r.decisions for r in usable],
                "errors": errors,
                "model_disagreement": round(disagreement, 3),
                "model_disagreement_flag": disagreement >= self._gap,
            },
            state_hash=usable[0].state_hash,
            question_version=context.question_version,
        )
