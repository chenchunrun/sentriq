# Copyright 2026 CCR <chenchunrun@gmail.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may no use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Slow Path stop conditions (requirement §23).

A: Evidence sufficient  B: Hypothesis converged  C: No more useful evidence
D: Budget limit         E: Human required
The agent may never loop forever.
"""

from dataclasses import dataclass
from typing import Optional

from ..core.registry import registry
from .state import Budget, HypothesisSet


@dataclass
class StopDecision:
    finished: bool
    reason: str = ""


def evaluate_stop(
    hypotheses: HypothesisSet,
    budget: Budget,
    evidence_count: int,
    no_more_tools: bool,
    tool_failures: int = 0,
    min_evidence: int = 3,
) -> StopDecision:
    stop_cfg = registry.stop_conditions
    converged_at = float(stop_cfg.get("hypothesis_converged", 0.85))

    # D. budget limit (also returns which budget tripped)
    budget_reason = budget.exhausted
    if budget_reason:
        return StopDecision(True, f"BUDGET_{budget_reason}")

    # E. human required - tooling is failing
    if tool_failures >= 3:
        return StopDecision(True, "HUMAN_REQUIRED_TOOL_FAILURES")

    # B. hypothesis converged
    top = hypotheses.top()
    if top.posterior >= converged_at and evidence_count >= min_evidence:
        return StopDecision(True, f"HYPOTHESIS_CONVERGED_{top.id}_{top.posterior:.2f}")

    # C. no more useful evidence obtainable
    if no_more_tools:
        return StopDecision(True, "NO_MORE_USEFUL_EVIDENCE")

    return StopDecision(False)
