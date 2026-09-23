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

"""Fast path orchestration (requirement §27).

Alert -> Normalize(Context) -> Compress -> Fast Decision -> Hard Gate ->
Decision Router -> (observability record). The slow path is triggered by the
caller when the route is DEEP_INVESTIGATE / URGENT_ESCALATE.
"""

import time
from typing import Any, Dict, Optional

from ..core import gate as gate_mod
from ..core import router as router_mod
from ..core.compressor import CompressedState, compress
from ..core.context import AlertContext
from ..core.registry import registry
from ..core.store import get_store
from ..decision_models import DecisionModelProvider, decide_with_fallback
from ..decision_models.base import DecisionContext


async def triage_fast(
    raw_alert: Dict[str, Any],
    provider: Optional[DecisionModelProvider] = None,
    thresholds: Optional[Dict[str, Dict[str, Any]]] = None,
    store=None,
    persist: bool = True,
) -> Dict[str, Any]:
    """Run the fast decision pipeline for one alert. Returns the full result."""
    t0 = time.perf_counter()
    context = AlertContext.build(raw_alert)
    state: CompressedState = compress(context, raw_alert)
    state_dict = state.model_dump()

    # Training/serving skew guard: alerts ingested from external formats
    # (e.g. NGSOC) may carry the exact state text the decision model was
    # fine-tuned on - prefer it over the generic compressor rendering.
    state_text_override = raw_alert.get("state_text_override")

    decision_ctx = DecisionContext(
        alert_id=state.alert_id,
        state_text=state_text_override or state.to_text(),
        question_version=registry.question_version,
    )
    decision = await decide_with_fallback(state_dict, registry.questions, decision_ctx, provider)

    gates = gate_mod.evaluate_hard_gates(state_dict)
    routing = router_mod.route(decision, gates, state_dict, thresholds=thresholds)

    result = {
        "alert_id": state.alert_id,
        "route": routing.route,
        "reason_codes": routing.reason_codes,
        "hard_gates": routing.hard_gates,
        "decision": decision.model_dump(),
        "model_suggested_route": routing.model_suggested_route,
        "state_tokens": state.token_estimate(),
        "compressed_state": state_dict,
        "total_latency_ms": int((time.perf_counter() - t0) * 1000),
    }

    if persist:
        target = store or get_store()
        decision_id = target.save_decision({
            "alert_id": state.alert_id,
            "provider": decision.provider,
            "model": decision.model,
            "model_version": decision.version,
            "state_hash": decision.state_hash,
            "question_version": decision.question_version,
            "answers": decision.decisions,
            "route_prediction": decision.route_prediction,
            "hard_gates": routing.hard_gates,
            "router_result": routing.route,
            "router_reason": routing.reason_codes,
            "policy_version": registry.policy.get("version"),
            "latency_ms": decision.latency_ms,
        })
        result["decision_id"] = decision_id
    return result
