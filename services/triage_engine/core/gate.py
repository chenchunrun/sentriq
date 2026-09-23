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

"""Hard Gate Engine (requirement §12).

Any hit forbids FAST_CLOSE regardless of model confidence (requirement §3.3).
Gates are evaluated over the compressed state - deterministic, config-driven.
"""

from typing import Any, Dict, List

from pydantic import BaseModel, Field

from ..core.registry import registry


class HardGateResult(BaseModel):
    gates_hit: List[str] = Field(default_factory=list)
    fast_close_allowed: bool = True

    @property
    def hit(self) -> bool:
        return bool(self.gates_hit)


def evaluate_hard_gates(state: Dict[str, Any]) -> HardGateResult:
    asset = state.get("asset", {}) or {}
    identity = state.get("identity", {}) or {}
    features = state.get("detection_features", {}) or {}

    hits: List[str] = []
    if str(asset.get("asset_criticality", "")).lower() == "critical":
        hits.append("asset_critical")
    if bool(identity.get("privileged")):
        hits.append("privileged_identity")
    for gate in (
        "credential_access",
        "lateral_movement",
        "multiple_hosts",
        "active_attack",
        "data_exfiltration",
        "ransomware",
        "evidence_conflict",
        "attack_success",
        "external_to_internal",
    ):
        if bool(features.get(gate)):
            hits.append(gate)

    # keep the evaluated gate list aligned with the registry (config is source of truth)
    configured = set(registry.hard_gate_names)
    hits = [h for h in hits if h in configured]

    return HardGateResult(gates_hit=hits, fast_close_allowed=not hits)
