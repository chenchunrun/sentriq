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

"""Policy Engine (requirement §25/§26).

Final verdicts never translate directly into actions. Action Decision =
Verdict + Asset Criticality + Identity Risk + Action Risk + Policy ->
AUTO / APPROVAL_REQUIRED / MANUAL / DENY.

V1 automation boundary: only whitelisted low-risk actions run automatically;
high-risk actions always require human approval. The LLM never owns execution
authority (requirement §40).
"""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from ..core.registry import registry

AUTO = "AUTO"
APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
MANUAL = "MANUAL"
DENY = "DENY"


class ActionProposal(BaseModel):
    action: str
    rationale: Optional[str] = None


class ActionDecision(BaseModel):
    action: str
    mode: str                       # AUTO | APPROVAL_REQUIRED | MANUAL | DENY
    policy_version: str
    reasons: List[str] = Field(default_factory=list)
    approver_required: bool = False


def evaluate_action(
    action: str,
    verdict: Optional[Dict[str, Any]] = None,
    state: Optional[Dict[str, Any]] = None,
    policy: Optional[Dict[str, Any]] = None,
) -> ActionDecision:
    """Decide the execution mode for a proposed action."""
    cfg = policy or registry.policy
    auto_allowed = set(cfg.get("auto_allowed_actions", []))
    approval = set(cfg.get("approval_required_actions", []))

    reasons: List[str] = []
    asset = (state or {}).get("asset", {}) or {}
    identity = (state or {}).get("identity", {}) or {}

    if action in approval:
        # high-risk action: always human approval (requirement §26)
        reasons.append("action_in_approval_list")
        if asset.get("asset_criticality") == "critical":
            reasons.append("critical_asset")
        if identity.get("privileged"):
            reasons.append("privileged_identity")
        return ActionDecision(
            action=action, mode=APPROVAL_REQUIRED, policy_version=cfg.get("version", ""),
            reasons=reasons, approver_required=True,
        )

    if action in auto_allowed:
        # V1 whitelist still escalates to approval on critical contexts
        if verdict and str(verdict.get("verdict", "")).upper() == "MALICIOUS" and asset.get("asset_criticality") == "critical":
            reasons.extend(["critical_asset", "malicious_verdict"])
            return ActionDecision(
                action=action, mode=APPROVAL_REQUIRED, policy_version=cfg.get("version", ""),
                reasons=reasons, approver_required=True,
            )
        return ActionDecision(action=action, mode=AUTO, policy_version=cfg.get("version", ""), reasons=reasons)

    # unknown action: manual handling, never deny innovation silently
    return ActionDecision(
        action=action, mode=MANUAL, policy_version=cfg.get("version", ""),
        reasons=["action_not_in_policy_lists"],
    )


def evaluate_proposals(
    proposals: List[ActionProposal],
    verdict: Optional[Dict[str, Any]] = None,
    state: Optional[Dict[str, Any]] = None,
) -> List[ActionDecision]:
    return [evaluate_action(p.action, verdict, state) for p in proposals]
