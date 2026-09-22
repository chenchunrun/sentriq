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

"""Alert State Compressor (requirement §7).

A deterministic program - NOT an LLM summarizer. Reduces an AlertContext
(potentially 5KB-1MB of raw telemetry) into a structured state of roughly
200-800 tokens that the fast model can decide on.

Retains (§7.1): alert type/time/host/user/IP/process tree/file hash/domain/
IOC/asset criticality/user privilege/change state/history frequency/blocked
state/similar count/key detection features.
Never passes through (§7.2): full syslogs, raw process command history, bulk
JSON, raw telemetry dumps.
"""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from .context import AlertContext

_MAX_FIELD_LEN = 200  # hard cap per free-text field


def _clip(value: Any, limit: int = _MAX_FIELD_LEN) -> Any:
    if isinstance(value, str) and len(value) > limit:
        return value[: limit - 3] + "..."
    return value


class CompressedState(BaseModel):
    alert_id: str
    alert_type: str
    rule_id: Optional[str] = None
    title: Optional[str] = None
    severity: str
    timestamp: Optional[str] = None
    description: Optional[str] = None
    host: Optional[str] = None
    user: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    process_tree: List[str] = Field(default_factory=list)
    file_hash: Optional[str] = None
    domain: Optional[str] = None
    ioc_hit: bool = False
    ioc_reputation: Optional[str] = None
    asset: Dict[str, Any] = Field(default_factory=dict)
    identity: Dict[str, Any] = Field(default_factory=dict)
    change_context: Dict[str, Any] = Field(default_factory=dict)
    history: Dict[str, Any] = Field(default_factory=dict)
    containment: Dict[str, Any] = Field(default_factory=dict)
    detection_features: Dict[str, Any] = Field(default_factory=dict)

    def to_text(self) -> str:
        """Deterministic text rendering used as the fast model's state input."""
        lines = [f"alert_id: {self.alert_id}", f"type: {self.alert_type}", f"severity: {self.severity}"]
        if self.rule_id:
            lines.append(f"rule_id: {self.rule_id}")
        if self.title:
            lines.append(f"title: {self.title}")
        if self.timestamp:
            lines.append(f"timestamp: {self.timestamp}")
        if self.description:
            lines.append(f"description: {self.description}")
        for label, value in (
            ("host", self.host),
            ("user", self.user),
            ("source_ip", self.source_ip),
            ("destination_ip", self.destination_ip),
            ("file_hash", self.file_hash),
            ("domain", self.domain),
        ):
            if value:
                lines.append(f"{label}: {value}")
        if self.process_tree:
            lines.append("process_tree: " + " -> ".join(self.process_tree))
        lines.append(f"ioc_hit: {str(self.ioc_hit).lower()}")
        if self.ioc_reputation:
            lines.append(f"ioc_reputation: {self.ioc_reputation}")
        for section in ("asset", "identity", "change_context", "history", "containment"):
            for key, value in getattr(self, section).items():
                lines.append(f"{key}: {value}")
        if self.detection_features:
            feats = " ".join(f"{k}={v}" for k, v in sorted(self.detection_features.items()))
            lines.append(f"detection_features: {feats}")
        return "\n".join(lines)

    def token_estimate(self) -> int:
        return max(1, len(self.to_text()) // 4)


def compress(context: AlertContext, raw: Optional[Dict[str, Any]] = None) -> CompressedState:
    """Build the compressed state from an AlertContext.

    `raw` may carry extra detection features (process tree, connection counts)
    already extracted by upstream collectors; only whitelisted keys survive.
    """
    raw = raw or {}
    tree = [str(p) for p in (raw.get("process_tree") or [])][:6]

    detection_features: Dict[str, Any] = {}
    for key in (
        "connection_count",
        "bytes_out",
        "failed_logins",
        "new_process",
        "persistence_key",
        "multiple_hosts_count",
        "off_hours",
    ):
        if raw.get(key) is not None:
            detection_features[key] = _clip(raw[key], 60)
    detection_features.update(context.flags.model_dump())

    return CompressedState(
        alert_id=context.alert.id,
        alert_type=context.alert.alert_type,
        rule_id=context.alert.rule_id,
        title=_clip(context.alert.title),
        severity=context.alert.severity,
        timestamp=context.alert.timestamp,
        description=_clip(context.alert.description),
        host=context.entities.host.get("id"),
        user=context.entities.user.get("id"),
        source_ip=context.entities.source_ip.get("value"),
        destination_ip=context.entities.destination_ip.get("value"),
        process_tree=tree,
        file_hash=context.entities.file.get("hash"),
        domain=context.entities.domain.get("value"),
        ioc_hit=context.threat_intel.ioc_hit,
        ioc_reputation=context.threat_intel.reputation,
        asset={
            "asset_criticality": context.asset.criticality,
            "environment": context.asset.environment,
            "business_system": context.asset.business_system,
            "internet_exposed": context.asset.internet_exposed,
        },
        identity={
            "privileged": context.identity.privileged,
            "service_account": context.identity.service_account,
            "normal_work_hours": context.identity.normal_work_hours,
            "identity_role": context.identity.role,
        },
        change_context={"active_change": context.change_context.active_change},
        history={
            "similar_alerts_30d": context.history.similar_alerts_30d,
            "historical_false_positive_rate": context.history.historical_false_positive_rate,
        },
        containment={
            "edr_blocked": context.containment.edr_blocked,
            "process_killed": context.containment.process_killed,
        },
        detection_features=detection_features,
    )
