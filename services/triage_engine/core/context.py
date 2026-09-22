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

"""AlertContext - the standardized input for both fast and slow models (requirement §5).

`AlertContext.build()` normalizes a raw alert dict (SIEM/EDR-style) and enriches
it from the repository mock data files (CMDB assets, IAM users, internal IOC
list) so the engine is runnable end-to-end without external systems.
"""

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

_DEFAULT_DATA_DIR = Path(__file__).resolve().parents[2] / "data" / ".." / ".." / "data"

_SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_KEYWORD_FLAGS: list = [
    (r"lsass|credential|kerberoast|mimikatz|dump.*(password|cred)|t1003", "credential_access"),
    (r"lateral|smb.*multi|psexec|wmic.*remote|winrm|ssh.*brute|t1021", "lateral_movement"),
    (r"exfil|data.*(leak|transfer|staging)|large.*upload|t1041", "data_exfiltration"),
    (r"ransom|encrypt.*file.*mass|wannacry|lockbit|t1486", "ransomware"),
    (r"multiple hosts|multi-host|\b\d+\s*(hosts|servers)\b|spread", "multiple_hosts"),
]


def _repo_data_dir() -> Path:
    """Repository data/ directory (src layout: services/triage_engine/core -> repo/data)."""
    return Path(__file__).resolve().parents[3] / "data"


def _load_json(name: str) -> Dict[str, Any]:
    path = _repo_data_dir() / name
    if not path.exists():
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {}


class AlertInfo(BaseModel):
    id: str
    source: str = "SIEM"
    rule_id: Optional[str] = None
    title: Optional[str] = None
    alert_type: str = "unknown"
    severity: str = "medium"
    timestamp: Optional[str] = None
    description: Optional[str] = None


class Entities(BaseModel):
    host: Dict[str, Any] = Field(default_factory=dict)
    user: Dict[str, Any] = Field(default_factory=dict)
    source_ip: Dict[str, Any] = Field(default_factory=dict)
    destination_ip: Dict[str, Any] = Field(default_factory=dict)
    process: Dict[str, Any] = Field(default_factory=dict)
    file: Dict[str, Any] = Field(default_factory=dict)
    domain: Dict[str, Any] = Field(default_factory=dict)


class AssetContext(BaseModel):
    criticality: str = "unknown"  # low|medium|high|critical|unknown
    environment: Optional[str] = None
    business_system: Optional[str] = None
    internet_exposed: Optional[bool] = None
    asset_id: Optional[str] = None
    owner: Optional[str] = None


class IdentityContext(BaseModel):
    user_id: Optional[str] = None
    privileged: bool = False
    service_account: bool = False
    normal_work_hours: Optional[bool] = None
    department: Optional[str] = None
    role: Optional[str] = None


class ThreatIntelContext(BaseModel):
    ioc_hit: bool = False
    reputation: Optional[str] = None
    matched_iocs: List[str] = Field(default_factory=list)


class ChangeContext(BaseModel):
    active_change: Optional[bool] = None
    change_id: Optional[str] = None


class HistoryContext(BaseModel):
    similar_alerts_30d: int = 0
    historical_false_positive_rate: float = 0.0


class ContainmentContext(BaseModel):
    edr_blocked: bool = False
    process_killed: bool = False


class DetectionFlags(BaseModel):
    """Hard-gate inputs (requirement §12). Derived from alert content or passed explicitly."""

    credential_access: bool = False
    lateral_movement: bool = False
    multiple_hosts: bool = False
    active_attack: bool = False
    data_exfiltration: bool = False
    ransomware: bool = False
    evidence_conflict: bool = False


class AlertContext(BaseModel):
    alert: AlertInfo
    entities: Entities = Field(default_factory=Entities)
    asset: AssetContext = Field(default_factory=AssetContext)
    identity: IdentityContext = Field(default_factory=IdentityContext)
    threat_intel: ThreatIntelContext = Field(default_factory=ThreatIntelContext)
    change_context: ChangeContext = Field(default_factory=ChangeContext)
    history: HistoryContext = Field(default_factory=HistoryContext)
    containment: ContainmentContext = Field(default_factory=ContainmentContext)
    flags: DetectionFlags = Field(default_factory=DetectionFlags)

    # ------------------------------------------------------------------ build
    @classmethod
    def build(cls, raw: Dict[str, Any]) -> "AlertContext":
        """Normalize a raw alert dict + enrich from repo mock data (deterministic)."""
        alert = AlertInfo(
            id=str(raw.get("alert_id") or raw.get("id") or "ALT-UNKNOWN"),
            source=str(raw.get("source") or raw.get("alert_source") or "SIEM"),
            rule_id=raw.get("rule_id"),
            title=raw.get("title"),
            alert_type=str(raw.get("alert_type") or raw.get("type") or "unknown").lower(),
            severity=str(raw.get("severity") or "medium").lower(),
            timestamp=raw.get("timestamp"),
            description=raw.get("description") or raw.get("message"),
        )

        blob = " ".join(
            str(x) for x in (alert.alert_type, alert.rule_id, alert.title, alert.description, "") if x
        ).lower()

        flags = DetectionFlags(
            **{name: bool(re.search(pat, blob)) for pat, name in _KEYWORD_FLAGS}
        )
        if raw_flags := raw.get("flags"):
            flags = flags.model_copy(update={k: bool(v) for k, v in raw_flags.items()})
        if raw.get("multiple_hosts_count", 0) and int(raw["multiple_hosts_count"]) > 1:
            flags.multiple_hosts = True
        flags.active_attack = bool(raw.get("active_attack", False)) or (
            flags.ransomware or flags.data_exfiltration
        )

        ctx = cls(alert=alert, flags=flags)
        ctx._enrich(raw)
        return ctx

    # ----------------------------------------------------------------- enrich
    def _enrich(self, raw: Dict[str, Any]) -> None:
        host_id = raw.get("asset_id") or raw.get("host") or raw.get("hostname")
        src_ip, dst_ip = raw.get("source_ip"), raw.get("target_ip") or raw.get("destination_ip")
        user_id = raw.get("user_id") or raw.get("user")
        file_hash = raw.get("file_hash") or raw.get("hash")
        domain = raw.get("domain")

        self.entities = Entities(
            host={"id": host_id} if host_id else {},
            user={"id": user_id} if user_id else {},
            source_ip={"value": src_ip} if src_ip else {},
            destination_ip={"value": dst_ip} if dst_ip else {},
            process={"name": raw.get("process_name")} if raw.get("process_name") else {},
            file={"hash": file_hash} if file_hash else {},
            domain={"value": domain} if domain else {},
        )

        self.asset = self._asset_lookup(host_id, dst_ip)
        self.identity = self._identity_lookup(user_id, raw)
        self.threat_intel = self._ioc_lookup([v for v in (src_ip, dst_ip, file_hash, domain) if v])
        self.change_context = ChangeContext(
            active_change=raw.get("active_change"),
            change_id=raw.get("change_id"),
        )
        self.history = HistoryContext(
            similar_alerts_30d=int(raw.get("similar_alerts_30d", 0)),
            historical_false_positive_rate=float(raw.get("historical_false_positive_rate", 0.0)),
        )
        self.containment = ContainmentContext(
            edr_blocked=bool(raw.get("edr_blocked", False)),
            process_killed=bool(raw.get("process_killed", False)),
        )
        if raw.get("normal_work_hours") is not None:
            self.identity.normal_work_hours = bool(raw["normal_work_hours"])

    def _asset_lookup(self, host_id: Optional[str], dst_ip: Optional[str]) -> AssetContext:
        assets = _load_json("assets.json").get("assets", [])
        match = None
        for asset in assets:
            if (host_id and asset.get("asset_id") == host_id) or (
                dst_ip and asset.get("ip_address") == dst_ip
            ):
                match = asset
                break
        if not match:
            return AssetContext()
        return AssetContext(
            criticality=str(match.get("criticality", "unknown")),
            environment=match.get("environment"),
            business_system=match.get("business_unit"),
            internet_exposed=bool(match.get("internet_exposed", False)),
            asset_id=match.get("asset_id"),
            owner=match.get("owner"),
        )

    def _identity_lookup(self, user_id: Optional[str], raw: Dict[str, Any]) -> IdentityContext:
        users = _load_json("users.json").get("users", [])
        match = next((u for u in users if user_id and u.get("user_id") == user_id), None)
        privileged_roles = {"admin", "administrator", "dba", "domain_admin", "privileged", "root"}
        if match:
            return IdentityContext(
                user_id=match.get("user_id"),
                privileged=str(match.get("access_level", "")).lower() in {"privileged", "admin"}
                or str(match.get("role", "")).lower() in privileged_roles,
                service_account=str(match.get("role", "")).lower() in {"service", "service_account"}
                or str(match.get("username", "")).startswith(("svc-", "service-")),
                department=match.get("department"),
                role=match.get("role"),
            )
        # no CMDB/IAM match: honor explicit hints from the raw alert
        return IdentityContext(
            user_id=user_id,
            privileged=bool(raw.get("privileged", False)),
            service_account=str(user_id or "").startswith(("svc-", "service-")),
        )

    def _ioc_lookup(self, indicators: List[str]) -> ThreatIntelContext:
        iocs = _load_json("internal_iocs.json").get("iocs", [])
        by_value = {i.get("ioc_value"): i for i in iocs}
        hits = [by_value[v] for v in indicators if v in by_value]
        if not hits:
            return ThreatIntelContext()
        return ThreatIntelContext(
            ioc_hit=True,
            reputation=hits[0].get("threat_type"),
            matched_iocs=[h.get("ioc_value") for h in hits],
        )
