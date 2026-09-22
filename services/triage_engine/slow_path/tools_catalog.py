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

"""Typed read-only security tools (requirement §19) backed by repository mock
data (CMDB assets, IAM users, internal IOC list, sample SIEM alerts) plus
deterministic synthetic EDR/NDR telemetry.

Tools return a normalized payload:
    {"facts": [str], "entities": [...], "timestamp": iso|None,
     "relationships": [(subject, verb, object)], "raw_reference": str}

The Investigation Agent never talks to data sources directly - only through
the ToolGateway allowlist (requirement §18: no raw SQL / SSH / shell).
"""

import hashlib
import json
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from ..core.context import _load_json  # repo data loader


def _data_dir() -> Path:
    return Path(__file__).resolve().parents[3] / "data"


def _seeded(key: str) -> int:
    return int(hashlib.sha256(key.encode()).hexdigest()[:8], 16)


class ToolEnvironment:
    """Case-scoped data view: alert context drives deterministic telemetry so
    suspicious alerts surface suspicious evidence (mock, reproducible)."""

    def __init__(self, raw_alert: Dict[str, Any]) -> None:
        self.raw = raw_alert
        self.alert_id = str(raw_alert.get("alert_id") or raw_alert.get("id") or "ALT-UNKNOWN")
        self.suspicious = self._is_suspicious()

    def _is_suspicious(self) -> bool:
        blob = " ".join(
            str(v) for v in (
                self.raw.get("alert_type"), self.raw.get("description"), self.raw.get("title"),
            ) if v
        ).lower()
        markers = ("lsass", "credential", "malware", "ransom", "exfil", "lateral", "mimikatz",
                   "webshell", "c2", "phish", "brute")
        return any(m in blob for m in markers)


# --------------------------------------------------------------------- handlers

def get_asset(params: Dict[str, Any], env: ToolEnvironment) -> Dict[str, Any]:
    asset_id = params.get("asset_id")
    assets = _load_json("assets.json").get("assets", [])
    match = next((a for a in assets if a.get("asset_id") == asset_id), None)
    if not match:
        return {"facts": [f"asset {asset_id} not found in CMDB"], "entities": [], "timestamp": None, "relationships": [], "raw_reference": f"cmdb://assets/{asset_id}"}
    facts = [
        f"asset {match['asset_id']} ({match.get('asset_name')}): criticality={match.get('criticality')}, env={match.get('environment')}, owner={match.get('owner')}",
        f"open vulnerabilities: critical={match.get('vulnerabilities', {}).get('critical', 0)}, high={match.get('vulnerabilities', {}).get('high', 0)}",
    ]
    return {
        "facts": facts,
        "entities": [{"type": "host", "id": match["asset_id"]}],
        "timestamp": match.get("last_scan"),
        "relationships": [],
        "raw_reference": f"cmdb://assets/{asset_id}",
    }


def get_asset_owner(params: Dict[str, Any], env: ToolEnvironment) -> Dict[str, Any]:
    assets = _load_json("assets.json").get("assets", [])
    asset_id = params.get("asset_id")
    match = next((a for a in assets if a.get("asset_id") == asset_id), None)
    owner = match.get("owner") if match else "unknown"
    return {
        "facts": [f"asset {asset_id} owned by {owner} (business_unit={match.get('business_unit') if match else 'unknown'})"],
        "entities": [{"type": "team", "id": owner}],
        "timestamp": None,
        "relationships": [(asset_id, "owned_by", owner)] if match else [],
        "raw_reference": f"cmdb://assets/{asset_id}/owner",
    }


def get_process_tree(params: Dict[str, Any], env: ToolEnvironment) -> Dict[str, Any]:
    host = params.get("host") or env.raw.get("asset_id") or "HOST-UNKNOWN"
    if env.suspicious:
        chain = ["powershell.exe", "rundll32.exe", "lsass.exe"]
        facts = [f"process chain on {host}: powershell.exe -> rundll32.exe -> access to lsass.exe",
                 "rundll32.exe executed with obfuscated command line; parent powershell spawned off-hours"]
    else:
        chain = ["chrome.exe", "chrome.exe (renderer)"]
        facts = [f"process chain on {host}: chrome.exe -> chrome.exe (renderer)", "no anomalous process relationships observed"]
    return {
        "facts": facts,
        "entities": [{"type": "process", "id": c} for c in chain],
        "timestamp": env.raw.get("timestamp"),
        "relationships": [(chain[i], "spawned", chain[i + 1]) for i in range(len(chain) - 1)],
        "raw_reference": f"edr://process_tree/{host}",
    }


def get_process_events(params: Dict[str, Any], env: ToolEnvironment) -> Dict[str, Any]:
    host = params.get("host") or env.raw.get("asset_id") or "HOST-UNKNOWN"
    if env.suspicious:
        facts = [
            f"process events on {host}: rundll32.exe opened handle to lsass.exe with PROCESS_VM_READ",
            "powershell.exe launched with -enc (base64 encoded command) at 01:07 local time",
        ]
    else:
        facts = [f"process events on {host}: routine browser and update activity only"]
    return {"facts": facts, "entities": [{"type": "host", "id": host}], "timestamp": env.raw.get("timestamp"), "relationships": [], "raw_reference": f"edr://process_events/{host}"}


def search_user_logins(params: Dict[str, Any], env: ToolEnvironment) -> Dict[str, Any]:
    user_id = params.get("user_id") or env.raw.get("user_id") or ""
    users = _load_json("users.json").get("users", [])
    match = next((u for u in users if u.get("user_id") == user_id), None)
    hist = (match or {}).get("login_history", {})
    facts = [
        f"last login for {user_id}: {hist.get('last_login')} from {hist.get('last_location')} ({hist.get('last_ip')})",
        f"unusual_login flag: {hist.get('unusual_login', 'n/a')}",
    ]
    if env.suspicious and user_id:
        facts.append(f"additional login for {user_id} observed from foreign ASN 30 minutes before the alert (impossible travel)")
    return {"facts": facts, "entities": [{"type": "user", "id": user_id}], "timestamp": hist.get("last_login"), "relationships": [(user_id, "logged_into", env.raw.get("asset_id") or "host")] if user_id else [], "raw_reference": f"iam://logins/{user_id}"}


def search_host_logins(params: Dict[str, Any], env: ToolEnvironment) -> Dict[str, Any]:
    host = params.get("host") or env.raw.get("asset_id") or "HOST-UNKNOWN"
    user_id = env.raw.get("user_id") or "unknown"
    if env.suspicious:
        facts = [f"interactive logins on {host}: {user_id} at 01:02 (outside normal hours), no other users"]
    else:
        facts = [f"interactive logins on {host}: {user_id} during normal hours, consistent with baseline"]
    return {"facts": facts, "entities": [{"type": "host", "id": host}], "timestamp": env.raw.get("timestamp"), "relationships": [(user_id, "logged_into", host)], "raw_reference": f"iam://host_logins/{host}"}


def get_network_connections(params: Dict[str, Any], env: ToolEnvironment) -> Dict[str, Any]:
    host = params.get("host") or env.raw.get("asset_id") or "HOST-UNKNOWN"
    seed = _seeded(f"{env.alert_id}:{host}:conn")
    if env.suspicious:
        peers = [f"10.0.1.{20 + (seed % 8)}", f"10.0.2.{10 + (seed % 6)}", f"10.0.2.{20 + (seed % 6)}"]
        facts = [f"{host} initiated SMB connections to 3+ internal servers: {', '.join(peers)}",
                 f"outbound connection to {env.raw.get('source_ip') or '45.33.32.156'}:443 with low-and-slow beacon pattern"]
        rels = [(host, "SMB", p) for p in peers] + [(host, "connects_to", str(env.raw.get("source_ip") or "45.33.32.156"))]
    else:
        facts = [f"{host} network activity limited to known update/CDN destinations"]
        rels = []
    return {"facts": facts, "entities": [{"type": "host", "id": host}], "timestamp": env.raw.get("timestamp"), "relationships": rels, "raw_reference": f"ndr://connections/{host}"}


def search_dns(params: Dict[str, Any], env: ToolEnvironment) -> Dict[str, Any]:
    domain = params.get("domain") or (env.raw.get("domain") or "")
    if not domain:
        return {"facts": ["no domain provided and none present in alert"], "entities": [], "timestamp": None, "relationships": [], "raw_reference": "ndr://dns"}
    suspicious_domain = env.suspicious
    fact = (f"DNS: {domain} resolved to 45.33.32.156 (newly registered, 3 days old)" if suspicious_domain
            else f"DNS: {domain} resolved to known CDN address, long-standing record")
    return {"facts": [fact], "entities": [{"type": "domain", "id": domain}], "timestamp": env.raw.get("timestamp"), "relationships": [(domain, "resolved_to", "45.33.32.156")] if suspicious_domain else [], "raw_reference": f"ndr://dns/{domain}"}


def get_ioc_reputation(params: Dict[str, Any], env: ToolEnvironment) -> Dict[str, Any]:
    value = params.get("value") or env.raw.get("source_ip") or env.raw.get("file_hash") or ""
    iocs = _load_json("internal_iocs.json").get("iocs", [])
    match = next((i for i in iocs if i.get("ioc_value") == value), None)
    if match:
        facts = [f"IOC match: {value} is a known {match.get('threat_type')} (source={match.get('source')}, confidence={match.get('confidence')}, tags={match.get('tags')})"]
    else:
        facts = [f"no IOC record for {value} in internal threat intel"]
    return {"facts": facts, "entities": [{"type": "ioc", "id": value}], "timestamp": (match or {}).get("last_seen"), "relationships": [], "raw_reference": f"ti://ioc/{value}"}


def find_related_alerts(params: Dict[str, Any], env: ToolEnvironment) -> Dict[str, Any]:
    data = _load_json("sample_alerts.json").get("alerts", [])
    related = [a for a in data if a.get("alert_id") != env.alert_id and (
        a.get("source_ip") == env.raw.get("source_ip")
        or a.get("asset_id") == env.raw.get("asset_id")
        or a.get("user_id") == env.raw.get("user_id")
    )]
    facts = [f"related alerts (24h window): {len(related)}" if related else "no related alerts in the last 24h"]
    facts += [f"related: {a.get('alert_id')} ({a.get('alert_type')}, {a.get('severity')})" for a in related[:4]]
    return {"facts": facts, "entities": [{"type": "alert", "id": a.get("alert_id")} for a in related[:4]], "timestamp": env.raw.get("timestamp"), "relationships": [], "raw_reference": "siem://alerts/related"}


def find_similar_alerts(params: Dict[str, Any], env: ToolEnvironment) -> Dict[str, Any]:
    similar_count = int(env.raw.get("similar_alerts_30d", 0))
    if similar_count:
        facts = [f"{similar_count} similar alerts in the last 30 days (same rule/entity combination)"]
        if env.raw.get("historical_false_positive_rate"):
            facts.append(f"historical false positive rate for this pattern: {env.raw.get('historical_false_positive_rate')}")
    else:
        facts = ["no similar alerts in the last 30 days - first occurrence of this pattern"]
    return {"facts": facts, "entities": [], "timestamp": env.raw.get("timestamp"), "relationships": [], "raw_reference": "siem://alerts/similar"}


def get_change_records(params: Dict[str, Any], env: ToolEnvironment) -> Dict[str, Any]:
    asset_id = params.get("asset_id") or env.raw.get("asset_id") or ""
    if env.raw.get("active_change"):
        facts = [f"active change record CHG-{_seeded(asset_id) % 9999:04d} covers {asset_id} during the alert window"]
    else:
        facts = [f"no active change records covering {asset_id} during the alert window"]
    return {"facts": facts, "entities": [{"type": "host", "id": asset_id}] if asset_id else [], "timestamp": env.raw.get("timestamp"), "relationships": [], "raw_reference": f"itsm://changes/{asset_id}"}


def get_incident_history(params: Dict[str, Any], env: ToolEnvironment) -> Dict[str, Any]:
    entity = params.get("entity") or env.raw.get("asset_id") or env.raw.get("user_id") or ""
    count = _seeded(f"{entity}:incidents") % 3 if not env.suspicious else 1 + _seeded(f"{entity}:inc") % 3
    facts = [f"incident history for {entity}: {count} prior incident(s) on record"]
    return {"facts": facts, "entities": [{"type": "entity", "id": entity}] if entity else [], "timestamp": None, "relationships": [], "raw_reference": f"siem://incidents/{entity}"}


# --------------------------------------------------------------------- catalog

TOOL_CATALOG: Dict[str, Dict[str, Any]] = {
    "get_asset": {"category": "CMDB", "readonly": True, "params": ["asset_id"], "handler": get_asset,
                  "description": "Asset criticality, environment, owner, vulnerabilities"},
    "get_asset_owner": {"category": "CMDB", "readonly": True, "params": ["asset_id"], "handler": get_asset_owner,
                        "description": "Owning team / business unit of an asset"},
    "get_process_tree": {"category": "EDR", "readonly": True, "params": ["host"], "handler": get_process_tree,
                         "description": "Process ancestry for a host"},
    "get_process_events": {"category": "EDR", "readonly": True, "params": ["host"], "handler": get_process_events,
                           "description": "Detailed process events (handles, command lines)"},
    "search_user_logins": {"category": "IAM", "readonly": True, "params": ["user_id"], "handler": search_user_logins,
                           "description": "Login history for a user (incl. impossible travel)"},
    "search_host_logins": {"category": "IAM", "readonly": True, "params": ["host"], "handler": search_host_logins,
                           "description": "Interactive logins on a host"},
    "get_network_connections": {"category": "NDR", "readonly": True, "params": ["host"], "handler": get_network_connections,
                                "description": "Network connections, lateral movement, beacons"},
    "search_dns": {"category": "NDR", "readonly": True, "params": ["domain"], "handler": search_dns,
                   "description": "DNS resolution history for a domain"},
    "get_ioc_reputation": {"category": "TI", "readonly": True, "params": ["value"], "handler": get_ioc_reputation,
                           "description": "Threat intel reputation for an IP/hash/domain"},
    "find_related_alerts": {"category": "SIEM", "readonly": True, "params": [], "handler": find_related_alerts,
                            "description": "Related alerts on same entities in the window"},
    "find_similar_alerts": {"category": "SIEM", "readonly": True, "params": [], "handler": find_similar_alerts,
                            "description": "30-day similar alert count and FP rate"},
    "get_change_records": {"category": "ITSM", "readonly": True, "params": ["asset_id"], "handler": get_change_records,
                           "description": "Active change records covering the asset"},
    "get_incident_history": {"category": "SIEM", "readonly": True, "params": ["entity"], "handler": get_incident_history,
                             "description": "Prior incidents for an entity"},
}

TOOL_NAMES = list(TOOL_CATALOG.keys())
