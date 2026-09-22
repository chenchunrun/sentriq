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

"""Next Best Evidence planner (requirement §17).

The agent does not "query whatever comes to mind": the next tool is the one
with the highest expected discrimination value - relevance to the current
hypothesis distribution weighted by remaining uncertainty.
"""

from typing import Any, Dict, List, Optional, Tuple

# tool -> {hypothesis: relevance}
RELEVANCE: Dict[str, Dict[str, float]] = {
    "search_user_logins": {"H1": 0.9, "H0": 0.5, "H3": 0.3},
    "search_host_logins": {"H1": 0.7, "H0": 0.3},
    "get_process_tree": {"H2": 0.9, "H4": 0.3},
    "get_process_events": {"H2": 0.8},
    "get_network_connections": {"H2": 0.7, "H3": 0.4, "H1": 0.2},
    "search_dns": {"H2": 0.5, "H4": 0.2},
    "get_ioc_reputation": {"H2": 0.8, "H4": 0.5},
    "get_asset": {"H0": 0.4, "H2": 0.2},
    "get_asset_owner": {"H0": 0.5},
    "get_change_records": {"H0": 0.9, "H3": 0.4},
    "find_related_alerts": {"H2": 0.4, "H3": 0.5, "H4": 0.3},
    "find_similar_alerts": {"H4": 0.8, "H0": 0.4},
    "get_incident_history": {"H2": 0.3, "H4": 0.2},
}

# ordered fallback plan when the matrix ties
_PLAN_ORDER = [
    "get_process_tree",
    "search_user_logins",
    "get_ioc_reputation",
    "get_change_records",
    "get_network_connections",
    "get_process_events",
    "get_asset",
    "search_host_logins",
    "find_similar_alerts",
    "find_related_alerts",
    "search_dns",
    "get_asset_owner",
    "get_incident_history",
]


def default_params(tool: str, compressed_state: Dict[str, Any], raw_alert: Dict[str, Any]) -> Dict[str, Any]:
    """Derive tool parameters from the alert (host / user / indicator)."""
    host = compressed_state.get("host") or raw_alert.get("asset_id") or raw_alert.get("hostname")
    user = compressed_state.get("user") or raw_alert.get("user_id")
    return {
        "get_asset": {"asset_id": host},
        "get_asset_owner": {"asset_id": host},
        "get_process_tree": {"host": host},
        "get_process_events": {"host": host},
        "search_user_logins": {"user_id": user},
        "search_host_logins": {"host": host},
        "get_network_connections": {"host": host},
        "search_dns": {"domain": compressed_state.get("domain")},
        "get_ioc_reputation": {"value": compressed_state.get("source_ip") or compressed_state.get("file_hash")},
        "get_change_records": {"asset_id": host},
        "get_incident_history": {"entity": user or host},
    }.get(tool, {})


def next_tool(
    called_tools: List[str],
    hypothesis_posteriors: Dict[str, float],
) -> Optional[Tuple[str, float]]:
    """Pick the uncalled tool with max sum(relevance * posterior)."""
    remaining = [t for t in _PLAN_ORDER if t not in called_tools]
    if not remaining:
        return None
    scored = []
    for tool in remaining:
        rel = RELEVANCE.get(tool, {})
        value = sum(weight * hypothesis_posteriors.get(hyp, 0.0) for hyp, weight in rel.items())
        scored.append((tool, value))
    scored.sort(key=lambda tv: tv[1], reverse=True)
    best_tool, best_value = scored[0]
    if best_value <= 0.0:
        # nothing discriminates anymore - fall back to plan order for coverage
        return remaining[0], 0.0
    return best_tool, round(best_value, 3)
