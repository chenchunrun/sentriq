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

"""LangChain Tools for AI Triage Agent."""

from .context_tools import collect_network_context, collect_asset_context, collect_user_context
from .threat_intel_tools import query_threat_intel, check_vulnerabilities, check_malware_hash
from .risk_assessment_tools import (
    calculate_risk_score,
    estimate_business_impact,
    generate_containment_strategies,
)

__all__ = [
    # Context tools
    "collect_network_context",
    "collect_asset_context",
    "collect_user_context",
    # Threat intel tools
    "query_threat_intel",
    "check_vulnerabilities",
    "check_malware_hash",
    # Risk assessment tools
    "calculate_risk_score",
    "estimate_business_impact",
    "generate_containment_strategies",
]
