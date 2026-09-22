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

"""Provider factory with the mandated fail-safe chain (requirement §41).

Primary provider fails -> configured fallback (rule by default). The result
carries degraded=True / degraded_reason; the Decision Router then routes to
HUMAN_REVIEW instead of ever closing on a failed model.
"""

import os
from typing import Optional

from ..core.registry import registry
from .base import DecisionModelProvider, DecisionResult, ProviderUnavailable
from .ensemble import EnsembleProvider
from .jev import JevProvider
from .laya import LayaDecisionProvider
from .rule import RuleProvider

_cache: dict = {}


def _build(name: str) -> DecisionModelProvider:
    if name == "laya":
        return LayaDecisionProvider()
    if name == "rule":
        return RuleProvider()
    if name == "jev":
        return JevProvider()
    if name == "ensemble":
        laya = LayaDecisionProvider(prewarm=False)
        members = [laya, RuleProvider()] if laya.available else [RuleProvider()]
        return EnsembleProvider(members)
    raise ValueError(f"unknown provider: {name}")


def get_provider(name: Optional[str] = None, fallback: Optional[str] = None) -> DecisionModelProvider:
    """Return a provider by name (or the configured default)."""
    key = name or registry.providers.get("default", "laya")
    if key not in _cache:
        _cache[key] = _build(key)
    return _cache[key]


def reset_cache() -> None:
    _cache.clear()


async def decide_with_fallback(
    state: dict,
    questions: dict,
    context,
    provider: Optional[DecisionModelProvider] = None,
) -> DecisionResult:
    """Run the primary provider; on failure fall back (§41). Never closes on failure."""
    primary = provider or get_provider()
    fallback_name = os.environ.get(
        "TRIAGE_ENGINE_FALLBACK", registry.providers.get("fallback", "rule")
    )
    try:
        return await primary.decide(state, questions, context)
    except ProviderUnavailable as exc:
        fallback = get_provider(fallback_name)
        result = await fallback.decide(state, questions, context)
        result.degraded = True
        result.degraded_reason = f"{primary.name} unavailable: {exc}"
        return result


__all__ = [
    "DecisionModelProvider",
    "DecisionResult",
    "ProviderUnavailable",
    "LayaDecisionProvider",
    "RuleProvider",
    "JevProvider",
    "EnsembleProvider",
    "get_provider",
    "decide_with_fallback",
    "reset_cache",
]
