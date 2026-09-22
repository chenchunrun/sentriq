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

"""JevProvider - reserved adapter (requirement §30, P2).

The unified DecisionModelProvider API means swapping Laya for Jev (or any
future provider) requires no change in business code. Until a Jev runtime is
available this provider reports itself unavailable so the factory falls back.
"""

from typing import Any, Dict

from .base import (
    DecisionContext,
    DecisionModelProvider,
    DecisionResult,
    ProviderUnavailable,
)


class JevProvider(DecisionModelProvider):
    name = "jev"

    async def decide(
        self,
        state: Dict[str, Any],
        questions: Dict[str, Dict[str, Any]],
        context: DecisionContext,
    ) -> DecisionResult:
        raise ProviderUnavailable(
            "JevProvider is reserved for a future runtime (requirement §46 P2); "
            "configure providers.default=laya|rule|ensemble instead"
        )
