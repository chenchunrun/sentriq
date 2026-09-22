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

"""Security Tool Gateway (requirement §18).

The only path from the Investigation Agent to data sources:
- allowlist of typed read-only tools (no raw SQL / SPL / SSH / shell possible)
- per-call timeout, audit trail, per-case call budget
- RBAC-lite: the agent role is read-only by construction
"""

import asyncio
import time
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from .tools_catalog import TOOL_CATALOG, ToolEnvironment

_DEFAULT_TIMEOUT_S = 5.0


class ToolCallRecord(BaseModel):
    tool: str
    query: Dict[str, Any] = Field(default_factory=dict)
    ok: bool
    duration_ms: int
    error: Optional[str] = None


class ToolGatewayError(Exception):
    pass


class ToolGateway:
    def __init__(self, env: ToolEnvironment, timeout_s: float = _DEFAULT_TIMEOUT_S) -> None:
        self.env = env
        self.timeout_s = timeout_s
        self.audit: List[ToolCallRecord] = []
        self._call_counts: Dict[str, int] = {}

    @property
    def total_calls(self) -> int:
        return sum(self._call_counts.values())

    def available_tools(self) -> List[str]:
        return list(TOOL_CATALOG.keys())

    async def execute(self, tool: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        params = params or {}
        spec = TOOL_CATALOG.get(tool)
        if spec is None:
            raise ToolGatewayError(f"tool not in allowlist: {tool}")
        if not spec.get("readonly", False):
            raise ToolGatewayError(f"tool is not read-only: {tool}")
        unknown_params = set(params) - set(spec.get("params", []))
        if unknown_params:
            raise ToolGatewayError(f"unknown params for {tool}: {sorted(unknown_params)}")

        t0 = time.perf_counter()
        try:
            result = await asyncio.wait_for(
                asyncio.to_thread(spec["handler"], params, self.env),
                timeout=self.timeout_s,
            )
            self._record(tool, params, True, t0, None)
            return result
        except asyncio.TimeoutError:
            self._record(tool, params, False, t0, "timeout")
            raise ToolGatewayError(f"tool timeout: {tool}")
        except Exception as exc:  # noqa: BLE001
            self._record(tool, params, False, t0, str(exc))
            raise ToolGatewayError(f"tool failed: {tool}: {exc}")

    def _record(self, tool: str, query: Dict[str, Any], ok: bool, t0: float, error: Optional[str]) -> None:
        self._call_counts[tool] = self._call_counts.get(tool, 0) + 1
        self.audit.append(
            ToolCallRecord(
                tool=tool,
                query=query,
                ok=ok,
                duration_ms=int((time.perf_counter() - t0) * 1000),
                error=error,
            )
        )
