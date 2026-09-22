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

"""Minimal OpenAI-compatible chat client for the slow-path judge (System 2).

Env: LLM_API_KEY / LLM_BASE_URL / LLM_MODEL - same convention as the rest of
the platform. When unset the judge falls back to its deterministic rule path
(fail safe, requirement §41).
"""

import os
from typing import Any, Dict, List, Optional

try:  # httpx is optional for the rule-only deployment
    import httpx
except ImportError:  # pragma: no cover
    httpx = None  # type: ignore


class LLMClient:
    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        timeout: float = 60.0,
    ) -> None:
        self.api_key = api_key or os.environ.get("LLM_API_KEY", "")
        self.base_url = (base_url or os.environ.get("LLM_BASE_URL", "")).rstrip("/")
        self.model = model or os.environ.get("LLM_MODEL", "qwen-plus")
        self.timeout = timeout

    @property
    def available(self) -> bool:
        return bool(self.api_key and self.base_url and httpx is not None)

    async def chat(self, system: str, user: str, max_tokens: int = 2000) -> Dict[str, Any]:
        """Return {"content": str, "tokens": int}. Raises on transport errors."""
        if not self.available:
            raise RuntimeError("LLM client not configured (LLM_API_KEY / LLM_BASE_URL)")
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": 0.0,
            "max_tokens": max_tokens,
        }
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(f"{self.base_url}/chat/completions", json=payload, headers=headers)
            resp.raise_for_status()
            data = resp.json()
        content = data["choices"][0]["message"]["content"]
        tokens = int(data.get("usage", {}).get("total_tokens", 0)) or len(content) // 4
        return {"content": content, "tokens": tokens}
