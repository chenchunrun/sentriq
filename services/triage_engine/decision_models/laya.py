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

"""LayaProvider - native adapter for the open-source Laya fast decision model
(https://github.com/NandhaKishorM/laya, MLX runtime: laya-mlx).

Responsibilities (requirement §6.3): load/prewarm checkpoints, checkpoint
routing (§6.4, via our own SecurityLayaRouter - not blindly trusting Laya's
internal Router), typed question conversion, token budget, timeout, retry,
telemetry, and a normalized DecisionResult. Invalid or unavailable output is
reported to the caller as ProviderUnavailable; the engine then fails safe to
the RuleProvider (§41).
"""

import asyncio
import os
import re
import threading
import time
from typing import Any, Dict, Optional, Tuple

from ..core.registry import registry
from .base import (
    DecisionContext,
    DecisionModelProvider,
    DecisionResult,
    ProviderUnavailable,
    state_hash,
    validate_answers,
)

_CJK_RE = re.compile(r"[\u4e00-\u9fff\u3040-\u30ff\uac00-\ud7af]")


def cjk_ratio(text: str) -> float:
    if not text:
        return 0.0
    cjk = len(_CJK_RE.findall(text))
    return cjk / max(1, len(text))


class SecurityLayaRouter:
    """Own checkpoint routing (requirement §6.4).

    chinese-dominant state -> multilingual; security typed workflow ->
    typed-decisions; otherwise english/general.
    """

    def __init__(self, cfg: Dict[str, Any]) -> None:
        self._cfg = cfg

    def select(self, state_text: str, context: DecisionContext) -> Tuple[str, str]:
        ratio_cfg = float(self._cfg.get("cjk_ratio_for_multilingual", 0.15))
        if cjk_ratio(state_text) >= ratio_cfg:
            return "multilingual", "chinese_state"
        if context.use_typed_workflow:
            return "typed", "security_typed_workflow"
        return "general", "default_english"


class LayaDecisionProvider(DecisionModelProvider):
    """Native Laya provider. `import laya_mlx` / `import laya` happens lazily
    inside this module only - business code never touches the model library."""

    name = "laya"

    def __init__(self, runtime: Optional[str] = None, prewarm: bool = True) -> None:
        cfg = registry.providers.get("laya", {})
        self._cfg = cfg
        self.runtime = runtime or os.environ.get("LAYA_RUNTIME") or cfg.get("runtime", "mlx")
        self._router = SecurityLayaRouter(cfg)
        self._hf_repo = cfg.get("hf_repo", "convaiinnovations/laya")
        self._subfolders: Dict[str, Optional[str]] = {
            "multilingual": cfg.get("subfolders", {}).get("multilingual"),
            "typed": cfg.get("subfolders", {}).get("typed"),
            "general": cfg.get("subfolders", {}).get("general"),
        }
        self._timeout = float(cfg.get("timeout_seconds", 10))
        self._max_retries = int(cfg.get("max_retries", 1))
        self._max_state_tokens = int(cfg.get("max_state_tokens", 800))
        self._module: Any = None          # laya_mlx or laya module
        self._agents: Dict[str, Any] = {}  # checkpoint -> loaded agent
        self._lock = threading.Lock()
        if prewarm:
            try:
                self._load_runtime()
            except Exception:  # weights missing at startup -> lazy retry at first call
                pass

    # ------------------------------------------------------------------ runtime
    def _load_runtime(self) -> Any:
        if self._module is not None:
            return self._module
        if self.runtime == "mlx":
            import laya_mlx as module  # type: ignore
        elif self.runtime == "torch":
            import laya as module  # type: ignore
        else:
            raise ProviderUnavailable(f"unknown laya runtime: {self.runtime}")
        self._module = module
        return module

    def _agent(self, checkpoint: str) -> Any:
        if checkpoint not in self._agents:
            with self._lock:
                if checkpoint not in self._agents:
                    module = self._load_runtime()
                    subfolder = self._subfolders.get(checkpoint) or None
                    self._agents[checkpoint] = module.load(self._hf_repo, subfolder=subfolder)
        return self._agents[checkpoint]

    @property
    def available(self) -> bool:
        try:
            self._load_runtime()
            return True
        except Exception:
            return False

    # ------------------------------------------------------------- questions
    @staticmethod
    def build_questions(question_specs: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """Convert our decision registry into laya typed questions."""
        laya_questions: Dict[str, Dict[str, Any]] = {}
        for name, spec in question_specs.items():
            q: Dict[str, Any] = {"type": spec["type"], "instructions": spec["instructions"]}
            if spec["type"] == "score":
                q["criteria"] = spec["criteria"]
            elif spec["type"] == "choice":
                q["criteria"] = spec["criteria"]
            laya_questions[name] = q
        return laya_questions

    # ---------------------------------------------------------------- decide
    async def decide(
        self,
        state: Dict[str, Any],
        questions: Dict[str, Dict[str, Any]],
        context: DecisionContext,
    ) -> DecisionResult:
        t0 = time.perf_counter()
        checkpoint, routing_reason = self._router.select(context.state_text, context)
        state_text = context.state_text
        # token budget guard (requirement §6.3): the compressor already keeps
        # state small; enforce a hard ceiling here as the last line of defense.
        if len(state_text) // 4 > self._max_state_tokens:
            state_text = state_text[: self._max_state_tokens * 4]

        laya_questions = self.build_questions(questions)
        agent = self._agent(checkpoint)

        last_error: Optional[Exception] = None
        for attempt in range(self._max_retries + 1):
            try:
                raw = await asyncio.wait_for(
                    asyncio.to_thread(agent.predict, state_text, laya_questions),
                    timeout=self._timeout,
                )
                answers = self._extract_answers(raw)
                issues = validate_answers(answers, questions)
                if issues:
                    raise ProviderUnavailable(f"invalid laya answers: {issues}")
                latency_ms = int((time.perf_counter() - t0) * 1000)
                return self._to_result(answers, raw, checkpoint, routing_reason, latency_ms, context)
            except (ProviderUnavailable, asyncio.TimeoutError, Exception) as exc:  # noqa: BLE001
                last_error = exc
                continue

        raise ProviderUnavailable(f"laya decision failed: {last_error}")

    # ---------------------------------------------------------------- mapping
    @staticmethod
    def _extract_answers(raw: Any) -> Dict[str, Any]:
        """Flatten laya's answer payload. Handles both {"answers": {...}} and
        bare {...} shapes; keeps structured values for validate_answers to unwrap."""
        if isinstance(raw, dict) and isinstance(raw.get("answers"), dict):
            raw = raw["answers"]
        if not isinstance(raw, dict):
            raise ProviderUnavailable(f"unexpected laya output shape: {type(raw)}")
        return raw

    def _to_result(
        self,
        answers: Dict[str, Any],
        raw: Any,
        checkpoint: str,
        routing_reason: str,
        latency_ms: int,
        context: DecisionContext,
    ) -> DecisionResult:
        decisions: Dict[str, Any] = {}
        route_prediction: Dict[str, float] = {}
        tokens = 0

        for name, value in answers.items():
            if isinstance(value, dict):
                # laya raw shapes:
                #   noul   -> {"noul": p, "confidence": c}
                #   score  -> {"score": continuous, "probabilities": {...}}
                #   choice -> {"choice": str, "probabilities": {...}}
                if "noul" in value:
                    decisions[name] = float(value["noul"])
                elif "score" in value:
                    decisions[name] = float(value["score"])
                elif "choice" in value:
                    decisions[name] = str(value["choice"])
                if name == "route" and isinstance(value.get("probabilities"), dict):
                    route_prediction = {
                        str(k): float(v) for k, v in value["probabilities"].items()
                    }
                    total = sum(route_prediction.values()) or 1.0
                    route_prediction = {k: round(v / total, 3) for k, v in route_prediction.items()}
            else:
                decisions[name] = value

        model_version = ""
        if isinstance(raw, dict):
            model_version = str(raw.get("model") or raw.get("model_version") or "")
            usage = raw.get("usage") or {}
            tokens = int(usage.get("input_tokens", 0) or 0)

        return DecisionResult(
            provider=self.name,
            model=f"laya-{checkpoint}",
            version=model_version,
            decisions=decisions,
            route_prediction=route_prediction,
            latency_ms=latency_ms,
            model_metadata={
                "runtime": self.runtime,
                "checkpoint": checkpoint,
                "routing_reason": routing_reason,
                "hf_repo": self._hf_repo,
                "input_tokens": tokens,
            },
            state_hash=state_hash(context.state_text),
            question_version=context.question_version,
        )
