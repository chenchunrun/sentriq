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

"""Decision Registry + Threshold Registry (requirement §31/§32).

Loads config/engine.yaml once and exposes typed accessors. Thresholds must
never be hardcoded at call sites.
"""

import os
import threading
from pathlib import Path
from typing import Any, Dict, List

import yaml

_DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "engine.yaml"
_lock = threading.Lock()
_cached: Dict[str, Any] = {}


def _load() -> Dict[str, Any]:
    with _lock:
        if not _cached:
            path = os.environ.get("TRIAGE_ENGINE_CONFIG", str(_DEFAULT_CONFIG_PATH))
            with open(path, "r", encoding="utf-8") as fh:
                _cached.update(yaml.safe_load(fh))
        return _cached


def reload_config() -> None:
    """Drop the cache so the next access re-reads engine.yaml."""
    with _lock:
        _cached.clear()


class Registry:
    """Read-only view over engine.yaml."""

    @property
    def raw(self) -> Dict[str, Any]:
        return _load()

    # ---- decision registry -------------------------------------------------
    @property
    def question_version(self) -> str:
        return _load()["decision_registry"]["version"]

    @property
    def questions(self) -> Dict[str, Dict[str, Any]]:
        return _load()["decision_registry"]["questions"]

    def question_types(self) -> Dict[str, str]:
        return {name: spec["type"] for name, spec in self.questions.items()}

    # ---- thresholds ---------------------------------------------------------
    @property
    def threshold_version(self) -> str:
        return _load()["thresholds"]["version"]

    def thresholds(self, section: str) -> Dict[str, Any]:
        return dict(_load()["thresholds"][section])

    # ---- hard gates / budgets / policy / providers --------------------------
    @property
    def hard_gate_names(self) -> List[str]:
        return list(_load()["hard_gates"].keys())

    @property
    def budgets(self) -> Dict[str, Any]:
        return dict(_load()["slow_path"]["budgets"])

    @property
    def stop_conditions(self) -> Dict[str, Any]:
        return dict(_load()["slow_path"]["stop"])

    @property
    def policy(self) -> Dict[str, Any]:
        return dict(_load()["policy"])

    @property
    def providers(self) -> Dict[str, Any]:
        return dict(_load()["providers"])

    @property
    def replay_limits(self) -> Dict[str, Any]:
        return dict(_load()["replay"])


registry = Registry()
