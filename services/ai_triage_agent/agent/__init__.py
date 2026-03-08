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

"""Agent module exports with backward-compatible imports."""

from __future__ import annotations

import importlib.util
from pathlib import Path

__all__ = ["AITriageAgent", "TriageAgent", "run_triage_agent"]


# Backward compatibility:
# The project historically exposed AITriageAgent from services/ai_triage_agent/agent.py.
# This package (services/ai_triage_agent/agent/) shadows that module name, so we load it
# explicitly by file path and re-export AITriageAgent here.
_legacy_agent_path = Path(__file__).resolve().parent.parent / "agent.py"
_legacy_spec = importlib.util.spec_from_file_location(
    "ai_triage_agent._legacy_agent_module",
    _legacy_agent_path,
)
if _legacy_spec and _legacy_spec.loader:
    _legacy_module = importlib.util.module_from_spec(_legacy_spec)
    _legacy_spec.loader.exec_module(_legacy_module)
    AITriageAgent = _legacy_module.AITriageAgent
else:
    raise ImportError(f"Unable to load legacy agent module: {_legacy_agent_path}")


# Optional LangChain exports:
# Do not fail package import when langchain deps are missing.
try:
    from .triage_agent import TriageAgent, run_triage_agent
except ModuleNotFoundError:
    TriageAgent = None
    run_triage_agent = None
