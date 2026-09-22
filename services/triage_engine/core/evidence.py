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

"""Evidence Service (requirement §20/§21).

Every tool response is normalized into an immutable Evidence record. The LLM
never mutates evidence (§3.4 No Evidence -> No Fact). A lightweight entity
graph (relationship tuples) is kept alongside - PostgreSQL/JSONB territory in
production, plain relationship records here (§21).
"""

import itertools
import threading
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

_counter = itertools.count(1)
_lock = threading.Lock()


def next_evidence_id() -> str:
    with _lock:
        return f"EV-{next(_counter):05d}"


def reset_ids() -> None:
    """Test helper."""
    global _counter
    with _lock:
        _counter = itertools.count(1)


class Evidence(BaseModel):
    evidence_id: str
    source: str                      # EDR / IAM / CMDB / SIEM / TI / ITSM
    timestamp: Optional[str] = None
    entity: Dict[str, Any] = Field(default_factory=dict)
    fact: str
    raw_reference: Optional[str] = None
    reliability: float = 0.9
    collector: Dict[str, Any] = Field(default_factory=dict)  # {"tool": ..., "query": ...}
    hypothesis_links: Dict[str, Dict[str, float]] = Field(default_factory=dict)
    # {"H2": {"supports": 0.7}, "H0": {"contradicts": 0.5}}


class Relationship(BaseModel):
    subject: str
    verb: str
    object: str
    evidence_id: str


class EvidenceService:
    """In-memory evidence registry for one investigation case."""

    def __init__(self) -> None:
        self._evidence: Dict[str, Evidence] = {}
        self._relationships: List[Relationship] = []

    def add(
        self,
        fact: str,
        source: str,
        tool: str,
        query: Optional[Dict[str, Any]] = None,
        entity: Optional[Dict[str, Any]] = None,
        timestamp: Optional[str] = None,
        reliability: float = 0.9,
        raw_reference: Optional[str] = None,
        hypothesis_links: Optional[Dict[str, Dict[str, float]]] = None,
    ) -> Evidence:
        ev = Evidence(
            evidence_id=next_evidence_id(),
            source=source,
            timestamp=timestamp,
            entity=entity or {},
            fact=fact,
            raw_reference=raw_reference,
            reliability=reliability,
            collector={"tool": tool, "query": query or {}},
            hypothesis_links=hypothesis_links or {},
        )
        self._evidence[ev.evidence_id] = ev
        return ev

    def add_relationship(self, subject: str, verb: str, obj: str, evidence_id: str) -> None:
        self._relationships.append(
            Relationship(subject=subject, verb=verb, object=obj, evidence_id=evidence_id)
        )

    def get(self, evidence_id: str) -> Optional[Evidence]:
        return self._evidence.get(evidence_id)

    def all(self) -> List[Evidence]:
        return list(self._evidence.values())

    def relationships(self) -> List[Relationship]:
        return list(self._relationships)

    def by_source(self, source: str) -> List[Evidence]:
        return [e for e in self._evidence.values() if e.source == source]

    def validate_evidence_ids(self, evidence_ids: List[str]) -> List[str]:
        """Reject any verdict citation that does not exist (No Evidence -> No Fact)."""
        return [e for e in evidence_ids if e not in self._evidence]
