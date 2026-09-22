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

"""Timeline Engine (requirement §22).

Timelines are derived exclusively from Evidence timestamps - the LLM cannot
invent events. Evidence without a timestamp is appended at the end marked
`untimed`.
"""

from typing import List, Optional

from pydantic import BaseModel

from .evidence import Evidence


class TimelineEvent(BaseModel):
    timestamp: Optional[str]
    event: str
    source: str
    evidence_id: str


def build_timeline(evidence: List[Evidence]) -> List[TimelineEvent]:
    timed = [e for e in evidence if e.timestamp]
    untimed = [e for e in evidence if not e.timestamp]
    timed.sort(key=lambda e: e.timestamp or "")
    events = [
        TimelineEvent(timestamp=e.timestamp, event=e.fact, source=e.source, evidence_id=e.evidence_id)
        for e in timed
    ]
    events += [
        TimelineEvent(timestamp=None, event=e.fact, source=e.source, evidence_id=e.evidence_id)
        for e in untimed
    ]
    return events
