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

"""SQLite-backed observability store (requirement §38).

Persists every decision, case, feedback and replay run with the fields the
spec requires (decision_id / provider / model / state_hash / router_result /
latency ...). Uses the stdlib sqlite3 with a small lock - deliberately no ORM
so the service runs standalone without PostgreSQL.
"""

import json
import os
import sqlite3
import threading
import time
import uuid
from typing import Any, Dict, List, Optional

_SCHEMA = """
CREATE TABLE IF NOT EXISTS decisions (
    decision_id TEXT PRIMARY KEY,
    alert_id TEXT,
    provider TEXT, model TEXT, model_version TEXT,
    state_hash TEXT, question_version TEXT,
    answers TEXT, route_prediction TEXT,
    hard_gates TEXT, router_result TEXT, router_reason TEXT,
    policy_version TEXT,
    latency_ms INTEGER, created_at TEXT
);
CREATE TABLE IF NOT EXISTS cases (
    case_id TEXT PRIMARY KEY,
    alert_id TEXT,
    route TEXT, escalation_reasons TEXT,
    state TEXT,
    status TEXT, verdict TEXT,
    llm TEXT, prompt_version TEXT,
    tool_calls TEXT, evidence TEXT, hypotheses TEXT,
    tokens INTEGER, latency_ms INTEGER, cost_usd REAL,
    human_override TEXT,
    created_at TEXT, updated_at TEXT
);
CREATE TABLE IF NOT EXISTS feedback (
    feedback_id TEXT PRIMARY KEY,
    decision_id TEXT, alert_id TEXT,
    feedback_type TEXT, human_verdict TEXT,
    override_reason TEXT, payload TEXT,
    created_at TEXT
);
CREATE TABLE IF NOT EXISTS replay_runs (
    run_id TEXT PRIMARY KEY,
    requested_by TEXT, provider TEXT,
    threshold_version TEXT, question_version TEXT,
    alert_count INTEGER, metrics TEXT, results TEXT,
    created_at TEXT
);
CREATE TABLE IF NOT EXISTS adjudications (
    family_id TEXT PRIMARY KEY,
    family_key TEXT,            -- JSON list [name, src_scopes, dst_scopes, domain]
    name TEXT,
    soc_verdict TEXT,           -- 有效告警 | 无效告警 | 需复查
    disposition TEXT,           -- auto_close_ok|suppress|blocklist|monitor|relabel
    alert_ids TEXT,             -- JSON list of member worksheet ids
    applies_to_family INTEGER,  -- 1 = verdict covers the whole family
    days TEXT,                  -- JSON list of export days
    engine_route TEXT,          -- route at adjudication time (evidence)
    adjudicator TEXT, source_worksheet TEXT, notes TEXT,
    created_at TEXT, updated_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_decisions_alert ON decisions(alert_id);
CREATE INDEX IF NOT EXISTS idx_cases_alert ON cases(alert_id);
CREATE INDEX IF NOT EXISTS idx_feedback_alert ON feedback(alert_id);
"""


class Store:
    def __init__(self, path: Optional[str] = None) -> None:
        self.path = path or os.environ.get(
            "TRIAGE_ENGINE_DB",
            str(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "triage_engine.db")),
        )
        self._lock = threading.Lock()
        if self.path != ":memory:":
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        # the offline adjudication-import CLI writes the same DB file the
        # service may hold - retry briefly instead of failing locked
        self._conn.execute("PRAGMA busy_timeout = 5000")
        with self._lock, self._conn:
            self._conn.executescript(_SCHEMA)

    # ------------------------------------------------------------------ write
    def _now(self) -> str:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    def save_decision(self, record: Dict[str, Any]) -> str:
        decision_id = record.get("decision_id") or f"D-{uuid.uuid4().hex[:12]}"
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT OR REPLACE INTO decisions VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    decision_id, record.get("alert_id"),
                    record.get("provider"), record.get("model"), record.get("model_version"),
                    record.get("state_hash"), record.get("question_version"),
                    json.dumps(record.get("answers", {})), json.dumps(record.get("route_prediction", {})),
                    json.dumps(record.get("hard_gates", [])), record.get("router_result"),
                    json.dumps(record.get("router_reason", [])),
                    record.get("policy_version"),
                    record.get("latency_ms", 0), self._now(),
                ),
            )
        return decision_id

    def save_case(self, case: Dict[str, Any]) -> str:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT OR REPLACE INTO cases VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    case["case_id"], case.get("alert_id"),
                    case.get("route"), json.dumps(case.get("escalation_reasons", [])),
                    json.dumps(case.get("state", {})),
                    case.get("status", "open"), json.dumps(case.get("verdict")),
                    case.get("llm"), case.get("prompt_version"),
                    json.dumps(case.get("tool_calls", [])),
                    json.dumps(case.get("evidence", [])), json.dumps(case.get("hypotheses", [])),
                    case.get("tokens", 0), case.get("latency_ms", 0), case.get("cost_usd", 0.0),
                    json.dumps(case.get("human_override")),
                    case.get("created_at", self._now()), self._now(),
                ),
            )
        return case["case_id"]

    def save_feedback(self, record: Dict[str, Any]) -> str:
        feedback_id = f"FB-{uuid.uuid4().hex[:10]}"
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO feedback VALUES (?,?,?,?,?,?,?,?)",
                (
                    feedback_id, record.get("decision_id"), record.get("alert_id"),
                    record.get("feedback_type", "override"), record.get("human_verdict"),
                    record.get("override_reason"), json.dumps(record.get("payload", {})),
                    self._now(),
                ),
            )
        return feedback_id

    def save_replay_run(self, record: Dict[str, Any]) -> str:
        run_id = record.get("run_id") or f"RP-{uuid.uuid4().hex[:10]}"
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT OR REPLACE INTO replay_runs VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    run_id, record.get("requested_by"), record.get("provider"),
                    record.get("threshold_version"), record.get("question_version"),
                    record.get("alert_count", 0),
                    json.dumps(record.get("metrics", {})), json.dumps(record.get("results", [])),
                    self._now(),
                ),
            )
        return run_id

    def save_adjudication(self, record: Dict[str, Any]) -> str:
        """Upsert a family adjudication (the SOC may revisit a family).

        Returns the family_id (the primary key - stable across re-imports).
        """
        family_id = record["family_id"]
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO adjudications VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(family_id) DO UPDATE SET
                    family_key=excluded.family_key, name=excluded.name,
                    soc_verdict=excluded.soc_verdict, disposition=excluded.disposition,
                    alert_ids=excluded.alert_ids, applies_to_family=excluded.applies_to_family,
                    days=excluded.days, engine_route=excluded.engine_route,
                    adjudicator=excluded.adjudicator,
                    source_worksheet=excluded.source_worksheet, notes=excluded.notes,
                    updated_at=excluded.updated_at
                """,
                (
                    family_id,
                    json.dumps(record.get("family_key", []), ensure_ascii=False),
                    record.get("name"),
                    record.get("soc_verdict"),
                    record.get("disposition"),
                    json.dumps(record.get("alert_ids", [])),
                    1 if record.get("applies_to_family") else 0,
                    json.dumps(record.get("days", [])),
                    record.get("engine_route"),
                    record.get("adjudicator"),
                    record.get("source_worksheet"),
                    record.get("notes"),
                    self._now(), self._now(),
                ),
            )
        return family_id

    # ------------------------------------------------------------------- read
    def get_decision(self, decision_id: str) -> Optional[Dict[str, Any]]:
        row = self._conn.execute("SELECT * FROM decisions WHERE decision_id=?", (decision_id,)).fetchone()
        return dict(row) if row else None

    def get_case(self, case_id: str) -> Optional[Dict[str, Any]]:
        row = self._conn.execute("SELECT * FROM cases WHERE case_id=?", (case_id,)).fetchone()
        return self._unjson_case(dict(row)) if row else None

    def list_cases(self, limit: int = 50) -> List[Dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM cases ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [self._unjson_case(dict(r)) for r in rows]

    def list_feedback(self, alert_id: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        if alert_id:
            rows = self._conn.execute(
                "SELECT * FROM feedback WHERE alert_id=? ORDER BY created_at DESC LIMIT ?",
                (alert_id, limit),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM feedback ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["payload"] = json.loads(d.get("payload") or "{}")
            out.append(d)
        return out

    def get_replay_run(self, run_id: str) -> Optional[Dict[str, Any]]:
        row = self._conn.execute("SELECT * FROM replay_runs WHERE run_id=?", (run_id,)).fetchone()
        if not row:
            return None
        d = dict(row)
        d["metrics"] = json.loads(d.get("metrics") or "{}")
        d["results"] = json.loads(d.get("results") or "[]")
        return d

    def list_adjudications(self, family_id: Optional[str] = None,
                           disposition: Optional[str] = None,
                           limit: int = 100) -> List[Dict[str, Any]]:
        query = "SELECT * FROM adjudications"
        conditions: List[str] = []
        params: List[Any] = []
        if family_id:
            conditions.append("family_id=?")
            params.append(family_id)
        if disposition:
            conditions.append("disposition=?")
            params.append(disposition)
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY updated_at DESC LIMIT ?"
        params.append(limit)
        rows = self._conn.execute(query, params).fetchall()
        return [self._unjson_adjudication(dict(r)) for r in rows]

    def get_adjudication(self, family_id: str) -> Optional[Dict[str, Any]]:
        row = self._conn.execute(
            "SELECT * FROM adjudications WHERE family_id=?", (family_id,)
        ).fetchone()
        return self._unjson_adjudication(dict(row)) if row else None

    def adjudication_stats(self) -> Dict[str, Any]:
        rows = self._conn.execute("SELECT * FROM adjudications").fetchall()
        by_verdict: Dict[str, int] = {}
        by_disposition: Dict[str, int] = {}
        member_alerts = 0
        for r in rows:
            by_verdict[r["soc_verdict"]] = by_verdict.get(r["soc_verdict"], 0) + 1
            by_disposition[r["disposition"]] = by_disposition.get(r["disposition"], 0) + 1
            member_alerts += len(json.loads(r["alert_ids"] or "[]"))
        return {"total": len(rows), "by_verdict": by_verdict,
                "by_disposition": by_disposition, "member_alerts": member_alerts}

    @staticmethod
    def _unjson_adjudication(d: Dict[str, Any]) -> Dict[str, Any]:
        for key in ("family_key", "alert_ids", "days"):
            if key in d and isinstance(d[key], str):
                d[key] = json.loads(d[key])
        if "applies_to_family" in d:
            d["applies_to_family"] = bool(d["applies_to_family"])
        return d

    def close(self) -> None:
        self._conn.close()

    @staticmethod
    def _unjson_case(d: Dict[str, Any]) -> Dict[str, Any]:
        for key in ("escalation_reasons", "state", "tool_calls", "evidence", "hypotheses", "verdict", "human_override"):
            if key in d and isinstance(d[key], str):
                d[key] = json.loads(d[key])
        return d


_store: Optional[Store] = None


def get_store() -> Store:
    global _store
    if _store is None:
        _store = Store()
    return _store


def set_store(store: Optional[Store]) -> None:
    """Test helper - inject an in-memory store."""
    global _store
    _store = store
