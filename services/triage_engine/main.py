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

"""AI Security Triage Engine - API service.

Fast path (System 1 / Laya), Security Decision Plane (gate + router + policy)
and slow path (Investigation Agent) behind a small REST surface
(requirement §43):

    POST /api/v1/triage                     full fast-path triage (+optional slow)
    POST /api/v1/decision                   fast decision only (unified §30:
                                            also POST /decision/v1/system-one)
    POST /api/v1/investigations             run a deep investigation
    GET  /api/v1/investigations/{case_id}
    GET  /api/v1/cases/{case_id}
    GET  /api/v1/cases
    POST /api/v1/replay                     batch replay / shadow evaluation
    POST /api/v1/feedback                   human feedback (§35)
    POST /api/v1/adjudications              batch SOC family adjudications
    GET  /api/v1/adjudications[/{family_id}]
    GET  /health
"""

import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional

# allow both `python main.py` from this directory and package imports
_PARENT = str(Path(__file__).resolve().parent.parent)
if __package__ in (None, "") and _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from triage_engine.core import policy as policy_mod
from triage_engine.core.compressor import compress
from triage_engine.core.context import AlertContext
from triage_engine.core.registry import registry
from triage_engine.core.store import get_store
from triage_engine.decision_models import decide_with_fallback, get_provider
from triage_engine.decision_models.base import DecisionContext
from triage_engine.evaluation.replay import replay
from triage_engine.evaluation.worksheet import DISPOSITIONS, SOC_VERDICTS
from triage_engine.fast_path.triage import triage_fast
from triage_engine.slow_path.investigator import run_investigation
from triage_engine.slow_path.llm import LLMClient

SLOW_ROUTES = {"DEEP_INVESTIGATE", "URGENT_ESCALATE"}


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.store = get_store()
    app.state.llm = LLMClient()
    try:
        app.state.provider = get_provider()
        provider_name = app.state.provider.name
    except Exception:  # noqa: BLE001 - service still boots with rule fallback
        app.state.provider = get_provider("rule")
        provider_name = "rule (fallback)"
    yield


app = FastAPI(
    title="AI Security Triage Engine",
    version="1.0.0",
    description="System 1 (Laya fast decisions) + System 2 (Investigation Agent) + Decision Plane",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]
)


# ---------------------------------------------------------------------- models
class TriageRequest(BaseModel):
    alert: Dict[str, Any]
    run_slow: bool = Field(
        default=False, description="run the Investigation Agent when routed to a slow route"
    )


class DecisionRequest(BaseModel):
    state: Dict[str, Any]
    questions: Optional[Dict[str, Dict[str, Any]]] = None
    provider: str = "auto"
    alert_id: str = "ALT-API"


class InvestigationRequest(BaseModel):
    alert: Dict[str, Any]
    route: str = "DEEP_INVESTIGATE"
    reason_codes: List[str] = Field(default_factory=list)
    budget_overrides: Optional[Dict[str, Any]] = None


class ReplayRequest(BaseModel):
    alerts: List[Dict[str, Any]]
    labels: Optional[Dict[str, str]] = None
    provider: Optional[str] = None
    persist_decisions: bool = False


class FeedbackRequest(BaseModel):
    decision_id: Optional[str] = None
    alert_id: Optional[str] = None
    feedback_type: str = "override"   # agree | override | wrong_classification | missing_evidence | wrong_route
    human_verdict: Optional[str] = None
    override_reason: Optional[str] = None
    payload: Dict[str, Any] = Field(default_factory=dict)


class ActionPolicyRequest(BaseModel):
    action: str
    verdict: Optional[Dict[str, Any]] = None
    state: Optional[Dict[str, Any]] = None


class AdjudicationIn(BaseModel):
    """One family adjudication from the SOC worksheet (or manual review)."""
    family_id: str
    family_key: Optional[List[Any]] = None
    name: Optional[str] = None
    soc_verdict: str                                    # SOC_VERDICTS
    disposition: Optional[str] = None                   # DISPOSITIONS
    alert_ids: List[str] = Field(default_factory=list)
    applies_to_family: bool = False
    days: List[str] = Field(default_factory=list)
    engine_route: Optional[str] = None                  # route at adjudication time
    adjudicator: Optional[str] = None
    source_worksheet: Optional[str] = None
    notes: Optional[str] = None


class AdjudicationBatchRequest(BaseModel):
    adjudications: List[AdjudicationIn]
    link_feedback: bool = Field(
        default=True, description="also append a soc_adjudication feedback row per member alert"
    )


# -------------------------------------------------------------------- endpoints
@app.get("/health")
async def health() -> Dict[str, Any]:
    provider = get_provider()
    laya_ok = getattr(provider, "available", True)
    return {
        "success": True,
        "data": {
            "service": "triage-engine",
            "provider": provider.name,
            "laya_available": laya_ok,
            "llm_judge_available": LLMClient().available,
            "question_version": registry.question_version,
            "threshold_version": registry.threshold_version,
            "policy_version": registry.policy.get("version"),
        },
    }


@app.post("/api/v1/triage")
async def triage(req: TriageRequest) -> Dict[str, Any]:
    result = await triage_fast(req.alert, provider=app.state.provider, store=app.state.store)
    case = None
    if req.run_slow and result["route"] in SLOW_ROUTES:
        case = await run_investigation(
            req.alert, result["compressed_state"], result["route"],
            result["reason_codes"], llm=app.state.llm, store=app.state.store,
        )
    # policy preview for the routed outcome (requirement §25-26)
    preview_action = {
        "FAST_CLOSE": "close_false_positive",
        "FAST_QUEUE": "reprioritize_alert",
        "DEEP_INVESTIGATE": "create_case",
        "URGENT_ESCALATE": "notify_soc",
        "HUMAN_REVIEW": "create_case",
    }[result["route"]]
    result["policy"] = policy_mod.evaluate_action(
        preview_action, verdict=None, state=result["compressed_state"]
    ).model_dump()
    if case:
        result["case_id"] = case["case_id"]
        result["verdict"] = case["verdict"]
    return {"success": True, "data": result}


@app.post("/api/v1/decision")
@app.post("/decision/v1/system-one")
async def decision(req: DecisionRequest) -> Dict[str, Any]:
    """Unified fast-decision endpoint (requirement §30) - callers cannot tell
    whether Laya, Jev or an internal model answered."""
    provider = app.state.provider if req.provider == "auto" else get_provider(req.provider)
    state_text = " ".join(f"{k}: {v}" for k, v in sorted(req.state.items()))
    ctx = DecisionContext(
        alert_id=req.alert_id, state_text=state_text, question_version=registry.question_version
    )
    result = await decide_with_fallback(req.state, req.questions or registry.questions, ctx, provider)
    return {
        "success": True,
        "data": {
            "provider": result.provider,
            "model": result.model,
            "answers": result.decisions,
            "route_prediction": result.route_prediction,
            "latency_ms": result.latency_ms,
            "degraded": result.degraded,
            "model_metadata": result.model_metadata,
        },
    }


@app.post("/api/v1/investigations")
async def create_investigation(req: InvestigationRequest) -> Dict[str, Any]:
    from core.compressor import compress
    from core.context import AlertContext

    ctx = AlertContext.build(req.alert)
    state = compress(ctx, req.alert).model_dump()
    case = await run_investigation(
        req.alert, state, req.route, req.reason_codes,
        llm=app.state.llm, budget_overrides=req.budget_overrides, store=app.state.store,
    )
    return {"success": True, "data": {"case_id": case["case_id"], "case": case}}


@app.get("/api/v1/investigations/{case_id}")
@app.get("/api/v1/cases/{case_id}")
async def get_case(case_id: str) -> Dict[str, Any]:
    case = app.state.store.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail={"error_code": "CASE_NOT_FOUND", "case_id": case_id})
    return {"success": True, "data": case}


@app.get("/api/v1/cases")
async def list_cases(limit: int = 50) -> Dict[str, Any]:
    return {"success": True, "data": app.state.store.list_cases(limit=limit), "meta": {"limit": limit}}


@app.post("/api/v1/replay")
async def run_replay(req: ReplayRequest) -> Dict[str, Any]:
    provider = get_provider(req.provider) if req.provider else app.state.provider
    run_result = await replay(
        req.alerts, labels=req.labels, provider=provider,
        persist_decisions=req.persist_decisions, store=app.state.store,
    )
    return {"success": True, "data": run_result}


@app.post("/api/v1/feedback")
async def feedback(req: FeedbackRequest) -> Dict[str, Any]:
    feedback_id = app.state.store.save_feedback(req.model_dump())
    return {"success": True, "data": {"feedback_id": feedback_id}}


@app.get("/api/v1/feedback")
async def list_feedback(alert_id: Optional[str] = None, limit: int = 100) -> Dict[str, Any]:
    return {"success": True, "data": app.state.store.list_feedback(alert_id=alert_id, limit=limit)}


@app.post("/api/v1/adjudications")
async def import_adjudications(req: AdjudicationBatchRequest) -> Dict[str, Any]:
    """Batch-import SOC family adjudications (worksheet or manual review).

    Each record upserts the family row and, by default, appends one
    ``soc_adjudication`` feedback row per member alert so the existing
    feedback read path keeps working.
    """
    for record in req.adjudications:
        if record.soc_verdict not in SOC_VERDICTS:
            raise HTTPException(status_code=422, detail={
                "error_code": "INVALID_VERDICT", "family_id": record.family_id,
                "value": record.soc_verdict,
                "allowed": list(SOC_VERDICTS)})
        if record.disposition is not None and record.disposition not in DISPOSITIONS:
            raise HTTPException(status_code=422, detail={
                "error_code": "INVALID_DISPOSITION", "family_id": record.family_id,
                "value": record.disposition, "allowed": list(DISPOSITIONS)})
    if not req.adjudications:
        raise HTTPException(status_code=422, detail={"error_code": "EMPTY_BATCH"})

    feedback_rows = 0
    for record in req.adjudications:
        app.state.store.save_adjudication(record.model_dump())
        if req.link_feedback:
            for alert_id in record.alert_ids:
                app.state.store.save_feedback({
                    "alert_id": alert_id,
                    "feedback_type": "soc_adjudication",
                    "human_verdict": record.soc_verdict,
                    "override_reason": record.disposition,
                    "payload": {
                        "family_id": record.family_id,
                        "family_key": record.family_key,
                        "days": record.days,
                        "engine_route": record.engine_route,
                        "source_worksheet": record.source_worksheet,
                        "adjudicator": record.adjudicator,
                        "notes": record.notes,
                    },
                })
                feedback_rows += 1
    return {
        "success": True,
        "data": {
            "imported": len(req.adjudications),
            "family_ids": [r.family_id for r in req.adjudications],
            "feedback_rows": feedback_rows,
        },
    }


@app.get("/api/v1/adjudications")
async def list_adjudications(family_id: Optional[str] = None,
                             disposition: Optional[str] = None,
                             limit: int = 100) -> Dict[str, Any]:
    return {
        "success": True,
        "data": app.state.store.list_adjudications(
            family_id=family_id, disposition=disposition, limit=limit),
        "meta": {"limit": limit, "stats": app.state.store.adjudication_stats()},
    }


@app.get("/api/v1/adjudications/{family_id}")
async def get_adjudication(family_id: str) -> Dict[str, Any]:
    record = app.state.store.get_adjudication(family_id)
    if not record:
        raise HTTPException(status_code=404, detail={
            "error_code": "ADJUDICATION_NOT_FOUND", "family_id": family_id})
    return {"success": True, "data": record}


@app.post("/api/v1/policy/evaluate")
async def evaluate_action_policy(req: ActionPolicyRequest) -> Dict[str, Any]:
    decision = policy_mod.evaluate_action(req.action, verdict=req.verdict, state=req.state)
    return {"success": True, "data": decision.model_dump()}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host=os.environ.get("TRIAGE_ENGINE_HOST", "0.0.0.0"),
        port=int(os.environ.get("TRIAGE_ENGINE_PORT", "8009")),
        reload=False,
    )
