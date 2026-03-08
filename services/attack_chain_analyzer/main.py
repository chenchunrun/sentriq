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

"""
Attack Chain Analyzer Service - MITRE ATT&CK mapping and attack pattern analysis.

This service provides:
- Attack chain analysis from alert sequences
- MITRE ATT&CK technique mapping
- Kill chain phase identification
- Related campaign detection
- Mitigation recommendations
"""

import os
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from shared.database import close_database, get_database_manager, init_database
from shared.utils import Config, get_logger

from attack_patterns import AttackPattern, AttackPatternAnalyzer, PatternIndicator
from mitre_mapper import (
    AttackPhase,
    MitreMapper,
    MitreTactic,
    MitreTechnique,
    MITRE_TECHNIQUES,
)

logger = get_logger(__name__)
config = Config()


# =============================================================================
# Request/Response Models
# =============================================================================


class AlertInput(BaseModel):
    """Input alert model."""

    alert_id: str
    alert_type: str
    severity: str = "medium"
    timestamp: Optional[str] = None
    source_ip: Optional[str] = None
    target_ip: Optional[str] = None
    asset_id: Optional[str] = None
    user_id: Optional[str] = None
    file_hash: Optional[str] = None
    url: Optional[str] = None
    description: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


class AttackChainRequest(BaseModel):
    """Request for attack chain analysis."""

    alerts: List[AlertInput]
    context: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Additional context (network, assets, users)",
    )


class TechniqueResult(BaseModel):
    """MITRE technique result."""

    id: str
    name: str
    tactic: str
    description: str
    detection_methods: List[str]
    mitigations: List[str]


class AttackChainResult(BaseModel):
    """Attack chain analysis result."""

    attack_stages: List[str] = Field(description="Identified attack stages")
    ttps: List[str] = Field(description="MITRE ATT&CK technique IDs")
    techniques: List[TechniqueResult] = Field(description="Detailed technique information")
    kill_chain_phase: str = Field(description="Estimated kill chain phase")
    confidence: float = Field(description="Analysis confidence (0-1)")
    attack_patterns: List[Dict[str, Any]] = Field(description="Detected attack patterns")
    related_campaigns: List[Dict[str, Any]] = Field(description="Related threat campaigns")
    mitigations: List[Dict[str, Any]] = Field(description="Prioritized mitigations")
    timeline: List[Dict[str, Any]] = Field(description="Attack timeline")


class SuccessResponse(BaseModel):
    """Standard success response."""

    success: bool = True
    data: Any
    meta: Dict[str, Any]


# =============================================================================
# Application Setup
# =============================================================================


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifespan."""
    logger.info("Starting Attack Chain Analyzer service...")

    try:
        # Initialize database
        await init_database(
            database_url=config.database_url,
            pool_size=int(os.getenv("DB_POOL_SIZE", "5")),
            max_overflow=int(os.getenv("DB_MAX_OVERFLOW", "10")),
            echo=config.debug,
        )
        db_manager = get_database_manager()
        logger.info("✓ Database connected")

        logger.info("✓ Attack Chain Analyzer service started successfully")

        yield

    except Exception as e:
        logger.error(f"Failed to start service: {e}")
        raise

    finally:
        await close_database()
        logger.info("✓ Database connection closed")
        logger.info("✓ Attack Chain Analyzer service stopped")


app = FastAPI(
    title="Attack Chain Analyzer Service",
    description="MITRE ATT&CK mapping and attack pattern analysis",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# =============================================================================
# Core Analysis Functions
# =============================================================================


def analyze_attack_chain(request: AttackChainRequest) -> AttackChainResult:
    """
    Perform comprehensive attack chain analysis.

    Args:
        request: Attack chain analysis request with alerts and context

    Returns:
        Comprehensive attack chain analysis result
    """
    alerts = [a.model_dump() for a in request.alerts]
    context = request.context or {}

    logger.info(f"Analyzing attack chain with {len(alerts)} alerts")

    # Step 1: Map alerts to MITRE techniques
    all_techniques: List[MitreTechnique] = []
    for alert in alerts:
        techniques = MitreMapper.map_alert_to_techniques(
            alert_type=alert.get("alert_type", "unknown"),
            alert_data=alert,
        )
        all_techniques.extend(techniques)

    # Deduplicate techniques
    unique_techniques = list({t.id: t for t in all_techniques}.values())

    # Step 2: Determine attack stages
    attack_stages = list(set(
        MitreMapper._tactic_to_phase(t.tactic).value
        for t in unique_techniques
    ))

    # Step 3: Determine kill chain phase
    if alerts:
        # Use the highest severity alert to estimate phase
        severity_priority = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        highest_severity = max(
            alerts,
            key=lambda a: severity_priority.get(a.get("severity", "info"), 0),
        )
        kill_chain_phase = MitreMapper.determine_kill_chain_phase(
            alert_type=highest_severity.get("alert_type", "unknown"),
            severity=highest_severity.get("severity", "medium"),
            techniques=unique_techniques,
        )
    else:
        kill_chain_phase = AttackPhase.RECONNAISSANCE

    # Step 4: Detect attack patterns
    pattern_indicators = AttackPatternAnalyzer.analyze_alerts(alerts, context)

    # Step 5: Get related campaigns
    related_campaigns = MitreMapper.get_related_campaigns(unique_techniques)

    # Step 6: Get mitigations
    mitigations = MitreMapper.get_mitigations(unique_techniques)

    # Step 7: Build timeline
    timeline = build_attack_timeline(alerts, unique_techniques, pattern_indicators)

    # Calculate overall confidence
    confidence = calculate_confidence(
        len(unique_techniques),
        len(pattern_indicators),
        len(alerts),
    )

    # Build result
    return AttackChainResult(
        attack_stages=sorted(attack_stages),
        ttps=[t.id for t in unique_techniques],
        techniques=[
            TechniqueResult(
                id=t.id,
                name=t.name,
                tactic=t.tactic.value,
                description=t.description,
                detection_methods=t.detection_methods,
                mitigations=t.mitigations,
            )
            for t in unique_techniques
        ],
        kill_chain_phase=kill_chain_phase.value,
        confidence=confidence,
        attack_patterns=[
            {
                "pattern": p.pattern.value,
                "confidence": p.confidence,
                "evidence": p.evidence,
                "affected_assets": p.affected_assets,
            }
            for p in pattern_indicators
        ],
        related_campaigns=related_campaigns,
        mitigations=mitigations,
        timeline=timeline,
    )


def build_attack_timeline(
    alerts: List[Dict[str, Any]],
    techniques: List[MitreTechnique],
    patterns: List[PatternIndicator],
) -> List[Dict[str, Any]]:
    """Build attack timeline from alerts and analysis."""
    timeline = []

    # Add alert events
    for alert in sorted(alerts, key=lambda a: a.get("timestamp", "")):
        timeline.append({
            "type": "alert",
            "timestamp": alert.get("timestamp"),
            "event": alert.get("description", alert.get("alert_type")),
            "alert_type": alert.get("alert_type"),
            "severity": alert.get("severity"),
            "source_ip": alert.get("source_ip"),
            "target_ip": alert.get("target_ip"),
            "asset_id": alert.get("asset_id"),
        })

    # Add pattern detection events
    for pattern in patterns:
        for event in pattern.timeline:
            timeline.append({
                "type": "pattern",
                "pattern": pattern.pattern.value,
                **event,
            })

    # Sort by timestamp
    timeline.sort(key=lambda e: e.get("timestamp", ""))

    return timeline[:50]  # Limit to 50 events


def calculate_confidence(
    technique_count: int,
    pattern_count: int,
    alert_count: int,
) -> float:
    """Calculate overall analysis confidence."""
    base_confidence = 0.5

    # More techniques = higher confidence (up to +0.3)
    technique_bonus = min(0.3, technique_count * 0.05)

    # More patterns = higher confidence (up to +0.15)
    pattern_bonus = min(0.15, pattern_count * 0.05)

    # More alerts = more data (up to +0.05)
    alert_bonus = min(0.05, alert_count * 0.01)

    return min(0.95, base_confidence + technique_bonus + pattern_bonus + alert_bonus)


# =============================================================================
# API Endpoints
# =============================================================================


@app.post("/api/v1/analyze-chain", response_model=SuccessResponse)
async def analyze_chain(request: AttackChainRequest):
    """
    Analyze attack chain from alert sequence.

    Returns comprehensive analysis including:
    - Attack stages and kill chain phase
    - MITRE ATT&CK technique mapping
    - Attack pattern detection
    - Related campaigns
    - Mitigation recommendations
    """
    try:
        if not request.alerts:
            raise HTTPException(status_code=400, detail="No alerts provided")

        result = analyze_attack_chain(request)

        logger.info(
            f"Attack chain analysis completed: {len(result.ttps)} techniques, "
            f"{len(result.attack_patterns)} patterns, confidence={result.confidence:.2f}"
        )

        return SuccessResponse(
            data=result.model_dump(),
            meta={
                "timestamp": datetime.utcnow().isoformat(),
                "version": "1.0.0",
                "alert_count": len(request.alerts),
            },
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Attack chain analysis failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@app.post("/api/v1/map-techniques", response_model=SuccessResponse)
async def map_techniques(alert_type: str, alert_data: Optional[Dict[str, Any]] = None):
    """
    Map a single alert to MITRE ATT&CK techniques.

    Useful for quick technique lookups without full chain analysis.
    """
    try:
        techniques = MitreMapper.map_alert_to_techniques(alert_type, alert_data)

        return SuccessResponse(
            data={
                "alert_type": alert_type,
                "techniques": [
                    {
                        "id": t.id,
                        "name": t.name,
                        "tactic": t.tactic.value,
                        "description": t.description,
                    }
                    for t in techniques
                ],
            },
            meta={
                "timestamp": datetime.utcnow().isoformat(),
                "technique_count": len(techniques),
            },
        )

    except Exception as e:
        logger.error(f"Technique mapping failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/techniques/{technique_id}", response_model=SuccessResponse)
async def get_technique(technique_id: str):
    """Get details for a specific MITRE ATT&CK technique."""
    technique = MITRE_TECHNIQUES.get(technique_id.upper())

    if not technique:
        raise HTTPException(status_code=404, detail=f"Technique {technique_id} not found")

    return SuccessResponse(
        data={
            "id": technique.id,
            "name": technique.name,
            "tactic": technique.tactic.value,
            "description": technique.description,
            "detection_methods": technique.detection_methods,
            "mitigations": technique.mitigations,
            "related_techniques": technique.related_techniques,
        },
        meta={
            "timestamp": datetime.utcnow().isoformat(),
        },
    )


@app.get("/api/v1/techniques", response_model=SuccessResponse)
async def list_techniques(tactic: Optional[str] = None):
    """
    List all available MITRE ATT&CK techniques.

    Optionally filter by tactic.
    """
    techniques = list(MITRE_TECHNIQUES.values())

    if tactic:
        techniques = [t for t in techniques if t.tactic.value == tactic.upper()]

    return SuccessResponse(
        data=[
            {
                "id": t.id,
                "name": t.name,
                "tactic": t.tactic.value,
            }
            for t in techniques
        ],
        meta={
            "timestamp": datetime.utcnow().isoformat(),
            "total_count": len(techniques),
        },
    )


@app.get("/api/v1/tactics", response_model=SuccessResponse)
async def list_tactics():
    """List all MITRE ATT&CK tactics."""
    return SuccessResponse(
        data=[
            {"id": tactic.value, "name": tactic.name}
            for tactic in MitreTactic
        ],
        meta={
            "timestamp": datetime.utcnow().isoformat(),
            "total_count": len(MitreTactic),
        },
    )


@app.get("/api/v1/kill-chain-phases", response_model=SuccessResponse)
async def list_kill_chain_phases():
    """List all cyber kill chain phases."""
    return SuccessResponse(
        data=[
            {"id": phase.value, "name": phase.name}
            for phase in AttackPhase
        ],
        meta={
            "timestamp": datetime.utcnow().isoformat(),
        },
    )


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "attack-chain-analyzer",
        "timestamp": datetime.utcnow().isoformat(),
        "capabilities": {
            "techniques": len(MITRE_TECHNIQUES),
            "tactics": len(MitreTactic),
            "attack_patterns": len(AttackPattern),
        },
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host=config.host,
        port=int(os.getenv("PORT", "9502")),
        reload=config.debug,
    )
