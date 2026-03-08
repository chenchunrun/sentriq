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
Triage repository for database operations.

This module provides all database operations for AI triage results,
including CRUD operations, filtering, and review management.
"""

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from shared.database.models import TriageResult
from shared.database.repositories.base import BaseRepository
from shared.utils.logger import get_logger
from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

logger = get_logger(__name__)


class TriageRepository(BaseRepository[TriageResult]):
    """
    Repository for TriageResult model operations.

    Provides specialized methods for triage result queries,
    filtering, and review management.
    """

    def __init__(self, session: AsyncSession):
        """
        Initialize triage repository.

        Args:
            session: Database session
        """
        super().__init__(TriageResult, session)

    async def save_triage_result(self, triage_data: Dict[str, Any]) -> TriageResult:
        """
        Save a new triage result.

        Args:
            triage_data: Triage result data dictionary

        Returns:
            Created triage result instance
        """
        triage_result = TriageResult(**triage_data)
        self.session.add(triage_result)
        await self.session.flush()
        await self.session.refresh(triage_result)

        logger.info(
            "Triage result saved",
            extra={
                "id": str(triage_result.id),
                "alert_id": triage_result.alert_id,
                "risk_score": triage_result.risk_score,
                "risk_level": triage_result.risk_level,
            },
        )

        return triage_result

    async def get_triage_result_by_id(self, result_id: str) -> Optional[TriageResult]:
        """
        Get triage result by ID.

        Args:
            result_id: Triage result UUID

        Returns:
            Triage result instance or None
        """
        return await self.get(result_id)

    async def get_triage_result_by_alert_id(self, alert_id: str) -> Optional[TriageResult]:
        """
        Get triage result by alert ID.

        Args:
            alert_id: Alert identifier

        Returns:
            Triage result instance or None
        """
        result = await self.session.execute(
            select(TriageResult).where(TriageResult.alert_id == alert_id)
        )
        return result.scalar_one_or_none()

    async def update_risk_score(
        self,
        alert_id: str,
        risk_score: float,
        risk_level: str,
        confidence: Optional[float] = None,
    ) -> Optional[TriageResult]:
        """
        Update risk score for an alert's triage result.

        Args:
            alert_id: Alert identifier
            risk_score: New risk score (0-100)
            risk_level: Risk level (critical, high, medium, low)
            confidence: Optional confidence score

        Returns:
            Updated triage result or None
        """
        triage_result = await self.get_triage_result_by_alert_id(alert_id)
        if not triage_result:
            logger.warning(f"Triage result not found for alert: {alert_id}")
            return None

        triage_result.risk_score = risk_score
        triage_result.risk_level = risk_level
        if confidence is not None:
            triage_result.confidence = confidence

        await self.session.flush()
        await self.session.refresh(triage_result)

        logger.info(
            "Risk score updated",
            extra={
                "alert_id": alert_id,
                "risk_score": risk_score,
                "risk_level": risk_level,
            },
        )

        return triage_result

    async def mark_for_human_review(
        self,
        alert_id: str,
        requires_review: bool = True,
    ) -> Optional[TriageResult]:
        """
        Mark triage result as requiring human review.

        Args:
            alert_id: Alert identifier
            requires_review: Whether human review is required

        Returns:
            Updated triage result or None
        """
        triage_result = await self.get_triage_result_by_alert_id(alert_id)
        if not triage_result:
            logger.warning(f"Triage result not found for alert: {alert_id}")
            return None

        triage_result.requires_human_review = requires_review

        await self.session.flush()
        await self.session.refresh(triage_result)

        logger.info(
            "Human review flag updated",
            extra={
                "alert_id": alert_id,
                "requires_review": requires_review,
            },
        )

        return triage_result

    async def submit_review(
        self,
        alert_id: str,
        reviewer_id: str,
        comments: Optional[str] = None,
    ) -> Optional[TriageResult]:
        """
        Submit human review for triage result.

        Args:
            alert_id: Alert identifier
            reviewer_id: Reviewer user UUID
            comments: Optional reviewer comments

        Returns:
            Updated triage result or None
        """
        triage_result = await self.get_triage_result_by_alert_id(alert_id)
        if not triage_result:
            logger.warning(f"Triage result not found for alert: {alert_id}")
            return None

        triage_result.reviewed_by = reviewer_id
        triage_result.reviewed_at = datetime.utcnow()
        if comments:
            triage_result.reviewer_comments = comments

        await self.session.flush()
        await self.session.refresh(triage_result)

        logger.info(
            "Review submitted",
            extra={
                "alert_id": alert_id,
                "reviewer_id": reviewer_id,
            },
        )

        return triage_result

    async def get_triage_results_by_risk_level(
        self,
        risk_level: str,
        skip: int = 0,
        limit: int = 100,
    ) -> List[TriageResult]:
        """
        Get triage results by risk level.

        Args:
            risk_level: Risk level (critical, high, medium, low)
            skip: Number of records to skip
            limit: Max number of records to return

        Returns:
            List of triage results
        """
        result = await self.session.execute(
            select(TriageResult)
            .where(TriageResult.risk_level == risk_level)
            .order_by(TriageResult.risk_score.desc())
            .offset(skip)
            .limit(limit)
        )
        return list(result.scalars().all())

    async def get_triage_results_pending_review(
        self,
        skip: int = 0,
        limit: int = 100,
    ) -> List[TriageResult]:
        """
        Get triage results pending human review.

        Args:
            skip: Number of records to skip
            limit: Max number of records to return

        Returns:
            List of triage results pending review
        """
        result = await self.session.execute(
            select(TriageResult)
            .where(
                and_(
                    TriageResult.requires_human_review == True,
                    TriageResult.reviewed_at.is_(None),
                )
            )
            .order_by(TriageResult.risk_score.desc())
            .offset(skip)
            .limit(limit)
        )
        return list(result.scalars().all())

    async def get_triage_results_reviewed_by_user(
        self,
        reviewer_id: str,
        skip: int = 0,
        limit: int = 100,
    ) -> List[TriageResult]:
        """
        Get triage results reviewed by a specific user.

        Args:
            reviewer_id: Reviewer user UUID
            skip: Number of records to skip
            limit: Max number of records to return

        Returns:
            List of reviewed triage results
        """
        result = await self.session.execute(
            select(TriageResult)
            .where(TriageResult.reviewed_by == reviewer_id)
            .order_by(TriageResult.reviewed_at.desc())
            .offset(skip)
            .limit(limit)
        )
        return list(result.scalars().all())

    async def get_triage_results_by_model(
        self,
        model_name: str,
        skip: int = 0,
        limit: int = 100,
    ) -> List[TriageResult]:
        """
        Get triage results by AI model used.

        Args:
            model_name: Model name (e.g., 'deepseek', 'qwen')
            skip: Number of records to skip
            limit: Max number of records to return

        Returns:
            List of triage results
        """
        result = await self.session.execute(
            select(TriageResult)
            .where(TriageResult.model_used == model_name)
            .order_by(TriageResult.created_at.desc())
            .offset(skip)
            .limit(limit)
        )
        return list(result.scalars().all())

    async def get_triage_results_by_date_range(
        self,
        start_date: datetime,
        end_date: datetime,
        skip: int = 0,
        limit: int = 100,
    ) -> List[TriageResult]:
        """
        Get triage results within a date range.

        Args:
            start_date: Start datetime
            end_date: End datetime
            skip: Number of records to skip
            limit: Max number of records to return

        Returns:
            List of triage results
        """
        result = await self.session.execute(
            select(TriageResult)
            .where(
                and_(
                    TriageResult.created_at >= start_date,
                    TriageResult.created_at <= end_date,
                )
            )
            .order_by(TriageResult.created_at.desc())
            .offset(skip)
            .limit(limit)
        )
        return list(result.scalars().all())

    async def get_triage_results_with_exploits(
        self,
        skip: int = 0,
        limit: int = 100,
    ) -> List[TriageResult]:
        """
        Get triage results with known exploits.

        Args:
            skip: Number of records to skip
            limit: Max number of records to return

        Returns:
            List of triage results with known exploits
        """
        result = await self.session.execute(
            select(TriageResult)
            .where(TriageResult.known_exploits == True)
            .order_by(TriageResult.risk_score.desc())
            .offset(skip)
            .limit(limit)
        )
        return list(result.scalars().all())

    async def get_triage_results_with_cve(
        self,
        cve_id: str,
        skip: int = 0,
        limit: int = 100,
    ) -> List[TriageResult]:
        """
        Get triage results associated with a specific CVE.

        Args:
            cve_id: CVE identifier (e.g., 'CVE-2024-1234')
            skip: Number of records to skip
            limit: Max number of records to return

        Returns:
            List of triage results
        """
        result = await self.session.execute(
            select(TriageResult)
            .where(TriageResult.cve_references.contains([cve_id]))
            .order_by(TriageResult.created_at.desc())
            .offset(skip)
            .limit(limit)
        )
        return list(result.scalars().all())

    async def get_average_risk_score(self) -> Optional[float]:
        """
        Get average risk score across all triage results.

        Returns:
            Average risk score or None
        """
        result = await self.session.execute(
            select(func.avg(TriageResult.risk_score))
        )
        return result.scalar()

    async def get_risk_level_distribution(self) -> Dict[str, int]:
        """
        Get distribution of risk levels.

        Returns:
            Dictionary with risk level as key and count as value
        """
        result = await self.session.execute(
            select(TriageResult.risk_level, func.count(TriageResult.id))
            .group_by(TriageResult.risk_level)
        )

        return {risk_level: count for risk_level, count in result.all()}

    async def get_model_usage_stats(self) -> Dict[str, int]:
        """
        Get usage statistics for AI models.

        Returns:
            Dictionary with model name as key and count as value
        """
        result = await self.session.execute(
            select(TriageResult.model_used, func.count(TriageResult.id))
            .group_by(TriageResult.model_used)
        )

        return {model: count for model, count in result.all()}

    async def get_pending_review_count(self) -> int:
        """
        Get count of triage results pending human review.

        Returns:
            Number of pending reviews
        """
        result = await self.session.execute(
            select(func.count(TriageResult.id)).where(
                and_(
                    TriageResult.requires_human_review == True,
                    TriageResult.reviewed_at.is_(None),
                )
            )
        )
        return result.scalar()

    async def get_average_processing_time(self) -> Optional[float]:
        """
        Get average AI processing time in milliseconds.

        Returns:
            Average processing time or None
        """
        result = await self.session.execute(
            select(func.avg(TriageResult.processing_time_ms)).where(
                TriageResult.processing_time_ms.isnot(None)
            )
        )
        return result.scalar()

    async def get_high_confidence_results(
        self,
        min_confidence: float = 0.8,
        skip: int = 0,
        limit: int = 100,
    ) -> List[TriageResult]:
        """
        Get high-confidence triage results.

        Args:
            min_confidence: Minimum confidence threshold
            skip: Number of records to skip
            limit: Max number of records to return

        Returns:
            List of high-confidence triage results
        """
        result = await self.session.execute(
            select(TriageResult)
            .where(TriageResult.confidence >= min_confidence)
            .order_by(TriageResult.confidence.desc())
            .offset(skip)
            .limit(limit)
        )
        return list(result.scalars().all())

    async def bulk_create_triage_results(
        self,
        triage_results_data: List[Dict[str, Any]],
    ) -> List[TriageResult]:
        """
        Bulk create triage results.

        Args:
            triage_results_data: List of triage result data dictionaries

        Returns:
            List of created triage result instances
        """
        triage_results = [
            TriageResult(**triage_data) for triage_data in triage_results_data
        ]
        self.session.add_all(triage_results)
        await self.session.flush()

        for triage_result in triage_results:
            await self.session.refresh(triage_result)

        logger.info(f"Bulk created {len(triage_results)} triage results")

        return triage_results

    async def update_threat_intel_summary(
        self,
        alert_id: str,
        threat_intel_summary: str,
        threat_intel_sources: List[str],
    ) -> Optional[TriageResult]:
        """
        Update threat intelligence summary for triage result.

        Args:
            alert_id: Alert identifier
            threat_intel_summary: Threat intelligence summary text
            threat_intel_sources: List of threat intel sources queried

        Returns:
            Updated triage result or None
        """
        triage_result = await self.get_triage_result_by_alert_id(alert_id)
        if not triage_result:
            logger.warning(f"Triage result not found for alert: {alert_id}")
            return None

        triage_result.threat_intel_summary = threat_intel_summary
        triage_result.threat_intel_sources = threat_intel_sources

        await self.session.flush()
        await self.session.refresh(triage_result)

        logger.info(
            "Threat intel summary updated",
            extra={"alert_id": alert_id},
        )

        return triage_result

    async def get_recent_triage_results(
        self,
        hours: int = 24,
        skip: int = 0,
        limit: int = 100,
    ) -> List[TriageResult]:
        """
        Get recent triage results within specified hours.

        Args:
            hours: Number of hours to look back
            skip: Number of records to skip
            limit: Max number of records to return

        Returns:
            List of recent triage results
        """
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)

        result = await self.session.execute(
            select(TriageResult)
            .where(TriageResult.created_at >= cutoff_time)
            .order_by(TriageResult.created_at.desc())
            .offset(skip)
            .limit(limit)
        )
        return list(result.scalars().all())
