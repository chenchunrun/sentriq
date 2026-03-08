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
Alert repository for database operations.

This module provides all database operations for security alerts,
including CRUD operations, filtering, and bulk operations.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from shared.database.models import Alert
from shared.database.repositories.base import BaseRepository
from shared.models.alert import AlertFilter, AlertStatus, AlertType, Severity
from shared.utils.logger import get_logger
from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import Select

logger = get_logger(__name__)
ALERT_TIME_FIELD = Alert.received_at


class AlertRepository(BaseRepository[Alert]):
    """
    Repository for Alert model operations.

    Provides specialized methods for alert queries, filtering,
    and status management.
    """

    def __init__(self, session: AsyncSession):
        """
        Initialize alert repository.

        Args:
            session: Database session
        """
        super().__init__(Alert, session)

    async def create_alert(self, alert_data: Dict[str, Any]) -> Alert:
        """
        Create a new security alert.

        Args:
            alert_data: Alert data dictionary

        Returns:
            Created alert instance
        """
        alert = Alert(**alert_data)
        self.session.add(alert)
        await self.session.flush()
        await self.session.refresh(alert)

        logger.info(
            "Alert created",
            extra={
                "alert_id": alert.alert_id,
                "alert_type": alert.alert_type,
                "severity": alert.severity,
            },
        )

        return alert

    async def get_alert_by_id(self, alert_id: str) -> Optional[Alert]:
        """
        Get alert by alert_id.

        Args:
            alert_id: Alert identifier

        Returns:
            Alert instance or None
        """
        result = await self.session.execute(
            select(Alert).where(Alert.alert_id == alert_id)
        )
        return result.scalar_one_or_none()

    async def get_alerts_by_filter(
        self,
        filters: AlertFilter,
        skip: int = 0,
        limit: int = 100,
        sort_by: str = "received_at",
        sort_order: str = "desc",
    ) -> tuple[List[Alert], int]:
        """
        Get alerts with filtering and pagination.

        Args:
            filters: Alert filter criteria
            skip: Number of records to skip
            limit: Max number of records to return
            sort_by: Field to sort by
            sort_order: Sort order (asc or desc)

        Returns:
            Tuple of (list of alerts, total count)
        """
        # Build base query
        query = select(Alert)
        count_query = select(func.count(Alert.alert_id))

        # Apply filters
        conditions = []

        if filters.alert_id:
            conditions.append(Alert.alert_id == filters.alert_id)

        if filters.alert_type:
            conditions.append(Alert.alert_type == filters.alert_type.value)

        if filters.severity:
            conditions.append(Alert.severity == filters.severity.value)

        if filters.status:
            conditions.append(Alert.status == filters.status.value)

        if filters.source_ip:
            conditions.append(Alert.source_ip == filters.source_ip)

        if filters.target_ip:
            conditions.append(Alert.destination_ip == filters.target_ip)

        if filters.asset_id:
            conditions.append(Alert.asset_id == filters.asset_id)

        if filters.user_id:
            conditions.append(Alert.user_id == filters.user_id)

        if filters.source:
            conditions.append(Alert.source == filters.source)

        if filters.start_date:
            conditions.append(ALERT_TIME_FIELD >= filters.start_date)

        if filters.end_date:
            conditions.append(ALERT_TIME_FIELD <= filters.end_date)

        if filters.search:
            # Text search in description and title
            search_pattern = f"%{filters.search}%"
            conditions.append(
                or_(
                    Alert.description.ilike(search_pattern),
                    Alert.title.ilike(search_pattern),
                )
            )

        # Apply conditions to both queries
        if conditions:
            query = query.where(and_(*conditions))
            count_query = count_query.where(and_(*conditions))

        # Get total count
        count_result = await self.session.execute(count_query)
        total = count_result.scalar()

        # Apply sorting
        sort_column = getattr(Alert, sort_by, ALERT_TIME_FIELD)
        if sort_order.lower() == "asc":
            query = query.order_by(sort_column.asc())
        else:
            query = query.order_by(sort_column.desc())

        # Apply pagination
        query = query.offset(skip).limit(limit)

        # Execute query
        result = await self.session.execute(query)
        alerts = list(result.scalars().all())

        logger.info(
            "Alerts retrieved",
            extra={
                "count": len(alerts),
                "total": total,
                "skip": skip,
                "limit": limit,
            },
        )

        return alerts, total

    async def update_alert_status(
        self,
        alert_id: str,
        status: AlertStatus | str,
        assigned_to: Optional[str] = None,
        comment: Optional[str] = None,
    ) -> Optional[Alert]:
        """
        Update alert status and assignment.

        Args:
            alert_id: Alert identifier
            status: New status
            assigned_to: Optional user UUID to assign to
            comment: Optional comment for the update

        Returns:
            Updated alert or None
        """
        alert = await self.get_alert_by_id(alert_id)
        if not alert:
            logger.warning(f"Alert not found: {alert_id}")
            return None

        alert.status = status.value if isinstance(status, AlertStatus) else str(status)
        if assigned_to:
            alert.assigned_to = assigned_to

        await self.session.flush()
        await self.session.refresh(alert)

        logger.info(
            "Alert status updated",
            extra={
                "alert_id": alert_id,
                "status": status.value if isinstance(status, AlertStatus) else str(status),
                "assigned_to": assigned_to,
            },
        )

        return alert

    async def update_alert_risk_score(
        self,
        alert_id: str,
        risk_score: float,
        confidence: Optional[float] = None,
    ) -> Optional[Alert]:
        """
        Update alert risk score.

        Args:
            alert_id: Alert identifier
            risk_score: Risk score (0-100)
            confidence: Optional confidence score

        Returns:
            Updated alert or None
        """
        alert = await self.get_alert_by_id(alert_id)
        if not alert:
            logger.warning(f"Alert not found: {alert_id}")
            return None

        alert.risk_score = risk_score
        if confidence is not None:
            alert.confidence = confidence

        # Update severity based on risk score
        alert.severity = Severity.from_score(risk_score).value

        await self.session.flush()
        await self.session.refresh(alert)

        logger.info(
            "Alert risk score updated",
            extra={
                "alert_id": alert_id,
                "risk_score": risk_score,
                "severity": alert.severity,
            },
        )

        return alert

    async def get_alerts_by_asset(
        self,
        asset_id: str,
        skip: int = 0,
        limit: int = 100,
    ) -> List[Alert]:
        """
        Get alerts for a specific asset.

        Args:
            asset_id: Asset identifier
            skip: Number of records to skip
            limit: Max number of records to return

        Returns:
            List of alerts
        """
        result = await self.session.execute(
            select(Alert)
            .where(Alert.asset_id == asset_id)
            .order_by(ALERT_TIME_FIELD.desc())
            .offset(skip)
            .limit(limit)
        )
        return list(result.scalars().all())

    async def get_alerts_by_user(
        self,
        user_id: str,
        skip: int = 0,
        limit: int = 100,
    ) -> List[Alert]:
        """
        Get alerts for a specific user.

        Args:
            user_id: User identifier
            skip: Number of records to skip
            limit: Max number of records to return

        Returns:
            List of alerts
        """
        result = await self.session.execute(
            select(Alert)
            .where(Alert.user_id == user_id)
            .order_by(ALERT_TIME_FIELD.desc())
            .offset(skip)
            .limit(limit)
        )
        return list(result.scalars().all())

    async def get_alerts_by_source_ip(
        self,
        source_ip: str,
        skip: int = 0,
        limit: int = 100,
    ) -> List[Alert]:
        """
        Get alerts by source IP address.

        Args:
            source_ip: Source IP address
            skip: Number of records to skip
            limit: Max number of records to return

        Returns:
            List of alerts
        """
        result = await self.session.execute(
            select(Alert)
            .where(Alert.source_ip == source_ip)
            .order_by(ALERT_TIME_FIELD.desc())
            .offset(skip)
            .limit(limit)
        )
        return list(result.scalars().all())

    async def get_alerts_by_date_range(
        self,
        start_date: datetime,
        end_date: datetime,
        skip: int = 0,
        limit: int = 100,
    ) -> List[Alert]:
        """
        Get alerts within a date range.

        Args:
            start_date: Start datetime
            end_date: End datetime
            skip: Number of records to skip
            limit: Max number of records to return

        Returns:
            List of alerts
        """
        result = await self.session.execute(
            select(Alert)
            .where(
                and_(
                    ALERT_TIME_FIELD >= start_date,
                    ALERT_TIME_FIELD <= end_date,
                )
            )
            .order_by(ALERT_TIME_FIELD.desc())
            .offset(skip)
            .limit(limit)
        )
        return list(result.scalars().all())

    async def get_alerts_by_type_and_severity(
        self,
        alert_type: AlertType,
        severity: Severity,
        skip: int = 0,
        limit: int = 100,
    ) -> List[Alert]:
        """
        Get alerts by type and severity.

        Args:
            alert_type: Alert type
            severity: Severity level
            skip: Number of records to skip
            limit: Max number of records to return

        Returns:
            List of alerts
        """
        result = await self.session.execute(
            select(Alert)
            .where(
                and_(
                    Alert.alert_type == alert_type.value,
                    Alert.severity == severity.value,
                )
            )
            .order_by(ALERT_TIME_FIELD.desc())
            .offset(skip)
            .limit(limit)
        )
        return list(result.scalars().all())

    async def get_active_alerts(
        self,
        skip: int = 0,
        limit: int = 100,
    ) -> List[Alert]:
        """
        Get active (non-resolved/closed) alerts.

        Args:
            skip: Number of records to skip
            limit: Max number of records to return

        Returns:
            List of active alerts
        """
        result = await self.session.execute(
            select(Alert)
            .where(
                Alert.status.notin_([AlertStatus.RESOLVED.value, AlertStatus.CLOSED.value])
            )
            .order_by(ALERT_TIME_FIELD.desc())
            .offset(skip)
            .limit(limit)
        )
        return list(result.scalars().all())

    async def get_high_priority_alerts(
        self,
        min_risk_score: float = 70.0,
        skip: int = 0,
        limit: int = 100,
    ) -> List[Alert]:
        """
        Get high-priority alerts based on risk score.

        Args:
            min_risk_score: Minimum risk score threshold
            skip: Number of records to skip
            limit: Max number of records to return

        Returns:
            List of high-priority alerts
        """
        result = await self.session.execute(
            select(Alert)
            .where(
                and_(
                    Alert.risk_score >= min_risk_score,
                    Alert.status.notin_([AlertStatus.RESOLVED.value, AlertStatus.CLOSED.value]),
                )
            )
            .order_by(Alert.risk_score.desc())
            .offset(skip)
            .limit(limit)
        )
        return list(result.scalars().all())

    async def get_alerts_count_by_severity(self) -> Dict[str, int]:
        """
        Get alert count grouped by severity.

        Returns:
            Dictionary with severity as key and count as value
        """
        result = await self.session.execute(
            select(Alert.severity, func.count(Alert.alert_id))
            .group_by(Alert.severity)
        )

        return {severity: count for severity, count in result.all()}

    async def get_alerts_count_by_status(self) -> Dict[str, int]:
        """
        Get alert count grouped by status.

        Returns:
            Dictionary with status as key and count as value
        """
        result = await self.session.execute(
            select(Alert.status, func.count(Alert.alert_id))
            .group_by(Alert.status)
        )

        return {status: count for status, count in result.all()}

    async def get_alerts_count_by_type(self) -> Dict[str, int]:
        """
        Get alert count grouped by type.

        Returns:
            Dictionary with alert type as key and count as value
        """
        result = await self.session.execute(
            select(Alert.alert_type, func.count(Alert.alert_id))
            .group_by(Alert.alert_type)
        )

        return {alert_type: count for alert_type, count in result.all()}

    async def bulk_create_alerts(self, alerts_data: List[Dict[str, Any]]) -> List[Alert]:
        """
        Bulk create alerts.

        Args:
            alerts_data: List of alert data dictionaries

        Returns:
            List of created alert instances
        """
        alerts = [Alert(**alert_data) for alert_data in alerts_data]
        self.session.add_all(alerts)
        await self.session.flush()

        for alert in alerts:
            await self.session.refresh(alert)

        logger.info(f"Bulk created {len(alerts)} alerts")

        return alerts

    async def assign_alert(
        self,
        alert_id: str,
        user_id: str,
    ) -> Optional[Alert]:
        """
        Assign alert to a user.

        Args:
            alert_id: Alert identifier
            user_id: User UUID

        Returns:
            Updated alert or None
        """
        return await self.update_alert_status(
            alert_id=alert_id,
            status=AlertStatus.ASSIGNED,
            assigned_to=user_id,
        )

    async def close_alert(
        self,
        alert_id: str,
    ) -> Optional[Alert]:
        """
        Close an alert.

        Args:
            alert_id: Alert identifier

        Returns:
            Updated alert or None
        """
        return await self.update_alert_status(
            alert_id=alert_id,
            status=AlertStatus.CLOSED,
        )
