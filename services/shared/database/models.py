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
SQLAlchemy ORM models for the security triage system.

This module defines all database models that map to the PostgreSQL schema.
These models are used for database operations across all microservices.
"""

from datetime import datetime
from typing import Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import ARRAY, INET, UUID, JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Base class for all ORM models."""
    pass


class User(Base):
    """
    User model for authentication and authorization.

    Corresponds to the 'users' table in the database.
    """

    __tablename__ = "users"

    id: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=func.uuid_generate_v4(),
    )
    username: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    full_name: Mapped[Optional[str]] = mapped_column(String(255))
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(
        String(50),
        default="analyst",
        nullable=False,
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    mfa_secret: Mapped[Optional[str]] = mapped_column(String(255))
    phone: Mapped[Optional[str]] = mapped_column(String(20))
    department: Mapped[Optional[str]] = mapped_column(String(100))
    last_login_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    # Relationships
    # assigned_alerts = relationship("Alert", back_populates="assigned_user")  # Commented out - assigned_to field not in DB
    triage_results = relationship("TriageResult", back_populates="analyst")
    created_incidents = relationship("Incident", foreign_keys="[Incident.created_by]", back_populates="creator")
    assigned_incidents = relationship("Incident", foreign_keys="[Incident.assigned_to]", back_populates="assignee")

    __table_args__ = (
        Index("ix_users_role", "role"),
        Index("ix_users_is_active", "is_active"),
    )


class Asset(Base):
    """
    Asset model for infrastructure and endpoint tracking.

    Corresponds to the 'assets' table in the database.
    """

    __tablename__ = "assets"

    id: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=func.uuid_generate_v4(),
    )
    asset_id: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    asset_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45))
    mac_address: Mapped[Optional[str]] = mapped_column(String(17))
    os: Mapped[Optional[str]] = mapped_column(String(100))
    owner: Mapped[Optional[str]] = mapped_column(String(255))
    location: Mapped[Optional[str]] = mapped_column(String(255))
    criticality: Mapped[str] = mapped_column(String(20), default="medium", nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    attributes: Mapped[Optional[dict]] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    # Relationships
    # alerts = relationship("Alert", back_populates="asset")  # Commented out - asset_id not a foreign key in alerts table

    __table_args__ = (
        Index("ix_assets_type", "asset_type"),
        Index("ix_assets_criticality", "criticality"),
        Index("ix_assets_is_active", "is_active"),
    )


class Alert(Base):
    """
    Alert model for security alerts.

    Corresponds to the 'alerts' table in the database.
    """

    __tablename__ = "alerts"

    alert_id: Mapped[str] = mapped_column(String(100), primary_key=True, nullable=False)
    received_at: Mapped[datetime] = mapped_column(
        "received_at",
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )
    alert_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(50), default="pending", nullable=False, index=True)
    title: Mapped[Optional[str]] = mapped_column(String(500))
    description: Mapped[Optional[str]] = mapped_column(Text)

    # Network information
    source_ip: Mapped[Optional[str]] = mapped_column(INET)
    source_port: Mapped[Optional[int]] = mapped_column(Integer)
    destination_ip: Mapped[Optional[str]] = mapped_column(INET)
    destination_port: Mapped[Optional[int]] = mapped_column(Integer)
    protocol: Mapped[Optional[str]] = mapped_column(String(20))

    # Entity references
    asset_id: Mapped[Optional[str]] = mapped_column(String(100))
    user_id: Mapped[Optional[str]] = mapped_column("user_name", String(255))

    # Threat-specific fields
    file_hash: Mapped[Optional[str]] = mapped_column(String(100))
    file_name: Mapped[Optional[str]] = mapped_column(String(255))
    url: Mapped[Optional[str]] = mapped_column(String(1000))
    dns_query: Mapped[Optional[str]] = mapped_column(String(500))

    # Fields not in current database schema - commented out for POC
    # process_name: Mapped[Optional[str]] = mapped_column(String(255))
    # process_id: Mapped[Optional[int]] = mapped_column(Integer)
    # risk_score: Mapped[Optional[float]] = mapped_column(Float)
    # confidence: Mapped[Optional[float]] = mapped_column(Float)
    # assigned_to: Mapped[Optional[UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"))
    # triage_result_id: Mapped[Optional[UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("triage_results.id"))
    # source: Mapped[Optional[str]] = mapped_column(String(100))
    # source_ref: Mapped[Optional[str]] = mapped_column(String(255))
    # normalized_data: Mapped[Optional[dict]] = mapped_column(JSON)
    # tags: Mapped[Optional[list]] = mapped_column(ARRAY(String), default=list)

    # Raw data
    raw_data: Mapped[Optional[dict]] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    # Relationships
    # asset: Mapped[Optional["Asset"]] = relationship("Asset", back_populates="alerts")
    # assigned_user: Mapped[Optional["User"]] = relationship("User", foreign_keys=[assigned_to], back_populates="assigned_alerts")
    # triage_result: Mapped[Optional["TriageResult"]] = relationship("TriageResult", foreign_keys=[triage_result_id])
    context_data = relationship("AlertContext", back_populates="alert", uselist=False)
    # incident_alerts: Mapped[list] = relationship("IncidentAlert", back_populates="alert")  # Commented out for POC

    __table_args__ = (
        Index("ix_alerts_received_at", "received_at"),
        Index("ix_alerts_severity", "severity"),
        Index("ix_alerts_status", "status"),
        Index("ix_alerts_alert_type", "alert_type"),
        Index("ix_alerts_source_ip", "source_ip"),
    )


class AlertContext(Base):
    """
    Alert context model for enriched alert data.

    Corresponds to the 'alert_context' table in the database.
    """

    __tablename__ = "alert_context"

    id: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=func.uuid_generate_v4(),
    )
    alert_id: Mapped[str] = mapped_column(
        String(100),
        ForeignKey("alerts.alert_id", ondelete="CASCADE"),
        unique=True,
        nullable=False,
    )

    # Network context
    source_geo: Mapped[Optional[dict]] = mapped_column(JSON)
    destination_geo: Mapped[Optional[dict]] = mapped_column(JSON)
    ip_reputation: Mapped[Optional[dict]] = mapped_column(JSON)
    network_anomalies: Mapped[Optional[dict]] = mapped_column(JSON)

    # Asset context
    asset_criticality: Mapped[Optional[str]] = mapped_column(String(20))
    asset_owner: Mapped[Optional[str]] = mapped_column(String(255))
    asset_location: Mapped[Optional[str]] = mapped_column(String(255))
    asset_vulnerabilities: Mapped[Optional[list]] = mapped_column(JSON)

    # User context
    user_department: Mapped[Optional[str]] = mapped_column(String(255))
    user_role: Mapped[Optional[str]] = mapped_column(String(100))
    user_manager: Mapped[Optional[str]] = mapped_column(String(255))
    user_history: Mapped[Optional[dict]] = mapped_column(JSON)

    # Additional context
    related_alerts: Mapped[Optional[list]] = mapped_column(JSON)
    historical_patterns: Mapped[Optional[dict]] = mapped_column(JSON)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    # Relationships
    alert: Mapped["Alert"] = relationship("Alert", back_populates="context_data")


class TriageResult(Base):
    """
    Triage result model for AI analysis results.

    Corresponds to the 'triage_results' table in the database.
    """

    __tablename__ = "triage_results"

    id: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=func.uuid_generate_v4(),
    )
    alert_id: Mapped[str] = mapped_column(
        String(100),
        ForeignKey("alerts.alert_id", ondelete="CASCADE"),
        unique=True,
        nullable=False,
    )

    # Risk assessment
    risk_score: Mapped[float] = mapped_column(Float, nullable=False)
    risk_level: Mapped[str] = mapped_column(String(20), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)

    # Analysis details
    severity_weight: Mapped[float] = mapped_column(Float, default=0.0)
    threat_intel_weight: Mapped[float] = mapped_column(Float, default=0.0)
    asset_criticality_weight: Mapped[float] = mapped_column(Float, default=0.0)
    exploitability_weight: Mapped[float] = mapped_column(Float, default=0.0)

    # AI analysis
    analysis: Mapped[str] = mapped_column(Text, nullable=False)
    key_findings: Mapped[list] = mapped_column(ARRAY(String), default=list)
    iocs_identified: Mapped[dict] = mapped_column(JSON, default=dict)

    # Threat intelligence
    threat_intel_summary: Mapped[Optional[str]] = mapped_column(Text)
    threat_intel_sources: Mapped[list] = mapped_column(ARRAY(String), default=list)
    known_exploits: Mapped[Optional[bool]] = mapped_column(Boolean)
    cve_references: Mapped[list] = mapped_column(ARRAY(String), default=list)

    # Human review
    requires_human_review: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    reviewed_by: Mapped[Optional[UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"))
    reviewed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    reviewer_comments: Mapped[Optional[str]] = mapped_column(Text)

    # Model metadata
    model_used: Mapped[str] = mapped_column(String(100), nullable=False)
    model_version: Mapped[Optional[str]] = mapped_column(String(50))
    processing_time_ms: Mapped[Optional[int]] = mapped_column(Integer)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    # Relationships
    analyst: Mapped[Optional["User"]] = relationship("User", foreign_keys=[reviewed_by], back_populates="triage_results")

    __table_args__ = (
        Index("ix_triage_results_risk_score", "risk_score"),
        Index("ix_triage_results_risk_level", "risk_level"),
        Index("ix_triage_results_alert_id", "alert_id"),
    )


class ThreatIntel(Base):
    """
    Threat intelligence model for IOC data.

    Corresponds to the 'threat_intel' table in the database.
    """

    __tablename__ = "threat_intel"

    id: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=func.uuid_generate_v4(),
    )
    ioc_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    ioc_value: Mapped[str] = mapped_column(String(2048), nullable=False, index=True)

    # Threat data
    threat_type: Mapped[Optional[str]] = mapped_column(String(100))
    severity: Mapped[Optional[str]] = mapped_column(String(20))
    confidence: Mapped[Optional[float]] = mapped_column(Float)
    detection_rate: Mapped[Optional[float]] = mapped_column(Float)
    first_seen: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    # Source information
    source: Mapped[str] = mapped_column(String(100), nullable=False)
    source_reference: Mapped[Optional[str]] = mapped_column(String(500))
    tags: Mapped[Optional[list]] = mapped_column(ARRAY(String), default=list)

    # Additional data
    description: Mapped[Optional[str]] = mapped_column(Text)
    alert_metadata: Mapped[Optional[dict]] = mapped_column(JSON)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    __table_args__ = (
        Index("ix_threat_intel_ioc_type", "ioc_type"),
        Index("ix_threat_intel_ioc_value", "ioc_value"),
        Index("ix_threat_intel_severity", "severity"),
    )


class Incident(Base):
    """
    Incident model for incident tracking.

    Corresponds to the 'incidents' table in the database.
    """

    __tablename__ = "incidents"

    id: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=func.uuid_generate_v4(),
    )
    incident_id: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)

    # Incident classification
    severity: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(50), default="open", nullable=False, index=True)
    incident_type: Mapped[Optional[str]] = mapped_column(String(100))

    # Assignment
    created_by: Mapped[UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    assigned_to: Mapped[Optional[UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"))

    # Timeline
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    reported_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    contained_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    # Impact assessment
    impact_summary: Mapped[Optional[str]] = mapped_column(Text)
    affected_assets: Mapped[Optional[list]] = mapped_column(JSON)
    affected_users: Mapped[Optional[list]] = mapped_column(JSON)

    # Additional data
    root_cause: Mapped[Optional[str]] = mapped_column(Text)
    lessons_learned: Mapped[Optional[str]] = mapped_column(Text)
    attributes: Mapped[Optional[dict]] = mapped_column(JSON)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    # Relationships
    creator: Mapped["User"] = relationship("User", foreign_keys=[created_by], back_populates="created_incidents")
    assignee: Mapped[Optional["User"]] = relationship("User", foreign_keys=[assigned_to], back_populates="assigned_incidents")
    alerts = relationship("IncidentAlert", back_populates="incident")
    remediation_actions = relationship("RemediationAction", back_populates="incident")

    __table_args__ = (
        Index("ix_incidents_severity", "severity"),
        Index("ix_incidents_status", "status"),
    )


class IncidentAlert(Base):
    """
    Junction table for incident-alert relationships.

    Corresponds to the 'incident_alerts' table in the database.
    """

    __tablename__ = "incident_alerts"

    id: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=func.uuid_generate_v4(),
    )
    incident_id: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
    )
    alert_id: Mapped[str] = mapped_column(
        String(100),
        ForeignKey("alerts.alert_id", ondelete="CASCADE"),
        nullable=False,
    )

    # Relationships
    incident: Mapped["Incident"] = relationship("Incident", back_populates="alerts")
    alert: Mapped["Alert"] = relationship("Alert")  # Removed back_populates - Alert doesn't have incident_alerts relationship for POC


class RemediationAction(Base):
    """
    Remediation action model for tracking response actions.

    Corresponds to the 'remediation_actions' table in the database.
    """

    __tablename__ = "remediation_actions"

    id: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=func.uuid_generate_v4(),
    )
    action_id: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)

    # References
    incident_id: Mapped[Optional[UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("incidents.id", ondelete="SET NULL"),
    )
    alert_id: Mapped[Optional[str]] = mapped_column(String(100))

    # Action details
    action_type: Mapped[str] = mapped_column(String(100), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)

    # Status
    status: Mapped[str] = mapped_column(String(50), default="pending", nullable=False)
    priority: Mapped[str] = mapped_column(String(20), default="medium", nullable=False)

    # Assignment
    assigned_to: Mapped[Optional[UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"))
    created_by: Mapped[UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)

    # Automation
    is_automated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    automation_script: Mapped[Optional[str]] = mapped_column(String(255))

    # Execution
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    result: Mapped[Optional[str]] = mapped_column(Text)
    error_message: Mapped[Optional[str]] = mapped_column(Text)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    # Relationships
    incident = relationship("Incident", back_populates="remediation_actions")


class AuditLog(Base):
    """
    Audit log model for tracking all system events.

    Corresponds to the 'audit_logs' table in the database.
    """

    __tablename__ = "audit_logs"

    id: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=func.uuid_generate_v4(),
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True,
    )

    # Event details
    event_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    event_category: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    action: Mapped[str] = mapped_column(String(100), nullable=False)

    # Actor
    actor_id: Mapped[Optional[str]] = mapped_column(String(255))
    actor_type: Mapped[Optional[str]] = mapped_column(String(50))
    actor_ip: Mapped[Optional[str]] = mapped_column(String(45))

    # Target
    target_type: Mapped[Optional[str]] = mapped_column(String(100))
    target_id: Mapped[Optional[str]] = mapped_column(String(255))

    # Event data
    details: Mapped[Optional[dict]] = mapped_column(JSON)
    old_values: Mapped[Optional[dict]] = mapped_column(JSON)
    new_values: Mapped[Optional[dict]] = mapped_column(JSON)

    # Result
    status: Mapped[str] = mapped_column(String(50), nullable=False)
    error_message: Mapped[Optional[str]] = mapped_column(Text)

    __table_args__ = (
        Index("ix_audit_logs_timestamp", "timestamp"),
        Index("ix_audit_logs_event_type", "event_type"),
        Index("ix_audit_logs_actor_id", "actor_id"),
    )


class Report(Base):
    """
    Report model for storing generated security reports.

    Corresponds to the 'reports' table in the database.
    """

    __tablename__ = "reports"

    id: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=func.uuid_generate_v4(),
    )
    report_id: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        index=True,
    )

    # Report details
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    report_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,  # alerts, metrics, trends, custom
    )
    format: Mapped[str] = mapped_column(
        String(20),
        nullable=False,  # pdf, csv, json, excel
    )

    # Status
    status: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="pending",
        index=True,  # pending, generating, completed, failed
    )

    # Report configuration
    filters: Mapped[Optional[dict]] = mapped_column(JSON)  # Alert filters, date ranges, etc.
    related_alerts: Mapped[Optional[dict]] = mapped_column(JSON)  # Associated alert IDs

    # File information
    file_path: Mapped[Optional[str]] = mapped_column(String(500))
    file_size: Mapped[Optional[int]] = mapped_column(Integer)  # in bytes

    # Creator
    created_by: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        default="system",
    )

    # Schedule (optional, for recurring reports)
    schedule_frequency: Mapped[Optional[str]] = mapped_column(String(20))  # daily, weekly, monthly
    schedule_time: Mapped[Optional[str]] = mapped_column(String(10))  # HH:MM format
    schedule_recipients: Mapped[Optional[list]] = mapped_column(ARRAY(String))

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    # Error information
    error_message: Mapped[Optional[str]] = mapped_column(Text)

    __table_args__ = (
        Index("ix_reports_report_id", "report_id"),
        Index("ix_reports_status", "status"),
        Index("ix_reports_report_type", "report_type"),
        Index("ix_reports_created_at", "created_at"),
    )


class SystemConfig(Base):
    """
    System configuration model for storing system-wide settings.

    Corresponds to the 'system_configs' table in the database.
    """

    __tablename__ = "system_configs"

    id: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=func.uuid_generate_v4(),
    )
    config_key: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        index=True,
    )
    config_value: Mapped[dict] = mapped_column(JSON, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    category: Mapped[Optional[str]] = mapped_column(String(100), index=True)
    is_sensitive: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    # Audit
    updated_by: Mapped[Optional[str]] = mapped_column(String(255))

    __table_args__ = (
        Index("ix_system_configs_config_key", "config_key"),
        Index("ix_system_configs_category", "category"),
    )


class UserPreference(Base):
    """
    User preference model for storing user-specific settings.

    Corresponds to the 'user_preferences' table in the database.
    """

    __tablename__ = "user_preferences"

    id: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=func.uuid_generate_v4(),
    )
    user_id: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
    )
    preference_key: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    preference_value: Mapped[dict] = mapped_column(JSON, nullable=False)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    __table_args__ = (
        Index("ix_user_preferences_user_id", "user_id"),
        Index("ix_user_preferences_user_key", "user_id", "preference_key", unique=True),
    )


class Workflow(Base):
    """
    Workflow model for automation playbooks and SOAR workflows.

    Corresponds to the 'workflows' table in the database.
    """

    __tablename__ = "workflows"

    id: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=func.uuid_generate_v4(),
    )
    workflow_id: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
        index=True,
    )

    # Workflow details
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    category: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,  # containment, remediation, notification, enrichment
    )

    # Workflow configuration
    trigger_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="manual",  # manual, alert_created, schedule, webhook
    )
    trigger_conditions: Mapped[Optional[dict]] = mapped_column(JSON)

    # Status
    status: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="draft",  # draft, active, disabled, archived
    )
    priority: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="medium",  # low, medium, high, critical
    )

    # Workflow steps (JSON array of step objects)
    steps: Mapped[list] = mapped_column(JSON, nullable=False, default=list)

    # Execution tracking
    total_executions: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    successful_executions: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    failed_executions: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_execution_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    last_execution_status: Mapped[Optional[str]] = mapped_column(String(50))

    # Owner
    created_by: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        default="system",
    )

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    __table_args__ = (
        Index("ix_workflows_workflow_id", "workflow_id"),
        Index("ix_workflows_status", "status"),
        Index("ix_workflows_category", "category"),
    )


class WorkflowExecution(Base):
    """
    Workflow execution model for tracking workflow runs.

    Corresponds to the 'workflow_executions' table in the database.
    """

    __tablename__ = "workflow_executions"

    id: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=func.uuid_generate_v4(),
    )
    execution_id: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
        index=True,
    )

    # Reference
    workflow_id: Mapped[str] = mapped_column(
        String(100),
        ForeignKey("workflows.workflow_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Trigger
    trigger_type: Mapped[str] = mapped_column(String(50), nullable=False)
    trigger_reference: Mapped[Optional[str]] = mapped_column(String(255))  # e.g., alert_id

    # Status
    status: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="running",  # running, completed, failed, cancelled
    )

    # Execution
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    duration_seconds: Mapped[Optional[int]] = mapped_column(Integer)

    # Steps execution (JSON with step status and results)
    steps_execution: Mapped[Optional[dict]] = mapped_column(JSON)

    # Result
    result: Mapped[Optional[str]] = mapped_column(Text)
    error_message: Mapped[Optional[str]] = mapped_column(Text)

    # Actor
    executed_by: Mapped[Optional[str]] = mapped_column(String(255))

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    __table_args__ = (
        Index("ix_workflow_executions_execution_id", "execution_id"),
        Index("ix_workflow_executions_workflow_id", "workflow_id"),
        Index("ix_workflow_executions_status", "status"),
        Index("ix_workflow_executions_started_at", "started_at"),
    )


class WorkflowTemplate(Base):
    """
    Workflow template model for pre-built automation workflows.

    Corresponds to the 'workflow_templates' table in the database.
    """

    __tablename__ = "workflow_templates"

    id: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=func.uuid_generate_v4(),
    )
    template_id: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    category: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    steps: Mapped[dict] = mapped_column(JSONB, nullable=False)
    steps_count: Mapped[int] = mapped_column(Integer, nullable=False)
    estimated_time: Mapped[Optional[str]] = mapped_column(String(50))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_by: Mapped[Optional[str]] = mapped_column(String(100))

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    __table_args__ = (
        Index("ix_workflow_templates_template_id", "template_id"),
        Index("ix_workflow_templates_category", "category"),
    )


class Notification(Base):
    """
    Notification model for user notifications.

    Corresponds to the 'notifications' table in the database.
    """

    __tablename__ = "notifications"

    id: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=func.uuid_generate_v4(),
    )
    notification_id: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        index=True,
    )
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    message: Mapped[Optional[str]] = mapped_column(Text)
    type: Mapped[str] = mapped_column(String(50), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    is_read: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    is_deleted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    link: Mapped[Optional[str]] = mapped_column(String(500))
    user_id: Mapped[str] = mapped_column(String(100), default="default", nullable=False, index=True)
    read_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True,
    )

    __table_args__ = (
        Index("ix_notifications_notification_id", "notification_id"),
        Index("ix_notifications_user_id", "user_id"),
        Index("ix_notifications_is_read", "is_read"),
        Index("ix_notifications_created_at", "created_at"),
    )
