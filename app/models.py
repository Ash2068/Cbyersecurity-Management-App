"""
SQLAlchemy models for the logon-event AI system.

LogonEvent  - one row per logon attempt ingested from your app/IdP/SIEM.
Alert       - one row per anomaly the detection engine raised for an event.
"""
from datetime import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
)
from sqlalchemy.orm import relationship

from app.database import Base


class LogonEvent(Base):
    __tablename__ = "logon_events"

    id = Column(Integer, primary_key=True, index=True)

    # Who / what tried to log in
    user_id = Column(String, index=True, nullable=False)
    is_privileged = Column(Boolean, default=False)  # admin/service account flag

    # When
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)

    # Where / how
    ip_address = Column(String, index=True, nullable=True)
    country = Column(String, nullable=True)  # pass this in if you have geo-IP already;
                                              # otherwise leave null and that check is skipped
    device_fingerprint = Column(String, nullable=True)  # user-agent hash, device id, etc.

    # Outcome
    success = Column(Boolean, default=True)

    # Detection engine output (filled in after processing)
    is_anomalous = Column(Boolean, default=False)
    risk_score = Column(Integer, default=0)
    severity = Column(String, default="none")  # none/low/medium/high/critical
    summary = Column(String, nullable=True)

    alerts = relationship("Alert", back_populates="event", cascade="all, delete-orphan")


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(Integer, ForeignKey("logon_events.id"))

    rule = Column(String, nullable=False)       # which detection rule fired
    weight = Column(Integer, default=0)         # contribution to risk score
    detail = Column(String, nullable=True)      # human-readable specifics

    created_at = Column(DateTime, default=datetime.utcnow)

    event = relationship("LogonEvent", back_populates="alerts")
