from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel


class LogonEventIn(BaseModel):
    """What you POST to /events/logon for every logon attempt."""
    user_id: str
    timestamp: Optional[datetime] = None  # defaults to "now" if omitted
    ip_address: Optional[str] = None
    country: Optional[str] = None  # fill in if you already resolve geo-IP upstream
    device_fingerprint: Optional[str] = None
    success: bool = True
    is_privileged: bool = False


class AlertOut(BaseModel):
    rule: str
    weight: int
    detail: Optional[str]

    class Config:
        from_attributes = True


class LogonEventOut(BaseModel):
    id: int
    user_id: str
    timestamp: datetime
    ip_address: Optional[str]
    country: Optional[str]
    device_fingerprint: Optional[str]
    success: bool
    is_privileged: bool
    is_anomalous: bool
    risk_score: int
    severity: str
    summary: Optional[str]
    alerts: List[AlertOut] = []

    class Config:
        from_attributes = True
