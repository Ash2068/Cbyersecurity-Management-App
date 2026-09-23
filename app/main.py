"""
Logon Event AI -- ingestion + anomaly detection + classification + real-time
alerting for authentication events.

Run with:
    uvicorn app.main:app --reload

Then POST logon events to /events/logon and watch /static/dashboard.html
(served at /) for live alerts, or connect your own client to /ws/alerts.
"""
from datetime import datetime
from typing import List

from fastapi import Depends, FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session

from app import detection
from app.alerting import manager
from app.database import Base, SessionLocal, engine, get_db
from app.models import Alert, LogonEvent
from app.schemas import LogonEventIn, LogonEventOut

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Logon Event AI")
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/")
def dashboard():
    return FileResponse("static/dashboard.html")


@app.post("/events/logon", response_model=LogonEventOut)
async def ingest_logon_event(payload: LogonEventIn, db: Session = Depends(get_db)):
    """
    Point your app/IdP/SIEM at this endpoint for every logon attempt.
    Runs the event through the detection engine, stores the result, and
    broadcasts an alert over WebSocket if it's anomalous.
    """
    event = LogonEvent(
        user_id=payload.user_id,
        timestamp=payload.timestamp or datetime.utcnow(),
        ip_address=payload.ip_address,
        country=payload.country,
        device_fingerprint=payload.device_fingerprint,
        success=payload.success,
        is_privileged=payload.is_privileged,
    )
    db.add(event)
    db.commit()
    db.refresh(event)

    score, severity, findings = detection.evaluate_event(db, event)
    event.risk_score = score
    event.severity = severity
    event.is_anomalous = score > 0
    event.summary = detection.summarize(findings, severity)

    for f in findings:
        db.add(Alert(event_id=event.id, rule=f["rule"], weight=f["weight"], detail=f["detail"]))

    db.commit()
    db.refresh(event)

    if event.is_anomalous:
        await manager.broadcast({
            "id": event.id,
            "user_id": event.user_id,
            "timestamp": event.timestamp,
            "severity": event.severity,
            "risk_score": event.risk_score,
            "summary": event.summary,
        })

    return event


@app.get("/events", response_model=List[LogonEventOut])
def list_events(limit: int = 100, db: Session = Depends(get_db)):
    return (
        db.query(LogonEvent)
        .order_by(LogonEvent.timestamp.desc())
        .limit(limit)
        .all()
    )


@app.get("/alerts", response_model=List[LogonEventOut])
def list_alerts(limit: int = 100, db: Session = Depends(get_db)):
    """Only the events the detection engine flagged as anomalous."""
    return (
        db.query(LogonEvent)
        .filter(LogonEvent.is_anomalous.is_(True))
        .order_by(LogonEvent.timestamp.desc())
        .limit(limit)
        .all()
    )


@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()  # keep the connection open; ignore input
    except WebSocketDisconnect:
        manager.disconnect(websocket)
