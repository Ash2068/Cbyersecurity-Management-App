"""
Real-time alert delivery. Anything that raises risk_score > 0 gets pushed to
every connected WebSocket client (e.g. the dashboard). Swap `broadcast`'s
body to also POST to Slack/email/PagerDuty/SIEM webhook in production --
the detection engine doesn't need to know or care how alerts get delivered.
"""
import json
from typing import List

from fastapi import WebSocket


class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, payload: dict):
        dead = []
        for connection in self.active_connections:
            try:
                await connection.send_text(json.dumps(payload, default=str))
            except Exception:
                dead.append(connection)
        for d in dead:
            self.disconnect(d)


manager = ConnectionManager()
