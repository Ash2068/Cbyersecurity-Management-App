"""
Fires a mix of normal and suspicious logon events at a running server so you
can watch the dashboard light up. Start the server first:

    uvicorn app.main:app --reload

Then in another terminal:

    python simulate_events.py
"""
import time
from datetime import datetime, timedelta

import requests

BASE_URL = "http://127.0.0.1:8000"


def send(event: dict):
    r = requests.post(f"{BASE_URL}/events/logon", json=event)
    r.raise_for_status()
    body = r.json()
    print(f"-> {event['user_id']:10s} severity={body['severity']:8s} score={body['risk_score']:3d}  {body['summary']}")


def iso(dt: datetime) -> str:
    return dt.isoformat()


def main():
    now = datetime.utcnow()

    print("\n-- normal logins --")
    send({"user_id": "alice", "ip_address": "10.0.0.5", "country": "US",
          "device_fingerprint": "alice-laptop", "success": True,
          "timestamp": iso(now.replace(hour=9, minute=0))})
    time.sleep(0.3)

    print("\n-- brute force attempt on 'bob' --")
    for i in range(6):
        send({"user_id": "bob", "ip_address": "203.0.113.9", "success": False,
              "timestamp": iso(now + timedelta(minutes=i))})
        time.sleep(0.2)

    print("\n-- impossible travel for 'carol' --")
    send({"user_id": "carol", "ip_address": "10.0.0.9", "country": "US",
          "device_fingerprint": "carol-phone", "success": True,
          "timestamp": iso(now)})
    time.sleep(0.3)
    send({"user_id": "carol", "ip_address": "198.51.100.4", "country": "RO",
          "device_fingerprint": "unknown-device", "success": True,
          "timestamp": iso(now + timedelta(minutes=20))})
    time.sleep(0.3)

    print("\n-- off-hours privileged login --")
    send({"user_id": "admin_dan", "ip_address": "10.0.0.2", "country": "US",
          "device_fingerprint": "dan-workstation", "success": True,
          "is_privileged": True,
          "timestamp": iso(now.replace(hour=2, minute=30))})

    print("\n-- credential stuffing from one IP --")
    for user in ["u1", "u2", "u3", "u4", "u5"]:
        send({"user_id": user, "ip_address": "192.0.2.77", "success": False,
              "timestamp": iso(now + timedelta(minutes=1))})
        time.sleep(0.2)


if __name__ == "__main__":
    main()
