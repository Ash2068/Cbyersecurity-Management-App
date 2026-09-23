# Logon Event AI

A logon-event anomaly detection, classification, and real-time alerting
service, built to slot into a larger cybersecurity management app. It's
framework-agnostic on the ingestion side: point any app, IdP, or log
shipper at one HTTP endpoint and it does the rest.

## What it does

1. **Ingests** logon events via `POST /events/logon`.
2. **Detects anomalies** with five rules, run against each user's history:
   - `brute_force_attempt` — 5+ failed logins for one user within 10 minutes
   - `credential_stuffing_pattern` — one IP hitting 5+ distinct accounts within 10 minutes
   - `new_device` / `new_ip_address` — first time seeing this device/IP for the user
   - `impossible_travel` — successful logins from two different countries within 2 hours
   - `off_hours_privileged_login` — a privileged account logging in outside 6am–10pm UTC
3. **Classifies severity** (none/low/medium/high/critical) by summing weighted
   findings, and writes a plain-English summary explaining *why* — see
   `app/detection.py`.
4. **Alerts in real time** over a WebSocket (`/ws/alerts`) to a live dashboard
   at `/`, the moment an anomalous event is scored.

Rule-based rather than a black-box model on purpose: for a security tool,
"why was this flagged" matters as much as "was it flagged." See the note in
`app/detection.py` for how to layer a trained model on top later without
changing the API.

## Setup

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000` for the live alert dashboard.

In another terminal, generate test traffic:

```bash
python simulate_events.py
```

You'll see brute-force, impossible-travel, off-hours-privileged, and
credential-stuffing events light up the dashboard as they're detected.

## Connecting your real logon events

POST each logon attempt as it happens:

```bash
curl -X POST http://127.0.0.1:8000/events/logon \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "jsmith",
    "ip_address": "203.0.113.42",
    "country": "US",
    "device_fingerprint": "hash-of-user-agent-or-device-id",
    "success": true,
    "is_privileged": false
  }'
```

Fields:
- `user_id` (required) — who's logging in
- `timestamp` — ISO 8601; defaults to now if omitted
- `ip_address`, `country` — `country` is optional; pass it if you already
  resolve geo-IP upstream, otherwise the impossible-travel check just skips
- `device_fingerprint` — anything stable per device (hashed user-agent,
  a device ID cookie, etc.)
- `success` — was the logon successful
- `is_privileged` — flag admin/service accounts for the off-hours rule

The response includes the risk score, severity, and summary for that event
immediately, so you can also use this synchronously (e.g. to block/challenge
a login) rather than only for after-the-fact alerting.

## Other endpoints

- `GET /events?limit=100` — recent logon events (anomalous or not)
- `GET /alerts?limit=100` — only the flagged/anomalous ones
- `GET /docs` — interactive OpenAPI docs (built into FastAPI)

## Where to take this next

- **Swap SQLite for Postgres**: change `SQLALCHEMY_DATABASE_URL` in
  `app/database.py`.
- **Deliver alerts elsewhere**: `app/alerting.py`'s `broadcast()` is the one
  place to add a Slack/email/PagerDuty webhook call alongside the WebSocket push.
- **Add auth** to the API itself (this starter has none — don't expose
  `/events/logon` publicly without an API key or mTLS in front of it).
- **Layer a trained model in**: the detection engine already isolates each
  rule as a function returning weighted findings; an isolation-forest or
  logistic-regression score can be added as one more rule alongside the
  others, or used to auto-tune the rule weights over time.
- **Geo-IP resolution**: currently you supply `country` yourself; wiring in
  a MaxMind GeoLite2 lookup on ingest would let you drop that requirement.
