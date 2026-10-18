# SmartGrid Sentinel
### Privacy-Preserving Aggregate MACs & Hash-Based Metering Verification

A fresh educational prototype for demonstrating secure smart-meter ingestion, HMAC-SHA256 authentication, SHA-256 hash-chain verification, replay rejection, integrity baselines, and aggregate-only reporting.

## What works in this prototype
- Dashboard with live API-backed KPIs, consumption visualization, meters, and security event feed.
- Register a meter and submit readings.
- Each reading is authenticated using HMAC-SHA256 with a per-meter demo key.
- Each reading links to the previous reading with a SHA-256 hash chain.
- Replayed sequence numbers are rejected.
- Create an integrity baseline and verify stored reading chains against it.
- Tamper simulation changes a stored reading without updating its chain; the next integrity check should fail.
- Aggregate endpoint returns the total for a meter without returning individual reading values.
- Security events are saved to SQLite and shown in the dashboard.

## Important scope note
This is a classroom prototype, not a production smart-grid deployment. Meter secrets are stored locally in SQLite for ease of demonstration, readings are not homomorphically encrypted, and the aggregate endpoint is an application-level privacy boundary—not a proof of cryptographic secure aggregation. Production work would require key management, access control, encrypted-at-rest storage, authenticated clients, threat modelling, and a reviewed aggregation protocol.

## Run on Kali Linux
From the extracted project directory:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open:
- Dashboard: http://127.0.0.1:8000/
- API docs: http://127.0.0.1:8000/docs
- Health: http://127.0.0.1:8000/api/health

If port 8000 is already busy:
```bash
uvicorn app.main:app --reload --port 8001
```

## Suggested 5-minute supervisor demo
1. Open dashboard and click **Load demo data** if the database is empty.
2. Register `METER-001` (or use an existing meter).
3. Submit a reading such as `1250 Wh`.
4. Click **Verify integrity**; the chain should be valid.
5. Click **Aggregate**; the API returns the meter's total only.
6. Click **Simulate replay**; the duplicate latest sequence should be rejected and logged.
7. Click **Simulate tampering**, then **Verify integrity**; verification should fail because the stored value no longer matches its hash chain.
8. Refresh the event feed to show the audit trail.

## Project structure
```text
SmartGridSentinel/
├── app/
│   ├── __init__.py
│   ├── main.py
│   ├── database.py
│   ├── security.py
│   └── static/
│       ├── index.html
│       ├── styles.css
│       └── app.js
├── requirements.txt
└── README.md
```

## API overview
- `GET /api/health`
- `GET /api/dashboard`
- `GET /api/meters`
- `POST /api/meters`
- `GET /api/meters/{meter_id}/readings`
- `POST /api/readings`
- `GET /api/meters/{meter_id}/aggregate`
- `POST /api/meters/{meter_id}/baseline`
- `POST /api/meters/{meter_id}/verify`
- `POST /api/demo/replay/{meter_id}`
- `POST /api/demo/tamper/{meter_id}`
- `POST /api/demo/seed`
- `GET /api/events`
