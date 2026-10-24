# SmartGridSentinel ⚡🔐
### Secure Smart Meter Monitoring & Cryptographic Integrity Verification

**SmartGridSentinel** is a cybersecurity-focused smart grid monitoring prototype that demonstrates secure meter-reading ingestion, HMAC-based authentication, hash-chain integrity verification, replay-attack detection, tampering simulation, and Paillier-based aggregate computation.

The project combines cybersecurity, applied cryptography, and energy telemetry in a dashboard-driven environment designed for experimentation, security testing, and educational demonstrations.

> **Project status:** Educational prototype  
> **Primary focus:** Cybersecurity · Applied Cryptography · Smart Grid Security  
> **Deployment:** Local development environment

---

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Security Mechanisms](#security-mechanisms)
- [Technology Stack](#technology-stack)
- [System Architecture](#system-architecture)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Installation and Setup](#installation-and-setup)
  - [Kali Linux](#1-kali-linux)
  - [Windows](#2-windows)
- [Running the Application](#running-the-application)
- [Using the Dashboard](#using-the-dashboard)
- [API Endpoints](#api-endpoints)
- [Testing](#testing)
- [Security Considerations](#security-considerations)
- [Limitations](#limitations)
- [Future Improvements](#future-improvements)
- [Troubleshooting](#troubleshooting)
- [Learning Outcomes](#learning-outcomes)
- [Author](#author)
- [License](#license)

---

## Overview

Smart grids rely on connected devices and digital communication to monitor and manage electricity consumption. Compromised meter readings, replayed packets, or unauthorized data modifications can undermine the reliability of monitoring systems.

SmartGridSentinel explores these risks through a local smart meter simulation environment.

The application allows users to register meters, submit consumption readings, inspect telemetry, verify cryptographic integrity, simulate selected attacks, and calculate aggregate consumption using a Paillier-based computation workflow.

A web dashboard provides visibility into meter activity, integrity checks, energy consumption, and security events.

### Project Objectives

- Demonstrate message authentication using HMAC-SHA256.
- Detect modifications to stored meter readings through cryptographic integrity checks.
- Maintain a hash chain for recorded readings.
- Demonstrate replay-attack rejection.
- Simulate tampering and inspect the resulting security response.
- Explore Paillier homomorphic encryption for aggregate computation.
- Maintain a local audit trail of application security events.
- Provide a dashboard for interacting with and monitoring the prototype.

---

## Key Features

### 1. Smart Meter Fleet Management

- Register smart meters with a meter ID and location label.
- View registered meters and their status.
- Inspect reading counts and total recorded energy consumption.
- Select a meter for integrity checks and aggregate queries.

### 2. Secure Reading Ingestion

- Submit energy consumption readings through the dashboard.
- Process readings through the backend.
- Authenticate submitted data before storing it.
- Associate readings with sequence information and cryptographic integrity metadata.
- Store application data in a local SQLite database.

### 3. HMAC-Based Authentication

The application uses HMAC-SHA256 to demonstrate message authentication.

HMAC provides a mechanism for checking whether a message was authenticated using the expected secret and whether its contents have changed.

The integrity check can report authentication success or failure for stored readings.

### 4. Hash-Chain Integrity Verification

Readings can be linked using cryptographic hashes to form a hash chain.

The chain provides a way to detect inconsistencies in the recorded sequence of readings.

Integrity verification checks the stored records against the application's implemented integrity rules.

### 5. Merkle Baseline Verification

The integrity lab supports baseline creation and subsequent comparison.

A baseline represents the data state against which later integrity checks can be performed. Changes to the records covered by a baseline can cause a mismatch.

**Important:** A baseline mismatch does not, by itself, prove malicious activity. Legitimate changes to the dataset may also require a baseline update according to the implementation's design.

### 6. Replay-Attack Simulation

The dashboard includes a replay simulation intended to demonstrate the rejection of duplicate sequence packets.

The application records relevant security events so that the outcome can be inspected after the simulation.

### 7. Tampering Simulation

The dashboard provides a controlled tampering demonstration for examining the integrity-verification response to a modified stored value.

The simulation is intended for the local educational environment. Verify the resulting security event and confirm the database state after each test.

### 8. Paillier-Based Aggregate Computation

The project uses the Paillier cryptosystem through the Python `phe` library to demonstrate homomorphic aggregation.

The workflow is intended to calculate an aggregate consumption value without returning each individual reading in the aggregate response.

This demonstrates an application-level privacy objective, not a formal guarantee that the complete system provides privacy-preserving aggregation.

### 9. Security Event Logging

The dashboard displays recent application security events, including events associated with integrity checks, replay simulations, tampering simulations, and aggregate operations where recorded by the application.

Events are stored locally in SQLite.

### 10. Web Dashboard

The frontend provides:

- Overview metrics
- Smart meter fleet
- Consumption activity chart
- Integrity verification controls
- Baseline creation
- Replay and tampering simulations
- Secure reading submission
- Reading history
- Aggregate query
- Recent security events

---

## Security Mechanisms

| Mechanism | Purpose |
|---|---|
| HMAC-SHA256 | Demonstrate message authentication and tamper detection |
| Cryptographic hash chain | Detect inconsistencies in linked meter records |
| Merkle baseline | Compare a dataset against a previously established state |
| Sequence validation | Demonstrate replay rejection for duplicate sequence packets |
| Paillier cryptosystem | Demonstrate homomorphic aggregate computation |
| SQLite audit trail | Persist application records and security events |

These mechanisms address different security concerns and should not be treated as interchangeable.

For example, HMAC authentication, hash-chain verification, and Merkle baseline comparison have different inputs and verification semantics. A successful result from one mechanism does not guarantee that every other security property is satisfied.

---

## Technology Stack

| Component | Technology |
|---|---|
| Programming language | Python |
| Backend framework | FastAPI |
| ASGI server | Uvicorn |
| Frontend | HTML, CSS, JavaScript |
| Database | SQLite |
| Message authentication | HMAC-SHA256 |
| Homomorphic encryption | Paillier |
| Paillier implementation | `phe` / `python-paillier` |
| Testing | pytest |
| Development environment | Windows / Kali Linux / Linux |

---

## System Architecture

The application follows a local, dashboard-driven architecture.

```text
                 ┌──────────────────────────┐
                 │       Web Dashboard       │
                 │      HTML / CSS / JS      │
                 └────────────┬─────────────┘
                              │ HTTP / JSON
                              ▼
                 ┌──────────────────────────┐
                 │       FastAPI Backend     │
                 │                          │
                 │ Meter Management         │
                 │ Reading Ingestion        │
                 │ Integrity Verification   │
                 │ Security Event Logging   │
                 │ Aggregate Computation    │
                 └──────┬──────────┬────────┘
                        │          │
              ┌─────────▼────┐  ┌──▼────────────────┐
              │    SQLite    │  │ Cryptographic     │
              │              │  │ Components        │
              │ Meter Data   │  │                   │
              │ Readings     │  │ HMAC-SHA256       │
              │ Audit Events │  │ Hash Chain        │
              │ Baselines    │  │ Paillier          │
              └──────────────┘  └───────────────────┘
```

### High-Level Data Flow

1. A user selects a meter or registers a new one.
2. A reading is submitted through the dashboard.
3. The backend processes the request and performs the implemented authentication and storage operations.
4. Reading metadata and application records are stored locally.
5. Integrity verification checks the relevant stored data.
6. The aggregate endpoint executes the implemented aggregate computation.
7. The dashboard displays the returned metrics, verification results, and recorded events.

The exact verification and persistence behavior is determined by the backend implementation.

---

## Project Structure

The following is a representative structure of the application. Some files, test modules, and data artifacts may vary by checkout.

```text
SmartGridSentinel/
│
├── app/
│   ├── main.py
│   ├── database.py
│   ├── security.py
│   ├── paillier_manager.py
│   │
│   └── static/
│       ├── index.html
│       ├── styles.css
│       └── app.js
│
├── data/
│   ├── smartgrid_sentinel.db
│   └── paillier_keys.json
│
├── tests/
│   ├── test_security.py
│   └── test_paillier.py
│
├── requirements.txt
├── .gitignore
└── README.md
```

### Important Files

| File | Responsibility |
|---|---|
| `app/main.py` | FastAPI application and HTTP endpoints |
| `app/database.py` | SQLite database operations |
| `app/security.py` | HMAC and hash-chain security helpers |
| `app/paillier_manager.py` | Paillier key handling and aggregate computation |
| `app/static/index.html` | Dashboard structure |
| `app/static/styles.css` | Dashboard styling |
| `app/static/app.js` | Frontend interactions and API requests |
| `tests/test_security.py` | Security helper tests |
| `tests/test_paillier.py` | Paillier-related tests |
| `requirements.txt` | Python dependencies |

---

## Prerequisites

Install the following before running the application:

- Python 3
- pip
- Git, if cloning the repository
- A supported modern web browser
- A terminal or shell

The application is intended to run locally. Internet access may be required to install dependencies and load externally hosted fonts used by the dashboard.

---

## Installation and Setup

### 1. Kali Linux

#### Step 1: Install system dependencies

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git
```

#### Step 2: Clone the repository

```bash
git clone https://github.com/codebysantusht/SmartGridSentinel.git
cd SmartGridSentinel
```

#### Step 3: Create a virtual environment

```bash
python3 -m venv .venv
```

#### Step 4: Activate the environment

```bash
source .venv/bin/activate
```

#### Step 5: Install project dependencies

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

If you want to run the test suite and pytest is not included in the project's runtime dependencies, install it separately:

```bash
pip install pytest
```

#### Step 6: Start the server

```bash
python -m uvicorn app.main:app --reload
```

### 2. Windows

#### Step 1: Clone the repository

Open PowerShell:

```powershell
git clone https://github.com/codebysantusht/SmartGridSentinel.git
cd SmartGridSentinel
```

#### Step 2: Create a virtual environment

```powershell
python -m venv .venv
```

#### Step 3: Activate the environment

```powershell
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks script activation, use Command Prompt instead:

```bat
.venv\Scripts\activate.bat
```

#### Step 4: Install dependencies

```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
```

#### Step 5: Start the server

```powershell
python -m uvicorn app.main:app --reload
```

---

## Running the Application

After starting Uvicorn, open the dashboard in your browser.

| Resource | URL |
|---|---|
| Dashboard | http://127.0.0.1:8000/ |
| Interactive API documentation | http://127.0.0.1:8000/docs |
| API health endpoint | http://127.0.0.1:8000/api/health |

The API documentation is useful for inspecting available request methods, parameters, and response schemas.

### If Port 8000 Is Already in Use

Start the application on another port:

```bash
python -m uvicorn app.main:app --reload --port 8001
```

Then open:

- Dashboard: http://127.0.0.1:8001/
- API documentation: http://127.0.0.1:8001/docs
- Health check: http://127.0.0.1:8001/api/health

### Stopping the Server

Press `Ctrl + C` in the terminal running Uvicorn.

---

## Using the Dashboard

### 1. Register a Meter

Use the meter registration control to create a meter with a unique identifier and a location label.

### 2. Submit a Reading

Select a meter, enter a positive consumption value in watt-hours, and submit it.

Check the dashboard to confirm that the reading was accepted and that the history and meter statistics have updated.

### 3. Establish an Integrity Baseline

Select the appropriate meter and click **Set baseline** to establish a reference state for the current dataset, according to the application's implementation.

### 4. Verify Integrity

Click **Verify integrity** to inspect the returned HMAC, hash-chain, and baseline results.

If the baseline reports a mismatch, investigate whether the underlying dataset changed after the baseline was created before concluding that malicious tampering occurred.

### 5. Test Replay Detection

Use **Simulate replay** in the local demo environment. Inspect the returned outcome and the security event log.

### 6. Test Tampering Detection

Use **Simulate tampering** in the local demo environment. Verify that the integrity check identifies the simulated modification and inspect the database state afterward.

Do not use the simulation against production data.

### 7. Calculate Aggregate Consumption

Select a meter and click **Calculate aggregate**.

The dashboard should display the aggregate total and the number of readings reported by the backend. The exact response depends on the implementation.

---

## API Endpoints

The following routes are used by the dashboard JavaScript. Request and response schemas should be confirmed through the running application's OpenAPI documentation at `/docs`.

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/api/health` | Check application health |
| `GET` | `/api/dashboard` | Retrieve overview metrics and chart data |
| `GET` | `/api/meters` | Retrieve registered meters |
| `POST` | `/api/meters` | Register a meter |
| `POST` | `/api/readings` | Submit a meter reading |
| `GET` | `/api/meters/{meter_id}/readings` | Retrieve reading history |
| `POST` | `/api/meters/{meter_id}/verify` | Verify meter integrity |
| `POST` | `/api/meters/{meter_id}/baseline` | Establish a baseline |
| `GET` | `/api/meters/{meter_id}/aggregate` | Calculate an aggregate |
| `GET` | `/api/events?limit=12` | Retrieve recent security events |
| `POST` | `/api/demo/replay/{meter_id}` | Run the replay simulation |
| `POST` | `/api/demo/tamper/{meter_id}` | Run the tampering simulation |
| `POST` | `/api/demo/seed` | Initialize demo data, if needed |

### Inspect API Documentation

Start the application and visit:

http://127.0.0.1:8000/docs

Use the interactive documentation to inspect the available endpoints and test requests against your local instance.

---

## Testing

The project includes tests for security helpers and Paillier-related functionality.

Activate the project's virtual environment and run:

```bash
python -m pytest -v
```

To run the security tests:

```bash
python -m pytest tests/test_security.py -v
```

To run the Paillier tests:

```bash
python -m pytest tests/test_paillier.py -v
```

### Suggested Manual Test Plan

| Test | Action | Expected observation |
|---|---|---|
| Meter registration | Register a new meter | Meter appears in the fleet |
| Reading ingestion | Submit a valid reading | Backend accepts the reading |
| Baseline verification | Establish a baseline and verify | Results reflect the current stored data |
| Replay simulation | Submit a simulated duplicate packet | Replay rejection is reported if implemented successfully |
| Tampering simulation | Run the local tampering demonstration | Integrity failure is reported if the modification is detected |
| Aggregate computation | Calculate a meter aggregate | Total and reading count are returned |
| Audit trail | Run security operations | Relevant events appear if logged by the backend |

**Testing note:** Automated unit tests do not replace end-to-end testing. Verify the actual application behavior in your environment before presenting the project as fully tested.

---

## Security Considerations

### Local Secrets and Cryptographic Keys

The application may use locally stored cryptographic key material for demonstrations. Do not publish private keys, HMAC secrets, real meter data, or other sensitive artifacts.

Review `.gitignore` and the repository contents before committing changes.

### Database Protection

SQLite is used for local persistence. Database files may contain readings, security metadata, or other sensitive information.

Avoid uploading live database files to a public repository unless they have been reviewed and sanitized.

### Development Server

The `--reload` option is intended for development. Do not expose the development server directly to the public internet.

### Cryptographic Verification

A successful integrity check only establishes the properties tested by the implementation. It does not prove that the application is free from vulnerabilities or that its keys and endpoints are securely managed.

### Responsible Security Testing

Use the replay and tampering features only in the project's controlled demo environment or other systems for which you have explicit authorization.

---

## Limitations

SmartGridSentinel is a classroom and portfolio prototype, not a production-ready smart-grid security platform.

Current scope limitations include:

- Local database storage rather than a hardened production data store.
- Demonstration-oriented local cryptographic key management.
- No complete production authentication and authorization system.
- No guarantee of encrypted-at-rest database storage.
- Application-level aggregate response minimization is not a formal proof of privacy-preserving aggregation.
- No independent cryptographic protocol audit.
- Security dashboard metrics represent the implemented checks, not a comprehensive assessment of system security.

These limitations define the current scope of the project and provide opportunities for further development.

---

## Future Improvements

Potential extensions include:

- Role-based access control and authenticated API clients.
- Hardened key storage and key rotation.
- A formally specified and independently reviewed aggregation protocol.
- Improved audit logging and event filtering.
- Automated security report generation.
- More comprehensive integration and regression tests.
- Containerized deployment for reproducible demonstrations.
- CI workflows for linting and automated tests.
- Better monitoring, alerting, and operational health checks.
- Security documentation and threat modelling.

These are possible future enhancements, not claims about existing functionality.

---

## Troubleshooting

### `ModuleNotFoundError`

Make sure the virtual environment is activated and dependencies are installed:

```bash
python -m pip install -r requirements.txt
```

### `Address already in use`

Start the server on a different port:

```bash
python -m uvicorn app.main:app --reload --port 8001
```

### Dashboard Does Not Load

1. Confirm that Uvicorn is running.
2. Open the health endpoint.
3. Inspect the browser developer console for frontend errors.
4. Check the terminal for backend exceptions.
5. Verify that the static files are in `app/static/`.

### Integrity Verification Reports a Baseline Mismatch

A baseline mismatch can occur when the dataset being checked differs from the established baseline.

Investigate the reading history and security events first. Establish a new baseline only after confirming that the current data is trusted.

### Existing Data Is Missing

Check that the application is using the expected database path. A different working directory, configuration, or fresh clone may point to a different database file.

Back up the database and key files before making changes. Do not delete or regenerate existing key material simply to resolve an unrelated dashboard issue.

---

## Learning Outcomes

This project provides practical exposure to:

- Secure data ingestion concepts.
- HMAC-based message authentication.
- Cryptographic hash chains and integrity checking.
- Replay-attack detection concepts.
- Merkle baseline verification.
- Paillier homomorphic encryption.
- FastAPI application development.
- SQLite persistence and audit logging.
- Frontend-to-backend API integration.
- Security testing and attack simulation.
- Documenting limitations and security assumptions.

---

## Author

**Santusht Lakhanpal**

B.Tech — Computer Science and Engineering  
Specialization: Cyber Security

**GitHub:** [codebysantusht](https://github.com/codebysantusht)

**Project Repository:** [SmartGridSentinel](https://github.com/codebysantusht/SmartGridSentinel)

---

## License

No license is specified here. Add a `LICENSE` file to the repository if you want to grant others explicit permission to use, modify, and distribute this project. Until then, do not assume that the repository is open-source licensed.

---

*SmartGridSentinel is an educational cybersecurity project intended for learning, experimentation, and authorized security demonstrations.*
