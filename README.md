# SmartGrid Sentinel

### Privacy-Aware Smart Grid Monitoring & Cryptographic Integrity Verification
SmartGrid Sentinel is a cybersecurity-focused smart grid monitoring prototype designed to demonstrate secure smart meter communication, cryptographic integrity verification, replay attack detection, and privacy-aware neighborhood-level energy aggregation.

The system combines **HMAC-SHA256 authentication, SHA-256 hash chains, Merkle-based integrity baselines, Paillier homomorphic encryption, and hierarchical MAC aggregation** to demonstrate how cryptographic mechanisms can help protect smart grid telemetry.

It provides a web-based security dashboard where users can monitor smart meters, submit authenticated readings, simulate attacks, verify integrity, and inspect neighborhood aggregation results.

---

## Table of Contents

- [Project Overview](#project-overview)
- [Problem Statement](#problem-statement)
- [Key Features](#key-features)
- [System Architecture](#system-architecture)
- [Cryptographic Implementation](#cryptographic-implementation)
- [Dashboard Modules](#dashboard-modules)
- [Technology Stack](#technology-stack)
- [Project Structure](#project-structure)
- [Installation and Setup](#installation-and-setup)
- [Running the Application](#running-the-application)
- [Security Demonstrations](#security-demonstrations)
- [Running Tests](#running-tests)
- [API Documentation](#api-documentation)
- [Security Considerations and Limitations](#security-considerations-and-limitations)
- [Future Enhancements](#future-enhancements)
- [Author](#author)

---

## Project Overview

Smart grids rely on smart meters to collect and transmit electricity consumption readings. These readings must remain authentic and protected against unauthorized modifications, replay attacks, and integrity violations.

SmartGrid Sentinel demonstrates a security architecture for this environment.

The application allows a grid operator to:

- Register and manage smart meters.
- Submit electricity consumption readings.
- Authenticate readings using HMAC-SHA256.
- Verify reading integrity using SHA-256 hash chains.
- Detect replayed or modified readings.
- Establish Merkle-based integrity baselines.
- Generate neighborhood-level aggregate MACs.
- Perform additive homomorphic aggregation using Paillier encryption.
- Monitor security events through a web dashboard.

The project focuses on demonstrating cryptographic security mechanisms in a simulated smart grid environment.

## Problem Statement

**Privacy-Preserving Aggregate MACs and Hash-Based Metering Verification**

The project addresses the challenge of verifying aggregated electricity consumption data from multiple smart meters while reducing unnecessary exposure of individual household information.

The proposed prototype explores:

1. Message Authentication Codes for validating meter readings.
2. Cryptographic hash chains for detecting unauthorized modifications.
3. Hierarchical MACs for authenticating neighborhood-level aggregates.
4. Paillier homomorphic encryption for encrypted additive aggregation.
5. Integrity monitoring and replay attack detection.

The objective is to demonstrate how cryptographic authentication and encrypted aggregation can support the security of smart grid monitoring systems.

---

## Key Features

### 1. Smart Meter Authentication

- Secure reading submission through a FastAPI backend.
- HMAC-SHA256 generation and verification.
- Meter-specific authentication.
- Sequence-based reading management.

### 2. Hash-Based Integrity Verification

- SHA-256 hash-chain implementation.
- Previous-hash linkage between consecutive readings.
- Detection of modified stored readings.
- Merkle-based integrity baseline verification.

### 3. Replay Attack Detection

- Sequence number validation.
- Detection of duplicate or invalid reading sequences.
- Security event generation for blocked replay attempts.

### 4. Tampering Detection

- Controlled tampering simulation.
- Temporary modification of stored consumption values.
- HMAC and hash-chain verification after modification.
- Restoration of the original reading after simulation.
- Dashboard alerts for detected integrity violations.

### 5. Neighborhood MAC Aggregation

- Selection of multiple smart meters.
- Individual meter evidence verification.
- Child manifest SHA-256 digest generation.
- Parent aggregate MAC generation.
- Parent MAC verification.

### 6. Paillier Homomorphic Encryption

- Encryption of smart meter readings.
- Additive aggregation of encrypted values.
- Ciphertext digest generation.
- Authentication binding between encrypted data and meter readings.
- Decryption of the final aggregate in the private aggregation workflow.

### 7. Security Monitoring Dashboard

- Smart meter fleet overview.
- Reading and energy statistics.
- HMAC VALID and INVALID status indicators.
- Integrity verification controls.
- Tampering and replay simulation.
- Neighborhood aggregation interface.
- Security event monitoring.
- Reading history and cryptographic metadata.

---

## System Architecture

The application follows a modular architecture with a web dashboard, FastAPI backend, cryptographic components, and SQLite database.

### High-Level Architecture

```text
                SMART GRID ENVIRONMENT
                         |
             +-----------+-----------+
             |                       |
        Smart Meter 1           Smart Meter 2
             |                       |
             +-----------+-----------+
                         |
                  FastAPI Backend
                         |
          +--------------+--------------+
          |              |              |
     HMAC-SHA256     SHA-256       Sequence
     Verification   Hash Chain     Validation
          |              |              |
          +--------------+--------------+
                         |
                 Integrity Monitor
                         |
          +--------------+--------------+
          |                             |
    Neighborhood MAC              Paillier
     Aggregation                 Encryption
          |                             |
     Parent MAC                  Encrypted Sum
          |                             |
          +--------------+--------------+
                         |
                   SQLite Database
                         |
                 Web Security Dashboard
```

### Reading Authentication Workflow

1. A smart meter submits an electricity consumption reading.
2. The backend prepares a canonical reading payload.
3. HMAC-SHA256 authenticates the payload.
4. A SHA-256 hash-chain entry is generated.
5. The encrypted reading and related cryptographic metadata are stored.
6. Integrity verification checks the authentication and chain linkage.

---

## Cryptographic Implementation

| Cryptographic Component | Purpose                                                  |
| ----------------------- | -------------------------------------------------------- |
| HMAC-SHA256             | Message authentication and integrity verification        |
| SHA-256                 | Cryptographic hashing                                    |
| Hash Chains             | Detection of unauthorized reading modifications          |
| Merkle Baseline         | Integrity baseline verification                          |
| Paillier Encryption     | Additive homomorphic encryption                          |
| Nested MACs             | Neighborhood aggregate authentication                    |
| Ciphertext Digest       | Binding encrypted data to authenticated reading metadata |

### HMAC-SHA256

HMAC is used to verify the authenticity and integrity of smart meter reading payloads.

The authentication process uses a secret key and a cryptographic hash function.

Conceptually:

`HMAC = HMAC-SHA256(secret_key, message)`

If the authenticated message changes without updating its valid MAC, verification fails.

### SHA-256 Hash Chain

Each reading is linked to the previous reading through a cryptographic hash.

Conceptually:

`H(i) = SHA256(Data(i) || H(i-1))`

This linkage helps detect modifications to previously stored readings.

### Paillier Homomorphic Encryption

Paillier is an additive homomorphic encryption scheme.

It allows encrypted values to be combined without first decrypting each individual value.

Conceptually:

`E(m1) × E(m2) = E(m1 + m2)`

This property is used to demonstrate encrypted smart meter aggregation.

### Hierarchical MAC Aggregation

The neighborhood aggregation module authenticates individual meter evidence and creates an aggregate-level authentication structure.

The child manifest digest represents the included meter evidence, while the parent MAC authenticates the neighborhood aggregate envelope.

---

## Dashboard Modules

The web dashboard provides the following modules:

| Module               | Functionality                                                    |
| -------------------- | ---------------------------------------------------------------- |
| Overview             | Fleet statistics, readings, energy processed and security events |
| Smart Meter Fleet    | Meter registration and management                                |
| Integrity Lab        | HMAC and hash-chain verification                                 |
| Tampering Simulation | Controlled integrity attack demonstration                        |
| Replay Simulation    | Duplicate sequence attack demonstration                          |
| Neighborhood MAC     | Hierarchical aggregate authentication                            |
| Aggregate Query      | Consumption aggregation                                          |
| Secure Readings      | Reading submission and authentication                            |
| Reading History      | Reading metadata, MAC and chain hash                             |
| Security Events      | Application security event monitoring                            |

### HMAC Verification Demonstration

The Integrity Lab provides a visual demonstration of HMAC verification.

**Valid HMAC:**

- The original reading remains unchanged.
- HMAC verification succeeds.
- The dashboard displays a green VALID status.

**Invalid HMAC:**

- The tampering simulation modifies a stored reading temporarily.
- The original HMAC no longer matches the modified payload.
- The dashboard displays a red INVALID status.
- A tampering detection event is generated.

The simulation restores the original reading after verification, allowing repeated demonstrations without permanently modifying the stored reading.

---

## Technology Stack

### Backend

- Python
- FastAPI
- REST APIs

### Frontend

- HTML5
- CSS3
- JavaScript

### Database

- SQLite

### Cryptography

- HMAC-SHA256
- SHA-256
- Paillier Homomorphic Encryption
- Merkle-based integrity verification
- Hierarchical MAC authentication

### Testing

- Pytest

### Development Tools

- Visual Studio Code
- Git
- GitHub
- Kali Linux / Windows development environment

---

## Project Structure

```text
SmartGridSentinel/
│
├── app/
│   ├── main.py
│   ├── database.py
│   ├── security.py
│   ├── paillier_manager.py
│   ├── neighborhood_aggregator.py
│   ├── private_neighborhood_aggregator.py
│   │
│   └── static/
│       ├── index.html
│       ├── app.js
│       └── styles.css
│
├── tests/
│   ├── test_private_neighborhood_aggregator.py
│   └── ... additional test modules
│
├── data/
│   └── Local database and demonstration data
│
├── .gitignore
├── requirements.txt
└── README.md
```

*Note: The structure above highlights the main application components. Additional test files and local runtime data may also be present.*

---

## Installation and Setup

### Prerequisites

Make sure you have:

- Python 3.10 or newer
- Git
- pip
- A terminal or PowerShell

### 1. Clone the Repository

```bash
git clone https://github.com/codebysantusht/SmartGridSentinel.git
```

```bash
cd SmartGridSentinel
```

### 2. Create a Virtual Environment

Windows PowerShell:

```powershell
python -m venv .venv
```

### 3. Activate the Virtual Environment

```powershell
.\.venv\Scripts\Activate.ps1
```

### 4. Install Dependencies

```powershell
pip install -r requirements.txt
```

---

## Running the Application

Start the FastAPI development server:

```powershell
uvicorn app.main:app --reload
```

The application will be available at:

**Dashboard:**

[http://127.0.0.1:8000](http://127.0.0.1:8000)

**Swagger API Documentation:**

[http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

**Health Endpoint:**

[http://127.0.0.1:8000/api/health](http://127.0.0.1:8000/api/health)

Stop the server using `Ctrl + C`.

---

## Security Demonstrations

The following workflow can be used to demonstrate the application.

### Demonstration 1: Smart Meter Registration

1. Open the dashboard.
2. Register a new smart meter.
3. Verify that the meter appears in the fleet section.

### Demonstration 2: Secure Reading Submission

1. Select a registered meter.
2. Enter a consumption value.
3. Submit the reading.
4. Observe the authentication success message.

### Demonstration 3: HMAC Integrity Verification

1. Select a meter in the Integrity Lab.
2. Click Verify Integrity.
3. Observe the green HMAC VALID status.

### Demonstration 4: Tampering Detection

1. Click Simulate Tampering.
2. Observe the red HMAC INVALID status.
3. Inspect the security event generated by the system.
4. Run Verify Integrity again.
5. Observe that the original reading passes verification after restoration.

### Demonstration 5: Replay Attack Simulation

1. Select a meter.
2. Click Simulate Replay.
3. Observe the replay rejection message.
4. Inspect the corresponding security event.

### Demonstration 6: Neighborhood MAC Aggregation

1. Enter a neighborhood ID and batch ID.
2. Select multiple active meters.
3. Generate the neighborhood aggregate.
4. Inspect the child manifest digest and parent MAC.
5. Click Verify Parent MAC.
6. Observe the verification result.

### Demonstration 7: Encrypted Aggregation

1. Submit readings for registered meters.
2. Use the private neighborhood aggregation workflow.
3. Observe the encrypted aggregation process.
4. Inspect the resulting aggregate.

---

## Running Tests

The project uses Pytest for automated testing.

Activate the virtual environment and execute:

```powershell
pytest -v
```

For a concise test summary:

```powershell
pytest -q
```

The latest reported test run during development completed with:

**30 tests passed.**

---

## API Documentation

SmartGrid Sentinel exposes REST endpoints through FastAPI.

The interactive Swagger documentation is available at:

[http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

Important API operations include:

| Endpoint                          | Method | Purpose                         |
| --------------------------------- | ------ | ------------------------------- |
| `/api/health`                     | GET    | Application health check        |
| `/api/dashboard`                  | GET    | Dashboard statistics            |
| `/api/meters`                     | GET    | Retrieve registered meters      |
| `/api/meters`                     | POST   | Register a meter                |
| `/api/readings`                   | POST   | Submit a meter reading          |
| `/api/meters/{meter_id}/verify`   | POST   | Verify meter integrity          |
| `/api/meters/{meter_id}/baseline` | POST   | Create integrity baseline       |
| `/api/demo/tamper/{meter_id}`     | POST   | Simulate reading tampering      |
| `/api/demo/replay/{meter_id}`     | POST   | Simulate replay attack          |
| `/api/neighborhoods/aggregate`    | POST   | Generate neighborhood aggregate |
| `/api/neighborhoods/verify`       | POST   | Verify parent aggregate MAC     |

---

## Security Considerations and Limitations

SmartGrid Sentinel is an educational cybersecurity prototype, not a production-ready smart grid security platform.

The following limitations are important:

- Individual consumption readings are currently stored in plaintext in the local SQLite database.
- The application provides encrypted aggregation demonstrations, but does not yet enforce complete household-level confidentiality across every component.
- The current architecture uses local demonstration key management and is not designed for production key lifecycle management.
- HMAC verification authenticates a payload but does not independently prove that a meter's reported consumption is physically accurate.
- Zero-knowledge range proofs and threshold decryption are not currently implemented.
- Information-theoretic privacy analysis using entropy and mutual information remains a future enhancement.
- Production deployment would require stronger access control, secure key storage, hardened infrastructure, and a defined threat model.

The project is intended to demonstrate cryptographic concepts and their application to smart grid security in a controlled environment.

---

## Future Enhancements

Potential future improvements include:

- Zero-knowledge range proofs for encrypted meter readings.
- Threshold Paillier decryption.
- Stronger household-level data isolation.
- Information-theoretic privacy analysis using Shannon entropy.
- Mutual information-based privacy leakage evaluation.
- Role-based access control.
- Secure key management and rotation.
- Improved audit logging and monitoring.
- Docker-based deployment.
- Expanded automated security testing.

---

## Author

**Santusht Lakhanpal**

B.Tech Computer Science and Engineering
Specialization: Cyber Security
Bennett University

**Areas of Interest:**

- Cybersecurity
- Application Security
- Cryptography
- Network Security
- Security Engineering

**GitHub:**
[https://github.com/codebysantusht](https://github.com/codebysantusht)

---

## Disclaimer

SmartGrid Sentinel is developed for educational, research, and demonstration purposes. It should not be deployed in a real smart grid environment without further security engineering, testing, and independent review.

**Built to explore cryptographic integrity, secure metering, and privacy-aware smart grid aggregation.**
