# BlockVote-India: Project File Structure & System Architecture

This document provides a comprehensive overview of the `BlockVote-India` repository. It documents the production layout, module boundaries, cryptographic assets, and data flows across the system.

---

## High-Level Repository Architecture

```text
BlockVote-India/
│
├── backend/                  # Django Full-Stack Web Application, Gasless Relayer & UI
│   ├── api/                  # Core Application: Views, WebSockets, ZK Prover & Templates
│   ├── config/               # Project Settings, ASGI/Channels Routing, URL Dispatcher
│   ├── manage.py             # Django Management Utility
│   ├── seed_demo_data.py     # Deterministic Seeder for Demo Elections & Voters
│   └── venv/                 # Backend Virtual Environment
│
├── ml_service/               # Active Sentinel AI/ML Microservice (FastAPI + Scikit-Learn)
│   ├── main.py               # Real-Time Anomaly Scoring API (/api/v1/analyze-threat/)
│   ├── train.py              # Synthetic Telemetry Data Generator & Isolation Forest Trainer
│   ├── model.pkl             # Serialized Scikit-Learn Isolation Forest Model
│   └── venv/                 # ML Service Virtual Environment
│
├── blockchain/               # Polygon Amoy Smart Contracts & Circom ZK Circuits
│   ├── contracts/            # Solidity Smart Contracts (Voting.sol, Verifier.sol, etc.)
│   ├── circuits/             # Circom Groth16 Zero-Knowledge Circuits & Keys
│   ├── scripts/              # Contract Deployment & Verification Automations
│   ├── test/                 # Hardhat Test Suites for On-Chain Proof Verification
│   ├── hardhat.config.js     # Hardhat Network & Compiler Configuration
│   └── package.json          # Node.js Cryptographic Dependencies (SnarkJS, Ethers)
│
├── docker-compose.yml        # Multi-Container Compose Configuration (PostgreSQL 15, Redis 7)
├── requirements.txt          # Unified Python Dependencies (Django, FastAPI, Web3, Scikit-Learn)
├── HARDWARE_REQUIREMENTS.md  # Minimum & Recommended Execution Specs
├── Project_Plan.md           # Master Project Plan & Execution Milestones (Current Architecture)
├── Project_Plan.txt          # Plaintext Mirror of Project Plan
├── FILE_STRUCTURE.md         # Repository Layout & Architectural Blueprint (This Document)
└── .gitignore                # Global Ignore Definitions
```

---

## 1. Backend Application (`/backend`)

The backend is built with **Django 5**, **Django REST Framework**, and **Django Channels 4** (ASGI). It acts as the full-stack portal engine, cryptographic relayer, and session coordinator.

```text
backend/
├── config/
│   ├── settings.py           # Database, Security, CORS, Channels & Static Configuration
│   ├── urls.py               # Root URL Router for Portals & REST Endpoints
│   ├── asgi.py               # ASGI Application Entry (Daphne/Channels Protocol Router)
│   └── wsgi.py               # WSGI Application Entry
│
├── api/
│   ├── models.py             # Database Models:
│   │                         #   - Election (Timestamps, Merkle Root Lock)
│   │                         #   - Candidate (Ballot Candidates & Party Data)
│   │                         #   - VoterIdentity (Zero-Knowledge Hash Whitelist Registry)
│   │                         #   - BallotRecord (Anonymous On-Chain Receipts & Nullifiers)
│   │                         #   - ThreatLog (Active Sentinel AI Anomaly Records)
│   │
│   ├── views.py              # Portal Views & REST Endpoints:
│   │                         #   - portal_selection_view (/): Flagship Hub
│   │                         #   - voter_auth_view (/auth/voter/): Dynamic OTP Register & Login
│   │                         #   - voter_dashboard_view (/voter/): Citizen Voting Terminal
│   │                         #   - admin_dashboard_view (/admin-panel/): EC Commission Console
│   │                         #   - auditor_dashboard_view (/auditor/): Independent Audit Portal
│   │                         #   - generate_voter_otp (/api/v1/send-otp/): Cryptographic OTP Dispatch
│   │                         #   - submit_vote_relayer (/api/v1/relayer/submit-vote/): Gasless ZK Relayer
│   │
│   ├── consumers.py          # WebSocket Consumers:
│   │                         #   - QRTokenConsumer (/ws/qr-session/): 60s Single-Use HMAC-SHA256 Token
│   │                         #   - TelemetryConsumer (/ws/admin-telemetry/): Real-Time Threat Stream
│   │
│   ├── routing.py            # Channels WebSocket URL Routing
│   ├── urls.py               # App-Level URL Routing
│   ├── admin.py              # Django Admin Model Registrations
│   │
│   ├── static/api/           # Flagship Antigravity Design System & Client-Side Scripts:
│   │   ├── css/
│   │   │   └── antigravity.css     # Antigravity Light-Theme Design System (Glassmorphic)
│   │   ├── js/
│   │   │   ├── antigravity_ui.js   # Universal UI Engine (Toasts, Modals, Clipboard, Smooth Physics)
│   │   │   ├── web3_wallet.js      # Ethers.js Injected Web3 Wallet Coordinator
│   │   │   ├── zkp_prover.js       # Client-Side SnarkJS Groth16 WASM Prover & Witness Generator
│   │   │   ├── qr_streamer.js      # 60s Countdown Engine, WebSocket Listener & Auto-Expiry Overlay
│   │   │   └── auditor_mempool.js  # Live WebSocket & RPC Mempool Transaction Streamer
│   │   └── crypto/
│   │       ├── verification_key.json      # Groth16 Verification Key (SnarkJS format)
│   │       ├── voter_eligibility.wasm     # Compiled Circom Circuit WASM (Browser Execution)
│   │       └── voter_eligibility_final.zkey # Proving Key Parameter Asset
│   │
│   └── templates/api/        # Production Jinja2/Django HTML5 Templates:
│       ├── base.html               # Master Layout (Header, Sticky Nav, Web3 Bar, Antigravity Theme)
│       ├── portal_select.html      # Flagship 3-Portal Landing Hub
│       ├── auth_voter.html         # Citizen Auth: Dynamic Registration & Login with OTP Verification
│       ├── auth_admin.html         # Election Commission Staff Credential Login
│       ├── auth_auditor.html       # Certified Institutional Observer Token-Gated Login
│       ├── voter_dashboard.html    # 3-Step Citizen Terminal: KYC -> 60s QR Session -> ZK Ballot
│       ├── admin_dashboard.html    # EC Command: Candidate Setup, Merkle Lock & Live Threat Map
│       └── auditor_dashboard.html  # Public Transparency Portal: Merkle Inspector & Mempool Stream
```

---

## 2. Blockchain & Cryptography Engine (`/blockchain`)

Smart contracts deployed to the **Polygon Amoy Testnet** (and compatible with local Hardhat nodes). Zero-knowledge proofs guarantee voter privacy and prevent double-voting using spent nullifiers.

```text
blockchain/
├── contracts/
│   ├── ElectionRegistration.sol  # Whitelist Merkle Tree Root storage & Admin Lock Mechanism
│   ├── Voting.sol                # Anonymous Ballot Counter, Proof Verifier & Nullifier Storage
│   └── verifier.sol              # Groth16 SnarkJS-generated on-chain pairing verifier
│
├── circuits/
│   ├── voter_eligibility.circom  # Circom circuit: 20-level Poseidon Merkle Proof & Nullifier Derivation
│   └── build/                    # Circuit compilation artifacts (.r1cs, .sym)
│
├── scripts/
│   ├── deploy.js                 # Hardhat deployment script for Polygon Amoy
│   └── auditor_verify.js         # CLI tool for mathematical auditor tally verification
│
├── test/
│   ├── voting-test.js            # Proof verification & nullifier anti-replay test suite
│   └── relayer-test.js           # EIP-2771 meta-transaction relayer tests
│
├── hardhat.config.js             # Solidity 0.8.20 compiler, Polygon Amoy & Localhost network settings
└── package.json                  # Hardhat, @openzeppelin/contracts, snarkjs, circomlibjs
```

---

## 3. Active Sentinel AI/ML Microservice (`/ml_service`)

A high-performance **FastAPI** microservice serving as an autonomous firewall against DDoS attacks, automated bots, and anomalous traffic surges on the Gasless Relayer.

```text
ml_service/
├── main.py                       # FastAPI application serving /api/v1/analyze-threat/
├── train.py                      # Synthetic telemetry generator and Isolation Forest trainer
├── model.pkl                     # Serialized Scikit-Learn IsolationForest model
└── venv/                         # Python virtual environment
```

**Features Evaluated:**
1. `payload_size`: Evaluates bytes submitted to the relayer.
2. `request_velocity`: Rolling request frequency (requests/second per IP).
- Normal voting traffic: Velocity ~1-5 req/sec, Payload ~2,000 bytes.
- DDoS/Botnet traffic: Velocity >30 req/sec or Payload >8,000 bytes -> **Blocked automatically**.

---

## 4. End-to-End Cryptographic Flow

1. **Citizen Onboarding & KYC:**
   - Citizen enters EPIC and Mobile Number on `/auth/voter/`.
   - Clicks **Send OTP** -> receives dynamic 6-digit code.
   - Enters OTP -> Backend verifies and computes salted hash: `voter_hash = SHA256(EPIC + Mobile + Salt)`.
   - Whitelists voter in `VoterIdentity` without storing raw PII.

2. **Session Security (1-Minute Single-Use QR):**
   - On `/voter/`, client opens WebSocket to `/ws/qr-session/`.
   - Backend issues an HMAC-SHA256 signed session token with an exact **60-second** lifetime.
   - When the countdown reaches `00:00`, the QR code is disabled, showing a locked overlay, and vote submission buttons are disabled until the page is refreshed.

3. **Client-Side Zero-Knowledge Proving:**
   - Citizen selects candidate on the ballot.
   - Browser runs `zkp_prover.js` via **SnarkJS WASM** directly in memory.
   - Derives a secret scalar nullifier and generates a valid Groth16 zk-SNARK proof that the citizen is an authorized leaf on the Merkle tree.
   - **Zero Knowledge:** The candidate choice and voter identity are cryptographically decoupled.

4. **Gasless Relayer & On-Chain Verification:**
   - Proof transmitted to Django Relayer (`/api/v1/relayer/submit-vote/`).
   - Active Sentinel evaluates client IP & velocity -> drops bad actors with HTTP 403.
   - Relayer verifies `nullifier` hasn't been spent, signs transaction with server gas wallet, and invokes `Voting.sol.castVote(...)`.
   - Stores `BallotRecord`, marks voter as voted, and broadcasts event to the live Auditor Mempool.
