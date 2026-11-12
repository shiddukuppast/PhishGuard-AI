# PhishGuard AI

> **Detect. Analyze. Protect.**  
> AI-Powered Phishing Detection & Website Security Analysis Platform.

PhishGuard AI is an enterprise-grade cybersecurity SaaS platform engineered to analyze URLs, detect suspicious structural and lexical anomalies, assign calibrated risk scores, and deliver actionable security recommendations for Security Operations Centers (SOC) and end users.

The application features a modern Next.js 14 frontend integrated with a Python FastAPI asynchronous backend, MongoDB Atlas database, and Scikit-learn machine learning pipeline.

---

## 🏛️ Project Architecture

The repository is organized into three completely independent modules:

```
PhishGuard-AI/
├── frontend/     # Next.js 14, React, TypeScript, Tailwind CSS, Lucide icons, Recharts
├── backend/      # Python FastAPI REST API, MongoDB Atlas (Motor), Argon2, JWT, Scikit-learn, ReportLab
└── model/        # Machine learning pipeline, training scripts, notebooks, and serialized model artifacts
```

---

## 🛡️ Core Highlights

### 1. Frontend Console (`frontend/`)
- **Cybersecurity SaaS UI**: Dark navy palette (`#0B1120`), elevated cards (`#111827`), subtle `#263244` borders, electric cyan (`#06B6D4`), and high-visibility status indicators.
- **Zero Mock / Synthetic Data**: All demo credentials, simulated scan histories, fake threat intelligence streams, and hardcoded KPI statistics have been completely removed. MongoDB is the single source of truth.
- **Honest Zero-States**: When the database has 0 records, the dashboard displays true zero metrics (Total Scans: 0, Phishing Detected: 0, Safe: 0, Suspicious: 0) and clean call-to-action cards directing users to launch their first scan.
- **Authentication & Route Guards**:
  - **Public Routes**: `/` (Landing Page), `/login` (Sign In), `/signup` (Registration).
  - **Protected Console**: `/dashboard`, `/scanner`, `/history`, `/intelligence`, `/reports`, `/settings`.
  - Live session restore on application startup via `GET /api/v1/auth/me`.
  - HTTP-only cookie credentials (`credentials: 'include'`) for secure JWT lifecycle without storing credentials or tokens in localStorage.
- **Centralized REST API Service (`frontend/lib/api.ts`)**:
  - Configured with `NEXT_PUBLIC_API_BASE_URL=http://127.0.0.1:8000/api/v1`.
  - 15-second AbortController request timeout.
  - Standardized error handling for 401, 422, 429, 500, and offline network errors.
- **URL Scanner**:
  - Multi-stage analysis animation.
  - SVG risk score gauge (0–100) with color-coded classification.
  - Transparent 3-layer breakdown: Rule-Based Heuristics, ML Classifier Status (displaying accurate offline/online notice), and Threat Intelligence Feeds.
  - One-click streaming ReportLab PDF download.
- **Scan History**:
  - Real scans queried live from MongoDB via `GET /api/v1/history/`.
  - User-isolated audit trail with live search, classification filtering, and score sorting.
  - Delete scan action connected directly to `DELETE /api/v1/history/{scan_id}`.
- **Threat Intelligence Radar**:
  - Connected to `GET /api/v1/intelligence/overview`.
  - Displays real configuration status for PhishTank and OpenPhish feeds.
  - On-demand verification tool querying `POST /api/v1/intelligence/check`.
  - Lists verified malicious records harvested directly from MongoDB.
- **Reports Management**:
  - Connected to `GET /api/v1/reports/`.
  - Generate reports from scans via `POST /api/v1/reports/` and `POST /api/v1/reports/generate/{scan_id}`.
  - Download official PDF dossiers streamed directly from ReportLab engine via `GET /api/v1/reports/{report_id}/pdf`.
- **Analyst Settings & Profile**:
  - Displays real user metadata (Name, Email, Role, Created Date, Database ID) from active session.

---

### 2. Backend REST API (`backend/`)
- **Framework**: Python FastAPI running on Uvicorn with asynchronous endpoints.
- **Database**: MongoDB Atlas with asynchronous Motor driver, connection pooling, and automated index creation (`users`, `scans`, `reports`).
- **Authentication & Security**: Argon2 password hashing (via `argon2-cffi`), PyJWT token generation, HTTP-only secure cookie sessions, and SlowAPI rate limiting.
- **Static URL Feature Extraction (`url_analyzer.py`)**: 13 static lexical/structural features without visiting target URLs (SSRF prevention).
- **Machine Learning Integration (`prediction_service.py`)**: Scikit-learn estimator interface with transparent fallback message when the model artifact is offline.
- **Threat Intelligence Feeds (`threat_intelligence.py`)**: PhishTank and OpenPhish lookups with LRU in-memory caching and graceful unconfigured key handling.
- **ReportLab PDF Generator (`report_service.py`)**: Multi-page security audit PDF generation streamed dynamically.
- **Automated Test Suite**: 29 Pytest asynchronous unit and integration tests passing with 100% test success.

---

### 3. Machine Learning Pipeline (`model/`)
- Dedicated directory for dataset curation, preprocessing, feature engineering, and model training.
- Serialized model artifacts are saved to `model/artifacts/phishing_model.pkl` and ingested automatically by `prediction_service.py`.

---

## 📖 REST API Endpoints Specification

| Method | Endpoint | Description | Auth Required |
|---|---|---|---|
| `GET` | `/health` | System health check (MongoDB connection & ML status) | No |
| `POST` | `/api/v1/auth/signup` | Register new account (Argon2 hash + JWT cookie) | No |
| `POST` | `/api/v1/auth/login` | Authenticate user credentials & issue JWT session cookie | No |
| `GET` | `/api/v1/auth/me` | Fetch active user clearance profile | **Yes** |
| `POST` | `/api/v1/auth/logout` | Clear HTTP-only session cookie | No |
| `POST` | `/api/v1/scanner/scan` | Analyze target URL with heuristics & threat intel | Optional |
| `GET` | `/api/v1/scanner/{id}` | Fetch full scan forensics by ID | Optional |
| `GET` | `/api/v1/history/` | List user scan records with search, filter, and pagination | **Yes** |
| `DELETE` | `/api/v1/history/{id}` | Delete a scan from user history in MongoDB | **Yes** |
| `GET` | `/api/v1/dashboard/stats` | KPI summary metrics & trend calculations | Optional |
| `GET` | `/api/v1/dashboard/activity` | 7-day threat activity counts for Recharts | Optional |
| `GET` | `/api/v1/dashboard/recent-scans` | Recent scans list for dashboard table | Optional |
| `GET` | `/api/v1/reports/` | List security audit dossiers from MongoDB | **Yes** |
| `POST` | `/api/v1/reports/` | Generate and persist a security audit report | **Yes** |
| `POST` | `/api/v1/reports/generate/{scan_id}` | Generate report directly using scan ID | **Yes** |
| `GET` | `/api/v1/reports/{report_id}/pdf` | Stream binary ReportLab PDF security report | **Yes** |
| `GET` | `/api/v1/reports/{report_id}/download` | Alias for PDF security report download | **Yes** |
| `GET` | `/api/v1/intelligence/overview` | Threat radar status, metrics, and MongoDB signatures | No |
| `POST` | `/api/v1/intelligence/check` | On-demand feed verification for a target URL | No |

---

## 🚀 Quick Start Guide

### Prerequisites
- **Node.js** (v18+ or v20+) and **npm**
- **Python** (v3.10+)

---

### Step 1: Start the FastAPI Backend

```bash
# Navigate to backend directory
cd backend

# Create virtual environment and activate
python -m venv .venv
# On Windows PowerShell:
.\.venv\Scripts\Activate.ps1
# On Linux / macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Configure environment variables
# Copy .env.example to .env and configure your MongoDB Atlas connection string
cp .env.example .env

# Start the backend server
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

- **Backend API:** [http://127.0.0.1:8000](http://127.0.0.1:8000)
- **Interactive Swagger Docs:** [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **ReDoc:** [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)
- **Health Check:** [http://127.0.0.1:8000/health](http://127.0.0.1:8000/health)

#### Run Backend Test Suite:
```bash
pytest backend/tests/ -v
```

---

### Step 2: Start the Next.js Frontend

In a separate terminal:

```bash
# Navigate to frontend directory
cd frontend

# Install dependencies
npm install

# Start Next.js development server
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) in your browser.

---

## 🔐 Authentication & MongoDB Workflow

1. Navigate to `/signup` to register a new security analyst account. Your password is securely hashed using **Argon2id** and stored in MongoDB Atlas (`phishguard.users`).
2. Upon login (`/login`), the backend sets a secure HTTP-only cookie (`phishguard_access_token`).
3. All URL scans performed while authenticated are associated with your `user_id` and indexed in MongoDB (`phishguard.scans`).
4. Real-time statistics, scan histories, threat feeds, and downloadable PDF reports are isolated and owned by your account.

---

*PhishGuard AI — Autonomous Threat Detection Platform*
