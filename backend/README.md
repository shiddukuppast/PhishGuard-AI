# PhishGuard AI - Backend REST API Service
> **Detect. Analyze. Protect.**  
> High-performance Python FastAPI service with MongoDB Atlas, Argon2 password hashing, JWT authentication, Scikit-learn ML inference interface, multi-factor risk assessment, threat intelligence integrations, and ReportLab PDF dossier generation.

---

## 1. Architecture Overview

PhishGuard AI follows a strict three-pillar project architecture:
```
PhishGuard-AI/
├── frontend/     # Next.js 14, React, TypeScript, Tailwind CSS, Lucide icons
├── backend/      # Python FastAPI REST API, Motor/MongoDB Atlas, Pydantic, Argon2, JWT
└── model/        # Standalone ML training pipeline, notebooks, datasets, model artifacts
```

The backend is structured into clean modular layers:
```
backend/
├── app/
│   ├── main.py                     # FastAPI entrypoint, CORS, lifespan, exception handlers
│   ├── config/
│   │   ├── settings.py             # Pydantic BaseSettings loading from environment variables
│   │   └── database.py             # Async Motor connection manager, indexes, offline fallback
│   ├── models/                     # MongoDB document models
│   │   ├── user.py                 # User document schema
│   │   ├── scan.py                 # Scan result document schema
│   │   └── report.py               # Report dossier document schema
│   ├── schemas/                    # Pydantic v2 validation and response models
│   │   ├── auth.py                 # Signup/Login requests and Auth responses
│   │   ├── user.py                 # User profile responses
│   │   ├── scanner.py              # URL scan request and structured scan responses
│   │   ├── report.py               # Report creation and list responses
│   │   ├── dashboard.py            # Aggregate metrics, trends, and time-series schemas
│   │   └── intelligence.py         # Threat intelligence response schemas
│   ├── routes/                     # API route controllers under /api/v1
│   │   ├── auth.py                 # POST /signup, POST /login, GET /me, POST /logout
│   │   ├── scanner.py              # POST /scan, GET /{id}
│   │   ├── history.py              # GET /, DELETE /{id}
│   │   ├── dashboard.py            # GET /stats, GET /activity, GET /distribution
│   │   ├── reports.py              # GET /, POST /, GET /{scan_id}/download (PDF)
│   │   └── intelligence.py         # POST /check
│   ├── services/                   # Core business logic and security processing
│   │   ├── auth_service.py         # User registration, authentication, JWT tokens, cookies
│   │   ├── url_analyzer.py         # Static URL lexical and structural feature extraction
│   │   ├── prediction_service.py   # Scikit-learn model loader and inference engine
│   │   ├── threat_intelligence.py  # PhishTank and OpenPhish threat feed lookups
│   │   ├── risk_engine.py          # Multi-factor score calculator (0-100) and explanations
│   │   └── report_service.py       # ReportLab PDF dossier streaming generator
│   └── utils/
│       ├── security.py             # Argon2 password hashing & PyJWT token utilities
│       └── dependencies.py         # FastAPI dependency injection & slowapi rate limiter
├── tests/                          # Complete Pytest asynchronous test suite (29 tests)
│   ├── conftest.py                 # In-memory mock async database and ASGI test client
│   ├── test_auth.py                # Signup, login, duplicate email, weak password, auth cookies
│   ├── test_url_analyzer.py        # Static feature extraction, IP hosts, shorteners, entropy
│   ├── test_prediction.py          # ML service loading & graceful fallback handling
│   ├── test_risk_engine.py         # Risk scoring, classification levels, indicator generation
│   ├── test_threat_intel.py        # Threat feed caching and unconfigured key handling
│   ├── test_scanner_api.py         # Guest scans, authenticated scans, validation errors
│   ├── test_history_dashboard.py   # History queries, filters, aggregate stats, health checks
│   └── test_reports.py             # Report persistence and PDF download streaming
├── .env.example                    # Template environment variables
├── requirements.txt                # Production and development dependencies
└── README.md                       # Comprehensive backend documentation
```

---

## 2. Technology Stack & Key Libraries

- **Language:** Python 3.10+
- **Framework:** [FastAPI](https://fastapi.tiangolo.com/) + [Uvicorn](https://www.uvicorn.org/)
- **Database:** [MongoDB Atlas](https://www.mongodb.com/atlas) with [Motor](https://motor.readthedocs.io/) (asynchronous PyMongo)
- **Validation:** [Pydantic v2](https://docs.pydantic.dev/) + [Pydantic-Settings](https://docs.pydantic.dev/latest/concepts/pydantic_settings/)
- **Password Security:** [Argon2-cffi](https://argon2-cffi.readthedocs.io/) (memory-hard, modern password hashing)
- **Session Tokens:** [PyJWT](https://pyjwt.readthedocs.io/) (HMAC-SHA256, HTTP-only cookies + Bearer auth)
- **Machine Learning Integration:** [Scikit-learn](https://scikit-learn.org/) + [Joblib](https://joblib.readthedocs.io/)
- **PDF Generation:** [ReportLab](https://www.reportlab.com/) (binary PDF byte stream generation)
- **HTTP Client:** [HTTPX](https://www.python-httpx.org/) (asynchronous HTTP for threat intel APIs)
- **Rate Limiting:** [SlowAPI](https://slowapi.readthedocs.io/) (token bucket IP rate limiting)
- **Testing:** [Pytest](https://docs.pytest.org/) + [Pytest-Asyncio](https://pytest-asyncio.readthedocs.io/)

---

## 3. Environment Configuration & MongoDB Atlas Setup

### Step 1: Create a MongoDB Atlas Cluster
1. Sign in to your [MongoDB Atlas account](https://www.mongodb.com/cloud/atlas).
2. Create a free M0 cluster (e.g., in AWS `us-east-1` or your preferred region).
3. Under **Security > Database Access**, create a database user (e.g., `phishguard_admin`) with **Read and write to any database** privileges and a strong password.
4. Under **Security > Network Access**, click **Add IP Address** and whitelist your server's IP address (or `0.0.0.0/0` during development).
5. Under **Database > Connect**, select **Drivers > Python** to copy your connection string:
   ```
   mongodb+srv://<username>:<password>@<cluster-url>/?retryWrites=true&w=majority
   ```

### Step 2: Configure Environment Variables
Copy `.env.example` to `.env` in the `backend/` directory:
```bash
cp backend/.env.example backend/.env
```

Edit `backend/.env` with your values:
```ini
# Application Configuration
APP_NAME=PhishGuard AI Backend
APP_VERSION=1.0.0
DEBUG=False

# MongoDB Atlas Connection String
MONGODB_URI=mongodb+srv://phishguard_admin:YourStrongPassword123@cluster0.abcde.mongodb.net/?retryWrites=true&w=majority
DATABASE_NAME=phishguard

# JWT Authentication Configuration
JWT_SECRET_KEY=change_this_to_a_random_32_character_string_for_production
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=1440

# Cookie Configuration
COOKIE_NAME=phishguard_access_token
COOKIE_SECURE=false      # Set to true in production over HTTPS
COOKIE_SAMESITE=lax

# Frontend Application Origin (for CORS)
FRONTEND_URL=http://localhost:3000

# Threat Intelligence API Keys (Optional)
PHISHTANK_API_KEY=
OPENPHISH_API_KEY=

# Machine Learning Model Path (Relative to backend/ or absolute)
MODEL_PATH=../model/artifacts/phishing_model.pkl

# Rate Limiting
RATE_LIMIT_ENABLED=true
RATE_LIMIT_AUTH=10/minute
RATE_LIMIT_SCAN=30/minute
```

> **Note on Disconnected/Offline Mode:**  
> If `MONGODB_URI` is blank or the cluster is temporarily unreachable, the service starts gracefully in disconnected mode, logging a diagnostic warning. Health checks at `/health` and `/api/v1/health` will report `database.status: "disconnected"` while core static analysis endpoints continue functioning.

---

## 4. Installation & Local Development Setup

### 1. Create a Python Virtual Environment
Inside the `backend/` directory:
```bash
# Windows
python -m venv .venv
.\.venv\Scripts\activate

# macOS / Linux
python3 -m venv .venv
source .venv/bin/activate
```

### 2. Install Dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### 3. Start the FastAPI Development Server
```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

The server will boot at `http://localhost:8000`.

---

## 5. Interactive API Documentation

FastAPI automatically generates interactive OpenAPI documentation:
- **Swagger UI:** [http://localhost:8000/docs](http://localhost:8000/docs)
- **ReDoc:** [http://localhost:8000/redoc](http://localhost:8000/redoc)
- **OpenAPI JSON:** [http://localhost:8000/openapi.json](http://localhost:8000/openapi.json)

---

## 6. REST API Endpoints Specification

All API routes are prefixed under `/api/v1`:

| Method | Endpoint | Description | Auth Required |
|---|---|---|---|
| `GET` | `/health` | System health, MongoDB status & ML model availability | No |
| `POST` | `/api/v1/auth/signup` | Register new user with Argon2 password hashing | No |
| `POST` | `/api/v1/auth/login` | Authenticate user, issue JWT & set HTTP-only cookie | No |
| `GET` | `/api/v1/auth/me` | Retrieve profile of currently authenticated user | **Yes** |
| `POST` | `/api/v1/auth/logout` | Clear HTTP-only session cookie | No |
| `POST` | `/api/v1/scanner/scan` | Analyze URL with ML inference, heuristics & threat intel | Optional |
| `GET` | `/api/v1/scanner/{id}` | Retrieve full forensic details of a past scan | Optional |
| `GET` | `/api/v1/history/` | List scans with search, filter, and pagination | **Yes** |
| `DELETE` | `/api/v1/history/{id}` | Delete a scan from user history | **Yes** |
| `GET` | `/api/v1/dashboard/stats` | Aggregated dashboard summary metrics and trends | Optional |
| `GET` | `/api/v1/dashboard/activity` | 7-day threat activity counts for Recharts | Optional |
| `GET` | `/api/v1/dashboard/distribution` | Threat distribution breakdown for Donut chart | Optional |
| `GET` | `/api/v1/reports/` | List security audit dossiers for current user | **Yes** |
| `POST` | `/api/v1/reports/` | Generate and persist a security audit report | **Yes** |
| `GET` | `/api/v1/reports/{scan_id}/download` | Stream binary ReportLab PDF security dossier | Optional |
| `POST` | `/api/v1/intelligence/check` | Look up URL against PhishTank & OpenPhish | Optional |

---

## 7. Machine Learning Model Integration

The ML interface is decoupled via `backend/app/services/prediction_service.py` and reads model artifacts from the root `model/` folder:
- **Default Artifact Location:** `model/artifacts/phishing_model.pkl`

### Expected Scikit-Learn Model Interface:
The model pipeline or estimator should be saved using `joblib.dump(model, "phishing_model.pkl")` and implement standard scikit-learn inference methods:
```python
# Returns 1 for Phishing, 0 for Legitimate
prediction = model.predict(feature_array)

# Returns probabilities [[P(Legitimate), P(Phishing)]]
probabilities = model.predict_proba(feature_array)
```

### Extracted Feature Vector (13 Features):
The backend's `URLAnalyzer.extract_features()` generates the following numeric vector passed to the model:
1. `url_length` (int)
2. `domain_length` (int)
3. `dots` (int)
4. `hyphens` (int)
5. `subdomain_count` (int)
6. `has_ip_host` (0 or 1)
7. `has_https` (0 or 1)
8. `keyword_count` (int)
9. `parameter_count` (int)
10. `is_shortened` (0 or 1)
11. `shannon_entropy` (float)
12. `has_at_symbol` (0 or 1)
13. `has_non_standard_port` (0 or 1)

### Fallback Behavior:
If the model file is not yet trained or absent, `prediction_service` marks `available = False` and logs a clean notice. The `RiskEngine` transparently adjusts its scoring weights to rely on static heuristic features and threat intelligence, without crashing or faking predictions.

---

## 8. Running Automated Tests

The backend includes a comprehensive asynchronous Pytest suite verifying authentication, password hashing, JWT cookies, static URL feature extraction, risk evaluation, threat intel caching, database persistence, and PDF generation.

To run the test suite:
```bash
# In backend virtual environment:
pytest backend/tests -v
```

All 29 tests execute against an isolated in-memory mock database with zero external network dependencies.

