# PhishGuard AI

A phishing URL analysis project built with Next.js, FastAPI, MongoDB, and a scikit-learn classifier. It combines static URL features, heuristic risk indicators, optional threat-feed checks, user-specific history, and PDF reports.

**This is a prototype, not a guarantee that a link is safe.** The scanner does not visit submitted URLs or verify their TLS certificates. The bundled model has documented dataset leakage; its historical scores must not be interpreted as real-world detection accuracy. See [model limitations](model/README.md).

## Features

- Account registration, Argon2 password hashing, JWT cookie sessions and bearer API authentication.
- Static HTTP(S) URL analysis, with malformed input rejected before inference or feed queries.
- Separate ML, heuristic and external-feed results; unavailable services are reported explicitly.
- Account-scoped scan history, dashboard, search and reports.
- PDF exports with submitted text escaped before rendering.
- Bounded, expiring threat-feed cache. Failed checks are not cached as negative evidence.
- Public threat radar only includes feed-confirmed records explicitly marked `public_feed: true` with no user owner. Guest and private scans are not published automatically.
- Automated backend tests and frontend build/type/dependency checks in GitHub Actions.

## Local setup

Use Python 3.12, Node.js 22, and a running MongoDB instance (local or Atlas).

From the repository root:

```sh
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
cp backend/.env.example backend/.env
```

Edit `backend/.env`: set your MongoDB URI and replace `JWT_SECRET_KEY` with a unique random secret. You can generate one with:

```sh
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Start the API:

```sh
cd backend
../.venv/bin/uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

In another terminal, from the repository root:

```sh
npm --prefix frontend ci
npm run dev
```

Open [the app](http://localhost:3000), [API documentation](http://localhost:8000/docs), or [health status](http://localhost:8000/health). The frontend defaults to `http://localhost:8000/api/v1`; set `NEXT_PUBLIC_API_BASE_URL` in `frontend/.env.local` for another API address. Use matching frontend/backend hostnames for cookie authentication.

MongoDB is required for accounts, history and reports. Guest analysis can still run without persistence; `/health` reports HTTP 503 when the database is unavailable. Optional provider credentials belong in the backend environment only. Configured credentials do not establish provider availability. Provider connectivity/subscription compatibility must be verified separately.

## Verification

From the repository root, with the virtual environment activated:

```sh
python -m pytest -q
npm --prefix frontend run typecheck
npm run build
npm --prefix frontend audit --audit-level=high
```

The backend tests use an in-memory database double and mocked provider responses; they do not validate a live MongoDB deployment or external subscriptions. The optional training-extractor consistency test is skipped because the standalone training extractor is not included.

## Main API routes

All routes below use the `/api/v1` prefix; the generated `/docs` page is the full API contract.

| Route | Purpose | Authentication |
| --- | --- | --- |
| `POST /auth/signup`, `POST /auth/login` | Create account / sign in | Public |
| `GET /auth/me` | Current account | Required |
| `POST /auth/logout` | Clear session cookie | Public |
| `POST /scanner/scan` | Analyze a URL | Optional; invalid supplied sessions are rejected |
| `GET /history/`, `GET /history/{id}`, `DELETE /history/{id}` | Own scan records | Required |
| `GET /dashboard/stats`, `/dashboard/activity`, `/dashboard/recent-scans` | Own statistics | Required |
| `GET /reports/`, `POST /reports/` | List / generate own reports | Required |
| `GET /reports/{id}/download` | Download PDF | Required |
| `GET /intelligence/overview` | Explicitly public feed records | Public |
| `POST /intelligence/check` | Rate-limited provider check | Public |

## Scope and next steps

- Retrain on representative legitimate and phishing URLs with equivalent URL formatting and independent, time-separated evaluation. Do not use the leakage-affected historical benchmark to claim production readiness.
- Feed checks send submitted URLs to configured third-party providers. Avoid submitting links containing secrets or personal tokens.
- Use HTTPS, a strong JWT secret, secure cookies, restricted CORS, and deployment-specific session/CSRF controls before public deployment. The development JWT default must not be used publicly.
- The browser currently supports a sessionStorage bearer fallback in addition to HTTP-only cookies. This is accessible to JavaScript and is not equivalent to a cookie-only session design.
- Risk scores are heuristic signals, not calibrated probabilities. Accuracy and lure-lifespan statistics are displayed as unavailable until measured.

## Structure

```text
backend/    FastAPI routes, services, schemas and regression tests
frontend/   Next.js console and API client
model/      Bundled classifier, metadata and historical dataset notes
```
