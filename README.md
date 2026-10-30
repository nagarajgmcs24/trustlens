# TRUSTLENS

**See Through the Scam. Trust What Matters.**

TRUSTLENS is a privacy-conscious web application that screens suspicious messages for phishing, impersonation, and social-engineering indicators. It provides explainable heuristic findings and recommended precautions; it does not determine with certainty whether a message is fraudulent.

## Problem

Scam messages often imitate banks, government services, employers, delivery providers, or support teams. Urgency and fear can pressure people to click links, pay fees, or share credentials before they verify the sender.

## Solution

Paste a message into TRUSTLENS to get a transparent, rule-based risk assessment. The app extracts message signals and URLs without opening the links, then displays a risk score, matching categories, explanations, and recommended next steps.

## Key features

- Rule-based checks for urgency, sensitive-information requests, financial and government impersonation, job/reward scams, and payment requests.
- URL extraction and caution checks for URL shorteners, IP-address hosts, HTTP, and unusual verification-style hostnames.
- Explainable score and recommendations returned by the backend.
- React pages for landing, dashboard, analysis, results, and about.
- FastAPI endpoints for analysis, health, and history.
- Optional MongoDB Atlas metadata history, with in-memory backend fallback and browser-local fallback.
- Analysis history stores metadata only; original messages are not saved to MongoDB.

## Technology

- Frontend: React, JavaScript, Vite, Tailwind CSS, Axios, React Router, Lucide React
- Backend: Python, FastAPI, Pydantic, Uvicorn, PyMongo, python-dotenv
- Database: MongoDB Atlas (optional)
- Detection: deterministic Python rules, regular expressions, and URL parsing

## Architecture

```text
Browser (React/Vite)
  ├─ Axios POST /api/analyze ──> FastAPI validation and rule engine
  │                              └─ metadata ──> MongoDB analysis_history
  └─ Axios GET /api/history <── FastAPI history endpoint
                                 └─ in-memory fallback if MongoDB is unavailable
```

The backend analyzes the message and returns the report. MongoDB stores only the analysis ID, timestamp, channel, risk level, score, and detected categories. The frontend keeps the current original message in navigation state to display the report; local browser history stores result metadata.

## Project structure

```text
TRUSTLENS/
├── README.md
├── HACKATHON_DEMO.md
├── JUDGE_QA.md
├── backend/
│   ├── main.py
│   ├── database.py
│   ├── .env.example
│   ├── requirements.txt
│   ├── routes/
│   ├── models/
│   ├── services/
│   └── tests/
└── frontend/
    ├── package.json
    ├── vite.config.js
    └── src/
        ├── components/
        ├── pages/
        └── services/
```

## Requirements

- Python and Node.js/npm installed.
- The project-provided `backend/venv/` environment, or a separately created Python environment with `backend/requirements.txt` installed.
- MongoDB Atlas is optional. Analysis remains available without it.

## Environment configuration

Copy the example file to `backend/.env` and add your Atlas URI locally:

```cmd
cd /d C:\TRUSTLENS\backend
copy .env.example .env
notepad .env
```

Configure these values:

```env
MONGODB_URI=your-private-atlas-connection-uri
MONGODB_DB_NAME=trustlens
CORS_ORIGINS=http://localhost:5173,http://127.0.0.1:5173
APP_ENV=development
HOST=127.0.0.1
PORT=8000
ENABLE_HISTORY_API=true
```

Do not commit or share `.env`. The backend `.gitignore` excludes it. Never place MongoDB credentials in frontend files. Configure the frontend API URL with `VITE_API_BASE_URL` if the backend is not at `http://localhost:8000`; the variable is public configuration and must never contain a secret.

## Start the application

Run the backend in terminal one:

```cmd
cd /d C:\TRUSTLENS\backend
.\venv\Scripts\python.exe -m uvicorn main:app --reload --port 8000
```

Run the frontend in terminal two:

```cmd
cd /d C:\TRUSTLENS\frontend
npm install
npm run dev
```

Open `http://localhost:5173`. The API is at `http://localhost:8000`; interactive API documentation is available at `http://localhost:8000/docs`.

## API

### `GET /`

Returns a simple backend-running status message.

### `GET /api/health`

Returns backend status and MongoDB connectivity (`connected` or `offline`). A configured connection is checked with a MongoDB ping.

### `POST /api/analyze`

Example request:

```json
{
  "message": "Your account is suspended. Verify your KYC immediately.",
  "channel": "SMS",
  "language": "English",
  "claimed_organization": "Example Bank",
  "sender_name": "Example sender",
  "sender_email": "alerts@example.com"
}
```

`message` is required (10–5000 characters); `channel` may be SMS, WhatsApp, Email, or Other; `language` may be English, Hindi, or Kannada (default: English). Optional `claimed_organization`, `sender_name`, and `sender_email` values support heuristic sender/domain mismatch checks. Missing sender details do not add risk by themselves. `risk_score` and `risk_level` are the evidence-only score and classification; `effective_risk_score` and `effective_risk_level` include contextual combination and sender mismatch bonuses. The response also includes detected categories, matched evidence, explanations, and recommendations.

### `GET /api/history`

Returns up to 100 newest analysis metadata records from MongoDB, or the backend's in-memory fallback if MongoDB is unavailable.
Dashboard totals and risk counts summarize the history records returned by this endpoint (up to 100), not an unlimited lifetime total.
This unauthenticated endpoint is available only in development. It returns 404 in production until authentication and user-scoped history are implemented.

### `DELETE /api/history`

Clears analysis history in development only. It returns 404 in production until authentication and user-scoped deletion are implemented.

## Database

When configured, PyMongo connects to the `trustlens` database and uses `analysis_history`. A ping is performed before database operations. Saved fields are limited to analysis ID, timestamp, channel, effective risk level and score, and detected categories. Sender fields and the original message are not persisted. If the connection is unavailable, analysis continues and the backend uses an in-memory history fallback; this fallback is cleared when the backend process stops.

## Detection and scoring

The engine applies Unicode-normalized phrase rules for account threats, urgency, specific time pressure, sensitive-information requests, financial/government impersonation, upfront job fees, prizes/rewards, money requests, and suspicious URLs. Context rules combine related signals while applying only the strongest matching combination bonus, so overlapping patterns do not stack the same signals repeatedly. Targeted English, Hindi, and Kannada negation patterns suppress certain warnings such as “never share your OTP” or “no fee is required.” Sender-domain mismatch checks compare a user-supplied claimed organization and sender email against a small static list; they do not verify email authenticity, domain ownership, or a sender's identity. Hindi and Kannada coverage remains limited and none of the rule sets is comprehensive. The response includes each detected category, matched phrase, phrase language, explanation, points, and recommended safe action. A category contributes at most once to the evidence score, overlapping phrases within a category do not stack, and the effective score is capped at 100. A shortener alone adds only a low-weight signal; dates and ordinary time references are not treated as urgency by themselves.

- 0–29: LOW RISK
- 30–59: MEDIUM RISK
- 60–100: HIGH RISK

The score is an initial heuristic ranking—not a probability, guarantee, or scientifically calibrated measure. False positives and false negatives are possible.

The current synthetic multilingual validation corpus and measured results are documented in [DETECTION-QUALITY-REPORT.md](./DETECTION-QUALITY-REPORT.md). Its results are limited to that authored test set and are not real-world accuracy estimates.

## Privacy and security

- Message content is sent only to the TRUSTLENS backend for analysis; no external AI service is used.
- MongoDB stores analysis metadata, not raw messages.
- URLs are parsed as text and are not visited, fetched, or executed.
- Keep Atlas credentials in `backend/.env`; never commit that file.
- Use a narrow Atlas IP access list and a dedicated least-privilege database user.
- Verify high-impact claims independently through known official channels.
- The default development server binds to localhost. History routes do not implement user authentication, so do not expose this single-user demo backend to a public or shared network; add authentication and user-scoped records before deployment.
- Set `APP_ENV=production` to disable history routes. Production startup requires explicit `CORS_ORIGINS` entries and rejects wildcard origins. Configure the deployment's bind address/port using `HOST`/`PORT` (when running `python main.py`) or the equivalent Uvicorn command-line options.
- Production hosting is not fully hardened: `/api/analyze` remains unauthenticated and there is no rate limiting. Add abuse controls and a deployment security review before exposing it publicly.

## Limitations

- Keyword rules and scoped negation patterns do not understand full context, language nuance, or novel scam techniques.
- URL heuristics do not verify reputation, redirect destinations, or page contents.
- HTTPS alone does not mean a URL is trustworthy.
- Sender identity and domain ownership are not independently validated; mismatch checks are heuristic and use a non-exhaustive static list.
- Offline history is in memory and is not durable.
- The application is a demo aid, not a substitute for security professionals or official verification.

## Future enhancements

- Add broader synthetic and user-consented evaluation cases with measured false-positive/negative rates.
- Improve context-aware, multilingual rule coverage while preserving explainability.
- Add optional URL reputation lookups with explicit privacy and network controls.
- Add database indexes and retention controls for larger deployments.
- Add automated browser integration tests and deployment hardening.
