# ScamLens

**See the red flags before you act.**

ScamLens is an AI-powered decision-support tool that helps people recognize suspicious communication,
understand the evidence behind the warning, verify claims, and take safer actions before responding.
Built for the *AI + Cybersecurity* hackathon track.

## Problem

Scams, phishing, impersonation and social engineering are now fast, convincing and cheap to run: fake bank alerts
asking for an OTP, "registration fee" job offers, giveaway prizes, "Hi Mum, new number" WhatsApp messages and
too-good-to-be-true investments. A bare "scam / safe" label doesn't help ordinary users. They need to know what
looks wrong, why it matters, and what to do next.

## Solution

Paste a message, upload a screenshot, or upload an email file. ScamLens extracts the text (OCR for screenshots,
which the user can correct), analyzes it with an AI model, calibrates the result with transparent rule-based
checks, and explains it:

- a risk level (LOW, MEDIUM, HIGH, CRITICAL) and an **AI Risk Confidence** score
- every **red flag** with a quote from the message and a plain-language "why it matters"
- **recommended actions** and **verification steps**
- a separate **link analysis** (links are parsed, never opened)

It never claims certainty. Wording is "high-risk communication detected", not "this is a scam".

## Features

- Message, screenshot (OCR with review/edit step) and `.txt` / `.eml` input
- Structured, validated AI output with malformed-response handling (one retry only if needed)
- **False-positive protection:** urgency or a payment request alone is capped at MEDIUM; strong combinations
  (e.g. OTP request + pressure) are raised. Every adjustment is explained on the result page
- Evidence check: each quoted piece of evidence is verified against the message
- Link analysis: shorteners, IP hosts, look-alike domains, odd subdomains, suspicious endings, HTTP
- Analysis history (SQLite) and a statistics dashboard computed from real data
- Fictional demo messages (Nigerian/African context) with no real organisations
- Accessible UI: icons plus text labels plus a level scale, so colour is never the only signal
- Security: input validation, file-size and type limits, safe image decoding, rate limiting, optional shared API token, no secrets in the frontend

## Architecture

```
User
 ↓
Streamlit (app.py, frontend/)
 ↓  HTTP (optional X-API-Key)
FastAPI (backend/main.py)
 ↓
OCR / text processing (ocr.py, utils.py)
 ↓
AI analysis (analyzer.py: AIAnalyzer → Provider → Model)
 ↓
Risk engine (risk_engine.py: links, signals, calibration)
 ↓
SQLite (database.py)
 ↓
Results
```

```
scamlens/
├── app.py                 Streamlit entry point and navigation
├── backend/
│   ├── main.py            FastAPI routes, auth, rate limit, error handlers
│   ├── service.py         Pipeline: validate → cache → AI → risk engine → store
│   ├── analyzer.py        Prompt, provider abstraction, response validation
│   ├── risk_engine.py     Link analysis, rule-based signals, risk calibration
│   ├── ocr.py             Validate, preprocess and read screenshots (Tesseract)
│   ├── database.py / models.py   SQLite access and schema
│   ├── schemas.py / config.py / errors.py / utils.py
├── frontend/              Pages (home, analyze, history, dashboard, about), components, API client, demo data
├── tests/                 pytest suite
├── data/scamlens.db       Created automatically on first run
├── Dockerfile, render.yaml, .streamlit/
└── docs/DEMO_SCRIPT.md
```

## Technology

Python 3.10+, FastAPI, Streamlit, SQLite, Tesseract OCR (via `pytesseract` and Pillow), and an AI model API
(Anthropic by default, or any OpenAI-compatible API).

## Installation

1. Install **Tesseract**: `sudo apt install tesseract-ocr` (Ubuntu/Debian), `brew install tesseract` (macOS), or the
   [Windows installer](https://github.com/UB-Mannheim/tesseract/wiki) (add it to `PATH`).
2. Create an environment and install dependencies:

```bash
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
```

## Environment variables

Edit `.env` (never commit it). The essentials:

| Variable | Purpose |
|---|---|
| `SCAMLENS_AI_PROVIDER` | `anthropic` (default) or `openai` (any OpenAI-compatible API) |
| `ANTHROPIC_API_KEY`, `ANTHROPIC_MODEL` | Anthropic key and model (default `claude-haiku-4-5-20251001`) |
| `OPENAI_API_KEY`, `OPENAI_BASE_URL`, `OPENAI_MODEL` | OpenAI-compatible settings (OpenAI, Groq, OpenRouter, local servers) |
| `SCAMLENS_API_TOKEN` | Optional shared secret; if set, the frontend must send the same value |
| `SCAMLENS_API_URL` | Where the Streamlit app finds the backend (default `http://localhost:8000`) |
| `SCAMLENS_RATE_LIMIT_PER_MIN` | Per-IP limit on analysis endpoints (default 20, `0` disables) |

All options are listed in `.env.example`. API keys are only ever read by the backend. If no key is set, the
backend starts and returns a friendly "AI service unavailable" error; it never fabricates results.

To add another AI provider, subclass `AIProvider` in `backend/analyzer.py` and register it in `PROVIDER_FACTORIES`.

## Running locally

```bash
# Terminal 1: backend (http://localhost:8000, docs at /docs)
uvicorn backend.main:app --reload

# Terminal 2: frontend (http://localhost:8501)
streamlit run app.py
```

Tests: `pip install -r requirements-dev.txt && pytest -q`
(AI calls are replaced by a test double; OCR tests run real Tesseract and are skipped if it isn't installed.)

## API

Interactive docs: `http://localhost:8000/docs`.

| Endpoint | Description |
|---|---|
| `POST /analyze/text` | JSON `{text, source_type?, original_text?}` → full analysis. `?refresh=true` bypasses the cache |
| `POST /analyze/image` | Multipart `file` (PNG/JPG/WebP) → OCR + analysis |
| `POST /ocr` | Multipart `file` → extracted text only (used for the review step) |
| `POST /analyze/file` | Multipart `.txt` or `.eml` → analysis |
| `GET /analyses` | History: `limit`, `offset`, `risk_level=HIGH,CRITICAL` |
| `GET /analyses/{id}` | One stored analysis |
| `GET /stats` | Totals, risk distribution, top categories, recent analyses |
| `GET /health` | Status, whether an AI key is configured, whether OCR is available |

Errors are JSON `{ "detail": "<friendly message>", "code": "<machine code>" }`. Stack traces are only logged server-side.
Identical messages reuse the stored result instead of calling the model again.

## Deployment

**Backend (Docker, any Python host).** The `Dockerfile` installs Tesseract. On Render: create a Blueprint from
`render.yaml`, then set `ANTHROPIC_API_KEY`. Copy the generated `SCAMLENS_API_TOKEN`. Note the backend URL.
SQLite lives on the container disk: on free plans history resets on redeploy; attach a persistent disk at
`/app/data` to keep it. The same image works on Railway, Fly.io or Cloud Run.

**Frontend (Streamlit Community Cloud).** Push the repo to GitHub, create an app with `app.py` as the entry
point, and add secrets (see `.streamlit/secrets.toml.example`):

```toml
SCAMLENS_API_URL = "https://your-scamlens-api.onrender.com"
SCAMLENS_API_TOKEN = "the-same-token-as-the-backend"
```

For a single-host demo you can also run both processes in one container or VM.

## Limitations

ScamLens is an AI-assisted risk assessment tool. It does not guarantee that a communication is fraudulent or safe.
The model can be wrong, OCR can misread text, link checks are static (no reputation lookup), and message text is
sent to the configured AI provider. Rate limiting is per process and in memory. Screenshots are not stored.

## Future improvements

Browser extension, WhatsApp and email integrations, multilingual support (Pidgin, Yoruba, Igbo, Hausa, Swahili),
voice scam detection, URL reputation services, organization verification, on-device analysis.

## Why this fits the AI + Cybersecurity prompt

It uses AI to help people **recognize** scam and impersonation indicators, **verify** claims through independent
steps, **prevent** harm with concrete actions (don't click, don't pay, don't share an OTP) and **respond** to
fraud attempts, while staying honest about uncertainty and keeping suspicious links unopened.
