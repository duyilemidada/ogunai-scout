# OgunAI Scout

Automated passive security audit engine for Nigerian fintech APIs.

**Live demo:** https://ogunai-scout.onrender.com/docs

## What it does

OgunAI Scout runs fully automated security audits against production APIs
using only passive, observational checks — no attack payloads, no credential
stuffing, no injection attempts. Every finding is based on what the server
voluntarily broadcasts.

Checks performed:

- HTTP security headers (HSTS, CSP, X-Frame-Options)
- Sensitive path exposure (.env, .git, admin panels, API docs)
- SSL/TLS certificate validity and TLS version
- DNS and email security (SPF, DMARC)
- CORS policy with spoofed origin test
- Rate limiting detection
- Information disclosure via error responses
- Dependency CVE scanning via OSV.dev

Findings are mapped to CBN Cybersecurity Framework and NDPR obligations
automatically, producing reports suitable for regulatory review.

## How the AI agent works

Scout is powered by a ReAct (Reasoning + Acting) agent loop running on Groq's
LLaMA‑3.3‑70B model. The agent receives a system prompt describing the target,
then iteratively:

1. Thinks about what to test next
2. Calls the appropriate tool (e.g., `check_security_headers`)
3. Reads the result
4. Decides whether to write a finding or move on

All tools are passive and read‑only. The agent never sends attack payloads.

## Architecture

FastAPI + SQLite/PostgreSQL + BackgroundTasks + Groq (LLM)

No Docker. No Redis. No Celery. Single-process design that runs on
constrained hardware and deploys to Render's free tier.

- **Backend:** FastAPI, SQLAlchemy, APScheduler
- **Engine:** ReAct agent loop, model-agnostic LLM adapter (Groq/Ollama/Anthropic)
- **Auth:** JWT + bcrypt API key authentication with O(1) prefix-indexed lookup
- **Scheduling:** Weekly automated audits via APScheduler (no Redis needed)

## Running locally

```bash
# Backend
cd backend
python -m venv venv && source venv/Scripts/activate
pip install -r requirements.txt
cp ../.env.example .env   # fill in OPENAI_API_KEY and SECRET_KEY
uvicorn app.main:app --reload --port 8000
```

API docs: http://localhost:8000/docs

## Sample audit output

Against FraudShield (my production fraud detection API):

- HIGH: Missing SPF/DMARC records (email spoofing risk)
- HIGH: Rate limiting not detected on prediction endpoint
- MEDIUM: API documentation publicly accessible (/docs, /openapi.json)

Report includes executive summary, risk score, CBN/NDPR compliance mapping,
and remediation roadmap.

## Related

- **FraudShield** — the fraud detection API OgunAI Scout audits:
  https://github.com/duyilemidada/FraudShield
