# OgunAI Scout

Automated passive security audit engine for Nigerian fintech APIs.

**Live demo:** https://ogunai-scout.onrender.com/docs

---

## What it does

OgunAI Scout runs fully automated security audits against production APIs using only passive,
observational checks — no attack payloads, no credential stuffing, no injection attempts.
Every finding is based on what the server voluntarily broadcasts.

Checks performed:

- OpenAPI/Swagger schema discovery (schema-aware probing)
- HTTP security headers (HSTS, CSP, X-Frame-Options, Referrer-Policy)
- Sensitive path exposure (.env, .git, admin panels, API docs)
- SSL/TLS certificate validity and TLS version
- DNS and email security (SPF, DMARC) with context-aware severity
- CORS policy with spoofed origin test
- Rate limiting detection (method-aware — sends correct HTTP verb)
- Information disclosure via error responses
- Dependency CVE scanning via OSV.dev

Findings are mapped to CBN Cybersecurity Framework and NDPR obligations automatically,
producing reports with executive summary, risk score, compliance section, and
remediation roadmap.

---

## How the AI agent works

Scout is powered by a ReAct (Reasoning + Acting) agent loop. The agent receives a system
prompt describing the target, then iteratively:

1. Thinks about what to test next (OBSERVATION → ANALYSIS → PLAN)
2. Calls the appropriate tool
3. Reads the result
4. Decides whether to write a finding or move on

All tools are passive and read-only. The agent never sends attack payloads.

---

## Key engineering decisions

### Context-aware severity suppression

SPF and DMARC findings are only HIGH when the domain has MX records and actually sends
email. A Render subdomain like `api.example.onrender.com` has no MX records — flagging it
HIGH for missing email security is a false positive. The DNS tool checks for MX records
first and downgrades email security findings to LOW with an explanation when email is not
configured. This was the most impactful credibility improvement in the codebase.

### Schema-aware probing

Scout calls `fetch_openapi_schema` first on every audit. If the target exposes
`/openapi.json` or `/swagger.json`, the agent reads the full endpoint list including HTTP
methods and request body requirements. This enables method-aware rate limit probing:
instead of sending GET to a POST-only endpoint (which returns 405 and tells you nothing),
Scout sends POST with a minimal valid body and correctly reports `auth_blocked: true`
when unauthenticated probes are rejected before the rate limiter activates.

### Confidence field on findings

Every finding carries a confidence level: `high` (direct evidence in response),
`medium` (strong indicator, default), or `low` (circumstantial — probe limitations apply).
Rate limit findings on auth-required endpoints are always `low` confidence because the
rate limiter cannot be reached without valid credentials. This prevents over-reporting
and gives developers honest signal about what to prioritise.

### Lightweight RAG layer (local use)

Locally, Scout uses sentence-transformers (all-MiniLM-L6-v2, 80MB CPU-only) with numpy
cosine similarity to store past findings as embeddings. When auditing a new client, it
retrieves semantically similar findings from previous audits and injects them as context.
This gives the agent cross-client learning — patterns found in one system surface as
hypotheses when auditing another. ChromaDB was rejected because it requires Microsoft
C++ Build Tools to compile on Windows. The implementation uses numpy directly — no
compilation required.

RAG is disabled on Render free tier (`RAG_ENABLED=false`) because PyTorch (a
sentence-transformers dependency) consumes ~450MB RAM and Render's free tier is 512MB.
The agent works correctly without it.

### Infrastructure without servers

| v3 (over-engineered)      | Scout (lean)       | Reason                                  |
| ------------------------- | ------------------ | --------------------------------------- |
| Celery + Redis            | BackgroundTasks    | No server required                      |
| PostgreSQL                | SQLite             | No server required                      |
| Qdrant/ChromaDB           | JSON + numpy       | No compilation required                 |
| Multi-agent orchestration | Single ReAct loop  | Same model, more complexity, no benefit |
| 5 Docker services         | `uvicorn main:app` | Matches hardware reality                |

### Groq free tier reality

Scout uses Groq's free API with `qwen/qwen3.8-27b`. The free tier caps output tokens
per minute at 1000, which causes some iterations to fail and retry. The agent is
resilient to this — it continues from where it left off and completes the audit.
Findings are real: SSL/TLS, CORS, sensitive path exposure, and DNS checks all run to
completion. Upgrading to Groq's Developer tier removes this constraint entirely.

---

## Architecture

FastAPI + SQLite + BackgroundTasks + Groq (LLM)

- **Backend:** FastAPI, SQLAlchemy, APScheduler (weekly scheduled audits)
- **Engine:** ReAct agent loop, model-agnostic LLM adapter (Groq / Ollama / Anthropic)
- **Auth:** JWT + bcrypt, O(1) API key lookup via indexed prefix (fixes the O(n) bcrypt scan bug)
- **Persistence:** SQLite locally, ephemeral on Render (data resets on redeploy — acceptable for portfolio)
- **Scheduling:** APScheduler inside the FastAPI process — no Redis, no Celery, no worker processes

---

## Running locally

```bash
cd backend
python -m venv venv
source venv/Scripts/activate   # Windows
pip install -r requirements.txt
cp .env.example .env           # add OPENAI_API_KEY (Groq) and SECRET_KEY
uvicorn app.main:app --reload --port 8000
```

Engine (in a second terminal):

```bash
cd engine
pip install -r requirements.engine.txt
```

API docs: http://localhost:8000/docs

---

## Sample audit output

**FraudShield** (my production fraud detection API):

| Finding                                                     | Severity | Confidence | Notes                                                      |
| ----------------------------------------------------------- | -------- | ---------- | ---------------------------------------------------------- |
| API docs publicly accessible (/docs, /openapi.json, /redoc) | MEDIUM   | high       | Direct 200 response confirmed                              |
| Missing SPF and DMARC records                               | LOW      | low        | Suppressed — domain has no MX records, does not send email |
| Rate limiting unconfirmed on /predict                       | LOW      | low        | Auth-blocked: 403 returned before rate limiter activates   |

**ProjectHub** (Node.js/Express marketplace):

| Finding                       | Severity | Confidence | Notes                           |
| ----------------------------- | -------- | ---------- | ------------------------------- |
| Missing SPF and DMARC records | LOW      | low        | Render subdomain, no MX records |

Reports include executive summary, risk score bar, CBN/NDPR compliance mapping,
and prioritised remediation roadmap in Markdown.

---

## Known limitations and honest assessment

- **Render free tier RAM:** RAG is disabled because PyTorch exceeds 512MB RAM. The agent
  works without it; cross-client learning is a local-only feature at this scale.
- **Groq free tier OTPM:** Some iterations fail and retry due to the 1000 output
  token/minute cap. The audit completes despite this.
- **Schema visibility:** FraudShield disables its OpenAPI schema in production (correct
  security practice). Scout correctly notes this and falls back to generic probing.
- **Rate limit probing without credentials:** Authenticated endpoints reject unauthenticated
  probes before the rate limiter fires. Scout reports this as `auth_blocked: true` with
  `confidence: low` rather than claiming rate limiting is absent.

---

## Related

- **FraudShield** — production fraud detection API audited by Scout:
  https://github.com/duyilemidada/FraudShield
- **Improvement roadmap** — pinned in codebase: context-aware severity (done),
  OpenAPI ingestion (done), method-aware rate limiting (done), confidence field (done),
  authenticated scanning, CI/CD webhook, PDF export (planned)
