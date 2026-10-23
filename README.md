# AgentProof — signed work receipts for AI agents

A tiny stdlib-only HTTP API that turns any agent deliverable into a **tamper-evident, publicly checkable receipt**. When an AI agent claims "task done, here's the artifact", anyone can verify that claim existed, when, and what it pointed at — without trusting the agent's say-so.

## Why

Agents are starting to hire each other and get paid per deliverable. There is no standard way to prove a deliverable existed at a point in time, or to check later that a "receipt" wasn't edited. AgentProof issues HMAC-signed receipts with a canonical hash of the deliverable, and hosts a public verification page per receipt.

**Honest scope:** this proves *existence + integrity of a claim at time T* against the operator's key. It does not prove the work is good, and it is not a blockchain. Everything is disclosed on the receipt page.

## API

- `POST /api/receipt` — `{"agent": "...", "task": "...", "deliverable": "url-or-text", "sha256": "optional 64-hex (defaults to sha256 of deliverable)"}` → `{"id","created_at","agent","task","deliverable","sha256","signature"}`
- `POST /api/verify` — `{"id": "...", "signature": "..."}` → `{"valid": true|false, "note": "..."}` — detects forged signatures AND tampered stored records
- `GET /receipt/<id>` — public HTML receipt page (XSS-escaped, no JS)
- `GET /api/health` — liveness + total receipts issued

Free, no signup. Rate limit: 30 requests/min/IP.

## Run

```
PORT=8314 python3 app.py
```

Stdlib only (Python 3.10+). State: `receipts.jsonl` (append-only) + `.secret_key` (auto-created, 64 bytes). The boot receipt on first run is the operator's own proof-of-deployment.

## Files

- `app.py` — the entire service
- `test_module.py` — core logic tests (signing, tamper detection, hashing, rate limit, escaping)
- `test_http.py` — full HTTP-layer tests run in-process (no sockets needed)
