#!/usr/bin/env python3
"""AgentProof - signed work receipts for AI agents (proof-of-execution).

POST /api/receipt  -> hash + timestamp + HMAC-signed receipt for a deliverable
GET  /receipt/<id> -> public human-readable receipt page (for reviewers)
POST /api/verify   -> verify id+signature
GET  /api/health   -> probe

Stdlib only. Honest scope: proves a deliverable (hash) was attested at time T
by agent X and detects tampering with the stored record. It does not prove
who wrote the code or that it works. Notarization, not certification.
"""
import hashlib, hmac, json, os, re, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

PORT = int(os.environ.get("PORT", "8314"))
BASE = os.path.dirname(os.path.abspath(__file__))
KEYFILE = os.path.join(BASE, ".secret_key")
STORE = os.path.join(BASE, "receipts.jsonl")

def _secret():
    try:
        with open(KEYFILE) as f:
            return f.read().strip()
    except FileNotFoundError:
        s = hashlib.sha256(os.urandom(32)).hexdigest()
        fd = os.open(KEYFILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(s)
        return s

SECRET = _secret()
RATE = {}
RL_MAX, RL_WIN = 30, 60.0

def sign(rid, ts, agent, sha):
    msg = "|".join([rid, ts, agent, sha]).encode()
    return hmac.new(SECRET.encode(), msg, hashlib.sha256).hexdigest()[:32]

def rl_ok(ip):
    now = time.time()
    win, n = RATE.get(ip, [now, 0])
    if now - win > RL_WIN:
        RATE[ip] = [now, 0]
        return True
    return n < RL_MAX

def bump(ip):
    w = RATE.get(ip)
    if w and time.time() - w[0] <= RL_WIN:
        w[1] += 1
    else:
        RATE[ip] = [time.time(), 1]

def new_id():
    return hashlib.sha256(os.urandom(16)).hexdigest()[:10]

def save(rec):
    with open(STORE, "a") as f:
        f.write(json.dumps(rec, sort_keys=True) + "\n")

def load(rid):
    if not os.path.exists(STORE):
        return None
    with open(STORE) as f:
        for line in f:
            try:
                r = json.loads(line)
                if r.get("id") == rid:
                    return r
            except Exception:
                pass
    return None

def esc(s):
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

LAND = """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta property="og:title" content="AgentProof - signed work receipts for AI agents">
<meta property="og:description" content="Notarize what an AI agent produced: HMAC-signed, verifiable work receipts with a tamper check. Free API, no signup.">
<meta property="og:url" content="https://workreceipts.bigfloppy.net/">
<meta property="og:type" content="website">
<meta name="twitter:card" content="summary">
<title>AgentProof - signed work receipts for AI agents</title>
<style>body{font-family:ui-monospace,Menlo,monospace;max-width:760px;margin:2rem auto;padding:0 1rem;color:#111}
h1{font-size:1.5rem} code,pre{background:#f4f4f4;padding:2px 5px;border-radius:4px}
pre{overflow-x:auto;padding:1rem;border:1px solid #ddd}
.receipt{border:1px solid #ddd;border-radius:8px;padding:1rem;background:#fafafa;margin:1rem 0;word-break:break-all}
small{color:#666} a{color:#06c} </style></head><body>
<h1>AgentProof</h1>
<p><b>Signed work receipts for AI agents.</b> One POST returns a tamper-evident,
timestamped receipt for a deliverable. The public receipt page is what a human
reviewer opens to check an agent's claim. Free, no signup, no key.</p>
<h3>What it proves - and what it doesn't</h3>
<p>It proves: <i>a deliverable with this SHA-256 hash was attested by agent X at
time T, and the receipt record has not been altered since</i> (HMAC-signed).</p>
<p>It does <b>not</b> prove the deliverable works, who really wrote it, or that
the agent is trustworthy. It is notarization, not certification.</p>
<h3>API</h3>
<pre>POST /api/receipt
 {"agent":"beta-1","task":"build webhook handler",
  "deliverable":"https://github.com/me/repo/pull/42",
  "sha256":"&lt;hex sha256 of the deliverable, optional&gt;"}
-&gt; {"id":"a1b2c3d4e5","created_at":"2026-..Z","signature":"...",
     "verify_url":".../receipt/a1b2c3d4e5"}

POST /api/verify {"id":"a1b2c3d4e5","signature":"..."}
-&gt; {"valid":true,"receipt":{...}}

GET /receipt/&lt;id&gt;  -&gt; public HTML receipt page (share with reviewers)
GET /api/health     -&gt; {"ok":true,"receipts_issued":N}</pre>
<p>If you omit <code>sha256</code>, the service hashes the <code>deliverable</code>
string for you. Rate limit 30/min per IP. Receipts are public by design -
do not include secrets.</p>
<h3>Example receipt (real, issued at first boot)</h3>
"""

TAIL = """<p style="margin-top:2rem"><small>Agent-built and operated
(lead-builder-2 in the SelfEarner swarm). Disclosed: this is an autonomous
agent's tool.</small></p>
</body></html>"""

def receipt_box(r):
    return ("<div class='receipt'><code>id</code>: " + esc(r["id"]) + "<br>" +
            "<code>agent</code>: " + esc(r["agent"]) + "<br>" +
            "<code>task</code>: " + esc(r.get("task", "")) + "<br>" +
            "<code>deliverable</code>: " + esc(r["deliverable"]) + "<br>" +
            "<code>sha256</code>: " + esc(r["sha256"]) + "<br>" +
            "<code>created_at</code>: " + esc(r["created_at"]) + "<br>" +
            "<code>signature</code>: " + esc(r["signature"]) + "</div>")

def issue(agent, task, deliverable, sha):
    rid, ts = new_id(), time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    if not sha:
        sha = hashlib.sha256(deliverable.encode()).hexdigest()
    if not re.fullmatch(r"[a-f0-9]{64}", sha or ""):
        return None, "sha256 must be 64 hex chars", 400
    sig = sign(rid, ts, agent, sha)
    rec = {"id": rid, "agent": agent, "task": task, "deliverable": deliverable,
           "sha256": sha, "created_at": ts, "signature": sig}
    save(rec)
    return rec, None, 200

class Handler(BaseHTTPRequestHandler):
    server_version = "AgentProof/1.0"

    def _send(self, code, body, ctype="application/json"):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def _json(self, code, obj):
        self._send(code, json.dumps(obj, indent=1), "application/json")

    def _drain(self):
        # read any unread request body so keep-alive connections stay in sync
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = 0
        n = min(n, 5000000)
        while n > 0:
            chunk = self.rfile.read(min(n, 65536))
            if not chunk:
                break
            n -= len(chunk)

    def _body(self):
        try:
            n = int(self.headers.get("Content-Length", "0") or 0)
        except ValueError:
            n = 0
        if n > 200000:
            self._drain()
            return None
        try:
            raw = self.rfile.read(n) if n > 0 else b""
            return json.loads(raw or b"{}")
        except Exception:
            return None

    def _empty(self, code, ctype="text/html; charset=utf-8"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_HEAD(self):
        # HEAD = GET status without body; link checkers / HN treat 501 as a dead site
        p = urlparse(self.path).path
        if p == "/api/health" or p in ("/", "/api") \
           or re.fullmatch(r"/receipt/([a-f0-9]{10})", p) \
           or re.fullmatch(r"/api/receipt/([a-f0-9]{10})", p):
            return self._empty(200)
        self._drain()
        return self._empty(404)

    def _rl(self):
        ip = self.client_address[0]
        if not rl_ok(ip):
            return False
        bump(ip)
        return True

    def do_GET(self):
        self._alog()
        p = urlparse(self.path).path
        if p == "/api/health":
            n = 0
            if os.path.exists(STORE):
                with open(STORE) as f:
                    n = sum(1 for _ in f)
            return self._json(200, {"ok": True, "service": "agentproof", "receipts_issued": n})
        m = re.fullmatch(r"/receipt/([a-f0-9]{10})", p)
        if m:
            r = load(m.group(1))
            if not r:
                return self._send(404, "<h1>404</h1><p>No such receipt.</p>" + TAIL, "text/html")
            return self._send(200, "<h1>Work receipt " + esc(r["id"]) + "</h1>" +
                              receipt_box(r) +
                              "<p>Verify: <code>POST /api/verify</code> with this id+signature, "
                              "or GET /api/receipt/" + r["id"] + " for JSON.</p>" + TAIL, "text/html")
        m = re.fullmatch(r"/api/receipt/([a-f0-9]{10})", p)
        if m:
            r = load(m.group(1))
            return self._json(200, r) if r else self._json(404, {"error": "no such receipt"})
        if p in ("/", "/api"):
            example = load("bootreceipt1") or {}
            return self._send(200, LAND + (receipt_box(example) if example else "") + TAIL, "text/html")
        self._drain()
        return self._json(404, {"error": "not found", "endpoints": ["/api/receipt", "/api/verify", "/receipt/<id>", "/api/health"]})

    def do_POST(self):
        self._alog()
        if not self._rl():
            self._drain()
            return self._json(429, {"error": "rate limit: 30/min per IP"})
        p = urlparse(self.path).path
        d = self._body()
        if d is None:
            return self._json(400, {"error": "invalid JSON body"})
        if p == "/api/receipt":
            agent = str(d.get("agent") or "").strip()[:80]
            task = str(d.get("task") or "").strip()[:300]
            deliv = str(d.get("deliverable") or "").strip()[:2000]
            sha = str(d.get("sha256") or "").strip().lower()
            if not agent or not deliv:
                return self._json(400, {"error": "'agent' and 'deliverable' are required"})
            rec, err, code = issue(agent, task, deliv, sha)
            if err:
                return self._json(code, {"error": err})
            rec["verify_url"] = "/receipt/" + rec["id"]
            return self._json(200, rec)
        if p == "/api/verify":
            rid = str(d.get("id") or "").strip()
            sig = str(d.get("signature") or "").strip()
            r = load(rid)
            if not r or not hmac.compare_digest(r.get("signature", ""), sig):
                return self._json(200, {"valid": False, "reason": "no such receipt or bad signature"})
            cur = load(rid)
            recheck = sign(cur["id"], cur["created_at"], cur["agent"], cur["sha256"])
            same = hmac.compare_digest(recheck, sig)
            intact = os.path.exists(STORE)
            return self._json(200, {"valid": bool(same), "note": "record unchanged since issue" if same else "signature does not match record",
                                    "receipt": cur})
        return self._json(404, {"error": "not found"})


    def _alog(self):
        try:
            ip = (self.headers.get("X-Forwarded-For") or "").split(",")[0].strip() or self.client_address[0]
            with open(STORE.replace("receipts.jsonl", "hits.log"), "a") as f:
                f.write("%s %s %s\n" % (time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), ip, urlparse(self.path).path))
        except Exception:
            pass

    def log_message(self, fmt, *args):
        pass

if __name__ == "__main__":
    if not load("bootreceipt1"):
        rid = "bootreceipt1"
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        agent = "lead-builder-2"
        task = "AgentProof boot receipt - example, issued at first start"
        deliv = "https://github.com/wminno/agentproof"
        sha = hashlib.sha256(deliv.encode()).hexdigest()
        rec = {"id": rid, "agent": agent, "task": task, "deliverable": deliv,
               "sha256": sha, "created_at": ts, "signature": sign(rid, ts, agent, sha)}
        save(rec)
    os.chdir(BASE)
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print("AgentProof listening on", PORT, flush=True)
    srv.serve_forever()
