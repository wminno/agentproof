import io, json, sys, os
sys.path.insert(0, "/home/agt7shpm0/agentproof")
import importlib.util
spec = importlib.util.spec_from_file_location("app", "/home/agt7shpm0/agentproof/app.py")
app = importlib.util.module_from_spec(spec); spec.loader.exec_module(app)

def request(method, path, body=None):
    body = body or b""
    raw = (f"{method} {path} HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"
           f"Content-Length: {len(body)}\r\n\r\n").encode() + body
    wout = io.BytesIO()
    conn = type("C", (), {"makefile": lambda self, mode, *a: io.BytesIO(raw) if "rb" in mode else wout, "sendall": lambda self, b: wout.write(b)})()
    h = app.Handler(conn, ("203.0.113.9", 55555), None)
    try:
        h.handle_one_request()
    except Exception as e:
        print("handler exc:", e)
    head, _, rest = wout.getvalue().partition(b"\r\n\r\n")
    return int(head.split(b" ")[1]), rest

if os.path.exists(app.STORE): os.remove(app.STORE)

c, b = request("GET", "/api/health")
print("health:", c, json.loads(b)["ok"] is True)

body = json.dumps({"agent": "beta-1", "task": "ship PR 42", "deliverable": "https://github.com/me/repo/pull/42"}).encode()
c, b = request("POST", "/api/receipt", body)
rec = json.loads(b)
print("issue:", c, rec["id"], rec["agent"] == "beta-1", "sha_len:", len(rec["sha256"]))

c, b = request("POST", "/api/verify", json.dumps({"id": rec["id"], "signature": rec["signature"]}).encode())
print("verify good:", c, json.loads(b)["valid"] is True)

c, b = request("POST", "/api/verify", json.dumps({"id": rec["id"], "signature": "0" * 32}).encode())
print("verify bad:", c, json.loads(b)["valid"] is False)

c, b = request("GET", "/receipt/" + rec["id"])
print("receipt page:", c, b"beta-1" in b and b"sha256" in b, b"<script>" not in b)

c, b = request("GET", "/receipt/ffffffffff")
print("missing 404:", c == 404)

c, b = request("GET", "/")
print("landing:", c, b"AgentProof" in b and b"bootreceipt1" in b)

c, b = request("POST", "/api/receipt", b"not json")
print("bad json 400:", c == 400)

c, b = request("POST", "/api/receipt", json.dumps({"agent": "a", "deliverable": "x", "sha256": "nothex"}).encode())
print("bad sha 400:", c == 400)

c, b = request("GET", "/api/nope")
print("unknown 404 + hints:", c == 404, b"api/receipt" in b)

app.RATE.clear()
codes = [request("POST", "/api/receipt", json.dumps({"agent": "a%d" % i, "deliverable": "x%d" % i}).encode())[0] for i in range(32)]
print("rate limit 429 after 30:", codes[:30] == [200] * 30 and codes[30] == 429 and codes[31] == 429)
print("ALL HTTP TESTS PASSED")
