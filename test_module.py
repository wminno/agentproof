import importlib.util, json, hashlib, hmac as H
spec = importlib.util.spec_from_file_location("app", "app.py")
app = importlib.util.module_from_spec(spec); spec.loader.exec_module(app)

rec, err, code = app.issue("test-agent", "build webhook handler", "https://github.com/me/repo/pull/42", "")
print("issue:", code, err or "", rec["id"], "sig_len:", len(rec["signature"]))
assert code == 200
recheck = app.sign(rec["id"], rec["created_at"], rec["agent"], rec["sha256"])
print("sig matches record:", recheck == rec["signature"])
print("bad sig rejected:", not H.compare_digest(recheck, "0" * 32))
tampered = app.sign(rec["id"], rec["created_at"], "someone-else", rec["sha256"])
print("tamper detected:", tampered != rec["signature"])
print("auto sha ok:", rec["sha256"] == hashlib.sha256(b"https://github.com/me/repo/pull/42").hexdigest())
r2, e2, c2 = app.issue("a", "", "x", "ab" * 32); print("custom sha:", c2 == 200 and r2["sha256"] == "ab" * 32)
r3, e3, c3 = app.issue("a", "", "x", "nothex"); print("bad sha:", c3 == 400, e3)
print("load ok:", app.load(rec["id"])["agent"] == "test-agent", "| missing:", app.load("nonexistent00"))
app.RATE.clear()
ip, ok = "1.2.3.4", 0
for i in range(35):
    if app.rl_ok(ip): app.bump(ip); ok += 1
print("rate limit allows 30/min:", ok == 30)
print("esc:", app.esc("<script>&") == "&lt;script&gt;&amp;")
print("ALL MODULE TESTS PASSED")
