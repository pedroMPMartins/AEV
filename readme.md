# AEV

This repository holds all materials and documentation developed for the AEV class. Scripts, tool documentation and my own attepts at breaking CTF challenges allong with my whole throught process for most of these things.

![](/004.gif)

## Table of Contents

- [Repository Structure](#repository-structure)
- [Challenges](#challenges)

## Repository Structure

- **tool_docs**: documentation for different tools that I use.
  - **[nmap.md](tool_docs/nmap.md)**: nmap documentation. Used to find services, and explore networks.
  - **[ffuf.md](tool_docs/ffuf.md)**: ffuf documentation. Used to find information on many different things, such as endpoints, files and find possible variables that URLs take

- **services**: documentation on the different CTF challenges solved during the subject's duration. They are organized by the number of the port (for example, `8010.md`). Each document holds what I found in said port, and my though process, tools and all sorts of things I used to solve the challenge and get the flag.

- **scripts**: folder holding scripts I made to solve CTFs. Some are generic, others may need small changes to adapt to the actual new challenge.


## Challenges

The following table holds the link for the documentation on each challenge, it's type, it's difficulty and a small summary on how I solved it:

| Challenge | Type | Difficulty | Summary |
| :--- | :--- | :---: | :--- |
| [8010](services/8010.md) | Information Leakage (Backup File) | Easy | Discovered backup file `config.py.bak` under `/static/` exposing internal API configuration and flag. |
| [8011](services/8011.md) | Information Leakage (Debug Endpoint) | Easy | Enumerated API routes to discover `/debug/env` leaking environment variables and container metadata. |
| [8012](services/8012.md) | Information Leakage (Directory Listing) | Easy | Exploited enabled directory indexing on `/public/` to access unlinked `flag.txt`. |
| [8013](services/8013.md) | Information Leakage (Git Leaks) | Easy | Cloned exposed `.git` directory and inspected commit history (`git log`) to recover a removed temporary test flag. |
| [8014](services/8014.md) | Information Leakage (API Parameter Disclosure) | Medium | Fuzzed API endpoints and query parameters using `ffuf` (`/api/users/7?verbose=1`) to disclose sensitive user records. |
| [8015](services/8015.md) | Broken Authentication (IDOR / Sequential Enumeration) | Medium | Enumerated sequential user IDs on the authentication service to dump tokens and access privileged user records. |
| [8016](services/8016.md) | Information Leakage (Cryptographic Oracle) | Hard | Developed custom bash script to perform character-by-character timing/prefix brute-forcing against oracle response codes. |
| [8017](services/8017.md) | Information Leakage (robots.txt) | Easy | Checked `robots.txt` crawler rules to find the hidden `/admin-secret/` route containing the flag. |
| [8018](services/8018.md) | Information Leakage (HTML Comments) | Easy | Inspected HTML source code to find the flag directly hidden inside a comment (`<!-- FLAG: ... -->`). |
| [8019](services/8019.md) | Information Leakage (Debug Stack Trace) | Easy | Provoked an internal server error to trigger an unhandled exception stack trace revealing the hardcoded secret. |
| [8020](services/8020.md) | Broken Authentication (Credential Brute-force) | Medium | Evaluated notes login endpoint; analyzed response codes and method restrictions during authentication testing. |
| [8021](services/8021.md) | Cross-Site Scripting (Reflected XSS) | Medium | Injected script setting `xss_grant=1` cookie into search parameter to bypass access control and redirect to `/flag`. |
| [8022](services/8022.md) | Cross-Site Scripting (Stored XSS) | Medium | Injected persistent JavaScript into the bench log form to grant `xss_grant=1` cookie on page visits and unlock `/flag`. |
| [8023](services/8023.md) | Cross-Site Scripting (DOM/Reflected XSS) | Medium | Injected `<img src=x onerror="grant()">` into the `card` parameter to trigger the internal client-side `grant()` function. |
| [8024](services/8024.md) | Network Security (UDP Port Knocking) | Hard | Analyzed network service behavior and scripted a UDP port knocking sequence to unlock firewall rules and access the flag service. |
| [8030](services/8030.md) | SQL Injection (Authentication Bypass) | Easy | Bypassed staff portal login authentication using classic `' OR '1'='1` payload. |
| [8031](services/8031.md) | SQL Injection (UNION-based) | Medium | Exploited search bar SQL injection using `UNION SELECT` to dump confidential inventory items and flags. |
| [8032](services/8032.md) | SQL Injection (UNION-based) | Medium | Tested photo `id` parameter and executed `UNION SELECT` to extract rows from the `vault` table. |
| [8033](services/8033.md) | SQL Injection (Blind SQLi) | Hard | Wrote Python exploit script to extract the flag character-by-character via blind SQL injection. |
| [8034](services/8034.md) | SQL Injection (Blind / Filter Bypass) | Hard | Bypassed strict SQL keyword filters and extracted secrets character-by-character using an automated Python script on the `tag` parameter. |
| [8035](services/8035.md) | SQL Injection (Time-based Blind & Reflection) | Legendary | Built an extensive Python harness to dump the entire database schema and flag via time-delay and reflection injection channels. |
| [8036](services/8036.md) | SQL Injection / SSRF (Out-of-Band Exfiltration) | Legendary | Chained Linkly's URL preview crawler with SQL injection to exfiltrate `vault` records out-of-band to a public webhook. |
| [8037](services/8037.md) | SQL Injection (Arbitrary Table Export) | Easy | Queried the `vault` table directly with filter `1=1` in the report generator form to download `vault.csv` containing the flag. |
| [8040](services/8040.md) | Command Injection (Shell Metacharacters) | Medium | Injected shell metacharacters into network ping diagnostic utility (`ping; cat /flag/flag`) to read the flag. |
| [8041](services/8041.md) | Command Injection (Filter Bypass) | Hard | Fuzzed printer label service, discovered unescaped newline `\n` characters, and bypassed command filters to execute `cat /flag/flag`. |
| [8042](services/8042.md) | Server-Side Template Injection (SSTI) | Medium | Injected Jinja2 template payload `{{cycler.__init__.__globals__.os.popen(...)}}` into the dashboard to achieve RCE. |
| [8043](services/8043.md) | XML External Entity (XXE) | Medium | Crafted malicious XML with `<!ENTITY xxe SYSTEM "file:///flag/flag">` and imported it into the catalog to read `/flag/flag`. |
| [8044](services/8044.md) | Command Injection (Shell Chaining) | Easy | Chained arbitrary commands via semicolon in the backup filename parameter (`backup; cat /flag/flag`) to display the flag. |
| [8045](services/8045.md) | Command Injection (Code Injection / Eval) | Easy | Exploited template engine code evaluation in CardCraft to execute Node.js `fs.readFileSync('/flag/flag')`. |
| [8046](services/8046.md) | Command Injection (Subshell Command Substitution) | Medium | Substituted subshell execution `$(cat /flag/flag)` in ticket requester input to bypass character filtering and print flag in logs. |
| [8047](services/8047.md) | Command Injection / Path Normalization | Medium | Bypassed directory audit access restrictions using path normalization (`/flag/./flag`) to trigger error-based file execution and display contents. |
| [8048](services/8048.md) | Server-Side Request Forgery (SSRF) | Easy | Leveraged image preview URL parameter with `file:///flag/flag` scheme to read local flag files directly. |
| [8050](services/8050.md) | Command Injection (Parameter Injection) | Medium | Injected command delimiters into log tailing utility (`/ && cat /flag/flag`) to dump directory contents and read `/flag/flag`. |
| [8051](services/8051.md) | Broken Authentication (Insecure Deserialization) | Medium | Exploited Python pickle deserialization in workspace restore form using base64-encoded `os.popen()` payload to read the flag. |
| [8052](services/8052.md) | Command Injection (Serverless Function Execution) | Easy | Discovered and invoked pre-configured `health4` serverless function executing `head -n 20 /flag/flag`. |
| [8053](services/8053.md) | Command Injection (Argument Injection) | Hard | Fuzzed date utility with over 100 payloads, exploiting `date -f /flag/flag` to leak file contents inside the error response. |
| [8060](services/8060.md) | Broken Authentication (HTTP Basic Brute-force) | Medium | Scripted dictionary attack against HTTP Basic auth on `/admin` to discover `admin:admin123` and retrieve ISP support token. |
| [8061](services/8061.md) | Broken Authentication (Exposed Admin Token) | Easy | Inspected emergency wiki instructions to find exposed break-glass admin token. |
| [8062](services/8062.md) | Broken Authentication (IDOR / Concierge Token) | Easy | Enumerated delivery tracking records to access privileged concierge support tokens without authentication. |
| [8063](services/8063.md) | Broken Authentication (Cookie Manipulation) | Medium | Captured session cookie and modified client-side `role` value from `employee` to `manager` to access the manager approval console. |
| [8064](services/8064.md) | Broken Authentication (Unprotected Dashboard) | Easy | Used `ffuf` to discover an unauthenticated `/dashboard` endpoint exposing the advising console token. |
| [8065](services/8065.md) | Broken Authentication (Cross-Context Cookie Planting) | Hard | Planted session cookie on marketing subdomain and triggered registrar link checker to sign into advisor dashboard and extract the token. |
| [8069](services/8069.md) | Broken Authentication (Predictable Credentials) | Easy | Logged in using predictable employee credentials `pnatarajan:admin123` to access the HR admin console. |
| [8071](services/8071.md) | Broken Authentication (Base64 Credential Exposure) | Medium | Discovered base64-encoded credentials `Tytrb2lzdGIxTksy`, decoded password `O+koistb1NK2`, and logged in as administrator. |
| [8073](services/8073.md) | Broken Authentication (Session Hijacking) | Medium | Analyzed server session cookies and manipulated manager session identifier to gain unauthorized access to FernBank Online console. |
| [8081](services/8081.md) | Web Vulnerability Lab (bWAPP Environment) | Medium | Deployed and audited bWAPP testing environment across various web vulnerability modules. |
| [8084](services/8084.md) | Command Injection (WordPress Exploit / WP2shell) | Legendary | Developed Python exploit chain combining CVE-2026-63030 and CVE-2026-60137 to upload webshell plugin and achieve remote code execution. |
