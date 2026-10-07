#!/usr/bin/env python3
"""
cesr_describe.py: print a table of the messages in a CESR text-domain stream (stdin or a file).

For each message: type, sequence number, SAID, body size, and the attachment groups that follow it
(count code, how many items, what they are). Understands the groups used in Chapters 4-6:
  -V attachment group (length in quadlets)   -A controller indexed sigs   -B witness indexed sigs
  -C non-transferable receipt couples        -E first-seen replay couples -H trans last-est sig groups
"""
import json, re, sys

ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
NAMES = {"A": "controller sigs", "B": "witness sigs", "C": "receipt couples (witness AID + sig)",
         "E": "first-seen couples (fn + datetime)"}
ITEM = {"A": 88, "B": 88, "C": 44 + 88, "E": 24 + 36}

def _sig_group_len(att, i):
    """length of a nested '-A' indexed-signature group starting at i"""
    n = ALPHA.index(att[i + 2]) * 64 + ALPHA.index(att[i + 3]); return 4 + 88 * n

def groups(att):
    out, i = [], 0
    while i < len(att) and att[i] == "-":
        code = att[i + 1]; n = ALPHA.index(att[i + 2]) * 64 + ALPHA.index(att[i + 3]); i += 4
        if code == "V":                       # wrapper: n quadlets of nested groups
            inner = att[i:i + 4 * n]; i += 4 * n
            out.append(("V", n, "attachment group (%d chars) containing:" % len(inner)))
            out.extend(groups(inner)); continue
        if code == "F":                       # n x (AID 44 + sn 24 + est-event SAID 44 + nested -A group)
            for _ in range(n):
                aid = att[i:i + 44]; sn = att[i + 44:i + 68]; i += 44 + 24 + 44
                out.append(("F", 1, f"transferable sig group: signer {aid[:12]}... (est. event sn {int.from_bytes(__import__('base64').urlsafe_b64decode('AA' + sn[2:]), 'big')})"))
                i += _sig_group_len(att, i)
            continue
        if code == "H":                       # n x (AID 44 + nested -A group): signed with the signer's latest keys
            for _ in range(n):
                aid = att[i:i + 44]; i += 44
                out.append(("H", 1, f"last-establishment sig group: signer {aid[:12]}..."))
                i += _sig_group_len(att, i)
            continue
        size = ITEM.get(code)
        if size is None: out.append((code, n, "(unrecognized group; stopping)")); break
        out.append((code, n, NAMES[code])); i += size * n
    return out

def describe(stream):
    pos = 0; rows = []
    while pos < len(stream):
        m = re.match(r'\{"v":"KERI10JSON([0-9a-f]{6})_"', stream[pos:])
        if not m: break
        size = int(m.group(1), 16); body = json.loads(stream[pos:pos + size]); pos += size
        j = pos
        while j < len(stream) and stream[j] == "-":                 # find end of this message's attachments
            code = stream[j + 1]; n = ALPHA.index(stream[j + 2]) * 64 + ALPHA.index(stream[j + 3])
            if code == "V": j += 4 + 4 * n; continue
            if code == "F":
                j += 4
                for _ in range(n): j += 44 + 24 + 44; j += _sig_group_len(stream, j)
                continue
            if code == "H":
                j += 4
                for _ in range(n): j += 44; j += _sig_group_len(stream, j)
                continue
            j += 4 + ITEM.get(code, 0) * n
        rows.append((body, size, groups(stream[pos:j]))); pos = j
    return rows

if __name__ == "__main__":
    text = open(sys.argv[1]).read() if len(sys.argv) > 1 else sys.stdin.read()
    for body, size, gs in describe(text.strip()):
        sn = body.get("s", "-"); ident = (body.get("i") or body.get("a", {}).get("eid", "") if isinstance(body.get("a"), dict) else body.get("i", ""))[:14]
        print(f"{body['t']:4} s={sn:<2} d={body['d'][:16]}…  body={size} bytes" + (f"  route={body['r']}" if 'r' in body else ""))
        for code, n, label in gs: print(f"       -{code} x{n}: {label}")
