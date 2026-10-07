"""
bookgen.py: the code that generated every worked example in the book.

It implements, from scratch and with only `cryptography` and `blake3`:
  * CESR text-domain encoding of keys, digests, signatures, indexed signatures, count codes
  * SAID computation (dummy placeholder -> digest -> embed)
  * the key events in the book (icp / rot / ixn), signed, as a CESR stream
  * an independent validator that parses that stream and checks every rule in Chapters 3-5

All keys derive from PUBLISHED seed strings. They are for learning only.
"""
import base64, hashlib, json, re
import blake3
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

def b64(b): return base64.urlsafe_b64encode(b).decode()

def qual(code, raw):
    """CESR text domain: pre-pad with zero bytes to a 24-bit boundary, then replace the pad characters by the code."""
    ps = (3 - len(raw) % 3) % 3
    return code + b64(b"\x00" * ps + raw)[ps:]

def unqual_raw(q, ps):
    """Inverse for a primitive whose code is ps characters long (ps == pad bytes)."""
    return base64.urlsafe_b64decode("A" * ps + q[ps:])[ps:]

def keypair(label):
    seed = hashlib.sha256(b"KERI-PRIMER-DEMO-ONLY:" + label.encode()).digest()
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    pub = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return sk, qual("D", pub), qual("B", pub)      # (signer, transferable key, non-transferable AID)

def dig(data): return qual("E", blake3.blake3(data).digest())          # BLAKE3-256 digest, CESR code E
def sign(sk, data): return qual("0B", sk.sign(data))                   # plain Ed25519 signature, code 0B
def isig(sk, data, i):                                                  # indexed signature, code A + index char
    return "A" + ALPHA[i] + b64(b"\x00\x00" + sk.sign(data))[2:]
def count(code, n): return "-" + code + ALPHA[n // 64] + ALPHA[n % 64]  # count code, e.g. count("A", 1) == "-AAB"
def ser(d): return json.dumps(d, separators=(",", ":")).encode()
def version(size): return "KERI10JSON%06x_" % size

def saidify(d, labels=("d",)):
    """Fill the dummy placeholder in every label, serialize, digest, write the digest back in."""
    for l in labels: d[l] = "#" * 44
    d["v"] = version(0); d["v"] = version(len(ser(d)))
    said = dig(ser(d))
    for l in labels: d[l] = said
    return ser(d)

def pubraw(q): return unqual_raw(q, 1)

def verify(pubq, raw, sig):
    """Verify a plain (0B) or indexed (A?) signature (both are 88 characters)."""
    s = base64.urlsafe_b64decode("AA" + sig[2:])[2:]
    Ed25519PublicKey.from_public_bytes(pubraw(pubq)).verify(s, raw)

# ----------------------------------------------------------------------------------------------
def build(witnesses=0, toad=0, receipted=(0, 1)):
    """Alice's three-event log. witnesses=3, toad=2 gives the witnessed variant of Chapter 5."""
    k0, k0q, _ = keypair("signing-key-0"); k1, k1q, _ = keypair("signing-key-1"); k2, k2q, _ = keypair("signing-key-2")
    W = [keypair(f"witness-{i}") for i in range(witnesses)]
    wid = [w[2] for w in W]; wsk = [w[0] for w in W]
    icp = {"v": "", "t": "icp", "d": "", "i": "", "s": "0", "kt": "1", "k": [k0q], "nt": "1",
           "n": [dig(k1q.encode())], "bt": str(toad), "b": wid, "c": [], "a": []}
    r_icp = saidify(icp, ("d", "i")); aid = icp["i"]
    rot = {"v": "", "t": "rot", "d": "", "i": aid, "s": "1", "p": icp["d"], "kt": "1", "k": [k1q], "nt": "1",
           "n": [dig(k2q.encode())], "bt": str(toad), "br": [], "ba": [], "a": []}     # note: no "c" in a rotation
    r_rot = saidify(rot)
    ixn = {"v": "", "t": "ixn", "d": "", "i": aid, "s": "2", "p": rot["d"], "a": [{"d": dig(b"example document body")}]}
    r_ixn = saidify(ixn)
    msgs = []
    for raw, k, evs in ((r_icp, k0, True), (r_rot, k1, True), (r_ixn, k1, False)):
        m = raw.decode() + count("A", 1) + isig(k, raw, 0)
        if witnesses and evs:
            m += count("B", len(receipted)) + "".join(isig(wsk[i], raw, i) for i in receipted)
        msgs.append(m)
    return aid, msgs

ATT = {"A": 88, "B": 88}     # item sizes (characters) for the attachment groups used in the book

def parse(stream):
    pos = 0; out = []
    while pos < len(stream):
        m = re.match(r'\{"v":"KERI10JSON([0-9a-f]{6})_"', stream[pos:])
        size = int(m.group(1), 16); body = stream[pos:pos + size]; pos += size; atts = {}
        while pos < len(stream) and stream[pos] == "-":
            code = stream[pos + 1]; n = ALPHA.index(stream[pos + 2]) * 64 + ALPHA.index(stream[pos + 3]); pos += 4
            atts[code] = [stream[pos + 88 * j: pos + 88 * (j + 1)] for j in range(n)]; pos += 88 * n
        out.append((body, json.loads(body), atts))
    return out

def validate(stream, say=print):
    """Independent validator: structure, SAID, chain, pre-rotation, signature threshold, witness threshold."""
    prev = None
    for body, ev, att in parse(stream):
        raw = body.encode(); chk = json.loads(body); chk["d"] = "#" * 44
        if ev["t"] == "icp": chk["i"] = "#" * 44
        assert dig(ser(chk)) == ev["d"], "SAID mismatch"
        if ev["t"] == "icp":
            assert ev["s"] == "0" and ev["i"] == ev["d"]
            keys, kt, wits, toad = ev["k"], int(ev["kt"], 16), ev["b"], int(ev["bt"])
        else:
            assert int(ev["s"], 16) == prev["s"] + 1 and ev["p"] == prev["d"], "chain"
            keys, kt, wits, toad = prev["k"], prev["kt"], prev["b"], prev["bt"]
            if ev["t"] == "rot":
                assert any(dig(k.encode()) == prev["n"][0] for k in ev["k"]), "pre-rotation commitment"
                keys, kt = ev["k"], int(ev["kt"], 16)
        good = 0
        for sg in att["A"]:
            verify(keys[ALPHA.index(sg[1])], raw, sg); good += 1       # raises if invalid
        assert good >= kt, "signing threshold"
        w = 0
        for sg in att.get("B", []):
            verify(wits[ALPHA.index(sg[1])], raw, sg); w += 1
        assert w >= toad, "witness threshold"
        say(f"event {ev['s']} {ev['t']}: OK  controller sigs={good}  witness receipts={w} (toad {toad})")
        prev = {"d": ev["d"], "s": int(ev["s"], 16), "k": keys, "kt": kt, "b": wits, "bt": toad,
                "n": ev["n"] if "n" in ev else prev["n"]}
    return True


# ----------------------------------------------------------------------------------------------
# Reply messages and transferable signature groups (Chapters 5 and 7)
def number128(n):
    """CESR 128-bit number primitive (code 0A): 24 text characters."""
    return "0A" + b64(b"\x00\x00" + n.to_bytes(16, "big"))[2:]

def reply(route, attrs, dt):
    """A KERI reply message (rpy) with its SAID."""
    r = {"v": "", "t": "rpy", "d": "", "dt": dt, "r": route, "a": attrs}
    return saidify(r)

def trans_group(aid, sn, est_said, sk, raw, index=0):
    """-F group: signer AID, sequence number and SAID of the establishment event whose keys signed, then indexed sigs."""
    return count("F", 1) + aid + number128(sn) + est_said + count("A", 1) + isig(sk, raw, index)
