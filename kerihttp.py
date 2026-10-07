"""
kerihttp.py: shared by Labs 20 and 21.

  * signing and verifying HTTP requests and responses with a KERI identifier, using keripy's own
    Signature-Input and Signature header helpers (the same pattern KERIA uses for Signify clients)
  * SAID-named JSON documents and their JSON Schemas
  * a generic walker that follows a credential's edges up to a trusted root and checks every link
  * small wrappers around kli, for the operations a service delegates to it

Everything here is lab code: clear rather than fast, and single-key identifiers only.
"""
import base64, hashlib, json, logging, os, subprocess
logging.disable(logging.CRITICAL)                       # keripy logs every rejection; the labs print their own reasons
from keri.app import habbing
from keri.core import coring, scheming, serdering
from keri.end import ending
from keri.help import helping
from keri.vdr import credentialing

PC = os.environ.get("LAB_PASSCODE", "")
LAB_DIR = os.environ.get("LAB_DIR", ".")
SIGNED_FIELDS = ["@method", "@path", "content-digest", "signify-resource", "signify-timestamp"]
MAX_SKEW = 300                                          # seconds a signed request may be early or late

# ------------------------------------------------------------------ stores
def open_store(name):
    """Open a keystore and its credential registry. Services open per request and close afterwards,
    so that kli, run as a separate process, always sees the latest state and never finds the store busy."""
    hby = habbing.Habery(name=name, base="", bran=PC, temp=False)
    rgy = credentialing.Regery(hby=hby, name=name, base="")
    return hby, rgy

def kli(*args, timeout=90):
    env = dict(os.environ)
    if env.get("LIBSODIUM_LIB"):
        env["DYLD_FALLBACK_LIBRARY_PATH"] = env["LIBSODIUM_LIB"]
    r = subprocess.run(["kli", *args, "--passcode", PC], capture_output=True, text=True, timeout=timeout, env=env)
    return r.returncode, (r.stdout + r.stderr).strip()

# ------------------------------------------------------------------ SAID-named documents
def saidify(doc, label="d"):
    _, out = coring.Saider.saidify(sad=dict(doc, **{label: ""}), label=label)
    return out

def said_ok(doc, label="d"):
    try:
        return coring.Saider(qb64=doc[label]).verify(sad=dict(doc), prefixed=True, label=label)
    except Exception:
        return False

def schema_check(schema, doc):
    """Return None if doc matches the JSON Schema, else the first line of the reason."""
    try:
        scheming.Schemer(sed=schema).verify(json.dumps(doc).encode())
        return None
    except Exception as ex:
        return str(ex).splitlines()[0].replace("Credential validation exception: ", "")

# ------------------------------------------------------------------ HTTP signatures
def content_digest(body):
    return "sha-256=:" + base64.b64encode(hashlib.sha256(body).digest()).decode() + ":"

def sign(hab, method, path, body=b""):
    """Headers that bind this identifier's current key to the method, the path, and the exact body."""
    headers = {"signify-resource": hab.pre, "signify-timestamp": helping.nowIso8601(),
               "content-digest": content_digest(body)}
    siginput, cigar = ending.siginput("signify", method, path, headers, SIGNED_FIELDS, hab=hab,
                                      alg="ed25519", keyid=hab.pre)
    sig = ending.signature([ending.Signage(markers=dict(signify=cigar), indexed=False, signer=None,
                                           ordinal=None, digest=None, kind=None)])
    headers.update({k.lower(): v for k, v in siginput.items()})
    headers.update({k.lower(): v for k, v in sig.items()})
    return headers

def _signature_base(inp, method, path, headers):
    """Rebuild, byte for byte, the string that ending.siginput signed."""
    items = []
    for f in inp.fields:
        if f == "@method":
            items.append(f'"{f}": {method}')
        elif f == "@path":
            items.append(f'"{f}": {path}')
        else:
            items.append(f'"{f}": {headers[f].strip()}')
    params = [f"({' '.join(inp.fields)})", f"created={inp.created}"]
    for k in ("expires", "nonce", "keyid", "context", "alg"):
        v = getattr(inp, k)
        if v is not None:
            params.append(f"{k}={v}")
    items.append(f'"@signature-params: {";".join(params)}"')
    return "\n".join(items).encode("utf-8")

def check_signature(kever, method, path, headers, body):
    """Return None if the request was signed by kever's CURRENT key, else the reason it fails."""
    h = {k.lower(): v for k, v in headers.items()}
    for need in ("signature-input", "signature", "signify-resource", "signify-timestamp", "content-digest"):
        if need not in h:
            return f"missing header {need}"
    if h["signify-resource"] != kever.prefixer.qb64:
        return "signify-resource names a different identifier"
    if h["content-digest"] != content_digest(body):
        return "the body does not match its content-digest (changed in transit)"
    inputs = [i for i in ending.desiginput(h["signature-input"].encode()) if i.name == "signify"]   # http_sfv parses bytes, not str
    if not inputs:
        return "no signify signature input"
    inp = inputs[0]
    if any(f not in inp.fields for f in SIGNED_FIELDS):
        return "the signature does not cover every required field"
    age = abs(helping.nowUTC().timestamp() - helping.fromIso8601(h["signify-timestamp"]).timestamp())
    if age > MAX_SKEW:
        return f"signify-timestamp is {int(age)} seconds from now"
    cigar = ending.designature(h["signature"])[0].markers["signify"]
    ok = kever.verfers[0].verify(sig=cigar.raw, ser=_signature_base(inp, method, path, h))
    return None if ok else "the signature does not verify against the signer's current key"

# ------------------------------------------------------------------ key logs
def anchored(hby, pre, said):
    """True if some event in pre's key log carries a digest seal of said."""
    for msg in hby.db.clonePreIter(pre=pre):
        srdr = serdering.SerderKERI(raw=bytearray(msg))
        for seal in srdr.ked.get("a", []) or []:
            if isinstance(seal, dict) and seal.get("d") == said:
                return srdr.sn
    return None

# ------------------------------------------------------------------ credential chains
STATUS = {"iss": "issued", "bis": "issued", "rev": "REVOKED", "brv": "REVOKED"}

def credential(hby, rgy, said):
    c = rgy.reger.creds.get(keys=said)
    if c is None:
        return None, None
    et = rgy.reger.cloneCreds([coring.Saider(qb64=said)], hby.db)[0]["status"]["et"]
    return c, STATUS.get(et, et)

class Chain:
    """Follows a credential's edges up to a credential issued by the trusted root, checking every link."""
    def __init__(self, hby, rgy, root, allowed, titles):
        self.hby, self.rgy, self.root, self.allowed, self.titles = hby, rgy, root, allowed, titles
        self.notes, self.failed, self.creds = [], False, {}

    def note(self, ok, text):
        self.notes.append(("  ok   " if ok else "  FAIL ") + text)
        self.failed = self.failed or not ok
        return ok

    def walk(self, said, depth=0):
        pad = "  " * depth
        c, status = credential(self.hby, self.rgy, said)
        if c is None:
            self.note(False, f"{pad}credential {said[:12]}... is not held")
            return None
        name = self.titles.get(c.schema, c.schema[:12] + "...")
        self.creds[name] = c
        self.note(c.schema in self.allowed, f"{pad}{name}: schema on the allowed list")
        self.note(status == "issued", f"{pad}{name}: status {status}")
        edges = {k: v for k, v in (c.edge or {}).items() if k != "d"}
        if not edges:
            self.note(c.issuer == self.root, f"{pad}{name}: issued by the trusted root")
            return c
        for label, e in edges.items():
            parent = self.walk(e["n"], depth + 1)
            if parent is None:
                return None
            self.note(parent.schema == e["s"], f"{pad}{name}: edge '{label}' points at the schema it pins")
            if e.get("o", "I2I") != "NI2I":
                self.note(c.issuer == parent.issuee,
                          f"{pad}{name}: issued by the party its '{label}' parent was issued to")
        return c

# ------------------------------------------------------------------ JWTs signed by a KERI identifier (RFC 7515, alg EdDSA per RFC 8037)
def _b64u(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def _unb64u(s): return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def jwt_sign(hab, header, claims):
    """A compact JWS whose key is named by the identifier in kid: the verifier gets the key from the KEL, not from a JWKS or a certificate."""
    h = dict(header, alg="EdDSA", kid=hab.pre)
    signing_input = f"{_b64u(json.dumps(h, separators=(',', ':')).encode())}.{_b64u(json.dumps(claims, separators=(',', ':')).encode())}"
    cigar = hab.sign(ser=signing_input.encode(), indexed=False)[0]
    return f"{signing_input}.{_b64u(cigar.raw)}"

def jwt_parse(token):
    h, c, s = token.split(".")
    return json.loads(_unb64u(h)), json.loads(_unb64u(c)), f"{h}.{c}".encode(), _unb64u(s)

def jwt_verify(kever, token):
    """Return (header, claims) if the JWT was signed by kever's CURRENT key, else raise ValueError with the reason."""
    header, claims, signing_input, sig = jwt_parse(token)
    if header.get("alg") != "EdDSA":
        raise ValueError(f"alg {header.get('alg')} is not EdDSA")
    if header.get("kid") != kever.prefixer.qb64:
        raise ValueError("kid names a different identifier")
    if not kever.verfers[0].verify(sig=sig, ser=signing_input):
        raise ValueError("the signature does not verify against the current key of " + header["kid"][:12] + "...")
    return header, claims
