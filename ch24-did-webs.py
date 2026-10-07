#!/usr/bin/env python3
"""Lab 24: a did:webs-style publish and resolve, with keripy's own verification.

  ch24-did-webs.py make    <keystore> <alias> <webroot> <host:port> <path>
        exports the identifier's KERI event stream to keri.cesr and writes a did.json beside it
  ch24-did-webs.py resolve <did:webs:...>
        fetches both files, VERIFIES the event stream, and checks the DID document against the key state it proves

The DID document layout is my reading of the did:webs specification (v0.10.x). Check it against the current text."""
import base64, json, os, subprocess, sys, urllib.parse, urllib.request
from keri.app import habbing
from keri.core import coring, eventing, parsing

PC = os.environ.get("LAB_PASSCODE", "")

def key_state(stream):
    """Replay a CESR event stream into a throwaway keystore. Returns {aid: Kever} for what verifies."""
    with habbing.openHby(name="resolver", temp=True) as hby:
        kvy = eventing.Kevery(db=hby.db, lax=True, local=False)
        parsing.Parser(kvy=kvy).parse(ims=bytearray(stream))
        return {pre: (k.sn, [v.qb64 for v in k.verfers]) for pre, k in kvy.kevers.items()}

def jwk(qb64):                      # an Ed25519 public key as a JWK: x is the raw 32 bytes, base64url without padding
    raw = coring.Verfer(qb64=qb64).raw
    return {"kty": "OKP", "crv": "Ed25519", "x": base64.urlsafe_b64encode(raw).decode().rstrip("=")}

def make(store, alias, webroot, hostport, path):
    out = subprocess.run(["kli", "export", "--name", store, "--alias", alias, "--passcode", PC], capture_output=True, check=True).stdout
    aid = subprocess.run(["kli", "aid", "--name", store, "--alias", alias, "--passcode", PC], capture_output=True, text=True, check=True).stdout.strip()
    ks = key_state(out)
    sn, keys = ks[aid]
    did = f"did:webs:{urllib.parse.quote(hostport, safe='')}:{path.replace('/', ':')}:{aid}"
    doc = {"id": did, "verificationMethod": [{"id": f"#{keys[0]}", "type": "JsonWebKey", "controller": did, "publicKeyJwk": jwk(keys[0])}],
           "authentication": [f"#{keys[0]}"], "assertionMethod": [f"#{keys[0]}"]}
    d = os.path.join(webroot, path, aid); os.makedirs(d, exist_ok=True)
    open(os.path.join(d, "keri.cesr"), "wb").write(out); json.dump(doc, open(os.path.join(d, "did.json"), "w"), indent=2)
    print("DID      :", did); print("key state: sn", sn, "current key", keys[0][:20] + "...")
    print("wrote    :", os.path.join(path, aid, "did.json"), f"({os.path.getsize(os.path.join(d, 'did.json'))} bytes)", "and keri.cesr", f"({len(out)} bytes)")

def resolve(did):
    parts = did.split(":")
    assert parts[:2] == ["did", "webs"], "not a did:webs identifier"
    host, path, aid = urllib.parse.unquote(parts[2]), parts[3:-1], parts[-1]
    base = f"http://{host}/" + "/".join(path + [aid]) + "/"
    print("resolving", did[:40] + "...", "\n  fetch", base + "did.json", "\n  fetch", base + "keri.cesr")
    doc = json.loads(urllib.request.urlopen(base + "did.json", timeout=10).read())
    stream = urllib.request.urlopen(base + "keri.cesr", timeout=10).read()
    state = key_state(stream)
    if aid not in state:
        print("  FAIL the event stream does not establish", aid[:12] + "...: it did not verify"); return 1
    sn, keys = state[aid]
    print(f"  ok   the event stream verifies: sn {sn}, current key {keys[0][:16]}...")
    ok = urllib.parse.unquote(doc.get("id", "")).lower() == urllib.parse.unquote(did).lower().replace(aid.lower(), aid.lower())   # percent-encoding case is not significant
    print(("  ok   " if ok else "  FAIL ") + "the DID document names this DID")
    claimed = [v["publicKeyJwk"]["x"] for v in doc.get("verificationMethod", [])]
    proven = jwk(keys[0])["x"]
    match = proven in claimed
    print(("  ok   " if match else "  FAIL ") + "the key in the DID document is the key the KERI log proves is current")
    print("RESOLVED" if ok and match else "REJECTED"); return 0 if ok and match else 1

if __name__ == "__main__":
    if sys.argv[1] == "make": make(*sys.argv[2:7])
    else: sys.exit(resolve(sys.argv[2]))
