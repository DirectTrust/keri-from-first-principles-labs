#!/usr/bin/env python3
"""Lab 19: a small vLEI verifier, written with keripy's own libraries.

  ch19-verifier.py verify <store> <oor-said> --root <aid> [--no-oor-schema] [--lei-registry LEI,LEI]
        walks the chain from a presented OOR credential to the root, and checks every link and every equality
  ch19-verifier.py nonce
        prints a fresh challenge
  ch19-verifier.py sign <store> <alias> <nonce>
        the person's side of a login: signs the nonce with the identifier's current key
  ch19-verifier.py prove <store> <aid> <nonce> <signature>
        the verifier's side: checks that signature against the key state it holds for that AID
"""
import argparse, json, os, secrets, sys
from keri.app import habbing
from keri.core import coring
from keri.vdr import credentialing

PC = os.environ["LAB_PASSCODE"]
SCHEMAS = os.path.join(os.environ.get("LAB_DIR", "."), "vlei-schemas")

def load_titles():
    out = {}
    for f in os.listdir(SCHEMAS):
        d = json.load(open(os.path.join(SCHEMAS, f))); out[d["$id"]] = d["title"]
    return out

def lei_ok(lei):
    if len(lei) != 20 or not lei.isalnum() or lei != lei.upper(): return False
    return int("".join(str(int(c, 36)) for c in lei)) % 97 == 1

class Verifier:
    def __init__(self, name):
        self.hby = habbing.Habery(name=name, base="", bran=PC, temp=False)
        self.rgy = credentialing.Regery(hby=self.hby, name=name, base="")
        self.reger = self.rgy.reger
        self.titles = load_titles()
        self.lines = []; self.failed = False

    def close(self): self.hby.close()

    def note(self, ok, text):
        self.lines.append(("  ok   " if ok else "  FAIL ") + text)
        if not ok: self.failed = True
        return ok

    def get(self, said):
        c = self.reger.creds.get(keys=said)
        if c is None: return None, None
        st = self.reger.cloneCreds([coring.Saider(qb64=said)], self.hby.db)[0]["status"]["et"]
        return c, {"iss": "issued", "bis": "issued", "rev": "REVOKED", "brv": "REVOKED"}.get(st, st)

    def link(self, said, label, want_schema, depth=0):
        pad = "  " * depth
        c, status = self.get(said)
        if c is None:
            self.note(False, f"{pad}{label}: credential {said[:10]}... is not held, so the chain cannot be followed")
            return None
        title = self.titles.get(c.schema, c.schema[:10] + "...")
        self.note(c.schema == want_schema, f"{pad}{label}: schema is {title}" + ("" if c.schema == want_schema else f", expected {self.titles.get(want_schema, want_schema)}"))
        self.note(c.schema in self.titles and c.schema in self.allowed, f"{pad}{label}: schema is on the verifier's allowed list")
        self.note(status == "issued", f"{pad}{label}: status in the issuer's registry is {status}")
        return c

    def verify(self, oor_said, root, require_oor_schema=True, lei_registry=None):
        by_title = {v: k for k, v in self.titles.items()}
        S = {k: by_title[t] for k, t in (("qvi", "Qualified vLEI Issuer Credential"), ("le", "Legal Entity vLEI Credential"),
             ("oora", "OOR Authorization vLEI Credential"), ("oor", "Legal Entity Official Organizational Role vLEI Credential"))}
        self.allowed = set(S.values()) if require_oor_schema else {S["qvi"], S["le"], S["oora"]}
        oor = self.link(oor_said, "OOR credential", S["oor"])
        if oor is None: return False
        e = oor.edge or {}
        if "auth" not in e: return self.note(False, "OOR credential has no auth edge")
        auth = self.link(e["auth"]["n"], "  authorization", S["oora"], 1)
        if auth is None: return False
        self.note(e["auth"]["s"] == S["oora"], "  the OOR's edge pins the OOR Authorization schema")
        self.note(e["auth"].get("o") == "I2I", f"  edge operator is {e['auth'].get('o')}, must be I2I")
        self.note(oor.issuer == auth.issuee, "  I2I: the OOR's issuer is the authorization's issuee (the QVI the entity named)")
        le = self.link(auth.edge["le"]["n"], "    legal entity credential", S["le"], 2) if auth.edge and "le" in auth.edge else None
        if le is None: return self.note(False, "authorization has no usable le edge")
        self.note(auth.issuer == le.issuee, "    the authorization was issued by the legal entity the LE credential names")
        qvi = self.link(le.edge["qvi"]["n"], "      QVI credential", S["qvi"], 3) if le.edge and "qvi" in le.edge else None
        if qvi is None: return self.note(False, "legal entity credential has no usable qvi edge")
        self.note(le.issuer == qvi.issuee, "      the LE credential was issued by the QVI that the QVI credential names")
        self.note(qvi.issuer == root, f"      the QVI credential was issued by the trusted root ({root[:10]}...)")
        a_oor, a_auth, a_le = oor.attrib, auth.attrib, le.attrib
        self.note(a_auth["AID"] == a_oor["i"], "equality: the authorization's AID is the OOR's issuee")
        self.note(a_auth["LEI"] == a_oor["LEI"] == a_le["LEI"], "equality: the same LEI in the OOR, the authorization, and the LE credential")
        self.note(a_auth["personLegalName"] == a_oor["personLegalName"], "equality: the same person name in the authorization and the OOR")
        self.note(a_auth["officialRole"] == a_oor["officialRole"], "equality: the same role in the authorization and the OOR")
        self.note(lei_ok(a_oor["LEI"]), f"the LEI {a_oor['LEI']} has valid check digits")
        if lei_registry is not None:
            self.note(a_oor["LEI"] in lei_registry, "the LEI is in the verifier's own LEI list")
        self.person = a_oor["i"]; self.role = a_oor["officialRole"]; self.name = a_oor["personLegalName"]; self.lei = a_oor["LEI"]
        return not self.failed

def main():
    p = argparse.ArgumentParser(); sub = p.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("verify"); v.add_argument("store"); v.add_argument("said"); v.add_argument("--root", required=True)
    v.add_argument("--no-oor-schema", action="store_true"); v.add_argument("--lei-registry", default=None)
    sub.add_parser("nonce")
    s = sub.add_parser("sign"); s.add_argument("store"); s.add_argument("alias"); s.add_argument("nonce")
    r = sub.add_parser("prove"); r.add_argument("store"); r.add_argument("aid"); r.add_argument("nonce"); r.add_argument("signature")
    a = p.parse_args()
    if a.cmd == "nonce":
        print(secrets.token_hex(16)); return 0
    if a.cmd == "sign":
        hby = habbing.Habery(name=a.store, base="", bran=PC, temp=False); hab = hby.habByName(a.alias)
        sig = hab.sign(ser=a.nonce.encode(), indexed=False)[0]; print(sig.qb64); hby.close(); return 0
    if a.cmd == "prove":
        hby = habbing.Habery(name=a.store, base="", bran=PC, temp=False)
        try: kever = hby.kevers[a.aid]          # note: .get() does not load key state lazily, [] does
        except KeyError: print("  FAIL I hold no key state for", a.aid[:12] + "..."); return 1
        cig = coring.Cigar(qb64=a.signature, verfer=kever.verfers[0])
        ok = kever.verfers[0].verify(sig=cig.raw, ser=a.nonce.encode())
        print(("  ok   " if ok else "  FAIL ") + f"the signature over the nonce {'verifies' if ok else 'does NOT verify'} against the current key of {a.aid[:12]}...")
        hby.close(); return 0 if ok else 1
    ver = Verifier(a.store)
    ok = ver.verify(a.said, a.root, require_oor_schema=not a.no_oor_schema,
                    lei_registry=set(a.lei_registry.split(",")) if a.lei_registry else None)
    print("\n".join(ver.lines))
    print(f"\nDECISION: {'ACCEPT' if ok else 'REJECT'}" + (f"   {ver.name}, {ver.role}, LEI {ver.lei}, identifier {ver.person[:12]}..." if ok else ""))
    ver.close(); return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())
