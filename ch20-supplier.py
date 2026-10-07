#!/usr/bin/env python3
"""
Lab 20, the supplier's side: Northwind Medical Supply's Order API.

  python3 ch20-supplier.py --port 7700 --root <trusted root AID>

Endpoints
  GET  /.well-known/keri        the supplier's identifier, its OOBI, and the SAIDs of the schemas it uses
  GET  /oobi/<SAID>             a data OOBI: the purchase order schema, served as application/schema+json
  POST /customers               onboarding: a signed request carrying the buyer's OOBI and its credential chain
  POST /orders                  a signed, anchored purchase order. Answers with a signed, anchored acknowledgement
  POST /status                  credential status updates (registry events). They prove themselves, so anyone may post one

Every request and response body is JSON. Every decision comes back with the list of checks that made it.
"""
import argparse, json, os, tempfile, threading
from decimal import Decimal
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import kerihttp as kh

STORE = ALIAS = "nwd"
LOCK = threading.Lock()                     # one request at a time: the keystore and kli share one database
STATE = os.path.join(kh.LAB_DIR, "supplier-state.json")
POLICY = {                                  # the supplier's own decisions, not the credential's
    "accounts": {},                         # LEI -> customer name, filled in by --account
    "roles": {"Procurement Officer": Decimal("5000.00")},   # role -> largest order it may place, in USD
}

def load_state():
    return json.load(open(STATE)) if os.path.exists(STATE) else {"customers": {}, "orders": {}}

def save_state(st):
    json.dump(st, open(STATE, "w"), indent=1)

def vlei_titles():
    d = os.path.join(kh.LAB_DIR, "vlei-schemas")
    return {json.load(open(os.path.join(d, f)))["$id"]: json.load(open(os.path.join(d, f)))["title"] for f in os.listdir(d)}

class Decision:
    def __init__(self): self.checks, self.failed = [], False
    def check(self, ok, text):
        self.checks.append(("ok   " if ok else "FAIL ") + text); self.failed = self.failed or not ok; return ok
    def add(self, notes):
        for n in notes: self.check(n.strip().startswith("ok"), n.strip()[5:] if n.strip()[:4] in ("ok  ", "FAIL") else n)

class Supplier(BaseHTTPRequestHandler):
    server_version = "NorthwindOrderAPI/1.0"

    def log_message(self, *a): pass

    # ------------------------------------------------------------ plumbing
    def body(self):
        return self.rfile.read(int(self.headers.get("Content-Length", 0)))

    def reply(self, code, obj, ctype="application/json", sign=True):
        raw = json.dumps(obj, indent=1).encode()
        headers = {}
        if sign:                                    # the supplier signs every response it makes
            hby, _ = kh.open_store(STORE)
            try:
                headers = kh.sign(hby.habByName(ALIAS), self.command, self.path, raw)
            finally:
                hby.close()
        self.send_response(code)
        self.send_header("Content-Type", ctype); self.send_header("Content-Length", str(len(raw)))
        for k, v in headers.items(): self.send_header(k, v)
        self.end_headers(); self.wfile.write(raw)

    # ------------------------------------------------------------ discovery
    def do_GET(self):
        with LOCK:
            if self.path == "/.well-known/keri":
                return self.reply(200, {"name": "Northwind Medical Supply", "aid": SELF["aid"], "oobi": SELF["oobi"],
                                        "schemas": {"PurchaseOrder": PO_SCHEMA["$id"]}})
            if self.path == f"/oobi/{PO_SCHEMA['$id']}":
                raw = json.dumps(PO_SCHEMA).encode()
                self.send_response(200); self.send_header("Content-Type", "application/schema+json")
                self.send_header("Content-Length", str(len(raw))); self.end_headers(); self.wfile.write(raw); return
            return self.reply(404, {"error": "not found"}, sign=False)

    def do_POST(self):
        with LOCK:
            raw = self.body()
            route = {"/customers": self.onboard, "/orders": self.order, "/status": self.status}.get(self.path)
            if route is None:
                return self.reply(404, {"error": "not found"}, sign=False)
            try:
                return route(raw)
            except Exception as ex:
                return self.reply(400, {"decision": "rejected", "checks": [f"FAIL malformed request: {ex}"]})

    # ------------------------------------------------------------ the signer, whoever it claims to be
    def signer(self, d, raw, oobi=None, anchor=None, anchor_said=None):
        pre = self.headers.get("signify-resource", "")
        if oobi:                                       # first contact: learn the signer's key log from its witnesses
            code, _ = kh.kli("oobi", "resolve", "--name", STORE, "--oobi-alias", pre[:12], "--oobi", oobi)
            d.check(code == 0, "resolved the signer's OOBI and validated its key event log")
        else:                                          # every later request: refresh, so a rotation is never missed
            # The witnesses answer through this supplier's own mailbox, and an answer can land after kli query
            # has stopped listening. So ask again, up to four times, until the anchoring event is here.
            # (kli query --anchor would not help: it only matches event seals {i, s, d}, and an order is sealed
            # with a digest seal {d}, so the witness would never answer. We fetch the log and look ourselves.)
            for attempt in range(1, 5):
                code, _ = kh.kli("query", "--name", STORE, "--alias", ALIAS, "--prefix", pre)
                if not anchor_said:
                    break
                hby, rgy = kh.open_store(STORE)
                found = pre in hby.kevers and kh.anchored(hby, pre, anchor_said) is not None
                hby.close()
                if found:
                    break
            d.check(code == 0, "asked the witnesses for the signer's latest key state" +
                    (f", and for the event that anchors the order ({attempt} quer{'y' if attempt == 1 else 'ies'})" if anchor else ""))
        hby, rgy = kh.open_store(STORE)
        try:
            kever = hby.kevers[pre]
        except KeyError:
            hby.close(); d.check(False, "I hold no key state for the signer"); return None, None, None
        why = kh.check_signature(kever, self.command, self.path, self.headers, raw)
        d.check(why is None, why or f"request signed by the current key of {pre[:12]}... (sequence number {kever.sn})")
        return pre, hby, rgy

    # ------------------------------------------------------------ onboarding
    def onboard(self, raw):
        d = Decision(); req = json.loads(raw)
        pre, hby, rgy = self.signer(d, raw, oobi=req["oobi"])
        if d.failed:
            if hby: hby.close()
            return self.reply(401, {"decision": "rejected", "checks": d.checks})
        hby.close()
        with tempfile.NamedTemporaryFile("w", suffix=".cesr", delete=False) as f:
            f.write(req["chain"])
        code, _ = kh.kli("vc", "import", "--name", STORE, "--file", f.name)
        d.check(code == 0, "imported the presented credential chain (credentials, registries, key logs)")
        hby, rgy = kh.open_store(STORE)
        try:
            chain = kh.Chain(hby, rgy, ROOT, set(TITLES), TITLES)
            role = chain.walk(req["credential"])
            d.add(chain.notes)
            if role is not None:
                c = chain.creds
                ecr = c.get("Legal Entity Engagement Context Role vLEI Credential")
                auth = c.get("ECR Authorization vLEI Credential")
                le = c.get("Legal Entity vLEI Credential")
                d.check(ecr is not None and auth is not None and le is not None, "the chain is ECR, ECR Authorization, Legal Entity, QVI")
                if not d.failed:
                    d.check(ecr.issuee == pre, "the role credential was issued to the signer")
                    d.check(auth.attrib["AID"] == ecr.issuee, "equality: the authorization names the same identifier")
                    d.check(auth.attrib["LEI"] == ecr.attrib["LEI"] == le.attrib["LEI"], "equality: the same LEI in all three")
                    d.check(auth.attrib["engagementContextRole"] == ecr.attrib["engagementContextRole"], "equality: the same role in the authorization and the credential")
                    lei, role_name = ecr.attrib["LEI"], ecr.attrib["engagementContextRole"]
                    d.check(lei in POLICY["accounts"], f"policy: LEI {lei} is a customer account ({POLICY['accounts'].get(lei, 'unknown')})")
                    d.check(role_name in POLICY["roles"], f"policy: the role '{role_name}' may place orders")
        finally:
            hby.close()
        if d.failed:
            return self.reply(403, {"decision": "rejected", "checks": d.checks})
        st = load_state()
        st["customers"][pre] = {"lei": lei, "name": ecr.attrib["personLegalName"], "role": role_name, "credential": req["credential"]}
        save_state(st)
        return self.reply(200, {"decision": "onboarded", "customer": st["customers"][pre], "checks": d.checks})

    # ------------------------------------------------------------ orders
    def order(self, raw):
        d = Decision(); po = json.loads(raw)
        st = load_state(); pre = self.headers.get("signify-resource", "")
        cust = st["customers"].get(pre)
        if not d.check(cust is not None, "the signer is an onboarded customer"):
            return self.reply(403, {"decision": "rejected", "checks": d.checks})
        # 1. the document itself: its shape, its name, and its arithmetic
        why = kh.schema_check(PO_SCHEMA, po)
        d.check(why is None, why or f"matches the purchase order schema {PO_SCHEMA['$id'][:12]}...")
        d.check(kh.said_ok(po), "the purchase order's SAID matches its content")
        total = sum(Decimal(l["unitPrice"]) * l["qty"] for l in po.get("lines", []))
        d.check(Decimal(po.get("total", "0")) == total, f"the total is the sum of the lines ({total})")
        d.check(po.get("supplier") == SELF["aid"], "the order is addressed to this supplier")
        fresh = d.check(po.get("d") not in st["orders"], "the order has not been seen before (no replay)")
        if d.failed:
            return self.reply(409 if not fresh else 400, {"decision": "rejected", "checks": d.checks})
        # 2. the signer: fresh key state, a valid signature, and the order anchored in the signer's own log
        pre2, hby, rgy = self.signer(d, raw, anchor=True, anchor_said=po["d"])
        if hby is None:
            return self.reply(401, {"decision": "rejected", "checks": d.checks})
        try:
            d.check(po["buyer"]["aid"] == pre, "the signer is the buyer named in the order")
            sn = kh.anchored(hby, pre, po["d"])
            d.check(sn is not None, f"the order's SAID is sealed in the buyer's key log" + (f" at sequence number {sn}" if sn is not None else ""))
            # 3. authority, checked again now, because status can change after onboarding
            chain = kh.Chain(hby, rgy, ROOT, set(TITLES), TITLES)
            chain.walk(cust["credential"])
            ok = not chain.failed
            d.check(ok, "the buyer's role credential chain is still good, every link, right now")
            if not ok:
                d.checks += ["       " + n.strip() for n in chain.notes if "FAIL" in n]
            d.check(po["buyer"]["credential"] == cust["credential"], "the order cites the credential presented at onboarding")
            d.check(po["buyer"]["lei"] == cust["lei"], "the order's LEI is the customer's LEI")
            limit = POLICY["roles"].get(cust["role"], Decimal("0"))
            d.check(total <= limit, f"policy: {total} is within the {limit} limit for a {cust['role']}")
        finally:
            hby.close()
        if d.failed:
            return self.reply(403, {"decision": "rejected", "checks": d.checks})
        # 4. accept: a SAID-named acknowledgement, anchored in the supplier's own log, in a signed response
        ack = kh.saidify({"d": "", "type": "OrderAcknowledgement", "po": po["d"], "number": po["number"],
                          "supplier": SELF["aid"], "dt": kh.helping.nowIso8601(), "status": "accepted", "total": str(total)})
        code, _ = kh.kli("interact", "--name", STORE, "--alias", ALIAS, "--data", json.dumps([{"d": ack["d"]}]))
        d.check(code == 0, "the acknowledgement's SAID is sealed in the supplier's own key log")
        st["orders"][po["d"]] = {"number": po["number"], "buyer": pre, "ack": ack["d"]}
        save_state(st)
        return self.reply(201, {"decision": "accepted", "acknowledgement": ack, "checks": d.checks})

    # ------------------------------------------------------------ status updates
    def status(self, raw):
        with tempfile.NamedTemporaryFile("wb", suffix=".cesr", delete=False) as f:
            f.write(raw)
        code, _ = kh.kli("vc", "import", "--name", STORE, "--file", f.name)
        return self.reply(200 if code == 0 else 400, {"decision": "imported" if code == 0 else "rejected",
                          "checks": ["ok   registry events imported. They are anchored in the issuer's key log, so they prove themselves"]})

def po_schema():
    S = {"type": "string"}
    line = {"type": "object", "additionalProperties": False, "required": ["sku", "description", "qty", "unitPrice"],
            "properties": {"sku": S, "description": S, "qty": {"type": "integer", "minimum": 1},
                           "unitPrice": {"type": "string", "pattern": "^[0-9]+\\.[0-9]{2}$"}}}
    return kh.saidify({
        "$id": "", "$schema": "http://json-schema.org/draft-07/schema#",
        "title": "Purchase Order", "description": "An order for goods, signed by an authorized officer of the buyer.",
        "type": "object", "version": "1.0.0",
        "properties": {
            "d": {"description": "SAID of this purchase order", "type": "string"},
            "type": {"const": "PurchaseOrder"},
            "number": S, "dt": {"type": "string", "format": "date-time"},
            "buyer": {"type": "object", "additionalProperties": False, "required": ["aid", "lei", "credential"],
                      "properties": {"aid": S, "lei": {"type": "string", "pattern": "^[0-9A-Z]{18}[0-9]{2}$"},
                                     "credential": {"description": "SAID of the buyer's role credential", "type": "string"}}},
            "supplier": {"description": "the supplier's AID", "type": "string"},
            "currency": {"enum": ["USD"]},
            "lines": {"type": "array", "minItems": 1, "items": line},
            "total": {"type": "string", "pattern": "^[0-9]+\\.[0-9]{2}$"}},
        "required": ["d", "type", "number", "dt", "buyer", "supplier", "currency", "lines", "total"],
        "additionalProperties": False}, label="$id")

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, default=7700); p.add_argument("--root", required=True)
    p.add_argument("--oobi", required=True); p.add_argument("--account", action="append", default=[])
    a = p.parse_args()
    for acct in a.account:
        lei, name = acct.split("=", 1); POLICY["accounts"][lei] = name
    ROOT = a.root; TITLES = vlei_titles(); PO_SCHEMA = po_schema()
    hby, _ = kh.open_store(STORE); SELF = {"aid": hby.habByName(ALIAS).pre, "oobi": a.oobi}; hby.close()
    if os.path.exists(STATE): os.remove(STATE)
    print(f"Northwind Order API on :{a.port}  aid {SELF['aid']}  PO schema {PO_SCHEMA['$id']}", flush=True)
    ThreadingHTTPServer(("127.0.0.1", a.port), Supplier).serve_forever()
