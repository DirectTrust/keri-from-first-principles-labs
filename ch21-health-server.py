#!/usr/bin/env python3
"""
Lab 21, the server side: Riverside Health Data Exchange, an OAuth 2.0 authorization server and a FHIR server
that authenticate organizations with KERI identifiers and vLEI-chained credentials instead of X.509 certificates.

  python3 ch21-health-server.py --port 7800 --root <trusted root AID> --oobi <this server's OOBI> --app-schema <SAID>

Endpoints (the shapes follow SMART Backend Services and UDAP. The "keri" metadata block and the KERI-based
registration are this book's design, not a published standard)
  GET  /.well-known/smart-configuration     discovery, with a "keri" block naming the server's AID and OOBI
  POST /register                            registration: a KERI-signed request carrying the app's credential chain
  POST /token                               client_credentials grant, authenticated by a KERI-signed JWT (private_key_jwt)
  GET  /fhir/Patient/<id>, /fhir/Observation?patient=<id>     FHIR reads, authorized by the access token
  POST /status                              credential status updates (registry events, which prove themselves)
"""
import argparse, json, os, secrets, tempfile, threading, time, urllib.parse
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import kerihttp as kh

STORE = ALIAS = "hdx"
LOCK = threading.Lock()
STATE = {"clients": {}, "jtis": {}}
SUPPORTED = ["system/Patient.read", "system/Observation.read", "system/Patient.write"]
ACCESS_TOKEN_LIFETIME = 600              # seconds. UDAP caps access tokens at 60 minutes
ASSERTION_MAX_LIFETIME = 300             # seconds. UDAP and SMART both cap the client assertion at 5 minutes
PARTICIPANTS = {}                        # LEI -> organization name: the network's own membership list

PATIENTS = {"p-1001": {"resourceType": "Patient", "id": "p-1001", "active": True,
                       "name": [{"family": "Rivera", "given": ["Ana"]}], "gender": "female", "birthDate": "1971-04-12"}}
OBSERVATIONS = [{"resourceType": "Observation", "id": "o-1", "status": "final", "subject": {"reference": "Patient/p-1001"},
                 "code": {"coding": [{"system": "http://loinc.org", "code": "4548-4", "display": "Hemoglobin A1c"}]},
                 "valueQuantity": {"value": 6.1, "unit": "%"}, "effectiveDateTime": "2026-09-30"}]

def titles():
    d = os.path.join(kh.LAB_DIR, "vlei-schemas"); t = {}
    for f in os.listdir(d):
        s = json.load(open(os.path.join(d, f))); t[s["$id"]] = s["title"]
    s = json.load(open(os.path.join(kh.LAB_DIR, "health-app-schema.json"))); t[s["$id"]] = s["title"]
    return t

class Server(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def send(self, code, obj, headers=None):
        raw = json.dumps(obj, indent=1).encode()
        self.send_response(code); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(raw)))
        for k, v in (headers or {}).items(): self.send_header(k, v)
        self.end_headers(); self.wfile.write(raw)

    def oauth_error(self, code, err, desc, checks):
        return self.send(code, {"error": err, "error_description": desc, "checks": checks})

    def fhir_error(self, code, desc):
        return self.send(code, {"resourceType": "OperationOutcome", "issue": [{"severity": "error", "code": "security", "diagnostics": desc}]},
                         {"WWW-Authenticate": f'Bearer error="invalid_token", error_description="{desc}"'})

    # ------------------------------------------------------------------ discovery
    def do_GET(self):
        with LOCK:
            if self.path == "/.well-known/smart-configuration":
                return self.send(200, {
                    "issuer": BASE, "token_endpoint": BASE + "/token", "registration_endpoint": BASE + "/register",
                    "grant_types_supported": ["client_credentials"], "scopes_supported": SUPPORTED,
                    "token_endpoint_auth_methods_supported": ["private_key_jwt"],
                    "token_endpoint_auth_signing_alg_values_supported": ["EdDSA"],
                    "keri": {"aid": SELF, "oobi": OOBI, "trusted_root": ROOT, "credential_schema": APP_SCHEMA}})
            if self.path.startswith("/fhir/"):
                return self.fhir()
            return self.send(404, {"error": "not found"})

    def do_POST(self):
        with LOCK:
            raw = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            if self.path == "/register": return self.register(raw)
            if self.path == "/token": return self.token(raw)
            if self.path == "/status":
                with tempfile.NamedTemporaryFile("wb", suffix=".cesr", delete=False) as f: f.write(raw)
                code, _ = kh.kli("vc", "import", "--name", STORE, "--file", f.name)
                return self.send(200, {"status": "imported" if code == 0 else "rejected"})
            return self.send(404, {"error": "not found"})

    # ------------------------------------------------------------------ registration (the KERI counterpart of UDAP DCR)
    def chain_checks(self, hby, rgy, said, client):
        """The app credential, its chain to the root, and the equalities. Returns (checks, failed, app credential)."""
        chain = kh.Chain(hby, rgy, ROOT, set(TITLES), TITLES)
        app = chain.walk(said)
        checks = [n.strip() for n in chain.notes]; failed = chain.failed
        if app is not None and not failed:
            le = chain.creds.get("Legal Entity vLEI Credential")
            for ok, text in ((app.issuee == client, "the app credential was issued to the client's identifier"),
                             (le is not None and app.attrib["LEI"] == le.attrib["LEI"], "equality: the same LEI in the app credential and the LE credential"),
                             (app.attrib["LEI"] in PARTICIPANTS, f"policy: LEI {app.attrib['LEI']} is a network participant ({PARTICIPANTS.get(app.attrib['LEI'], 'unknown')})")):
                checks.append(("ok   " if ok else "FAIL ") + text); failed = failed or not ok
        return checks, failed, app

    def register(self, raw):
        req = json.loads(raw); pre = self.headers.get("signify-resource", ""); checks = []
        code, _ = kh.kli("oobi", "resolve", "--name", STORE, "--oobi-alias", pre[:12], "--oobi", req["oobi"])
        checks.append(("ok   " if code == 0 else "FAIL ") + "resolved the client's OOBI and validated its key event log")
        with tempfile.NamedTemporaryFile("w", suffix=".cesr", delete=False) as f: f.write(req["chain"])
        code, _ = kh.kli("vc", "import", "--name", STORE, "--file", f.name)
        checks.append(("ok   " if code == 0 else "FAIL ") + "imported the presented credential chain")
        hby, rgy = kh.open_store(STORE)
        try:
            why = kh.check_signature(hby.kevers[pre], "POST", "/register", self.headers, raw)
            checks.append(("ok   " if why is None else "FAIL ") + (why or "registration request signed by the client's current key"))
            more, failed, app = self.chain_checks(hby, rgy, req["credential"], pre)
            checks += more
        finally:
            hby.close()
        if why or failed:
            return self.oauth_error(400, "invalid_client_metadata", "the credential does not establish this client", checks)
        scopes = [s for s in app.attrib["scopes"] if s in SUPPORTED]
        STATE["clients"][pre] = {"credential": req["credential"], "scopes": scopes, "name": app.attrib["appName"], "lei": app.attrib["LEI"]}
        return self.send(201, {"client_id": pre, "client_name": app.attrib["appName"], "scope": " ".join(scopes),
                               "token_endpoint_auth_method": "private_key_jwt", "checks": checks})

    # ------------------------------------------------------------------ token endpoint
    def token(self, raw):
        form = dict(urllib.parse.parse_qsl(raw.decode())); checks = []
        def c(ok, text):
            checks.append(("ok   " if ok else "FAIL ") + text); return ok
        if not (c(form.get("grant_type") == "client_credentials", "grant_type is client_credentials") and
                c(form.get("client_assertion_type") == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", "client_assertion_type is jwt-bearer")):
            return self.oauth_error(400, "invalid_request", "unsupported grant or assertion type", checks)
        try:
            header, claims, _, _ = kh.jwt_parse(form["client_assertion"])
        except Exception:
            c(False, "client_assertion is a well-formed JWT"); return self.oauth_error(400, "invalid_client", "malformed assertion", checks)
        cid = claims.get("iss"); client = STATE["clients"].get(cid)
        if not c(client is not None, f"the client {str(cid)[:12]}... is registered"):
            return self.oauth_error(401, "invalid_client", "unknown client", checks)
        now = int(time.time())
        c(claims.get("sub") == cid and header.get("kid") == cid, "iss, sub, and kid all name the client's identifier")
        c(claims.get("aud") == BASE + "/token", "aud is this token endpoint")
        c(claims.get("exp", 0) > now and claims.get("exp", 0) - claims.get("iat", 0) <= ASSERTION_MAX_LIFETIME, "the assertion is unexpired and lives at most five minutes")
        seen = STATE["jtis"].get(claims.get("jti"))
        c(seen is None, "the jti has not been used before (no replay)")
        # Refresh the client's key state before trusting it. Answers arrive through this server's mailbox and can
        # lag, so a signature that fails is retried after another refresh: a key that just rotated is never refused
        # because this server was a few seconds behind. A signature by a retired key fails every time.
        why = None
        for attempt in range(1, 4):
            code, _ = kh.kli("query", "--name", STORE, "--alias", ALIAS, "--prefix", cid)
            hby, rgy = kh.open_store(STORE)
            try:
                kever = hby.kevers[cid]; sn = kever.sn
                kh.jwt_verify(kever, form["client_assertion"]); why = None
            except ValueError as ex:
                why = str(ex)
            finally:
                hby.close()
            if why is None:
                break
        c(code == 0, f"asked the witnesses for the client's latest key state ({attempt} quer{'y' if attempt == 1 else 'ies'})")
        c(why is None, why or f"the assertion is signed by the client's current key (sequence number {sn})")
        hby, rgy = kh.open_store(STORE)
        try:
            more, failed, app = self.chain_checks(hby, rgy, client["credential"], cid)
            c(not failed, "the app credential chain is still good, every link, right now")
            if failed: checks += ["       " + m for m in more if m.startswith("FAIL")]
        finally:
            hby.close()
        if any(x.startswith("FAIL") for x in checks):
            return self.oauth_error(401, "invalid_client", "client authentication failed", checks)
        asked = form.get("scope", "").split()
        if not c(all(s in client["scopes"] for s in asked), f"the requested scopes are within the credential's: {' '.join(client['scopes'])}"):
            return self.oauth_error(400, "invalid_scope", "scope exceeds the client's credential", checks)
        STATE["jtis"][claims["jti"]] = claims["exp"]
        hby, _ = kh.open_store(STORE)
        try:
            at = kh.jwt_sign(hby.habByName(ALIAS), {"typ": "at+jwt"},
                             {"iss": BASE, "sub": cid, "aud": BASE + "/fhir", "scope": " ".join(asked), "iat": now,
                              "exp": now + ACCESS_TOKEN_LIFETIME, "jti": secrets.token_hex(12),
                              "client_name": client["name"], "lei": client["lei"]})
        finally:
            hby.close()
        return self.send(200, {"access_token": at, "token_type": "Bearer", "expires_in": ACCESS_TOKEN_LIFETIME,
                               "scope": " ".join(asked), "checks": checks})

    # ------------------------------------------------------------------ the FHIR resource server
    def fhir(self):
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return self.fhir_error(401, "no bearer token")
        hby, _ = kh.open_store(STORE)
        try:
            _, claims = kh.jwt_verify(hby.kevers[SELF], auth[7:])
        except Exception as ex:
            return self.fhir_error(401, f"token rejected: {ex}")
        finally:
            hby.close()
        if claims["exp"] < time.time() or claims["aud"] != BASE + "/fhir":
            return self.fhir_error(401, "token expired or for another audience")
        path = urllib.parse.urlparse(self.path)
        rtype = path.path.split("/")[2]
        if f"system/{rtype}.read" not in claims["scope"].split():
            return self.fhir_error(403, f"scope does not allow reading {rtype}")
        if rtype == "Patient":
            p = PATIENTS.get(path.path.split("/")[3]) if len(path.path.split("/")) > 3 else None
            return self.send(200, p) if p else self.send(404, {"resourceType": "OperationOutcome"})
        if rtype == "Observation":
            pid = urllib.parse.parse_qs(path.query).get("patient", [""])[0]
            hits = [o for o in OBSERVATIONS if o["subject"]["reference"] == f"Patient/{pid}"]
            return self.send(200, {"resourceType": "Bundle", "type": "searchset", "total": len(hits),
                                   "entry": [{"resource": o} for o in hits]})
        return self.fhir_error(404, "unknown resource type")

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, default=7800); p.add_argument("--root", required=True); p.add_argument("--oobi", required=True)
    p.add_argument("--app-schema", required=True); p.add_argument("--participant", action="append", default=[])
    a = p.parse_args()
    for x in a.participant:
        lei, name = x.split("=", 1); PARTICIPANTS[lei] = name
    BASE = f"http://127.0.0.1:{a.port}"; ROOT = a.root; OOBI = a.oobi; APP_SCHEMA = a.app_schema; TITLES = titles()
    hby, _ = kh.open_store(STORE); SELF = hby.habByName(ALIAS).pre; hby.close()
    print(f"Riverside Health Data Exchange on :{a.port}  aid {SELF}", flush=True)
    ThreadingHTTPServer(("127.0.0.1", a.port), Server).serve_forever()
