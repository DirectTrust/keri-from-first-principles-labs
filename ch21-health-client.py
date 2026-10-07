#!/usr/bin/env python3
"""
Lab 21, the client side: Acme Health's care-coordination backend, a confidential OAuth client whose
identity is a KERI identifier and whose authority is a credential chained to Acme's vLEI.

  ch21-health-client.py discover  <base> <store>
  ch21-health-client.py register  <base> <store> <credential SAID>
  ch21-health-client.py assertion <base> <store> <file>               write a client assertion JWT to a file, for later
  ch21-health-client.py token     <base> <store> <scope>... [--assertion <file>] [--save <file>]
  ch21-health-client.py read      <base> <path> --token <file> [--forge-scope <scope>]
"""
import argparse, json, secrets, time, urllib.parse, urllib.request, urllib.error
import kerihttp as kh

def http(method, url, body=None, headers=None):
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=180) as r: return r.status, r.read()
    except urllib.error.HTTPError as e: return e.code, e.read()

def config(base):
    return json.loads(http("GET", base + "/.well-known/smart-configuration")[1])

def discover(base, store):
    cfg = config(base)
    print("GET /.well-known/smart-configuration")
    for k in ("token_endpoint", "registration_endpoint", "grant_types_supported", "token_endpoint_auth_methods_supported",
              "token_endpoint_auth_signing_alg_values_supported", "scopes_supported", "keri"):
        print(f"  {k}: {json.dumps(cfg[k])}")
    code, _ = kh.kli("oobi", "resolve", "--name", store, "--oobi-alias", "hdx", "--oobi", cfg["keri"]["oobi"])
    print(f"resolved the server's OOBI and validated its key event log: {code == 0}")

def register(base, store, credential):
    _, chain = kh.kli("vc", "export", "--name", store, "--alias", store, "--said", credential, "--full")
    hby, _ = kh.open_store(store); hab = hby.habByName(store)
    body = json.dumps({"oobi": f"http://127.0.0.1:5642/oobi/{hab.pre}/witness", "credential": credential, "chain": chain}).encode()
    headers = dict(kh.sign(hab, "POST", "/register", body), **{"Content-Type": "application/json"}); hby.close()
    status, rb = http("POST", base + "/register", body, headers); obj = json.loads(rb)
    print(f"HTTP {status}  client_id {obj.get('client_id', '-')}  scope: {obj.get('scope', obj.get('error'))}")
    for c in obj.get("checks", []): print("   ", c)

def assertion(base, store):
    hby, _ = kh.open_store(store); hab = hby.habByName(store); now = int(time.time())
    jwt = kh.jwt_sign(hab, {"typ": "JWT"}, {"iss": hab.pre, "sub": hab.pre, "aud": config(base)["token_endpoint"],
                                            "iat": now, "exp": now + 300, "jti": secrets.token_hex(16)})
    sn = hby.kevers[hab.pre].sn; hby.close()
    return jwt, sn

def token(base, store, scopes, assertion_file=None, save=None):
    if assertion_file:
        jwt = open(assertion_file).read().strip(); print(f"using the assertion saved in {assertion_file.split('/')[-1]}")
    else:
        jwt, sn = assertion(base, store); print(f"a fresh client assertion, signed with the key from sequence number {sn}")
    h, c, _, _ = kh.jwt_parse(jwt)
    print(f"  header {json.dumps(h)}"); print(f"  claims iss=sub={c['iss'][:12]}...  aud={c['aud']}  lifetime={c['exp'] - c['iat']}s  jti={c['jti'][:8]}...")
    form = urllib.parse.urlencode({"grant_type": "client_credentials", "scope": " ".join(scopes),
                                   "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                                   "client_assertion": jwt}).encode()
    status, rb = http("POST", config(base)["token_endpoint"], form, {"Content-Type": "application/x-www-form-urlencoded"})
    obj = json.loads(rb)
    print(f"HTTP {status}  " + (f"access token issued, scope '{obj['scope']}', expires in {obj['expires_in']}s" if status == 200
                                 else f"error {obj.get('error')}: {obj.get('error_description')}"))
    for x in obj.get("checks", []): print("   ", x)
    if status == 200:
        h2, c2, _, _ = kh.jwt_parse(obj["access_token"])
        print(f"  access token header {json.dumps(h2)}")
        print(f"  access token claims {json.dumps({k: c2[k] for k in ('iss', 'sub', 'aud', 'scope', 'client_name', 'lei')})}")
        if save: open(save, "w").write(obj["access_token"])
    if assertion_file is None and save:
        open(save + ".assertion", "w").write(jwt)

def read(base, path, token_file, forge=None):
    tok = open(token_file).read().strip()
    if forge:                                      # change a claim, keep the old signature
        h, c, _, _ = kh.jwt_parse(tok); c["scope"] += " " + forge
        parts = tok.split("."); parts[1] = kh._b64u(json.dumps(c, separators=(",", ":")).encode()); tok = ".".join(parts)
        print(f"FORGED: '{forge}' added to the token's scope, original signature kept")
    status, rb = http("GET", base + path, None, {"Authorization": "Bearer " + tok, "Accept": "application/fhir+json"})
    obj = json.loads(rb)
    if status == 200 and obj["resourceType"] == "Patient":
        print(f"GET {path} -> {status} Patient {obj['id']}: {obj['name'][0]['given'][0]} {obj['name'][0]['family']}, born {obj['birthDate']}")
    elif status == 200 and obj["resourceType"] == "Bundle":
        for e in obj["entry"]:
            o = e["resource"]; print(f"GET {path} -> {status} Bundle, {obj['total']} Observation: {o['code']['coding'][0]['display']} {o['valueQuantity']['value']}{o['valueQuantity']['unit']}")
    else:
        print(f"GET {path} -> {status} {obj['resourceType']}: {obj['issue'][0]['diagnostics']}")

if __name__ == "__main__":
    p = argparse.ArgumentParser(); s = p.add_subparsers(dest="cmd", required=True)
    for n in ("discover", "register", "assertion", "token"):
        x = s.add_parser(n); x.add_argument("base"); x.add_argument("store")
        if n == "register": x.add_argument("credential")
        if n == "assertion": x.add_argument("file")
        if n == "token": x.add_argument("scopes", nargs="+"); x.add_argument("--assertion"); x.add_argument("--save")
    r = s.add_parser("read"); r.add_argument("base"); r.add_argument("path"); r.add_argument("--token", required=True); r.add_argument("--forge-scope")
    a = p.parse_args()
    if a.cmd == "discover": discover(a.base, a.store)
    elif a.cmd == "register": register(a.base, a.store, a.credential)
    elif a.cmd == "assertion":
        jwt, sn = assertion(a.base, a.store); open(a.file, "w").write(jwt); print(f"assertion signed with the key from sequence number {sn}, saved for later")
    elif a.cmd == "token": token(a.base, a.store, a.scopes, a.assertion, a.save)
    else: read(a.base, a.path, a.token, a.forge_scope)
