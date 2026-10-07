#!/usr/bin/env python3
"""
Lab 20, the buyer's side: Acme Health's procurement software, acting for one officer's identifier.

  ch20-buyer.py discover <url> <store>                 learn the supplier's identifier and fetch its order schema
  ch20-buyer.py onboard  <url> <store> <credential>    present the officer's role credential and its chain
  ch20-buyer.py order    <url> <store> <number> <sku:qty:price>... [--no-anchor] [--tamper] [--replay]
"""
import argparse, json, os, sys, urllib.request, urllib.error
from decimal import Decimal
import kerihttp as kh

LAST = os.path.join(kh.LAB_DIR, "last-order-request.json")
CATALOG = {"GLV-NITRILE-M": "Nitrile exam gloves, medium, box of 100", "MSK-SURG-L3": "Surgical masks, level 3, box of 50",
           "SYR-3ML": "Syringe, 3 ml, luer lock, box of 100"}

def http(method, url, body=b"", headers=None):
    req = urllib.request.Request(url, data=body if method != "GET" else None, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=180) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()

def show(status, body, verified):
    obj = json.loads(body)
    print(f"HTTP {status}  decision: {obj.get('decision')}   response signed by the supplier: {verified}")
    for c in obj.get("checks", []): print("   ", c)
    return obj

def supplier_signed(store, sup_aid, method, path, headers, body):
    hby, _ = kh.open_store(store)
    try:
        why = kh.check_signature(hby.kevers[sup_aid], method, path, headers, body)
    finally:
        hby.close()
    return "yes" if why is None else f"NO, {why}"

def well_known(url):
    return json.loads(http("GET", url + "/.well-known/keri")[2])

def discover(url, store):
    wk = well_known(url)
    print(f"supplier: {wk['name']}  aid {wk['aid']}")
    code, _ = kh.kli("oobi", "resolve", "--name", store, "--oobi-alias", "northwind", "--oobi", wk["oobi"])
    print(f"resolved its OOBI and validated its key event log: {code == 0}")
    sid = wk["schemas"]["PurchaseOrder"]
    code, _ = kh.kli("oobi", "resolve", "--name", store, "--oobi-alias", "po-schema", "--oobi", f"{url}/oobi/{sid}")
    hby, _ = kh.open_store(store)
    try:
        schemer = hby.db.schema.get(keys=(sid,))
        print(f"fetched the purchase order schema by data OOBI: {sid}")
        print(f"  stored only after its SAID was recomputed from its content: {schemer is not None and schemer.said == sid}")
    finally:
        hby.close()

def onboard(url, store, credential):
    wk = well_known(url)
    hby, _ = kh.open_store(store); hab = hby.habByName(store); pre = hab.pre; hby.close()
    _, chain = kh.kli("vc", "export", "--name", store, "--alias", store, "--said", credential, "--full")
    oobi = f"http://127.0.0.1:5642/oobi/{pre}/witness"
    body = json.dumps({"oobi": oobi, "credential": credential, "chain": chain}).encode()
    hby, _ = kh.open_store(store); headers = kh.sign(hby.habByName(store), "POST", "/customers", body); hby.close()
    print(f"presenting credential {credential[:12]}... and a chain of {len(chain)} characters")
    status, rh, rb = http("POST", url + "/customers", body, dict(headers, **{"Content-Type": "application/json"}))
    show(status, rb, supplier_signed(store, wk["aid"], "POST", "/customers", rh, rb))

def order(url, store, number, items, credential, lei, no_anchor=False, tamper=False, replay=False):
    wk = well_known(url)
    if replay:
        saved = json.load(open(LAST)); body = saved["body"].encode(); headers = saved["headers"]
        print(f"replaying the request for {json.loads(body)['number']}, byte for byte, signature and all")
    else:
        lines = []
        for it in items:
            sku, qty, price = it.split(":")
            lines.append({"sku": sku, "description": CATALOG[sku], "qty": int(qty), "unitPrice": price})
        total = sum(Decimal(l["unitPrice"]) * l["qty"] for l in lines)
        hby, _ = kh.open_store(store); pre = hby.habByName(store).pre
        po = kh.saidify({"d": "", "type": "PurchaseOrder", "number": number, "dt": kh.helping.nowIso8601(),
                         "buyer": {"aid": pre, "lei": lei, "credential": credential}, "supplier": wk["aid"],
                         "currency": "USD", "lines": lines, "total": f"{total:.2f}"})
        schema = hby.db.schema.get(keys=(wk["schemas"]["PurchaseOrder"],)).sed
        hby.close()
        why = kh.schema_check(schema, po)
        print(f"{number}: {len(lines)} line(s), total {total:.2f} USD, SAID {po['d']}")
        print(f"  checked against the supplier's schema before sending: {'valid' if why is None else why}")
        if not no_anchor:
            code, _ = kh.kli("interact", "--name", store, "--alias", store, "--data", json.dumps([{"d": po["d"]}]))
            print(f"  anchored the order's SAID in the officer's key log, witnessed: {code == 0}")
        else:
            print("  NOT anchored in the officer's key log")
        body = json.dumps(po).encode()
        hby, _ = kh.open_store(store); headers = kh.sign(hby.habByName(store), "POST", "/orders", body); hby.close()
        headers["Content-Type"] = "application/json"
        json.dump({"body": body.decode(), "headers": headers}, open(LAST, "w"))
        if tamper:     # a careful man in the middle: changes the quantity, then fixes the total, the SAID, and the digest
            po2 = json.loads(body); po2["lines"][0]["qty"] *= 10
            po2["total"] = f"{sum(Decimal(l['unitPrice']) * l['qty'] for l in po2['lines']):.2f}"
            po2 = kh.saidify(po2); body = json.dumps(po2).encode(); headers["content-digest"] = kh.content_digest(body)
            print("  IN TRANSIT: quantity multiplied by 10, and the total, the SAID, and the content-digest all recomputed to match")
    status, rh, rb = http("POST", url + "/orders", body, headers)
    obj = show(status, rb, supplier_signed(store, wk["aid"], "POST", "/orders", rh, rb))
    ack = obj.get("acknowledgement")
    if ack:
        print(f"  acknowledgement {ack['d'][:12]}... names this order: {ack['po'] == json.loads(body)['d']}   its SAID checks: {kh.said_ok(ack)}")

if __name__ == "__main__":
    p = argparse.ArgumentParser(); sub = p.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("discover"); d.add_argument("url"); d.add_argument("store")
    o = sub.add_parser("onboard"); o.add_argument("url"); o.add_argument("store"); o.add_argument("credential")
    r = sub.add_parser("order"); r.add_argument("url"); r.add_argument("store"); r.add_argument("number")
    r.add_argument("items", nargs="*"); r.add_argument("--credential", required=True); r.add_argument("--lei", required=True)
    r.add_argument("--no-anchor", action="store_true"); r.add_argument("--tamper", action="store_true"); r.add_argument("--replay", action="store_true")
    a = p.parse_args()
    if a.cmd == "discover": discover(a.url, a.store)
    elif a.cmd == "onboard": onboard(a.url, a.store, a.credential)
    else: order(a.url, a.store, a.number, a.items, a.credential, a.lei, a.no_anchor, a.tamper, a.replay)
