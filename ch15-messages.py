#!/usr/bin/env python3
"""Lab 15a: build the IPEX messages with keripy's own functions and show how they thread together.
Uses a throwaway in-memory keystore. No witnesses needed."""
import json
from keri.app import habbing
from keri.vc import protocoling, proving
from keri.peer import exchanging

SCHEMA = "EHALeorydPBm2vL1hFAN507bs4z2AgUt0TsXDISfTlF0"
with habbing.openHby(name="ipex-demo", salt="0ACDEyMzQ1Njc4OWxtbm9aBc", temp=True) as hby:
    verifier = hby.makeHab(name="verifier")
    holder = hby.makeHab(name="holder")
    issuer = hby.makeHab(name="issuer")
    print("verifier", verifier.pre[:16] + "...  holder", holder.pre[:16] + "...  issuer", issuer.pre[:16] + "...")

    acdc = proving.credential(schema=SCHEMA, issuer=issuer.pre, recipient=holder.pre, status=issuer.pre,
                              data=dict(clinicName="Riverside Family Clinic", status="accredited"))

    def show(label, exn):
        k = exn.ked
        body = {n: k[n] for n in ("t", "r", "i", "rp", "p") if n in k and k[n] != ""}
        print(f"\n{label}\n  {k['r']}  from {k['i'][:8]}...  p={k['p'][:8] + '...' if k['p'] else '(none)'}  d={k['d'][:8]}...")
        for n, v in k["a"].items(): print(f"    a.{n}: {str(v) if len(str(v)) < 44 else str(v)[:40] + '...'}")
        if k.get("e"): print("  embeds  e:", [n for n in k["e"] if n != "d"])
        return exn

    print("\n### 1. the six messages of IPEX, as the reference implementation builds them")
    apply_, _ = protocoling.ipexApplyExn(hab=verifier, recp=holder.pre, message="Please show me an accreditation", schema=SCHEMA, attrs=["clinicName", "status"])
    show("apply  (verifier asks for a credential with these attributes)", apply_)
    offer, _ = protocoling.ipexOfferExn(hab=holder, message="I can show you this", acdc=acdc.raw, apply=apply_)
    show("offer  (holder replies with the credential's metadata, answering the apply)", offer)
    agree, _ = protocoling.ipexAgreeExn(hab=verifier, message="Yes, please send it", offer=offer)
    show("agree  (verifier accepts the offer)", agree)
    admit_stub = type("G", (), {"said": agree.said})()
    admit, _ = protocoling.ipexAdmitExn(hab=verifier, message="Received and verified", grant=admit_stub)
    show("admit  (verifier accepts; here answering a stand-in for the grant)", admit)
    spurn, _ = protocoling.ipexSpurnExn(hab=verifier, message="Not what I asked for", spurned=offer)
    show("spurn  (verifier declines, here the offer)", spurn)

    print("\n### 2. what threads them: the p field holds the SAID of the message being answered")
    chain = [("apply", apply_), ("offer", offer), ("agree", agree), ("admit", admit), ("spurn", spurn)]
    names = {m.said: n for n, m in chain}
    for n, m in chain:
        print(f"  {n:6} answers {names.get(m.ked['p'], '(nothing: it starts a conversation)')}")
