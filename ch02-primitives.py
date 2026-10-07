#!/usr/bin/env python3
"""Lab 2: reproduce every number in Chapter 2 with ~20 lines of crypto, no KERI software."""
import base64, blake3, json
import bookgen as g

sk, pub_t, aid_nt = g.keypair("signing-key-0")
msg = b"Transfer the patient's records to Dr. Chen."
tampered = b"Transfer the patient's records to Dr. Chan."

print("public key (transferable, code D) :", pub_t)
print("self-certifying identifier (code B):", aid_nt)
print()
print("BLAKE3-256 digest of message       :", g.dig(msg))
print("... one letter changed             :", g.dig(tampered))
sig = g.sign(sk, msg)
print("\nEd25519 signature (code 0B)       :", sig)
g.verify(pub_t, msg, sig); print("verify(message)   -> valid")
try: g.verify(pub_t, tampered, sig)
except Exception: print("verify(tampered)  -> INVALID (as it must be)")

print("\n--- CESR encoding of the public key, step by step ---")
raw = g.pubraw(pub_t)
print("raw key, 32 bytes        :", raw.hex())
print("pad needed (3-32%3)%3    :", (3 - 32 % 3) % 3, "byte -> 33 bytes")
print("Base64URL of 00||raw     :", g.b64(b"\x00" + raw))
print("replace pad char by code :", "D" + g.b64(b"\x00" + raw)[1:])

print("\n--- a SAID ---")
doc = {"d": "", "name": "Alice Nguyen", "role": "Nurse Practitioner"}
doc["d"] = "#" * 44
print("serialized with placeholder:", g.ser(doc).decode())
doc["d"] = g.dig(g.ser(doc)); print("with its SAID embedded     :", json.dumps(doc))
