#!/usr/bin/env python3
"""Lab 23: a battery of attacks on a key event log, run against the book's independent validator.
Offline, no witnesses. Each attack says what the attacker did and what the validator did about it.
The last three rows are the interesting ones: things a single-log validator CANNOT catch."""
import copy, json
import bookgen as g

aid, wmsgs = g.build(witnesses=3, toad=2, receipted=(0, 1))     # inception and rotation, each receipted by 2 of 3 witnesses
msgs = wmsgs[:2]; good = "".join(msgs)
def run(stream):
    try:
        g.validate(stream, say=lambda *_: None); return "ACCEPTED"
    except AssertionError as e: return f"rejected: {e}"
    except KeyError: return "rejected: a required attachment is missing"
    except TypeError: return "rejected: out of order, there is no prior event"
    except Exception as e: return f"rejected: {type(e).__name__}"

def flip(s, where, old, new):
    i = s.index(where) + where.index(old); return s[:i] + new + s[i + len(old):]

print("the honest log, with witness receipts:", run(good), "\n")
rows = []
rows.append(("1. change one field of the inception after signing", run(flip(good, '"bt":"2"', "2", "1"))))
mk = lambda label: g.keypair(label)
atk, atkq, _ = mk("attacker-key")
ev0 = g.parse(good)[0][0].encode()
forged = msgs[0].replace(msgs[0][len(ev0) + 4:len(ev0) + 4 + 88], g.isig(atk, ev0, 0), 1)
rows.append(("2. replace the controller's signature with the attacker's", run(forged + msgs[1])))
rows.append(("3. strip the signatures from the rotation", run(msgs[0] + msgs[1][:len(g.parse(msgs[1])[0][0])])))
rows.append(("4. deliver the events out of order (rotation before inception)", run(msgs[1] + msgs[0])))
# 5. a rotation to a key that was never committed
rot = json.loads(g.parse(good)[1][0]); rot["k"] = [atkq]; rot["d"] = ""
r = g.saidify(rot); bad_rot = r.decode() + g.count("A", 1) + g.isig(atk, r, 0)
rows.append(("5. rotate to a key the log never committed to (a thief without the next key)", run(msgs[0] + bad_rot)))
# 6. too few witness receipts
_, thin = g.build(witnesses=3, toad=2, receipted=(0,))
rows.append(("6. present an event with one witness receipt when two are required", run("".join(thin[:2]))))
# 7. receipts from a key that is not a designated witness
fake = msgs[0].replace(msgs[0][-88:], g.isig(atk, ev0, 1), 1)
rows.append(("7. swap a witness receipt for one signed by a stranger", run(fake + msgs[1])))
for label, result in rows: print(f"{label}\n     -> {result}")

print("\nthree things a single-log validator CANNOT see (an unwitnessed three-event log, for simplicity):")
_, um = g.build(); ugood = "".join(um)
print("8. a stale but valid log: the thief withholds the last event")
print("     ->", run(um[0] + um[1]), "   (Chapter 6: freshness needs a watcher or a query)")
# 9. a fork: two different, individually valid interaction events at the same sn
k1, _, _ = g.keypair("signing-key-1")
ixn = json.loads(g.parse(ugood)[2][0]); ixn["a"] = [{"d": g.dig(b"a document the controller never approved")}]; ixn["d"] = ""
r = g.saidify(ixn); fork = r.decode() + g.count("A", 1) + g.isig(k1, r, 0)
print("9. a fork at sequence number 2: the controller (or a thief) signs a second, different event")
print("     the real log   ->", run(ugood))
print("     the forked log ->", run(um[0] + um[1] + fork), "   (each is valid alone; only comparing them shows duplicity, Chapter 6)")
print("10. a valid log for an identifier nobody has any reason to trust")
print("     ->", run(ugood), "   (a log proves control. It says nothing about who the controller is. Chapters 12 to 19)")
