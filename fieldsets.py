"""Prints the field set of every message type that keripy enforces, for KERI v1 and ACDC v1.
Appendix C of the book is this output with the meanings added."""
import logging; logging.disable(logging.CRITICAL)
from keri.core import serdering
from keri.kering import Vrsn_1_0, Protocols

for proto in (Protocols.keri, Protocols.acdc):
    print(f"### {proto} v1")
    for ilk, fd in serdering.Serder.Fields[proto][Vrsn_1_0].items():
        opts = [k for k in fd.alls if k in fd.opts]
        alts = sorted({tuple(sorted(p)) for p in fd.alts.items()})
        line = f"  {ilk or '(none)':6} {' '.join(fd.alls)}"
        if opts: line += f"   optional: {' '.join(opts)}"
        if alts: line += f"   one of: {', '.join('/'.join(a) for a in alts)}"
        line += f"   SAIDs: {' '.join(fd.saids)}" + ("" if fd.strict else "   extras allowed")
        print(line)
