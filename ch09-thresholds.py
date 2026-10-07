#!/usr/bin/env python3
"""Lab 9a: evaluate weighted signing thresholds with keripy's own Tholder.
Each digit in the output is a position in the event's `k` list, which is what an indexed signature (-A) carries."""
import textwrap
from itertools import combinations
from keri.core.coring import Tholder

def show(title, sith, n):
    t = Tholder(sith=sith)
    print(f"\n{title}\n  sith = {sith}\n  stored as: {t.sith}")
    ok = [c for r in range(1, n + 1) for c in combinations(range(n), r) if t.satisfy(list(c))]
    minimal = [c for c in ok if not any(set(o) < set(c) for o in ok)]
    print("  smallest satisfying sets:", " ".join("".join(map(str, c)) for c in minimal))

show("simple 2-of-3 (a bare number)", "2", 3)
show("same idea, written as weights", ["1/2", "1/2", "1/2"], 3)
show("a board: chair and director count double", ["1/2", "1/2", "1/4", "1/4"], 4)
show("two clauses, BOTH must pass: any 2 of officers 0-2, AND counsel 3 or 4",
     [["1/2", "1/2", "1/2"], ["1", "1"]], 5)
print("\nA near miss: weights that can never reach 1 are rejected at construction:")
try:
    Tholder(sith=["1/3", "1/3"])
except Exception as e:
    print(textwrap.fill(f"{type(e).__name__}: {e}", width=78, initial_indent="  ", subsequent_indent="    "))
