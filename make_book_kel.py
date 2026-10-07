#!/usr/bin/env python3
"""Writes the book's two KEL streams and validates them with the independent validator."""
import pathlib, bookgen as g
here = pathlib.Path(__file__).parent
aid, msgs = g.build()                                   # Chapters 3-4: no witnesses
(here / "book-kel.cesr").write_text("".join(msgs))
print("unwitnessed AID:", aid, " stream chars:", len("".join(msgs)))
g.validate("".join(msgs))
aid, msgs = g.build(witnesses=3, toad=2)                # Chapter 5: 3 witnesses, toad 2, w2 never responded
(here / "book-kel-witnessed.cesr").write_text("".join(msgs[:2]))
print("witnessed AID:  ", aid, " stream chars:", len("".join(msgs[:2])))
g.validate("".join(msgs[:2]))
