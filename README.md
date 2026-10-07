# Labs for *KERI from First Principles*

Hands-on labs that go with the book *KERI from First Principles*, Chapters 2 to 24. Every command and output shown in the book comes from
these scripts, run against `keripy` 1.3.6 and real, locally running witnesses. The book's Appendix A is the full lab guide, and this README is its short form.

## Setup

Requirements: Python 3.12+, `git`, `curl`, and **libsodium** (macOS `brew install libsodium`;
Debian/Ubuntu `apt install libsodium-dev`).

```bash
git clone https://github.com/DirectTrust/keri-from-first-principles-labs.git
cd keri-from-first-principles-labs
./lab-setup.sh            # virtualenv + keri==1.3.6 + keripy's demo configuration (in ./lab-run)
```

Everything the labs create is under `./lab-run` (the labs point `HOME` there, so `~/.keri` is
never touched). Delete `lab-run` to remove it all.

If Python cannot find libsodium, set `export LIBSODIUM_LIB=<directory containing libsodium.dylib/.so>`
before running a lab (macOS Homebrew on Apple Silicon: `/opt/homebrew/lib`).

## Running

| Lab | Chapter | Run | Needs witnesses |
|-----|---------|-----|-----------------|
| 2 | Primitives, CESR, SAIDs by hand | `python3 ch02-primitives.py` then `./ch02-said.sh` | no |
| 3 | A live key event log | `./ch03-kel.sh` | no |
| 3b | `EO`, 2-of-3, non-transferable identifiers | `./ch03-variants.sh` | no |
| 3c | Tamper with one character | `./ch03-tamper.sh` (after `ch03-kel.sh`) | no |
| 3d | The schema of a key event | `python3 ch03-schema.py` | no |
| 4 | Wire format, database, import the book's log | `./ch04-wire-and-storage.sh` (after `ch03-kel.sh`) | no |
| 4b | Events that arrive early | `./ch04-arrivals.sh` | no |
| 5 | A witnessed identifier | `./ch05-witnesses.sh` | **yes** |
| 5b | What the software enforces about `bt` | `./ch05-threshold-rules.sh` | **yes** |
| 6 | Staleness, duplicity, recovery | `./ch06-duplicity.sh` | **yes** |
| 7a | Build every message type (`qry`, `rpy`, `exn`, `/fwd`) | `python3 ch07-messages.py` | no |
| 7b | BADA: which signed reply wins | `python3 ch07-bada.py` | no |
| 7c | OOBIs, contacts, a mailbox, challenge-response | `./ch07-discovery-and-mail.sh` | **yes** |
| 8a-c | Salts, hand-derived keys, restore from a salt, key store at rest | `./ch08-keys.sh` | no |
| 8d | An edge client (Signify) and a cloud agent (KERIA) | `./ch08-agent.sh` | needs KERIA |
| 9a | Weighted and clause thresholds, evaluated by `keripy` | `python3 ch09-thresholds.py` | no |
| 9b | Three people, one group identifier: inception, interaction, partial rotation, removal | `./ch09-multisig.sh` | **yes** |
| 10 | A delegate asks for permission, waits, and is approved | `./ch10-delegation.sh` | **yes** |
| 11 | A thief wins the race; an identifier abandons itself | `./ch11-compromise.sh` | **yes** |
| 12a | Build a schema and an ACDC by hand; tamper with it | `python3 ch12-acdc.py` | no |
| 12b | Issue a real credential with a registry; export the proof | `./ch12-issue.sh` | **yes** |
| 13 | Issue, check, revoke, check again; a registry with backers | `./ch13-registry.sh` | **yes** |
| 14a | Guess a digest, add a salt, disclose a block at a time | `python3 ch14-disclosure.py` | no |
| 14b | A chain of authority: regulator, accreditor, clinic | `./ch14-chain.sh` | **yes** |
| 15a | Build the IPEX messages and see how they thread | `python3 ch15-messages.py` | no |
| 15b | Grant, admit, present, spurn, over real mailboxes | `./ch15-ipex.sh` | **yes** |
| 16a | Compute and test an LEI's check digits | `python3 ch16-lei.py` | no |
| 16b | Download GLEIF's vLEI schemas and verify them | `python3 ch16-vlei-schemas.py` | no (needs network) |
| 17 | A small QVI ceremony: two GARs, two QARs, one delegation | `./ch17-qvi-ceremony.sh` | **yes** (about 10 minutes) |
| 18 | The whole vLEI chain with GLEIF's real schemas | `./ch18-vlei-chain.sh` | **yes** (about 15 minutes) |
| 19 | A small verifier: chain, equalities, login, policy, revocation | `./ch19-login.sh` (run Lab 18 first, do not clean) | **yes** |
| 20 | A purchase order: buyer and supplier services, signed and anchored orders | `./ch20-purchase-order.sh` (after Lab 18) | **yes** |
| 21 | OAuth 2.0 and FHIR with a KERI identifier and a vLEI-chained credential | `./ch21-oauth-fhir.sh` (after Lab 18) | **yes** |
| 22 | Three witnesses of your own, a failure drill, and a restore | `./ch22-failure-drill.sh` | no (starts its own on HTTP ports 6642-6644) |
| 23 | A battery of attacks on a key event log | `python3 ch23-attacks.py` | no |
| 24 | Publish and resolve a KERI identifier the did:webs way | `./ch24-did-webs.sh` | no |

For the labs that need witnesses, run this in a **separate terminal** and leave it running:

```bash
./start-witnesses.sh      # three demo witnesses: HTTP 5642-5644, TCP 5632-5634
```

Lab 8d needs a KERIA agent and its own virtualenv (KERIA 0.4.0 pins `keripy` 1.2.12; the labs use 1.3.6):

```bash
./lab-setup.sh agent      # once: also creates ./lab-run/venv-agent with keria and signifypy
./start-keria.sh          # in its own terminal: admin 3901, KERI 3902, boot 3903
```

Reset the lab identities between runs (witnesses are left alone):

```bash
./lab-clean.sh
```

## Files

| File | Purpose |
|------|---------|
| `lab-env.sh` | Sourced by every script: isolates `HOME`, activates the virtualenv, defines the demo witness AIDs |
| `lab-setup.sh` | One-time setup (`agent` argument also installs KERIA and SignifyPy) |
| `lab-clean.sh` | Resets lab identities |
| `start-witnesses.sh` | Runs keripy's three demo witnesses in the foreground |
| `start-keria.sh` | Runs a KERIA cloud agent in the foreground (Lab 8d) |
| `bookgen.py` | The code behind every hand-built example in the book: CESR encoding, SAIDs, signed events, and an independent validator |
| `make_book_kel.py` | Builds and validates the book's logs; writes `book-kel.cesr` and `book-kel-witnessed.cesr` |
| `cesr_describe.py` | Prints the structure of any CESR text-domain stream (messages and attachment groups) |
| `ch04-inspect-db.py` | Opens a `keripy` LMDB event database read-only and shows the rows for one identifier |
| `ch08-inspect-keystore.py`, `ch08-derive.py` | Open a key store read-only; derive an identifier's keys by hand from a salt |
| `ch09-exns.py` | Lists the `/multisig/*` exchange messages stored in a member's database |

## Troubleshooting

| Symptom | Cause and fix |
|---------|---------------|
| `Unable to find libsodium` | Install libsodium and set `LIBSODIUM_LIB`. On macOS, `DYLD_*` variables are dropped when a command is launched through a system tool (for example `nohup` or `/usr/bin/env`), so set it in the same script that runs `kli`. |
| `ERR: AID already exists with that name` | The lab was already run. `./lab-clean.sh`. |
| `Keystore must already exist` | Run the earlier lab in the sequence (for example `ch03-kel.sh` before `ch04-...`). |
| `Start ./start-witnesses.sh first.` | Labs 5, 5b, 6 and 7c need the witnesses running in another terminal. |
| `Start ./start-keria.sh first.` | Lab 8d needs the KERIA agent running; install it with `./lab-setup.sh agent`. |
| `agent does not exist for controller ...` | A Signify client with a passcode (or tier) that never booted this agent. Expected for a wrong passcode. |
| `kli challenge verify` never returns | It polls the mailbox until it finds a response to *those* words. With wrong words it keeps polling: Ctrl-C. |
| `kli import` never returns | The input ends in the middle of a message; the importer is waiting for the rest. Ctrl-C. |
| `kli oobi resolve ... resolved` but nothing changes | `keripy` caches resolved OOBIs. Use a different witness's URL to force a fresh fetch. |
| Identifiers differ from the book | Expected: each key store draws a random salt. |

## Caution

The passcode in `lab-env.sh` is public. The labs are for learning. Never use it, or any key from
this book, for anything real.
