#!/usr/bin/env bash
# Lab 19: a verifier decides whether to let a stranger in. REQUIRES start-witnesses.sh, and Lab 18 to have been run
# first and NOT cleaned (it uses the parties gleif, qvi, le, per). Creates one more party, ver.
set -uo pipefail
. "$(dirname "$0")/lab-env.sh"; HERE="$(cd "$(dirname "$0")" && pwd)"; cd "$LAB_DIR"
PC="$LAB_PASSCODE"
curl -sf "http://127.0.0.1:5642/oobi/$WAN/controller" >/dev/null || { echo "Start ./start-witnesses.sh first."; exit 1; }
[ -d "$HOME/.keri/db/per" ] || { echo "Run ./ch18-vlei-chain.sh first (and do not clean)."; exit 1; }
V() { python3 "$HERE/ch19-verifier.py" "$@"; }
aid() { kli aid --name "$1" --alias "$1" --passcode "$PC"; }
GL=$(aid gleif); QV=$(aid qvi); LE=$(aid le); PE=$(aid per)
sid() { python3 -c "import json; print(json.load(open('vlei-schemas/$1.json'))['\$id'])"; }
OOR_S=$(sid legal-entity-official-organizational-role-vLEI-credential); OORA_S=$(sid oor-authorization-vlei-credential)
OOR=$(kli vc list --name per --alias per --passcode "$PC" --said --schema "$OOR_S" | tail -1)
AUTH=$(kli vc list --name le --alias le --passcode "$PC" --issued --said --schema "$OORA_S" | tail -1)
oobi() { kli oobi resolve --name "$1" --passcode "$PC" --oobi-alias "$2" --oobi "http://127.0.0.1:5642/oobi/$3/witness" >/dev/null 2>&1; }

echo "### 1. the verifier (ver): an ordinary witnessed party that holds the six schemas and knows the others"
kli init --name ver --passcode "$PC" >/dev/null
for w in "wan 5642 $WAN" "wil 5643 $WIL" "wes 5644 $WES"; do set -- $w
  kli oobi resolve --name ver --passcode "$PC" --oobi-alias $1 --oobi "http://127.0.0.1:$2/oobi/$3/controller" >/dev/null; done
echo "{\"transferable\": true, \"wits\": [\"$WAN\",\"$WIL\",\"$WES\"], \"toad\": 2, \"icount\": 1, \"ncount\": 1, \"isith\": \"1\", \"nsith\": \"1\"}" > ver-icp.json
kli incept --name ver --alias ver --passcode "$PC" --file ver-icp.json >/dev/null
for f in vlei-schemas/*.json; do kli vc schema import --name ver --passcode "$PC" --schema $f >/dev/null; done
VE=$(aid ver); for p in "gleif $GL" "qvi $QV" "le $LE" "per $PE"; do set -- $p; oobi ver $1 $2; oobi $1 ver $VE; done
echo "trusted root (configured in the verifier): $GL"
echo "the credential being presented: $OOR"

echo; echo "### 2. the person PRESENTS the role credential: an IPEX grant to the verifier, who admits it"
to 90 kli ipex grant --name per --alias per --passcode "$PC" --said "$OOR" --recipient "$VE" --message "Please let me in" >/dev/null 2>&1
G=$(to 90 kli ipex list --name ver --alias ver --passcode "$PC" --poll --said 2>&1 | grep -E "^E" | tail -1)
to 90 kli ipex admit --name ver --alias ver --passcode "$PC" --said "$G" --message "Received" >/dev/null 2>&1; sleep 3
echo "the verifier now holds the OOR credential, and nothing above it:"
V verify ver "$OOR" --root "$GL" | tail -4

echo; echo "### 3. the chain arrives: the issuer's full export, with the parent credentials and their proofs"
kli vc export --name qvi --alias qvi --passcode "$PC" --said "$OOR" --full > oor-full.cesr 2>/dev/null
kli vc import --name ver --passcode "$PC" --file oor-full.cesr >/dev/null 2>&1; sleep 5
echo "stream size: $(wc -c < oor-full.cesr | tr -d ' ') bytes"
V verify ver "$OOR" --root "$GL"

echo; echo "### 4. LOGIN: possession of the key. The verifier sends a fresh nonce; the person signs it"
N=$(V nonce); echo "nonce: $N"
SIG=$(V sign per per "$N"); echo "the person signs : ${SIG:0:30}..."
V prove ver "$PE" "$N" "$SIG"
echo "an impostor (the legal entity's key) signs the same nonce and claims to be the person:"
BAD=$(V sign le le "$N"); V prove ver "$PE" "$N" "$BAD"
echo "the person's signature replayed against a NEW nonce:"
V prove ver "$PE" "$(V nonce)" "$SIG"

echo; echo "### 5. the verifier's policy decides, not the credential. Same credential, three policies"
echo "(a) a different root of trust:"; V verify ver "$OOR" --root "$LE" | grep -E "FAIL|DECISION"
echo "(b) a policy that does not allow OOR credentials:"; V verify ver "$OOR" --root "$GL" --no-oor-schema | grep -E "FAIL|DECISION"
echo "(c) a policy that only accepts LEIs from its own list:"; V verify ver "$OOR" --root "$GL" --lei-registry 1234567890ABCDEFGH12 | grep -E "FAIL|DECISION"

echo; echo "### 6. the legal entity REVOKES the authorization. The verifier learns of it, and the same credential now fails"
to 90 kli vc revoke --name le --alias le --passcode "$PC" --registry-name reg-le --said "$AUTH" >/dev/null 2>&1
kli vc export --name le --alias le --passcode "$PC" --said "$AUTH" --full > auth-revoked.cesr 2>/dev/null
kli vc import --name ver --passcode "$PC" --file auth-revoked.cesr >/dev/null 2>&1; sleep 5
V verify ver "$OOR" --root "$GL" | grep -E "FAIL|DECISION"
