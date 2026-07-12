#!/usr/bin/env bash
set -u
cd /tmp/app-7
export PATH="$HOME/.local/bin:$HOME/.nvm/versions/node/v22.23.1/bin:$HOME/.deno/bin:$HOME/.bun/bin:$PATH"
PY=python3.11
export CAPDEL_HOME=/tmp/capdel7
B=http://127.0.0.1:4571

# 1) root fs cap "workspace root"
OUT=$($PY capdel.py mint fs --root /tmp/capdel7-root --ops list,read,write --ttl 1h --name "workspace root")
A=$(echo "$OUT" | sed -n 's/^id=//p'); ATOK=$(echo "$OUT" | sed -n 's/^token=//p')
echo "root A=$A tok=$ATOK"
echo "$A" > /tmp/capdel7-A.id; echo "$ATOK" > /tmp/capdel7-A.tok

# 2) attenuate A -> "docs-reviewer" (read under refs)
BRES=$(curl -s -H "Authorization: Bearer $ATOK" -d '{"constraints":{"root":"/tmp/capdel7-root/refs","ops":["list","read"]},"name":"docs-reviewer","ttl_s":3600}' $B/caps/$A/attenuate)
echo "attenuate B: $BRES"
BB=$(echo "$BRES" | $PY -c 'import sys,json;print(json.load(sys.stdin)["id"])')
BTOK=$(echo "$BRES" | $PY -c 'import sys,json;print(json.load(sys.stdin)["token"])')
echo "$BB" > /tmp/capdel7-B.id; echo "$BTOK" > /tmp/capdel7-B.tok

# 3) escalate from B (add write)
ESC=$(curl -s -H "Authorization: Bearer $BTOK" -d '{"want":{"root":"/tmp/capdel7-root/refs","ops":["list","read","write"]},"reason":"need to write summary"}' $B/caps/$BB/escalate)
echo "escalate: $ESC"
REQ=$(echo "$ESC" | $PY -c 'import sys,json;print(json.load(sys.stdin)["request_id"])')
echo "$REQ" > /tmp/capdel7-REQ.id

# 4) approve -> fresh owner root with escalation provenance
$PY capdel.py approve "$REQ" --ttl 1h

# 5) a revoked subtree for visual parity (downloads scan + child) -> mint root, revoke
OUT2=$($PY capdel.py mint fs --root /tmp/capdel7-root --ops read --ttl 1h --name "downloads scan")
D=$(echo "$OUT2" | sed -n 's/^id=//p'); DTOK=$(echo "$OUT2" | sed -n 's/^token=//p')
curl -s -H "Authorization: Bearer $DTOK" -d '{"constraints":{"root":"/tmp/capdel7-root/refs/pdfs","ops":["read"]},"name":"temp-scan worker","ttl_s":3600}' $B/caps/$D/attenuate >/dev/null
$PY capdel.py revoke "$D"
echo "revoked D=$D"

# 6) short-TTL cap to exercise clear-expired (expires in 3s)
OUT3=$($PY capdel.py mint fs --root /tmp/capdel7-root --ops list --ttl 3s --name "temp-quick")
E=$(echo "$OUT3" | sed -n 's/^id=//p')
echo "$E" > /tmp/capdel7-E.id
echo "short-ttl E=$E (expires ~3s)"

echo "--- /_tree via owner secret (direct) ---"
curl -s -H "Authorization: Bearer owner-secret" $B/_tree | $PY -m json.tool
