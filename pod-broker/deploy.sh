#!/usr/bin/env bash
# Deploy the capdel BROKER itself to the oauth3 pod as a deno source tarball (dev mode).
# Minting / attenuation / enforcement run INSIDE the attested pod; the audit log lives in
# the TEE. The one secret travels only in the manifest env, never committed:
#   CAPDEL_OWNER_SECRET — the single owner gate (POST /_mint, /_tree, /_audit, /_event, /_gc).
#   CAPDEL_POP=off|allow|require (optional; default off).
#
# Deploying to the attested pod is an OPERATOR step — the classifier blocks the assistant
# from prod-deploy, so run this yourself:
#   CAPDEL_OWNER_SECRET=some-long-secret [CAPDEL_POP=require] bash deploy.sh
set -euo pipefail
export PATH="$HOME/.deno/bin:$PATH"   # so the bundle's `deno check` resolves
CVM="${CVM:-https://pod.dstack.soc1024.com}"
DIR="$(cd "$(dirname "$0")" && pwd)"
TEE_DAEMON_TOKEN="${TEE_DAEMON_TOKEN:-$(grep -E '^TEE_DAEMON_TOKEN=' "$HOME/projects/hermes-agent/deploy-notes/.env.prod9" 2>/dev/null | cut -d= -f2- || true)}"
: "${TEE_DAEMON_TOKEN:?no daemon token (set TEE_DAEMON_TOKEN or populate .env.prod9)}"
: "${CAPDEL_OWNER_SECRET:?set CAPDEL_OWNER_SECRET (the pod broker owner gate)}"
POP="${CAPDEL_POP:-off}"

MANIFEST=$(CAPDEL_OWNER_SECRET="$CAPDEL_OWNER_SECRET" POP="$POP" python3 - <<'PY'
import json, os
print(json.dumps({
  "name": "capdel-broker", "runtime": "deno", "entry": "broker.ts", "mode": "dev",
  "listen": {"port": 8080, "protocol": "http"},
  "env": {"CAPDEL_OWNER_SECRET": os.environ["CAPDEL_OWNER_SECRET"],
          "CAPDEL_POP": os.environ["POP"], "CAPDEL_HOME": "/tmp/capdel-state"}}))
PY
)

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
# The pod deno runtime runs a SINGLE entry file (it does not resolve local imports), so
# bundle capdel.ts + the adapter into one broker.ts. capdel.ts is dependency-free, so a
# plain concat is a valid module: drop capdel.ts's CLI auto-run and broker.ts's import.
sed '/if (import.meta.main) await main();/d' "$DIR/capdel.ts" > "$TMP/broker.ts"
grep -v '^import { configure, ensureHome, handle } from "./capdel.ts";' "$DIR/broker.ts" >> "$TMP/broker.ts"
cp "$DIR/project.json" "$TMP/project.json"
deno check "$TMP/broker.ts" >/dev/null 2>&1 || { echo "bundle failed deno check"; exit 1; }
tar czf "$TMP/app.tgz" -C "$TMP" broker.ts project.json
RESP=$(curl -fsS -X POST "$CVM/_api/projects" \
  -H "Authorization: Bearer $TEE_DAEMON_TOKEN" \
  -F "manifest=$MANIFEST;type=application/json" \
  -F "files=@$TMP/app.tgz")
echo "$RESP" | python3 -c 'import sys,json; d=json.load(sys.stdin); print("deployed:",d["name"],"| mode:",d.get("mode"),"| tree:",d.get("tree_hash","")[:12])'
echo
echo "Broker base → $CVM/capdel-broker"
echo "Version     → curl -s $CVM/capdel-broker/_api/version"
echo "Mint (owner-gated, over HTTP):"
echo "  curl -s -X POST $CVM/capdel-broker/_mint -H \"Authorization: Bearer \$CAPDEL_OWNER_SECRET\" \\"
echo "    -d '{\"type\":\"fs\",\"constraints\":{\"root\":\"/tmp\",\"ops\":[\"list\",\"read\"]},\"name\":\"demo\"}'"
echo "Then a holder invokes at $CVM/capdel-broker/caps/<id>/invoke  (Bearer <token>)."
echo "Owner-only grant tree → curl -s $CVM/capdel-broker/_tree -H \"Authorization: Bearer \$CAPDEL_OWNER_SECRET\""
