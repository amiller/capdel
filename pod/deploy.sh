#!/usr/bin/env bash
# Deploy capdel-relay to the oauth3 pod tee-daemon as a deno source tarball (dev mode).
# Modeled on webhost-apps/otterpilot/deploy.sh. Two secrets travel only in the deploy
# POST's manifest env, never committed:
#   CAPDEL_RELAY_SECRET — gates the laptop's _pull/_reply and the dashboard (?key=).
#   CAPDEL_OWNER_SECRET — lets the dashboard read the broker's /_tree, /_audit.
# Both must match what you pass to `capdel serve` / `capdel tunnel` on the laptop.
#
#   CAPDEL_RELAY_SECRET=… CAPDEL_OWNER_SECRET=… bash deploy.sh
#
# NOTE: deploying to the attested pod is an operator step. The assistant is blocked from
# prod-deploy by the classifier; run this yourself. Prints the relay URL + the exact
# `capdel tunnel` command to run on the laptop.
set -euo pipefail
CVM="${CVM:-https://pod.dstack.soc1024.com}"
DIR="$(cd "$(dirname "$0")" && pwd)"
TEE_DAEMON_TOKEN="${TEE_DAEMON_TOKEN:-$(grep -E '^TEE_DAEMON_TOKEN=' "$HOME/projects/hermes-agent/deploy-notes/.env.prod9" 2>/dev/null | cut -d= -f2- || true)}"
: "${TEE_DAEMON_TOKEN:?no daemon token (set TEE_DAEMON_TOKEN or populate .env.prod9)}"
: "${CAPDEL_RELAY_SECRET:?set CAPDEL_RELAY_SECRET}"
: "${CAPDEL_OWNER_SECRET:?set CAPDEL_OWNER_SECRET (must match the broker)}"

MANIFEST=$(CAPDEL_RELAY_SECRET="$CAPDEL_RELAY_SECRET" CAPDEL_OWNER_SECRET="$CAPDEL_OWNER_SECRET" python3 - <<'PY'
import json, os
print(json.dumps({
  "name": "capdel-relay", "runtime": "deno", "entry": "relay.ts", "mode": "dev",
  "listen": {"port": 8080, "protocol": "http"},
  "env": {
    "CAPDEL_RELAY_SECRET": os.environ["CAPDEL_RELAY_SECRET"],
    "CAPDEL_OWNER_SECRET": os.environ["CAPDEL_OWNER_SECRET"],
  }}))
PY
)

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
tar czf "$TMP/app.tgz" -C "$DIR" relay.ts project.json public
RESP=$(curl -fsS -X POST "$CVM/_api/projects" \
  -H "Authorization: Bearer $TEE_DAEMON_TOKEN" \
  -F "manifest=$MANIFEST;type=application/json" \
  -F "files=@$TMP/app.tgz")
echo "$RESP" | python3 -c 'import sys,json; d=json.load(sys.stdin); print("deployed:",d["name"],"| mode:",d.get("mode"),"| tree:",d.get("tree_hash","")[:12])'
echo
echo "Shareable demo (public)  → $CVM/capdel-relay/demo"
echo "Live dashboard (gated)   → $CVM/capdel-relay/?key=<relay-secret>"
echo "On the laptop, alongside capdel serve:"
echo "  CAPDEL_OWNER_SECRET=<owner> capdel serve"
echo "  CAPDEL_RELAY_SECRET=<relay> capdel tunnel --relay $CVM/capdel-relay --broker-id laptop1"
echo "A remote agent then invokes at:"
echo "  $CVM/capdel-relay/b/laptop1/caps/<id>/invoke   (Bearer <capdel-token>)"
