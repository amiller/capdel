#!/usr/bin/env bash
# Launch the capdel broker + relay + tunnel for issue #7 verification. Idempotent: kills
# prior pids from the pidfiles first (NEVER pkill -f — that matches this script's argv).
set -u
cd /tmp/app-7
export PATH="$HOME/.local/bin:$HOME/.nvm/versions/node/v22.23.1/bin:$HOME/.deno/bin:$HOME/.bun/bin:$PATH"
PY=python3.11
HOME_DIR=/tmp/capdel7
ROOT=/tmp/capdel7-root
BPORT=4571; RPORT=8931
BID=laptop-soc1024

# stop previous (by pidfile only)
for f in broker relay tunnel; do
  pf=/tmp/capdel7-$f.pid
  [ -f "$pf" ] && kill "$(cat $pf)" >/dev/null 2>&1 || true
done
sleep 1

rm -rf "$HOME_DIR" "$ROOT"
mkdir -p "$ROOT/refs/pdfs"
echo "hello portico" > "$ROOT/refs/pdfs/portico.pdf"

setsid env CAPDEL_HOME="$HOME_DIR" CAPDEL_OWNER_SECRET=owner-secret \
  "$PY" capdel.py serve --bind 127.0.0.1:$BPORT \
  >/tmp/capdel7-broker.log 2>&1 </dev/null &
echo $! > /tmp/capdel7-broker.pid

sleep 1.5
setsid env CAPDEL_RELAY_SECRET=relay-secret CAPDEL_OWNER_SECRET=owner-secret PORT=$RPORT \
  deno run -A pod/relay.ts \
  >/tmp/capdel7-relay.log 2>&1 </dev/null &
echo $! > /tmp/capdel7-relay.pid

sleep 2
setsid env CAPDEL_HOME="$HOME_DIR" \
  "$PY" capdel.py tunnel --relay http://127.0.0.1:$RPORT --broker-id "$BID" --secret relay-secret \
  >/tmp/capdel7-tunnel.log 2>&1 </dev/null &
echo $! > /tmp/capdel7-tunnel.pid

sleep 2
echo "broker log:"; cat /tmp/capdel7-broker.log
echo "relay log:"; cat /tmp/capdel7-relay.log
echo "tunnel log:"; cat /tmp/capdel7-tunnel.log
echo "--- version (direct to broker) ---"; curl -sm 5 http://127.0.0.1:$BPORT/_api/version; echo
echo "pids: broker=$(cat /tmp/capdel7-broker.pid) relay=$(cat /tmp/capdel7-relay.pid) tunnel=$(cat /tmp/capdel7-tunnel.pid)"
