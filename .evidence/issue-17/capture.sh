#!/usr/bin/env bash
# Tier-1 capture for issue #17: owner-secret gate on /_tree /_audit /_gc /_event.
# Three throwaway brokers: PR code + secret (4781), PR code + NO secret (4782),
# origin/main code + secret (4783). Raw curl output only; nothing is summarized here.
set -euo pipefail
ROOT=${CAPDEL_ROOT:-$(cd "$(dirname "$0")" && git rev-parse --show-toplevel)}
W=$(mktemp -d /tmp/capdel-17.XXXXXX)
S=owner-secret-e2e-issue17
trap 'kill $(jobs -p) 2>/dev/null || true' EXIT

CAPDEL_HOME=$W/a CAPDEL_OWNER_SECRET=$S python3 "$ROOT/capdel.py" serve --bind 127.0.0.1:4781 & A=$!
CAPDEL_HOME=$W/b                                  python3 "$ROOT/capdel.py" serve --bind 127.0.0.1:4782 & B=$!
if [ -d /tmp/rw-17-main ]; then
  CAPDEL_HOME=$W/c CAPDEL_OWNER_SECRET=$S python3 /tmp/rw-17-main/capdel.py serve --bind 127.0.0.1:4783 & C=$!
fi
sleep 1.5

hit(){ # $1=url $2=token(or '-') $3=method $4=body(or '-')
  local args=(-s -X "$3"); [ "$4" != - ] && args+=(-H 'Content-Type: application/json' -d "$4")
  [ "$2" != - ] && args+=(-H "Authorization: Bearer $2")
  printf '$ %s\n-> ' "$*"; curl "${args[@]}" -w '\n[%{http_code}]\n' "$1"
}

for port in 4781 4783; do
  U=http://127.0.0.1:$port
  echo "===== broker on :$port — $U/_api/version"
  hit $U/_api/version - GET -
  for route in /_tree /_audit; do
    hit $U$route - GET -
    hit $U$route wrong-secret GET -
    hit $U$route $S GET -
  done
  hit $U/_event - POST '{"name":"e2e-issue17-noauth"}'
  hit $U/_event wrong-secret POST '{"name":"e2e-issue17-wrong"}'
  hit $U/_event $S POST '{"name":"e2e-issue17"}'
  hit $U/_gc - POST -
  hit $U/_gc wrong-secret POST -
  hit $U/_gc $S POST -
done

echo "===== broker on :4782 (NO owner secret configured) — $U/_api/version"
U=http://127.0.0.1:4782
hit $U/_api/version - GET -
for route in /_tree /_audit; do
  hit $U$route - GET -
  hit $U$route $S GET -          # even the would-be secret is refused: OWNER_SECRET is None
done
hit $U/_event $S POST '{"name":"e2e-issue17"}'
hit $U/_gc $S POST -

kill $A $B ${C:-} 2>/dev/null || true
wait 2>/dev/null || true
echo "===== done"
