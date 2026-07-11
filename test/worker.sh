#!/bin/sh
# A swarm worker running inside a container with ONLY a scoped capdel token. It has no
# filesystem/shell/network access to the owner's machine except through $CAPDEL_URL —
# which is the whole point: even if this container is fully compromised, its blast radius
# is exactly what the token allows. Discovers what it can do from the API, no docs.
set -eu
: "${CAPDEL_URL:?}"; : "${CAPDEL_TOKEN:?}"; : "${CAP_ID:?}"
AUTH="Authorization: Bearer ${CAPDEL_TOKEN}"

echo "[$(hostname)] discovering capability ${CAP_ID}…"
curl -fsS -H "$AUTH" "${CAPDEL_URL}/caps/${CAP_ID}" | jq -c '{type, constraints}'

# Do whatever the plan says; each line is: op-json  expected-http-status
echo "[$(hostname)] running plan:"
printf '%s\n' "$WORKER_PLAN" | while IFS='|' read -r body expect; do
  [ -z "$body" ] && continue
  code=$(curl -s -o /tmp/out -w '%{http_code}' -H "$AUTH" -d "$body" "${CAPDEL_URL}/caps/${CAP_ID}/invoke")
  mark="OK"; [ "$code" = "$expect" ] || mark="MISMATCH(got $code want $expect)"
  echo "  [$mark] $body -> $code  $(head -c 120 /tmp/out)"
done
echo "[$(hostname)] done."
