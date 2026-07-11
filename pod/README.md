# capdel-relay — the pod rendezvous + dashboard

A dstack pod app (Deno) that is the public rendezvous for a laptop capdel broker
(SPEC §3.7). The laptop **dials out** with `capdel tunnel` — no inbound port — and
this relay forwards remote requests down that connection. The relay never holds a
capability; enforcement stays in the broker on the laptop. It also serves a
**read-only dashboard** of the live grant tree, pulled through the tunnel with the
owner secret server-side (the browser never sees it).

```
remote agent ──HTTPS──▶ <pod>/capdel-relay/b/<broker-id>/caps/<id>/invoke
                              │  (Bearer <capdel-token>)
                              ▼   relay enqueues, laptop long-polls it down
   laptop: capdel broker ◀──dial-out── relay ──▶ response back to the agent
                              enforcement here          (relay only forwards)
```

## Try it locally (no pod needed)

Four terminals (or backgrounded). `relay.ts` has a dev harness so `deno run` serves
the same handler standalone.

```sh
# 1. broker with an owner secret (enables the dashboard's /_tree read)
CAPDEL_OWNER_SECRET=owner123 python3 ../capdel.py serve

# 2. the relay, standalone
PORT=8090 CAPDEL_RELAY_SECRET=relay123 CAPDEL_OWNER_SECRET=owner123 deno run -A relay.ts

# 3. the dial-out tunnel (laptop → relay)
CAPDEL_RELAY_SECRET=relay123 python3 ../capdel.py tunnel \
  --relay http://127.0.0.1:8090 --broker-id laptop1

# 4. owner mints a cap, then a "remote" agent uses it THROUGH the relay
python3 ../capdel.py mint fs --root ~/notes --ops list,read --ttl 1h   # prints id + token
curl -H "Authorization: Bearer <token>" \
  -d '{"op":"read","path":"/home/you/notes/x.md"}' \
  http://127.0.0.1:8090/b/laptop1/caps/<id>/invoke

# dashboard (read-only): http://127.0.0.1:8090/?key=relay123
```

## Deploy to the pod

`bash deploy.sh` (operator step — the assistant is blocked from prod-deploy). Set
`CAPDEL_RELAY_SECRET` and `CAPDEL_OWNER_SECRET` to match the laptop's broker/tunnel.
Served at `<pod>/capdel-relay/`. Two pages:

- **`<pod>/capdel-relay/demo`** — a public, shareable read-only page with illustrative
  data (chains, expiry, an approved escalation, a revoked subtree). No broker or key
  needed; this is the link to share.
- **`<pod>/capdel-relay/?key=<relay-secret>`** — the live dashboard, real capabilities
  pulled through the tunnel. Gated; needs a connected broker.

## Security notes

- The relay sees the capdel bearer token in transit — it forwards it to the broker,
  where the actual check runs. This is exactly why SPEC §8 promotes holder-bound
  (PoP) tokens: once a token crosses a public relay, a bearer token is replayable by
  the relay operator. v0 accepts this (the relay is the attested pod); PoP is the
  tracked hardening.
- Two independent gates guard a remote invoke: the relay secret (to reach the relay
  at all) and the capdel token (what you may do). The owner secret stays in the
  relay's attested env and never reaches the browser.
- Dashboard is read-only and gated by `?key=<relay-secret>`.
