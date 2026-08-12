# capdel

> prototype — v0.1, built and subagent-tested 2026-07-11

Dynamic capability delegation for agents: a trusted agent mints narrow, expiring,
revocable capabilities at dispatch time; less-trusted agents (local subagents or
remote workers) hold only a token and exercise the authority through a broker on
the owner's machine. The anti-pattern this replaces: cron-copying cookies and
credentials into remote machines. See `SPEC.md` for the full design and
requirements provenance.

Single file, stdlib-only Python 3.9+. State in `$CAPDEL_HOME` (default `~/.capdel`).

## What's in here

- **`capdel.py`** — the whole thing: the broker (a local reference monitor that holds
  real fs/exec/net authority) plus the CLI (`serve`, `mint`, `tree`, `approve`, `revoke`,
  `tunnel`).
- **`mcp_server.py`** — a thin MCP server (Model Context Protocol, stdio, stdlib-only)
  that exposes a capability as native MCP tools (`describe`/`invoke`/`attenuate`/
  `escalate`/`poll_request`) for harnesses that only speak MCP. It holds only
  `CAPDEL_URL`+`CAPDEL_TOKEN`+`CAP_ID` and forwards to the broker; the broker still
  enforces everything. See *MCP harnesses* below.
- **`skill/capdel/SKILL.md`** — a Claude Code skill that teaches a trusted agent to reach
  for capdel when it dispatches a subagent (mint a narrow capability, hand over only a
  token). Drop it in `~/.claude/skills/capdel/` to use it. **Start here to understand the
  point.**
- **`pod/`** — an optional dstack pod app so a *remote* agent can exercise a capability
  back on your machine through a dial-out tunnel, plus a read-only dashboard of your grant
  tree. Not needed for local use.
- **`docs/user-journeys.md`** — five concrete "when would I use this" stories (local
  subagent, remote GLM worker, command-back-to-laptop, mid-task escalation, swarm
  fan-out), each with an honest analysis of what works today vs. what's still weak.
- **`SPEC.md`** — the full design, requirements, and a comparison to prior work.

## Walkthrough — delegate to a helper, in one screen

The whole point of capdel in one story. You give a helper a read-only key, it hits a
wall, asks, you approve, it finishes — and it never had more than you granted.

```sh
python3 capdel.py serve &                                    # the doorman (broker)
U=http://127.0.0.1:4571

# 1. You mint a read-only capability. Prints an id + a token — the "ticket".
python3 capdel.py mint fs --root ~/work --ops list,read --ttl 30m --name helper
#   id=cap-e0ce…   token=ct-3471…

# 2. The helper — holding only the token — discovers what it can do (no docs needed):
curl -H "Authorization: Bearer $TOKEN" $U/caps/$ID
#   → {constraints:{root:~/work, ops:[list,read]}, how:[…curl examples…], escalate:…}

# 3. It reads (works); every entry carries type + size:
curl -H "Authorization: Bearer $TOKEN" -d '{"op":"list","path":"…/work"}'      $U/caps/$ID/invoke
#   → {"entries":[{"name":"report.txt","type":"file","size":32}]}

# 4. It tries to WRITE — refused, with the exact reason:
curl -H "Authorization: Bearer $TOKEN" -d '{"op":"write","path":"…","content":"x"}' $U/caps/$ID/invoke
#   → {"error":"denied","violated":"op 'write' not in granted ops ['list','read']"}

# 5. It ASKS — sending only the delta (the new op), not the whole scope:
curl -H "Authorization: Bearer $TOKEN" -d '{"want":{"ops":["list","read","write"]},"reason":"need to write summary"}' $U/caps/$ID/escalate
#   → {request_id:req-e76f…, granted_if_approved:{root:~/work, ops:[list,read,write]},
#      note:"if approved, poll returns a NEW token+cap — switch to them"}

# 6. You rule on it:
python3 capdel.py requests                    # see who's asking, why, and for exactly what
python3 capdel.py approve req-e76f… --ttl 20m # mints a fresh grant

# 7. The helper polls, gets the NEW token+cap, and writes — now it works:
curl -H "Authorization: Bearer $NEW_TOKEN" -d '{"op":"write","path":"…/summary.txt","content":"…"}' $U/caps/$NEW_CAP/invoke
#   → {"path":"…/work/summary.txt","written":40,"created":true}

# The helper's ORIGINAL token still can't write. Revoke anything, anytime:
python3 capdel.py revoke $ID                  # kills it and its whole subtree now
```

## Quickstart

```sh
python3 capdel.py serve &                       # broker on 127.0.0.1:4571

# operator mints roots (local CLI only, never over HTTP)
python3 capdel.py mint fs   --root ~/projects/foo --ops list,read,write --ttl 4h
python3 capdel.py mint exec --allow "git status" --allow "rg" --cwd-root ~/projects/foo --ttl 4h
python3 capdel.py mint net  --allow "api.github.com:443" --allow "10.0.0.5:*" --ttl 4h
# → prints id + token (token shown once; broker stores only its hash)

# trusted agent attenuates at dispatch time and hands the CHILD token to a subagent
curl -H "Authorization: Bearer $PARENT_TOKEN" \
  -d '{"constraints":{"root":"/home/u/projects/foo/docs","ops":["list","read"]},"ttl_s":3600}' \
  http://127.0.0.1:4571/caps/$PARENT_ID/attenuate

# the subagent needs only two values:
#   CAPDEL_URL=http://127.0.0.1:4571   CAPDEL_TOKEN=ct-…  (+ cap id in its brief)
curl -H "Authorization: Bearer $CAPDEL_TOKEN" http://127.0.0.1:4571/caps/$CAP_ID
# → self-describing: constraints + literal usage examples + how to escalate
```

## Holder-bound tokens (anti-replay, opt-in)

By default a token is **bearer** (the curl examples above). The moment a token transits
the public pod relay (§3.7), a bearer is replayable by whoever sees it. Flip to
holder-bound **proof-of-possession** so the token is an HMAC key that never re-crosses
the wire:

```sh
# 1. mint a PoP cap — the printed token is now a signing key, not a password
python3 capdel.py mint fs --root ~/work --ops list,read --ttl 30m --pop
# 2. the cap serves a ~15-line stdlib signer at GET /capdel-sign (also inlined in self-description)
curl http://127.0.0.1:4571/capdel-sign > capdel-sign && chmod +x capdel-sign
export CAPDEL_URL=http://127.0.0.1:4571 CAPDEL_TOKEN=ct-…
# 3. invoke — same shape as bearer, minus the Authorization header; each request is single-use
./capdel-sign POST /caps/$ID/invoke '{"op":"read","path":"…"}'
```

A captured request is useless: the signature binds method + broker-local path +
body-hash + a one-time nonce + timestamp (`±300s`). Modes: `CAPDEL_POP=off` (default,
bearer) | `allow` (per-request) | `require` (PoP mandatory). Design:
`tasks/pop-design-hmac.md`; tests: `python3 test/test_pop.py`.

## The five verbs

| verb | who | what |
|---|---|---|
| `mint` | operator, CLI | create root authority from nothing |
| `attenuate` | any token holder | mint a strictly-narrower child (subset checked structurally, 403 otherwise) |
| `invoke` | any token holder | exercise the capability (fs: list/read/write/stat inside root; exec: allowlisted argv prefixes, no shell; net: one brokered TCP connect to an allowlisted host:port) |
| `escalate` | any token holder | request more, with a reason; owner rules via `capdel approve/deny`; requester polls |
| `revoke` | operator, CLI | kill a capability and its whole subtree immediately |
| `event` | operator, CLI | fire a trusted event; auto-revokes every cap whose `--closes-on` lists it (closure) |

Legibility: `capdel tree` (live grant tree = the at-a-glance exposure view),
`capdel audit` (JSONL, every allow/deny), `capdel requests` (pending escalations).

## Closure — authority dies with its justification

TTL alone leaves a capability live after the reason it was granted ends. A cap may
declare `closes_on` — trusted-event names that auto-revoke it when the owner fires
one (`capdel event NAME`, or owner-secret `POST /_event`). PORTICO-style: tie a
grant's lifetime to the reason it was granted.

```sh
# grant a helper read access that dies the moment the build passes
python3 capdel.py mint fs --root ~/work --ops list,read --ttl 4h \
  --closes-on build-passed --name helper
# …later, the owner verifies the build and fires the event — the cap (and any
# children) is revoked automatically; nothing waits around for TTL.
python3 capdel.py event build-passed
```

Closure only narrows authority: a child may add events, a parent's closure cascades
to its subtree, and the effective closure is the union up the chain (shown in the
cap self-description and `capdel tree`). Events are owner-filed only — the value is
a signal a delegated holder *cannot* forge.

## `secret` caps — paste-vault a credential, the broker injects it (issue #19)

`fs | exec | net | llm` all scope access to things the broker's machine *has*. `secret`
covers the one thing the SPEC names first — a credential the remote agent otherwise
"holds the whole of, not the narrow slice." You paste a key once, capdel vaults it
(encrypted at rest), and it is *used* broker-side so the plaintext never enters any
holder's context. capdel as a powerbox for CLI secrets.

```sh
python3 capdel.py serve &
U=http://127.0.0.1:4571

# 1. Paste the key ONCE (stdin — never argv, never shell history, never audit).
#    The inject template carries the literal {{secret}} sentinel; \r\n escapes decode.
printf 'sk-live-key-...' | python3 capdel.py vault --name openai \
  --allow api.openai.com:443 \
  --inject 'GET /v1/models HTTP/1.1\r\nHost: api.openai.com\r\nAuthorization: Bearer {{secret}}\r\nConnection: close\r\n\r\n'
#   id=cap-…  token=ct-…  type=secret name=openai pop=True
#   note: the value is vaulted under secrets/<id>.bin and is never returned by any op

# 2. A holder (holding only the token) narrows it to exactly one host and exercises it.
#    The broker dials api.openai.com:443, writes the inject prefix WITH the key
#    substituted AFTER the relay boundary, relays the reply, closes. The holder
#    never sees the key — describe, audit, and the reply are all redacted of it.
curl -s -H "Authorization: Bearer $TOKEN" -d '{"op":"connect","host":"api.openai.com","port":443}' \
  $U/caps/$ID/invoke
#   → {"recv":"HTTP/1.1 200 …","bytes":N,"truncated":false}

# 3. Widening the host is denied; no op returns the raw value; every use is audited:
capdel audit --cap $ID      # each connect row: cap, ts, dest=api.openai.com:443, bytes=N — never the value
```

Trustworthy only under confinement (the SPEC §4 caveat): unconfined, a holder with
FS access on the broker machine can read the vault directly. `secret` caps default to
PoP (`--pop`) so a leaked token ≠ a spent key. The sibling `llm` cap is the narrow,
single-protocol version of the same idea — one canned chat/completions shape with a
key from the broker env; `secret` is the general, arbitrary-destination mechanism.

## Trying it on a subagent

Give the subagent nothing but the URL, cap id, and token, and the instruction that
the API is its only route to the resource. It can bootstrap entirely from
`GET /caps/<id>`. Confinement of the agent *process* is a separate, composable
layer (run it in Docker+gVisor/Deno with only those two env vars) — the broker
bounds what the token can do, the sandbox bounds what the process can do.

## MCP harnesses (harnesses that only speak MCP)

Some agent harnesses only speak the Model Context Protocol — their tool list is fixed at
session start, so they can't `curl` a capdel URL or discover a capability mid-flight. For
those, `mcp_server.py` is a ~thin adapter: spawn it as an MCP server with the same two
values a subagent already gets, and the capability shows up as native tools
(`describe`, `invoke`, `attenuate`, `escalate`, `poll_request`). It parses nothing and
enforces nothing — every call is forwarded to the broker over the HTTP API in §5, so the
broker is still the only reference monitor.

```sh
python3 capdel.py serve &                      # broker on 127.0.0.1:4571
python3 capdel.py mint fs --root ~/work --ops list,read --ttl 30m --name helper   # → id + token
```

then point your MCP harness at (e.g. a Claude Desktop / MCP-client config):

```json
{"command": "python3", "args": ["mcp_server.py"],
 "env": {"CAPDEL_URL": "http://127.0.0.1:4571",
          "CAPDEL_TOKEN": "ct-…", "CAP_ID": "cap-…"}}
```

A denial comes back as a tool *error* that names the violated constraint, so the model
can decide to `escalate` and `poll_request` for the result. Auth is bearer by default; a
PoP (`--pop`) cap wants PoP signing, which belongs in `capdel-sign`, not this wrapper.
Black-box drive: `python3 test/mcp.py`.

## Remote agents + the dashboard (`pod/`)

For an agent on another machine (a zed/Paseo worker), the laptop broker **dials
out** to a rendezvous instead of listening — `capdel tunnel --relay <url>
--broker-id NAME`. The rendezvous is `pod/`, a dstack pod app (Deno) that forwards
remote requests down the tunnel and never holds authority, plus a read-only
dashboard of the live grant tree pulled through the tunnel. Run the whole thing
locally with `deno run` — see `pod/README.md`. Design rationale is SPEC §3.7.
