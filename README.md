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

## The five verbs

| verb | who | what |
|---|---|---|
| `mint` | operator, CLI | create root authority from nothing |
| `attenuate` | any token holder | mint a strictly-narrower child (subset checked structurally, 403 otherwise) |
| `invoke` | any token holder | exercise the capability (fs: list/read/write/stat inside root; exec: allowlisted argv prefixes, no shell; net: one brokered TCP connect to an allowlisted host:port) |
| `escalate` | any token holder | request more, with a reason; owner rules via `capdel approve/deny`; requester polls |
| `revoke` | operator, CLI | kill a capability and its whole subtree immediately |

Legibility: `capdel tree` (live grant tree = the at-a-glance exposure view),
`capdel audit` (JSONL, every allow/deny), `capdel requests` (pending escalations).

## Trying it on a subagent

Give the subagent nothing but the URL, cap id, and token, and the instruction that
the API is its only route to the resource. It can bootstrap entirely from
`GET /caps/<id>`. Confinement of the agent *process* is a separate, composable
layer (run it in Docker+gVisor/Deno with only those two env vars) — the broker
bounds what the token can do, the sandbox bounds what the process can do.

## Remote agents + the dashboard (`pod/`)

For an agent on another machine (a zed/Paseo worker), the laptop broker **dials
out** to a rendezvous instead of listening — `capdel tunnel --relay <url>
--broker-id NAME`. The rendezvous is `pod/`, a dstack pod app (Deno) that forwards
remote requests down the tunnel and never holds authority, plus a read-only
dashboard of the live grant tree pulled through the tunnel. Run the whole thing
locally with `deno run` — see `pod/README.md`. Design rationale is SPEC §3.7.
