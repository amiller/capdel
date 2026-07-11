---
name: capdel
description: >
  Delegate scoped, revocable OS authority (files, shell commands, network) to a
  subagent or remote worker instead of giving it broad access or copying credentials.
  Use when dispatching a less-trusted agent (a cheaper/unsupervised model, a worker on
  another machine) that needs to touch specific files, run specific commands, or reach
  specific hosts on this machine. Mint a narrow capability, hand over only the token.
---

# capdel — delegate a narrow capability, not broad access

You (the trusted agent) hold broad authority on this machine. When you dispatch a
subagent or a remote worker, **do not** hand it your access or a raw credential.
Instead mint a capability scoped to exactly what its task needs, and give it only a
URL + a token. It can do what the token allows and nothing else; you can revoke it.

The broker runs locally (`capdel serve`, on `127.0.0.1:4571`). Everything below talks
to it. `capdel.py` is stdlib-only Python.

## When to use this

Reach for capdel the moment you're about to let another agent act on this machine:
- a subagent that should read one directory but not the whole disk,
- a worker running a cheaper/less-trusted model you don't want to give a shell,
- a remote worker (on zed/Paseo) that needs to run one command back on your laptop.

If you'd otherwise write `--dangerously-skip-permissions`, copy a cookie, or share an
ssh key — mint a capability instead.

## The one move: mint, then hand over the token

```sh
# You mint a capability scoped to the subagent's task. Prints an id and a token.
python3 capdel.py mint fs   --root ./data --ops list,read --ttl 30m --name "reviewer"
python3 capdel.py mint exec --allow "git status" --allow "rg" --cwd-root . --ttl 30m
python3 capdel.py mint net  --allow "api.github.com:443" --ttl 30m
```

Then dispatch the subagent with **only** these three facts in its brief/env — never
your own credentials:

```
CAPDEL_URL=http://127.0.0.1:4571
CAPDEL_TOKEN=<the token you just minted>
cap id=<the id you just minted>
```

Tell the subagent: *"The capdel HTTP API is your only way to touch files / run
commands / reach the network. Discover what you can do with `GET $CAPDEL_URL/caps/<id>`."*
That GET returns the capability's exact scope plus copy-pasteable `curl` examples, so
the subagent needs no other documentation.

## The three capability types

- **fs** — files under a root. ops ⊆ `list read write stat`. Paths are realpath-checked;
  symlinks and `..` that escape the root are refused.
- **exec** — commands whose argv extends an allowlisted prefix (`git status` allows
  `git status --short` but not `git push`). No shell, so no injection surface.
- **net** — one brokered TCP connection to an allowlisted `host:port`. Not a proxy —
  the subagent never gets a socket, just one relayed request/response.

## How a holder uses a capability (fs example)

```sh
curl -H "Authorization: Bearer $CAPDEL_TOKEN" $CAPDEL_URL/caps/<id>            # what can I do?
curl -H "Authorization: Bearer $CAPDEL_TOKEN" -d '{"op":"read","path":"…"}' $CAPDEL_URL/caps/<id>/invoke
```
A denied call returns `{"error":"denied","violated":"…"}` naming the exact constraint.

## Attenuate: narrow further before re-delegating

Any token holder can mint a strictly-narrower child — the subagent can hand its own
sub-subagent an even tighter slice. It can never widen.

```sh
curl -H "Authorization: Bearer $PARENT_TOKEN" \
  -d '{"constraints":{"root":"./data/pub","ops":["read"]},"ttl_s":600}' \
  $CAPDEL_URL/caps/<parent-id>/attenuate
```

## Escalate: when the subagent hits a wall

If the task genuinely needs more than you granted, the subagent asks — it does not get
it automatically:

```sh
curl -H "Authorization: Bearer $CAPDEL_TOKEN" \
  -d '{"want":{"root":"./data","ops":["list","read","write"]},"reason":"need to write results"}' \
  $CAPDEL_URL/caps/<id>/escalate            # → {request_id, status:"pending"}
```
You (the owner) rule on it: `python3 capdel.py requests` then
`python3 capdel.py approve <request_id> --ttl 20m`. Approval mints a fresh grant with a
new token; the subagent polls `GET $CAPDEL_URL/requests/<request_id>` and switches to it.
`want` is a full constraints object (same shape as `mint`), not just the delta.

## See and revoke what you've handed out

```sh
python3 capdel.py tree                 # the live grant forest: who holds what, expiry
python3 capdel.py audit                # every allow/deny
python3 capdel.py revoke <cap-id>      # kills that capability and its whole subtree now
```

## The principle

The broker holds the real authority; the subagent holds a token. Enforcement is a
mechanical subset check on your machine — no LLM in the loop deciding. Confinement of
the subagent *process* (Docker/gVisor/Deno) is a separate, complementary layer: the
sandbox bounds what the process can do to itself, capdel bounds what it can do to *your*
resources. Grant the least that lets the task succeed, with a short TTL, and revoke when
done.
