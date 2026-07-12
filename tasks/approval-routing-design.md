# capdel approval routing — escalate hook + dashboard approve/deny

Design for issue #3. Concrete and implementable. Target: keep the broker stdlib-only,
keep notifier credentials out of the broker TCB, and keep the property that approval
renders the *shape* (the exact constraints), never just the agent's narration.

## 0. Problem restated

An escalation today is a file the owner must poll for (`capdel requests`). In the exact
moment the flow matters — the owner is heads-down elsewhere (Journey B) — capdel
silently fails them: the worker stalls, the ask never arrives. Two halves to build:

1. **Push**: the broker tells the owner a request exists, over whatever channel the
   owner already watches (Matrix, ntfy, Paseo, `notify-send`).
2. **Act**: the owner rules from where the ping lands — the pod dashboard gets
   approve/deny — without weakening "authority decisions happen against the shape."

The tunnel stays transport; the relay still never holds a capability or a decision.

## 1. The hook primitive (`CAPDEL_ESCALATE_HOOK`)

Set at serve time, same pattern as `CAPDEL_OWNER_SECRET` / `CAPDEL_POP`:

```sh
CAPDEL_ESCALATE_HOOK=~/bin/capdel-notify python3 capdel.py serve
```

When a request is filed, the broker spawns the hook with an **event envelope on
stdin** and no arguments:

```json
{
  "kind": "escalation.filed",              // envelope is versioned by kind, not schema
  "request_id": "req-e76f…",
  "cap": {"id": "cap-3f9a…", "name": "helper for docs/", "lineage": ["cap-root-fs"]},
  "reason": "need write to update the index",          // agent narration — untrusted
  "want": {"ops": ["list", "read", "write"]},          // the delta, as filed
  "granted_if_approved": {"root": "…", "ops": ["list","read","write"]},  // THE SHAPE
  "expires_at": 1783810000,                            // request TTL (issue #2)
  "decide": {"approve": "capdel approve req-e76f…", "deny": "capdel deny req-e76f…",
             "dashboard": "https://pod…/capdel-relay/b/<broker-id>/_requests"}
}
```

Rules:

- **Fire-and-forget.** Spawned detached with a hard timeout (10s, then SIGKILL); the
  escalate HTTP response never waits on it. A missing/crashing hook must not break
  escalation — poll still works, `capdel requests` still works. Nonzero exit or
  timeout is audited (`event=hook, decision=fail`), not retried.
- **One hook, an envelope, not N env vars.** `kind` lets future events
  (`escalation.decided`, `request.expiring`) reuse the same hook without breaking
  existing consumers; v1 ships `escalation.filed` only.
- **The hook is owner-chosen code running with broker privileges.** That is the
  point, not a bug: the Matrix token / ntfy topic lives in the hook script, so
  notifier credentials never enter the broker. Document it; don't sandbox it (the
  owner already owns this machine).
- **The payload leads with `granted_if_approved`.** A notifier that shows one field
  shows the shape. The `reason` is labeled untrusted in the envelope ordering and in
  the doc — the consent-integrity rule, applied at the notification layer.

One-liner wirings (ship in the README):

```sh
#!/bin/sh  # ntfy
jq -r '"[capdel] \(.cap.name) wants \(.granted_if_approved.ops|join(",")) — \(.decide.approve)"' \
  | curl -s -d @- https://ntfy.sh/$TOPIC
```

```sh
#!/bin/sh  # notify-send (local)
j=$(cat); notify-send "capdel escalation" "$(echo "$j" | jq -r .reason)"
```

## 2. Dashboard approve/deny

### 2.1 Broker endpoints (owner-gated, mirrors `/_gc` from #7)

```
GET  /_requests                     owner secret → pending requests, full shapes
POST /_requests/<id>/approve        owner secret, {"ttl_s"?, "closes_on"?} → {ok, cap_id}
POST /_requests/<id>/deny           owner secret → {ok}
```

Same code path as `cmd_approve`/`cmd_deny` — one implementation, two front doors.
The `/_gc` forwarding pattern through the relay already exists; these ride it.

**The new token never appears in the approve response.** Approval mints the cap and
stores the token for the *requester's* poll pickup, exactly as today. The dashboard
sees `{ok, cap_id}` — the owner authorizes authority, they don't carry it. This keeps
the relay unable to learn a usable credential even on the approval path (and for
`--pop` requesters the poll delivers a key the relay never sees used as a bearer).

### 2.2 The approval view renders the shape

Per request, the dashboard shows, in this order:
1. `granted_if_approved` — the literal constraints, clamped, front and center
2. the requesting cap: name, lineage chain, expiry
3. **that cap's recent audit tail** (last ~10 invokes: op, path/argv digest, decision)
   — the "what has this worker been doing" context Journey B stage 2 asks for, pulled
   through the tunnel like `/_tree`. This is the cheap version of the context-manifest
   idea (five-axes report, axis 4); the full manifest is a follow-on, not v1.
4. the `reason`, visually subordinate, labeled as the requester's words
5. approve (with a TTL selector defaulting to the requested cap's remaining TTL,
   capped) · deny

### 2.3 Security posture (stated, not deferred)

- The owner secret already gates `/_tree`/`/_audit`/`/_gc` through the relay; these
  endpoints raise its value from "read my grant tree" to "mint authority I asked
  for". Two mitigations ship with v1: the secret is sent as a header (never a cookie
  → no CSRF surface; the dashboard page keeps it in sessionStorage), and approve is
  **bounded by the stored request** — the owner can only approve the `want` that was
  filed (with an equal-or-shorter TTL), never edit constraints upward through the
  relay. Widening beyond the ask stays CLI-only.
- Residual risk to name in SPEC §4: a relay operator who steals the owner secret can
  approve *pending* requests (not file them — filing needs a cap token). PoP for the
  owner secret is the same hardening ladder as #4 and lands on the same framework
  if/when it matters.

## 3. Out of scope for v1

Batch rule-on-several (multi-select is a dashboard afterthought once single works) ·
auto-approval policies (that's guard-policy territory, five-axes axis 3) ·
`escalation.decided` hook events · Matrix bot with inline buttons (a hook consumer,
not broker work).

### 3.1 v2 sketch: clarification round (monotone negotiation)

Prior art is AAuth §7.3 (202 + pending URL; agent answers, revises, or withdraws) and
GNAP's continuation API — but selected by capdel's rules (training-data-dense HTTP
idioms, adversarial mileage, context economy), not adopted as shapes. A request gains
one more state: the owner attaches a question to a pending request (dashboard box or
`capdel ask req-… "why the whole folder?"`, with an optional `options` array —
structured choices over free Markdown wherever possible, since every prose field in
the loop is LITL surface). The requester sees it on its existing poll — no new
credential, no continuation token; it stays authenticated as its cap — and may answer,
**revise**, or withdraw (DELETE). The one rule neither AAuth nor GNAP has, and the
reason to build this at all: **revision is monotone** — a revised `want` must be a
subset of the *originally filed* `want`, checked by the same structural subset code as
attenuation, else 403. The ask the owner is deliberating can shrink under negotiation
but never inflate. AAuth's `updated_request` may replace the request arbitrarily;
GNAP's grant modification is unconstrained; both make "what am I approving?" a moving
target. Monotone revision keeps the negotiation converging toward minimal scope —
which is also the mechanism the #15 escalation-as-recovery experiment wants to
measure.

## 4. Test plan

Tier-1 (`swarm.py`) grows: file escalation → assert hook ran (hook = append-to-file
script) with the right envelope → approve via `POST /_requests/<id>/approve` with the
owner secret → requester poll picks up the new cap → assert the approve response
contained no token. Negative: hook crashes → escalate still 200s; approve with wrong
secret → 403; approve a `want` after mutating the stored request file → clamped to
the filed shape.
