# capdel — dynamic capability delegation for agents

Status: draft v0.1, 2026-07-11. Name provisional.
Source requirements: a live design discussion, 2026-07-11.

## 1. Problem

Agents with different trust levels share one user's authority. Today the practice is:
a trusted agent (Claude Code) runs with near-full user access on the laptop, while
less-trusted agents (unsupervised, cheaper/riskier models, remote workers) get
credentials by *copying* them — a cron that pushes cookies to remote machines every
few minutes. Two failures:

- **Over-grant**: the remote agent holds the whole credential, not the narrow slice
  the task needs. Revocation is "wait for the cookie to expire."
- **No back-channel**: remote agents can't act *on the laptop* at all, so anything
  that needs local authority gets pre-copied instead of brokered.

Existing agent-auth work assumes a fixed scope list defined ahead of time. Nothing
covers the lifecycle we actually need: **dynamically generating a capability at
dispatch time, attenuating it from an existing one, handing it to a subagent,
escalating mid-task when the task genuinely needs more, and revoking/expiring it.**

## 2. Requirements (from the source discussion)

R1. **Trust differential.** The trusted agent drafts/mints attenuated capabilities;
    the less-trusted agent only ever holds the attenuated thing. "I would use Claude
    to draft the capability restriction and then give the more risky model access
    only to that capability."

R2. **Attenuation as the primitive.** New capabilities are made by narrowing existing
    ones (not by picking from a pre-defined scope menu). Narrowing means: subset of
    operations, subset of resources (path prefix, command allowlist), shorter expiry.

R3. **Dispatch-time minting.** No standing switchboard of thousands of scopes. At the
    moment a subagent is dispatched, the dispatcher works out what it needs and mints
    exactly that.

R4. **Remote execution back to the owner's machine.** A capability must be exercisable
    by an agent on another machine: the authority stays home, the token travels.
    (Reverse-tunnel/exposed broker; the opposite of cookie-copying.)

R5. **Mid-task escalation.** If a subagent hits a wall it can *request* more, with a
    reason; the owner approves/denies out-of-band, ideally batched. "If it truly was
    not foreseeable at the beginning… I am okay giving it an extra credential."

R6. **Legibility.** A read-only view of total capability exposure at a glance
    (tree of live grants, what each can do, audit trail). Input stays agent-driven.

R7. **Agent-friendly surface.** Trivially usable from a shell by a model that has
    only `curl`/python and two env vars. Discoverable mid-flight (a capability can
    describe itself), because MCP tool lists are static per session.

R8. **Cheap.** No per-capability container. Enforcement happens in one broker
    process; sandboxes (Docker+gVisor / Deno) are a *complement* for confining the
    agent process itself, not the mechanism of authority.

Non-goals for v0: browser-cookie/account delegation (that's oauth3's lane), offline
attenuation (Biscuit-style), multi-user federation, quotas/metering (R-future),
signed audit.

## 3. Design

One **broker** process runs where the authority lives (the laptop). It is a
reference monitor: it holds real authority (filesystem, subprocess execution) and
exposes it only through **capabilities**.

A **capability** is a record held by the broker plus a bearer **token** held by an
agent:

```json
{
  "id": "cap-3f9a…",
  "parent": "cap-root-fs",          // attenuation chain
  "name": "reader for refs/",
  "type": "fs",                      // fs | exec
  "constraints": { … type-specific … },
  "expires_at": 1783810000,          // unix; never later than parent's
  "revoked": false,
  "created_by": "cap-root-fs",       // which token minted it
  "token_sha256": "…"                // broker stores only the hash
}
```

The chain `parent → child` is the delegation history; revoking a node revokes its
whole subtree (checked at invoke time by walking ancestors).

### 3.1 Capability types

**`fs`** — scoped filesystem access.

```json
{ "root": "/home/amiller/projects/oauth3/refs",
  "ops": ["list", "read"],           // subset of list|read|write|stat
  "max_bytes": 1048576 }             // per read/write, optional
```

Enforcement: every path argument is resolved (symlinks followed, `..` collapsed via
realpath) and must be inside `root` *after* resolution. Symlinks that escape the
root are rejected.

**`exec`** — scoped process execution on the broker's machine.

```json
{ "allow": [["git", "status"], ["ls"], ["rg"]],   // argv prefix allowlist
  "cwd_root": "/home/amiller/projects/oauth3",
  "timeout_s": 60, "max_output": 262144 }
```

Enforcement: the requested argv must extend one of the `allow` prefixes exactly
(`["git","status","--short"]` matches `["git","status"]`; `["git","push"]` does
not). No shell — argv is passed to `subprocess.run(list)` directly, so there is no
quoting/injection surface. `cwd` must resolve inside `cwd_root`.

**`net`** — scoped outbound network access *from the broker's machine*. The inverse
of the pod's shared openvpn-socks5 egress: instead of routing a remote agent's whole
traffic out one exit, this lends one specific dial-out as a capability. It exists
for the case where a remote agent needs the owner's *network position* (residential
IP, a LAN device, a service only reachable from home) rather than its files or shell.

```json
{ "allow": [["api.github.com", 443], ["10.0.0.5", 0]],  // (host, port) prefixes; port 0 = any
  "max_bytes": 10485760,                                 // per connection, optional
  "timeout_s": 30 }
```

Enforcement is a brokered CONNECT, **not a proxy handle**: the agent asks the broker
to open one TCP connection to an allowed `(host, port)`; the broker dials, then
relays bytes for that single connection and closes. `host` matches literally (no DNS
wildcards in v0 — an exact hostname or IP); `port` must equal an allowed port or the
entry's port is `0` (any). The agent never receives a socket, a SOCKS endpoint, or
the ability to open a second connection off the same grant — every connection is a
fresh `invoke` that re-checks the allowlist and is audited. This is the deliberate
non-answer to "just give it SOCKS5 back": a raw proxy is ambient L4 authority over
the whole home vantage; a `net` capability is a per-destination, per-connection,
revocable grant shaped exactly like `fs` paths and `exec` argv.

The three types are deliberately *deny-by-default and prefix-shaped*: the subset
relation needed for attenuation (3.2) is decidable by inspection.

### 3.2 Attenuation rules

`POST /caps/<id>/attenuate` with the parent token mints a child. The broker verifies
`child ⊆ parent` structurally; otherwise 403 with the violated field. No judgment
calls, no LLM in the loop at enforcement time.

- fs: `child.root` under `parent.root`; `child.ops ⊆ parent.ops`;
  `child.max_bytes ≤ parent.max_bytes`.
- exec: every `child.allow` entry must have some `parent.allow` entry as a prefix;
  `child.cwd_root` under `parent.cwd_root`; `child.timeout_s ≤`, `child.max_output ≤`.
- net: every `child.allow` entry `(h, p)` must be covered by some parent entry
  `(h, p')` where `h` is identical and `p' == 0` (parent allows any port) or
  `p' == p`; `child.max_bytes ≤ parent.max_bytes`, `child.timeout_s ≤`.
- all: `child.expires_at ≤ parent.expires_at`; same `type`.

Anyone holding a token can attenuate it further (delegation is not owner-only —
that's the point). What a token can never do is *widen*.

### 3.3 Roots

`capdel mint` (local CLI, no HTTP) creates root capabilities from nothing. Only the
operator at the broker machine can do this. Root caps are ordinary caps with
`parent: null` — the same subset rules apply below them.

### 3.4 Escalation (R5)

A token whose capability is too narrow can file a request against *its own* cap:

```
POST /caps/<id>/escalate   {"want": {…constraints…}, "reason": "need write to update the index"}
→ {"request_id": "req-…", "status": "pending"}
GET  /requests/<request_id>          (same token) → pending | denied | {"status":"approved","token":…,"cap":…}
```

The owner sees pending requests via `capdel requests` and rules with
`capdel approve req-… [--ttl …]` / `capdel deny req-…`. Approval mints the requested
constraints as a **fresh owner capability** (a new root, `parent: null`) — an
escalation exists precisely because the needed authority was *not* in the requester's
chain, so there is no ancestor to clamp against; the owner is the root of authority
and approving is the same act as `capdel mint`. The requesting agent polls and picks
up the new token; the lineage (which request, from which cap) is in the new cap's
name and the audit log. Batching = the owner rules on several at once; how the request
*reaches* the owner (poll, dashboard, push) is the open design axis — v0 is poll + CLI.

### 3.5 Discovery (R7)

`GET /caps/<id>` with the token returns the capability's own constraints and a
usage cheat-sheet (`how`: literal curl/python examples). A subagent that receives
only `CAPDEL_URL` + `CAPDEL_TOKEN` can bootstrap itself mid-flight — nothing needs
to be in the tool list at session start.

### 3.6 Audit + legibility (R6)

Every invoke/attenuate/escalate/deny is appended to `audit.jsonl`
(`ts, cap, op, args-digest, decision, latency`). `capdel tree` prints the live
grant tree with constraints and last-used; `capdel audit [--cap id]` tails the log.
These two views *are* the read-only dashboard for v0; an HTML rendering is v0.2.

### 3.7 Remote use (R4)

The broker binds localhost by default. Reaching it from a remote agent is the whole
point of R4 — but **the tunnel is transport, never authority**. Nothing about how
bytes reach the broker changes what a token is allowed to do; the tunnel only
determines who can *knock*, and the token determines what happens when they do.

**Principle: dial out, don't listen.** A SOCKS5 proxy or `ssh -R` that terminates at
the laptop hands the remote side raw L4 reach into the home network — exactly the
ambient over-grant `net` (§3.1) exists to replace. So the laptop broker makes an
**outbound** connection to a public rendezvous and serves capdel requests back down
it. No inbound ports, NAT-irrelevant, and revocation is "hang up the socket."

**The rendezvous is the pod (dogfooding).** oauth3's tee-daemon already hosts public,
attested apps, so the rendezvous is a small **relay app** on the pod rather than a
new piece of infrastructure:

```
remote agent ──HTTPS──▶ pod: /capdel-relay/<broker-id>/caps/<id>/invoke
                              │  (oauth3 app; reaching it is itself token-gated)
                              ▼
                        relay holds the laptop's live outbound WebSocket
                              │  forwards the request frame down it
                              ▼
   laptop: capdel broker ◀──WSS(dial-out)── relay
                              │  broker answers locally, frames the response back up
                              ▼
                        relay returns the HTTP response to the remote agent
```

- The laptop runs `capdel tunnel --relay https://pod…/capdel-relay --broker-id …`,
  which opens and keeps alive one WSS to the relay and pumps request/response frames
  to the local broker. Purely a byte mux — it parses nothing, enforces nothing.
- The relay app is ~a screenful: accept a broker's registration WSS, accept inbound
  HTTP for a registered `broker-id`, forward the request frame, await the matching
  response frame, reply. It never sees a capability or a decision — enforcement stays
  on the laptop, in the broker, where the authority actually is.
- Because the relay is an oauth3 app, **reaching the tunnel is itself a delegated,
  revocable capability** — the pod's own scoped-token gate sits in front of the
  capdel URL. Two independent layers now guard a remote invoke: the oauth3 token that
  lets you talk to the relay at all, and the capdel token that says what you may do.
  This is where PoP stops being theoretical: once warrants transit a public relay, a
  bearer token is replayable by the relay operator, so §8's holder-bound-token item
  becomes the natural next hardening.
- Off-the-shelf substitutes for the mux if you don't want to host the app: `ssh -R`
  to any box, or rathole/frp/chisel. Tailscale works but adds a third-party control
  plane; pagekite has shown 503s under load on zed. The pod relay is preferred
  precisely because it folds remote-reach into the same token model as everything
  else.

Tokens are bearer by default (v0); tunnel/TLS integrity is assumed from the transport (WSS +
the pod's in-TEE cert). **Holder-bound proof-of-possession is implemented** as an opt-in
HMAC-PoP scheme (`CAPDEL_POP=off|allow|require`, `capdel mint --pop`): the token becomes
an HMAC key that never re-crosses the wire; each request signs a canonical string over
method + broker-local path + body-hash + nonce + timestamp, so a token lifted from a relay
log or a captured request is useless (single-use nonces). See `tasks/pop-design-hmac.md`.
Asymmetric PoP (Ed25519, so the broker stores only a public key) is the reserved opt-in slot.

### 3.8 What the sandbox is for (R8)

Broker-side enforcement bounds what a token can *do to the owner's resources*.
It does not bound what the agent process does on its own machine. The two compose:
run the untrusted agent in Docker+gVisor / Deno with nothing but `CAPDEL_URL` and
`CAPDEL_TOKEN` in its environment, and its *only* route to the owner's world is the
brokered, audited, attenuated one. Per-capability cost is a JSON record, not a
container (the overhead comparison from the discussion — Deno ~shared runtime,
Docker ~30–50 MB, LXC weaker isolation — applies to confining agents, not to
capabilities).

## 4. Security model

- **Holder of a token** = the principal. Tokens are 128-bit random, broker stores
  only SHA-256. Loss of a token loses exactly its subtree of authority; `capdel
  revoke` kills a subtree immediately.
- **Prompt injection at draft time** (raised in the discussion): if the same agent
  drafts and uses a capability, injection can shape the draft. Mitigation is the
  trust differential itself (R1: drafting happens in the trusted agent's context)
  plus structural subset-checking — even a malicious draft cannot exceed the parent
  it attenuates. Root minting is offline-only.
- **The broker is TCB.** ~600 lines of stdlib Python, no deps, no shell, realpath
  containment, prefix-matched argv. Small enough to read.
- **Known v0 gaps**: bearer tokens are the default but **HMAC-PoP is implemented** (`--pop` /
  `CAPDEL_POP=require`) — the remaining gap is the *symmetric* cost: a PoP cap's secret is
  stored at rest in `~/.capdel` (the broker must hold it to verify), so reading the state
  dir yields usable keys (moot, since that read access already grants the real authority;
  asymmetric Ed25519-PoP removes it); no rate limits; fs `write`
  can fill a disk within max_bytes per call; exec allowlist can't constrain flags
  beyond prefix (allow `["rg"]` and any rg flags are fair game — write tighter
  prefixes or wrap in scripts); `net` matches host literally, so it can't express
  "any subdomain of x" and does nothing about a matched host resolving to an internal
  IP (pin IPs in the allowlist for SSRF-sensitive targets); audit log is unsigned.

## 5. HTTP API (v0)

```
POST /caps/<id>/invoke      Bearer <token>   {"op": …, …}         → result | 403
POST /caps/<id>/attenuate   Bearer <token>   {"constraints":…, "name":…, "ttl_s":…} → {id, token}
POST /caps/<id>/escalate    Bearer <token>   {"want":…, "reason":…}                → {request_id}
GET  /caps/<id>             Bearer <token>                        → self-description + how
GET  /requests/<rid>        Bearer <token of requesting cap>      → status [+ token]
```

fs invoke ops: `{"op":"list","path"}`, `{"op":"read","path"}`, `{"op":"write","path","content"}`,
`{"op":"stat","path"}`. exec invoke: `{"op":"run","argv":[…],"cwd"?,"stdin"?}` →
`{code, stdout, stderr, truncated}`. net invoke:
`{"op":"connect","host":…,"port":…,"send"?:<base64>}` → `{recv:<base64>, bytes, truncated}`
— one brokered TCP connection to an allowed `(host, port)`, optional bytes sent, reply
relayed back up to `max_bytes`, then closed.

Errors are always `{"error": …, "violated": …?}` with 4xx — no silent clamping;
a denied call names the constraint it hit so the agent can decide to escalate.

## 6. CLI (owner-side, local)

```
capdel serve [--bind 127.0.0.1:4571]
capdel tunnel --relay https://pod…/capdel-relay --broker-id NAME   # dial out to the pod relay (§3.7)
capdel mint fs   --root PATH --ops list,read [--ttl 4h] [--name …]     → prints id + token
capdel mint exec --allow "git status" --allow "ls" --cwd-root PATH …   → prints id + token
capdel mint net  --allow "api.github.com:443" --allow "10.0.0.5:*" …   → prints id + token
capdel tree | capdel audit [--cap ID] | capdel requests
capdel approve REQ [--ttl 1h] | capdel deny REQ | capdel revoke CAP
```

State: `$CAPDEL_HOME` (default `~/.capdel`), 0700: `caps/*.json`, `requests/*.json`,
`audit.jsonl`. CLI talks to the same state dir directly (no HTTP needed for owner ops).

## 7. Related work

- **oauth3** — same worldview (delegate a scoped revocable capability, never hand
  over the credential) applied to *web accounts/sessions*; capdel is the same move
  applied to *local OS authority* (files, processes, outbound network). Deliberately
  standalone.
- **AAuth** — the closest protocol-level neighbor; see §7.1.
- **UCAN / Biscuit** — offline-attenuable token formats; capdel v0 keeps attenuation
  online (broker-checked) for a smaller TCB, and could adopt Biscuit as the token
  engine later without changing the model (per the 2026-07-09 delegation-landscape
  survey).
- **MCP** — orthogonal: MCP describes tools to a model at session start; capdel is
  the authority behind a tool and is discoverable mid-flight (§3.5). A thin MCP
  server wrapping `invoke` is an obvious v0.2 so harnesses that only speak MCP can
  join.

### 7.1 AAuth findings (researched 2026-07-11)

**AAuth** ("Agent Auth") is by **Dick Hardt** — editor of OAuth 2.0 (RFC 6749),
co-author of OAuth 2.1. Site: https://www.aauth.dev/ · repo:
https://github.com/dickhardt/AAuth · IETF individual draft
`draft-hardt-oauth-aauth-protocol-09` (updated 2026-07-04, not yet WG-adopted).
His framing matches ours: agents "assemble toolchains dynamically at runtime …
making authorization decisions mid-task," and "OAuth is not a good fit for MCP."

Core mechanics: every client gets a self-assertable identity
(`aauth:local@domain` + published JWKS; self-hosted agents self-issue), and every
request is signed with HTTP Message Signatures (RFC 9421) — proof-of-possession
throughout, no bearer tokens. Four incremental access modes: identity-based →
resource-managed (the *resource* returns a 401 challenge with a `resource_token`
describing what access it needs — inverting OAuth's pre-registered-client model) →
PS-asserted (a "Person Server" represents the user and grants after consent) →
federated. Optional "missions": scoped authorization contexts spanning multiple
resources, re-checked at every step.

Where it lands against our requirements:

| Ours | AAuth |
|---|---|
| R2/R3 dynamic scope generation | **Partial-good**: scopes are free strings requested at runtime; the resource itself declares requirements. The exploratory "R3 Rich Resource Requests" doc (vocabulary-based, content-addressed requests in MCP/OpenAPI schemas) is the closest thing to our dynamic-scopes thesis. |
| R2 attenuation | **Absent.** No token-side narrowing (no UCAN/Biscuit-style derivation); narrowing means going back to the PS for a new token. This is capdel's core primitive and AAuth's clearest gap. |
| R1 delegation chains | **Shallow by design**: call-chaining (§10.1, `upstream_token`) and sub-agents (§10.2) exist, but "sub-agents MUST NOT request authorization directly" and depth is capped at one level — the parent signs everything. capdel's arbitrary-depth attenuation chain is out of scope for them. |
| R4 remote exec on owner's machine | **Not addressed.** Nearest: self-hosted agent provider + exploratory "AAuth Events" (async notify without public endpoints). Nothing runs anything *back on the user's device*. |
| R5 mid-task escalation | **Their signature strength.** Pending is a first-class state (202 + poll, §12.4); step-up re-challenge on an already-authorized request (§6.6.4); and a "clarification chat" (§7.3) — a markdown Q&A channel between the consenting user and the agent *during* the consent decision. Worth stealing for capdel's escalation flow (our `reason` string is the degenerate form). |

Implementations exist (TS reference SDK `aauth-dev/packages-js`; Christian Posta's
Python/Go libs, Keycloak extension, Person Server, and full demo with Agentgateway
as enforcement point — blog.christianposta.com). No TEE/attestation story anywhere.

**Position**: AAuth is HTTP-service-to-service agent auth with excellent
consent/escalation UX; capdel is local-authority brokering with attenuation as the
primitive. Complementary, not competing: capdel's broker could speak AAuth on the
wire (RFC 9421 request signing would replace bearer tokens — the v0.2 "DPoP-style"
item is exactly this), and AAuth's clarification-chat + 202-pending pattern is the
model for capdel escalation v0.2. What capdel has that AAuth doesn't: token-side
attenuation, arbitrary-depth chains, exec/fs authority (not just HTTP APIs), and
the reverse direction (remote agent → owner's machine).

## 8. v0.2+ roadmap

From the 2026-07-11 subagent trials (both passed 7/7; these are their UX notes):
denials should report *all* violated constraints, not short-circuit on the first;
the approved-escalation poll response should include the new cap's constraints and
expiry inline; escalate should return poll-interval guidance (`Retry-After`); the
`want` shape deserves a worked example in the cap self-description.


Pod relay app + `capdel tunnel` (§3.7) — the concrete R4 build: a Deno oauth3 app
that muxes remote HTTP to a laptop broker over a dial-out WSS, with the pod's own
scoped-token gate in front. DPoP-style holder-bound tokens (§4), promoted from
"tracked" to "needed" the moment tokens cross that relay — **now implemented** as HMAC-PoP
(`--pop` / `CAPDEL_POP=require`); the asymmetric Ed25519 slot (broker stores only a public
key, cannot forge for a holder) is reserved on the same framework. `net` capability
implementation (§3.1) beyond the spec — brokered CONNECT with per-connection audit.
Guard scripts attached at attenuation time (arbitrary predicates beyond
subset-shaped constraints — the "attach scripts that restrict" idea; needs its own
sandbox story). Notification hooks for escalations (Matrix). HTML read-only
dashboard. MCP wrapper. Resource quotas (CPU/mem/disk for exec; the "lend a friend's
agent limited resources" case). Signed audit.
