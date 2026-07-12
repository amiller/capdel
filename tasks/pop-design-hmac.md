# capdel PoP — symmetric HMAC (DPoP-lite)

Design for issue #4. Concrete and implementable. Target: keep capdel stdlib-only
(`hmac`, `hashlib`, `secrets`), no new deps, no change to the mint/handoff UX.

## 0. Problem restated

Today a capability's token is a 128-bit random **bearer** string. The broker stores
only `sha256(token)`; a holder sends `Authorization: Bearer <token>` on every request.
The broker is trusted (owner's machine). The **relay** (`pod/relay.ts`) and the network
are untrusted: they see every request. A bearer token in transit is replayable by
anyone who sees it, and can be lifted from a log and reused forever.

**Goal.** Make the token a *secret key that never crosses the wire after mint*. Each
request carries an HMAC over a canonical string; the broker recomputes and verifies. A
per-request nonce + timestamp make a captured request non-replayable. Because the broker
is trusted, it may hold the key — that is the accepted cost of the symmetric approach.

---

## 1. Wire format

### 1.1 Canonical string

Signed message is six `\n`-joined fields, first field is a scheme tag for
domain-separation + versioning:

```
capdel-hmac-sha256
<METHOD>            e.g. POST
<PATH>              broker-local request-target, e.g. /caps/cap-3f9a/invoke  (incl. query if any)
<BODY_SHA256_HEX>   sha256 of the exact request-body bytes; empty body → sha256(b"")
<NONCE>             Capdel-Nonce header value (client random, 128-bit hex)
<TIMESTAMP>         Capdel-Timestamp header value (unix seconds, integer string)
```

Signature: `HMAC-SHA256(key = token_utf8, msg = canonical_utf8)`, lowercase hex.

**PATH is broker-local, not the public URL.** This is the one subtle rule. A remote
request hits the relay at `…/capdel-relay/b/<broker-id>/caps/<id>/invoke`, but the tunnel
strips `/b/<broker-id>` and the broker only ever sees `/caps/<id>/invoke`
(see `cmd_tunnel` → `local + job["path"]` in `capdel.py`, and relay.ts `cpath`). So the
client must sign **from `/caps` onward** — the same string the broker verifies —
regardless of relay prefix. The signing helper takes this path as an explicit argument
(`$CAPDEL_URL` carries the relay prefix; the signed path never does). This is why the
signature survives relay path-rewriting.

Body is hashed as **raw bytes on the wire** — no JSON canonicalization. The client hashes
exactly the bytes it sends; the broker hashes exactly the bytes it receives. (Consequence
for the helper: use `curl --data-binary`, never `-d`, which mangles newlines.)

### 1.2 Headers

PoP request carries three headers and **no `Authorization`** (the key never leaves the
holder):

```
Capdel-Nonce:     3b1e…            (secrets.token_hex(16))
Capdel-Timestamp: 1783810012
Capdel-Signature: 9f2c…            (hex HMAC-SHA256)
```

The capability id is already in the path, so no key-id header is needed; the broker loads
the cap from the path and uses its stored secret as the HMAC key.

### 1.3 Clock-skew window

`SKEW = 300` (5 min). Reject if `abs(now - timestamp) > SKEW`. Covers ordinary laptop /
pod clock drift; small enough that the replay-memory window stays tiny.

### 1.4 Nonce store (in-memory, TTL)

`{nonce: expiry_unix}` in a module dict behind a `threading.Lock` (the broker is a
`ThreadingHTTPServer`). On a *valid-signature* request, the nonce is inserted with
`expiry = max(now, timestamp) + SKEW`; if already present → replay → deny. A request with
timestamp `T` is acceptable during real-time `[T-SKEW, T+SKEW]`, so a nonce must be
remembered for at most `2*SKEW` (~10 min) — after that the timestamp check alone rejects
any replay. Lazy GC: sweep expired entries on each insert. Memory is bounded by request
rate × 2·SKEW, i.e. tiny.

**Order matters:** verify the HMAC *before* consuming the nonce, so an attacker cannot
burn/poison nonces with unsigned garbage.

**Known gap:** the store is in-memory, so a broker restart forgets nonces — a request
captured `< SKEW` ago becomes replayable once, until its timestamp ages out. Acceptable
for v0 (restarts are rare, window is 5 min); persist the store or shrink SKEW if it
matters.

### 1.5 What the broker stores per cap (changed)

HMAC verification is symmetric: the verifier needs the *key*, not a one-way hash of it.
So the broker can no longer keep only `token_sha256`. A PoP cap stores the raw secret:

```json
{
  "id": "cap-3f9a…",
  "parent": "cap-root-fs",
  "secret": "ct-1a2b…",        // NEW — the raw HMAC key
  "token_sha256": "…",         // kept: cap identity + bearer/allow-mode fallback
  "pop": true,                 // NEW — this cap requires PoP (per-cap override)
  "type": "fs", "constraints": {…}, "expires_at": …, "revoked": false, …
}
```

**Compromise implication.** At rest, state now contains *usable* keys, not just
preimage-resistant hashes. A leak/backup of `~/.capdel/caps/*.json` is a full key leak (an
attacker can forge any request). Under bearer-only, a leak gave only hashes — useless
without a preimage. This is the intrinsic at-rest cost of *symmetric* PoP, and it is
accepted because the broker is the TCB: anyone who can read `~/.capdel` already sits on the
machine that holds the real fs/exec/net authority the caps merely gate. Keep `~/.capdel`
0700 (already `chmod 0o700` in `ensure_home`). See §5 for the asymmetric alternative that
removes this cost.

---

## 2. The agent-friendliness crux

Today the whole point is a curl one-liner:

```
curl -H "Authorization: Bearer $CAPDEL_TOKEN" -d '{"op":"list","path":"…"}' $U/caps/$ID/invoke
```

HMAC signing breaks that one-liner. The fix is a **~15-line stdlib signer** the agent
writes once and then calls almost exactly like curl. The broker *ships the signer source
inside its own self-description*, so an agent that arrives with only `$CAPDEL_URL` +
`$CAPDEL_TOKEN` can still self-serve: it GETs the cap, gets the signer + usage lines, and
runs them.

### 2.1 `capdel-sign` (the helper — this is the literal file)

```python
#!/usr/bin/env python3
# capdel-sign METHOD PATH [BODY]  — signs and sends a capdel PoP request via curl.
# Needs env: CAPDEL_URL (may include a relay /b/<id> prefix), CAPDEL_TOKEN (the secret key).
import hashlib, hmac, os, secrets, subprocess, sys, time
tok  = os.environ["CAPDEL_TOKEN"].encode()
base = os.environ["CAPDEL_URL"].rstrip("/")
method, path = sys.argv[1].upper(), sys.argv[2]          # PATH is broker-local: /caps/<id>/invoke
body = sys.argv[3] if len(sys.argv) > 3 else ""
bh    = hashlib.sha256(body.encode()).hexdigest()
nonce = secrets.token_hex(16); ts = str(int(time.time()))
msg   = "\n".join(["capdel-hmac-sha256", method, path, bh, nonce, ts]).encode()
sig   = hmac.new(tok, msg, hashlib.sha256).hexdigest()
args  = ["curl", "-s", "-X", method, base + path,
         "-H", "Capdel-Nonce: "     + nonce,
         "-H", "Capdel-Timestamp: " + ts,
         "-H", "Capdel-Signature: " + sig]
if body:
    args += ["-H", "Content-Type: application/json", "--data-binary", body]  # --data-binary: exact bytes
sys.exit(subprocess.call(args))
```

The agent's per-call line is then barely longer than before:

```
./capdel-sign POST /caps/$ID/invoke '{"op":"read","path":"…"}'
```

No key on the wire, no dependencies, works identically for localhost and relayed
(`$CAPDEL_URL` absorbs the `/b/<broker-id>` prefix; the signed path stays `/caps/…`).

### 2.2 Exact new `how` the self-description returns

`GET /caps/<id>` (itself PoP-signed) returns, in PoP mode, a `how` that bootstraps the
signer. New `describe()` output for an `fs` cap:

```json
{
  "id": "cap-3f9a",
  "name": "reader for refs/",
  "type": "fs",
  "constraints": {"root": "/home/amiller/refs", "ops": ["list","read"]},
  "expires_at": 1783810000,
  "auth": "pop-hmac-sha256",
  "how": [
    "# 1) save the signer once (stdlib python, no deps):",
    "curl -s $CAPDEL_URL/capdel-sign > capdel-sign && chmod +x capdel-sign   # or paste sign_helper below",
    "# 2) point it at this broker + your key:",
    "export CAPDEL_URL=… CAPDEL_TOKEN=ct-…",
    "# 3) invoke — same shape as before, minus the Bearer header:",
    "./capdel-sign POST /caps/cap-3f9a/invoke '{\"op\":\"list\",\"path\":\"/home/amiller/refs\"}'",
    "./capdel-sign POST /caps/cap-3f9a/invoke '{\"op\":\"read\",\"path\":\"/home/amiller/refs/x\"}'",
    "./capdel-sign GET  /caps/cap-3f9a ''      # re-read this description"
  ],
  "sign_helper": "#!/usr/bin/env python3\nimport hashlib,hmac,os,secrets,subprocess,sys,time\n…(the ~15 lines above, inline so an offline agent needs no extra fetch)…",
  "escalate": "POST /caps/cap-3f9a/escalate {\"want\":{…},\"reason\":…} — sign it too"
}
```

`exec`/`net` are identical except for the op payloads (`{"op":"run","argv":[…]}`,
`{"op":"connect","host":…,"port":…}`). Two ways to obtain the signer are offered: a
`GET /capdel-sign` route the broker serves (static text of the file above), and the
inline `sign_helper` string for a fully offline / no-extra-round-trip bootstrap. An agent
with only URL + token + curl is still self-sufficient.

---

## 3. Mint & handoff; delegation with per-cap keys

**Mint / handoff is unchanged.** `capdel mint …` still prints `id` + `token` once; the
holder still receives it out-of-band and exports `CAPDEL_TOKEN`. The *only* difference is
that the token is now used as an HMAC key and never re-sent. Root secrets are generated
locally by the CLI and printed at the terminal — they never touch the wire at all.

**Each cap has its own key.** `mint()` already generates a fresh `token` per cap, so a
child gets a **new secret**, independent of the parent's. The broker verifies a child
request by loading the child cap from the path and HMAC-ing with *its* secret — the
parent key is never needed to use a child. Parent↔child links matter only for the subset
check at mint and the revocation walk at invoke (both unchanged).

**The handoff-over-relay subtlety.** `POST /caps/<parent>/attenuate` (PoP-signed with the
parent key) mints a child and must get the child's secret to the holder. Two modes:

- **(a) Simple / dev — return it in the response body.** Matches today. Fine over
  localhost or a trusted channel. **But** the attenuate response then carries a secret,
  and if attenuation is done *through the relay* the relay operator sees that child
  secret. So: don't attenuate over an untrusted relay in mode (a).

- **(b) Derived-key mode (recommended) — nothing secret is returned.** Define
  `child_secret = "ct-" + hmac_sha256(parent_secret, child_id)[:32]`. The broker computes
  and stores it at mint; the attenuate response returns **only `child_id`**. The parent
  holder — who has `parent_secret` — recomputes `child_secret` locally
  (`capdel-sign derive <child_id>`, three lines) and hands it to the subagent. The child
  secret is now **never transmitted**, so the relay never sees it. This is strictly better
  and barely more code; it is the recommended design. (A parent can always derive its
  descendants' keys — harmless, since child ⊆ parent means the parent could already invoke
  anything the child can.)

**Escalation.** `capdel approve` mints a **fresh root** (`parent: null`, random secret) —
there is no parent key to derive from, so its secret must reach the requester. If the
poll (`GET /requests/<rid>`) is answered over the relay, wrap the new secret under a key
derived from the *requesting* cap's token, which the relay does not know:
`wrapped = new_secret XOR HKDF(requester_secret, "escalation-resp", nonce)` where the
keystream is `HMAC(requester_secret, nonce || counter)` (stdlib). The requester unwraps
with its own key. v0 may instead simply require the approved-token poll to run over
localhost/trusted transport and return it plain — call it out explicitly.

---

## 4. Migration — bearer and PoP side by side

Global env `CAPDEL_POP` with three values, plus a per-cap `pop` override:

| `CAPDEL_POP` | behavior |
|---|---|
| `off` (default) | today's bearer-only. Nothing changes; existing flows unaffected. |
| `allow` | per-request: a request with `Capdel-Signature` → verify PoP; else with `Authorization: Bearer` → verify bearer. Lets a fleet migrate incrementally. |
| `require` | PoP mandatory; bearer rejected. |

Per-cap `pop: true` forces PoP for that cap even under `allow` (mint with `--pop`).
Legacy caps (no `secret`, only `token_sha256`) can only do bearer — so `require` is a
*new-caps* posture; run `allow` while old caps age out, or re-mint them with `--pop`.
Storage: bearer caps keep `token_sha256`; PoP caps add `secret`; an `allow`-mode cap may
carry both. The relay (`pod/relay.ts`) needs **no change** — it already forwards arbitrary
headers (`Authorization`, `Content-Type`) opaquely; add `Capdel-Nonce/Timestamp/Signature`
to its header passthrough allowlist (currently it only copies `Authorization` +
`Content-Type` — this is the one relay edit required).

---

## 5. Security analysis

**Stops:**

- **Relay/network replay.** A captured signed request replayed verbatim fails: its nonce
  is already consumed within the window, and once `now-timestamp > SKEW` the timestamp
  check rejects it outright. Captured request = single-use.
- **Token-in-log reuse.** The key never appears on the wire or in relay/access logs — only
  per-request signatures do, and each is single-use and bound to `(method, path, body,
  nonce, ts)`. HMAC is preimage-resistant, so the key can't be recovered from signatures.
- **Forging a *new* request** (different op, path, or body) by the relay or a network
  observer: impossible without the key. The relay can faithfully forward or drop, but it
  cannot author a request or alter one — any change to method/path/body/nonce/ts breaks
  the HMAC. It specifically cannot rewrite `read`→`write` or retarget one cap's signature
  at another cap.

**Does NOT stop:**

- **Broker compromise.** The broker stores the key (it must, to verify), so read access to
  `~/.capdel` yields all keys → full forgery. Symmetric PoP gives *zero* defense-in-depth
  at the broker vs. bearer's stored-hash. Accepted: the broker is the TCB and already holds
  the underlying authority; owning the broker box is game-over regardless of token scheme.
- **Confidentiality of request contents.** PoP is integrity + anti-replay, not encryption.
  The relay still sees plaintext bodies (which file, which argv, which host). The
  confidentiality leg is the transport: WSS + the pod's in-TEE cert (SPEC §3.7). The *key*
  is confidential unconditionally because it is never sent.
- **In-window replay across a broker restart** (§1.4) — in-memory nonce store.
- **Availability games** — the relay can still drop/delay/reorder; PoP doesn't address DoS.

**vs. asymmetric PoP (DPoP RFC 9449 / RFC 9421 / AAuth, SPEC §7.1):**

| | symmetric HMAC (this) | asymmetric (keypair) |
|---|---|---|
| broker stores | the secret key | only the public key |
| broker-at-rest compromise | forges everything | **cannot forge** (no private key at rest) |
| stdlib-only in Python | **yes** (`hmac`/`hashlib`) | no — needs EC/RSA (`cryptography`/`ecdsa`) |
| offline / third-party attenuation verify | no (broker-only) | yes (UCAN/Biscuit) |
| sig size / cost | 32 B, one hash | bigger, EC ops |

Because capdel's broker is **already trusted and already online for every check**,
symmetric PoP captures essentially all the practical value — no token on the wire,
anti-replay, no relay-forgery — at stdlib cost and zero new deps, fitting capdel's
"~600 lines, no deps" TCB. The single property it sacrifices (broker-at-rest key
compromise) is moot: that same read access already grants the real authority. Asymmetric
is the right move *only* if you later want the broker unable to impersonate holders, or
offline/third-party verification — out of scope for v0, and a clean later swap (the
canonical string + header shape stay; only the sign/verify primitive changes, which is
why the scheme tag `capdel-hmac-sha256` leads the canonical string).

---

## 6. Code sketch (real Python, drops into `capdel.py`)

```python
import hmac, threading   # hashlib, secrets, time already imported

SKEW = 300
POP_MODE = os.environ.get("CAPDEL_POP", "off")   # off | allow | require
_nonces, _nlock = {}, threading.Lock()           # nonce -> expiry unix ts

def _nonce_seen(nonce, ts):
    exp = max(now(), ts) + SKEW
    with _nlock:
        for n in [n for n, e in _nonces.items() if e < now()]:  # lazy GC
            del _nonces[n]
        if nonce in _nonces:
            return True
        _nonces[nonce] = exp
        return False

def verify_pop(cap, method, path, body_bytes, headers):
    sig   = headers.get("Capdel-Signature", "")
    nonce = headers.get("Capdel-Nonce", "")
    ts_s  = headers.get("Capdel-Timestamp", "")
    if not (sig and nonce and ts_s):
        raise Denied("missing PoP headers (Capdel-Signature/Nonce/Timestamp)")
    try:
        ts = int(ts_s)
    except ValueError:
        raise Denied("bad Capdel-Timestamp")
    if abs(now() - ts) > SKEW:
        raise Denied(f"timestamp outside ±{SKEW}s window")
    bh = hashlib.sha256(body_bytes).hexdigest()
    canonical = "\n".join(["capdel-hmac-sha256", method, path, bh, nonce, ts_s])
    expect = hmac.new(cap["secret"].encode(), canonical.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expect, sig):      # verify BEFORE consuming the nonce
        raise Denied("bad signature")
    if _nonce_seen(nonce, ts):
        raise Denied("nonce replay")
    return True
```

Handler integration — replace `_auth` with one that dispatches by mode. `body_bytes` is
the raw request body read *before* JSON parsing; `path` is `self.path` (already
broker-local, incl. query):

```python
def _authn(self, cid, method, body_bytes):
    cap = load(CAPS, cid)
    if not cap:
        return None
    per_cap = cap.get("pop")
    has_sig = "Capdel-Signature" in self.headers
    want_pop = (POP_MODE == "require") or per_cap is True or (POP_MODE == "allow" and has_sig)
    if want_pop:
        verify_pop(cap, method, self.path, body_bytes, self.headers)   # raises Denied
        return cap
    if POP_MODE != "require" and cap.get("token_sha256") \
            and hmac.compare_digest(sha(self._token()), cap["token_sha256"]):
        return cap                                                     # bearer (dev)
    return None
```

`do_POST` reads raw bytes once, then reuses them for both auth and JSON:

```python
n = int(self.headers.get("Content-Length") or 0)
raw = self.rfile.read(n) if n else b""
cap = self._authn(m.group(1), "POST", raw)   # inside the Denied try/except → 403 on bad sig
if not cap:
    return self._json(401, {"error": "unknown capability or failed PoP/bearer auth"})
body = json.loads(raw) if raw else {}
```

(`do_GET` is the same with `method="GET"`, `body_bytes=b""`.)

Mint change — derived child key + stored secret:

```python
def mint(type_, constraints, name, ttl_s, parent=None):
    validate_constraints(type_, constraints)
    expires = now() + ttl_s
    cid = "cap-" + secrets.token_hex(6)
    if parent:
        check_live(parent); check_subset(type_, constraints, parent)
        expires = min(expires, parent["expires_at"])
        secret = "ct-" + hmac.new(parent["secret"].encode(), cid.encode(),
                                  hashlib.sha256).hexdigest()[:32]      # derived: never sent
    else:
        secret = "ct-" + secrets.token_hex(16)                          # root: random, local only
    cap = {"id": cid, "parent": parent["id"] if parent else None, "name": name, "type": type_,
           "constraints": constraints, "expires_at": expires, "revoked": False,
           "secret": secret, "token_sha256": sha(secret), "pop": True,
           "created": now(), "last_used": None}
    save(CAPS, cap); audit(event="mint", cap=cid, parent=cap["parent"], name=name)
    return cap, secret
```

The signer (`capdel-sign`) is §2.1 verbatim; `derive` subcommand for mode (b):
`print("ct-" + hmac.new(os.environ["CAPDEL_TOKEN"].encode(), child_id.encode(), hashlib.sha256).hexdigest()[:32])`.
Serve it at `GET /capdel-sign` (static text) and inline it in `describe()["sign_helper"]`.

---

## 7. Implementation checklist

1. `verify_pop`, `_nonce_seen`, module globals (`SKEW`, `POP_MODE`, `_nonces`, `_nlock`).
2. `mint()`: store `secret`, derive child keys, set `pop`; keep `token_sha256`.
3. Handler: `_authn` dispatch; read raw body once in `do_POST`/`do_GET`; keep bad-sig
   inside the `Denied`→403 path.
4. `describe()`: `auth: "pop-hmac-sha256"`, helper-based `how`, `sign_helper`; add
   `GET /capdel-sign` route.
5. `pod/relay.ts`: add `Capdel-Nonce`/`Capdel-Timestamp`/`Capdel-Signature` to the header
   passthrough (the only relay edit).
6. CLI: `--pop` on `mint`; `capdel-sign` shipped in repo + `derive` subcommand.
7. Tests: valid sig passes; tampered body/path/method/nonce/ts → 403; replay (same nonce)
   → 403; stale timestamp → 403; relayed request (path `/b/<bid>/…` at relay, `/caps/…`
   at broker) verifies; bearer still works under `off`/`allow`; `require` rejects bearer.
```
