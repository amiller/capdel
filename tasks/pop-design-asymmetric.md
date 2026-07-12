# Proof-of-Possession for capdel — asymmetric (Ed25519) design

Issue #4. Draft, 2026-07-11. Implementable-from spec, not a survey.

## 0. Why, in one paragraph

Today a capability's credential is a 128-bit random **bearer** string; the broker
stores only its SHA-256 and a holder proves nothing but *possession of the string* on
each request (`Authorization: Bearer <token>`). The broker is trusted (owner's
machine). The **relay** (`pod/relay.ts`) and the network are not: every signed-nothing
request that transits the pod relay is a plaintext bearer token the relay operator can
**replay** — SPEC §3.7 / §4 flag this as the acute gap the moment tokens cross a public
relay. Proof-of-possession binds each capability to a **holder key** and signs each
request, so a captured request is not replayable and the token is useless without the
key. The **asymmetric** variant (this doc) additionally means the broker holds only a
*public* key: a compromised broker **or** relay can verify but **cannot forge** the
holder's requests — a property symmetric HMAC cannot give, because an HMAC verifier must
hold the same secret it would need to forge.

## 1. Crypto choice: vendored pure-Python Ed25519 (option a), with an optional self-tested accelerator

The constraint: Python's stdlib has **no** Ed25519 (no `nacl`, no curve arithmetic).
`hashlib` gives us SHA-512 (which Ed25519 uses internally) but not the group ops, so
"option (c) hashlib-only primitives" is not a real option — you still have to vendor the
curve. The real choice is (a) vendor the reference implementation vs (b) depend on
`cryptography`/`PyNaCl`.

**Pick (a): vendor the ~80-line public-domain djb reference** (`ed25519.py`, uses
`hashlib.sha512`). Justification, in capdel's own terms:

- capdel's entire pitch is "**~600 lines of stdlib Python, no deps, no shell, small
  enough to read**" and that this smallness *is* the TCB argument (SPEC §4). A
  `pip install cryptography` pulls in a large C/OpenSSL dependency that no reviewer of
  capdel will actually read — it would enlarge the TCB by orders of magnitude to shrink
  a file by 80 lines. Wrong trade for a reference monitor.
- "stdlib-only" is a distribution promise: `python3 capdel.py` works on a bare box, a
  remote worker, a scratch container, with nothing to install. A crypto dependency
  breaks exactly the low-friction dispatch capdel exists for.
- Option (b)'s "graceful degradation" is a **fallback** — forbidden here, and worse, a
  crypto fallback that silently downgrades verification is a security hole. We do not do
  that.

**The accelerator is not a fallback.** The naive reference `verify` is **~1.7 s per call**
(measured, CPython 3, RFC 8032 vector 2 — it recomputes a full modular inverse at every
point addition). That is too slow to leave as-is. Two stdlib-only fixes, in order of
preference: (i) a **projective/extended-coordinate** `scalarmult` that defers inversion to
one final `_inv` — same ~80 lines, ~20–50 ms/verify, still no dependency; ship this as the
vendored implementation. (ii) *If* `nacl` (libsodium) is importable, use it (~microseconds)
— but gated behind a
startup self-test that signs+verifies an **RFC 8032 test vector** through both the
vendored code and the accelerator and asserts byte-identical output; on any mismatch,
**crash** (`SystemExit`). Same algorithm, same result, proven at boot — an optimization,
not a degradation, and it fails loud rather than masking. Absent libsodium, the vendored
path is the one true implementation; PoP never silently weakens.

```python
try:
    import nacl.signing as _na          # optional accelerator only
    _ACCEL = True
except ImportError:
    _ACCEL = False
# ... at startup, verify _ACCEL agrees with vendored code on RFC 8032 vector 2 or die.
```

## 2. Wire format

### 2.1 Canonical signing string

Newline-joined, versioned, ASCII. Signed over the **broker-visible** request-target
(the path starting at `/caps/…`, i.e. *after* any relay `/b/<bid>` prefix is stripped —
see §4.4), so a request verifies identically whether it arrived directly or through the
pod relay:

```
capdel-sig-v1
<METHOD>                 e.g. POST
<PATH>                   e.g. /caps/cap-3f9a1c/invoke?x=1   (broker-visible, incl. query)
<BODY_SHA256_HEX>        hex(sha256(raw request-body bytes)); empty body → sha256(b"")
<KID>                    key id of the signing key (see 2.3)
<NONCE>                  base64url(16 random bytes)
<TS>                     unix seconds, integer
```

The signature covers **which capability** (path has the cap id), **what operation**
(body hash pins the exact JSON bytes), and **freshness** (nonce + ts). It deliberately
does *not* cover Host/relay identity, so the same signed request is valid end-to-end
across the tunnel. Cross-broker replay is out of scope for v0 (one broker); when multiple
brokers exist, add a `<BROKER_ID>` line — one-line change, one-line verify.

### 2.2 Headers

```
Capdel-Signature: <base64url(64-byte Ed25519 sig)>     # ~86 chars
Capdel-Key-Id:    <kid>                                # which bound/leaf key signed
Capdel-Nonce:     <base64url(16 bytes)>
Capdel-Timestamp: <unix seconds>
Capdel-Chain:     <base64url(json)>                    # OPTIONAL; offline delegation chain (§3, Model B)
```

There is **no `Authorization: Bearer`** on a pure PoP request — possession of the private
key *is* the credential. (A cap may be minted to require *both* a bearer token and a
signature as belt-and-suspenders during migration; §4.)

### 2.3 Key id

`kid = base64url(sha256(pubkey_32bytes))[:16]`. Stable, derivable by anyone from the
public key. The broker derives the expected kid from the cap's bound `holder_pubkey` and
rejects a mismatched `Capdel-Key-Id` early (cheap pre-filter before the expensive verify).

### 2.4 Body hashing

`sha256` over the **raw** Content-Length bytes the broker reads — never a re-serialized
JSON. Verified end-to-end because the relay forwards `await req.text()` unchanged and the
tunnel re-`.encode()`s it byte-for-byte (confirmed in `pod/relay.ts` + `cmd_tunnel`);
nothing reserializes the body, so the hash is stable across the hop.

### 2.5 Skew window

`abs(now - TS) <= CAPDEL_SKEW_S` (default **60 s**). Outside → `401 {"error":"stale or
future timestamp"}`. Bounds how long a captured request *could* be replayed even before
the nonce cache sees it.

### 2.6 Replay / nonce handling

In-memory `seen: dict[(kid,nonce) -> expiry]`, guarded by a `threading.Lock` (broker is a
`ThreadingHTTPServer`). On each PoP request, after the signature and skew checks pass:

- if `(kid,nonce)` present and unexpired → `401 {"error":"replayed nonce"}`;
- else insert with `expiry = now + 2*CAPDEL_SKEW_S` and prune expired entries.

Because `TS` must be within the skew window, the cache only needs to retain ~`2·skew`
seconds of nonces → **bounded memory** regardless of traffic. This is the property that
kills the relay: the relay can capture a valid signed request, but replaying it fails —
either the nonce is already burned or, after 60 s, the timestamp is stale. Restart empties
the cache, but the skew window still caps post-restart replay to 60 s (acceptable for v0;
persist the cache if that matters). This is the anti-teleport guarantee the delegation
survey and the Tenuo trial call for: a warrant is useless without the live holder key.

## 3. Key binding & delegated possession

### 3.1 Binding at mint / attenuate

A capability gains three fields:

```json
{ "pop": "ed25519",                       // "bearer" | "hmac-sha256" | "ed25519"
  "holder_pubkey": "<base64url 32 bytes>", // the bound verification key
  "token_sha256": null }                   // pure PoP: no bearer secret at all
```

- **CLI mint**: `capdel mint fs --root … --pop ed25519 --holder-pubkey <b64>`. Or
  `--pop ed25519 --gen-key` to have the CLI generate a keypair, **print the private seed
  once**, and bind the pubkey (mirrors how the token is printed once today).
- **HTTP attenuate**: `{"constraints":…, "pop":"ed25519", "holder_pubkey":"<b64>", "ttl_s":…}`.
  The child is bound to the **child's** pubkey — the sub-agent generates its own keypair
  and hands the parent only the public half.

### 3.2 How a holder generates & keeps its key

A keypair is a 32-byte seed (`CAPDEL_SK`, the private half, base64url) and the derived
32-byte pubkey. `capdel keygen` (or `capdel-sign keygen`, §5) prints both. Storage:

- **owner-held caps**: seed in `$CAPDEL_HOME/keys/<kid>.sk`, mode 0600.
- **dispatched sub-agent**: seed travels in the sub-agent's env as `CAPDEL_SK` (or a tmp
  file). Crucially it travels **once, at dispatch, over the trusted channel** — and
  **never crosses the relay again**: every subsequent request carries only a signature.
  Contrast the bearer world, where the secret itself crosses the relay on *every* call.

Two handoff shapes:

- **(i) dispatcher-generated (one step)**: the trusted dispatcher runs `keygen`, mints the
  cap against that pubkey, hands the sub-agent `CAPDEL_URL + cap-id + CAPDEL_SK`. The
  dispatcher (trusted) *could* impersonate the child; the relay/network cannot. Simplest.
- **(ii) sub-agent-generated (strongest)**: sub-agent runs `keygen`, returns its pubkey,
  dispatcher attenuates against it. The private key never leaves the sub-agent — nobody,
  not even the dispatcher, can forge its requests. One extra round-trip.

### 3.3 Delegated child proving possession — two models

**Model A — broker-registered (build this in v0.2).** Every `attenuate` registers the
child's `holder_pubkey` in the child cap record, exactly like `token_sha256` today.
Verification of a request is then trivial and unchanged in shape: load cap → the signer's
key *is* `cap.holder_pubkey`. Attenuation stays online (capdel already checks subsets at
the broker), so nothing new is needed beyond storing a pubkey instead of a token hash.

**Model B — offline signed chain (the UCAN/Biscuit convergence, roadmap).** A delegation
becomes a **signed statement** the parent key issues, no broker call:

```json
{ "grant":  { …child constraints, must be ⊆ parent… },
  "to":     "<child_pubkey>",
  "parent": "cap-3f9a1c",        // or the previous link's kid
  "exp":    1783810000,
  "sig":    "<parent-key signature over the above>" }
```

A **chain** is a list of these links, carried in `Capdel-Chain`. Any verifier — the broker,
or an offline auditor with no capdel state — checks:

1. link *i*'s `sig` verifies against link *i-1*'s `to` pubkey (root link verifies against
   the **root cap's** bound pubkey, or the **owner's** key);
2. `link[i].grant ⊆ link[i-1].grant` — **reusing capdel's existing `check_subset`
   verbatim** (fs root-under-root, exec argv-prefix, net host/port);
3. `link[i].exp` non-increasing;
4. the request's signing key (`Capdel-Key-Id`) == the **leaf** link's `to`.

Then verify the request signature against the leaf key. This is **offline-verifiable
attenuation**: the broker need never have seen the intermediate delegations — a sub-agent
can sub-delegate on a plane. That is precisely UCAN's/Biscuit's model. capdel converges
toward it *without adopting the format wholesale* because (a) the constraint language and
subset relation are already ours and stay identical, and (b) `check_subset` is the one
piece of enforcement logic, reused unchanged whether attenuation is checked online
(Model A) or over-a-chain (Model B). Adopting Biscuit later would swap only the
token *encoding*, not the model. v0.2 ships Model A; Model B is the next rung.

## 4. Migration: bearer (dev) + PoP, per-cap

### 4.1 Per-cap `pop` flag

`_auth(cid)` branches on the loaded cap's `pop` field:

- `"bearer"` (default, absent ⇒ this) → today's path exactly: `sha(token) ==
  token_sha256`. **The curl one-liner is untouched for local dev.**
- `"hmac-sha256"` → §2 canonical string, verified with `hmac.new(secret, msg, sha256)`
  (symmetric PoP; see §6 verdict).
- `"ed25519"` → §2 + Ed25519 verify against `holder_pubkey`.

The signing/replay framework (canonical string, headers, skew, nonce cache) is written
**once** and parameterized by algorithm; only the verify primitive differs. This lets us
ship HMAC-PoP trivially and Ed25519-PoP behind the same interface (see §6).

### 4.2 Policy: force PoP where it matters

`CAPDEL_REQUIRE_POP_VIA_RELAY=1`: the broker refuses a `bearer` cap on any request that
arrived through the relay (detected by the relay-injected `X-Capdel-Public-Base` header
that `cmd_tunnel` already sets). Result: bearer caps keep the frictionless curl path for
`127.0.0.1` dev, but are automatically rejected the moment they'd be replayable — exactly
the boundary SPEC §3.7 draws.

### 4.3 Attenuation may not downgrade auth strength

Order `bearer < hmac-sha256 < ed25519`. A child's `pop` must be `>=` its parent's. A
bearer cap can be attenuated *up* to PoP (fine); a PoP cap can **never** spawn a weaker
child (that would strip holder-binding off a subtree). Enforced alongside the existing
subset check in `check_subset`.

### 4.4 Relay path handling

The helper signs the **api-relative** path it is given (`/caps/$ID/invoke`) and sends the
HTTP request to `CAPDEL_URL + that path`, where `CAPDEL_URL` may be the relay base
(`…/capdel-relay/b/<bid>`). The broker sees `self.path == /caps/$ID/invoke` whether direct
or tunneled (relay strips `/b/<bid>`, tunnel replays `local + job.path`), so signer and
verifier agree with no URL-rewriting logic. No change to `relay.ts` is required.

## 5. Agent-friendliness (the crux) — `capdel-sign`

**The problem.** Today a curl-only agent self-serves from the `how` field: literal
`curl -H 'Authorization: Bearer …' -d '{…}' …/invoke`. Ed25519 signing **cannot** be a
curl one-liner — there is no `openssl` subcommand for it, unlike HMAC
(`openssl dgst -sha256 -hmac`). Something has to compute a signature. So PoP breaks the
pure-curl path harder than HMAC does. The fix is the **smallest possible signing helper**,
served *by the broker itself* and shown *inside* the `how` response.

**Smallest surface: one command that signs-and-sends.** A ~45-line stdlib script,
`capdel-sign`, fetched unauthenticated from the broker (public helper, like a JS bundle):

```sh
curl -s $CAPDEL_URL/capdel-sign -o capdel-sign        # once, first run
export CAPDEL_URL CAPDEL_TOKEN_SK=<seed>              # the cap's private seed
python3 capdel-sign /caps/$ID/invoke '{"op":"read","path":"/w/x"}'   # signs + POSTs + prints JSON
python3 capdel-sign /caps/$ID                          # GET (no body) — discovery
python3 capdel-sign keygen                             # prints seed + pubkey
```

It builds the §2 canonical string, signs with the vendored Ed25519 using
`CAPDEL_TOKEN_SK`, sets the four headers, and does the request via `urllib`. One line per
call — nearly as short as the old curl, and the agent never touches crypto details.
(Agents that already have `capdel.py` can instead run `python3 capdel.py client
/caps/$ID/invoke '{…}'` — same code, no fetch.)

**New self-description.** `describe()`'s `how` for a `pop:"ed25519"` cap becomes:

```json
"how": [
  "# one-time: fetch the signer",
  "curl -s $CAPDEL_URL/capdel-sign -o capdel-sign",
  "# this cap needs a signature, not a bearer token. Set your key seed:",
  "export CAPDEL_URL=… CAPDEL_TOKEN_SK=<the seed you were handed>",
  "# then every call is one line (signs + sends):",
  "python3 capdel-sign /caps/cap-3f9a1c/invoke '{\"op\":\"list\",\"path\":\"/w\"}'",
  "python3 capdel-sign /caps/cap-3f9a1c        # re-read this description"
]
```

New route: `GET /capdel-sign` → the helper script text, `text/plain`, no auth. (It's
public code; serving it is what makes cold-start self-service survive PoP.)

**Honest verdict — asymmetric vs HMAC, is the friction worth it?**

For capdel's *stated* threat model — broker **trusted**, relay/network the adversary —
**HMAC-PoP already closes the actual hole**: the relay sees only MAC'd requests with
burned nonces and cannot replay or forge new ones. HMAC is dramatically more
agent-friendly (stdlib `hmac`, an *almost*-curlable `openssl` path, no vendored curve)
and adds nothing to the TCB. If closing relay-replay were the *only* goal, HMAC wins and
Ed25519 is over-engineering.

Asymmetric earns its extra cost on two things HMAC structurally **cannot** do:

1. **Broker/relay can't forge.** An HMAC verifier must hold the same secret it would use
   to forge — so an HMAC cap makes the broker (and anyone who reads its state) able to
   impersonate the holder. Ed25519 keeps only a *public* key at the broker: a compromised
   broker or a malicious relay can verify but never mint the holder's requests. This moves
   the broker *out* of the forgery TCB — a strictly stronger posture than "broker is
   trusted," useful precisely when you're not fully sure it is.
2. **Offline-verifiable chains (§3 Model B).** A shared secret can't anchor a chain a
   third party verifies without being handed the secret. Public keys make delegation
   chains auditable by anyone — the UCAN/Biscuit convergence, and capdel's roadmap.

**Recommendation:** build the §4.1 framework once; ship **HMAC-PoP as the default v0.2
hardening** (cheap, curl-adjacent, kills the in-scope relay-replay threat today) and
**Ed25519-PoP as the opt-in** for the "don't trust the broker" posture and the offline-chain
future. Asymmetric is worth the agent friction *if and only if* you are committing to those
two properties; for the relay threat alone it is not. Since issue #4 asks specifically for
the asymmetric design, it is fully specified here — but the honest engineering call is to
gate the heavier mechanism behind the value it uniquely delivers.

## 6. Code sketch

### 6.1 Vendored Ed25519 (public-domain djb reference, ~stdlib SHA-512)

```python
import hashlib
_b, _q = 256, 2**255 - 19
_l = 2**252 + 27742317777372353535851937790883648493
def _H(m): return hashlib.sha512(m).digest()
def _expmod(b, e, m):
    if e == 0: return 1
    t = _expmod(b, e // 2, m) ** 2 % m
    return t * b % m if e & 1 else t
def _inv(x): return _expmod(x, _q - 2, _q)
_d = -121665 * _inv(121666) % _q
_I = _expmod(2, (_q - 1) // 4, _q)
def _xrecover(y):
    xx = (y * y - 1) * _inv(_d * y * y + 1)
    x = _expmod(xx, (_q + 3) // 8, _q)
    if (x * x - xx) % _q != 0: x = x * _I % _q
    return _q - x if x % 2 else x
_By = 4 * _inv(5) % _q
_B = [_xrecover(_By) % _q, _By % _q]
def _edwards(P, Q):
    x1, y1 = P; x2, y2 = Q
    return [(x1*y2 + x2*y1) * _inv(1 + _d*x1*x2*y1*y2) % _q,
            (y1*y2 + x1*x2) * _inv(1 - _d*x1*x2*y1*y2) % _q]
def _scalarmult(P, e):
    if e == 0: return [0, 1]
    Q = _scalarmult(P, e // 2); Q = _edwards(Q, Q)
    return _edwards(Q, P) if e & 1 else Q
def _bit(h, i): return (h[i // 8] >> (i % 8)) & 1
def _encodeint(y): return bytes(sum((y >> (8*i + j) & 1) << j for j in range(8)) for i in range(_b // 8))
def _encodepoint(P):
    x, y = P
    bits = [(y >> i) & 1 for i in range(_b - 1)] + [x & 1]
    return bytes(sum(bits[8*i + j] << j for j in range(8)) for i in range(_b // 8))
def _Hint(m):
    h = _H(m); return sum(2**i * _bit(h, i) for i in range(2 * _b))
def _secret_scalar(h):
    return 2**(_b - 2) + sum(2**i * _bit(h, i) for i in range(3, _b - 2))
def publickey(sk32):                       # sk32 = 32-byte seed
    h = _H(sk32); return _encodepoint(_scalarmult(_B, _secret_scalar(h)))
def sign(m, sk32, pk):
    h = _H(sk32); a = _secret_scalar(h)
    r = _Hint(h[_b // 8:_b // 4] + m); R = _scalarmult(_B, r)
    S = (r + _Hint(_encodepoint(R) + pk + m) * a) % _l
    return _encodepoint(R) + _encodeint(S)
def _decodeint(s): return sum(2**i * _bit(s, i) for i in range(_b))
def _isoncurve(P):
    x, y = P; return (-x*x + y*y - 1 - _d*x*x*y*y) % _q == 0
def _decodepoint(s):
    y = sum(2**i * _bit(s, i) for i in range(_b - 1)); x = _xrecover(y)
    if x & 1 != _bit(s, _b - 1): x = _q - x
    P = [x, y]
    if not _isoncurve(P): raise ValueError("point not on curve")
    return P
def verify(sig, m, pk):                    # returns True or raises
    if len(sig) != 64 or len(pk) != 32: raise ValueError("bad length")
    R = _decodepoint(sig[:32]); A = _decodepoint(pk); S = _decodeint(sig[32:])
    h = _Hint(sig[:32] + pk + m)
    if _scalarmult(_B, S) != _edwards(R, _scalarmult(A, h)):
        raise ValueError("signature failed verification")
    return True
```

Notes: seed-based (`CAPDEL_SK` = the 32-byte seed, base64url), matching §3.2. **Verified
correct** against RFC 8032 vector 2 (pubkey, signature, and verify all match byte-for-byte;
tampered message rejected). This *naive* form measures **~1.7 s/verify** — replace
`_scalarmult`/`_edwards` with extended-coordinate arithmetic (one deferred `_inv`) for
~20–50 ms before shipping (§1); the libsodium accelerator (self-tested identical at boot)
is for real throughput. Startup self-test against the RFC 8032 vector before serving any
PoP cap.

### 6.2 Broker-side verify (drop into `Handler`, replaces `_auth` for PoP caps)

```python
import base64, time, threading
_b64u  = lambda x: base64.urlsafe_b64encode(x).rstrip(b"=").decode()
_unb64 = lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
SKEW = int(os.environ.get("CAPDEL_SKEW_S", "60"))
_seen, _seen_lock = {}, threading.Lock()

def _kid(pub): return _b64u(hashlib.sha256(pub).digest())[:16]

def verify_pop(cap, method, path, body_bytes, headers):
    pub = _unb64(cap["holder_pubkey"])
    kid, sig = headers.get("Capdel-Key-Id", ""), headers.get("Capdel-Signature", "")
    nonce, ts = headers.get("Capdel-Nonce", ""), headers.get("Capdel-Timestamp", "")
    if not (sig and nonce and ts): raise Denied("missing PoP signature headers")
    if kid != _kid(pub): raise Denied("key id does not match the bound holder key")
    if abs(now() - int(ts)) > SKEW: raise Denied("stale or future timestamp")
    bh = hashlib.sha256(body_bytes).hexdigest()
    msg = "\n".join(["capdel-sig-v1", method, path, bh, kid, nonce, ts]).encode()
    verify(_unb64(sig), msg, pub)          # vendored Ed25519; raises on mismatch
    key, exp = (kid, nonce), now() + 2 * SKEW
    with _seen_lock:
        _seen_prune()
        if key in _seen: raise Denied("replayed nonce")
        _seen[key] = exp

def _seen_prune():
    t = now(); [_seen.pop(k) for k, e in list(_seen.items()) if e < t]
```

`_auth` gains a branch: `if cap.get("pop","bearer") == "ed25519":
verify_pop(cap, self.command, self.path, raw_body, self.headers)` and returns the cap on
success. The `raw_body` must be captured before JSON-parsing (hash the exact bytes).

### 6.3 The `capdel-sign` helper (served at `GET /capdel-sign`)

```python
#!/usr/bin/env python3
# capdel-sign — sign one capdel request with an Ed25519 holder key and send it.
# usage: capdel-sign <api-path> [json-body]   |   capdel-sign keygen
import os, sys, json, time, base64, hashlib, secrets, urllib.request
# --- vendored ed25519 (publickey, sign) inlined here, ~40 lines, see §6.1 ---
_b64u  = lambda x: base64.urlsafe_b64encode(x).rstrip(b"=").decode()
_unb64 = lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def main():
    if sys.argv[1] == "keygen":
        sk = secrets.token_bytes(32); pk = publickey(sk)
        print("CAPDEL_SK=" + _b64u(sk)); print("pubkey=" + _b64u(pk)); return
    url  = os.environ["CAPDEL_URL"].rstrip("/")
    sk   = _unb64(os.environ["CAPDEL_TOKEN_SK"]); pk = publickey(sk)
    path = sys.argv[1]
    body = sys.argv[2].encode() if len(sys.argv) > 2 else b""
    kid   = _b64u(hashlib.sha256(pk).digest())[:16]
    nonce = _b64u(secrets.token_bytes(16)); ts = str(int(time.time()))
    method = "POST" if body else "GET"
    bh  = hashlib.sha256(body).hexdigest()
    msg = "\n".join(["capdel-sig-v1", method, path, bh, kid, nonce, ts]).encode()
    sig = _b64u(sign(msg, sk, pk))
    req = urllib.request.Request(url + path, data=body or None, method=method, headers={
        "Capdel-Signature": sig, "Capdel-Key-Id": kid,
        "Capdel-Nonce": nonce, "Capdel-Timestamp": ts,
        "Content-Type": "application/json"})
    try:
        print(urllib.request.urlopen(req, timeout=30).read().decode())
    except urllib.error.HTTPError as e:
        print(e.read().decode()); sys.exit(1)

if __name__ == "__main__": main()
```

## 7. Security analysis

**What asymmetric PoP buys (over bearer and over HMAC):**

- **Anti-replay / anti-teleport (vs bearer):** a captured request can't be reused — nonce
  burned or `ts` stale within 60 s. The relay operator's replay power (SPEC §3.7/§4)
  is gone. Same as HMAC-PoP.
- **Broker & relay cannot forge (vs bearer *and* HMAC):** the broker stores only a public
  key. A compromised broker, a malicious relay, or a leak of broker state cannot mint the
  holder's requests. HMAC cannot offer this — its verifier holds the forging secret. This
  is the headline asymmetric advantage and the reason to pay the friction.
- **True holder binding:** the private key is the principal and **never crosses the relay**
  — only signatures do. Stealing the token-at-rest on the wire yields nothing.
- **Offline-verifiable chains (§3 Model B):** public keys let any third party audit a
  delegation chain; enables client-side attenuation (UCAN/Biscuit convergence) without a
  broker round-trip.

**Costs (honest):**

- **Vendored crypto in the TCB:** +~80 lines of curve arithmetic to read/trust. Mitigated:
  it's the well-known public-domain reference, self-tested against RFC 8032 vectors at
  boot, and still stdlib-only (no dependency added).
- **Agent friction:** the pure-curl path dies for PoP caps; agents need `capdel-sign`
  (§5). This is real and is why bearer stays the local-dev default (§4.2).
- **Pure-Python latency:** the naive reference is ~1.7 s/verify (measured) — unusable
  as-is; the extended-coordinate rewrite (§1, ~20–50 ms) or the libsodium accelerator is
  effectively required. HMAC verify, by contrast, is microseconds.
- **Key distribution & nonce state:** a private seed must reach the sub-agent (once, over
  the trusted channel, never via relay); the nonce cache is in-memory (skew still bounds
  post-restart replay).

**What PoP does *not* fix:** a compromised **holder** (whoever holds the private key *is*
the principal — key theft = full impersonation of that subtree); **confidentiality against
the broker** (broker is trusted and sees plaintext requests/results — out of scope); and
the relay **seeing or dropping** traffic (that's TLS + availability, not integrity — PoP
is anti-forge/anti-replay, not anti-eavesdrop). Audit log remains unsigned (separate item).

## 8. Concrete build order (v0.2)

1. Framework: canonical string + headers + skew + nonce cache, algorithm-parameterized (§2, §4.1).
2. HMAC-sha256 verify path (`hmac` stdlib) — ship, closes relay-replay cheaply.
3. Vendored Ed25519 (§6.1) + boot self-test + optional libsodium accelerator (§1).
4. `pop`/`holder_pubkey` cap fields; `_auth` branch; `mint`/`attenuate` binding; `keygen` CLI (§3).
5. `GET /capdel-sign` route + `capdel client` subcommand; PoP `how` self-description (§5).
6. `CAPDEL_REQUIRE_POP_VIA_RELAY` policy + attenuation strength-ordering (§4.2–4.3).
7. (Roadmap) Model B offline signed chains reusing `check_subset` (§3.3).
```
