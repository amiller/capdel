# capdel conformance suite

`vectors.json` defines capdel's behavior as language-neutral **conformance vectors** —
sequences of `mint / invoke / attenuate / escalate / approve / event` over the HTTP wire
protocol, each with an expected verdict (status, allow/deny, result fields). `run.py` drives
them against *any* spec-compatible broker.

The point is **cross-validation**: the same vectors run against two independent
implementations (`capdel.py`, `capdel.ts`). Identical verdicts on both ⇒ the SPEC is
unambiguous on that surface. A divergence is a spec bug or an impl bug — the backpressure
that keeps `SPEC.md` honest as it evolves. The suite is the spec's teeth; it is worth having
even with one implementation, because it makes the spec executable.

## Run

```bash
python3 conformance/run.py --broker python     # reference (stdlib-only python)
python3 conformance/run.py --broker deno        # deno/ts port  (needs deno on PATH)
python3 conformance/interop.py                  # byte-exact cross-impl crypto interop
```

All three are hermetic — a tempdir only, never `~/.capdel` — and exit non-zero on any fail.
Current status: **run 52/52 on both brokers; interop 7/7.**

## What it covers

- fs / exec / net cap **authorization** (path escape, argv-prefix, host/port) and
  **attenuation subset** rules (narrow ok, widen denied), incl. adversarial dot-dot / widen vectors.
- **PoP** (`capdel-hmac-sha256`): valid signature passes; tampered body/path/method/nonce,
  stale timestamp, and nonce replay are all rejected; `--pop` caps reject bearer; `require`
  mode rejects bearer and accepts PoP.
- **escalation** round-trip (deny → escalate → owner `approve` → fresh grant works) and
  **trusted closure** (owner `event` revokes the subtree).
- **interop** (`interop.py`): a PoP cap minted by one broker is verified + attenuated by the
  other on shared on-disk state, and the derived child secret matches
  `ct-` + `HMAC(parent_token, child_id)[:32]` byte-for-byte in both directions. This is the
  highest-value check — canonical-string and key-derivation ambiguity is the classic
  underspecification bug (cf. JWT/JOSE), and two impls force it to be pinned.

## Not yet covered (follow-on vectors)

`llm` cap (needs a live key), the dial-out tunnel/relay, `gc` + request-TTL expiry,
`max_bytes` truncation edges, symlink (vs dot-dot) escapes, and the exact `describe` `how`
hint strings (deliberately unasserted — they are guidance, not authority semantics). Add
these to `vectors.json`; both impls must stay green.

## The spec cleave this makes explicit

Everything here is **authority semantics** — portable and cross-validatable. What is *not*
in these vectors is **enforcement** (Deno `--allow-*`, kernel Landlock/seccomp, sandboxing):
that is platform-specific by nature and belongs in a platform annex, not the wire spec. The
suite draws the line: authority is specified and conformance-tested; enforcement is not.

## Running the Deno broker in a pod

`capdel.ts` is dependency-free (`deno run -A capdel.ts serve --bind 0.0.0.0:8080`) and uses
only `Deno.serve` + WebCrypto, so it runs unchanged as a dstack-webhost/pod app. The
owner-gated `POST /_mint` lets the whole protocol be driven over HTTP where there is no shell
to run `capdel mint`.
