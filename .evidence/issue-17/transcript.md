# Tier-1 evidence — issue #17 (constant-time owner-secret comparison)

Three throwaway brokers were started from `capdel.py` (for capdel, running the broker IS
deploying it — see `.evidence/issue-5/transcript.md` for the same convention) and driven
end-to-end over HTTP. Raw requests/responses captured by `.evidence/issue-17/capture.sh`;
no value below is described-only.

Re-verified 2026-08-28 after rebase onto `origin/main` `095baf7` (#28, broker self-confinement):
re-ran `capture.sh` and `test/swarm.py` at the rebased code commit `f0ad1ba` — the 12-exchange
behavior matrix is byte-identical to the pre-rebase capture, and all pins below are from that re-run.

| Broker | Code | OWNER_SECRET | Port |
|---|---|---|---|
| A | this branch `f0ad1ba` | set (`owner-secret-e2e-issue17`) | 4781 |
| B | this branch `f0ad1ba` | **unset** | 4782 |
| C | `origin/main` `095baf7` (pre-change for the owner gate) | set (same secret) | 4783 |

## Pin — `GET /_api/version` (running broker's commit == this PR)

```
$ curl -s http://127.0.0.1:4781/_api/version
{"server": "capdel/0.1", "commit": "f0ad1ba", "pop_mode": "off", "schemes": ["bearer", "capdel-hmac-sha256"]}   [200]
$ curl -s http://127.0.0.1:4783/_api/version
{"server": "capdel/0.1", "commit": "095baf7", "pop_mode": "off", "schemes": ["bearer", "capdel-hmac-sha256"]}   [200]
$ curl -s http://127.0.0.1:4782/_api/version
{"server": "capdel/0.1", "commit": "f0ad1ba", "pop_mode": "off", "schemes": ["bearer", "capdel-hmac-sha256"]}   [200]
```

Assert: broker A/B report `commit` = `f0ad1ba` == this PR's code commit (evidence commit on top);
broker C reports `095baf7` == `origin/main` HEAD at capture time. ✓

## Code at the pinned commit (capdel.py:977)

```
return bool(OWNER_SECRET) and hmac.compare_digest(self._token().encode(), OWNER_SECRET.encode())
```

## [A3] Owner-gated routes behave identically before (C) and after (A)

Every owner route, each with no token / wrong token / valid token. A and C return byte-identical
status codes and bodies on all twelve exchanges:

| Route | Method | no token | wrong token | valid token |
|---|---|---|---|---|
| `/_tree` | GET | 401 | 401 | 200 `{"tree": []}` |
| `/_audit` | GET | 401 | 401 | 200 `{"audit": []}` |
| `/_event` | POST | 401 | 401 | 200 `{"event": "e2e-issue17", "closed": [], "count": 0}` |
| `/_gc` | POST | 401 | 401 | 200 `{"cleared": 0, "ids": []}` |

Raw responses (broker A, then C) — verbatim from the capture:

```
$ GET /_tree (no auth)                 -> {"error": "owner secret required"}                        [401]
$ GET /_tree (Bearer wrong-secret)     -> {"error": "owner secret required"}                        [401]
$ GET /_tree (Bearer <valid>)          -> {"tree": []}                                            [200]
$ GET /_audit (no auth)                -> {"error": "owner secret required"}                        [401]
$ GET /_audit (Bearer wrong-secret)    -> {"error": "owner secret required"}                        [401]
$ GET /_audit (Bearer <valid>)         -> {"audit": []}                                           [200]
$ POST /_event {"name":…} (no auth)    -> {"error": "owner secret required (closure events are owner-filed — a delegated holder cannot forge them)"}   [401]
$ POST /_event (Bearer wrong-secret)   -> {"error": "owner secret required (closure events are owner-filed — a delegated holder cannot forge them)"}   [401]
$ POST /_event (Bearer <valid>)        -> {"event": "e2e-issue17", "closed": [], "count": 0}       [200]
$ POST /_gc (no auth)                  -> {"error": "owner secret required"}                        [401]
$ POST /_gc (Bearer wrong-secret)      -> {"error": "owner secret required"}                        [401]
$ POST /_gc (Bearer <valid>)           -> {"cleared": 0, "ids": []}                                [200]
```

Identical twelve lines (status and body) from broker C at `095baf7`.

## [A2] `OWNER_SECRET is None` still refuses every owner endpoint

Broker B (same code, no `CAPDEL_OWNER_SECRET`). Even presenting the token that would be valid
on A/C is refused — `bool(OWNER_SECRET)` short-circuits before `compare_digest` runs:

```
$ GET /_tree (no auth)                 -> {"error": "owner secret required"}   [401]
$ GET /_tree (Bearer <would-be valid>) -> {"error": "owner secret required"}   [401]
$ GET /_audit (Bearer <would-be valid>)-> {"error": "owner secret required"}   [401]
$ POST /_event (Bearer <would-be valid>)-> {"error": "owner secret required (closure events are owner-filed — …)"}   [401]
$ POST /_gc (Bearer <would-be valid>)  -> {"error": "owner secret required"}   [401]
```

## Black-box regression

`python3 test/swarm.py` at `f0ad1ba` (re-run post-rebase): **13/14 passed, 1 skipped (Landlock, host kernel), 0 failed**.

## What could NOT be verified

The timing side-channel itself (secret length / shared-prefix leak) is not directly observable
over HTTP from this host; what is demonstrated is that the pinned commit uses
`hmac.compare_digest` for the owner check and that no owner-route behavior changed.
