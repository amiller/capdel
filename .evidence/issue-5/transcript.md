# Tier-1 evidence — issue #5 (event-driven closure)

A throwaway broker was started from this branch's `capdel.py` (the broker IS the local
reference monitor — for capdel, running it is deploying it) and driven end-to-end over HTTP.
These are the real requests/responses, not mocked or described. The black-box regression is
`test/closure.py` (13/13 PASS) and `test/swarm.py` (14/14 PASS, no regression).

Branch HEAD at run time: `04e63c013a500f87b8dee0a48b2130e16743a6c2`

## Pin — `GET /_api/version` (running broker's commit == this PR)

```
$ curl -s http://127.0.0.1:4661/_api/version | python3 -m json.tool
{
    "server": "capdel/0.1",
    "commit": "04e63c0",
    "pop_mode": "off",
    "schemes": ["bearer", "capdel-hmac-sha256"]
}
```

Assert: `commit` = `04e63c0` == branch short SHA `04e63c0`. ✓ [A5]

## Setup — mint capA (`--closes-on build-passed`) and capB (control, no closure)

```
$ python3.11 capdel.py mint fs --root $ROOT --ops list,read,write --ttl 20m --name capA --closes-on build-passed
id=cap-2a207352b890
token=ct-329c7719c2aac3e474a3adfb5d6f6dc9
expires_at=1783834397
```

## [A1] Attenuate a child of capA that adds its own event `phase-exit`

```
$ curl -s -H "Authorization: Bearer $AT" -d '{"constraints":{"root":"...","ops":["read"]},"closes_on":["phase-exit"]}' \
       $U/caps/cap-2a207352b890/attenuate | python3 -m json.tool
{
    "id": "cap-2fa7d7a0e834",
    "token": "ct-d232bc78d215e5a406659987671d7fbb",
    "expires_at": 1783834397,
    "pop": false,
    "closes_on": ["phase-exit"]
}
```

## [A1] Self-description reports EFFECTIVE (inherited) `closes_on`

```
# capA (root) — its own declared events:
$ curl -s -H "Authorization: Bearer $AT" $U/caps/cap-2a207352b890 | python3 -c 'import sys,json;print(json.load(sys.stdin)["closes_on"])'
['build-passed']

# child — inherited build-passed ∪ own phase-exit:
$ curl -s -H "Authorization: Bearer $CT" $U/caps/cap-2fa7d7a0e834 | python3 -c 'import sys,json;print(json.load(sys.stdin)["closes_on"])'
['build-passed', 'phase-exit']
```

## Baseline — capA and capB both read OK before any event

```
capA read: HTTP 200
capB read: HTTP 200
```

## [A4] Firing an event requires the OWNER secret (a holder's cap token is refused)

```
# authenticating with capA's own capability token, not the owner secret:
$ curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $AT" -X POST -d '{"name":"build-passed"}' $U/_event
401
```

## [A2] Owner fires `build-passed` → capA auto-revokes (count 1); capB untouched

```
$ curl -s -H "Authorization: Bearer owner-secret" -X POST -d '{"name":"build-passed"}' $U/_event | python3 -m json.tool
{
    "event": "build-passed",
    "closed": ["cap-2a207352b890"],
    "count": 1
}
```

## [A3] After the event: capA denied (revoked); child denied (cascade); capB still works (control)

```
capA  invoke: HTTP 403  {"error": "denied", "violated": "capability cap-2a207352b890 is revoked"}
child invoke: HTTP 403  {"error": "denied", "violated": "capability cap-2a207352b890 is revoked"}   # cascade via ancestor
capB  invoke: HTTP 200                                                                                   # control, unaffected
```

## CLI path — `capdel event phase-exit` fires from the owner shell

```
$ python3.11 capdel.py event phase-exit
event 'phase-exit': closed 1 cap(s): cap-2fa7d7a0e834
```

## `capdel tree` — REVOKED state + effective `closes-on` per node

```
cap-2a207352b890  'capA'  fs list,read,write /tmp/tmp.XERXZZuiuC  [REVOKED, last used 0m ago, closes-on:build-passed]
  cap-2fa7d7a0e834  'child of cap-2a207352b890'  fs read /tmp/tmp.XERXZZuiuC  [REVOKED, closes-on:build-passed,phase-exit]
cap-82cc67b8cdff  'capB-control'  fs list,read,write /tmp/tmp.XERXZZuiuC  [expires in 20m, last used 0m ago]
```

## Acceptance recap (derived from issue #5 — it carried no `## Acceptance`)

- **A1** caps declare `closes_on`; self-description shows the effective (inherited) set. ✓
- **A2** a trusted event auto-revokes every cap whose `closes_on` lists it; cascade hits descendants. ✓
- **A3** closed cap → 403 `revoked`; a non-closing sibling keeps working. ✓
- **A4** only the owner can file an event (holder token → 401). ✓
- **A5** `GET /_api/version` pins the running broker to this PR's commit. ✓

## What was NOT verified here

- PoP (`--pop`) caps also carry `closes_on` (the closure path is type/auth-agnostic and the
  closure test exercises bearer caps only); the swarm test still passes, and PoP + closure share
  no code path, but a PoP+closure combo was not separately walked.
- Remote/relayed firing of `/_event` through the pod tunnel — out of scope for this issue; the
  endpoint is owner-secret-gated exactly like the existing `/_tree` and `/_audit` remote reads.
- The repo targets Python 3.9+ (uses `str.removeprefix`); this box's default `python3` is 3.8, so
  verification used `~/.local/bin/python3.11`. Not a behavior change — just the local interpreter.
