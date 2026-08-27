# issue #9 evidence — tier 1+2 (host: zed, docker 24.0.7)

```
$ git rev-parse --short HEAD && python3.11 test/scenario.py
6bd598c

  swarm test (broker 127.0.0.1:51339, echo :33227) — 14 checks
  ----------------------------------------------
  [PASS] reader: read own file
  [PASS] reader: read OTHER root denied
  [PASS] reader: write denied (read-only)
  [PASS] writer: write own root
  [PASS] writer: read OTHER root denied
  [SKIP] exec: ls allowed
         SKIP (host kernel lacks Landlock; VM tier covers this)
  [PASS] exec: rm denied (not allowlisted)
  [PASS] net: connect allowed host:port echoes
  [PASS] net: connect other port denied
  [PASS] escalator: initial write denied
  [PASS] escalator: escalate accepts delta
  [PASS] escalator: approval yields new creds
  [PASS] escalator: write works with new cap
  [PASS] escalator: OLD token still denied
  ----------------------------------------------
  13/14 passed, 1 skipped, 0 failed

== scenario: checkout commit 6bd598c
== tier 1: test/swarm.py (in-process swarm, ephemeral broker)

== tier 2: compose up broker+echo (owner host on 127.0.0.1:36999)
   version pin: /_api/version commit == 6bd598c == checkout 6bd598c  [OK]
== tier 2: mint 5 differently-scoped caps over POST /_mint (owner secret)
   minted reader     -> cap-51068782a3b9
   minted writer     -> cap-852bfbe17cd8
   minted exec       -> cap-dd74df8eaef8
   minted net        -> cap-330a0bbc0e21
   minted escalator  -> cap-bf49c9a86a34
== tier 2: launch all 5 workers concurrently (single `compose up`)
== tier 2: owner approves the escalation WHILE workers keep invoking
   approved req-2ce0f1b8df72 (escalator wanted ['list', 'read', 'write'])
== tier 2: collect worker matrices
  [PASS] reader:list own root (got 200, want 200)
  [PASS] reader:read readme.txt in root (got 200, want 200)
  [PASS] reader:write denied (op not granted) (got 403, want 403)
  [PASS] reader:write outside root denied (escape) (got 403, want 403)
  [PASS] reader:stat denied (op not granted) (got 403, want 403)
  [PASS] reader:sustained list x15 under swarm load (got 200, want 200)
  [PASS] writer:list own root (got 200, want 200)
  [PASS] writer:read seed.txt in root (got 200, want 200)
  [PASS] writer:write own root (granted) (got 200, want 200)
  [PASS] writer:write outside root denied (escape) (got 403, want 403)
  [PASS] writer:stat denied (op not granted) (got 403, want 403)
  [PASS] writer:sustained list x15 under swarm load (got 200, want 200)
  [SKIP] exec:run allowlisted ['ls'] (got 502, want None) — SKIP (broker kernel lacks Landlock; VM tier covers this)
  [PASS] exec:run non-allowlisted denied (got 403, want 403)
  [PASS] net:connect allowed echo:9000 echoes (got 200, want 200)
  [PASS] net:connect other host:port denied (got 403, want 403)
  [PASS] net:sustained connect x15 under swarm load (got 200, want 200)
  [PASS] escalator:initial write denied (got 403, want 403)
  [PASS] escalator:escalate accepts delta (got 200, want 200)
  [PASS] escalator:list kept working while escalation pending (120s window) (got 200, want 200)
  [PASS] escalator:approval yields new creds (got 200, want 200)
  [PASS] escalator:write works with new cap (got 200, want 200)
  [PASS] escalator:OLD token still denied (got 403, want 403)
== tier 2: egress proof — a worker's island reaches ONLY the broker
   {"broker:4571": true, "internet:1.1.1.1:80": false, "sibling_dns:echo:9000": false, "sibling_ip:10.201.3.2:9000": false}
   [PASS] egress: broker reachable, internet and sibling islands NOT

== tier 2 matrix summary
   24 checks: 23 passed, 1 skipped, 0 failed
   version pin re-checked after the run: still 6bd598c  [OK]

scenario: all green (1 kernel skip(s), see matrix — VM tier covers them)
exit=0
```
