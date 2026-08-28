# capdel swarm test rig

Three tiers, cheapest first. Each proves the same property: a swarm of workers, each
holding only its own scoped token, can do exactly what it was granted and nothing else —
concurrently, with the escalate→approve loop, and (on the VM) against a real kernel.

One command runs tiers 1+2 and prints the allow/deny matrix (`docs/user-journeys.md`,
"fan a swarm out and see total exposure"):

```sh
python3 test/scenario.py        # needs docker + docker compose
```

## Tier 1 — in-process scenario (seconds, no infra)

`test/swarm.py`: starts a throwaway broker on an **ephemeral**
port, mints five differently-scoped capabilities (fs-read, fs-write, exec, net, one that
must escalate), runs four workers **concurrently** against the broker, then walks the
escalation loop — all black-box HTTP + CLI assertions. Prints a PASS/FAIL table, exits
non-zero on any failure, touches only a tempdir (never `~/.capdel`).

Kernel note: exec caps are kernel-confined (Landlock, #23) and the broker fails LOUDLY on
kernels without it — on such hosts the allowlisted-exec check prints `[SKIP]` with the
reason instead of failing; the VM tier covers it on a real kernel. Broker self-confinement
(#24) is likewise kernel-tier: `test/kernel_broker.py` runs an unconfined and a
`--self-confinement` broker side by side on the VM and asserts an outside-root read flips
from leak to kernel-denied.

## Tier 2 — worker isolation containers (`scenario.py` drives it)

`docker compose up` brings up the whole rig:

- **broker** container = the disposable owner host: fresh state volume, seeded content
  volume, the repo's `capdel.py` bind-mounted in, `CAPDEL_COMMIT` pinned so
  `GET /_api/version` == the checkout's commit (asserted before and after the run).
- **echo** = a one-shot TCP relay target living on the net worker's island.
- **5 workers**, each a minimal image whose **ONLY environment is `CAPDEL_URL` + its
  scoped token** — no cap id, no plan, no other credentials. Each sits on its own
  `internal: true` network shared with nothing but the broker: no internet, no sibling
  workers (the scenario proves this empirically — see the egress row in the matrix).
- Workers self-discover (`GET /whoami`) and exercise their own boundaries: every granted
  op must be allowed, and one probe just outside each boundary (unguarded op, path escape,
  un-allowlisted argv, foreign host:port) must be denied.
- The scenario mints over the real API (`POST /_mint`), launches all workers with a
  single `compose up` (concurrent), and approves the escalation (`POST /_requests/<rid>/
  approve`) **while the other workers keep invoking** — escalation under load.

Manual poking: `docker compose -f test/docker-compose.yml --env-file test/.env up broker`
(scenario.py writes `test/.env`; it is gitignored).

## Tier 3 — disposable VM (kernel tests, destructive-safe)

`test/cloud-init.yaml` boots a throwaway Linux VM running the broker against throwaway
content: exec caps can do anything inside it, and the VM's kernel (noble = 6.8, Landlock
always-on) is a *real* kernel for confinement testing (#8), which containers cannot
provide (they share the host kernel).

```sh
bash test/vm.sh [branch]     # boots qemu/KVM, waits for the broker, runs exec-cap checks
```

Checks run host-side against the forwarded broker port: an allowlisted exec runs,
a non-allowlisted exec is denied by policy, and — the part only a real kernel can prove —
`ls /etc` **fails under the sandbox** even though `ls` is allowlisted (Landlock blocks the
read outside the granted paths). Since #24 the VM broker itself runs self-confined, and
`vm.sh` adds broker-side checks: an outside-root read is kernel-denied, a working-set root
reads fine, and an exec child syscall outside the broker allowlist dies with SIGSYS.

## What each tier is for

| Tier | Proves | When |
|---|---|---|
| in-process `swarm.py` | scope enforcement + concurrency + escalation | every change (fast inner loop) |
| containers (`scenario.py`) | worker isolation composes with token scope; egress limited to the broker | before trusting a real worker |
| VM (`vm.sh`) | destructive-safe exec + kernel-backed confinement (#8) | kernel work, swarm at scale |
