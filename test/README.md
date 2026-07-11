# capdel swarm test rig

Three tiers, cheapest first. Each proves the same property: a swarm of workers, each
holding only its own scoped token, can do exactly what it was granted and nothing else —
concurrently, with the escalate→approve loop, and (on the VM) against a real kernel.

## Tier 1 — local scenario (runnable now, no infra)

```sh
python3 test/swarm.py
```

Starts a throwaway broker on `127.0.0.1:4599`, mints five differently-scoped capabilities
(fs-read, fs-write, exec, net, and one that must escalate), runs four workers
**concurrently** against the broker, then walks the escalation loop — all as black-box
HTTP + CLI assertions. Prints a PASS/FAIL table and exits non-zero on any failure. Touches
only a tempdir; never `~/.capdel`. This is the fast inner-loop test — run it after any
change to `capdel.py`.

## Tier 2 — worker isolation (containers)

Each worker runs in its own container with **only** `CAPDEL_URL` + a scoped token in its
environment — no source, no credentials, no route to the host but the broker. This is the
realistic shape: the token bounds what it reaches on your machine, the container bounds
what the process reaches on its own.

```sh
python3 capdel.py serve --bind 0.0.0.0:4571 &          # broker reachable from containers
export CAPDEL_URL=http://host.docker.internal:4571
export READER_TOKEN=… READER_CAP=cap-…  WRITER_TOKEN=… WRITER_CAP=cap-…   # from `capdel mint`
docker compose -f test/docker-compose.yml up --build
```

Each worker discovers its capability from the API and runs a small allow/deny plan; watch
the logs for `MISMATCH` (there should be none). Egress confinement is the container's job;
scope is the token's job.

## Tier 3 — disposable VM (kernel tests, destructive-safe)

`test/cloud-init.yaml` boots a throwaway Linux VM running the broker against throwaway
content. Use it when you want to (a) let `exec` caps do anything without risking a real
machine, or (b) test kernel-backed confinement (#8 Landlock/seccomp/cgroups), which needs
a real kernel a container can't provide.

```sh
multipass launch --name capdel --cloud-init test/cloud-init.yaml 24.04
# broker now on the VM's :4571 — mint caps there, point containers or test/swarm.py at it
```

(qemu and any cloud provider work too — see the header of `cloud-init.yaml`.)

## What each tier is for

| Tier | Proves | When |
|---|---|---|
| local `swarm.py` | scope enforcement + concurrency + escalation | every change (CI) |
| containers | worker-process isolation composes with token scope | before trusting a real worker |
| VM | destructive-safe exec + a real kernel for confinement | testing #8, swarm at scale |
