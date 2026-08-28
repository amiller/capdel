# Issue #25 evidence — disk I/O quotas via cgroup-v2 io.max (Tier 1)

Rig: disposable Linux VM (`test/cloud-init.yaml` — Ubuntu 24.04, kernel 6.8, cgroup v2)
booted by `run-vm.sh` on branch `ready-25` @ `6b22126` (code tip; evidence commits on
top). Since #28 the VM broker serves `--self-confinement`, so this transcript was
captured against a broker that is itself Landlock+seccomp-confined; `capture.py` ran ON
the VM through an exec capability, and every probe is black-box HTTP against the live
broker at 127.0.0.1:4571 — the same rig and style as `.evidence/issue-8/` (#23).

| acceptance bullet | where demonstrated |
|---|---|
| an exec cap with a disk I/O quota | mint with `disk_max_bps: 4194304` — transcript §1 |
| throttled by cgroup-v2 io.max when exceeded | 16 MiB O_SYNC write: **0.03 s** unthrottled → **3.99 s** at 4 MiB/s; attenuated child (1 MiB/s) writes 4 MiB in **3.99 s** — 16/4 == 4/1 elapsed is the rate-limiting signature, not fixed latency |
| shown in a test, same rig as test/kernel.py | `test/kernel.py` io.max case (dd `oflag=direct`, scratch on the root disk under `/srv/demo`) → PASS on the VM — transcript §3 |

Also shown: attenuation narrowing 4→1 MiB/s accepted; widening 4→8 MiB/s denied
(403, "may only be narrowed"); regression `test/swarm.py` 14/14 on the VM.

Found while verifying (fixed in this PR):
- io.max rejects partitions — `st_dev` of a file names `vda1` and the write fails
  `ENODEV`; `_disk_dev()` resolves the whole disk (`vda`) via sysfs, nesting-aware
  (nvme nests a namespace under its controller).
- Children now join their cgroup in `preexec_fn` before exec — attaching from the
  parent after `Popen` returned left a window where a fast child could finish before
  cpu/memory/disk limits applied (this closes it for all three limits).
- Rebasing onto #28 (VM broker now `--self-confinement`): the working set left `/sys`
  read-only, so every quota'd exec invoke died `EACCES` at `prepare_cgroup` (cpu/memory
  from #23 included — `swarm.py` has no quota case, so #28's VM run never caught it).
  The working set now grants `/sys/fs/cgroup` write-side only (`WRITE_FILE|REMOVE_DIR|
  MAKE_DIR`); cgroupfs writes stay bounded by kernel cgroup delegation, the rest of
  `/sys` stays read-only. The demo/scratch dirs moved under `/srv/demo` — exec children
  inherit the broker's working set, and `/tmp`//`/var/tmp` are outside it by #24's design.

Observation, disclosed not fixed (inherent device-level accounting): rewriting a file
whose pages are still clean-warm in the page cache from a *previous cgroup's* write is
undercharged once (measured 1.2 s vs 4.0 s for 16 MiB @ 4 MiB/s); fresh files, direct
IO, buffered+fsync and repeated rewrites all throttle at exactly bytes/bps. io.max is
a device-scheduler limit on bios this cgroup submits, not a logical-byte limit.

Could NOT verify: none of the above ran on shared-kernel hosts (containers have no
Landlock/cgroup-v2 delegation there); kernel work needs this VM rig — the same
constraint #8/#23 recorded.
