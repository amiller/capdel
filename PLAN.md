# Issue #25 — disk I/O quotas (io.max) for exec capabilities

Acceptance: "An exec cap with a disk I/O quota, throttled by cgroup-v2 io.max when
exceeded — shown in a test, same rig as test/kernel.py."

- [x] `disk_max_bps` constraint on exec caps (bytes/s, read and write): validated,
      subset-narrowed only (same family rule as cpu_quota_us/memory_max_bytes),
      CLI `--disk-max-bps`, applied by cgroup-v2 `io.max` on the whole disk backing
      `cwd_root`; io controller enabled at root when missing; loud failure when the
      kernel primitive is unavailable (no fallback).
- [x] `test/kernel.py` case on the disposable-VM rig: an over-quota O_DIRECT write is
      throttled (elapsed ≥ bytes/quota and ≫ the unthrottled baseline).
- [x] SPEC.md amended where it declared disk I/O quotas future work (non-goals line +
      §3.8 platform annex).
- [x] Evidence (Tier 1, same rig as #8): HTTP transcript against the live VM broker with
      `GET /_api/version` pinned to the branch commit — throttled vs baseline write,
      attenuation narrowing + rejection, `test/kernel.py` PASS, `test/swarm.py`
      regression — committed to `.evidence/issue-25/`.

Found and fixed while verifying on the VM:
- io.max rejects partitions (ENODEV for vda1) — resolve the whole disk via sysfs.
- attach-from-parent race: children now join their cgroup in preexec_fn before exec
  (and before Landlock restriction), closing the window where a fast child finished
  before cpu/memory/disk limits applied.
