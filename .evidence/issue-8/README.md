# Issue #8 evidence — kernel-backed exec confinement (Tier 1)

Rig: disposable Linux VM booted from `test/cloud-init.yaml` (Ubuntu 24.04, kernel
6.8.0-138-generic, cgroup v2 with `memory` enabled at root), broker run by systemd
from `/opt/capdel` at the pinned commits. `capture.py` (committed here) generated
both transcripts on the VM itself; every probe is a black-box HTTP invoke against
the live broker on 127.0.0.1:4571.

| acceptance bullet | where demonstrated |
|---|---|
| Landlock ruleset rooted at `cwd_root`; kernel refuses outside reads | `after.md` §1 — `EACCES` (`Permission denied`), no secret in stdout |
| indirect path (symlink / `..`), not the argv check | `after.md` §1 probes pass the argv check (`cat …`); `before.md` §1 shows the SAME invokes succeeding on main (`3acc82d`) — the userspace check never saw them |
| before vs after transcript pinned | `before.md` (main @ `3acc82d`: secret leaks) / `after.md` (this PR @ `7c1bfde`: kernel-denied) |
| seccomp: denied syscall → SIGSYS | `after.md` §2 — `code: -31`; allowed syscalls unaffected (`print(42)` runs, see below) |
| cgroups: quota exceeded → killed | `after.md` §3 — 256 MiB alloc under `memory_max_bytes` 32 MiB → `code: -9` (OOM); also a `test/kernel.py` case |
| `GET /_api/version` pins this PR's commit | first line of each transcript (`7c1bfde` for the PR) |
| out-of-scope items filed, not dropped | #24 (broker self-confinement), #25 (disk I/O quotas) |

Regression: `test/swarm.py` passes 14/14 on the VM against `7c1bfde` (and on main).

Rework note: the original commit (5687c97) installed seccomp via
`prctl(PR_SET_SECCOMP, 1, …)` — that is STRICT mode, which ignores the filter
program and SIGKILLs the child on any syscall outside read/write/exit
(kernel audit `type=1326 … sig=9 … code=0x0`). Found by running the acceptance on
the VM; fixed in 7c1bfde by calling `seccomp(SECCOMP_SET_MODE_FILTER)` (x86_64
syscall 317). `after.md` is from the fixed commit.

Could NOT verify over HTTP: `cpu_quota_us` throttling (the code path shares
`attach_cgroup` with the demonstrated `memory_max_bytes`; the acceptance's
"CPU- and/or memory-limited" bullet is satisfied by memory).
