# Issue #24 evidence — broker self-confinement (Tier 1)

Rig: disposable Linux VM booted from `test/cloud-init.yaml` (Ubuntu 24.04, kernel
6.8.0-138-generic — the worker host has no Landlock LSM, so all kernel evidence ran on the
VM). Code verified at commit `aabaaf2` (the branch's last code commit; commits after it are
evidence-only, as with issue #8). `capture.py` (committed here) generated both transcripts
on the VM itself; every probe is a black-box HTTP invoke.

| acceptance bullet | where demonstrated |
|---|---|
| broker process (and any thread it spawns) under its own Landlock ruleset | `after.md` — `serve --self-confinement` applies the ruleset before the server (and any thread) exists; the broker's own `open()` of an outside-root file gets kernel EACCES |
| …+ seccomp allowlist | `after.md` — an exec child syscall on no deny list (ptrace) dies `-31` SIGSYS under the broker allowlist floor, inherited by everything it spawns |
| a broker bug cannot read outside its working set | `before.md` vs `after.md` — identical grant, identical request: plain broker returns `TOP-SECRET-capdel-24`, confined broker returns the kernel's `Permission denied` |
| a test in `test/` demonstrates a broker-side outside-root read being kernel-denied | `test/kernel_broker.py` — runs both brokers side by side, asserts leak→denied flip + working-set control + SIGSYS floor; PASS on the VM |

Regression on the same branch: `test/kernel.py` PASS (#8), `test/swarm.py` 14/14 on the VM
(real kernel), `test/vm.sh ready-24` 8/8 against the systemd-deployed self-confined broker
(`CAPDEL_COMMIT` pinned to the branch commit; the VM broker now runs self-confined by
default since this PR).

Rework note: the first allowlist revision killed the broker at bind time on the VM —
`status=31/SYS` inside `socket.getfqdn` → glibc 2.39's resolver batches A+AAAA DNS
queries via `sendmmsg` (307), which the worker host's glibc 2.31 / Python 3.8 never
calls. Found by siginfo capture on the VM (`si_syscall`) + a syscall inventory of the
failing window; fixed by adding `sendmmsg`/`recvmmsg`. A first BPF draft also had the
JEQ jump sense inverted (allow-everything) — caught by a ptrace probe that survived the
filter, fixed before any of the above runs.

Could NOT verify: nothing in the acceptance. Out-of-scope notes recorded in SPEC §3.8:
DNS-backed `net`/`secret` invokes on hosts whose `/etc/resolv.conf` is systemd-resolved's
`/run` stub need that stub path in the working set (tests dial 127.0.0.1, no DNS); the
allowlist floor bounds exec children — an exotic child binary calling outside the floor
dies with SIGSYS by design; x86_64-only.
