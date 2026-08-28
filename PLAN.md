# PLAN — issue #24: broker self-confinement (Landlock + seccomp allowlist)

Acceptance (issue body):
- The broker process (and any thread it spawns) runs under its own Landlock ruleset + seccomp
  allowlist, so a broker bug cannot read outside its working set; a test in `test/` demonstrates
  a broker-side outside-root read being kernel-denied.

Evidence tier: **Tier 1** (backend behavior, no UI) — HTTP transcript against the disposable VM
staging host (`test/cloud-init.yaml`) with `GET /_api/version` pinned to the PR commit, mirroring
PR #23's accepted format. Worker host has no Landlock LSM → all kernel evidence on the VM.

## Steps
- [ ] capdel.py: generalize `_apply_landlock` to a (path, access) rules list (exec-child behavior unchanged);
      factor the seccomp filter load; add `_BROKER_SYSCALLS` allowlist + `_apply_seccomp_allowlist`;
      add `apply_self_confinement(extra_roots)`; wire `serve --self-confinement [--confinement-root P]`
      to apply it before the server (and any thread) exists.
- [ ] Working set: CAPDEL_HOME + extra roots (rw) ∪ own source dir, /usr,/bin,/lib,/lib64 (r-x) ∪
      /etc,/proc,/sys (r) ∪ /dev (rw). No /run: hosts with systemd-resolved stub DNS must add it
      (documented in SPEC). No userspace pre-check of cap roots vs the working set — the kernel IS
      the backstop; denial surfaces as EACCES.
- [ ] SPEC.md §3.8: amend "broker self-confinement ... out of scope" → new subsection (#24).
- [ ] test/kernel_broker.py (new): unconfined broker leaks an outside-root read (before);
      self-confined broker: inside read 200, outside read 404 "Permission denied" (kernel),
      exec child syscall outside allowlist → SIGSYS (-31). Run on the VM.
- [ ] test/cloud-init.yaml: VM broker runs self-confined (+ --confinement-root /srv/demo);
      add /root/leak-root fixture. test/vm.sh: pin CAPDEL_COMMIT via env, add 3 host-side checks
      (outside read kernel-denied, control read 200, child SIGSYS floor). test/README.md note.
- [ ] Verify locally: py_compile, swarm.py 13/14+skip baseline holds; seccomp-only broker copy
      passes swarm.py on this host (allowlist coverage for threads/HTTP/fs/net/escalate paths).
- [ ] Verify on VM: push branch → `bash test/vm.sh ready-24` all green; in-VM: kernel.py (#8
      regression), kernel_broker.py (#24), swarm.py (14/14). Capture before/after transcripts
      → `.evidence/issue-24/`.
- [ ] PR (base=main, Tier 1 body per template) → swap issue label ready→in-review; label PR
      ready-to-merge only after evidence committed. Never merge.
