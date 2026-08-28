# Issue #24 — broker self-confinement, AFTER (`--self-confinement`) transcript

Same VM, same state, same caps as `before.md` — only the broker's own confinement differs.
Broker: `capdel.py serve --bind … --self-confinement --confinement-root …/inside`
(the working set is CAPDEL_HOME + the extra root + system read/exec dirs; see SPEC §3.8).

## `--self-confinement` broker: http://127.0.0.1:41139

`GET /_api/version` → 200 `{"server": "capdel/0.1", "commit": "aabaaf2", "pop_mode": "off", "schemes": ["bearer", "capdel-hmac-sha256"]}`
$ POST /caps/cap-8fbc16bc2ddb/invoke read (root INSIDE the working set) → HTTP 200 `{"content": "inside value\n", "offset": 0, "bytes": 13}`
$ POST /caps/cap-aa0368249179/invoke read (root OUTSIDE the working set) → HTTP 404 `{"error": "[Errno 13] Permission denied: '/tmp/capdel-24-6bbkdt3x/outside/leak'"}`
$ POST /caps/cap-f1b5d09fb275/invoke exec python3 ptrace(101) (on no deny list) → HTTP 200 `{"code": -31, "stdout": "", "stderr": "", "truncated": false}`

> **broker-side outside-root read is KERNEL-denied**: every userspace check passed (the
> path IS inside the granted cap root) — the 404 is the kernel's EACCES from the broker's
> own Landlock ruleset, not a policy 403. ✓
> **working-set root still reads (200)**: the denial is the outside-root rule, not
> general breakage. ✓
> **exec child syscall outside the broker allowlist dies with SIGSYS (code -31)** even
> though the cap's own deny list never names it — the allowlist floor is active and
> inherited by everything the broker spawns. ✓

## The deployed shape: systemd unit from `test/cloud-init.yaml`

The VM's actual broker (systemd, `ExecStart … serve --bind 0.0.0.0:4571 --self-confinement
--confinement-root /srv/demo`), commit pinned via `CAPDEL_COMMIT`:

- `GET /_api/version` → `{"server": "capdel/0.1", "commit": "b055150", …}` (== the pushed branch's code commit)
- owner mint `fs --root /root/leak-root` (outside the working set), holder read of
  `/root/leak-root/leak.txt` → HTTP 404 `{"error": "[Errno 13] Permission denied: '/root/leak-root/leak.txt'"}`

## Full rig on the same branch

- `bash test/vm.sh ready-24` (host-side, fresh VM from the pushed branch): **8/8 PASS** —
  the 5 original tier-3 checks plus the three new #24 checks (outside read kernel-denied,
  working-set control read, SIGSYS floor).
- In-VM on the same clone: `test/kernel.py` PASS (#8 regression), `test/kernel_broker.py`
  PASS (#24), `test/swarm.py` **14/14** (exec check included — real kernel).
