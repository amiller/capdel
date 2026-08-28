# Issue #25 evidence — disk I/O quotas (io.max) — Tier 1

Rig: disposable Linux VM booted from `test/cloud-init.yaml` (Ubuntu 24.04, kernel 6.8,\ncgroup v2) by `.evidence/issue-25/run-vm.sh` on branch `ready-25` @ `0d9b95a`;\n`capture.py` ran ON the VM through an exec capability; every probe is black-box HTTP\nagainst the live broker at 127.0.0.1:4571.

GET /_api/version -> 200 {"commit": "0d9b95a", "pop_mode": "off", "schemes": ["bearer", "capdel-hmac-sha256"], "server": "capdel/0.1"}

== 1. same write, with and without a disk I/O quota ==
  POST /_mint (io-demo-unthrottled, constraints={cwd_root:/var/tmp/capdel-demo, timeout_s:300}) -> 200 id=cap-88931ec3d22f
  POST /_mint (io-demo-4MiBps, constraints={cwd_root:/var/tmp/capdel-demo, timeout_s:300, disk_max_bps:4194304}) -> 200 id=cap-472c0f6ac459
  invoke no quota, 16 MiB: wrote 16 MiB (O_SYNC) in 0.02 s
  invoke disk_max_bps=4MiB/s, 16 MiB: wrote 16 MiB (O_SYNC) in 3.99 s

== 2. attenuation: disk_max_bps may only narrow ==
  POST /caps/cap-472c0f6ac459/attenuate disk_max_bps 4MiB/s -> 1MiB/s -> 200 id=cap-43966abbf9f1
  invoke attenuated 1MiB/s, 4 MiB: wrote 4 MiB (O_SYNC) in 3.98 s
  POST /caps/cap-472c0f6ac459/attenuate disk_max_bps 4MiB/s -> 8MiB/s -> 403 disk_max_bps may only be narrowed

== 3. kernel test rig (test/kernel.py) under an exec cap ==
  POST /_mint (kernel-rig, constraints={cwd_root:/, timeout_s:300}) -> 200 id=cap-77aae0a84b20
PASS: Landlock denies outside-root reads, seccomp kills getpid with SIGSYS, cgroup memory_max_bytes OOM-kills an over-quota child, cgroup io.max throttles an over-quota disk write

== 4. regression: test/swarm.py on the VM ==
  [PASS] escalator: OLD token still denied
  ----------------------------------------------
  14/14 passed, 0 skipped, 0 failed

  checks — 7/7 passed
  [PASS] version pin
  [PASS] over-quota write throttled (16MiB@4MiB/s >= 3.5s)
  [PASS] throttle is the quota, not the disk (baseline 16MiB < 2s)
  [PASS] narrowed child still throttles (4MiB@1MiB/s >= 3.5s; 16/4 == 4/1 elapsed)
  [PASS] widening disk_max_bps denied (403)
  [PASS] test/kernel.py PASS on the VM (now incl. io.max case)
  [PASS] test/swarm.py green on the VM
CAPTURE-OK
== vm: capture green
