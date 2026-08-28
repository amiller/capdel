#!/usr/bin/env python3
"""Issue #25 evidence generator — runs ON the disposable VM (test/cloud-init.yaml),
invoked through an exec capability, doing every probe as black-box HTTP against the
live broker at 127.0.0.1:4571. Prints the transcript to stdout.

Throttle proof: three O_SYNC writes of the same shape —
  no quota            16 MiB -> fast (page-cache-free baseline)
  disk_max_bps 4MiB/s 16 MiB -> ~4 s   (16/4)
  disk_max_bps 1MiB/s  4 MiB -> ~4 s   (4/1, via an ATTENUATED child token)
Two different (bytes, bps) pairs landing on the same elapsed time is the signature of
rate throttling; the widening attempt being 403'd is the attenuation rule.
"""
import json
import os
import shutil
import sys
import time
import urllib.error
import urllib.request

BASE = "http://127.0.0.1:4571"
MIB = 1024 * 1024
# Inside the self-confined broker's working set (#24 rw --confinement-root); it sits on
# the same root disk as /var/tmp, and io.max throttles the device, not the path.
DEMO = "/srv/demo/capdel-demo"

# O_SYNC so every write() is real block-device I/O (io.max never sees the page cache).
WRITE = r"""
import json, os, sys, time
mib = int(sys.argv[1]); t0 = time.monotonic()
fd = os.open(sys.argv[2], os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_SYNC)
for _ in range(mib):
    os.write(fd, b"\0" * (1024 * 1024))
os.close(fd)
print(json.dumps({"mib": mib, "elapsed_s": round(time.monotonic() - t0, 2)}))
"""


def env_secret():
    for line in open("/etc/capdel.env"):
        if line.startswith("CAPDEL_OWNER_SECRET="):
            return line.split("=", 1)[1].strip()
    raise SystemExit("no owner secret in /etc/capdel.env")


def http(method, path, token=None, body=None):
    req = urllib.request.Request(BASE + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None)
    if token: req.add_header("Authorization", f"Bearer {token}")
    if body is not None: req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=600) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def mint_exec(name, constraints):
    s, d = http("POST", "/_mint", env_secret(),
                {"type": "exec", "constraints": constraints, "name": name, "ttl_s": 900})
    assert s == 200 and d.get("token"), f"mint {name} -> {s} {d}"
    print(f"  POST /_mint ({name}, constraints={{{', '.join(f'{k}:{v}' for k, v in constraints.items() if k != 'allow')}}}) -> {s} id={d['id']}")
    return d["token"], d["id"]


def run_write(token, cid, mib, label):
    # fresh file per invoke: io.max throttles at the device queue, and rewriting a file
    # whose pages are still clean-warm in the page cache from a *previous cgroup's*
    # write gets undercharged once (measured 1.2s vs 4.0s for 16MiB @ 4MiB/s) — fresh
    # files, direct IO and repeated rewrites all throttle at exactly bytes/bps.
    path = f"{DEMO}/blob-{mib}MiB-{time.monotonic_ns()}"
    s, d = http("POST", f"/caps/{cid}/invoke", token,
                {"op": "run", "argv": ["python3", "-c", WRITE, str(mib), path],
                 "cwd": DEMO})
    assert s == 200 and d.get("code") == 0, f"{label} -> {s} {d}"
    out = json.loads(d["stdout"].strip())
    print(f"  invoke {label}: wrote {out['mib']} MiB (O_SYNC) in {out['elapsed_s']} s")
    return out["elapsed_s"]


def main():
    checks = []
    s, d = http("GET", "/_api/version")
    print(f"GET /_api/version -> {s} {json.dumps(d, sort_keys=True)}")
    checks.append(("version pin", s == 200 and d.get("commit")))

    exec_cons = {"allow": [["python3"]], "cwd_root": DEMO, "timeout_s": 300}
    os.makedirs(DEMO, exist_ok=True)

    print("\n== 1. same write, with and without a disk I/O quota ==")
    w_tok, w_id = mint_exec("io-demo-unthrottled", exec_cons)
    q_tok, q_id = mint_exec("io-demo-4MiBps", {**exec_cons, "disk_max_bps": 4 * MIB})
    base = run_write(w_tok, w_id, 16, "no quota, 16 MiB")
    q1 = run_write(q_tok, q_id, 16, "disk_max_bps=4MiB/s, 16 MiB")
    checks.append(("over-quota write throttled (16MiB@4MiB/s >= 3.5s)", 3.5 <= q1 <= 12))
    checks.append(("throttle is the quota, not the disk (baseline 16MiB < 2s)", base < 2))

    print("\n== 2. attenuation: disk_max_bps may only narrow ==")
    child = {**exec_cons, "disk_max_bps": 1 * MIB}
    s, d = http("POST", f"/caps/{q_id}/attenuate", q_tok, {"constraints": child, "ttl_s": 900})
    assert s == 200 and d.get("token"), f"attenuate narrow -> {s} {d}"
    print(f"  POST /caps/{q_id}/attenuate disk_max_bps 4MiB/s -> 1MiB/s -> {s} id={d['id']}")
    q2 = run_write(d["token"], d["id"], 4, "attenuated 1MiB/s, 4 MiB")
    checks.append(("narrowed child still throttles (4MiB@1MiB/s >= 3.5s; 16/4 == 4/1 elapsed)",
                   3.5 <= q2 <= 12 and abs(q1 - q2) < max(q1, q2) * 0.6))
    s, d = http("POST", f"/caps/{q_id}/attenuate", q_tok,
                {"constraints": {**exec_cons, "disk_max_bps": 8 * MIB}, "ttl_s": 900})
    print(f"  POST /caps/{q_id}/attenuate disk_max_bps 4MiB/s -> 8MiB/s -> {s} {d.get('violated', d)}")
    checks.append(("widening disk_max_bps denied (403)", s == 403 and "disk_max_bps" in str(d)))

    print("\n== 3. kernel test rig (test/kernel.py) under an exec cap ==")
    k_tok, k_id = mint_exec("kernel-rig", {"allow": [["python3"]], "cwd_root": "/", "timeout_s": 300})
    s, d = http("POST", f"/caps/{k_id}/invoke", k_tok,
                {"op": "run", "argv": ["python3", "test/kernel.py", "/srv/demo"], "cwd": "/opt/capdel"})
    print(d.get("stdout", "").strip() or d)
    checks.append(("test/kernel.py PASS on the VM (now incl. io.max case)",
                   s == 200 and d.get("code") == 0 and "PASS" in d.get("stdout", "")))

    print("\n== 4. regression: test/swarm.py on the VM ==")
    s, d = http("POST", f"/caps/{k_id}/invoke", k_tok,
                {"op": "run", "argv": ["python3", "test/swarm.py", "/srv/demo"], "cwd": "/opt/capdel"})
    tail = "\n".join(d.get("stdout", "").strip().splitlines()[-3:])
    print(tail or d)
    checks.append(("test/swarm.py green on the VM", s == 200 and d.get("code") == 0
                   and "0 failed" in d.get("stdout", "")))

    shutil.rmtree(DEMO, ignore_errors=True)
    failed = [name for name, ok in checks if not ok]
    print(f"\n  checks — {len(checks) - len(failed)}/{len(checks)} passed")
    for name, ok in checks:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    if failed:
        sys.exit(1)
    print("CAPTURE-OK")


if __name__ == "__main__":
    main()
