#!/usr/bin/env python3
"""Capture the before/after kernel-confinement transcript for issue #8 (Tier 1).

Runs ON the disposable VM booted from test/cloud-init.yaml, against the live broker
on 127.0.0.1:4571, as root (the cgroup probe writes to /sys/fs/cgroup). Modes:

  before — only the indirect-read probes, which work on main's userspace-only broker
           and show the bypass (the read succeeds).
  after  — the full acceptance walk on the PR commit: kernel-denied indirect reads,
           seccomp SIGSYS kill, cgroup OOM kill, plus test/kernel.py itself.
"""
import json, os, subprocess, sys, urllib.request, urllib.error
from pathlib import Path

CAPDEL = "/opt/capdel/capdel.py"
BASE = "http://127.0.0.1:4571"
CLI_ENV = dict(os.environ)
for line in open("/etc/capdel.env"):
    if "=" in line:
        k, _, v = line.strip().partition("=")
        CLI_ENV[k] = v

ROOT_DIR = Path("/srv/demo/work/root")
VAULT = Path("/srv/demo/vault/secret.txt")


def http(method, path, token=None, body=None):
    req = urllib.request.Request(BASE + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None)
    if token: req.add_header("Authorization", "Bearer " + token)
    if body is not None: req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=90) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def mint_exec(allow, **flags):
    args = ["mint", "exec", "--allow", allow, "--cwd-root", str(ROOT_DIR), "--ttl", "1h",
            "--name", flags.pop("name", allow)]
    for k, v in flags.items():
        args += [f"--{k.replace('_', '-')}", str(v)]
    out = subprocess.run([sys.executable, CAPDEL, *args], capture_output=True, text=True,
                         env=CLI_ENV, timeout=90)
    if out.returncode != 0:
        raise SystemExit(f"`capdel {' '.join(args[1:])}` failed:\n{out.stdout}{out.stderr}")
    kv = {}
    for tok in out.stdout.split():
        if "=" in tok:
            k, _, v = tok.partition("=")
            kv[k] = v
    return kv["id"], kv["token"]


def invoke(token, cid, argv):
    return http("POST", f"/caps/{cid}/invoke", token, {"argv": argv})


# fixture: a secret OUTSIDE the cap root, reachable only by an indirect path
ROOT_DIR.mkdir(parents=True, exist_ok=True)
VAULT.parent.mkdir(parents=True, exist_ok=True)
VAULT.write_text("TOP-SECRET-capdel-8\n")
leak = ROOT_DIR / "leak"
if leak.is_symlink() or leak.exists():
    leak.unlink()
leak.symlink_to("../../vault/secret.txt")

P = print
FAILURES = []


def check(label, ok):
    P(f"> **{label}**: {'✓' if ok else '✗ FAIL'}")
    if not ok:
        FAILURES.append(label)


mode = sys.argv[1] if len(sys.argv) > 1 else "after"
P(f"# Issue #8 — kernel-backed exec confinement, {'BEFORE (main, userspace-only)' if mode == 'before' else 'AFTER (this PR)'} transcript\n")
P(f"Broker: `{BASE}` (disposable VM, `test/cloud-init.yaml`); fixture: `{leak}` → `../../vault/secret.txt`, plus a `..` traversal argv.\n")
st, v = http("GET", "/_api/version")
P(f"`GET /_api/version` → `{v}`\n")

cid, tok = mint_exec("cat")
P("## exec cap scoped to the root, indirect outside reads\n")
P(f"```$ capdel mint exec --allow cat --cwd-root {ROOT_DIR}   →  id={cid} token=ct-…```\n")
for label, argv in [("symlink read `cat leak`", ["cat", "leak"]),
                    ("dotdot read `cat ../../vault/secret.txt`", ["cat", "../../vault/secret.txt"])]:
    st, d = invoke(tok, cid, argv)
    P(f"$ POST /caps/{cid}/invoke {{\"argv\": {json.dumps(argv)}}} → HTTP {st} ```json\n{json.dumps(d, indent=2)}\n```")
    if mode == "before":
        check(f"{label}: BYPASSES userspace check (stdout carries the secret)", st == 200 and "TOP-SECRET" in d.get("stdout", ""))
    else:
        check(f"{label}: kernel-denied (nonzero code, no secret in stdout)",
              st == 200 and d.get("code") != 0 and "TOP-SECRET" not in json.dumps(d))

if mode == "after":
    P("\n## seccomp: denied syscall terminates with SIGSYS\n")
    cid, tok = mint_exec("python3", name="nog", deny_syscall="getpid")
    st, d = invoke(tok, cid, ["python3", "-c", "import os; os.getpid()"])
    P(f"$ capdel mint exec --allow python3 --deny-syscall getpid … → id={cid}")
    P(f"$ POST /caps/{cid}/invoke argv=[\"python3\",\"-c\",\"import os; os.getpid()\"] → HTTP {st} ```json\n{json.dumps(d, indent=2)}\n```")
    check("getpid denied → SIGSYS (code -31)", st == 200 and d.get("code") == -31)

    P("\n## cgroups: memory_max_bytes exceeded → child OOM-killed\n")
    cid, tok = mint_exec("python3", name="small", memory_max_bytes=32 * 1024 * 1024)
    st, d = invoke(tok, cid, ["python3", "-c", "b = bytearray(256 * 1024 * 1024); print(len(b))"])
    P(f"$ capdel mint exec --allow python3 --memory-max-bytes {32 * 1024 * 1024} … → id={cid}")
    P(f"$ POST /caps/{cid}/invoke argv=[\"python3\",\"-c\",\"b = bytearray(256 * 1024 * 1024); print(len(b))\"] → HTTP {st} ```json\n{json.dumps(d, indent=2)}\n```")
    check("256 MiB alloc under a 32 MiB cap → OOM kill (code -9)", st == 200 and d.get("code") == -9)

    P("\n## test/kernel.py on this VM\n")
    r = subprocess.run([sys.executable, "/opt/capdel/test/kernel.py"], capture_output=True, text=True, timeout=300)
    P(f"```$ sudo python3 /opt/capdel/test/kernel.py  (exit {r.returncode})\n{r.stdout}{r.stderr}\n```")
    check("test/kernel.py exits 0", r.returncode == 0)

P(f"\n**{'ALL CHECKS PASS' if not FAILURES else str(len(FAILURES)) + ' CHECKS FAILED: ' + '; '.join(FAILURES)}**\n")
sys.exit(1 if FAILURES else 0)
