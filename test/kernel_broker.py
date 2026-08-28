#!/usr/bin/env python3
"""Broker self-confinement checks for issue #24; run on the disposable Linux VM.

Two brokers over the same throwaway state, identical grants:
  unconfined — a read of a cap root OUTSIDE the broker's working set succeeds: the grant
               alone is the barrier, i.e. exactly the blast radius of a broker bug.
  confined   — same state, same caps: the read is denied BY THE KERNEL (Landlock EACCES
               surfaces as "Permission denied", not a policy 403), a root inside the
               working set still reads fine, and an exec-child syscall outside the
               broker allowlist dies with SIGSYS.
"""
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CAPDEL = str(ROOT / "capdel.py")


def http(base, method, path, token=None, body=None):
    req = urllib.request.Request(base + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None)
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def wait_up(port):
    base = f"http://127.0.0.1:{port}"
    for _ in range(150):
        try:
            s, d = http(base, "GET", "/_api/version")
            if s == 200:
                return base
        except (urllib.error.URLError, OSError):
            pass
        time.sleep(0.2)
    raise SystemExit("broker never came up")


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def main():
    if sys.platform != "linux":
        print("SKIP: issue #24 needs Linux")
        return 77
    with tempfile.TemporaryDirectory(prefix="capdel-self-") as tmp:
        tmp = Path(tmp)
        inside, outside = tmp / "inside", tmp / "outside"
        inside.mkdir()
        outside.mkdir()
        (inside / "ok.txt").write_text("inside value\n")
        (outside / "leak").write_text("TOP-SECRET-capdel-24\n")
        env = {**os.environ, "CAPDEL_HOME": str(tmp / "home")}

        def mint(*args):
            out = subprocess.check_output([sys.executable, CAPDEL, "mint", *args], env=env, text=True)
            return dict(line.split("=", 1) for line in out.strip().splitlines())

        # holder tokens minted by the (unconfined, separate-process) owner CLI
        good = mint("fs", "--root", str(inside), "--ops", "read", "--ttl", "10m", "--name", "inside-read")
        bad = mint("fs", "--root", str(outside), "--ops", "read", "--ttl", "10m", "--name", "outside-read")
        run = mint("exec", "--allow", "python3", "--cwd-root", str(inside), "--ttl", "10m", "--name", "run")

        def invoke(base, cap, body):
            return http(base, "POST", f"/caps/{cap['id']}/invoke", cap["token"], body)

        port = free_port()
        plain = subprocess.Popen([sys.executable, CAPDEL, "serve", "--bind", f"127.0.0.1:{port}"], env=env)
        try:
            s, d = invoke(wait_up(port), bad, {"op": "read", "path": str(outside / "leak")})
            assert s == 200 and d.get("content") == "TOP-SECRET-capdel-24\n", (s, d)
        finally:
            plain.terminate()
            plain.wait()

        port = free_port()
        confined = subprocess.Popen([sys.executable, CAPDEL, "serve", "--bind", f"127.0.0.1:{port}",
                                     "--self-confinement", "--confinement-root", str(inside)], env=env)
        try:
            base = wait_up(port)
            s, d = invoke(base, good, {"op": "read", "path": str(inside / "ok.txt")})
            assert s == 200 and d.get("content") == "inside value\n", (s, d)
            # userspace checks all pass (path IS inside the cap root) — the kernel says no
            s, d = invoke(base, bad, {"op": "read", "path": str(outside / "leak")})
            assert s == 404 and "Permission denied" in d.get("error", ""), (s, d)
            # seccomp floor: an exec child inherits the broker allowlist; ptrace(101) is
            # not on it and the cap does not need to deny it itself
            s, d = invoke(base, run, {"op": "run", "argv": [
                "python3", "-c", "import ctypes; ctypes.CDLL(None).syscall(101, 0, 0, 0)"]})
            assert s == 200 and d.get("code") == -31, (s, d)
        finally:
            confined.terminate()
            confined.wait()
    print("PASS: unconfined broker leaks an outside-root read; --self-confinement broker gets the "
          "same read kernel-denied (EACCES) while a working-set root still reads, and an exec "
          "child syscall outside the broker allowlist dies with SIGSYS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
