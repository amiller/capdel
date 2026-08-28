#!/usr/bin/env python3
"""Capture the before/after self-confinement transcript for issue #24 (Tier 1).

Runs ON the disposable Linux VM (Landlock present). Boots two brokers over the same
throwaway state — one plain (main's behavior), one `--self-confinement` — and prints
the identical probe sequence against each: a read of a cap root OUTSIDE the broker's
working set, a read of a root inside it, and an exec child calling a syscall that is
on no deny list (ptrace) but is outside the broker allowlist.
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

ROOT = Path(__file__).resolve().parent.parent.parent
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
                return base, d
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


def probe(base, good, bad, run):
    s, d = http(base, "GET", "/_api/version")
    print(f"\n`GET /_api/version` → {s} `{json.dumps(d)}`")
    s, d = http(base, "POST", f"/caps/{good['id']}/invoke", good["token"],
                {"op": "read", "path": good["path"]})
    print(f"$ POST /caps/{good['id']}/invoke read (root INSIDE the working set) → HTTP {s} `{json.dumps(d)}`")
    s, d = http(base, "POST", f"/caps/{bad['id']}/invoke", bad["token"],
                {"op": "read", "path": bad["path"]})
    print(f"$ POST /caps/{bad['id']}/invoke read (root OUTSIDE the working set) → HTTP {s} `{json.dumps(d)}`")
    s, d = http(base, "POST", f"/caps/{run['id']}/invoke", run["token"],
                {"op": "run", "argv": ["python3", "-c",
                 "import ctypes; ctypes.CDLL(None).syscall(101, 0, 0, 0)"]})
    print(f"$ POST /caps/{run['id']}/invoke exec python3 ptrace(101) (on no deny list) → HTTP {s} `{json.dumps(d)}`")


def main():
    with tempfile.TemporaryDirectory(prefix="capdel-24-") as tmp:
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

        good = mint("fs", "--root", str(inside), "--ops", "read", "--ttl", "10m", "--name", "inside-read")
        good["path"] = str(inside / "ok.txt")
        bad = mint("fs", "--root", str(outside), "--ops", "read", "--ttl", "10m", "--name", "outside-read")
        bad["path"] = str(outside / "leak")
        run = mint("exec", "--allow", "python3", "--cwd-root", str(inside), "--ttl", "10m", "--name", "run")
        print(f"$ capdel mint fs --root {inside} / fs --root {outside} / exec python3 --cwd-root {inside}")
        print("   (owner CLI, an unconfined process; identical grants for both brokers)")

        port = free_port()
        plain = subprocess.Popen([sys.executable, CAPDEL, "serve", "--bind", f"127.0.0.1:{port}"],
                                 env=env, stderr=subprocess.DEVNULL)
        try:
            base, _ = wait_up(port)
            print(f"\n## BEFORE — plain broker (no --self-confinement): {base}")
            probe(base, good, bad, run)
        finally:
            plain.terminate()
            plain.wait()

        port = free_port()
        confined = subprocess.Popen([sys.executable, CAPDEL, "serve", "--bind", f"127.0.0.1:{port}",
                                     "--self-confinement", "--confinement-root", str(inside)],
                                    env=env, stderr=subprocess.DEVNULL)
        try:
            base, _ = wait_up(port)
            print(f"\n## AFTER — `--self-confinement --confinement-root {inside}`: {base}")
            probe(base, good, bad, run)
        finally:
            confined.terminate()
            confined.wait()


if __name__ == "__main__":
    main()
