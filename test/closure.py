#!/usr/bin/env python3
"""Closure test — event-driven capability revocation (issue #5, PORTICO-style).

Black-box: drives the real `capdel.py serve`/`mint`/`event` and the HTTP API the way an
owner + a delegated holder would. Asserts that a cap whose `closes_on` lists a trusted event
auto-revokes when the owner files that event, that the revocation cascades to children, that a
sibling cap with no such closure is unaffected, that only the owner can file an event, and that
the self-description reports the *effective* (inherited) closure set.

    python3.11 test/closure.py        # starts a throwaway broker on 127.0.0.1:4598

Exits non-zero if any assertion fails. Touches only a tempdir; never ~/.capdel.
"""
import json, os, socket, subprocess, sys, tempfile, time, urllib.request, urllib.error
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CAPDEL = str(ROOT / "capdel.py")
PORT = 4598
BASE = f"http://127.0.0.1:{PORT}"
OWNER = "closure-test-owner-secret"


def http(method, path, token=None, body=None):
    req = urllib.request.Request(BASE + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None)
    if token: req.add_header("Authorization", f"Bearer {token}")
    if body is not None: req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def cli(*args):
    env = {**os.environ, "CAPDEL_HOME": os.environ["CAPDEL_HOME"], "CAPDEL_OWNER_SECRET": OWNER}
    return subprocess.run([sys.executable, CAPDEL, *args], capture_output=True, text=True, env=env).stdout


def mint(*args):
    d = dict(line.split("=", 1) for line in cli("mint", *args).strip().splitlines() if "=" in line)
    return d["id"], d["token"]


def wait_port(port, secs=10):
    for _ in range(secs * 10):
        s = socket.socket()
        if s.connect_ex(("127.0.0.1", port)) == 0: s.close(); return True
        time.sleep(0.1)
    return False


def check(name, ok, detail):
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    if not ok: print(f"         detail: {detail}")
    return 1 if ok else 0


def main():
    tmp = tempfile.mkdtemp(prefix="capdel-closure-")
    os.environ["CAPDEL_HOME"] = os.path.join(tmp, "state")
    root = Path(tmp) / "root"; root.mkdir()
    (root / "a.txt").write_text("hello\n")

    broker = subprocess.Popen([sys.executable, CAPDEL, "serve", "--bind", f"127.0.0.1:{PORT}"],
                              env={**os.environ, "CAPDEL_OWNER_SECRET": OWNER},
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    results = []
    try:
        assert wait_port(PORT), "broker did not start"
        a, ta = mint("fs", "--root", str(root), "--ops", "list,read,write", "--ttl", "20m",
                     "--name", "A", "--closes-on", "build-passed")
        b, tb = mint("fs", "--root", str(root), "--ops", "list,read,write", "--ttl", "20m", "--name", "B-control")

        # A2 attenuate: child narrows AND adds its own event; parent closure is inherited
        s, d = http("POST", f"/caps/{a}/attenuate", ta,
                    {"constraints": {"root": str(root), "ops": ["read"]}, "closes_on": ["phase-exit"]})
        ch, tch = d["id"], d["token"]
        results.append(check("attenuate accepts closes_on", s == 200 and ch, d))

        # A1 self-description reports EFFECTIVE (inherited) closure
        s, d = http("GET", f"/caps/{a}", ta)
        results.append(check("describe A: effective closes_on == [build-passed]",
                             d.get("closes_on") == ["build-passed"], d.get("closes_on")))
        s, d = http("GET", f"/caps/{ch}", tch)
        results.append(check("describe child: effective closes_on == [build-passed, phase-exit] (inherited+own)",
                             d.get("closes_on") == ["build-passed", "phase-exit"], d.get("closes_on")))

        # baseline: both usable
        s, d = http("POST", f"/caps/{a}/invoke", ta, {"op": "read", "path": str(root / "a.txt")})
        results.append(check("baseline: A read works", s == 200 and "content" in d, d))
        s, d = http("POST", f"/caps/{b}/invoke", tb, {"op": "read", "path": str(root / "a.txt")})
        results.append(check("baseline: B-control read works", s == 200 and "content" in d, d))

        # A4 only the owner can fire an event
        s, d = http("POST", "/_event", ta, {"name": "build-passed"})  # holder's token, not owner secret
        results.append(check("non-owner cannot fire event (401)", s == 401, d))
        s, d = http("POST", "/_event", OWNER, {"name": "no-such-event"})
        results.append(check("owner fires unmatched event → 0 closed", s == 200 and d.get("count") == 0, d))
        s, d = http("POST", "/_event", OWNER, {"name": "build-passed"})
        results.append(check("owner fires build-passed → closes A only (count 1, id matches)",
                             s == 200 and d.get("count") == 1 and a in d.get("closed", []), d))

        # A2/A3 cascade: A and its child die; B-control is unaffected
        s, d = http("POST", f"/caps/{a}/invoke", ta, {"op": "read", "path": str(root / "a.txt")})
        results.append(check("post-event: A invoke denied (revoked)", s == 403 and "revoked" in d.get("violated", ""), d))
        s, d = http("POST", f"/caps/{ch}/invoke", tch, {"op": "read", "path": str(root / "a.txt")})
        results.append(check("post-event: child invoke denied (cascade via ancestor)",
                             s == 403 and "revoked" in d.get("violated", ""), d))
        s, d = http("POST", f"/caps/{b}/invoke", tb, {"op": "read", "path": str(root / "a.txt")})
        results.append(check("post-event: B-control STILL works (unaffected)", s == 200 and "content" in d, d))

        # CLI path: `capdel event phase-exit` closes the child (its own closes_on). Child already
        # dead via cascade, but it should be marked directly and B-control untouched.
        out = cli("event", "phase-exit")
        results.append(check("CLI `capdel event` runs and reports", "closed" in out, out.strip()))

        # bad event name is rejected, not silently ignored
        s, d = http("POST", "/_event", OWNER, {"name": "bad name with spaces"})
        results.append(check("malformed event name rejected (400)", s == 400, d))
    finally:
        broker.terminate()
        subprocess.run(["rm", "-rf", tmp])

    print(f"\n  closure test — {len(results)} checks, {sum(results)} passed\n")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
