#!/usr/bin/env python3
"""Regression test for issue #16 — invoke's `last_used` save must not clobber a concurrent
revoke / fire_event (TOCTOU un-revoke race).

Before the fix, `do_POST` loaded a cap at auth time, ran the work, then did
`cap["last_used"] = now(); save(CAPS, cap)` — writing the WHOLE stale in-memory copy back. A
`fire_event` (POST /_event · `capdel event`) or `cmd_revoke` (`capdel revoke`) that set
`revoked=True` on disk in that window got silently un-revoked.

The fix is a per-cap cross-process advisory lock (fcntl) held by every read-modify-writer of
an existing cap (record_last_used, fire_event, cmd_revoke) + re-load-freshest-and-skip.

Run:  python3 test/test_revoke_race.py        (no third-party deps; asserts, exit 0/1)
      python3 -m pytest test/test_revoke_race.py   (if pytest is installed)
"""
import http.client
import json
import os
import sys
import tempfile
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

# Isolated state: set CAPDEL_HOME + an owner secret BEFORE importing capdel, so its module-
# level HOME/OWNER_SECRET point at scratch space, never the operator's real ~/.capdel.
os.environ["CAPDEL_HOME"] = tempfile.mkdtemp(prefix="capdel-race-")
os.environ["CAPDEL_OWNER_SECRET"] = "test-owner-secret"
import capdel  # noqa: E402  (env must be set first)

capdel.ensure_home()

# capdel's HTTP auth (_token) uses str.removeprefix (Python 3.9+). The box this runs on may
# only have 3.8; the HTTP-level race test skips there. The four direct tests below are the
# deterministic proof of the #16 fix and run on 3.8+.
_PY39 = hasattr(str, "removeprefix")


def _reset():
    """Wipe cap/request state between tests so each starts clean."""
    for p in capdel.CAPS.glob("*.json"):
        p.unlink()
    for p in capdel.REQS.glob("*.json"):
        p.unlink(missing_ok=True)
    if capdel.AUDIT.exists():
        capdel.AUDIT.unlink()


def _mint_fs(closes_on=None):
    root = tempfile.mkdtemp(prefix="capdel-fsroot-")
    Path(root, "hello.txt").write_text("hello")
    cap, token = capdel.mint("fs", {"root": root, "ops": ["list", "read"]}, "racer", 3600,
                             closes_on=closes_on)
    return cap, token, root


def _post(host, port, path, token=None, body=None):
    conn = http.client.HTTPConnection(host, port, timeout=5)
    headers = {}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    payload = json.dumps(body).encode() if body is not None else b""
    if body is not None:
        headers["Content-Type"] = "application/json"
    conn.request("POST", path, body=payload, headers=headers)
    r = conn.getresponse()
    data = r.read().decode()
    conn.close()
    return r.status, data


def test_naive_save_does_clobber_docs_the_bug():
    """Documents the pre-fix behavior so the regression is concrete: a naive save of the
    stale auth-time copy (what do_POST used to do) DOES un-revoke a cap that fire_event just
    closed. The fix replaces that save with record_last_used, proven in the next tests."""
    _reset()
    cap, token, root = _mint_fs(closes_on=["tests-passed"])
    cid = cap["id"]
    stale = capdel.load(capdel.CAPS, cid)          # the auth-time in-memory copy (revoked=False)
    closed = capdel.fire_event("tests-passed")     # owner fires the closure event
    assert cid in closed
    assert capdel.load(capdel.CAPS, cid)["revoked"] is True
    capdel.save(capdel.CAPS, stale)                # THE BUG: save whole stale copy
    after = capdel.load(capdel.CAPS, cid)
    assert after["revoked"] is False, "naive save un-revokes the cap — this is the bug #16 fixes"
    print("ok 0 (documents bug): naive save(stale) un-revokes; record_last_used avoids it")


def test_record_last_used_does_not_unrevoke_after_fire_event():
    """The core fix: invoke holds a stale revoked=False copy; a fire_event lands; invoke then
    calls record_last_used. The cap MUST stay revoked (old code: it would un-revoke)."""
    _reset()
    cap, token, root = _mint_fs(closes_on=["tests-passed"])
    cid = cap["id"]
    stale = capdel.load(capdel.CAPS, cid)          # do_POST's auth-time copy
    assert stale["revoked"] is False
    closed = capdel.fire_event("tests-passed")
    assert cid in closed
    assert capdel.load(capdel.CAPS, cid)["revoked"] is True
    capdel.record_last_used(cid)                   # invoke tries to save last_used from stale copy
    after = capdel.load(capdel.CAPS, cid)
    assert after["revoked"] is True, "issue #16 regression: invoke un-revoked a closed cap"
    assert after["last_used"] is None, "last_used must not be written onto a revoked cap"
    print("ok 1: record_last_used did not clobber fire_event — cap stays revoked")


def test_record_last_used_does_not_unrevoke_after_cmd_revoke():
    """Same invariant against the manual revoke path (cmd_revoke), which the issue notes is the
    pre-existing manifestation."""
    _reset()
    cap, token, root = _mint_fs()
    cid = cap["id"]
    stale = capdel.load(capdel.CAPS, cid)

    class A: pass
    a = A(); a.cap = cid
    capdel.cmd_revoke(a)                            # `capdel revoke <cid>`
    assert capdel.load(capdel.CAPS, cid)["revoked"] is True

    capdel.record_last_used(cid)
    after = capdel.load(capdel.CAPS, cid)
    assert after["revoked"] is True, "issue #16 regression: invoke un-revoked a manually revoked cap"
    print("ok 2: record_last_used did not clobber cmd_revoke — cap stays revoked")


def test_record_last_used_updates_live_cap():
    """No regression of normal usage: on a LIVE cap, last_used IS still recorded."""
    _reset()
    cap, token, root = _mint_fs()
    cid = cap["id"]
    assert capdel.load(capdel.CAPS, cid)["last_used"] is None
    capdel.record_last_used(cid)
    after = capdel.load(capdel.CAPS, cid)
    assert after["revoked"] is False
    assert after["last_used"] is not None, "last_used should be stamped on a live cap"
    print("ok 3: last_used still recorded on a live cap (no behavior regression)")


def test_http_invoke_vs_fire_event_stays_revoked():
    """The race the issue asks for: hammer /invoke from many threads while the owner fires the
    closure event, then assert the cap STAYS revoked. On the fixed code this is deterministic
    (record_last_used + fire_event both take the per-cap lock); on the old code a racing
    invoke's stale save would leave the cap live after the event closed it."""
    if not _PY39:
        print(f"skip 4: HTTP race — capdel's HTTP auth needs str.removeprefix (Py3.9+); "
              f"this box is {sys.version.split()[0]} (pre-existing, unrelated to #16)")
        return "skip"
    _reset()
    cap, token, root = _mint_fs(closes_on=["tests-passed"])
    cid = cap["id"]
    srv = capdel.ThreadingHTTPServer(("127.0.0.1", 0), capdel.Handler)
    host, port = "127.0.0.1", srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    errs = []
    try:
        stop = threading.Event()
        invoke_path = f"/caps/{cid}/invoke"

        def hammer():
            while not stop.is_set():
                try:
                    _post(host, port, invoke_path, token, {"op": "read", "path": os.path.join(root, "hello.txt")})
                except Exception as e:                       # transport errors only; 403 after revoke is fine
                    errs.append(repr(e))

        workers = [threading.Thread(target=hammer) for _ in range(8)]
        for w in workers:
            w.start()
        time.sleep(0.15)                                     # let invokes fill the load→save window
        status, body = _post(host, port, "/_event", os.environ["CAPDEL_OWNER_SECRET"],
                             {"name": "tests-passed"})       # owner fires the event mid-race
        assert status == 200, f"/_event failed: {status} {body}"
        closed = json.loads(body).get("closed", [])
        assert cid in closed, f"event did not close the cap: {body}"
        time.sleep(0.05)
        stop.set()
        for w in workers:
            w.join(timeout=5)

        final = capdel.load(capdel.CAPS, cid)
        assert final["revoked"] is True, "issue #16: a racing invoke un-revoked the cap after fire_event"
        assert not errs, f"invoke threads errored: {errs[:3]}"
        print("ok 4: cap stayed revoked through concurrent invoke + fire_event (HTTP race)")
    finally:
        srv.shutdown()


def _run_all():
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    failed = skipped = 0
    for name, fn in tests:
        try:
            rc = fn()
        except Exception as e:
            failed += 1
            print(f"FAIL {fn.__name__}: {type(e).__name__}: {e}")
            continue
        if rc == "skip":
            skipped += 1
    ran = len(tests) - skipped
    print(f"\n{ran - failed}/{ran} passed, {skipped} skipped", file=sys.stderr)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    _run_all()
