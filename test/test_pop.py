#!/usr/bin/env python3
"""PoP (HMAC holder-bound tokens) scenario for issue #4 — black-box over the real HTTP API.

Drives `capdel.py serve`/`mint` exactly as an agent/owner would and asserts every line of the
design checklist in tasks/pop-design-hmac.md §7:

  - valid PoP signature passes (invoke + self-describe)
  - tampered body / path / method / nonce / timestamp  -> 403
  - replayed nonce                                      -> 403 (second use)
  - stale timestamp                                     -> 403
  - bearer still works under CAPDEL_POP=allow; a --pop cap forces PoP (bearer rejected)
  - CAPDEL_POP=require rejects bearer, accepts a signed request
  - the shipped ./capdel-sign helper works end-to-end against the broker
  - GET /capdel-sign + describe().sign_helper agree; GET /_api/version pins commit + pop_mode
  - attenuation of a --pop cap yields a PoP child whose key is derivable from the parent (mode b)

Run with python3.9+:   python3.11 test/test_pop.py
Exits non-zero if any check fails. Touches only a tempdir; never ~/.capdel.
"""
import hashlib, hmac, json, os, secrets, socket, subprocess, sys, tempfile, threading, time
import urllib.request, urllib.error
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CAPDEL = str(ROOT / "capdel.py")
PORT = 4577
BASE = f"http://127.0.0.1:{PORT}"
SCHEME = "capdel-hmac-sha256"
SKEW = 300
HOME = None  # set in main


# ---- HTTP + crypto helpers -----------------------------------------------------------

def http_raw(method, path, headers=None, body=b""):
    req = urllib.request.Request(BASE + path, data=(body or None), method=method)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    if body:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def http_json(method, path, headers=None, body=b""):
    s, b = http_raw(method, path, headers, body)
    try:
        return s, json.loads(b or b"{}")
    except ValueError:
        return s, {"_raw": b.decode("utf-8", "replace")}


def pop_headers(token, method, path, body=b""):
    """Compute the three Capdel-* headers for a holder-bound request."""
    bh = hashlib.sha256(body).hexdigest()
    nonce, ts = secrets.token_hex(16), str(int(time.time()))
    msg = "\n".join([SCHEME, method, path, bh, nonce, ts]).encode()
    sig = hmac.new(token.encode(), msg, hashlib.sha256).hexdigest()
    return {"Capdel-Nonce": nonce, "Capdel-Timestamp": ts, "Capdel-Signature": sig}


def wait_port(port, secs=10):
    for _ in range(secs * 10):
        s = socket.socket()
        if s.connect_ex(("127.0.0.1", port)) == 0:
            s.close(); return True
        time.sleep(0.1)
    return False


def cli(*args, pop_mode=None):
    env = {**os.environ, "CAPDEL_HOME": HOME}
    if pop_mode:
        env["CAPDEL_POP"] = pop_mode
    r = subprocess.run([sys.executable, CAPDEL, *args], capture_output=True, text=True, env=env)
    if "id=" not in r.stdout:
        raise RuntimeError(f"capdel {' '.join(args)} failed\nstdout={r.stdout!r}\nstderr={r.stderr!r}")
    return r.stdout


def mint(*args, pop_mode=None):
    out = cli("mint", *args, pop_mode=pop_mode)
    d = dict(line.split("=", 1) for line in out.strip().splitlines() if "=" in line)
    return d["id"], d["token"]


def start_broker(pop_mode):
    env = {**os.environ, "CAPDEL_HOME": HOME, "CAPDEL_POP": pop_mode}
    return subprocess.Popen([sys.executable, CAPDEL, "serve", "--bind", f"127.0.0.1:{PORT}"],
                            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


# ---- checks are (name, ok, detail) tuples -------------------------------------------

def main():
    global HOME
    tmp = tempfile.mkdtemp(prefix="capdel-pop-")
    HOME = os.path.join(tmp, "state")
    root_dir = os.path.join(tmp, "files")
    os.makedirs(root_dir)
    target = os.path.join(root_dir, "note.txt")
    Path(target).write_text("hello pop\n")

    checks = []
    broker = start_broker("allow")
    try:
        assert wait_port(PORT), "broker (allow) did not start"
        cb, tb = mint("fs", "--root", root_dir, "--ops", "list,read", "--ttl", "20m", "--name", "bearer")           # bearer cap
        cp, tp = mint("fs", "--root", root_dir, "--ops", "list,read", "--ttl", "20m", "--name", "pop", "--pop")     # PoP cap
        invoke = f"/caps/{cp}/invoke"
        body_good = json.dumps({"op": "read", "path": target}).encode()

        # 1. valid signature passes (invoke)
        s, d = http_json("POST", invoke, pop_headers(tp, "POST", invoke, body_good), body_good)
        checks.append(("valid PoP signature -> 200 + content", s == 200 and d.get("content") == "hello pop\n", d))

        # 2. valid signature on self-describe (GET)
        s, d = http_json("GET", f"/caps/{cp}", pop_headers(tp, "GET", f"/caps/{cp}", b""))
        checks.append(("PoP-signed GET describe -> 200 + auth=pop", s == 200 and d.get("auth") == "pop-hmac-sha256", d))
        sign_helper = d.get("sign_helper")

        # 3. tampered body -> 403 (sign one body, send different bytes)
        h = pop_headers(tp, "POST", invoke, body_good)
        tampered = json.dumps({"op": "read", "path": target + "x"}).encode()
        s, d = http_json("POST", invoke, h, tampered)
        checks.append(("tampered body -> 403", s == 403, d))

        # 4. tampered path -> 403 (sign for /escalate, POST to /invoke)
        h = pop_headers(tp, "POST", f"/caps/{cp}/escalate", body_good)
        s, d = http_json("POST", invoke, h, body_good)
        checks.append(("tampered path -> 403", s == 403, d))

        # 5. tampered method -> 403 (sign GET, POST)
        h = pop_headers(tp, "GET", invoke, body_good)
        s, d = http_json("POST", invoke, h, body_good)
        checks.append(("tampered method -> 403", s == 403, d))

        # 6. tampered nonce -> 403
        h = pop_headers(tp, "POST", invoke, body_good)
        h["Capdel-Nonce"] = secrets.token_hex(16)
        s, d = http_json("POST", invoke, h, body_good)
        checks.append(("tampered nonce -> 403", s == 403, d))

        # 7. tampered timestamp -> 403
        h = pop_headers(tp, "POST", invoke, body_good)
        h["Capdel-Timestamp"] = str(int(h["Capdel-Timestamp"]) + 1)
        s, d = http_json("POST", invoke, h, body_good)
        checks.append(("tampered timestamp -> 403", s == 403, d))

        # 8. replayed nonce -> second use is 403
        h = pop_headers(tp, "POST", invoke, json.dumps({"op": "list", "path": root_dir}).encode())
        s1, _ = http_json("POST", invoke, h, json.dumps({"op": "list", "path": root_dir}).encode())
        s2, d2 = http_json("POST", invoke, h, json.dumps({"op": "list", "path": root_dir}).encode())
        checks.append(("nonce replay: first 200, second 403", s1 == 200 and s2 == 403, d2))

        # 9. stale timestamp -> 403
        bh = hashlib.sha256(body_good).hexdigest()
        stale_ts = str(int(time.time()) - 3600)
        nonce = secrets.token_hex(16)
        msg = "\n".join([SCHEME, "POST", invoke, bh, nonce, stale_ts]).encode()
        h = {"Capdel-Nonce": nonce, "Capdel-Timestamp": stale_ts,
             "Capdel-Signature": hmac.new(tp.encode(), msg, hashlib.sha256).hexdigest()}
        s, d = http_json("POST", invoke, h, body_good)
        checks.append(("stale timestamp -> 403", s == 403, d))

        # 10. bearer still works under `allow`
        s, d = http_json("POST", f"/caps/{cb}/invoke", {"Authorization": f"Bearer {tb}"}, body_good)
        checks.append(("bearer works under allow", s == 200 and d.get("content") == "hello pop\n", d))

        # 11. a --pop cap forces PoP even under allow: bearer (the secret) is rejected
        s, d = http_json("POST", invoke, {"Authorization": f"Bearer {tp}"}, body_good)
        checks.append(("pop cap rejects bearer (per-cap forces PoP)", s == 403, d))

        # 12. GET /capdel-sign serves the helper, matching describe().sign_helper
        s, b = http_raw("GET", "/capdel-sign")
        checks.append(("GET /capdel-sign serves the signer source", s == 200 and b.startswith(b"#!/usr/bin/env python3")
                       and (sign_helper and b.decode() == sign_helper), (s, b[:40])))

        # 13. GET /_api/version pins commit + pop_mode
        s, d = http_json("GET", "/_api/version")
        checks.append(("/_api/version pins commit + pop_mode=allow",
                       s == 200 and d.get("pop_mode") == "allow" and d.get("commit") and d.get("schemes") == ["bearer", SCHEME], d))

        # 14. the shipped ./capdel-sign helper works end-to-end against the broker
        helper_path = os.path.join(tmp, "capdel-sign")
        Path(helper_path).write_text(sign_helper)
        os.chmod(helper_path, 0o755)
        env = {**os.environ, "CAPDEL_URL": BASE, "CAPDEL_TOKEN": tp, "PATH": os.environ["PATH"]}
        # capdel-sign signs + curls; capture curl stdout (the invoke JSON)
        out = subprocess.run([sys.executable, helper_path, "POST", invoke, json.dumps({"op": "read", "path": target})],
                             capture_output=True, text=True, env=env).stdout
        ok = False
        try:
            ok = json.loads(out).get("content") == "hello pop\n"
        except Exception:
            pass
        checks.append(("shipped capdel-sign helper end-to-end -> 200 + content", ok, out[:120]))

        # 15. attenuate a --pop cap -> PoP child; returned token works (mode a) and is derivable (mode b)
        att_body = json.dumps({"constraints": {"root": root_dir, "ops": ["read"]}, "name": "child", "ttl_s": 600}).encode()
        s, d = http_json("POST", f"/caps/{cp}/attenuate", pop_headers(tp, "POST", f"/caps/{cp}/attenuate", att_body), att_body)
        child_ok_shape = s == 200 and d.get("pop") is True and d.get("token", "").startswith("ct-")
        checks.append(("attenuate pop cap -> pop child (mode a token returned)", child_ok_shape, d))
        if child_ok_shape:
            child_id, child_tok = d["id"], d["token"]
            # mode b: parent derives the SAME secret locally (proves derivation, never transmitted)
            derived = "ct-" + hmac.new(tp.encode(), child_id.encode(), hashlib.sha256).hexdigest()[:32]
            checks.append(("child secret is derivable from parent (mode b)", derived == child_tok, (derived, child_tok)))
            # child invoke works with the returned/derived key
            cbody = json.dumps({"op": "read", "path": target}).encode()
            cinvoke = f"/caps/{child_id}/invoke"
            s2, d2 = http_json("POST", cinvoke, pop_headers(child_tok, "POST", cinvoke, cbody), cbody)
            checks.append(("child cap invoke works with derived key", s2 == 200 and d2.get("content") == "hello pop\n", d2))
        else:
            checks += [("child secret is derivable from parent (mode b)", False, "skipped"),
                       ("child cap invoke works with derived key", False, "skipped")]
    finally:
        broker.terminate()
        try:
            broker.wait(timeout=5)
        except Exception:
            pass

    # --- require mode: bearer rejected, PoP accepted ---------------------------------
    broker = start_broker("require")
    try:
        assert wait_port(PORT), "broker (require) did not start"
        # reuse the state: a fresh pop cap + bearer cap minted under require
        cp2, tp2 = mint("fs", "--root", tmp, "--ops", "list,read", "--ttl", "5m", "--name", "pop2", "--pop")
        cb2, tb2 = mint("fs", "--root", tmp, "--ops", "list,read", "--ttl", "5m", "--name", "bearer2")
        invoke2 = f"/caps/{cp2}/invoke"
        body2 = json.dumps({"op": "list", "path": tmp}).encode()
        # bearer rejected under require
        s, d = http_json("POST", f"/caps/{cb2}/invoke", {"Authorization": f"Bearer {tb2}"}, body2)
        checks.append(("require rejects bearer", s == 403, d))
        # pop accepted under require
        s, d = http_json("POST", invoke2, pop_headers(tp2, "POST", invoke2, body2), body2)
        checks.append(("require accepts PoP", s == 200 and "entries" in d, d))
        s, d = http_json("GET", "/_api/version")
        checks.append(("require: /_api/version pop_mode=require", d.get("pop_mode") == "require", d))
    finally:
        broker.terminate()
        try:
            broker.wait(timeout=5)
        except Exception:
            pass
        subprocess.run(["rm", "-rf", tmp])

    # --- report ----------------------------------------------------------------------
    print(f"\n  pop test — {len(checks)} checks\n  " + "-" * 50)
    passed = 0
    for name, ok, detail in checks:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
        if not ok:
            print(f"         detail: {detail}")
        passed += 1 if ok else 0
    print("  " + "-" * 50 + f"\n  {passed}/{len(checks)} passed\n")
    return 0 if passed == len(checks) else 1


if __name__ == "__main__":
    sys.exit(main())
