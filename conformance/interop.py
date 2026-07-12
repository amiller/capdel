#!/usr/bin/env python3
"""Cross-implementation interop: prove the two brokers agree BYTE-FOR-BYTE on the crypto,
not just on allow/deny verdicts. Shares one on-disk state dir between them and hands a
PoP token minted by one broker to the other.

  1. python mints a PoP cap p (token tp)          -> file on disk
  2. DENO verifies a tp-signed request against p   (canonicalization + cap-file format agree)
  3. DENO attenuates p -> child (id, tok)          (mode a)
  4. tok == ct-+hmac(tp, child_id)[:32] in python  (mode b derivation is byte-exact)
  5. PYTHON verifies a tok-signed invoke of child  (full round-trip, Deno-minted -> Python-verified)

A single mismatch here is exactly the spec-underspecification bug (canonical string, key
derivation) that having two implementations is designed to surface. Exits non-zero on any fail.
"""
import hashlib, hmac, json, os, secrets, socket, subprocess, sys, tempfile, time
import urllib.request, urllib.error
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PORT = 4601
BASE = f"http://127.0.0.1:{PORT}"
SCHEME = "capdel-hmac-sha256"
OWNER = "owner-" + secrets.token_hex(4)


def cmd(kind, *a):
    return [sys.executable, str(ROOT / "capdel.py"), *a] if kind == "python" else ["deno", "run", "-A", str(ROOT / "capdel.ts"), *a]


def http(method, path, headers=None, body=b""):
    req = urllib.request.Request(BASE + path, data=(body or None), method=method)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    if body:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def sign(token, method, path, body=b""):
    bh = hashlib.sha256(body).hexdigest()
    nonce, ts = secrets.token_hex(16), str(int(time.time()))
    msg = "\n".join([SCHEME, method, path, bh, nonce, ts]).encode()
    return {"Capdel-Nonce": nonce, "Capdel-Timestamp": ts,
            "Capdel-Signature": hmac.new(token.encode(), msg, hashlib.sha256).hexdigest()}


def wait():
    for _ in range(300):
        s = socket.socket()
        if s.connect_ex(("127.0.0.1", PORT)) == 0:
            s.close(); return True
        s.close(); time.sleep(0.05)
    return False


def up(kind, home, mode="allow"):
    p = subprocess.Popen(cmd(kind, "serve", "--bind", f"127.0.0.1:{PORT}"),
                         env={**os.environ, "CAPDEL_HOME": home, "CAPDEL_OWNER_SECRET": OWNER, "CAPDEL_POP": mode},
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    assert wait(), f"{kind} broker did not start"
    return p


def down(p):
    p.terminate()
    try:
        p.wait(timeout=5)
    except Exception:
        p.kill()


def main():
    checks = []
    tmp = tempfile.mkdtemp(prefix="capdel-interop-")
    home = os.path.join(tmp, "state")
    work = os.path.join(tmp, "ws"); os.makedirs(work)
    Path(work, "note.txt").write_text("interop\n")
    fpath = os.path.realpath(os.path.join(work, "note.txt"))

    # 1. python mints a PoP cap
    py = up("python", home)
    _, d = http("POST", "/_mint", {"Authorization": f"Bearer {OWNER}"},
                json.dumps({"type": "fs", "constraints": {"root": os.path.realpath(work), "ops": ["list", "read"]},
                            "name": "interop-pop", "pop": True}).encode())
    p_id, tp = d["id"], d["token"]
    checks.append(("python mints PoP cap", d.get("pop") is True and tp.startswith("ct-")))
    # sanity: python verifies its own signed request
    gp = f"/caps/{p_id}"
    s, _ = http("GET", gp, sign(tp, "GET", gp))
    checks.append(("python verifies its own PoP signature", s == 200))
    down(py)

    # 2. deno (same on-disk state) verifies a python-minted, tp-signed request
    dn = up("deno", home)
    s, dd = http("GET", gp, sign(tp, "GET", gp))
    checks.append(("DENO verifies a PYTHON-minted PoP cap (shared state + canonical agree)",
                   s == 200 and dd.get("auth") == "pop-hmac-sha256"))

    # 3. deno attenuates the python-minted pop cap -> pop child (mode a)
    ap = f"/caps/{p_id}/attenuate"
    abody = json.dumps({"constraints": {"root": os.path.realpath(work), "ops": ["read"]}, "name": "child", "ttl_s": 600}).encode()
    s, cd = http("POST", ap, sign(tp, "POST", ap, abody), abody)
    child_id, child_tok = cd.get("id"), cd.get("token")
    checks.append(("DENO attenuates -> PoP child (mode a token returned)", s == 200 and cd.get("pop") is True))

    # 4. mode b: the child secret Deno derived matches the reference HMAC formula exactly
    derived = "ct-" + hmac.new(tp.encode(), (child_id or "").encode(), hashlib.sha256).hexdigest()[:32]
    checks.append(("DENO's child secret == ct-+HMAC(parent,child_id)[:32] (byte-exact derivation)", derived == child_tok))

    # child invoke works against deno with that key
    ci = f"/caps/{child_id}/invoke"
    ibody = json.dumps({"op": "read", "path": fpath}).encode()
    s, id_ = http("POST", ci, sign(child_tok, "POST", ci, ibody), ibody)
    checks.append(("child invoke works on DENO with derived key", s == 200 and id_.get("content") == "interop\n"))
    down(dn)

    # 5. full round-trip: python verifies the DENO-minted child cap
    py = up("python", home)
    s, id2 = http("POST", ci, sign(child_tok, "POST", ci, ibody), ibody)
    checks.append(("PYTHON verifies a DENO-minted child cap (full round-trip)", s == 200 and id2.get("content") == "interop\n"))
    down(py)

    subprocess.run(["rm", "-rf", tmp])
    print("\n  capdel cross-impl interop\n  " + "-" * 60)
    passed = 0
    for name, ok in checks:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
        passed += 1 if ok else 0
    print("  " + "-" * 60 + f"\n  {passed}/{len(checks)} passed\n")
    return 0 if passed == len(checks) else 1


if __name__ == "__main__":
    sys.exit(main())
