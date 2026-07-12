#!/usr/bin/env python3
"""Broker-agnostic conformance runner. Drives conformance/vectors.json over HTTP against
either capdel implementation and asserts identical verdicts.

    python3 conformance/run.py --broker python
    python3 conformance/run.py --broker deno

Same vectors, same expected verdicts on both == the spec is unambiguous on that surface.
Touches only a tempdir; never ~/.capdel. Exits non-zero if any check fails.
"""
import argparse, hashlib, hmac, json, os, secrets, shutil, socket, subprocess, sys, tempfile, threading, time
import urllib.request, urllib.error
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PORT = 4599
BASE = f"http://127.0.0.1:{PORT}"
SCHEME = "capdel-hmac-sha256"
OWNER = "owner-secret-" + secrets.token_hex(4)


def broker_cmd(kind, *cli):
    if kind == "python":
        return [sys.executable, str(ROOT / "capdel.py"), *cli]
    return ["deno", "run", "-A", str(ROOT / "capdel.ts"), *cli]


def http(method, path, headers=None, body=b""):
    req = urllib.request.Request(BASE + path, data=(body or None), method=method)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    if body:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            raw = r.read(); code = r.status
    except urllib.error.HTTPError as e:
        raw = e.read(); code = e.code
    try:
        return code, json.loads(raw or b"{}")
    except ValueError:
        return code, {"_raw": raw.decode("utf-8", "replace")}


def pop_headers(token, method, path, body=b"", *, tamper=None):
    ts = int(time.time())
    if tamper == "stale":
        ts -= 3600
    sig_path = path + "x" if tamper == "path" else path
    sig_method = "GET" if tamper == "method" else method
    bh = hashlib.sha256(body).hexdigest()
    nonce = secrets.token_hex(16)
    msg = "\n".join([SCHEME, sig_method, sig_path, bh, nonce, str(ts)]).encode()
    sig = hmac.new(token.encode(), msg, hashlib.sha256).hexdigest()
    h = {"Capdel-Nonce": nonce, "Capdel-Timestamp": str(ts), "Capdel-Signature": sig}
    if tamper == "nonce":
        h["Capdel-Nonce"] = secrets.token_hex(16)  # sig was for the old nonce
    return h


def wait_port(secs=15):
    for _ in range(secs * 20):
        s = socket.socket()
        if s.connect_ex(("127.0.0.1", PORT)) == 0:
            s.close(); return True
        s.close(); time.sleep(0.05)
    return False


def echo_server():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0)); srv.listen(8)
    port = srv.getsockname()[1]

    def loop():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            try:
                c.sendall(b"OK\n")  # send immediately; the broker may send nothing first
            except OSError:
                pass
            finally:
                c.close()
    threading.Thread(target=loop, daemon=True).start()
    return srv, port


def subst(obj, v):
    if isinstance(obj, dict):
        return {k: subst(x, v) for k, x in obj.items()}
    if isinstance(obj, list):
        return [subst(x, v) for x in obj]
    if isinstance(obj, str):
        if obj == "$TCP_PORT":
            return v["port"]
        for k, val in v["str"].items():
            obj = obj.replace(k, val)
        return obj
    return obj


def run_scenario(kind, sc, env_home, vars_, binds, results):
    for step in sc["steps"]:
        do = step["do"]
        exp = step.get("expect", {})
        name = f"{sc['name']} :: {do}"
        if "note" in step:
            name += f" ({step['note']})"

        if do == "mint":
            b = {"type": step["type"], "constraints": subst(step["constraints"], vars_),
                 "name": step.get("name", "root"), "ttl_s": 3600, "pop": step.get("pop", False),
                 "closes_on": step.get("closes_on")}
            code, d = http("POST", "/_mint", {"Authorization": f"Bearer {OWNER}"}, json.dumps(b).encode())
            if step.get("name") and code == 200:
                binds[step["name"]] = {"id": d["id"], "token": d["token"], "pop": d.get("pop", False)}
            _assert(name, code, d, exp, results)

        elif do in ("invoke", "attenuate", "escalate", "describe"):
            cap = binds[step["cap"]]
            if do == "describe":
                path, method, body = f"/caps/{cap['id']}", "GET", b""
            elif do == "invoke":
                path, method = f"/caps/{cap['id']}/invoke", "POST"
                body = json.dumps(subst(step["body"], vars_)).encode()
            elif do == "attenuate":
                path, method = f"/caps/{cap['id']}/attenuate", "POST"
                body = json.dumps({"constraints": subst(step["constraints"], vars_),
                                   "name": step.get("name", "child"), "ttl_s": 1800}).encode()
            else:
                path, method = f"/caps/{cap['id']}/escalate", "POST"
                body = json.dumps({"want": subst(step["want"], vars_), "reason": step.get("reason", "")}).encode()

            sign = step.get("sign") or (cap["pop"] and not step.get("bearer"))
            tamper = step.get("tamper")
            if tamper == "replay":
                h = pop_headers(cap["token"], method, path, body)
                http(method, path, h, body)  # first use
                code, d = http(method, path, h, body)  # replay
            else:
                if sign:
                    send_body = body + b" " if tamper == "body" else body
                    h = pop_headers(cap["token"], method, path, body, tamper=tamper)
                    code, d = http(method, path, h, send_body)
                else:
                    code, d = http(method, path, {"Authorization": f"Bearer {cap['token']}"}, body)
            if do == "attenuate" and step.get("name") and code == 200:
                binds[step["name"]] = {"id": d["id"], "token": d["token"], "pop": d.get("pop", False)}
            if do == "escalate" and step.get("name") and code == 200:
                binds[step["name"]] = {"req": d["request_id"], "source": step["cap"]}
            _assert(name, code, d, exp, results)

        elif do == "approve":
            esc = binds[step["req"]]
            r = subprocess.run(broker_cmd(kind, "approve", esc["req"]),
                               env={**os.environ, "CAPDEL_HOME": env_home, "CAPDEL_OWNER_SECRET": OWNER},
                               capture_output=True, text=True)
            ok = "approved" in r.stdout
            src = binds[esc["source"]]
            code, d = http("GET", f"/requests/{esc['req']}", {"Authorization": f"Bearer {src['token']}"})
            ok = ok and code == 200 and d.get("status") == "approved" and d.get("token")
            if ok and step.get("name"):
                binds[step["name"]] = {"id": d["cap"], "token": d["token"], "pop": src.get("pop", False)}
            results.append((name, ok, {"cli": r.stdout.strip(), "poll": d}))

        elif do == "event":
            code, d = http("POST", "/_event", {"Authorization": f"Bearer {OWNER}"},
                           json.dumps({"name": step["name"]}).encode())
            results.append((name, code == 200, d))


def _assert(name, code, d, exp, results):
    ok = True
    detail = {"code": code, "resp": d}
    if "status" in exp:
        ok = ok and code == exp["status"]
    if exp.get("violated"):
        ok = ok and "violated" in d
    for k in exp.get("has", []):
        ok = ok and k in d
    for k, val in exp.get("equals", {}).items():
        ok = ok and d.get(k) == val
    results.append((name, ok, detail))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--broker", choices=["python", "deno"], required=True)
    args = ap.parse_args()

    tmp = tempfile.mkdtemp(prefix="capdel-conf-")
    work = os.path.join(tmp, "ws"); sub = os.path.join(work, "sub")
    os.makedirs(sub)
    Path(work, "note.txt").write_text("hello\n")
    Path(sub, "child.txt").write_text("child\n")
    escape = os.path.join(tmp, "escapee"); Path(escape).write_text("secret\n")
    srv, tcp_port = echo_server()

    vars_ = {"port": tcp_port, "str": {
        "$ROOT": os.path.realpath(work), "$FILE": os.path.realpath(os.path.join(work, "note.txt")),
        "$SUB": os.path.realpath(sub), "$ESCAPE": os.path.realpath(escape), "$TCP_HOST": "127.0.0.1"}}

    vectors = json.loads(Path(ROOT, "conformance", "vectors.json").read_text())
    by_mode = {}
    for sc in vectors["scenarios"]:
        by_mode.setdefault(sc.get("pop_mode", "allow"), []).append(sc)

    if args.broker == "deno":
        subprocess.run(["deno", "cache", str(ROOT / "capdel.ts")], check=False)

    results = []
    home = os.path.join(tmp, "state")
    for mode, scs in by_mode.items():
        env = {**os.environ, "CAPDEL_HOME": home, "CAPDEL_OWNER_SECRET": OWNER, "CAPDEL_POP": mode}
        proc = subprocess.Popen(broker_cmd(args.broker, "serve", "--bind", f"127.0.0.1:{PORT}"),
                                env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            if not wait_port():
                err = proc.stderr.read().decode(errors="replace") if proc.stderr else ""
                print(f"broker ({args.broker}, pop={mode}) did not start:\n{err}", file=sys.stderr)
                sys.exit(2)
            binds = {}
            for sc in scs:
                run_scenario(args.broker, sc, home, vars_, binds, results)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except Exception:
                proc.kill()
    srv.close()
    shutil.rmtree(tmp, ignore_errors=True)

    passed = sum(1 for _, ok, _ in results if ok)
    print(f"\n  capdel conformance — broker={args.broker} — {len(results)} checks\n  " + "-" * 60)
    for nm, ok, detail in results:
        print(f"  [{'PASS' if ok else 'FAIL'}] {nm}")
        if not ok:
            print(f"         {json.dumps(detail)[:300]}")
    print("  " + "-" * 60 + f"\n  {passed}/{len(results)} passed  (broker={args.broker})\n")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
