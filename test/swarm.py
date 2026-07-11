#!/usr/bin/env python3
"""Swarm scenario: one broker, N differently-scoped workers, concurrent, with assertions.

Black-box test — drives the real `capdel.py serve`/`mint`/`approve` and the HTTP API the
way a swarm would. Each worker holds ONLY its own scoped token and must succeed on its
allowed ops and be refused everything else. Also exercises concurrency (workers hit the
broker at once) and the escalate → owner-approve → resume loop.

    python3 test/swarm.py            # starts a throwaway broker on 127.0.0.1:4599

Exits non-zero if any assertion fails. Touches only a tempdir; never ~/.capdel.
"""
import json, os, socket, subprocess, sys, tempfile, threading, time, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CAPDEL = str(ROOT / "capdel.py")
PORT, ECHO_PORT = 4599, 4588
BASE = f"http://127.0.0.1:{PORT}"
OWNER = "swarm-test-owner-secret"


def http(method, path, token=None, body=None):
    req = urllib.request.Request(BASE + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None)
    if token: req.add_header("Authorization", f"Bearer {token}")
    if body is not None: req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def cli(*args):
    env = {**os.environ, "CAPDEL_HOME": os.environ["CAPDEL_HOME"], "CAPDEL_OWNER_SECRET": OWNER}
    return subprocess.run([sys.executable, CAPDEL, *args], capture_output=True, text=True, env=env).stdout


def mint(*args):
    out = cli("mint", *args)
    d = dict(line.split("=", 1) for line in out.strip().splitlines() if "=" in line)
    return d["id"], d["token"]


def wait_port(port, secs=10):
    for _ in range(secs * 10):
        s = socket.socket()
        if s.connect_ex(("127.0.0.1", port)) == 0: s.close(); return True
        time.sleep(0.1)
    return False


def echo_server(port, stop):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port)); srv.listen(8); srv.settimeout(0.5)
    while not stop.is_set():
        try:
            c, _ = srv.accept()
        except socket.timeout:
            continue
        data = c.recv(4096); c.sendall(data); c.close()   # echo once, then close
    srv.close()


# ---- workers: each returns a list of (check-name, ok, detail) --------------------------

def w_reader(cap, token, pubfile, workfile):
    r = []
    s, d = http("POST", f"/caps/{cap}/invoke", token, {"op": "read", "path": pubfile})
    r.append(("reader: read own file", s == 200 and "content" in d, d))
    s, d = http("POST", f"/caps/{cap}/invoke", token, {"op": "read", "path": workfile})
    r.append(("reader: read OTHER root denied", s == 403, d.get("violated", d)))
    s, d = http("POST", f"/caps/{cap}/invoke", token, {"op": "write", "path": pubfile, "content": "x"})
    r.append(("reader: write denied (read-only)", s == 403, d.get("violated", d)))
    return r

def w_writer(cap, token, workfile, pubfile):
    r = []
    s, d = http("POST", f"/caps/{cap}/invoke", token, {"op": "write", "path": workfile, "content": "hello\n"})
    r.append(("writer: write own root", s == 200 and d.get("created") in (True, False), d))
    s, d = http("POST", f"/caps/{cap}/invoke", token, {"op": "read", "path": pubfile})
    r.append(("writer: read OTHER root denied", s == 403, d.get("violated", d)))
    return r

def w_exec(cap, token, root):
    r = []
    s, d = http("POST", f"/caps/{cap}/invoke", token, {"op": "run", "argv": ["ls", root]})
    r.append(("exec: ls allowed", s == 200 and d.get("code") == 0, d.get("stderr", d)))
    s, d = http("POST", f"/caps/{cap}/invoke", token, {"op": "run", "argv": ["rm", "-rf", root]})
    r.append(("exec: rm denied (not allowlisted)", s == 403, d.get("violated", d)))
    return r

def w_net(cap, token):
    import base64
    r = []
    payload = base64.b64encode(b"ping").decode()
    s, d = http("POST", f"/caps/{cap}/invoke", token, {"op": "connect", "host": "127.0.0.1", "port": ECHO_PORT, "send": payload})
    ok = s == 200 and base64.b64decode(d.get("recv", "")) == b"ping"
    r.append(("net: connect allowed host:port echoes", ok, d))
    s, d = http("POST", f"/caps/{cap}/invoke", token, {"op": "connect", "host": "127.0.0.1", "port": 9999})
    r.append(("net: connect other port denied", s == 403, d.get("violated", d)))
    return r

def w_escalator(cap, token, workfile):
    """Denied write → escalate (delta) → [owner approves out of band] → poll → write."""
    r = []
    s, d = http("POST", f"/caps/{cap}/invoke", token, {"op": "write", "path": workfile, "content": "x"})
    r.append(("escalator: initial write denied", s == 403, d.get("violated", d)))
    s, d = http("POST", f"/caps/{cap}/escalate", token, {"want": {"ops": ["list", "read", "write"]}, "reason": "write results"})
    rid = d.get("request_id")
    r.append(("escalator: escalate accepts delta", s == 200 and rid, d))
    # owner side: wait for it to be visible, approve it by id
    for _ in range(50):
        if any(json.loads(f.read_text())["id"] == rid for f in (Path(os.environ["CAPDEL_HOME"]) / "requests").glob("*.json")):
            break
        time.sleep(0.1)
    cli("approve", rid, "--ttl", "10m")
    nt = nc = None
    for _ in range(50):
        s, d = http("GET", f"/requests/{rid}", token)
        if d.get("status") == "approved": nt, nc = d["token"], d["cap"]; break
        time.sleep(0.1)
    r.append(("escalator: approval yields new creds", bool(nt and nc), d))
    if nt:
        s, d = http("POST", f"/caps/{nc}/invoke", nt, {"op": "write", "path": workfile, "content": "done\n"})
        r.append(("escalator: write works with new cap", s == 200 and d.get("written"), d))
        s, d = http("POST", f"/caps/{cap}/invoke", token, {"op": "write", "path": workfile, "content": "no"})
        r.append(("escalator: OLD token still denied", s == 403, d.get("violated", d)))
    return r


def main():
    tmp = tempfile.mkdtemp(prefix="capdel-swarm-")
    os.environ["CAPDEL_HOME"] = os.path.join(tmp, "state")
    content = Path(tmp) / "content"
    (content / "pub").mkdir(parents=True); (content / "work").mkdir()
    (content / "pub" / "readme.txt").write_text("public note\n")
    (content / "work" / "seed.txt").write_text("work seed\n")

    stop = threading.Event()
    threading.Thread(target=echo_server, args=(ECHO_PORT, stop), daemon=True).start()
    broker = subprocess.Popen([sys.executable, CAPDEL, "serve", "--bind", f"127.0.0.1:{PORT}"],
                              env={**os.environ, "CAPDEL_OWNER_SECRET": OWNER},
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        assert wait_port(PORT), "broker did not start"
        pub, work = str(content / "pub" / "readme.txt"), str(content / "work" / "seed.txt")
        # owner mints one scoped capability per worker
        c_read, t_read = mint("fs", "--root", str(content / "pub"), "--ops", "list,read", "--ttl", "20m", "--name", "reader")
        c_write, t_write = mint("fs", "--root", str(content / "work"), "--ops", "list,read,write", "--ttl", "20m", "--name", "writer")
        c_exec, t_exec = mint("exec", "--allow", "ls", "--allow", "cat", "--cwd-root", str(content), "--ttl", "20m", "--name", "exec")
        c_net, t_net = mint("net", "--allow", f"127.0.0.1:{ECHO_PORT}", "--ttl", "20m", "--name", "net")
        c_esc, t_esc = mint("fs", "--root", str(content / "work"), "--ops", "list,read", "--ttl", "20m", "--name", "escalator")

        # concurrent swarm: four workers hit the broker at once
        jobs = [lambda: w_reader(c_read, t_read, pub, work),
                lambda: w_writer(c_write, t_write, work, pub),
                lambda: w_exec(c_exec, t_exec, str(content)),
                lambda: w_net(c_net, t_net)]
        with ThreadPoolExecutor(max_workers=len(jobs)) as ex:
            checks = [c for fut in [ex.submit(j) for j in jobs] for c in fut.result()]
        # escalation flow (needs owner interaction; run after the barrier)
        checks += w_escalator(c_esc, t_esc, str(content / "work" / "result.txt"))

        print(f"\n  swarm test — {len(checks)} checks\n  " + "-" * 46)
        passed = 0
        for name, ok, detail in checks:
            print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
            if not ok: print(f"         detail: {detail}")
            passed += 1 if ok else 0
        print("  " + "-" * 46 + f"\n  {passed}/{len(checks)} passed\n")
        return 0 if passed == len(checks) else 1
    finally:
        broker.terminate(); stop.set()
        subprocess.run(["rm", "-rf", tmp])


if __name__ == "__main__":
    sys.exit(main())
