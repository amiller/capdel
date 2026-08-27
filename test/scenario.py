#!/usr/bin/env python3
"""Swarm scenario (issue #9): one disposable broker container + N differently-scoped
worker containers, end to end, with an allow/deny matrix.

    python3 test/scenario.py            # needs docker + docker compose

What it proves, in order (transcript-friendly):
  1. tier-1: test/swarm.py — the in-process swarm (4 concurrent workers + escalation)
     against an ephemeral local broker, all 14 checks.
  2. tier-2: docker compose brings up the disposable owner host (broker container) + an
     echo island + 5 workers whose ONLY env is CAPDEL_URL + a scoped token, each on its
     own internal:true network. Minting happens over the real API (POST /_mint, owner
     secret); workers self-discover (GET /whoami) and exercise their own boundaries; the
     owner approves the escalation (POST /_requests/<rid>/approve) WHILE the other workers
     keep invoking — escalation under load.
  3. version pin: GET /_api/version == this checkout's commit, asserted BEFORE the run and
     again at the end (drift check). Committed evidence lives in .evidence/issue-9/.

Exit code 0 iff no check FAILs. Kernel-gated exec checks SKIP loudly (named reason) on
kernels without Landlock — the VM tier (test/vm.sh) covers those on a real kernel.
"""
import json, os, secrets, shutil, socket, subprocess, sys, tempfile, time, urllib.request, urllib.error
from pathlib import Path

TEST = Path(__file__).resolve().parent
ROOT = TEST.parent
COMPOSE = ["docker", "compose", "-f", str(TEST / "docker-compose.yml"), "--env-file", str(TEST / ".env")]
WORKERS = ["worker-reader", "worker-writer", "worker-exec", "worker-net", "worker-escalator"]
MINTS = {  # cap name -> /_mint body. Container-side paths: the broker container IS the owner host.
    "reader":    {"type": "fs",   "constraints": {"root": "/content/pub",  "ops": ["list", "read"]}},
    "writer":    {"type": "fs",   "constraints": {"root": "/content/work", "ops": ["list", "read", "write"]}},
    "exec":      {"type": "exec", "constraints": {"allow": [["ls"], ["cat"]], "cwd_root": "/content"}},
    "net":       {"type": "net",  "constraints": {"allow": [["echo", 9000]]}},
    "escalator": {"type": "fs",   "constraints": {"root": "/content/work", "ops": ["list", "read"]}},
}


def die(msg):
    print(f"scenario: {msg}", file=sys.stderr)
    sys.exit(2)


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def http(method, path, token=None, body=None, base=None):
    base = base or BASE
    req = urllib.request.Request(base + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    if body is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def compose(*args, check=True):
    r = run(COMPOSE + list(args))
    if check and r.returncode:
        die(f"`docker compose {' '.join(args)}` failed:\n{r.stdout}\n{r.stderr}")
    return r


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def pinned_version():
    s, d = http("GET", "/_api/version")
    assert s == 200, f"/_api/version -> {s} {d}"
    assert d["commit"] == COMMIT, f"version drift: broker serves {d['commit']!r}, checkout is {COMMIT!r}"
    return d["commit"]


# Run inside a worker container (compose run --entrypoint): prove the network island —
# the broker reachable, the internet NOT, a sibling worker's island NOT (by DNS name and
# by its real IP, passed as argv[1]).
EGRESS_PROBE = """import json, socket, sys\ndef reach(h, p, secs=4):\n    s = socket.socket(); s.settimeout(secs)\n    try:\n        s.connect((h, p)); return True\n    except Exception:\n        return False\nsib = sys.argv[1] if len(sys.argv) > 1 else "echo"\nprint(json.dumps({"broker:4571": reach("broker", 4571), "internet:1.1.1.1:80": reach("1.1.1.1", 80),\n                  "sibling_dns:echo:9000": reach("echo", 9000), f"sibling_ip:{sib}:9000": reach(sib, 9000)}))"""


def main():
    global BASE, COMMIT
    if shutil.which("docker") is None:
        die("docker not found on PATH")
    git = run(["git", "-C", str(ROOT), "rev-parse", "--short", "HEAD"])
    if git.returncode:
        die("not a git checkout — the version pin needs a commit to pin")
    COMMIT = git.stdout.strip()

    print(f"== scenario: checkout commit {COMMIT}")
    print("== tier 1: test/swarm.py (in-process swarm, ephemeral broker)")
    t1 = subprocess.run([sys.executable, str(TEST / "swarm.py")])
    if t1.returncode:
        die("tier-1 swarm.py failed — not starting tier 2")

    tmp = tempfile.mkdtemp(prefix="capdel-scenario-")
    results = os.path.join(tmp, "results")
    os.makedirs(results)
    owner_secret = "scenario-" + secrets.token_hex(16)
    host_port = free_port()
    BASE = f"http://127.0.0.1:{host_port}"
    (TEST / ".env").write_text(
        f"CAPDEL_OWNER_SECRET={owner_secret}\nCAPDEL_COMMIT={COMMIT}\n"
        f"CAPDEL_HOST_PORT={host_port}\nRESULTS_DIR={results}\n")

    compose("down", "-v", "--remove-orphans", check=False)  # stale run of this project, if any
    try:
        print(f"\n== tier 2: compose up broker+echo (owner host on 127.0.0.1:{host_port})")
        compose("up", "-d", "--build", "broker", "echo")
        for _ in range(300):
            try:
                http("GET", "/_api/version")
                break
            except (urllib.error.URLError, urllib.error.HTTPError, OSError):
                time.sleep(0.5)
        else:
            die("broker container never came up (see `docker compose logs broker`)")
        pin = pinned_version()
        print(f"   version pin: /_api/version commit == {pin} == checkout {COMMIT}  [OK]")

        print("== tier 2: mint 5 differently-scoped caps over POST /_mint (owner secret)")
        caps = {}
        for name, body in MINTS.items():
            s, d = http("POST", "/_mint", owner_secret, dict(body, name=name, ttl_s=3600))
            assert s == 200 and d.get("token"), f"mint {name} -> {s} {d}"
            caps[name] = d
            print(f"   minted {name:10s} -> {d['id']}")
        with (TEST / ".env").open("a") as f:
            for name, d in caps.items():
                f.write(f"{name.upper()}_TOKEN={d['token']}\n")

        print("== tier 2: launch all 5 workers concurrently (single `compose up`)")
        compose("up", "-d", "--build", *WORKERS)

        print("== tier 2: owner approves the escalation WHILE workers keep invoking")
        esc_cap = caps["escalator"]["id"]
        deadline = time.time() + 180
        approved = False
        while time.time() < deadline and not approved:
            s, d = http("GET", "/_requests", owner_secret)
            for req in d.get("requests", []):
                if req["cap"] and req["cap"]["id"] == esc_cap:
                    s2, d2 = http("POST", f"/_requests/{req['id']}/approve", owner_secret, {})
                    assert s2 == 200, f"approve -> {s2} {d2}"
                    print(f"   approved {req['id']} (escalator wanted {req['want']['ops']})")
                    approved = True
            time.sleep(0.5)
        if not approved:
            die("escalation request never appeared (see `docker compose logs worker-escalator`)")

        print("== tier 2: collect worker matrices")
        rows, fails, skips = [], 0, 0
        for _ in range(120):
            got = sorted(p.name for p in Path(results).glob("*.json"))
            if len(got) == len(MINTS):
                break
            time.sleep(1)
        else:
            die(f"results incomplete after 120s: {sorted(p.name for p in Path(results).glob('*.json'))}")
        for name in MINTS:
            m = json.loads((Path(results) / f"{name}.json").read_text())
            for c in m["checks"]:
                rows.append((name, c))
                mark = c["mark"]
                line = f"  [{mark}] {name}:{c['check']} (got {c['got']}, want {c['expect']})"
                if mark == "FAIL":
                    fails += 1
                    line += f" — {c['detail']}"
                elif mark == "SKIP":
                    skips += 1
                    line += f" — {c['detail']}"
                print(line)

        print("== tier 2: egress proof — a worker's island reaches ONLY the broker")
        echo_ip = run(["docker", "inspect", "capdel-swarm-echo-1", "--format",
                       '{{(index .NetworkSettings.Networks "capdel-swarm_w_net").IPAddress}}'])
        probe = run(COMPOSE + ["run", "--rm", "--no-deps", "--entrypoint", "python3",
                               "worker-reader", "-u", "-c", EGRESS_PROBE, echo_ip.stdout.strip()])
        if probe.returncode:
            die(f"egress probe failed to run:\n{probe.stdout}\n{probe.stderr}")
        egress = json.loads(probe.stdout.strip().splitlines()[-1])
        print(f"   {json.dumps(egress)}")
        want = {"broker:4571": True, "internet:1.1.1.1:80": False,
                "sibling_dns:echo:9000": False, f"sibling_ip:{echo_ip.stdout.strip()}:9000": False}
        if egress != want:
            rows.append(("egress", {"check": "worker island reaches only the broker",
                                    "expect": want, "got": egress, "mark": "FAIL", "detail": egress}))
            fails += 1
        else:
            rows.append(("egress", {"check": "worker island reaches only the broker",
                                    "expect": want, "got": egress, "mark": "PASS", "detail": ""}))
            print("   [PASS] egress: broker reachable, internet and sibling islands NOT")

        print("\n== tier 2 matrix summary")
        print(f"   {len(rows)} checks: {len(rows) - fails - skips} passed, {skips} skipped, {fails} failed")
        assert pinned_version() == COMMIT, "version drift over the run"
        print(f"   version pin re-checked after the run: still {COMMIT}  [OK]")
    finally:
        compose("down", "-v", "--remove-orphans", check=False)
        (TEST / ".env").unlink(missing_ok=True)
        shutil.rmtree(tmp, ignore_errors=True)

    if fails:
        print(f"\nscenario: {fails} FAIL(s)")
        return 1
    print("\nscenario: all green" + (f" ({skips} kernel skip(s), see matrix — VM tier covers them)" if skips else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
