#!/usr/bin/env python3
"""A swarm worker that knows ONLY its URL and its token.

This is the SPEC 3.8 shape: the container's environment is CAPDEL_URL + CAPDEL_TOKEN and
nothing else — no cap id, no plan, no credentials. It bootstraps itself the way a cold
subagent does (docs/user-journeys.md, Journey C): GET /whoami learns what it holds, then it
exercises its own capability at the boundary — every op its constraints permit (must be
allowed) and one just outside each boundary (must be denied) — and writes the allow/deny
matrix to /results/<name>.json for the scenario script to collect.

stdout lines mirror the matrix so `docker compose logs` shows the same truth.
"""
import base64, json, os, sys, time, urllib.request, urllib.error

RESULTS = "/results"
POLL_SECS = 120          # escalation approval window
LOAD_REPEATS = 15        # sustained invokes while siblings hammer the broker


def die(msg):
    print(f"worker: {msg}", file=sys.stderr)
    sys.exit(2)


def http(method, path, token, body=None):
    req = urllib.request.Request(os.environ["CAPDEL_URL"] + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None)
    req.add_header("Authorization", f"Bearer {token}")
    if body is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def kernel_skip(detail):
    # The broker fails LOUDLY when its kernel lacks Landlock (post-#23). Environment gap,
    # not a scope violation: SKIP with the reason, never green, never a silent failure.
    return "kernel confinement failed" in json.dumps(detail)


def fs_probes(c, checks):
    root, ops = c["root"], set(c["ops"])
    def invoke(op, path, content=None):
        body = {"op": op, "path": path}
        if content is not None:
            body["content"] = content
        return http("POST", "/caps/%s/invoke" % CAP_ID, TOKEN, body)

    s, d = invoke("list", root)
    checks.append(("list own root", 200, s, d))
    files = [e["name"] for e in d.get("entries", []) if e.get("type") == "file"] if s == 200 else []
    if files:
        s, d = invoke("read", f"{root}/{files[0]}")
        checks.append((f"read {files[0]} in root", 200, s, d))
    else:
        checks.append(("read a file in root (seeded)", 200, 0, {"entries": d.get("entries")}))
    if "write" in ops:
        s, d = invoke("write", f"{root}/worker-write.txt", "wrote by worker\n")
        checks.append(("write own root (granted)", 200, s, d))
    else:
        s, d = invoke("write", f"{root}/worker-write.txt", "x")
        checks.append(("write denied (op not granted)", 403, s, d))
    s, d = invoke("write", f"{root}/../escape-probe.txt", "x")
    checks.append(("write outside root denied (escape)", 403, s, d))
    if "stat" not in ops:
        s, d = invoke("stat", root)
        checks.append(("stat denied (op not granted)", 403, s, d))
    oks = [invoke("list", root)[0] == 200 for _ in range(LOAD_REPEATS)]
    checks.append((f"sustained list x{LOAD_REPEATS} under swarm load", 200 if all(oks) else 0,
                   200, {"all": oks.count(True), "of": len(oks)}))


def exec_probes(c, checks):
    allow, cwd = c["allow"], c["cwd_root"]
    def run(argv):
        return http("POST", "/caps/%s/invoke" % CAP_ID, TOKEN, {"op": "run", "argv": argv})
    s, d = run(list(allow[0]))
    if kernel_skip(d):
        checks.append((f"run allowlisted {list(allow[0])}", None, s,
                       "SKIP (broker kernel lacks Landlock; VM tier covers this)"))
    else:
        got = 200 if (s == 200 and d.get("code") == 0) else 0
        checks.append((f"run allowlisted {list(allow[0])}", 200, got, d))
    s, d = run(["rm", "-rf", cwd])
    checks.append(("run non-allowlisted denied", 403, s, d))


def net_probes(c, checks):
    host, port = c["allow"][0]
    def connect(h, p, send=None):
        body = {"op": "connect", "host": h, "port": p}
        if send is not None:
            body["send"] = base64.b64encode(send).decode()
        return http("POST", "/caps/%s/invoke" % CAP_ID, TOKEN, body)
    s, d = connect(host, port, b"ping")
    ok = s == 200 and base64.b64decode(d.get("recv", "")) == b"ping"
    checks.append((f"connect allowed {host}:{port} echoes", 200 if ok else 403, s, d))
    s, d = connect("127.0.0.1", 1)
    checks.append(("connect other host:port denied", 403, s, d))
    oks = [connect(host, port, b"ping")[0] == 200 for _ in range(LOAD_REPEATS)]
    checks.append((f"sustained connect x{LOAD_REPEATS} under swarm load", 200 if all(oks) else 0,
                   200, {"all": oks.count(True), "of": len(oks)}))


def escalate_probes(c, checks):
    root = c["root"]
    def invoke(op, path, content=None, token=None, cap=None):
        body = {"op": op, "path": path}
        if content is not None:
            body["content"] = content
        return http("POST", "/caps/%s/invoke" % (cap or CAP_ID), token or TOKEN, body)

    s, d = invoke("write", f"{root}/result.txt", "x")
    checks.append(("initial write denied", 403, s, d))
    s, d = http("POST", f"/caps/{CAP_ID}/escalate", TOKEN,
                {"want": {"ops": ["list", "read", "write"]}, "reason": "write results"})
    rid = d.get("request_id")
    checks.append(("escalate accepts delta", 200, 200 if rid else 0, d))

    # Hammer our own allowed op while the owner decides — escalation under load.
    deadline, new = time.time() + POLL_SECS, None
    load_ok = True
    while time.time() < deadline:
        if invoke("list", root)[0] != 200:
            load_ok = False
        s, d = http("GET", f"/requests/{rid}", TOKEN)
        if d.get("status") == "approved":
            new = (d["token"], d["cap"])
            break
        if d.get("status") in ("denied", "expired"):
            break
        time.sleep(0.3)
    checks.append((f"list kept working while escalation pending ({POLL_SECS}s window)",
                   200, 200 if load_ok else 0, {"load_ok": load_ok}))
    # A pending poll ALSO answers 200 — assert on the creds themselves, not the status.
    checks.append(("approval yields new creds", 200, 200 if new else 0, d))
    if new:
        s, d = invoke("write", f"{root}/result.txt", "done\n", token=new[0], cap=new[1])
        checks.append(("write works with new cap", 200, 200 if d.get("written") else 0, d))
        s, d = invoke("write", f"{root}/result.txt", "no")
        checks.append(("OLD token still denied", 403, s, d))


PROBES = {"fs": fs_probes, "exec": exec_probes, "net": net_probes, "secret": None}


def main():
    global CAP_ID, TOKEN
    TOKEN = os.environ.get("CAPDEL_TOKEN") or die("CAPDEL_TOKEN not set")
    if "CAPDEL_URL" not in os.environ:
        die("CAPDEL_URL not set")
    s, d = http("GET", "/whoami", TOKEN)
    if s != 200:
        die(f"/whoami failed: HTTP {s} {d}")
    CAP_ID, name, ctype, cons = d["id"], d["name"], d["type"], d["constraints"]
    print(f"[{name}] whoami: cap {CAP_ID} type={ctype} constraints={json.dumps(cons)}")

    checks = []  # (label, expect, got_status, detail) — expect None => SKIP
    probe = PROBES.get(ctype)
    if probe is None:
        die(f"no probe set for capability type {ctype!r}")
    # The scenario distinguishes the escalation-journey worker by its minted NAME (the
    # operator's label for the role) — the token itself carries no role.
    if ctype == "fs" and name == "escalator":
        escalate_probes(cons, checks)
    else:
        probe(cons, checks)

    rows, failed = [], 0
    for label, expect, got, detail in checks:
        if expect is None:
            mark, why = "SKIP", detail
        elif got == expect:
            mark, why = "PASS", detail
        else:
            mark, why, failed = "FAIL", detail, failed + 1
        rows.append({"check": label, "expect": expect, "got": got, "mark": mark, "detail": why})
        print(f"[{name}] [{mark}] {label} (got {got})" + (f" — {why}" if mark != "PASS" else ""))

    os.makedirs(RESULTS, exist_ok=True)
    with open(f"{RESULTS}/{name}.json", "w") as f:
        json.dump({"worker": name, "cap": CAP_ID, "type": ctype, "failed": failed, "checks": rows}, f, indent=1)
    print(f"[{name}] done: {len(rows) - failed}/{len(rows)} passed, {failed} failed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
