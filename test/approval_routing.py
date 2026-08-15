#!/usr/bin/env python3
"""Black-box approval routing checks for issue #3."""
import json, os, subprocess, sys, tempfile, time, urllib.error, urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CAPDEL = str(ROOT / "capdel.py")
PORT = 4601
BASE = f"http://127.0.0.1:{PORT}"
OWNER = "approval-routing-owner"


def http(method, path, token=None, body=None):
    req = urllib.request.Request(BASE + path, method=method,
        data=json.dumps(body).encode() if body is not None else None)
    if token: req.add_header("Authorization", f"Bearer {token}")
    if body is not None: req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def main():
    tmp = Path(tempfile.mkdtemp(prefix="capdel-approval-"))
    home, hook_log = tmp / "state", tmp / "hook.json"
    root = tmp / "work"; root.mkdir(parents=True)
    hook = tmp / "hook.sh"
    hook.write_text(f"#!/bin/sh\ncat > {hook_log}\nif grep -q '\"reason\": \"fail hook\"' {hook_log}; then exit 3; fi\n")
    hook.chmod(0o700)
    env = {**os.environ, "CAPDEL_HOME": str(home), "CAPDEL_OWNER_SECRET": OWNER,
           "CAPDEL_ESCALATE_HOOK": str(hook)}
    broker = subprocess.Popen([sys.executable, CAPDEL, "serve", "--bind", f"127.0.0.1:{PORT}"], env=env,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(50):
            try:
                urllib.request.urlopen(BASE + "/_api/version", timeout=1).close(); break
            except OSError: time.sleep(.1)
        mint = subprocess.run([sys.executable, CAPDEL, "mint", "fs", "--root", str(root),
            "--ops", "list,read", "--ttl", "20m", "--name", "worker"], env=env,
            capture_output=True, text=True, check=True).stdout
        vals = dict(line.split("=", 1) for line in mint.splitlines() if "=" in line)
        cid, token = vals["id"], vals["token"]
        status, filed = http("POST", f"/caps/{cid}/escalate", token,
            {"want": {"ops": ["list", "read", "write"]}, "reason": "need to update the index"})
        assert status == 200 and filed["granted_if_approved"]["ops"][-1] == "write"
        rid = filed["request_id"]
        for _ in range(50):
            if hook_log.exists(): break
            time.sleep(.1)
        envelope = json.loads(hook_log.read_text())
        assert list(envelope)[0] == "granted_if_approved"
        assert envelope["kind"] == "escalation.filed"
        assert envelope["granted_if_approved"]["ops"] == ["list", "read", "write"]
        assert envelope["reason"] == "need to update the index"
        assert http("GET", "/_requests", "wrong")[0] == 401
        status, view = http("GET", "/_requests", OWNER)
        assert status == 200 and view["requests"][0]["cap"]["name"] == "worker"
        req_file = home / "requests" / f"{rid}.json"
        req = json.loads(req_file.read_text()); req["want"]["ops"].append("stat"); req_file.write_text(json.dumps(req))
        status, approved = http("POST", f"/_requests/{rid}/approve", OWNER, {"ttl_s": 600})
        assert status == 200 and approved == {"ok": True, "cap_id": approved["cap_id"]} and "token" not in approved
        status, poll = http("GET", f"/requests/{rid}", token)
        assert status == 200 and poll["status"] == "approved" and "token" in poll
        status, desc = http("GET", f"/caps/{poll['cap']}", poll["token"])
        assert status == 200 and desc["constraints"]["ops"] == ["list", "read", "write"]
        status, failed = http("POST", f"/caps/{cid}/escalate", token,
            {"want": {"ops": ["list", "read", "write"]}, "reason": "fail hook"})
        assert status == 200
        for _ in range(50):
            events = [json.loads(line) for line in (home / "audit.jsonl").read_text().splitlines()]
            if any(e.get("event") == "hook" and e.get("decision") == "fail" for e in events): break
            time.sleep(.1)
        assert any(e.get("event") == "hook" and e.get("decision") == "fail" for e in events)
        print("approval routing: hook, hook failure isolation, owner gate, no-token approve, poll pickup, and filed-shape clamp passed")
    finally:
        broker.terminate(); broker.wait(timeout=5)
        subprocess.run(["rm", "-rf", str(tmp)], check=False)


if __name__ == "__main__":
    main()
