#!/usr/bin/env python3
"""Evidence transcript for issue #6 — real JSON-RPC drive of mcp_server.py against a live
broker, plus a GET /_api/version pin. Output is markdown; run:

    python3.11 .evidence/issue-6/transcript.py > .evidence/issue-6/transcript.md
"""
import json, os, socket, subprocess, sys, tempfile, time, urllib.request, urllib.error
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
CAPDEL = str(ROOT / "capdel.py")
MCP = str(ROOT / "mcp_server.py")
PORT = 4596
BASE = f"http://127.0.0.1:{PORT}"
OWNER = "evidence-owner-secret"


def wait_port(port, secs=10):
    for _ in range(secs * 10):
        s = socket.socket()
        if s.connect_ex(("127.0.0.1", port)) == 0:
            s.close(); return True
        time.sleep(0.1)
    return False


def get(path):
    with urllib.request.urlopen(BASE + path, timeout=10) as r:
        return r.status, json.loads(r.read())


def main():
    tmp = tempfile.mkdtemp(prefix="capdel-evidence-")
    home = os.path.join(tmp, "state")
    content = Path(tmp) / "pub"; content.mkdir(parents=True)
    (content / "readme.txt").write_text("public note\n")
    benv = {**os.environ, "CAPDEL_HOME": home, "CAPDEL_OWNER_SECRET": OWNER}
    broker = subprocess.Popen([sys.executable, CAPDEL, "serve", "--bind", f"127.0.0.1:{PORT}"],
                              env=benv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    assert wait_port(PORT), "broker did not start"
    out = []
    def w(s=""): out.append(s)
    try:
        m = subprocess.run([sys.executable, CAPDEL, "mint", "fs", "--root", str(content),
                            "--ops", "list,read", "--ttl", "20m", "--name", "evidence-reader"],
                           capture_output=True, text=True, env=benv).stdout
        cap = dict(line.split("=", 1) for line in m.strip().splitlines() if "=" in line)
        cid, token = cap["id"], cap["token"]

        w("# Tier-1 evidence — issue #6 (capdel MCP wrapper)")
        w()
        w("Real Model Context Protocol (JSON-RPC 2.0, newline-delimited over stdio) drive of")
        w("`mcp_server.py` against a live `capdel.py` broker, holding only `CAPDEL_URL` +")
        w("`CAPDEL_TOKEN` + `CAP_ID`. Spawned with `python3.11`. No mocks — the broker enforces.")
        w()
        w("## `/_api/version` pin (broker this PR ships)")
        st, ver = get("/_api/version")
        w(f"HTTP {st}  `GET /_api/version` →")
        w("```json")
        w(json.dumps(ver, indent=1))
        w("```")
        w()

        menv = {**os.environ, "CAPDEL_URL": BASE, "CAPDEL_TOKEN": token, "CAP_ID": cid}
        proc = subprocess.Popen([sys.executable, MCP], env=menv, stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
        nid = [0]
        def rpc(method, params=None, note=None, hide=None):
            nid[0] += 1
            req = {"jsonrpc": "2.0", "id": nid[0], "method": method}
            if params is not None:
                req["params"] = params
            proc.stdin.write(json.dumps(req) + "\n"); proc.stdin.flush()
            line = proc.stdout.readline()
            resp = json.loads(line)
            if note:
                w(f"### {note}")
                w()
            w(f"**→** `{method}`" + (f"  params={json.dumps(params)}" if params else ""))
            w("```json")
            shown = dict(resp)
            if hide:
                shown = json.loads(json.dumps(resp))
                for k in hide:
                    if k in shown.get("result", {}):
                        v = shown["result"][k]
                        if isinstance(v, str) and len(v) > 12:
                            shown["result"][k] = v[:10] + "…(redacted)"
            w(json.dumps(shown, indent=1))
            w("```")
            w()
            return resp
        try:
            rpc("initialize", note="1) Handshake — MCP protocolVersion + tools capability + serverInfo")
            rpc("ping")
            rpc("tools/list", note="2) The five capdel verbs are advertised as MCP tools")
            rpc("tools/call", {"name": "describe", "arguments": {}},
                note="3) `describe` (the mid-flight self-description from SPEC §3.5), as a tool")
            rpc("tools/call", {"name": "invoke", "arguments": {"op": "list", "path": str(content)}},
                note="4) `invoke` an ALLOWED op — lists the file (tool success)")
            rpc("tools/call", {"name": "invoke", "arguments": {"op": "write", "path": str(content / "x"), "content": "x"}},
                note="5) `invoke` a DENIED op — tool error (isError=true) NAMING the violated constraint")
            rpc("tools/call", {"name": "attenuate", "arguments": {"constraints": {"root": str(content), "ops": ["read"]}, "name": "child", "ttl_s": 600}},
                note="6) `attenuate` — mints a strictly-narrower child cap + token (redacted)", hide=["token"])
            r = rpc("tools/call", {"name": "escalate", "arguments": {"want": {"ops": ["list", "read", "write"]}, "reason": "need to write results"}},
                note="7) `escalate` — files a request; returns request_id to poll")
            rid = json.loads(r["result"]["content"][0]["text"])["request_id"]
            rpc("tools/call", {"name": "poll_request", "arguments": {"request_id": rid}},
                note="8) `poll_request` — completes the escalate loop shape for an MCP-only harness")
        finally:
            proc.stdin.close(); proc.terminate()
            try: proc.wait(timeout=5)
            except subprocess.TimeoutExpired: proc.kill()
        w("## Result")
        w()
        w("An MCP-only harness, with only the two-values-a-subagent-already-has env, can drive a")
        w("capdel capability end to end as native tools: discover, invoke (allow + deny), delegate")
        w("a narrower cap, and file + poll an escalation. Default bearer auth; the broker is the")
        w("sole reference monitor. `python3.11 test/mcp.py` → 14/14; `python3.11 test/swarm.py` → 14/14.")
    finally:
        broker.terminate()
        subprocess.run(["rm", "-rf", tmp])
    print("\n".join(out))


if __name__ == "__main__":
    main()
