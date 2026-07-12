#!/usr/bin/env python3
"""MCP wrapper test — drives the real broker + a real mcp_server.py subprocess over stdio.

Black-box: starts a throwaway broker, mints a read-only fs cap, spawns `mcp_server.py` with
only CAPDEL_URL/CAPDEL_TOKEN/CAP_ID, and speaks the Model Context Protocol (JSON-RPC 2.0,
newline-delimited) to it — exactly how an MCP-only harness would. Asserts that the five tools
are advertised, that describe/invoke/attenuate/escalate/poll_request work, that a denial
surfaces as a tool error carrying the violated constraint, and that JSON-RPC notifications get
no response.

    python3 test/mcp.py            # starts a throwaway broker on 127.0.0.1:4597

Exits non-zero if any assertion fails. Touches only a tempdir; never ~/.capdel. Complements
test/swarm.py (which exercises the HTTP API + concurrency + escalation directly).
"""
import json, os, socket, subprocess, sys, tempfile, time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CAPDEL = str(ROOT / "capdel.py")
MCP = str(ROOT / "mcp_server.py")
PORT = 4597
BASE = f"http://127.0.0.1:{PORT}"
OWNER = "mcp-test-owner-secret"


def cli(*args, env):
    return subprocess.run([sys.executable, CAPDEL, *args], capture_output=True, text=True, env=env).stdout


def mint(*args, env):
    out = cli("mint", *args, env=env)
    return dict(line.split("=", 1) for line in out.strip().splitlines() if "=" in line)


def wait_port(port, secs=10):
    for _ in range(secs * 10):
        s = socket.socket()
        if s.connect_ex(("127.0.0.1", port)) == 0:
            s.close(); return True
        time.sleep(0.1)
    return False


def mcp(proc, req):
    """Send one JSON-RPC request line, read one response line. req may be a dict (single) —
    the caller controls framing so it can also test notifications/batches separately."""
    proc.stdin.write(json.dumps(req) + "\n"); proc.stdin.flush()
    line = proc.stdout.readline()
    return json.loads(line) if line else None


def text_of(resp):
    """Pull the tool's text payload (JSON-encoded) from a tools/call result."""
    blk = resp["result"]["content"][0]["text"]
    return json.loads(blk)


def main():
    tmp = tempfile.mkdtemp(prefix="capdel-mcp-")
    home = os.path.join(tmp, "state")
    content = Path(tmp) / "content"
    pub = content / "pub"; pub.mkdir(parents=True)
    (pub / "readme.txt").write_text("public note\n")
    broker_env = {**os.environ, "CAPDEL_HOME": home, "CAPDEL_OWNER_SECRET": OWNER}

    checks = []
    def check(name, ok, detail=""):
        checks.append((name, bool(ok), detail))

    broker = subprocess.Popen([sys.executable, CAPDEL, "serve", "--bind", f"127.0.0.1:{PORT}"],
                              env=broker_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        assert wait_port(PORT), "broker did not start"
        cap = mint("fs", "--root", str(pub), "--ops", "list,read", "--ttl", "20m", "--name", "mcp-reader", env=broker_env)
        cid, token = cap["id"], cap["token"]

        # Spawn the MCP server with ONLY the subagent env (CAPDEL_URL/CAPDEL_TOKEN/CAP_ID).
        mcp_env = {**os.environ, "CAPDEL_URL": BASE, "CAPDEL_TOKEN": token, "CAP_ID": cid}
        proc = subprocess.Popen([sys.executable, MCP], env=mcp_env,
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, bufsize=1)
        try:
            # 1. initialize
            r = mcp(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize"})
            res = r.get("result", {})
            check("initialize: protocolVersion + tools capability + serverInfo",
                  res.get("protocolVersion") and "tools" in res.get("capabilities", {})
                  and res.get("serverInfo", {}).get("name") == "capdel", r)

            # 2. notifications/initialized → NO response (send it, then a ping; ping reply proves
            #    the server did not answer the notification).
            proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n"); proc.stdin.flush()
            r = mcp(proc, {"jsonrpc": "2.0", "id": 2, "method": "ping"})
            check("notification gets no response (next reply is ping's, id=2)", r and r.get("id") == 2, r)

            # 3. tools/list advertises the five capdel verbs with inputSchemas
            r = mcp(proc, {"jsonrpc": "2.0", "id": 3, "method": "tools/list"})
            tools = {t["name"]: t for t in r["result"]["tools"]}
            want = {"describe", "invoke", "attenuate", "escalate", "poll_request"}
            check("tools/list advertises describe/invoke/attenuate/escalate/poll_request",
                  want <= set(tools), sorted(set(tools)))
            check("every tool has an inputSchema", all("inputSchema" in t for t in tools.values()), list(tools))

            # 4. describe → this cap, bearer auth, read op present
            r = mcp(proc, {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                           "params": {"name": "describe", "arguments": {}}})
            d = text_of(r)
            check("describe: returns this cap (id, bearer auth, read op)",
                  d.get("id") == cid and d.get("auth") == "bearer" and "read" in d.get("constraints", {}).get("ops", []),
                  r["result"].get("isError"))
            check("describe: not a tool error", r["result"].get("isError") is False, d)

            # 5. invoke list (allowed) → entries include readme.txt
            r = mcp(proc, {"jsonrpc": "2.0", "id": 5, "method": "tools/call",
                           "params": {"name": "invoke", "arguments": {"op": "list", "path": str(pub)}}})
            d = text_of(r)
            names = [e["name"] for e in d.get("entries", [])]
            check("invoke list (allowed): lists readme.txt, not a tool error",
                  "readme.txt" in names and r["result"].get("isError") is False, names)

            # 6. invoke write (denied) → tool error naming the violated op
            r = mcp(proc, {"jsonrpc": "2.0", "id": 6, "method": "tools/call",
                           "params": {"name": "invoke", "arguments": {"op": "write", "path": str(pub / "x"), "content": "x"}}})
            d = text_of(r)
            check("invoke write (denied): isError=True, names the violated op",
                  r["result"].get("isError") is True and "write" in d.get("violated", ""), d)

            # 7. attenuate → strictly-narrower child (read-only on same root)
            r = mcp(proc, {"jsonrpc": "2.0", "id": 7, "method": "tools/call",
                           "params": {"name": "attenuate",
                                      "arguments": {"constraints": {"root": str(pub), "ops": ["read"]}, "name": "child", "ttl_s": 600}}})
            d = text_of(r)
            check("attenuate: mints a new child id+token (not the parent)",
                  d.get("id", "").startswith("cap-") and d.get("id") != cid and d.get("token", "").startswith("ct-")
                  and not r["result"].get("isError"), d)

            # 8. escalate → request_id, pending
            r = mcp(proc, {"jsonrpc": "2.0", "id": 8, "method": "tools/call",
                           "params": {"name": "escalate",
                                      "arguments": {"want": {"ops": ["list", "read", "write"]}, "reason": "need to write results"}}})
            d = text_of(r)
            rid = d.get("request_id")
            check("escalate: returns a pending request_id", bool(rid) and d.get("status") == "pending"
                  and not r["result"].get("isError"), d)

            # 9. poll_request → pending (completes the loop shape; owner approval is out of band)
            r = mcp(proc, {"jsonrpc": "2.0", "id": 9, "method": "tools/call",
                           "params": {"name": "poll_request", "arguments": {"request_id": rid}}})
            d = text_of(r)
            check("poll_request: same request_id, status pending", d.get("request_id") == rid and d.get("status") == "pending", d)

            # 10. unknown tool → JSON-RPC method error (-32602), not a tool result
            r = mcp(proc, {"jsonrpc": "2.0", "id": 10, "method": "tools/call",
                           "params": {"name": "nope", "arguments": {}}})
            check("unknown tool: JSON-RPC error -32602", r.get("error", {}).get("code") == -32602, r.get("error"))

            # 11. malformed line → parse error (-32700), server stays alive
            proc.stdin.write("{not json\n"); proc.stdin.flush()
            line = proc.stdout.readline()
            pe = json.loads(line) if line else {}
            check("malformed line: parse error -32700", pe.get("error", {}).get("code") == -32700, pe)
            # server survives: a follow-up request still answers
            r = mcp(proc, {"jsonrpc": "2.0", "id": 11, "method": "ping"})
            check("server survives the malformed line", r and r.get("id") == 11 and "result" in r, r)

        finally:
            proc.stdin.close(); proc.terminate()
            try: proc.wait(timeout=5)
            except subprocess.TimeoutExpired: proc.kill()
    finally:
        broker.terminate()
        subprocess.run(["rm", "-rf", tmp])

    print(f"\n  mcp wrapper test — {len(checks)} checks\n  " + "-" * 46)
    passed = 0
    for name, ok, detail in checks:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
        if not ok:
            print(f"         detail: {detail}")
        passed += 1 if ok else 0
    print("  " + "-" * 46 + f"\n  {passed}/{len(checks)} passed\n")
    return 0 if passed == len(checks) else 1


if __name__ == "__main__":
    sys.exit(main())
