#!/usr/bin/env python3
"""capdel MCP server — expose a capability as MCP tools for harnesses that only speak MCP.

Thin wrapper (SPEC §7 / README §8 roadmap). An MCP-only harness that gets only the values a
subagent already has — `CAPDEL_URL` + `CAPDEL_TOKEN` (+ `CAP_ID`) — can use a capdel
capability as native MCP tools. This server speaks the Model Context Protocol (JSON-RPC 2.0,
newline-delimited, over stdio) and forwards each tool call to the capdel HTTP API (SPEC §5).
It parses nothing and enforces nothing — the broker is still the reference monitor; this is
purely an adapter so a *static* MCP tool-list can reach a *dynamic* capdel capability that is
normally discovered mid-flight via `GET /caps/<id>` (R7).

Auth: bearer by default (the broker's default, CAPDEL_POP=off). If the cap is a PoP cap
(mint --pop) set CAPDEL_POP=allow|require; TODO: PoP signing belongs in capdel-sign, not here.

    CAPDEL_URL=http://127.0.0.1:4571 CAPDEL_TOKEN=ct-… CAP_ID=cap-… python3 mcp_server.py

Tools: describe | invoke | attenuate | escalate | poll_request
"""
import argparse, json, os, sys, urllib.request, urllib.error

PROTO = "2024-11-05"   # MCP protocol version (modelcontextprotocol spec)
SCHEMES = ["bearer"]   # this wrapper is bearer-only; PoP is handled by capdel-sign

CAP_URL = os.environ.get("CAPDEL_URL", "").rstrip("/")
CAP_TOKEN = os.environ.get("CAPDEL_TOKEN", "")
CAP_ID = os.environ.get("CAP_ID", "")


def env_check():
    """Return None if configured, else a human-readable missing-env message."""
    missing = [n for n, v in (("CAPDEL_URL", CAP_URL), ("CAPDEL_TOKEN", CAP_TOKEN), ("CAP_ID", CAP_ID)) if not v]
    return (f"capdel MCP server is misconfigured: set {', '.join(missing)} in the server's "
            f"environment (the same values a subagent gets)") if missing else None


def api(method, path, body=None):
    """Forward to the broker. Returns (http_status, parsed_json|errdict). Never raises."""
    url = CAP_URL + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {CAP_TOKEN}")
    if body is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:           # 4xx denials are a normal capdel result
        raw = e.read()
        try:
            return e.code, json.loads(raw) if raw else {"error": str(e)}
        except json.JSONDecodeError:
            return e.code, {"error": raw.decode("utf-8", "replace")}
    except urllib.error.URLError as e:
        return 0, {"error": f"broker unreachable at {url}: {e}"}
    except (TimeoutError, OSError) as e:
        return 0, {"error": f"transport error talking to broker: {e}"}


# Tool list. inputSchema is JSON-Schema; kept permissive where the capdel body is type-
# dependent (fs vs exec vs net) so the SAME `invoke` tool serves all three cap types — the
# broker validates the shape, exactly as the HTTP API does.
TOOLS = [
    {
        "name": "describe",
        "description": ("Discover what THIS capability can do — its type, constraints "
                        "(fs root+ops, exec argv-allowlist+cwd, or net host:ports), expiry, "
                        "auth mode, literal usage examples, and how to ask for more. "
                        "Call this first. No arguments."),
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "invoke",
        "description": ("Exercise the capability against the owner's machine. Pass the capdel "
                        "invoke body. fs: {op:'list'|'stat'|'read'|'write', path, content?(write), "
                        "offset?/length?(read)}. exec: {op:'run', argv:[...], cwd?, stdin?}. "
                        "net: {op:'connect', host, port, send?(base64)}. The broker enforces scope; "
                        "a denial is returned as a tool error that NAMES the violated constraint "
                        "so the model can decide to escalate."),
        "inputSchema": {
            "type": "object",
            "description": "the capdel invoke body — at minimum {op: ...}",
            "properties": {"op": {"type": "string"}},
            "required": ["op"],
            "additionalProperties": True,
        },
    },
    {
        "name": "attenuate",
        "description": ("Mint a STRICTLY NARROWER child capability (the broker subset-checks it; "
                        "403 otherwise) and return a new {id, token, expires_at, pop} to hand to a "
                        "less-trusted subprocess. `constraints` must be a subset of this cap's "
                        "constraints (narrower root / fewer ops / shorter argv prefixes / sooner ttl)."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "constraints": {"type": "object", "description": "narrowed constraints (a subset of this cap's)"},
                "name": {"type": "string"},
                "ttl_s": {"type": "integer", "minimum": 1},
            },
            "required": ["constraints"],
            "additionalProperties": False,
        },
    },
    {
        "name": "escalate",
        "description": ("Request MORE authority than this cap grants, with a reason. The owner "
                        "rules out-of-band (capdel approve/deny CLI). Returns a request_id to poll. "
                        "`want` is a DELTA merged onto the current constraints (e.g. add one op). "
                        "On approval, poll_request returns a NEW token+cap to switch to — THIS cap "
                        "is unchanged."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "want": {"type": "object", "description": "delta on current constraints, e.g. {ops:[...all ops you need...]}"},
                "reason": {"type": "string", "description": "why the extra authority is needed"},
            },
            "required": ["want", "reason"],
            "additionalProperties": False,
        },
    },
    {
        "name": "poll_request",
        "description": ("Poll an escalation request (the request_id from `escalate`). Returns "
                        "{status: pending|denied|expired}, or on approval the NEW {token, cap} to "
                        "switch to. Completes the escalate loop for an MCP-only harness."),
        "inputSchema": {
            "type": "object",
            "properties": {"request_id": {"type": "string"}},
            "required": ["request_id"],
            "additionalProperties": False,
        },
    },
]
TOOL_NAMES = {t["name"] for t in TOOLS}


def call_tool(name, args):
    """Return (http_status, payload) from the broker, or (0, errdict) for local arg errors."""
    args = args or {}
    bad = env_check()
    if bad:
        return 0, {"error": bad}
    if name == "describe":
        return api("GET", f"/caps/{CAP_ID}")
    if name == "invoke":
        return api("POST", f"/caps/{CAP_ID}/invoke", args)
    if name == "attenuate":
        if "constraints" not in args:
            return 0, {"error": "attenuate requires 'constraints'"}
        return api("POST", f"/caps/{CAP_ID}/attenuate",
                   {"constraints": args["constraints"], "name": args.get("name"), "ttl_s": args.get("ttl_s")})
    if name == "escalate":
        if "want" not in args:
            return 0, {"error": "escalate requires 'want'"}
        return api("POST", f"/caps/{CAP_ID}/escalate", {"want": args["want"], "reason": args.get("reason", "")})
    if name == "poll_request":
        rid = str(args.get("request_id", "")).strip()
        if not rid:
            return 0, {"error": "poll_request requires 'request_id'"}
        return api("GET", f"/requests/{rid}")
    return 0, {"error": f"unknown tool {name!r}"}


# --- JSON-RPC 2.0 / MCP dispatch ----------------------------------------------------------
def ok(rpc_id, result):
    return {"jsonrpc": "2.0", "id": rpc_id, "result": result}


def err(rpc_id, code, message, data=None):
    e = {"code": code, "message": message}
    if data is not None:
        e["data"] = data
    return {"jsonrpc": "2.0", "id": rpc_id, "error": e}


def tool_result(payload, status):
    """Wrap a broker response as an MCP tools/call result. A 4xx capdel denial is reported
    with isError=true so the model sees a failed tool call, but the violated-constraint body
    is preserved as text so it can reason about escalating."""
    return {"content": [{"type": "text", "text": json.dumps(payload, indent=1)}],
            "isError": status >= 400}


def handle(req):
    """Process one JSON-RPC request object. Return a response object, or None for a
    notification (no id) which must not be answered per JSON-RPC 2.0."""
    if not isinstance(req, dict) or req.get("jsonrpc") != "2.0":
        return err(req.get("id") if isinstance(req, dict) else None, -32600, "Invalid Request")
    rpc_id, method = req.get("id"), req.get("method")
    params = req.get("params") or {}
    if rpc_id is None:                            # notification
        return None
    if method == "initialize":
        return ok(rpc_id, {"protocolVersion": PROTO,
                           "capabilities": {"tools": {}},
                           "serverInfo": {"name": "capdel", "version": "0.1"}})
    if method == "ping":
        return ok(rpc_id, {})
    if method == "tools/list":
        return ok(rpc_id, {"tools": TOOLS})
    if method == "tools/call":
        name = params.get("name")
        if name not in TOOL_NAMES:
            return err(rpc_id, -32602, f"unknown tool {name!r}; known: {sorted(TOOL_NAMES)}")
        status, payload = call_tool(name, params.get("arguments") or {})
        return ok(rpc_id, tool_result(payload, status))
    return err(rpc_id, -32601, f"method not found: {method}")


def main():
    ap = argparse.ArgumentParser(prog="capdel-mcp", description="capdel MCP server (stdio, JSON-RPC 2.0)")
    ap.add_argument("--url", help="override CAPDEL_URL")
    ap.add_argument("--token", help="override CAPDEL_TOKEN")
    ap.add_argument("--cap-id", dest="cap_id", help="override CAP_ID")
    args = ap.parse_args()
    global CAP_URL, CAP_TOKEN, CAP_ID
    CAP_URL = (args.url or CAP_URL).rstrip("/")
    CAP_TOKEN = args.token or CAP_TOKEN
    CAP_ID = args.cap_id or CAP_ID
    if env_check():
        print(f"capdel MCP server: warning — {env_check()}", file=sys.stderr)
        print("  (initialize/tools/list still answer; tool calls will return this error)", file=sys.stderr)

    # Newline-delimited JSON-RPC over stdio. Use readline() in a loop — NOT `for line in
    # sys.stdin`, whose read-ahead iterator blocks on a pipe and breaks request/response
    # latency. Never print anything but JSON-RPC messages to stdout (logs → stderr).
    while True:
        line = sys.stdin.readline()
        if not line:
            break
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            sys.stdout.write(json.dumps(err(None, -32700, "Parse error")) + "\n")
            sys.stdout.flush()
            continue
        # Batch: a JSON array → respond with an array (filtering notifications).
        if isinstance(req, list):
            resp = [r for r in (handle(x) for x in req if isinstance(x, dict)) if r is not None]
            if resp:
                sys.stdout.write(json.dumps(resp) + "\n")
                sys.stdout.flush()
            continue
        resp = handle(req)
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
