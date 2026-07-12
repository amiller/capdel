# Tier-1 evidence — issue #6 (capdel MCP wrapper)

Real Model Context Protocol (JSON-RPC 2.0, newline-delimited over stdio) drive of
`mcp_server.py` against a live `capdel.py` broker, holding only `CAPDEL_URL` +
`CAPDEL_TOKEN` + `CAP_ID`. Spawned with `python3.11`. No mocks — the broker enforces.

## `/_api/version` pin (broker this PR ships)
HTTP 200  `GET /_api/version` →
```json
{
 "server": "capdel/0.1",
 "commit": "ea0cf15",
 "pop_mode": "off",
 "schemes": [
  "bearer",
  "capdel-hmac-sha256"
 ]
}
```

### 1) Handshake — MCP protocolVersion + tools capability + serverInfo

**→** `initialize`
```json
{
 "jsonrpc": "2.0",
 "id": 1,
 "result": {
  "protocolVersion": "2024-11-05",
  "capabilities": {
   "tools": {}
  },
  "serverInfo": {
   "name": "capdel",
   "version": "0.1"
  }
 }
}
```

**→** `ping`
```json
{
 "jsonrpc": "2.0",
 "id": 2,
 "result": {}
}
```

### 2) The five capdel verbs are advertised as MCP tools

**→** `tools/list`
```json
{
 "jsonrpc": "2.0",
 "id": 3,
 "result": {
  "tools": [
   {
    "name": "describe",
    "description": "Discover what THIS capability can do \u2014 its type, constraints (fs root+ops, exec argv-allowlist+cwd, or net host:ports), expiry, auth mode, literal usage examples, and how to ask for more. Call this first. No arguments.",
    "inputSchema": {
     "type": "object",
     "properties": {},
     "additionalProperties": false
    }
   },
   {
    "name": "invoke",
    "description": "Exercise the capability against the owner's machine. Pass the capdel invoke body. fs: {op:'list'|'stat'|'read'|'write', path, content?(write), offset?/length?(read)}. exec: {op:'run', argv:[...], cwd?, stdin?}. net: {op:'connect', host, port, send?(base64)}. The broker enforces scope; a denial is returned as a tool error that NAMES the violated constraint so the model can decide to escalate.",
    "inputSchema": {
     "type": "object",
     "description": "the capdel invoke body \u2014 at minimum {op: ...}",
     "properties": {
      "op": {
       "type": "string"
      }
     },
     "required": [
      "op"
     ],
     "additionalProperties": true
    }
   },
   {
    "name": "attenuate",
    "description": "Mint a STRICTLY NARROWER child capability (the broker subset-checks it; 403 otherwise) and return a new {id, token, expires_at, pop} to hand to a less-trusted subprocess. `constraints` must be a subset of this cap's constraints (narrower root / fewer ops / shorter argv prefixes / sooner ttl).",
    "inputSchema": {
     "type": "object",
     "properties": {
      "constraints": {
       "type": "object",
       "description": "narrowed constraints (a subset of this cap's)"
      },
      "name": {
       "type": "string"
      },
      "ttl_s": {
       "type": "integer",
       "minimum": 1
      }
     },
     "required": [
      "constraints"
     ],
     "additionalProperties": false
    }
   },
   {
    "name": "escalate",
    "description": "Request MORE authority than this cap grants, with a reason. The owner rules out-of-band (capdel approve/deny CLI). Returns a request_id to poll. `want` is a DELTA merged onto the current constraints (e.g. add one op). On approval, poll_request returns a NEW token+cap to switch to \u2014 THIS cap is unchanged.",
    "inputSchema": {
     "type": "object",
     "properties": {
      "want": {
       "type": "object",
       "description": "delta on current constraints, e.g. {ops:[...all ops you need...]}"
      },
      "reason": {
       "type": "string",
       "description": "why the extra authority is needed"
      }
     },
     "required": [
      "want",
      "reason"
     ],
     "additionalProperties": false
    }
   },
   {
    "name": "poll_request",
    "description": "Poll an escalation request (the request_id from `escalate`). Returns {status: pending|denied|expired}, or on approval the NEW {token, cap} to switch to. Completes the escalate loop for an MCP-only harness.",
    "inputSchema": {
     "type": "object",
     "properties": {
      "request_id": {
       "type": "string"
      }
     },
     "required": [
      "request_id"
     ],
     "additionalProperties": false
    }
   }
  ]
 }
}
```

### 3) `describe` (the mid-flight self-description from SPEC §3.5), as a tool

**→** `tools/call`  params={"name": "describe", "arguments": {}}
```json
{
 "jsonrpc": "2.0",
 "id": 4,
 "result": {
  "content": [
   {
    "type": "text",
    "text": "{\n \"id\": \"cap-ae9e6753380e\",\n \"name\": \"evidence-reader\",\n \"type\": \"fs\",\n \"constraints\": {\n  \"root\": \"/tmp/capdel-evidence-3z7s2inm/pub\",\n  \"ops\": [\n   \"list\",\n   \"read\"\n  ]\n },\n \"expires_at\": 1783830187,\n \"auth\": \"bearer\",\n \"how\": [\n  \"curl -s -H 'Authorization: Bearer $CAPDEL_TOKEN' -d '{\\\"op\\\":\\\"list\\\",\\\"path\\\":\\\"/tmp/capdel-evidence-3z7s2inm/pub\\\"}' http://127.0.0.1:4596/caps/cap-ae9e6753380e/invoke\",\n  \"you may: list, read. shapes: {\\\"op\\\":\\\"list|stat\\\",\\\"path\\\":\\u2026} {\\\"op\\\":\\\"read\\\",\\\"path\\\":\\u2026,\\\"offset\\\"?:\\u2026,\\\"length\\\"?:\\u2026} {\\\"op\\\":\\\"write\\\",\\\"path\\\":\\u2026,\\\"content\\\":\\u2026}\"\n ],\n \"escalate\": \"POST http://127.0.0.1:4596/caps/cap-ae9e6753380e/escalate {\\\"want\\\":{just the fields to change, e.g. add an op},\\\"reason\\\":\\u2026} \\u2192 poll GET http://127.0.0.1:4596/requests/<request_id>; on approval the poll returns a NEW token+cap to switch to\"\n}"
   }
  ],
  "isError": false
 }
}
```

### 4) `invoke` an ALLOWED op — lists the file (tool success)

**→** `tools/call`  params={"name": "invoke", "arguments": {"op": "list", "path": "/tmp/capdel-evidence-3z7s2inm/pub"}}
```json
{
 "jsonrpc": "2.0",
 "id": 5,
 "result": {
  "content": [
   {
    "type": "text",
    "text": "{\n \"entries\": [\n  {\n   \"name\": \"readme.txt\",\n   \"type\": \"file\",\n   \"size\": 12\n  }\n ]\n}"
   }
  ],
  "isError": false
 }
}
```

### 5) `invoke` a DENIED op — tool error (isError=true) NAMING the violated constraint

**→** `tools/call`  params={"name": "invoke", "arguments": {"op": "write", "path": "/tmp/capdel-evidence-3z7s2inm/pub/x", "content": "x"}}
```json
{
 "jsonrpc": "2.0",
 "id": 6,
 "result": {
  "content": [
   {
    "type": "text",
    "text": "{\n \"error\": \"denied\",\n \"violated\": \"op 'write' not in granted ops ['list', 'read']\"\n}"
   }
  ],
  "isError": true
 }
}
```

### 6) `attenuate` — mints a strictly-narrower child cap + token (redacted)

**→** `tools/call`  params={"name": "attenuate", "arguments": {"constraints": {"root": "/tmp/capdel-evidence-3z7s2inm/pub", "ops": ["read"]}, "name": "child", "ttl_s": 600}}
```json
{
 "jsonrpc": "2.0",
 "id": 7,
 "result": {
  "content": [
   {
    "type": "text",
    "text": "{\n \"id\": \"cap-93bb6a6cf7ba\",\n \"token\": \"ct-465c…(redacted; throwaway cap on a now-dead broker)\",\n \"expires_at\": 1783829587,\n \"pop\": false\n}"
   }
  ],
  "isError": false
 }
}
```

### 7) `escalate` — files a request; returns request_id to poll

**→** `tools/call`  params={"name": "escalate", "arguments": {"want": {"ops": ["list", "read", "write"]}, "reason": "need to write results"}}
```json
{
 "jsonrpc": "2.0",
 "id": 8,
 "result": {
  "content": [
   {
    "type": "text",
    "text": "{\n \"request_id\": \"req-01f2c902e9b5\",\n \"status\": \"pending\",\n \"granted_if_approved\": {\n  \"root\": \"/tmp/capdel-evidence-3z7s2inm/pub\",\n  \"ops\": [\n   \"list\",\n   \"read\",\n   \"write\"\n  ]\n },\n \"note\": \"if approved, poll returns a NEW token + cap id \\u2014 switch to them; your current token is unchanged\",\n \"poll\": \"GET http://127.0.0.1:4596/requests/req-01f2c902e9b5 \\u2014 authenticate as THIS cap (Bearer, or PoP-sign if it is a --pop cap)\"\n}"
   }
  ],
  "isError": false
 }
}
```

### 8) `poll_request` — completes the escalate loop shape for an MCP-only harness

**→** `tools/call`  params={"name": "poll_request", "arguments": {"request_id": "req-01f2c902e9b5"}}
```json
{
 "jsonrpc": "2.0",
 "id": 9,
 "result": {
  "content": [
   {
    "type": "text",
    "text": "{\n \"request_id\": \"req-01f2c902e9b5\",\n \"status\": \"pending\"\n}"
   }
  ],
  "isError": false
 }
}
```

## Result

An MCP-only harness, with only the two-values-a-subagent-already-has env, can drive a
capdel capability end to end as native tools: discover, invoke (allow + deny), delegate
a narrower cap, and file + poll an escalation. Default bearer auth; the broker is the
sole reference monitor. `python3.11 test/mcp.py` → 14/14; `python3.11 test/swarm.py` → 14/14.
