# Tier-1 evidence — capdel issue #4 (HMAC-PoP)

- **commit:** `57c10fa` (`57c10fab19d21dc3a32b4a00977cef16bb1ad73c`)
- **produced:** 2026-07-11 22:10:07-0500
- **target:** local capdel broker `capdel.py serve` (capdel is localhost-by-design; its native deployment shape is the local reference monitor, SPEC §3.7 — there is no pod-staging deployment of the broker).
- **suite:** `python3.11 test/test_pop.py` → 20/20; regression `test/swarm.py` → 14/14.
- **acceptance** (derived from the operator design comment + `tasks/pop-design-hmac.md` §7): a valid PoP signature passes; tampering body/path/method/nonce/timestamp, replaying a nonce, or a stale timestamp each → 403; bearer still works under `off`/`allow`; `require` rejects bearer; `--pop` mints a PoP cap; the relay passes `Capdel-*` headers.

**Setup (CLI, owner-side):** `capdel mint fs --root /tmp/capdel-ev-hw10785o/files --ops list,read --ttl 20m --pop`
→ `id=cap-0643768ba24d`  `token=ct-f03f229e1a9c933…`  (token is now an HMAC key, shown once at mint, never re-sent)
**Bearer cap (regression):** `id=cap-1f072eefedc5`  `token=ct-c17051c5d0e09e6…`

### Commit + mode pin  —  GET /_api/version
`GET /_api/version`
**→ HTTP 200**
```json
{
  "server": "capdel/0.1",
  "commit": "57c10fa",
  "pop_mode": "allow",
  "schemes": [
    "bearer",
    "capdel-hmac-sha256"
  ]
}
```

### Valid PoP signature  →  200 (file read)
`POST /caps/cap-0643768ba24d/invoke`
**headers:**
    Capdel-Nonce: 1c59884d1812d7b12e4379b4ea757eea
    Capdel-Timestamp: 1783825807
    Capdel-Signature: 9b2bb8dd023460ca00ad3b1496b43ca415fe8276537efb3495b1946ef1ff84dd
**body:** `{"op": "read", "path": "/tmp/capdel-ev-hw10785o/files/note.txt"}`
**→ HTTP 200**
```json
{
  "content": "the quick brown fox\n",
  "offset": 0,
  "bytes": 20
}
```

### Tampered BODY (path changed)  →  403
`POST /caps/cap-0643768ba24d/invoke`
**headers:**
    Capdel-Nonce: dff5c4851782d88bba34c973d25bdd72
    Capdel-Timestamp: 1783825807
    Capdel-Signature: 0493a4aaa0c137aa030f17faf188b914bd968b4754179b08eaf7774852fc0c9e
**body:** `{"op": "read", "path": "/tmp/capdel-ev-hw10785o/files/note.txtx"}`
**→ HTTP 403**
```json
{
  "error": "denied",
  "violated": "bad signature"
}
```

### Tampered PATH (signed /escalate, sent /invoke)  →  403
`POST /caps/cap-0643768ba24d/invoke`
**headers:**
    Capdel-Nonce: be8d4fe83a57aef6104531dc0e9cba9e
    Capdel-Timestamp: 1783825807
    Capdel-Signature: 7df3e6a5fbeaa699629eec6d96947f20a309fd695cfe2fd10c56ee0df923398a
**body:** `{"op": "read", "path": "/tmp/capdel-ev-hw10785o/files/note.txt"}`
**→ HTTP 403**
```json
{
  "error": "denied",
  "violated": "bad signature"
}
```

### Tampered NONCE  →  403
`POST /caps/cap-0643768ba24d/invoke`
**headers:**
    Capdel-Nonce: ffa5613e6793e9450364514c962612ed
    Capdel-Timestamp: 1783825807
    Capdel-Signature: 73dbba081bbc09b22ab3447417293e709a6460bfd31cf595efed36bae2cc99c2
**body:** `{"op": "read", "path": "/tmp/capdel-ev-hw10785o/files/note.txt"}`
**→ HTTP 403**
```json
{
  "error": "denied",
  "violated": "bad signature"
}
```

### Replay — first use of a nonce  →  200
`POST /caps/cap-0643768ba24d/invoke`
**headers:**
    Capdel-Nonce: 57167947a76a869b576af3599e12b9ac
    Capdel-Timestamp: 1783825807
    Capdel-Signature: 8766ffe9d32fe4dde84b518d5cc214da5c874a3418d85695ac31434ee1977761
**body:** `{"op": "list", "path": "/tmp/capdel-ev-hw10785o/files"}`
**→ HTTP 200**
```json
{
  "entries": [
    {
      "name": "note.txt",
      "type": "file",
      "size": 20
    }
  ]
}
```

### Replay — SAME nonce reused  →  403 (single-use)
`POST /caps/cap-0643768ba24d/invoke`
**headers:**
    Capdel-Nonce: 57167947a76a869b576af3599e12b9ac
    Capdel-Timestamp: 1783825807
    Capdel-Signature: 8766ffe9d32fe4dde84b518d5cc214da5c874a3418d85695ac31434ee1977761
**body:** `{"op": "list", "path": "/tmp/capdel-ev-hw10785o/files"}`
**→ HTTP 403**
```json
{
  "error": "denied",
  "violated": "nonce replay"
}
```

### Stale TIMESTAMP (1h old, outside ±300s)  →  403
`POST /caps/cap-0643768ba24d/invoke`
**headers:**
    Capdel-Nonce: 8324a7fcd519e616f5cd6ae1e81939e7
    Capdel-Timestamp: 1783822207
    Capdel-Signature: dafcba6af428663f6d99d90efefc86f7119140a22cb2da1d1ea0cd0d66c92a85
**body:** `{"op": "read", "path": "/tmp/capdel-ev-hw10785o/files/note.txt"}`
**→ HTTP 403**
```json
{
  "error": "denied",
  "violated": "timestamp outside \u00b1300s window"
}
```

### Bearer still works under CAPDEL_POP=allow  →  200 (regression)
`POST /caps/cap-1f072eefedc5/invoke`
**headers:**
    Authorization: Bearer ct-c17051c5d0e09e69ced73ab88849061d
**body:** `{"op": "read", "path": "/tmp/capdel-ev-hw10785o/files/note.txt"}`
**→ HTTP 200**
```json
{
  "content": "the quick brown fox\n",
  "offset": 0,
  "bytes": 20
}
```

### Shipped `capdel-sign` helper, end-to-end (no Bearer on the wire)
`GET /capdel-sign > capdel-sign && chmod +x capdel-sign`  (served by the broker)
`./capdel-sign POST /caps/cap-0643768ba24d/invoke '{"op":"read","path":"/tmp/capdel-ev-hw10785o/files/note.txt"}'`
**→ HTTP 200** (content read via the helper)
```json
{
  "content": "the quick brown fox\n",
  "offset": 0,
  "bytes": 20
}
```

### Attenuate a --pop cap  →  PoP child (mode a token returned)
`POST /caps/cap-0643768ba24d/attenuate`
**headers:**
    Capdel-Nonce: 427a7f70c04b69fcd9e8d021b7a1a9b3
    Capdel-Timestamp: 1783825807
    Capdel-Signature: f009ce4f825b9f1d027b8acf3ccfd365e2d28bcf587192bee8431c5edf67f2ea
**body:** `{"constraints": {"root": "/tmp/capdel-ev-hw10785o/files", "ops": ["read"]}, "name": "child", "ttl_s": 600}`
**→ HTTP 200**
```json
{
  "id": "cap-ea61d8b61652",
  "token": "ct-de83cf6254b030392e3b5fbd5a43940a",
  "expires_at": 1783826407,
  "pop": true
}
```

- child secret returned by broker: `ct-de83cf6254b0303…`
- parent derives the SAME secret locally (`capdel-sign derive <child-id>`): `ct-de83cf6254b0303…` — **match: `True`** (never transmitted in mode b)

### CAPDEL_POP=require rejects BEARER  →  403
`POST /caps/cap-634ab72c4b40/invoke`
**headers:**
    Authorization: Bearer ct-42dc37d4029c9c45b0642f06f2b744d5
**body:** `{"op": "list", "path": "/tmp/capdel-ev-hw10785o"}`
**→ HTTP 403**
```json
{
  "error": "denied",
  "violated": "capability has no PoP secret \u2014 mint with --pop (or run under CAPDEL_POP=allow)"
}
```

### CAPDEL_POP=require accepts PoP  →  200
`POST /caps/cap-1194a6ade98f/invoke`
**headers:**
    Capdel-Nonce: 8018cfe785066160759efbb85d62c964
    Capdel-Timestamp: 1783825807
    Capdel-Signature: 9813500d596ec046e83b0a6f9a21eca31b654810f7ce1c849ec850d0b476a37a
**body:** `{"op": "list", "path": "/tmp/capdel-ev-hw10785o"}`
**→ HTTP 200**
```json
{
  "entries": [
    {
      "name": "capdel-sign",
      "type": "file",
      "size": 1512
    },
    {
      "name": "files",
      "type": "dir",
      "size": null
    },
    {
      "name": "state",
      "type": "dir",
      "size": null
    }
  ]
}
```

### require mode pinned at /_api/version
`GET /_api/version`
**→ HTTP 200**
```json
{
  "server": "capdel/0.1",
  "commit": "57c10fa",
  "pop_mode": "require",
  "schemes": [
    "bearer",
    "capdel-hmac-sha256"
  ]
}
```

