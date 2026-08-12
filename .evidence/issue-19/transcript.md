# Issue #19 — `secret` cap, end-to-end transcript (Tier 1: real broker on 127.0.0.1)

Broker: `http://127.0.0.1:36829`  (fresh `$CAPDEL_HOME` tempdir; `capdel` commit pinned below)

`GET /_api/version` → {'server': 'capdel/0.1', 'commit': '1552c16', 'pop_mode': 'allow', 'schemes': ['bearer', 'capdel-hmac-sha256']}

## #1  vault ingest + value-never-revealed

```
$ printf '%s' 'sk-…' | capdel vault --name openai --allow 127.0.0.1:* --no-tls --no-pop \
      --inject 'GET /v1/models HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {{secret}}\r\n...'
id=cap-a8bed5b9e7fe
token=ct-a16fa251879292ef0c69cda64cf83d48
expires_at=1783887098
type=secret name=openai pop=False
note: the value is vaulted under secrets/cap-a8bed5b9e7fe.bin and is never returned by any op
```

```
$ capdel tree
cap-a8bed5b9e7fe  'openai'  secret [127.0.0.1:*] tls=off  [expires in 60m]
```
> **value-in-tree?** `False` (must be False)

```
$ GET /caps/cap-a8bed5b9e7fe  (describe, holder view)
{
  "id": "cap-a8bed5b9e7fe",
  "name": "openai",
  "type": "secret",
  "constraints": {
    "destinations": [
      [
        "127.0.0.1",
        0
      ]
    ],
    "inject": "GET /v1/models HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {{secret}}\r\nConnection: close\r\n\r\n",
    "tls": false
  },
  "expires_at": 1783887098,
  "auth": "bearer",
  "how": [
    "curl -s -H 'Authorization: Bearer $CAPDEL_TOKEN' -d '{\"op\":\"connect\",\"host\":\"127.0.0.1\",\"port\":0}' http://127.0.0.1:36829/caps/cap-a8bed5b9e7fe/invoke",
    "the broker injects the vaulted credential per the template below; you NEVER see the value. op: {\"op\":\"connect\",\"host\":\u2026,\"port\":\u2026,\"send\"? …
```
> **placeholder `{{secret}}` shown in describe?** `True`  ·  **value in describe?** `False` (must be False)

> cap JSON on disk carries the value? `False`  ·  vault file IS the plaintext? `False` (both must be False — at-rest encryption works)

## #2  broker injects the key; narrow ok, widen + non-connect denied

attenuate to `[127.0.0.1:57897]` → 200, child `cap-939461764c8f`
connect invoke → HTTP 200; holder's result keys = ['recv', 'bytes', 'truncated']
> **server received the injected credential?** `True` (the holder's request body never contained the key)

widen destination to `8.8.8.8:443` → HTTP 403  (`destination [8.8.8.8, 443] not covered by parent destinations [['127.0`)
op `read` (attempt to recover the raw secret) → HTTP denied  (there is no op that returns the value)

## #3  audit shows each use: cap / ts / dest / bytes — never the value

```
$ capdel audit --cap cap-939461764c8f
{"ts": 1783883498, "event": "mint", "cap": "cap-939461764c8f", "parent": "cap-a8bed5b9e7fe", "name": "narrowed", "constraints": {"destinations": [["127.0.0.1", 57897]], "inject": "GET /v1/models HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {{secret}}\r\nConnection: close\r\n\r\n", "tls": false}, "pop": false, "closes_on": []}
{"ts": 1783883498, "event": "invoke", "cap": "cap-939461764c8f", "op": "connect", "arg": "127.0.0.1", "decision": "allow", "dest": "127.0.0.1:57897", "bytes": 40}
{"ts": 1783883498, "event": "invoke", "cap": "cap-939461764c8f", "op": "/caps/cap-939461764c8f/invoke", "decision": "deny", "violated": "op 'read' not supported; the only secret op is 'connect' (the broker injects the vaulted key \u2014 there is deliberately no op that returns it)"}
```
> **value in audit?** `False` (must be False)  ·  audit rows carry `dest` + `bytes` for each connect ✓

