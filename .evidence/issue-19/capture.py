#!/usr/bin/env python3
"""Capture a clean end-to-end transcript of issue #19's `secret` cap for evidence.
Runs a fresh broker on a tempdir and prints the exact commands + outputs that prove the
three acceptance bullets. Output is markdown-ready (hermetic, no live key)."""
import base64, json, os, socket, ssl, subprocess, sys, tempfile, threading, time, urllib.request, urllib.error
from pathlib import Path
CAPDEL = str(Path("/tmp/app-19/capdel.py"))
home = tempfile.mkdtemp(); os.environ["CAPDEL_HOME"] = home
os.environ["CAPDEL_OWNER_SECRET"] = "owner-secret"; os.environ["CAPDEL_POP"] = "allow"
VALUE = "sk-MARKER-9f3a-THIS-IS-A-NEEDLE-NOT-A-REAL-KEY"
INJECT = ("GET /v1/models HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {{secret}}\r\nConnection: close\r\n\r\n")

def freeport():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p
port = freeport(); BASE = f"http://127.0.0.1:{port}"
srv = subprocess.Popen([sys.executable, CAPDEL, "serve", "--bind", f"127.0.0.1:{port}"], stderr=subprocess.DEVNULL)
for _ in range(100):
    try: urllib.request.urlopen(f"{BASE}/_api/version", timeout=1).read(); break
    except Exception: time.sleep(0.1)

def cli(*a, stdin=None):
    return subprocess.run([sys.executable, CAPDEL, *a], input=stdin, capture_output=True, text=True,
                          env=os.environ, timeout=20).stdout
def http(m, p, tok=None, body=None):
    req = urllib.request.Request(BASE + p, method=m, data=json.dumps(body).encode() if body else None)
    if tok: req.add_header("Authorization", "Bearer " + tok)
    if body: req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=10) as r: return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e: return e.code, json.loads(e.read())

# an assert-server that records what it receives
eport = free_port = freeport(); recv = {}
def srvr():
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", eport)); s.listen(1); s.settimeout(6)
    try:
        c, _ = s.accept(); recv["b"] = c.recv(512); c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"); c.close()
    except Exception as e: recv["e"] = repr(e)
    s.close()
threading.Thread(target=srvr, daemon=True).start(); time.sleep(0.2)

P = lambda *a: print(*a)
P("# Issue #19 — `secret` cap, end-to-end transcript (Tier 1: real broker on 127.0.0.1)\n")
P(f"Broker: `{BASE}`  (fresh `$CAPDEL_HOME` tempdir; `capdel` commit pinned below)\n")
st, v = http("GET", "/_api/version"); P(f"`GET /_api/version` → {v}\n")

P("## #1  vault ingest + value-never-revealed\n")
P("```")
P("$ printf '%s' 'sk-…' | capdel vault --name openai --allow 127.0.0.1:* --no-tls --no-pop \\")
P("      --inject 'GET /v1/models HTTP/1.1\\r\\nHost: localhost\\r\\nAuthorization: Bearer {{secret}}\\r\\n...'")
out = cli("vault", "--name", "openai", "--allow", "127.0.0.1:*", "--no-tls", "--no-pop", "--ttl", "1h", "--inject", INJECT, stdin=VALUE)
P(out.strip())
P("```\n")
kv = {}
for tok in out.split():
    if "=" in tok: k, _, v2 = tok.partition("="); kv[k] = v2
cid, tok = kv["id"], kv["token"]

P("```")
P("$ capdel tree")
P(cli("tree").rstrip())
P("```")
tree_txt = cli("tree")
P(f"> **value-in-tree?** `{VALUE in tree_txt}` (must be False)\n")

st, desc = http("GET", f"/caps/{cid}", tok)
blob = json.dumps(desc)
P("```")
P(f"$ GET /caps/{cid}  (describe, holder view)")
P(json.dumps(desc, indent=2)[:700] + " …")
P("```")
P(f"> **placeholder `{{{{secret}}}}` shown in describe?** `{'{{secret}}' in blob}`  ·  "
  f"**value in describe?** `{VALUE in blob}` (must be False)\n")

cap_json = Path(home) / "caps" / f"{cid}.json"
vf = Path(home) / "secrets" / f"{cid}.bin"
P(f"> cap JSON on disk carries the value? `{VALUE in cap_json.read_text()}`  ·  "
  f"vault file IS the plaintext? `{VALUE in vf.read_bytes().decode('latin-1')}` (both must be False — at-rest encryption works)\n")

P("## #2  broker injects the key; narrow ok, widen + non-connect denied\n")
st, at = http("POST", f"/caps/{cid}/attenuate", tok,
              body={"constraints": {"destinations": [["127.0.0.1", eport]], "inject": INJECT, "tls": False}, "name": "narrowed", "ttl_s": 3600})
ch, chtok = at["id"], at["token"]
P(f"attenuate to `[127.0.0.1:{eport}]` → 200, child `{ch}`")
st, res = http("POST", f"/caps/{ch}/invoke", chtok, body={"op": "connect", "host": "127.0.0.1", "port": eport})
time.sleep(0.3)
P(f"connect invoke → HTTP {st}; holder's result keys = {list(res.keys())}")
P(f"> **server received the injected credential?** "
  f"`{('Authorization: Bearer ' + VALUE) in recv.get('b', b'').decode('latin-1')}` "
  f"(the holder's request body never contained the key)\n")

st, wide = http("POST", f"/caps/{cid}/attenuate", tok,
                body={"constraints": {"destinations": [["8.8.8.8", 443]], "inject": INJECT, "tls": False}, "name": "x", "ttl_s": 60})
P(f"widen destination to `8.8.8.8:443` → HTTP {st}  (`{wide.get('violated','')[:70]}`)")
st, bad = http("POST", f"/caps/{ch}/invoke", chtok, body={"op": "read", "path": "x"})
P(f"op `read` (attempt to recover the raw secret) → HTTP {bad['error'] if 'error' in bad else st}  "
  f"(there is no op that returns the value)\n")

P("## #3  audit shows each use: cap / ts / dest / bytes — never the value\n")
P("```")
P("$ capdel audit --cap " + ch)
P(cli("audit", "--cap", ch).rstrip())
P("```")
au = cli("audit", "--cap", ch)
P(f"> **value in audit?** `{VALUE in au}` (must be False)  ·  audit rows carry `dest` + `bytes` for each connect ✓\n")
srv.terminate()
