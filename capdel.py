#!/usr/bin/env python3
"""capdel — broker for dynamic capability delegation to agents. See SPEC.md."""
import argparse, base64, hashlib, json, os, re, secrets, socket, subprocess, sys, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HOME = Path(os.environ.get("CAPDEL_HOME", str(Path.home() / ".capdel")))
CAPS, REQS, AUDIT = HOME / "caps", HOME / "requests", HOME / "audit.jsonl"
FS_OPS = {"list", "read", "write", "stat"}
DEF_MAX_BYTES, DEF_TIMEOUT, DEF_MAX_OUTPUT = 1 << 20, 60, 1 << 18
OWNER_SECRET = os.environ.get("CAPDEL_OWNER_SECRET")  # gates read-only /_tree, /_audit


class Denied(Exception): pass


def ensure_home():
    for d in (CAPS, REQS):
        d.mkdir(parents=True, exist_ok=True)
    HOME.chmod(0o700)


def now(): return int(time.time())
def sha(t): return hashlib.sha256(t.encode()).hexdigest()


def load(kind_dir, oid):
    p = kind_dir / f"{oid}.json"
    if not re.fullmatch(r"[a-z]+-[0-9a-f]+", oid or "") or not p.exists():
        return None
    return json.loads(p.read_text())


def save(kind_dir, obj): (kind_dir / f"{obj['id']}.json").write_text(json.dumps(obj, indent=1))


def audit(**kw):
    kw = {"ts": now(), **kw}
    with AUDIT.open("a") as f:
        f.write(json.dumps(kw) + "\n")


def all_caps(): return [json.loads(p.read_text()) for p in sorted(CAPS.glob("*.json"))]


def check_live(cap):
    c = cap
    while c:
        if c["revoked"]: raise Denied(f"capability {c['id']} is revoked")
        if now() > c["expires_at"]: raise Denied(f"capability {c['id']} is expired")
        c = load(CAPS, c["parent"]) if c["parent"] else None


def resolve_inside(root, path):
    rp, rroot = os.path.realpath(path), os.path.realpath(root)
    if os.path.commonpath([rroot, rp]) != rroot:
        raise Denied(f"path {path} escapes root {root}")
    return rp


def path_under(parent, child):
    rp, rc = os.path.realpath(parent), os.path.realpath(child)
    return os.path.commonpath([rp, rc]) == rp


def validate_constraints(type_, c):
    if type_ == "fs":
        if not (isinstance(c.get("root"), str) and os.path.isabs(c["root"])):
            raise Denied("fs constraints need an absolute 'root'")
        if not c.get("ops") or set(c["ops"]) - FS_OPS:
            raise Denied(f"fs 'ops' must be a non-empty subset of {sorted(FS_OPS)}")
    elif type_ == "exec":
        allow = c.get("allow")
        if not allow or not all(isinstance(a, list) and a and all(isinstance(x, str) for x in a) for a in allow):
            raise Denied("exec 'allow' must be a non-empty list of argv prefixes (lists of strings)")
        if not (isinstance(c.get("cwd_root"), str) and os.path.isabs(c["cwd_root"])):
            raise Denied("exec constraints need an absolute 'cwd_root'")
    elif type_ == "net":
        allow = c.get("allow")
        if not allow or not all(isinstance(a, list) and len(a) == 2 and isinstance(a[0], str)
                                and isinstance(a[1], int) and a[1] >= 0 for a in allow):
            raise Denied("net 'allow' must be a non-empty list of [host, port] (port int, 0=any)")
    else:
        raise Denied(f"unknown capability type {type_!r}")


def check_subset(type_, child, parent_cap):
    if type_ != parent_cap["type"]:
        raise Denied(f"type {type_!r} differs from parent type {parent_cap['type']!r}")
    p = parent_cap["constraints"]
    if type_ == "fs":
        extra = set(child["ops"]) - set(p["ops"])
        if extra: raise Denied(f"ops {sorted(extra)} exceed parent ops {p['ops']}")
        if not path_under(p["root"], child["root"]):
            raise Denied(f"root {child['root']} is not under parent root {p['root']}")
        if child.get("max_bytes", DEF_MAX_BYTES) > p.get("max_bytes", DEF_MAX_BYTES):
            raise Denied("max_bytes exceeds parent's")
    elif type_ == "exec":
        for a in child["allow"]:
            if not any(a[:len(pref)] == pref for pref in p["allow"]):
                raise Denied(f"argv prefix {a} is not an extension of any parent prefix {p['allow']}")
        if not path_under(p["cwd_root"], child["cwd_root"]):
            raise Denied(f"cwd_root {child['cwd_root']} is not under parent's {p['cwd_root']}")
        if child.get("timeout_s", DEF_TIMEOUT) > p.get("timeout_s", DEF_TIMEOUT):
            raise Denied("timeout_s exceeds parent's")
        if child.get("max_output", DEF_MAX_OUTPUT) > p.get("max_output", DEF_MAX_OUTPUT):
            raise Denied("max_output exceeds parent's")
    else:  # net
        for ch, cp in child["allow"]:
            if not any(ph == ch and (pp == 0 or pp == cp) for ph, pp in p["allow"]):
                raise Denied(f"destination [{ch}, {cp}] not covered by parent allow {p['allow']}")
        if child.get("max_bytes", DEF_MAX_BYTES) > p.get("max_bytes", DEF_MAX_BYTES):
            raise Denied("max_bytes exceeds parent's")
        if child.get("timeout_s", DEF_TIMEOUT) > p.get("timeout_s", DEF_TIMEOUT):
            raise Denied("timeout_s exceeds parent's")


def mint(type_, constraints, name, ttl_s, parent=None):
    validate_constraints(type_, constraints)
    expires = now() + ttl_s
    if parent:
        check_live(parent)
        check_subset(type_, constraints, parent)
        expires = min(expires, parent["expires_at"])
    token = "ct-" + secrets.token_hex(16)
    cap = {"id": "cap-" + secrets.token_hex(6), "parent": parent["id"] if parent else None,
           "name": name, "type": type_, "constraints": constraints, "expires_at": expires,
           "revoked": False, "token_sha256": sha(token), "created": now(), "last_used": None}
    save(CAPS, cap)
    audit(event="mint", cap=cap["id"], parent=cap["parent"], name=name, constraints=constraints)
    return cap, token


def fs_invoke(cap, body):
    c, op = cap["constraints"], body["op"]
    if op not in c["ops"]:
        raise Denied(f"op {op!r} not in granted ops {c['ops']}")
    rp = resolve_inside(c["root"], body["path"])
    max_bytes = c.get("max_bytes", DEF_MAX_BYTES)
    if op == "list":
        with os.scandir(rp) as it:
            entries = [{"name": e.name, "type": "dir" if e.is_dir() else ("file" if e.is_file() else "other"),
                        "size": e.stat().st_size if e.is_file() else None} for e in it]
        return {"entries": sorted(entries, key=lambda x: x["name"])}
    if op == "stat":
        st = os.stat(rp)
        return {"size": st.st_size, "mtime": int(st.st_mtime), "is_dir": os.path.isdir(rp)}
    if op == "read":
        data = Path(rp).read_bytes()
        if len(data) > max_bytes:
            raise Denied(f"file is {len(data)}B, over max_bytes {max_bytes}")
        return {"content": data.decode("utf-8", "replace")}
    data = body["content"].encode()
    if len(data) > max_bytes:
        raise Denied(f"write of {len(data)}B is over max_bytes {max_bytes}")
    created = not os.path.exists(rp)
    Path(rp).write_bytes(data)
    return {"path": rp, "written": len(data), "created": created}


def exec_invoke(cap, body):
    c, argv = cap["constraints"], body["argv"]
    if not (isinstance(argv, list) and argv and all(isinstance(a, str) for a in argv)):
        raise Denied("argv must be a non-empty list of strings")
    if not any(argv[:len(pref)] == pref for pref in c["allow"]):
        raise Denied(f"argv {argv[:3]}… does not extend any allowed prefix {c['allow']}")
    cwd = resolve_inside(c["cwd_root"], body.get("cwd", c["cwd_root"]))
    r = subprocess.run(argv, cwd=cwd, input=body.get("stdin"), capture_output=True,
                       text=True, timeout=c.get("timeout_s", DEF_TIMEOUT))
    mo = c.get("max_output", DEF_MAX_OUTPUT)
    return {"code": r.returncode, "stdout": r.stdout[:mo], "stderr": r.stderr[:mo],
            "truncated": len(r.stdout) > mo or len(r.stderr) > mo}


def net_invoke(cap, body):
    c = cap["constraints"]
    if body.get("op") != "connect":
        raise Denied(f"op {body.get('op')!r} not supported; net op is 'connect'")
    host, port = body["host"], int(body["port"])
    if not any(ph == host and (pp == 0 or pp == port) for ph, pp in c["allow"]):
        raise Denied(f"[{host}, {port}] not in allowed destinations {c['allow']}")
    max_bytes = c.get("max_bytes", DEF_MAX_BYTES)
    timeout_s = c.get("timeout_s", DEF_TIMEOUT)
    send = base64.b64decode(body["send"]) if body.get("send") else b""
    chunks, total = [], 0
    with socket.create_connection((host, port), timeout=timeout_s) as s:
        s.settimeout(timeout_s)
        if send: s.sendall(send)
        while total < max_bytes:
            b = s.recv(min(65536, max_bytes - total))
            if not b: break
            chunks.append(b); total += len(b)
    return {"recv": base64.b64encode(b"".join(chunks)).decode(), "bytes": total,
            "truncated": total >= max_bytes}


def describe(cap, base):
    c = cap["constraints"]
    dest = c["allow"][0] if (cap["type"] == "net" and c.get("allow")) else ["HOST", 0]
    how = {
        "fs": [f"curl -s -H 'Authorization: Bearer $CAPDEL_TOKEN' -d '{{\"op\":\"list\",\"path\":\"{c.get('root','')}\"}}' {base}/caps/{cap['id']}/invoke",
               'ops: {"op":"list|read|stat","path":…} {"op":"write","path":…,"content":…}'],
        "exec": [f"curl -s -H 'Authorization: Bearer $CAPDEL_TOKEN' -d '{{\"op\":\"run\",\"argv\":[\"ls\"]}}' {base}/caps/{cap['id']}/invoke",
                 'op: {"op":"run","argv":[…],"cwd"?:…,"stdin"?:…}'],
        "net": [f"curl -s -H 'Authorization: Bearer $CAPDEL_TOKEN' -d '{{\"op\":\"connect\",\"host\":\"{dest[0]}\",\"port\":{dest[1]}}}' {base}/caps/{cap['id']}/invoke",
                'op: {"op":"connect","host":…,"port":…,"send"?:<base64>} → {recv:<base64>,bytes,truncated}; send a request with Connection: close so the peer closes'],
    }[cap["type"]]
    return {"id": cap["id"], "name": cap["name"], "type": cap["type"],
            "constraints": cap["constraints"], "expires_at": cap["expires_at"],
            "escalate": f'POST {base}/caps/{cap["id"]}/escalate {{"want":{{just the fields to change, e.g. add an op}},"reason":…}} → poll GET {base}/requests/<request_id>; on approval the poll returns a NEW token+cap to switch to',
            "how": how}


class Handler(BaseHTTPRequestHandler):
    server_version = "capdel/0.1"

    def _json(self, code, obj):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n)) if n else {}

    def _token(self):
        return (self.headers.get("Authorization") or "").removeprefix("Bearer ").strip()

    def _auth(self, cid):
        cap = load(CAPS, cid)
        if not cap or sha(self._token()) != cap["token_sha256"]:
            return None
        return cap

    def _base(self):
        # When a request arrives through the pod relay, the tunnel injects the public
        # URL so self-description hints point somewhere a remote agent can actually reach.
        fwd = self.headers.get("X-Capdel-Public-Base")
        return fwd if fwd else f"http://{self.headers.get('Host', self.server.server_address[0])}"

    def _owner_ok(self):
        return bool(OWNER_SECRET) and self._token() == OWNER_SECRET

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path in ("/_tree", "/_audit"):
            if not self._owner_ok(): return self._json(401, {"error": "owner secret required"})
            return self._json(200, {"tree": tree_data()} if path == "/_tree" else {"audit": audit_tail()})
        m = re.fullmatch(r"/caps/([\w-]+)", self.path)
        if m:
            cap = self._auth(m.group(1))
            if not cap: return self._json(401, {"error": "unknown capability or bad token"})
            return self._json(200, describe(cap, self._base()))
        m = re.fullmatch(r"/requests/([\w-]+)", self.path)
        if m:
            req = load(REQS, m.group(1))
            if not req: return self._json(404, {"error": "unknown request"})
            cap = load(CAPS, req["cap"])
            if not cap or sha(self._token()) != cap["token_sha256"]:
                return self._json(401, {"error": "token does not own this request"})
            out = {"request_id": req["id"], "status": req["status"]}
            if req["status"] == "approved":
                out.update(token=req["token"], cap=req["minted_cap"])
            return self._json(200, out)
        self._json(404, {"error": "no such route"})

    def do_POST(self):
        m = re.fullmatch(r"/caps/([\w-]+)/(invoke|attenuate|escalate)", self.path)
        if not m:
            return self._json(404, {"error": "no such route"})
        cap = self._auth(m.group(1))
        if not cap:
            return self._json(401, {"error": "unknown capability or bad token"})
        action = m.group(2)
        try:
            body = self._body()
            check_live(cap)
            if action == "invoke":
                result = {"fs": fs_invoke, "exec": exec_invoke, "net": net_invoke}[cap["type"]](cap, body)
                cap["last_used"] = now()
                save(CAPS, cap)
                audit(event="invoke", cap=cap["id"], op=body.get("op"),
                      arg=body.get("path") or body.get("argv") or body.get("host"), decision="allow")
                return self._json(200, result)
            if action == "attenuate":
                child, token = mint(cap["type"], body["constraints"], body.get("name", f"child of {cap['id']}"),
                                    int(body.get("ttl_s", 3600)), parent=cap)
                return self._json(200, {"id": child["id"], "token": token, "expires_at": child["expires_at"]})
            # `want` may be a delta — merge it onto the cap's current constraints so a
            # holder can ask for just the extra op/host without restating root/cwd_root.
            want = {**cap["constraints"], **(body.get("want") or {})}
            validate_constraints(cap["type"], want)
            req = {"id": "req-" + secrets.token_hex(6), "cap": cap["id"], "type": cap["type"],
                   "want": want, "reason": body.get("reason", ""), "status": "pending", "created": now()}
            save(REQS, req)
            audit(event="escalate", cap=cap["id"], request=req["id"], want=want, reason=req["reason"])
            return self._json(200, {"request_id": req["id"], "status": "pending",
                                    "granted_if_approved": want,
                                    "note": "if approved, poll returns a NEW token + cap id — switch to them; your current token is unchanged",
                                    "poll": f"GET {self._base()}/requests/{req['id']}"})
        except Denied as e:
            audit(event=action, cap=cap["id"], op=self.path, decision="deny", violated=str(e))
            return self._json(403, {"error": "denied", "violated": str(e)})
        except (KeyError, ValueError, TypeError) as e:
            return self._json(400, {"error": f"bad request: {e!r}"})
        except (FileNotFoundError, NotADirectoryError, IsADirectoryError, PermissionError) as e:
            return self._json(404, {"error": str(e)})
        except subprocess.TimeoutExpired as e:
            return self._json(408, {"error": f"timed out after {e.timeout}s"})
        except TimeoutError:
            return self._json(408, {"error": "connection timed out (peer may not have closed; send Connection: close)"})
        except OSError as e:
            return self._json(502, {"error": f"connection failed: {e}"})

    def log_message(self, fmt, *args):
        sys.stderr.write("%s %s\n" % (self.address_string(), fmt % args))


def parse_ttl(s):
    m = re.fullmatch(r"(\d+)([smhd]?)", s)
    if not m: raise SystemExit(f"bad ttl {s!r} (use e.g. 90s, 30m, 4h, 2d)")
    return int(m.group(1)) * {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]


def fmt_constraints(cap):
    c = cap["constraints"]
    if cap["type"] == "fs":
        return f"fs {','.join(c['ops'])} {c['root']}"
    if cap["type"] == "exec":
        return f"exec [{' | '.join(' '.join(a) for a in c['allow'])}] cwd={c['cwd_root']}"
    dests = ', '.join(f"{h}:{p if p else '*'}" for h, p in c["allow"])
    return f"net [{dests}]"


def tree_data():
    kids = {}
    for c in all_caps():
        kids.setdefault(c["parent"], []).append(c)
    def node(c):
        return {"id": c["id"], "name": c["name"], "type": c["type"], "summary": fmt_constraints(c),
                "constraints": c["constraints"], "expires_at": c["expires_at"],
                "revoked": c["revoked"], "last_used": c["last_used"],
                "children": [node(k) for k in kids.get(c["id"], [])]}
    return [node(c) for c in kids.get(None, [])]


def audit_tail(n=200):
    if not AUDIT.exists(): return []
    return [json.loads(l) for l in AUDIT.read_text().splitlines()[-n:]]


def cmd_tree(_):
    def walk(n, depth):
        state = "REVOKED" if n["revoked"] else ("expired" if now() > n["expires_at"] else
                f"expires in {(n['expires_at'] - now()) // 60}m")
        used = f", last used {(now() - n['last_used']) // 60}m ago" if n["last_used"] else ""
        print(f"{'  ' * depth}{n['id']}  {n['name']!r}  {n['summary']}  [{state}{used}]")
        for k in n["children"]:
            walk(k, depth + 1)
    for n in tree_data():
        walk(n, 0)


def parse_dest(s):
    host, sep, port = s.rpartition(":")
    if not sep or not host:
        raise SystemExit(f"bad destination {s!r} (use host:port or host:*)")
    return [host, 0 if port in ("*", "0", "") else int(port)]


def cmd_mint(a):
    if a.type == "fs":
        constraints = {"root": os.path.realpath(a.root), "ops": a.ops.split(",")}
        if a.max_bytes: constraints["max_bytes"] = a.max_bytes
    elif a.type == "exec":
        constraints = {"allow": [al.split() for al in a.allow], "cwd_root": os.path.realpath(a.cwd_root)}
        if a.timeout: constraints["timeout_s"] = a.timeout
    else:  # net
        constraints = {"allow": [parse_dest(al) for al in a.allow]}
        if a.max_bytes: constraints["max_bytes"] = a.max_bytes
        if a.timeout: constraints["timeout_s"] = a.timeout
    cap, token = mint(a.type, constraints, a.name, parse_ttl(a.ttl))
    print(f"id={cap['id']}\ntoken={token}\nexpires_at={cap['expires_at']}")


def cmd_requests(_):
    for p in sorted(REQS.glob("*.json")):
        r = json.loads(p.read_text())
        if r["status"] != "pending": continue
        cap = load(CAPS, r["cap"])
        print(f"{r['id']}  from {r['cap']} ({cap['name']!r})  reason: {r['reason']}\n"
              f"  wants: {json.dumps(r['want'])}")


def cmd_approve(a):
    req = load(REQS, a.request)
    if not req or req["status"] != "pending": raise SystemExit(f"no pending request {a.request}")
    # The owner is the root of authority. An escalation exists because the needed grant
    # was NOT in the requester's chain, so approving mints it as a fresh owner capability
    # (same power as `capdel mint`) — not a sibling clamped to the requester's ancestor.
    cap, token = mint(req["type"], req["want"], f"escalation {req['id']} for {req['cap']}", parse_ttl(a.ttl))
    req.update(status="approved", token=token, minted_cap=cap["id"], decided=now())
    save(REQS, req)
    audit(event="approve", request=req["id"], cap=cap["id"])
    print(f"approved: minted {cap['id']} (fresh owner grant)")


def cmd_deny(a):
    req = load(REQS, a.request)
    if not req or req["status"] != "pending": raise SystemExit(f"no pending request {a.request}")
    req.update(status="denied", decided=now())
    save(REQS, req)
    audit(event="deny", request=req["id"])
    print("denied")


def cmd_revoke(a):
    cap = load(CAPS, a.cap)
    if not cap: raise SystemExit(f"no capability {a.cap}")
    cap["revoked"] = True
    save(CAPS, cap)
    audit(event="revoke", cap=cap["id"])
    print(f"revoked {cap['id']} (and its whole subtree, checked at invoke time)")


def cmd_audit(a):
    if not AUDIT.exists(): return
    for line in AUDIT.read_text().splitlines():
        e = json.loads(line)
        if a.cap and e.get("cap") != a.cap: continue
        print(json.dumps(e))


def cmd_serve(a):
    host, port = a.bind.rsplit(":", 1)
    srv = ThreadingHTTPServer((host, int(port)), Handler)
    owner = "with owner endpoints (/_tree, /_audit)" if OWNER_SECRET else "no owner secret (/_tree disabled)"
    print(f"capdel broker on http://{a.bind}  (state: {HOME}; {owner})", file=sys.stderr)
    srv.serve_forever()


def cmd_tunnel(a):
    # Dial-out relay client (§3.7): long-poll the pod relay for requests aimed at this
    # broker, replay each against the LOCAL broker, post the response back. No inbound
    # port on this machine; the broker is the only thing that enforces anything.
    import urllib.request, urllib.error
    relay, bid, local = a.relay.rstrip("/"), a.broker_id, f"http://{a.broker}"
    sec = {"X-Capdel-Relay-Secret": a.secret} if a.secret else {}
    def call(url, data=None, headers=None, method=None, timeout=40):
        r = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
        return urllib.request.urlopen(r, timeout=timeout)
    print(f"capdel tunnel: {relay} <-> {local} as broker {bid!r}", file=sys.stderr)
    while True:
        try:
            with call(f"{relay}/_pull/{bid}?wait=25", headers=sec, timeout=40) as r:
                if r.status == 204: continue
                job = json.loads(r.read())
        except urllib.error.HTTPError as e:
            print(f"pull error {e.code}: {e.read()[:200]}", file=sys.stderr); time.sleep(3); continue
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            time.sleep(3); continue
        body = job.get("body")
        lheaders = dict(job.get("headers") or {})
        lheaders["X-Capdel-Public-Base"] = f"{relay}/b/{bid}"  # so hints point at the relay, not localhost
        try:
            with call(local + job["path"], data=body.encode() if body else None,
                      headers=lheaders, method=job["method"], timeout=90) as lr:
                status, out = lr.status, lr.read().decode()
        except urllib.error.HTTPError as e:
            status, out = e.code, e.read().decode()
        except Exception as e:
            status, out = 502, json.dumps({"error": f"local broker unreachable: {e}"})
        try:
            call(f"{relay}/_reply/{bid}/{job['req_id']}",
                 data=json.dumps({"status": status, "body": out}).encode(),
                 headers={**sec, "Content-Type": "application/json"}, method="POST", timeout=15).read()
        except Exception as e:
            print(f"reply error: {e}", file=sys.stderr)


def main():
    ensure_home()
    p = argparse.ArgumentParser(prog="capdel")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve"); s.add_argument("--bind", default="127.0.0.1:4571"); s.set_defaults(f=cmd_serve)
    s = sub.add_parser("tunnel")
    s.add_argument("--relay", required=True); s.add_argument("--broker-id", dest="broker_id", required=True)
    s.add_argument("--broker", default="127.0.0.1:4571")
    s.add_argument("--secret", default=os.environ.get("CAPDEL_RELAY_SECRET"))
    s.set_defaults(f=cmd_tunnel)
    s = sub.add_parser("mint")
    s.add_argument("type", choices=["fs", "exec", "net"])
    s.add_argument("--root"); s.add_argument("--ops", default="list,read"); s.add_argument("--max-bytes", type=int, dest="max_bytes")
    s.add_argument("--allow", action="append", default=[]); s.add_argument("--cwd-root", dest="cwd_root"); s.add_argument("--timeout", type=int)
    s.add_argument("--ttl", default="4h"); s.add_argument("--name", default="root grant")
    s.set_defaults(f=cmd_mint)
    s = sub.add_parser("tree"); s.set_defaults(f=cmd_tree)
    s = sub.add_parser("requests"); s.set_defaults(f=cmd_requests)
    s = sub.add_parser("approve"); s.add_argument("request"); s.add_argument("--ttl", default="1h"); s.set_defaults(f=cmd_approve)
    s = sub.add_parser("deny"); s.add_argument("request"); s.set_defaults(f=cmd_deny)
    s = sub.add_parser("revoke"); s.add_argument("cap"); s.set_defaults(f=cmd_revoke)
    s = sub.add_parser("audit"); s.add_argument("--cap"); s.set_defaults(f=cmd_audit)
    a = p.parse_args()
    a.f(a)


if __name__ == "__main__":
    main()
