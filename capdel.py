#!/usr/bin/env python3
"""capdel — broker for dynamic capability delegation to agents. See SPEC.md."""
import argparse, base64, hashlib, hmac, json, os, re, secrets, socket, subprocess, sys, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HOME = Path(os.environ.get("CAPDEL_HOME", str(Path.home() / ".capdel")))
CAPS, REQS, AUDIT = HOME / "caps", HOME / "requests", HOME / "audit.jsonl"
FS_OPS = {"list", "read", "write", "stat"}
DEF_MAX_BYTES, DEF_TIMEOUT, DEF_MAX_OUTPUT = 1 << 20, 60, 1 << 18
OWNER_SECRET = os.environ.get("CAPDEL_OWNER_SECRET")  # gates read-only /_tree, /_audit
REQUEST_TTL = int(os.environ.get("CAPDEL_REQUEST_TTL", 3600))  # escalation requests expire after this

# --- Proof-of-possession (HMAC-PoP), issue #4 — see tasks/pop-design-hmac.md ------------------
# CAPDEL_POP=off (default: bearer-only, existing flows unchanged) | allow (per-request)
# | require (PoP mandatory). Per-cap `pop: true` (mint --pop) forces PoP even under allow.
POP_MODE = os.environ.get("CAPDEL_POP", "off")
SKEW = 300  # ±seconds a signed request's timestamp may drift
SCHEME = "capdel-hmac-sha256"
_nonces, _nlock = {}, threading.Lock()  # nonce -> expiry unix ts (in-memory replay store)


def _git_commit():
    try:
        return subprocess.check_output(["git", "rev-parse", "--short", "HEAD"],
                                       cwd=str(Path(__file__).resolve().parent),
                                       text=True, stderr=subprocess.DEVNULL).strip()
    except Exception:
        return "unknown"


COMMIT = _git_commit()

# The agent-side signer, served verbatim at GET /capdel-sign and inlined into a PoP cap's
# self-description, so an agent with only CAPDEL_URL + CAPDEL_TOKEN can bootstrap itself.
# Keep this byte-for-byte identical to the standalone ./capdel-sign file in the repo root.
SIGN_HELPER = '''#!/usr/bin/env python3
# capdel-sign — sign+send a capdel PoP request (HMAC-SHA256), or derive a child secret.
#   capdel-sign METHOD PATH [BODY]   sign and send via curl (BODY is JSON text, or empty)
#   capdel-sign derive <child-id>    derive a child cap's secret locally (attenuation mode b)
# Env: CAPDEL_URL (broker base, may include a relay /b/<id> prefix; the signed PATH never does),
#      CAPDEL_TOKEN (this cap's secret key — used to sign, NEVER sent on the wire).
import hashlib, hmac, os, secrets, subprocess, sys, time
SCHEME = "capdel-hmac-sha256"
tok = os.environ["CAPDEL_TOKEN"].encode()

def send(method, path, body):
    base = os.environ["CAPDEL_URL"].rstrip("/")
    bh = hashlib.sha256(body.encode()).hexdigest()
    nonce, ts = secrets.token_hex(16), str(int(time.time()))
    msg = "\\n".join([SCHEME, method.upper(), path, bh, nonce, ts]).encode()
    sig = hmac.new(tok, msg, hashlib.sha256).hexdigest()
    args = ["curl", "-s", "-X", method.upper(), base + path,
            "-H", "Capdel-Nonce: " + nonce, "-H", "Capdel-Timestamp: " + ts,
            "-H", "Capdel-Signature: " + sig]
    if body:
        args += ["-H", "Content-Type: application/json", "--data-binary", body]
    sys.exit(subprocess.call(args))

if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "derive":
        print("ct-" + hmac.new(tok, sys.argv[2].encode(), hashlib.sha256).hexdigest()[:32])
    else:
        send(sys.argv[1], sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else "")
'''


class Denied(Exception): pass


def ensure_home():
    for d in (CAPS, REQS):
        d.mkdir(parents=True, exist_ok=True)
    HOME.chmod(0o700)


def now(): return int(time.time())
def sha(t): return hashlib.sha256(t.encode()).hexdigest()
def req_status(req):  # a pending request past its TTL is effectively expired
    return "expired" if req["status"] == "pending" and now() > req.get("expires_at", 1 << 62) else req["status"]


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


def _nonce_seen(nonce, ts):
    """Record a nonce; return True if it was already seen (replay). A nonce is remembered
    for at most 2*SKEW, after which the timestamp check alone rejects any replay."""
    exp = max(now(), ts) + SKEW
    with _nlock:
        for stale in [n for n, e in _nonces.items() if e < now()]:  # lazy GC
            del _nonces[stale]
        if nonce in _nonces:
            return True
        _nonces[nonce] = exp
        return False


def verify_pop(cap, method, path, body_bytes, headers):
    """Holder-bound PoP: HMAC-SHA256 over (scheme, method, path, body-sha256, nonce,
    timestamp), keyed by the cap's stored secret. Raises Denied on any failure. The HMAC
    is verified BEFORE the nonce is consumed, so unsigned garbage cannot burn nonces.
    `path` is the broker-local request-target (what the broker sees, post relay-strip)."""
    if not cap.get("secret"):
        raise Denied("capability has no PoP secret — mint with --pop (or run under CAPDEL_POP=allow)")
    sig = headers.get("Capdel-Signature", "")
    nonce = headers.get("Capdel-Nonce", "")
    ts_s = headers.get("Capdel-Timestamp", "")
    if not (sig and nonce and ts_s):
        raise Denied("missing PoP headers (Capdel-Signature/Nonce/Timestamp)")
    try:
        ts = int(ts_s)
    except ValueError:
        raise Denied("bad Capdel-Timestamp")
    if abs(now() - ts) > SKEW:
        raise Denied(f"timestamp outside \u00b1{SKEW}s window")
    bh = hashlib.sha256(body_bytes).hexdigest()
    canonical = "\n".join([SCHEME, method, path, bh, nonce, ts_s])
    expect = hmac.new(cap["secret"].encode(), canonical.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expect, sig):
        raise Denied("bad signature")
    if _nonce_seen(nonce, ts):
        raise Denied("nonce replay")
    return True


def check_live(cap):
    c = cap
    while c:
        if c["revoked"]: raise Denied(f"capability {c['id']} is revoked")
        if now() > c["expires_at"]: raise Denied(f"capability {c['id']} is expired")
        c = load(CAPS, c["parent"]) if c["parent"] else None


def effective_closes_on(cap):
    """Union of closes_on along the ancestor chain — the events that would close this cap,
    whether declared on it or inherited (a parent closing revokes its whole subtree)."""
    evs, c = set(), cap
    while c:
        evs |= set(c.get("closes_on") or [])
        c = load(CAPS, c["parent"]) if c["parent"] else None
    return sorted(evs)


def fire_event(name):
    """Close (revoke) every non-revoked cap whose closes_on lists `name`. This is the trusted
    closure primitive (PORTICO): a cap's authority dies with the reason it was granted. Only the
    owner files events (CLI or owner-secret /_event) — a delegated holder must not be able to
    forge the 'tests passed' signal that justifies continued authority. Children whose closure
    comes only from an ancestor die via check_live's ancestor walk; marking the ancestor is enough."""
    if not re.fullmatch(r"[\w.:-]+", name or ""):
        raise Denied("event name must match [\\w.:-]+")
    closed = []
    for c in all_caps():
        if c.get("revoked"):
            continue
        if name in (c.get("closes_on") or []):
            c["revoked"] = True
            save(CAPS, c)
            closed.append(c["id"])
    audit(event="close_event", name=name, closed=closed)
    return closed


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
    elif type_ == "llm":
        if not c.get("models") or not all(isinstance(m, str) for m in c["models"]):
            raise Denied("llm 'models' must be a non-empty list of model-name strings")
        if "max_tokens" in c and not (isinstance(c["max_tokens"], int) and c["max_tokens"] > 0):
            raise Denied("llm 'max_tokens' must be a positive int")
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
    elif type_ == "net":
        for ch, cp in child["allow"]:
            if not any(ph == ch and (pp == 0 or pp == cp) for ph, pp in p["allow"]):
                raise Denied(f"destination [{ch}, {cp}] not covered by parent allow {p['allow']}")
        if child.get("max_bytes", DEF_MAX_BYTES) > p.get("max_bytes", DEF_MAX_BYTES):
            raise Denied("max_bytes exceeds parent's")
        if child.get("timeout_s", DEF_TIMEOUT) > p.get("timeout_s", DEF_TIMEOUT):
            raise Denied("timeout_s exceeds parent's")
    else:  # llm
        extra = set(child["models"]) - set(p["models"])
        if extra: raise Denied(f"models {sorted(extra)} exceed parent models {p['models']}")
        if child.get("max_tokens", 1 << 30) > p.get("max_tokens", 1 << 30):
            raise Denied("max_tokens exceeds parent's")
        if child.get("base_url", p.get("base_url")) != p.get("base_url"):
            raise Denied("base_url may not differ from parent's")


def validate_closes_on(events):
    """Closure predicate: trusted-event names that auto-revoke this cap when filed by the
    owner. Closure only NARROWS authority (ends a grant earlier), so a child may freely add
    events; a parent's closure still cascades to its subtree via check_live's ancestor walk."""
    if events is None:
        return []
    if not isinstance(events, list) or not all(isinstance(e, str) and re.fullmatch(r"[\w.:-]+", e) for e in events):
        raise Denied("closes_on must be a list of event-name strings (letters/digits/_/./:/-)")
    return sorted(set(events))


def mint(type_, constraints, name, ttl_s, parent=None, pop=False, closes_on=None):
    validate_constraints(type_, constraints)
    closes_on = validate_closes_on(closes_on)
    expires = now() + ttl_s
    if parent:
        check_live(parent)
        check_subset(type_, constraints, parent)
        expires = min(expires, parent["expires_at"])
    cid = "cap-" + secrets.token_hex(6)
    if pop:
        # PoP cap: the token IS an HMAC key that never crosses the wire again. A child's
        # key is DERIVED from the parent's secret (so attenuation over an untrusted relay
        # need never transmit the child secret — mode b in the design); a root's is random.
        if parent and parent.get("secret"):
            secret = "ct-" + hmac.new(parent["secret"].encode(), cid.encode(),
                                      hashlib.sha256).hexdigest()[:32]
        else:
            secret = "ct-" + secrets.token_hex(16)
        token, tok_sha = secret, sha(secret)
    else:
        token = "ct-" + secrets.token_hex(16)            # bearer (default): unchanged from v0
        tok_sha, secret = sha(token), None
    cap = {"id": cid, "parent": parent["id"] if parent else None,
           "name": name, "type": type_, "constraints": constraints, "expires_at": expires,
           "revoked": False, "token_sha256": tok_sha, "created": now(), "last_used": None,
           "pop": bool(pop), "closes_on": closes_on}
    if secret is not None:
        cap["secret"] = secret                            # bearer caps store only the hash
    save(CAPS, cap)
    audit(event="mint", cap=cap["id"], parent=cap["parent"], name=name, constraints=constraints,
          pop=bool(pop), closes_on=closes_on)
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
        off, length = int(body.get("offset", 0)), body.get("length")
        with open(rp, "rb") as f:
            f.seek(off)
            data = f.read(max_bytes + 1 if length is None else min(int(length), max_bytes + 1))
        if len(data) > max_bytes:
            raise Denied(f"read of {len(data)}B over max_bytes {max_bytes}; pass a smaller length or read in offset windows")
        return {"content": data.decode("utf-8", "replace"), "offset": off, "bytes": len(data)}
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


def llm_invoke(cap, body):
    # Wrap a shared LLM key: the broker holds it (env CAPDEL_LLM_KEY) and INJECTS it into the
    # outbound request. The holder sends only {op:"chat", model, messages} and never sees the key.
    import urllib.request, urllib.error
    c = cap["constraints"]
    if body.get("op") != "chat":
        raise Denied(f"op {body.get('op')!r} not supported; llm op is 'chat'")
    key = os.environ.get("CAPDEL_LLM_KEY")
    if not key:
        raise Denied("broker has no CAPDEL_LLM_KEY configured — cannot exercise an llm cap")
    model = body.get("model") or c["models"][0]
    if model not in c["models"]:
        raise Denied(f"model {model!r} not in allowed models {c['models']}")
    if not isinstance(body.get("messages"), list) or not body["messages"]:
        raise Denied("'messages' must be a non-empty list")
    base = c.get("base_url") or os.environ.get("CAPDEL_LLM_BASE_URL") or "https://api.z.ai/api/coding/paas/v4"
    payload = {"model": model, "messages": body["messages"], "temperature": body.get("temperature", 0)}
    cap_max, req_max = c.get("max_tokens"), body.get("max_tokens")
    if cap_max or req_max:
        payload["max_tokens"] = min(req_max or cap_max, cap_max or req_max)
    req = urllib.request.Request(base.rstrip("/") + "/chat/completions",
                                 data=json.dumps(payload).encode(),
                                 headers={"content-type": "application/json", "authorization": f"Bearer {key}"},
                                 method="POST")
    try:
        with urllib.request.urlopen(req, timeout=c.get("timeout_s", 60)) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        raise Denied(f"llm upstream {e.code}: {e.read()[:200].decode(errors='replace')}")


def describe(cap, base):
    c, cpath = cap["constraints"], f"/caps/{cap['id']}"
    if cap.get("pop"):  # PoP cap: `how` bootstraps the capdel-sign helper (no Bearer on the wire)
        root = c.get("root", "")
        if cap["type"] == "fs":
            ex = [f"./capdel-sign POST {cpath}/invoke '{{\"op\":\"list\",\"path\":\"{root}\"}}'",
                  "shapes: {\"op\":\"list|stat\",\"path\":…} {\"op\":\"read\",\"path\":…,\"offset\"?:…,\"length\"?:…} {\"op\":\"write\",\"path\":…,\"content\":…}"]
        elif cap["type"] == "exec":
            ex = [f"./capdel-sign POST {cpath}/invoke '{{\"op\":\"run\",\"argv\":[\"ls\"]}}'",
                  'op: {"op":"run","argv":[…],"cwd"?:…,"stdin"?:…}']
        elif cap["type"] == "llm":
            ex = [f"./capdel-sign POST {cpath}/invoke '{{\"op\":\"chat\",\"model\":\"{(c.get('models') or ['MODEL'])[0]}\",\"messages\":[{{\"role\":\"user\",\"content\":\"hi\"}}]}}'",
                  'op: {"op":"chat","model":…,"messages":[…],"max_tokens"?:…} (broker injects the shared key)']
        else:
            dest = c["allow"][0] if c.get("allow") else ["HOST", 0]
            ex = [f"./capdel-sign POST {cpath}/invoke '{{\"op\":\"connect\",\"host\":\"{dest[0]}\",\"port\":{dest[1]}}}'",
                  'op: {"op":"connect","host":…,"port":…,"send"?:<base64>}']
        how = ["# 1) save the signer once (stdlib python, no deps):",
               f"curl -s {base}/capdel-sign > capdel-sign && chmod +x capdel-sign",
               "# 2) set broker + key (CAPDEL_URL may include a relay /b/<id> prefix):",
               "export CAPDEL_URL=… CAPDEL_TOKEN=ct-…",
               "# 3) invoke — same shape as before, minus the Bearer header:"]
        how += ex + [f"./capdel-sign GET {cpath} ''   # re-read this description",
                     f"./capdel-sign POST {cpath}/escalate '{{\"want\":…,\"reason\":…}}'  (same as Bearer, just signed)"]
        out = {"id": cap["id"], "name": cap["name"], "type": cap["type"],
               "constraints": cap["constraints"], "expires_at": cap["expires_at"],
               "auth": "pop-hmac-sha256", "how": how, "sign_helper": SIGN_HELPER}
    else:  # bearer cap: the original curl one-liner
        dest = c["allow"][0] if (cap["type"] == "net" and c.get("allow")) else ["HOST", 0]
        how = {
            "fs": [f"curl -s -H 'Authorization: Bearer $CAPDEL_TOKEN' -d '{{\"op\":\"list\",\"path\":\"{c.get('root','')}\"}}' {base}/caps/{cap['id']}/invoke",
                   f"you may: {', '.join(c.get('ops', []))}. shapes: "
                   '{"op":"list|stat","path":…} {"op":"read","path":…,"offset"?:…,"length"?:…} {"op":"write","path":…,"content":…}'],
            "exec": [f"curl -s -H 'Authorization: Bearer $CAPDEL_TOKEN' -d '{{\"op\":\"run\",\"argv\":[\"ls\"]}}' {base}/caps/{cap['id']}/invoke",
                     'op: {"op":"run","argv":[…],"cwd"?:…,"stdin"?:…}'],
            "net": [f"curl -s -H 'Authorization: Bearer $CAPDEL_TOKEN' -d '{{\"op\":\"connect\",\"host\":\"{dest[0]}\",\"port\":{dest[1]}}}' {base}/caps/{cap['id']}/invoke",
                    'op: {"op":"connect","host":…,"port":…,"send"?:<base64>} → {recv:<base64>,bytes,truncated}; send a request with Connection: close so the peer closes'],
            "llm": [f"curl -s -H 'Authorization: Bearer $CAPDEL_TOKEN' -d '{{\"op\":\"chat\",\"model\":\"{(c.get('models') or ['MODEL'])[0]}\",\"messages\":[{{\"role\":\"user\",\"content\":\"hi\"}}]}}' {base}/caps/{cap['id']}/invoke",
                    f"you may call models {c.get('models', [])} (the broker injects the shared key; you never see it). op: {{\"op\":\"chat\",\"model\":…,\"messages\":[…],\"max_tokens\"?:…}} → OpenAI-shaped completion"],
        }[cap["type"]]
        out = {"id": cap["id"], "name": cap["name"], "type": cap["type"],
               "constraints": cap["constraints"], "expires_at": cap["expires_at"],
               "auth": "bearer", "how": how}
    # Effective closure = this cap's events ∪ ancestors' (a parent closing kills the subtree).
    out["closes_on"] = effective_closes_on(cap)
    out["escalate"] = f'POST {base}/caps/{cap["id"]}/escalate {{"want":{{just the fields to change, e.g. add an op}},"reason":…}} → poll GET {base}/requests/<request_id>; on approval the poll returns a NEW token+cap to switch to'
    return out


class Handler(BaseHTTPRequestHandler):
    server_version = "capdel/0.1"

    def _json(self, code, obj):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _text(self, s, code=200):
        data = s.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n)) if n else {}

    def _token(self):
        return (self.headers.get("Authorization") or "").removeprefix("Bearer ").strip()

    def _authn(self, cid, method, body_bytes):
        """Resolve the cap at `cid` and authenticate by PoP mode + per-cap `pop` flag.
        Returns the cap on success, None for an unknown cap or a wrong bearer token, and
        raises Denied when PoP is required and the signature/replay/timestamp check fails."""
        cap = load(CAPS, cid)
        if not cap:
            return None
        per_cap = cap.get("pop")
        has_sig = "Capdel-Signature" in self.headers
        want_pop = (POP_MODE == "require") or per_cap is True or (POP_MODE == "allow" and has_sig)
        if want_pop:
            verify_pop(cap, method, self.path, body_bytes, self.headers)  # raises Denied
            return cap
        if POP_MODE != "require" and cap.get("token_sha256") \
                and hmac.compare_digest(sha(self._token()), cap["token_sha256"]):
            return cap
        return None

    def _base(self):
        # When a request arrives through the pod relay, the tunnel injects the public
        # URL so self-description hints point somewhere a remote agent can actually reach.
        fwd = self.headers.get("X-Capdel-Public-Base")
        return fwd if fwd else f"http://{self.headers.get('Host', self.server.server_address[0])}"

    def _owner_ok(self):
        return bool(OWNER_SECRET) and self._token() == OWNER_SECRET

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/capdel-sign":
            return self._text(SIGN_HELPER)                 # public: the agent-side signer source
        if path == "/_api/version":
            return self._json(200, {"server": self.server_version, "commit": COMMIT,
                                    "pop_mode": POP_MODE, "schemes": ["bearer", SCHEME]})
        if path in ("/_tree", "/_audit"):
            if not self._owner_ok(): return self._json(401, {"error": "owner secret required"})
            return self._json(200, {"tree": tree_data()} if path == "/_tree" else {"audit": audit_tail()})
        m = re.fullmatch(r"/caps/([\w-]+)", self.path)
        if m:
            try:
                cap = self._authn(m.group(1), "GET", b"")
            except Denied as e:
                audit(event="authn", cap=m.group(1), op=self.path, decision="deny", violated=str(e))
                return self._json(403, {"error": "denied", "violated": str(e)})
            if not cap: return self._json(401, {"error": "unknown capability or bad token"})
            return self._json(200, describe(cap, self._base()))
        m = re.fullmatch(r"/requests/([\w-]+)", self.path)
        if m:
            req = load(REQS, m.group(1))
            if not req: return self._json(404, {"error": "unknown request"})
            try:
                cap = self._authn(req["cap"], "GET", b"")
            except Denied as e:
                audit(event="authn", cap=req["cap"], op=self.path, decision="deny", violated=str(e))
                return self._json(403, {"error": "denied", "violated": str(e)})
            if not cap:
                return self._json(401, {"error": "polling a request needs the SAME token you escalated with (Bearer, or its PoP signature)"})
            st = req_status(req)
            out = {"request_id": req["id"], "status": st}
            if st == "approved":
                out.update(token=req["token"], cap=req["minted_cap"])
            return self._json(200, out)
        self._json(404, {"error": "no such route"})

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        if path == "/_event":
            # Trusted closure (§3.6): owner-filed only. A delegated holder must not be able to
            # forge the event that ends its own authority (or DoS a peer's), so this needs the
            # owner secret just like /_tree and /_audit.
            if not self._owner_ok():
                return self._json(401, {"error": "owner secret required (closure events are owner-filed — a delegated holder cannot forge them)"})
            name = self._body().get("name")
            try:
                closed = fire_event(name)
            except Denied as e:
                return self._json(400, {"error": "denied", "violated": str(e)})
            except (ValueError, TypeError) as e:
                return self._json(400, {"error": f"bad request: {e!r}"})
            return self._json(200, {"event": name, "closed": closed, "count": len(closed)})
        if path == "/_gc":
            if not self._owner_ok(): return self._json(401, {"error": "owner secret required"})
            removed = gc_expired()
            return self._json(200, {"cleared": len(removed), "ids": removed})
        if path == "/_mint":
            # owner-gated HTTP mint (symmetric with the CLI; lets the whole protocol be
            # driven over HTTP, e.g. from a pod where there is no shell to run `capdel mint`).
            if not self._owner_ok(): return self._json(401, {"error": "owner secret required"})
            b = self._body()
            try:
                cap, token = mint(b["type"], b["constraints"], b.get("name", "root grant"),
                                  int(b.get("ttl_s", 14400)), pop=bool(b.get("pop")), closes_on=b.get("closes_on"))
                return self._json(200, {"id": cap["id"], "token": token, "expires_at": cap["expires_at"], "pop": cap["pop"]})
            except Denied as e:
                return self._json(403, {"error": "denied", "violated": str(e)})
            except (KeyError, ValueError, TypeError) as e:
                return self._json(400, {"error": f"bad request: {e!r}"})
        m = re.fullmatch(r"/caps/([\w-]+)/(invoke|attenuate|escalate)", self.path)
        if not m:
            return self._json(404, {"error": "no such route"})
        cid, action = m.group(1), m.group(2)
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b""           # read once: used for both auth + JSON
        try:
            cap = self._authn(cid, "POST", raw)
        except Denied as e:
            audit(event="authn", cap=cid, op=self.path, decision="deny", violated=str(e))
            return self._json(403, {"error": "denied", "violated": str(e)})
        if not cap:
            return self._json(401, {"error": "unknown capability or failed PoP/bearer auth"})
        try:
            body = json.loads(raw) if raw else {}
            check_live(cap)
            if action == "invoke":
                result = {"fs": fs_invoke, "exec": exec_invoke, "net": net_invoke, "llm": llm_invoke}[cap["type"]](cap, body)
                cap["last_used"] = now()
                save(CAPS, cap)
                audit(event="invoke", cap=cap["id"], op=body.get("op"),
                      arg=body.get("path") or body.get("argv") or body.get("host"), decision="allow")
                return self._json(200, result)
            if action == "attenuate":
                child_pop = bool(cap.get("pop")) or ("secret" in cap)   # a PoP parent begets PoP children
                child, token = mint(cap["type"], body["constraints"], body.get("name", f"child of {cap['id']}"),
                                    int(body.get("ttl_s", 3600)), parent=cap, pop=child_pop, closes_on=body.get("closes_on"))
                return self._json(200, {"id": child["id"], "token": token, "expires_at": child["expires_at"],
                                        "pop": child.get("pop", False), "closes_on": child.get("closes_on", [])})
            # `want` may be a delta — merge it onto the cap's current constraints so a
            # holder can ask for just the extra op/host without restating root/cwd_root.
            want = {**cap["constraints"], **(body.get("want") or {})}
            validate_constraints(cap["type"], want)
            req = {"id": "req-" + secrets.token_hex(6), "cap": cap["id"], "type": cap["type"],
                   "want": want, "reason": body.get("reason", ""), "status": "pending",
                   "created": now(), "expires_at": now() + REQUEST_TTL}
            save(REQS, req)
            audit(event="escalate", cap=cap["id"], request=req["id"], want=want, reason=req["reason"])
            return self._json(200, {"request_id": req["id"], "status": "pending",
                                    "granted_if_approved": want,
                                    "note": "if approved, poll returns a NEW token + cap id — switch to them; your current token is unchanged",
                                    "poll": f"GET {self._base()}/requests/{req['id']} — authenticate as THIS cap (Bearer, or PoP-sign if it is a --pop cap)"})
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
    if cap["type"] == "llm":
        mt = f" ≤{c['max_tokens']}tok" if c.get("max_tokens") else ""
        return f"llm [{','.join(c['models'])}]{mt}"
    dests = ', '.join(f"{h}:{p if p else '*'}" for h, p in c["allow"])
    return f"net [{dests}]"


def tree_data():
    kids = {}
    for c in all_caps():
        kids.setdefault(c["parent"], []).append(c)
    def node(c):
        return {"id": c["id"], "name": c["name"], "type": c["type"], "summary": fmt_constraints(c),
                "constraints": c["constraints"], "expires_at": c["expires_at"],
                "revoked": c["revoked"], "last_used": c["last_used"], "closes_on": c.get("closes_on") or [],
                "created": c.get("created"), "escalation": c.get("escalation"),
                "children": [node(k) for k in kids.get(c["id"], [])]}
    return [node(c) for c in kids.get(None, [])]


def audit_tail(n=200):
    if not AUDIT.exists(): return []
    return [json.loads(l) for l in AUDIT.read_text().splitlines()[-n:]]


def gc_expired():
    """Delete cap files whose TTL has passed (the "clear expired" sweep, issue #7:
    approved escalations are minted as fresh owner roots that otherwise pile up until
    TTL and then linger as dead files). Safe because mint() clamps a child's expires_at
    to <= its parent's, so every cap under an expired root is itself expired — nothing
    live can lose an ancestor. Revoked-but-unexpired caps are kept (revocation is an
    audit state; check_live already refuses them at invoke time)."""
    removed = []
    for c in all_caps():
        if now() > c["expires_at"]:
            (CAPS / f"{c['id']}.json").unlink(missing_ok=True)
            removed.append(c["id"])
    if removed:
        audit(event="gc", removed=removed)
    return removed


def cmd_tree(_):
    def walk(n, depth, inherited):
        state = "REVOKED" if n["revoked"] else ("expired" if now() > n["expires_at"] else
                f"expires in {(n['expires_at'] - now()) // 60}m")
        used = f", last used {(now() - n['last_used']) // 60}m ago" if n["last_used"] else ""
        eff = sorted(set(inherited) | set(n.get("closes_on") or []))   # effective closure incl. ancestors
        closes = f", closes-on:{','.join(eff)}" if eff else ""
        print(f"{'  ' * depth}{n['id']}  {n['name']!r}  {n['summary']}  [{state}{used}{closes}]")
        for k in n["children"]:
            walk(k, depth + 1, eff)
    for n in tree_data():
        walk(n, 0, set())


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
    elif a.type == "net":
        constraints = {"allow": [parse_dest(al) for al in a.allow]}
        if a.max_bytes: constraints["max_bytes"] = a.max_bytes
        if a.timeout: constraints["timeout_s"] = a.timeout
    else:  # llm
        constraints = {"models": [m for al in a.models for m in al.split(",")]}
        if a.base_url: constraints["base_url"] = a.base_url
        if a.max_tokens: constraints["max_tokens"] = a.max_tokens
        if a.timeout: constraints["timeout_s"] = a.timeout
    cap, token = mint(a.type, constraints, a.name, parse_ttl(a.ttl), pop=a.pop, closes_on=a.closes_on)
    print(f"id={cap['id']}\ntoken={token}\nexpires_at={cap['expires_at']}")


def cmd_requests(_):
    for p in sorted(REQS.glob("*.json")):
        r = json.loads(p.read_text())
        if req_status(r) != "pending": continue   # skip decided AND expired
        cap = load(CAPS, r["cap"])
        mins = (r.get("expires_at", now()) - now()) // 60
        print(f"{r['id']}  from {r['cap']} ({cap['name']!r})  reason: {r['reason']}  [expires in {mins}m]\n"
              f"  wants: {json.dumps(r['want'])}")


def cmd_approve(a):
    req = load(REQS, a.request)
    if not req: raise SystemExit(f"no such request {a.request}")
    if req_status(req) != "pending": raise SystemExit(f"request {a.request} is {req_status(req)}, not pending")
    # The owner is the root of authority. An escalation exists because the needed grant
    # was NOT in the requester's chain, so approving mints it as a fresh owner capability
    # (same power as `capdel mint`) — not a sibling clamped to the requester's ancestor.
    cap, token = mint(req["type"], req["want"], f"escalation {req['id']} for {req['cap']}", parse_ttl(a.ttl), pop=a.pop, closes_on=a.closes_on)
    # Record provenance on the minted cap so the dashboard can render the grant's
    # lineage (which request, from which cap, why) as data instead of parsing the name.
    cap["escalation"] = {"request": req["id"], "source_cap": req["cap"], "reason": req["reason"]}
    save(CAPS, cap)
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


def cmd_event(a):
    # Owner-filed trusted closure (§3.6): every cap whose closes_on lists this event auto-revokes.
    try:
        closed = fire_event(a.name)
    except Denied as e:
        raise SystemExit(str(e))
    if closed:
        print(f"event {a.name!r}: closed {len(closed)} cap(s): {', '.join(closed)}")
    else:
        print(f"event {a.name!r}: no capabilities close on it (0 closed)")


def cmd_gc(_):
    removed = gc_expired()
    word = "capability" if len(removed) == 1 else "capabilities"
    ids = f": {', '.join(removed)}" if removed else ""
    print(f"cleared {len(removed)} expired {word}{ids}")


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
    s.add_argument("type", choices=["fs", "exec", "net", "llm"])
    s.add_argument("--root"); s.add_argument("--ops", default="list,read"); s.add_argument("--max-bytes", type=int, dest="max_bytes")
    s.add_argument("--allow", action="append", default=[]); s.add_argument("--cwd-root", dest="cwd_root"); s.add_argument("--timeout", type=int)
    s.add_argument("--models", action="append", default=[], help="llm: allowed model name(s), repeatable or comma-sep")
    s.add_argument("--base-url", dest="base_url", help="llm: OpenAI-compatible base (default z.ai coding paas)")
    s.add_argument("--max-tokens", type=int, dest="max_tokens", help="llm: cap max_tokens per call")
    s.add_argument("--ttl", default="4h"); s.add_argument("--name", default="root grant")
    s.add_argument("--pop", action="store_true", help="mint a PoP cap: token is an HMAC key that never re-crosses the wire")
    s.add_argument("--closes-on", dest="closes_on", action="append", default=[],
                   help="trusted event name that auto-revokes this cap when the owner fires `capdel event NAME` (repeatable)")
    s.set_defaults(f=cmd_mint)
    s = sub.add_parser("tree"); s.set_defaults(f=cmd_tree)
    s = sub.add_parser("requests"); s.set_defaults(f=cmd_requests)
    s = sub.add_parser("approve"); s.add_argument("request"); s.add_argument("--ttl", default="1h")
    s.add_argument("--pop", action="store_true", help="mint the approved cap as PoP")
    s.add_argument("--closes-on", dest="closes_on", action="append", default=[],
                   help="trusted event name that auto-revokes the approved cap when fired (repeatable)")
    s.set_defaults(f=cmd_approve)
    s = sub.add_parser("deny"); s.add_argument("request"); s.set_defaults(f=cmd_deny)
    s = sub.add_parser("revoke"); s.add_argument("cap"); s.set_defaults(f=cmd_revoke)
    s = sub.add_parser("event"); s.add_argument("name", help="fire a trusted event; closes every cap whose --closes-on lists it")
    s.set_defaults(f=cmd_event)
    s = sub.add_parser("gc"); s.set_defaults(f=cmd_gc)
    s = sub.add_parser("audit"); s.add_argument("--cap"); s.set_defaults(f=cmd_audit)
    a = p.parse_args()
    a.f(a)


if __name__ == "__main__":
    main()
