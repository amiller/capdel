#!/usr/bin/env python3
"""Issue #19 — `secret` capability type: paste-vault a credential, use it broker-side,
audit every use. Black-box scenario in the style of test/swarm.py: it starts a throwaway
broker on 127.0.0.1, vaults a credential via `capdel vault`, and drives the HTTP API the way
a holder would. Asserts the three acceptance bullets verifiable without a live third-party key:

  #1  `printf 'sk-...' | capdel vault` prints a cap id; `tree` shows a `secret` node with NO
      value; the value never appears in --audit, GET /caps/<id>, describe, or owner _tree/_audit.
  #2  A narrowed secret cap makes ONE brokered connect to an allowed host:port; the broker
      INJECTS the key into the bytes the server receives; describe never reveals the key;
      widening the host is DENIED; any op other than connect is DENIED. (TLS path proven
      against a self-signed local server.) The "real 200 from api.openai.com" sub-step needs a
      live key and is operator-run.
  #3  `capdel audit` shows each use: cap, timestamp, destination, byte count — and NOT the value.

Hermetic: a tempdir only, never ~/.capdel. Exits non-zero on any failed assertion.
"""
import base64, json, os, socket, ssl, subprocess, sys, tempfile, threading, time, urllib.request, urllib.error
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CAPDEL = str(ROOT / "capdel.py")
OWNER = "secret-test-owner-secret"
SECRET_VALUE = "sk-MARKER-7c9f3a1e-never-a-real-key"   # a recognisable needle; must NOT leak

BASE = None


def http(method, path, token=None, body=None, base=None):
    req = urllib.request.Request((base or BASE) + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    if body is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, {"_raw": raw.decode(errors="replace")}


def cli(*args, stdin=None):
    env = {**os.environ, "CAPDEL_HOME": os.environ["CAPDEL_HOME"], "CAPDEL_OWNER_SECRET": OWNER}
    r = subprocess.run([sys.executable, CAPDEL, *args], input=stdin, capture_output=True,
                       text=True, env=env, timeout=20)
    return r.stdout, r.stderr, r.returncode


def parse_kv(out):
    d = {}
    for line in out.splitlines():
        for tok in line.split():
            if "=" in tok:
                k, _, v = tok.partition("=")
                d[k.strip()] = v.strip()
    return d


def check(cond, msg):
    if not cond:
        print(f"FAIL: {msg}", file=sys.stderr)
        raise SystemExit(1)


def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


class AssertServer:
    """Records the first chunk of bytes it receives, replies with a canned HTTP response, closes.
    Proves the broker INJECTED the key into the outbound bytes (the holder's request had none)."""

    def __init__(self, tls=False, certfile=None, keyfile=None):
        self.got = b""
        self.tls, self.certfile, self.keyfile = tls, certfile, keyfile
        self.port = free_port()
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", self.port)); self._srv.listen(8)
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        try:
            conn, _ = self._srv.accept()
        except OSError:
            return
        sock = conn
        if self.tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(self.certfile, self.keyfile)
            sock = ctx.wrap_socket(conn, server_side=True)
        try:
            sock.settimeout(5)
            while b"\r\n\r\n" not in self.got:
                b = sock.recv(4096)
                if not b:
                    break
                self.got += b
                if len(self.got) > 65536:
                    break
            sock.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
        except Exception:
            pass
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def received(self):
        return self.got


def sign_pop(token, method, path, body_bytes):
    import hashlib, hmac, secrets as _s, time as _t
    bh = hashlib.sha256(body_bytes).hexdigest()
    nonce, ts = _s.token_hex(16), str(int(_t.time()))
    canonical = "\n".join(["capdel-hmac-sha256", method.upper(), path, bh, nonce, ts])
    sig = hmac.new(token.encode(), canonical.encode(), hashlib.sha256).hexdigest()
    return {"Capdel-Nonce": nonce, "Capdel-Timestamp": ts, "Capdel-Signature": sig}


def signed_http(method, path, token, body=None, base=None):
    body_bytes = json.dumps(body).encode() if body is not None else b""
    req = urllib.request.Request((base or BASE) + path, method=method,
                                 data=body_bytes if body is not None else None)
    for k, v in sign_pop(token, method, path, body_bytes).items():
        req.add_header(k, v)
    if body is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, {"_raw": raw.decode(errors="replace")}


def start_broker(port, extra_env=None):
    env = {**os.environ, "CAPDEL_HOME": os.environ["CAPDEL_HOME"], "CAPDEL_OWNER_SECRET": OWNER,
           "CAPDEL_POP": "allow", **(extra_env or {})}
    srv = subprocess.Popen([sys.executable, CAPDEL, "serve", "--bind", f"127.0.0.1:{port}"],
                           stderr=subprocess.PIPE, env=env)
    for _ in range(100):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/_api/version", timeout=1).read()
            return srv
        except Exception:
            time.sleep(0.1)
    err = srv.stderr.read().decode()[-800:]
    raise SystemExit(f"broker did not become ready\n{err}")


def self_signed():
    d = tempfile.mkdtemp(prefix="capdel-tls-")
    cert, key = f"{d}/cert.pem", f"{d}/key.pem"
    r = subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", key,
                        "-out", cert, "-days", "1", "-nodes", "-subj", "/CN=localhost",
                        "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
                       capture_output=True, text=True)
    return (cert, key) if r.returncode == 0 else (None, None)


# inject template shared by the plain-TCP scenarios (real CRLF, literal {{secret}} placeholder)
INJECT = ("GET /v1/models HTTP/1.1\r\nHost: localhost\r\n"
          "Authorization: Bearer {{secret}}\r\nConnection: close\r\n\r\n")


def main():
    global BASE
    home = tempfile.mkdtemp(prefix="capdel-secret-")
    os.environ["CAPDEL_HOME"] = home
    port = free_port()
    BASE = f"http://127.0.0.1:{port}"
    srv = start_broker(port)
    try:
        # ---- #1: vault ingest + value-never-revealed ------------------------------------
        out, err, rc = cli("vault", "--name", "openai", "--allow", "127.0.0.1:*", "--no-tls",
                           "--no-pop", "--ttl", "1h", "--inject", INJECT, stdin=SECRET_VALUE)
        check(rc == 0, f"vault exited {rc}: {err!r}")
        d = parse_kv(out)
        check(d.get("id", "").startswith("cap-"), f"vault did not print a cap id: {out!r}")
        cap_id, token = d["id"], d["token"]
        print(f"[1] vaulted secret as {cap_id}")

        tree_out, _, _ = cli("tree")
        check("secret" in tree_out and "openai" in tree_out, f"tree missing secret/openai:\n{tree_out}")
        check(SECRET_VALUE not in tree_out, "LEAK: secret value in `capdel tree`")

        st, desc = http("GET", f"/caps/{cap_id}", token=token)
        check(st == 200, f"describe status {st}: {desc}")
        check("{{secret}}" in json.dumps(desc), "describe should carry the {{secret}} placeholder")
        check(SECRET_VALUE not in json.dumps(desc), "LEAK: secret value in GET /caps/<id>")

        st, tr = http("GET", "/_tree", token=OWNER)
        check(SECRET_VALUE not in json.dumps(tr), "LEAK: secret value in owner /_tree")
        st, au = http("GET", "/_audit", token=OWNER)
        check(SECRET_VALUE not in json.dumps(au), "LEAK: secret value in owner /_audit")

        cap_json = Path(home) / "caps" / f"{cap_id}.json"
        check(SECRET_VALUE not in cap_json.read_text(), "LEAK: secret value in caps/<id>.json")
        vault_file = Path(home) / "secrets" / f"{cap_id}.bin"
        check(vault_file.exists(), "no vaulted secret file was written")
        check(SECRET_VALUE not in vault_file.read_bytes().decode("latin-1"),
              "LEAK: vault file stores the value as plaintext (at-rest encryption broken)")
        print("[1] tree/describe/audit/_tree/_audit/cap-json/vault-file all clean of the value")

        # ---- #2: broker injects the key; narrow ok; widen + non-connect denied -----------
        srv_tcp = AssertServer(tls=False)
        st, at = http("POST", f"/caps/{cap_id}/attenuate", token=token,
                      body={"constraints": {"destinations": [["127.0.0.1", srv_tcp.port]],
                                            "inject": INJECT, "tls": False},
                            "name": "narrowed", "ttl_s": 3600})
        check(st == 200, f"attenuate (narrow) failed {st}: {at}")
        child_id, child_tok = at["id"], at["token"]
        print(f"[2] narrowed -> {child_id} (destinations=[127.0.0.1:{srv_tcp.port}])")

        st, cdesc = http("GET", f"/caps/{child_id}", token=child_tok)
        check(SECRET_VALUE not in json.dumps(cdesc), "LEAK: secret value in narrowed cap describe")

        st, res = http("POST", f"/caps/{child_id}/invoke", token=child_tok,
                       body={"op": "connect", "host": "127.0.0.1", "port": srv_tcp.port})
        check(st == 200, f"connect invoke failed {st}: {res}")
        time.sleep(0.3)
        seen = srv_tcp.received().decode("latin-1")
        check(f"Authorization: Bearer {SECRET_VALUE}" in seen,
              f"server did NOT receive the injected credential; got:\n{seen!r}")
        print(f"[2] server received the injected header ({len(seen)} bytes); holder never saw the key")

        # widening destination DENIED (parent covers only 127.0.0.1:*)
        st, wide = http("POST", f"/caps/{cap_id}/attenuate", token=token,
                        body={"constraints": {"destinations": [["8.8.8.8", 443]],
                                              "inject": INJECT, "tls": False}, "name": "x", "ttl_s": 60})
        check(st == 403, f"widening destination should be DENIED, got {st}: {wide}")
        print(f"[2] widen destination -> 403 ({wide.get('violated','')[:60]})")

        # differing inject DENIED (narrow WHERE, not HOW the key is used)
        st, dj = http("POST", f"/caps/{cap_id}/attenuate", token=token,
                      body={"constraints": {"destinations": [["127.0.0.1", 0]],
                                            "inject": INJECT + "X-Extra: yes\r\n", "tls": False},
                            "name": "x", "ttl_s": 60})
        check(st == 403, f"differing inject should be DENIED, got {st}: {dj}")
        print(f"[2] differing inject -> 403 ({dj.get('violated','')[:60]})")

        # the only op is connect; no op returns the raw secret
        st, bad = http("POST", f"/caps/{child_id}/invoke", token=child_tok,
                       body={"op": "read", "path": "whatever"})
        check(st == 403, f"non-connect op should be DENIED, got {st}: {bad}")
        check(SECRET_VALUE not in json.dumps(bad), "LEAK: denied-op response mentions the value")
        print("[2] op != connect -> 403 (there is no op that returns the raw secret)")

        # ---- #2/TLS: real TLS handshake + injection vs a self-signed local server ---------
        cert, key = self_signed()
        if cert:
            srv_tls = AssertServer(tls=True, certfile=cert, keyfile=key)
            out, err, rc = cli("vault", "--name", "tlssvc", "--allow", f"127.0.0.1:{srv_tls.port}",
                               "--ttl", "1h", "--no-pop", "--inject", INJECT, stdin=SECRET_VALUE + "-tls")
            check(rc == 0, f"tls vault failed {rc}: {err!r}")
            td = parse_kv(out)
            # second broker whose env trusts the self-signed cert via SSL_CERT_FILE
            tport = free_port()
            saved_base = BASE
            tls_srv = start_broker(tport, extra_env={"SSL_CERT_FILE": cert})
            try:
                BASE = f"http://127.0.0.1:{tport}"
                st, res = http("POST", f"/caps/{td['id']}/invoke", token=td["token"],
                               body={"op": "connect", "host": "127.0.0.1", "port": srv_tls.port})
                check(st == 200, f"TLS connect failed {st}: {res}")
                time.sleep(0.3)
                tls_seen = srv_tls.received().decode("latin-1")
                check(f"Authorization: Bearer {SECRET_VALUE}-tls" in tls_seen,
                      f"TLS server did not receive injected credential; got:\n{tls_seen!r}")
                print("[2/TLS] real TLS handshake + broker injection verified (self-signed local server)")
            finally:
                BASE = saved_base
                tls_srv.terminate()
        else:
            print("[2/TLS] skipped (openssl unavailable)")

        # ---- #2/PoP: default-vaulted cap is holder-bound (bearer denied, signed accepted) -
        out, err, rc = cli("vault", "--name", "poppy", "--allow", "127.0.0.1:*", "--no-tls",
                           "--ttl", "1h", "--inject", INJECT, stdin=SECRET_VALUE + "-pop")
        pd = parse_kv(out)
        check(pd.get("pop") == "True", f"vault should default to pop, got {pd}")
        pop_id, pop_tok = pd["id"], pd["token"]
        st, _b = http("POST", f"/caps/{pop_id}/invoke", token=pop_tok,   # bearer -> denied
                      body={"op": "connect", "host": "127.0.0.1", "port": 9})
        check(st == 403, f"PoP cap should reject bearer, got {st}")
        # a signed connect to a closed port fails at the NETWORK layer, proving auth passed
        st, _s = signed_http("POST", f"/caps/{pop_id}/invoke", pop_tok,
                             {"op": "connect", "host": "127.0.0.1", "port": 9})
        check(st in (502, 408), f"signed PoP request should pass auth and fail downstream, got {st}: {_s}")
        print(f"[2/PoP] default-vault is PoP: bearer->403, signed->auth-ok (downstream {st})")

        # ---- #3: audit shows cap/ts/dest/bytes per use, never the value ------------------
        au_out, _, _ = cli("audit", "--cap", child_id)
        check("connect" in au_out and "dest" in au_out and "bytes" in au_out,
              f"audit missing connect/dest/bytes:\n{au_out}")
        check(SECRET_VALUE not in au_out, "LEAK: secret value in `capdel audit`")
        rows = [json.loads(l) for l in au_out.splitlines() if l.strip()]
        connects = [r for r in rows if r.get("op") == "connect"]
        check(connects and all("dest" in r and "bytes" in r and "ts" in r for r in connects),
              f"connect audit rows lack ts/dest/bytes: {connects}")
        print(f"[3] audit shows {len(connects)} connect(s) with ts+dest+bytes, no value")

        print("\nALL ASSERTIONS PASSED")
    finally:
        try:
            srv.terminate(); srv.wait(timeout=5)
        except Exception:
            pass


if __name__ == "__main__":
    main()
