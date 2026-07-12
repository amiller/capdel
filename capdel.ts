#!/usr/bin/env -S deno run -A
// capdel — Deno/TS broker for dynamic capability delegation. Wire- and crypto-compatible
// with capdel.py (see SPEC.md + conformance/vectors.json). Runs standalone or as a pod app.
// Dependency-free (stdlib-only ethos, like capdel.py) — small path/base64 helpers inlined.
function join(...parts: string[]): string { return normalize(parts.filter((p) => p !== "").join("/")); }
function dirname(p: string): string { const i = p.replace(/\/+$/, "").lastIndexOf("/"); return i <= 0 ? (i === 0 ? "/" : ".") : p.slice(0, i); }
function normalize(p: string): string {
  const abs = p.startsWith("/");
  const out: string[] = [];
  for (const seg of p.split("/")) {
    if (seg === "" || seg === ".") continue;
    if (seg === "..") { if (out.length && out[out.length - 1] !== "..") out.pop(); else if (!abs) out.push(".."); }
    else out.push(seg);
  }
  return (abs ? "/" : "") + out.join("/") || (abs ? "/" : ".");
}
function encodeBase64(b: Uint8Array): string { let s = ""; for (const x of b) s += String.fromCharCode(x); return btoa(s); }
function decodeBase64(s: string): Uint8Array { const bin = atob(s); const out = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i); return out; }

const HOME = Deno.env.get("CAPDEL_HOME") ?? join(Deno.env.get("HOME") ?? ".", ".capdel");
const CAPS = join(HOME, "caps"), REQS = join(HOME, "requests"), AUDIT = join(HOME, "audit.jsonl");
const FS_OPS = new Set(["list", "read", "write", "stat"]);
const DEF_MAX_BYTES = 1 << 20, DEF_TIMEOUT = 60, DEF_MAX_OUTPUT = 1 << 18;
const OWNER_SECRET = Deno.env.get("CAPDEL_OWNER_SECRET") ?? null;
const REQUEST_TTL = parseInt(Deno.env.get("CAPDEL_REQUEST_TTL") ?? "3600");
const POP_MODE = Deno.env.get("CAPDEL_POP") ?? "off";
const SKEW = 300, SCHEME = "capdel-hmac-sha256";
const COMMIT = gitCommit();

class Denied extends Error {}

// ---- crypto (byte-exact with capdel.py) --------------------------------------------
const enc = new TextEncoder();
const buf = (x: Uint8Array): BufferSource => x as unknown as BufferSource;
const hex = (a: ArrayBuffer) => [...new Uint8Array(a)].map((b) => b.toString(16).padStart(2, "0")).join("");
async function sha256Hex(data: Uint8Array): Promise<string> {
  return hex(await crypto.subtle.digest("SHA-256", buf(data)));
}
const shaStr = (s: string) => sha256Hex(enc.encode(s));
async function hmacHex(keyStr: string, msg: string): Promise<string> {
  const key = await crypto.subtle.importKey("raw", buf(enc.encode(keyStr)), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return hex(await crypto.subtle.sign("HMAC", key, buf(enc.encode(msg))));
}
function randHex(nBytes: number): string {
  const b = new Uint8Array(nBytes);
  crypto.getRandomValues(b);
  return [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
}
function timingEq(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

// ---- state ------------------------------------------------------------------------
const now = () => Math.floor(Date.now() / 1000);
function ensureHome() {
  for (const d of [CAPS, REQS]) Deno.mkdirSync(d, { recursive: true });
  try { Deno.chmodSync(HOME, 0o700); } catch { /* windows */ }
}
function gitCommit(): string {
  try {
    const r = new Deno.Command("git", { args: ["rev-parse", "--short", "HEAD"], cwd: dirname(fromFileUrl(import.meta.url)), stderr: "null" }).outputSync();
    return r.success ? new TextDecoder().decode(r.stdout).trim() : "unknown";
  } catch { return "unknown"; }
}
function fromFileUrl(u: string): string { return decodeURIComponent(new URL(u).pathname); }

// deno-lint-ignore no-explicit-any
type Cap = any;
// deno-lint-ignore no-explicit-any
type Req = any;

function load(dir: string, oid: string): Cap | null {
  if (!/^[a-z]+-[0-9a-f]+$/.test(oid ?? "")) return null;
  try { return JSON.parse(Deno.readTextFileSync(join(dir, `${oid}.json`))); } catch { return null; }
}
function save(dir: string, obj: Cap) { Deno.writeTextFileSync(join(dir, `${obj.id}.json`), JSON.stringify(obj, null, 1)); }
// deno-lint-ignore no-explicit-any
function audit(kw: Record<string, any>) { Deno.writeTextFileSync(AUDIT, JSON.stringify({ ts: now(), ...kw }) + "\n", { append: true }); }
function allCaps(): Cap[] {
  const out: Cap[] = [];
  try { for (const e of [...Deno.readDirSync(CAPS)].sort((a, b) => a.name < b.name ? -1 : 1)) if (e.name.endsWith(".json")) out.push(JSON.parse(Deno.readTextFileSync(join(CAPS, e.name)))); } catch { /* empty */ }
  return out;
}
function reqStatus(r: Req): string { return r.status === "pending" && now() > (r.expires_at ?? 2 ** 62) ? "expired" : r.status; }

// ---- PoP nonce replay store --------------------------------------------------------
const nonces = new Map<string, number>();
function nonceSeen(nonce: string, ts: number): boolean {
  const exp = Math.max(now(), ts) + SKEW;
  for (const [n, e] of nonces) if (e < now()) nonces.delete(n);
  if (nonces.has(nonce)) return true;
  nonces.set(nonce, exp);
  return false;
}
async function verifyPop(cap: Cap, method: string, path: string, body: Uint8Array, headers: Headers) {
  if (!cap.secret) throw new Denied("capability has no PoP secret — mint with --pop (or run under CAPDEL_POP=allow)");
  const sig = headers.get("Capdel-Signature") ?? "", nonce = headers.get("Capdel-Nonce") ?? "", tsS = headers.get("Capdel-Timestamp") ?? "";
  if (!(sig && nonce && tsS)) throw new Denied("missing PoP headers (Capdel-Signature/Nonce/Timestamp)");
  const ts = parseInt(tsS);
  if (!Number.isFinite(ts) || !/^-?\d+$/.test(tsS)) throw new Denied("bad Capdel-Timestamp");
  if (Math.abs(now() - ts) > SKEW) throw new Denied(`timestamp outside ±${SKEW}s window`);
  const bh = await sha256Hex(body);
  const canonical = [SCHEME, method, path, bh, nonce, tsS].join("\n");
  const expect = await hmacHex(cap.secret, canonical);
  if (!timingEq(expect, sig)) throw new Denied("bad signature");
  if (nonceSeen(nonce, ts)) throw new Denied("nonce replay");
  return true;
}

function checkLive(cap: Cap) {
  let c: Cap | null = cap;
  while (c) {
    if (c.revoked) throw new Denied(`capability ${c.id} is revoked`);
    if (now() > c.expires_at) throw new Denied(`capability ${c.id} is expired`);
    c = c.parent ? load(CAPS, c.parent) : null;
  }
}
function effectiveClosesOn(cap: Cap): string[] {
  const evs = new Set<string>();
  let c: Cap | null = cap;
  while (c) { for (const e of (c.closes_on ?? [])) evs.add(e); c = c.parent ? load(CAPS, c.parent) : null; }
  return [...evs].sort();
}
function fireEvent(name: string): string[] {
  if (!/^[\w.:-]+$/.test(name ?? "")) throw new Denied("event name must match [\\w.:-]+");
  const closed: string[] = [];
  for (const c of allCaps()) {
    if (c.revoked) continue;
    if ((c.closes_on ?? []).includes(name)) { c.revoked = true; save(CAPS, c); closed.push(c.id); }
  }
  audit({ event: "close_event", name, closed });
  return closed;
}

// ---- path containment (matches os.path.realpath + commonpath) -----------------------
function lenientRealPath(p: string): string {
  let abs = normalize(p.startsWith("/") ? p : join(Deno.cwd(), p));
  // resolve symlinks on the longest existing prefix, keep the nonexistent tail
  const parts = abs.split("/");
  for (let i = parts.length; i > 0; i--) {
    const prefix = parts.slice(0, i).join("/") || "/";
    try {
      const real = Deno.realPathSync(prefix);
      abs = normalize(join(real, parts.slice(i).join("/")));
      break;
    } catch { /* keep shrinking */ }
  }
  return abs;
}
function commonPath(a: string, b: string): string {
  const pa = a.split("/"), pb = b.split("/"), out: string[] = [];
  for (let i = 0; i < Math.min(pa.length, pb.length); i++) { if (pa[i] !== pb[i]) break; out.push(pa[i]); }
  return out.join("/") || "/";
}
function resolveInside(root: string, path: string): string {
  const rp = lenientRealPath(path), rroot = lenientRealPath(root);
  if (commonPath(rroot, rp) !== rroot) throw new Denied(`path ${path} escapes root ${root}`);
  return rp;
}
function pathUnder(parent: string, child: string): boolean {
  const rp = lenientRealPath(parent), rc = lenientRealPath(child);
  return commonPath(rp, rc) === rp;
}

// ---- constraint validation + subset -----------------------------------------------
function validateConstraints(type_: string, c: Cap) {
  if (type_ === "fs") {
    if (!(typeof c.root === "string" && c.root.startsWith("/"))) throw new Denied("fs constraints need an absolute 'root'");
    if (!c.ops?.length || [...c.ops].some((o: string) => !FS_OPS.has(o))) throw new Denied(`fs 'ops' must be a non-empty subset of ${[...FS_OPS].sort()}`);
  } else if (type_ === "exec") {
    const allow = c.allow;
    if (!allow?.length || !allow.every((a: unknown) => Array.isArray(a) && a.length && a.every((x) => typeof x === "string"))) throw new Denied("exec 'allow' must be a non-empty list of argv prefixes (lists of strings)");
    if (!(typeof c.cwd_root === "string" && c.cwd_root.startsWith("/"))) throw new Denied("exec constraints need an absolute 'cwd_root'");
  } else if (type_ === "net") {
    const allow = c.allow;
    if (!allow?.length || !allow.every((a: unknown) => Array.isArray(a) && a.length === 2 && typeof a[0] === "string" && typeof a[1] === "number" && Number.isInteger(a[1]) && a[1] >= 0)) throw new Denied("net 'allow' must be a non-empty list of [host, port] (port int, 0=any)");
  } else if (type_ === "llm") {
    if (!c.models?.length || !c.models.every((m: unknown) => typeof m === "string")) throw new Denied("llm 'models' must be a non-empty list of model-name strings");
    if ("max_tokens" in c && !(Number.isInteger(c.max_tokens) && c.max_tokens > 0)) throw new Denied("llm 'max_tokens' must be a positive int");
  } else throw new Denied(`unknown capability type ${JSON.stringify(type_)}`);
}
function checkSubset(type_: string, child: Cap, parentCap: Cap) {
  if (type_ !== parentCap.type) throw new Denied(`type differs from parent type ${parentCap.type}`);
  const p = parentCap.constraints;
  if (type_ === "fs") {
    const extra = [...child.ops].filter((o: string) => !p.ops.includes(o));
    if (extra.length) throw new Denied(`ops ${extra.sort()} exceed parent ops ${p.ops}`);
    if (!pathUnder(p.root, child.root)) throw new Denied(`root ${child.root} is not under parent root ${p.root}`);
    if ((child.max_bytes ?? DEF_MAX_BYTES) > (p.max_bytes ?? DEF_MAX_BYTES)) throw new Denied("max_bytes exceeds parent's");
  } else if (type_ === "exec") {
    for (const a of child.allow) if (!p.allow.some((pref: string[]) => pref.every((x, i) => a[i] === x) && a.length >= pref.length)) throw new Denied(`argv prefix ${JSON.stringify(a)} is not an extension of any parent prefix`);
    if (!pathUnder(p.cwd_root, child.cwd_root)) throw new Denied(`cwd_root ${child.cwd_root} is not under parent's ${p.cwd_root}`);
    if ((child.timeout_s ?? DEF_TIMEOUT) > (p.timeout_s ?? DEF_TIMEOUT)) throw new Denied("timeout_s exceeds parent's");
    if ((child.max_output ?? DEF_MAX_OUTPUT) > (p.max_output ?? DEF_MAX_OUTPUT)) throw new Denied("max_output exceeds parent's");
  } else if (type_ === "net") {
    for (const [ch, cp] of child.allow) if (!p.allow.some(([ph, pp]: [string, number]) => ph === ch && (pp === 0 || pp === cp))) throw new Denied(`destination [${ch}, ${cp}] not covered by parent allow`);
    if ((child.max_bytes ?? DEF_MAX_BYTES) > (p.max_bytes ?? DEF_MAX_BYTES)) throw new Denied("max_bytes exceeds parent's");
    if ((child.timeout_s ?? DEF_TIMEOUT) > (p.timeout_s ?? DEF_TIMEOUT)) throw new Denied("timeout_s exceeds parent's");
  } else {
    const extra = [...child.models].filter((m: string) => !p.models.includes(m));
    if (extra.length) throw new Denied(`models ${extra.sort()} exceed parent models`);
    if ((child.max_tokens ?? (1 << 30)) > (p.max_tokens ?? (1 << 30))) throw new Denied("max_tokens exceeds parent's");
    if ((child.base_url ?? p.base_url) !== p.base_url) throw new Denied("base_url may not differ from parent's");
  }
}
function validateClosesOn(events: unknown): string[] {
  if (events == null) return [];
  if (!Array.isArray(events) || !events.every((e) => typeof e === "string" && /^[\w.:-]+$/.test(e))) throw new Denied("closes_on must be a list of event-name strings (letters/digits/_/./:/-)");
  return [...new Set(events)].sort();
}

async function mint(type_: string, constraints: Cap, name: string, ttlS: number, parent: Cap | null = null, pop = false, closesOn: unknown = null): Promise<[Cap, string]> {
  validateConstraints(type_, constraints);
  const closes = validateClosesOn(closesOn);
  let expires = now() + ttlS;
  if (parent) { checkLive(parent); checkSubset(type_, constraints, parent); expires = Math.min(expires, parent.expires_at); }
  const cid = "cap-" + randHex(6);
  let token: string, tokSha: string, secret: string | null;
  if (pop) {
    secret = parent?.secret ? "ct-" + (await hmacHex(parent.secret, cid)).slice(0, 32) : "ct-" + randHex(16);
    token = secret; tokSha = await shaStr(secret);
  } else {
    token = "ct-" + randHex(16); tokSha = await shaStr(token); secret = null;
  }
  const cap: Cap = { id: cid, parent: parent ? parent.id : null, name, type: type_, constraints, expires_at: expires, revoked: false, token_sha256: tokSha, created: now(), last_used: null, pop: !!pop, closes_on: closes };
  if (secret !== null) cap.secret = secret;
  save(CAPS, cap);
  audit({ event: "mint", cap: cid, parent: cap.parent, name, constraints, pop: !!pop, closes_on: closes });
  return [cap, token];
}

// ---- invoke -----------------------------------------------------------------------
async function fsInvoke(cap: Cap, body: Cap): Promise<Cap> {
  const c = cap.constraints, op = body.op;
  if (!c.ops.includes(op)) throw new Denied(`op ${JSON.stringify(op)} not in granted ops ${c.ops}`);
  const rp = resolveInside(c.root, body.path);
  const maxBytes = c.max_bytes ?? DEF_MAX_BYTES;
  if (op === "list") {
    const entries = [];
    for (const e of Deno.readDirSync(rp)) {
      let size = null;
      if (e.isFile) try { size = Deno.statSync(join(rp, e.name)).size; } catch { /* race */ }
      entries.push({ name: e.name, type: e.isDirectory ? "dir" : (e.isFile ? "file" : "other"), size });
    }
    entries.sort((a, b) => a.name < b.name ? -1 : 1);
    return { entries };
  }
  if (op === "stat") { const st = Deno.statSync(rp); return { size: st.size, mtime: Math.floor((st.mtime?.getTime() ?? 0) / 1000), is_dir: st.isDirectory }; }
  if (op === "read") {
    const off = parseInt(body.offset ?? 0), length = body.length;
    const all = Deno.readFileSync(rp);
    const want = length == null ? maxBytes + 1 : Math.min(parseInt(length), maxBytes + 1);
    const data = all.subarray(off, off + want);
    if (data.length > maxBytes) throw new Denied(`read of ${data.length}B over max_bytes ${maxBytes}; pass a smaller length or read in offset windows`);
    return { content: new TextDecoder().decode(data), offset: off, bytes: data.length };
  }
  const data = enc.encode(body.content);
  if (data.length > maxBytes) throw new Denied(`write of ${data.length}B is over max_bytes ${maxBytes}`);
  let created = false;
  try { Deno.statSync(rp); } catch { created = true; }
  Deno.writeFileSync(rp, data);
  return { path: rp, written: data.length, created };
}
async function execInvoke(cap: Cap, body: Cap): Promise<Cap> {
  const c = cap.constraints, argv = body.argv;
  if (!(Array.isArray(argv) && argv.length && argv.every((a) => typeof a === "string"))) throw new Denied("argv must be a non-empty list of strings");
  if (!c.allow.some((pref: string[]) => pref.every((x, i) => argv[i] === x) && argv.length >= pref.length)) throw new Denied(`argv ${JSON.stringify(argv.slice(0, 3))}… does not extend any allowed prefix ${JSON.stringify(c.allow)}`);
  const cwd = resolveInside(c.cwd_root, body.cwd ?? c.cwd_root);
  const cmd = new Deno.Command(argv[0], { args: argv.slice(1), cwd, stdin: body.stdin != null ? "piped" : "null", stdout: "piped", stderr: "piped", signal: AbortSignal.timeout((c.timeout_s ?? DEF_TIMEOUT) * 1000) });
  const child = cmd.spawn();
  if (body.stdin != null) { const w = child.stdin.getWriter(); await w.write(enc.encode(body.stdin)); await w.close(); }
  const r = await child.output();
  const mo = c.max_output ?? DEF_MAX_OUTPUT;
  const dec = new TextDecoder();
  const so = dec.decode(r.stdout), se = dec.decode(r.stderr);
  return { code: r.code, stdout: so.slice(0, mo), stderr: se.slice(0, mo), truncated: so.length > mo || se.length > mo };
}
async function netInvoke(cap: Cap, body: Cap): Promise<Cap> {
  const c = cap.constraints;
  if (body.op !== "connect") throw new Denied(`op ${JSON.stringify(body.op)} not supported; net op is 'connect'`);
  const host = body.host, port = parseInt(body.port);
  if (!c.allow.some(([ph, pp]: [string, number]) => ph === host && (pp === 0 || pp === port))) throw new Denied(`[${host}, ${port}] not in allowed destinations ${JSON.stringify(c.allow)}`);
  const maxBytes = c.max_bytes ?? DEF_MAX_BYTES, timeoutS = c.timeout_s ?? DEF_TIMEOUT;
  const send = body.send ? decodeBase64(body.send) : new Uint8Array();
  const conn = await deadline(Deno.connect({ hostname: host, port }), timeoutS * 1000);
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    if (send.length) await conn.write(send);
    while (total < maxBytes) {
      const buf = new Uint8Array(Math.min(65536, maxBytes - total));
      const n = await deadline(conn.read(buf), timeoutS * 1000);
      if (n === null) break;
      chunks.push(buf.subarray(0, n)); total += n;
    }
  } finally { try { conn.close(); } catch { /* already closed */ } }
  const merged = new Uint8Array(total);
  let o = 0; for (const c2 of chunks) { merged.set(c2, o); o += c2.length; }
  return { recv: encodeBase64(merged), bytes: total, truncated: total >= maxBytes };
}
async function llmInvoke(cap: Cap, body: Cap): Promise<Cap> {
  const c = cap.constraints;
  if (body.op !== "chat") throw new Denied(`op ${JSON.stringify(body.op)} not supported; llm op is 'chat'`);
  const key = Deno.env.get("CAPDEL_LLM_KEY");
  if (!key) throw new Denied("broker has no CAPDEL_LLM_KEY configured — cannot exercise an llm cap");
  const model = body.model ?? c.models[0];
  if (!c.models.includes(model)) throw new Denied(`model ${JSON.stringify(model)} not in allowed models ${JSON.stringify(c.models)}`);
  if (!Array.isArray(body.messages) || !body.messages.length) throw new Denied("'messages' must be a non-empty list");
  const base = c.base_url ?? Deno.env.get("CAPDEL_LLM_BASE_URL") ?? "https://api.z.ai/api/coding/paas/v4";
  // deno-lint-ignore no-explicit-any
  const payload: any = { model, messages: body.messages, temperature: body.temperature ?? 0 };
  const capMax = c.max_tokens, reqMax = body.max_tokens;
  if (capMax || reqMax) payload.max_tokens = Math.min(reqMax || capMax, capMax || reqMax);
  const resp = await fetch(base.replace(/\/$/, "") + "/chat/completions", { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${key}` }, body: JSON.stringify(payload) });
  if (!resp.ok) throw new Denied(`llm upstream ${resp.status}: ${(await resp.text()).slice(0, 200)}`);
  return await resp.json();
}
function deadline<T>(p: Promise<T>, ms: number): Promise<T> {
  return Promise.race([p, new Promise<T>((_, rej) => setTimeout(() => rej(new Denied("connection timed out (peer may not have closed; send Connection: close)")), ms))]);
}
const INVOKE: Record<string, (c: Cap, b: Cap) => Promise<Cap>> = { fs: fsInvoke, exec: execInvoke, net: netInvoke, llm: llmInvoke };

function describe(cap: Cap, base: string): Cap {
  const c = cap.constraints;
  const out: Cap = { id: cap.id, name: cap.name, type: cap.type, constraints: c, expires_at: cap.expires_at, auth: cap.pop ? "pop-hmac-sha256" : "bearer" };
  out.how = cap.pop
    ? [`# sign with capdel-sign (no Bearer on the wire); type=${cap.type}`, `curl -s ${base}/capdel-sign > capdel-sign && chmod +x capdel-sign`, `export CAPDEL_URL=${base} CAPDEL_TOKEN=ct-…`, `./capdel-sign POST /caps/${cap.id}/invoke '<op json>'`]
    : [`curl -s -H 'Authorization: Bearer $CAPDEL_TOKEN' -d '<op json>' ${base}/caps/${cap.id}/invoke`];
  out.closes_on = effectiveClosesOn(cap);
  out.escalate = `POST ${base}/caps/${cap.id}/escalate {"want":{…},"reason":…} → poll GET ${base}/requests/<id>`;
  if (cap.pop) out.sign_helper = SIGN_HELPER;
  return out;
}

// ---- the agent-side signer, served at GET /capdel-sign -----------------------------
const SIGN_HELPER = `#!/usr/bin/env python3
# capdel-sign — sign+send a capdel PoP request (HMAC-SHA256), or derive a child secret.
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
`;

// ---- HTTP -------------------------------------------------------------------------
function jsonResp(code: number, obj: Cap): Response { return new Response(JSON.stringify(obj), { status: code, headers: { "content-type": "application/json" } }); }
const bearerOf = (h: Headers) => (h.get("Authorization") ?? "").replace(/^Bearer /, "").trim();
const ownerOk = (h: Headers) => !!OWNER_SECRET && bearerOf(h) === OWNER_SECRET;
function baseOf(h: Headers): string { const fwd = h.get("X-Capdel-Public-Base"); return fwd ? fwd : `http://${h.get("Host") ?? "127.0.0.1"}`; }

async function authn(cid: string, method: string, path: string, body: Uint8Array, headers: Headers): Promise<Cap | null> {
  const cap = load(CAPS, cid);
  if (!cap) return null;
  const perCap = cap.pop, hasSig = headers.has("Capdel-Signature");
  const wantPop = POP_MODE === "require" || perCap === true || (POP_MODE === "allow" && hasSig);
  if (wantPop) { await verifyPop(cap, method, path, body, headers); return cap; }
  if (POP_MODE !== "require" && cap.token_sha256 && timingEq(await shaStr(bearerOf(headers)), cap.token_sha256)) return cap;
  return null;
}

async function handle(req: Request): Promise<Response> {
  const url = new URL(req.url);
  const path = url.pathname;
  const full = url.pathname + (url.search || "");
  const raw = new Uint8Array(await req.arrayBuffer());

  if (req.method === "GET") {
    if (path === "/capdel-sign") return new Response(SIGN_HELPER, { headers: { "content-type": "text/plain; charset=utf-8" } });
    if (path === "/_api/version") return jsonResp(200, { server: "capdel-deno/0.1", commit: COMMIT, pop_mode: POP_MODE, schemes: ["bearer", SCHEME] });
    if (path === "/_tree" || path === "/_audit") { if (!ownerOk(req.headers)) return jsonResp(401, { error: "owner secret required" }); return jsonResp(200, path === "/_tree" ? { tree: treeData() } : { audit: auditTail() }); }
    let m = path.match(/^\/caps\/([\w-]+)$/);
    if (m) {
      let cap: Cap | null;
      try { cap = await authn(m[1], "GET", full, raw, req.headers); } catch (e) { if (e instanceof Denied) { audit({ event: "authn", cap: m[1], op: full, decision: "deny", violated: e.message }); return jsonResp(403, { error: "denied", violated: e.message }); } throw e; }
      if (!cap) return jsonResp(401, { error: "unknown capability or bad token" });
      return jsonResp(200, describe(cap, baseOf(req.headers)));
    }
    m = path.match(/^\/requests\/([\w-]+)$/);
    if (m) {
      const r = load(REQS, m[1]);
      if (!r) return jsonResp(404, { error: "unknown request" });
      let cap: Cap | null;
      try { cap = await authn(r.cap, "GET", full, raw, req.headers); } catch (e) { if (e instanceof Denied) return jsonResp(403, { error: "denied", violated: (e as Error).message }); throw e; }
      if (!cap) return jsonResp(401, { error: "polling a request needs the SAME token you escalated with" });
      const st = reqStatus(r);
      const out: Cap = { request_id: r.id, status: st };
      if (st === "approved") { out.token = r.token; out.cap = r.minted_cap; }
      return jsonResp(200, out);
    }
    return jsonResp(404, { error: "no such route" });
  }

  if (req.method === "POST") {
    if (path === "/_event") {
      if (!ownerOk(req.headers)) return jsonResp(401, { error: "owner secret required (closure events are owner-filed)" });
      try { const name = JSON.parse(new TextDecoder().decode(raw) || "{}").name; const closed = fireEvent(name); return jsonResp(200, { event: name, closed, count: closed.length }); }
      catch (e) { return jsonResp(400, { error: "denied", violated: (e as Error).message }); }
    }
    if (path === "/_gc") { if (!ownerOk(req.headers)) return jsonResp(401, { error: "owner secret required" }); const removed = gcExpired(); return jsonResp(200, { cleared: removed.length, ids: removed }); }
    if (path === "/_mint") {
      // owner-gated HTTP mint (symmetric with the CLI; lets the whole protocol be driven over HTTP for a pod)
      if (!ownerOk(req.headers)) return jsonResp(401, { error: "owner secret required" });
      try { const b = JSON.parse(new TextDecoder().decode(raw) || "{}"); const [cap, token] = await mint(b.type, b.constraints, b.name ?? "root grant", b.ttl_s ?? 14400, null, !!b.pop, b.closes_on ?? null); return jsonResp(200, { id: cap.id, token, expires_at: cap.expires_at, pop: cap.pop }); }
      catch (e) { if (e instanceof Denied) return jsonResp(403, { error: "denied", violated: e.message }); return jsonResp(400, { error: `bad request: ${(e as Error).message}` }); }
    }
    const m = path.match(/^\/caps\/([\w-]+)\/(invoke|attenuate|escalate)$/);
    if (!m) return jsonResp(404, { error: "no such route" });
    const cid = m[1], action = m[2];
    let cap: Cap | null;
    try { cap = await authn(cid, "POST", full, raw, req.headers); } catch (e) { if (e instanceof Denied) { audit({ event: "authn", cap: cid, op: full, decision: "deny", violated: e.message }); return jsonResp(403, { error: "denied", violated: e.message }); } throw e; }
    if (!cap) return jsonResp(401, { error: "unknown capability or failed PoP/bearer auth" });
    try {
      const body = raw.length ? JSON.parse(new TextDecoder().decode(raw)) : {};
      checkLive(cap);
      if (action === "invoke") {
        const result = await INVOKE[cap.type](cap, body);
        cap.last_used = now(); save(CAPS, cap);
        audit({ event: "invoke", cap: cap.id, op: body.op, arg: body.path ?? body.argv ?? body.host, decision: "allow" });
        return jsonResp(200, result);
      }
      if (action === "attenuate") {
        const childPop = !!cap.pop || ("secret" in cap);
        const [child, token] = await mint(cap.type, body.constraints, body.name ?? `child of ${cap.id}`, parseInt(body.ttl_s ?? 3600), cap, childPop, body.closes_on);
        return jsonResp(200, { id: child.id, token, expires_at: child.expires_at, pop: child.pop ?? false, closes_on: child.closes_on ?? [] });
      }
      const want = { ...cap.constraints, ...(body.want ?? {}) };
      validateConstraints(cap.type, want);
      const r: Req = { id: "req-" + randHex(6), cap: cap.id, type: cap.type, want, reason: body.reason ?? "", status: "pending", created: now(), expires_at: now() + REQUEST_TTL };
      save(REQS, r);
      audit({ event: "escalate", cap: cap.id, request: r.id, want, reason: r.reason });
      return jsonResp(200, { request_id: r.id, status: "pending", granted_if_approved: want, note: "if approved, poll returns a NEW token + cap id — switch to them", poll: `GET ${baseOf(req.headers)}/requests/${r.id}` });
    } catch (e) {
      if (e instanceof Denied) { audit({ event: action, cap: cap.id, op: full, decision: "deny", violated: e.message }); return jsonResp(403, { error: "denied", violated: e.message }); }
      const msg = (e as Error).message ?? String(e);
      if (e instanceof Deno.errors.NotFound || e instanceof Deno.errors.NotADirectory || e instanceof Deno.errors.PermissionDenied) return jsonResp(404, { error: msg });
      return jsonResp(400, { error: `bad request: ${msg}` });
    }
  }
  return jsonResp(404, { error: "no such route" });
}

// ---- tree / audit / gc ------------------------------------------------------------
function fmtConstraints(cap: Cap): string {
  const c = cap.constraints;
  if (cap.type === "fs") return `fs ${c.ops.join(",")} ${c.root}`;
  if (cap.type === "exec") return `exec [${c.allow.map((a: string[]) => a.join(" ")).join(" | ")}] cwd=${c.cwd_root}`;
  if (cap.type === "llm") return `llm [${c.models.join(",")}]${c.max_tokens ? ` ≤${c.max_tokens}tok` : ""}`;
  return `net [${c.allow.map(([h, p]: [string, number]) => `${h}:${p ? p : "*"}`).join(", ")}]`;
}
function treeData(): Cap[] {
  const kids = new Map<string | null, Cap[]>();
  for (const c of allCaps()) { const k = c.parent; if (!kids.has(k)) kids.set(k, []); kids.get(k)!.push(c); }
  const node = (c: Cap): Cap => ({ id: c.id, name: c.name, type: c.type, summary: fmtConstraints(c), constraints: c.constraints, expires_at: c.expires_at, revoked: c.revoked, last_used: c.last_used, closes_on: c.closes_on ?? [], created: c.created, escalation: c.escalation, children: (kids.get(c.id) ?? []).map(node) });
  return (kids.get(null) ?? []).map(node);
}
function auditTail(n = 200): Cap[] { try { return Deno.readTextFileSync(AUDIT).trim().split("\n").slice(-n).map((l) => JSON.parse(l)); } catch { return []; } }
function gcExpired(): string[] {
  const removed: string[] = [];
  for (const c of allCaps()) if (now() > c.expires_at) { try { Deno.removeSync(join(CAPS, `${c.id}.json`)); removed.push(c.id); } catch { /* gone */ } }
  if (removed.length) audit({ event: "gc", removed });
  return removed;
}

// ---- CLI --------------------------------------------------------------------------
function parseTtl(s: string): number {
  const m = s.match(/^(\d+)([smhd]?)$/);
  if (!m) { console.error(`bad ttl ${s}`); Deno.exit(2); }
  return parseInt(m![1]) * ({ "": 1, s: 1, m: 60, h: 3600, d: 86400 } as Cap)[m![2]];
}
function parseDest(s: string): [string, number] {
  const i = s.lastIndexOf(":");
  if (i <= 0) { console.error(`bad destination ${s} (use host:port or host:*)`); Deno.exit(2); }
  const host = s.slice(0, i), port = s.slice(i + 1);
  return [host, ["*", "0", ""].includes(port) ? 0 : parseInt(port)];
}
function flag(args: string[], name: string): string | undefined { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : undefined; }
function flags(args: string[], name: string): string[] { const out: string[] = []; for (let i = 0; i < args.length; i++) if (args[i] === name) out.push(args[i + 1]); return out; }
const has = (args: string[], name: string) => args.includes(name);

async function main() {
  ensureHome();
  const [cmd, ...args] = Deno.args;
  if (cmd === "serve") {
    const bind = flag(args, "--bind") ?? "127.0.0.1:4571";
    const [host, port] = [bind.slice(0, bind.lastIndexOf(":")), parseInt(bind.slice(bind.lastIndexOf(":") + 1))];
    console.error(`capdel broker (deno) on http://${bind}  (state: ${HOME}; ${OWNER_SECRET ? "with owner endpoints" : "no owner secret"})`);
    Deno.serve({ hostname: host, port }, handle);
    return;
  }
  if (cmd === "mint") {
    const type_ = args[0];
    let constraints: Cap;
    if (type_ === "fs") { constraints = { root: Deno.realPathSync(flag(args, "--root")!), ops: (flag(args, "--ops") ?? "list,read").split(",") }; const mb = flag(args, "--max-bytes"); if (mb) constraints.max_bytes = parseInt(mb); }
    else if (type_ === "exec") { constraints = { allow: flags(args, "--allow").map((a) => a.split(/\s+/)), cwd_root: Deno.realPathSync(flag(args, "--cwd-root")!) }; const t = flag(args, "--timeout"); if (t) constraints.timeout_s = parseInt(t); }
    else if (type_ === "net") { constraints = { allow: flags(args, "--allow").map(parseDest) }; const mb = flag(args, "--max-bytes"); if (mb) constraints.max_bytes = parseInt(mb); const t = flag(args, "--timeout"); if (t) constraints.timeout_s = parseInt(t); }
    else { constraints = { models: flags(args, "--models").flatMap((m) => m.split(",")) }; const bu = flag(args, "--base-url"); if (bu) constraints.base_url = bu; const mt = flag(args, "--max-tokens"); if (mt) constraints.max_tokens = parseInt(mt); }
    const [cap, token] = await mint(type_, constraints, flag(args, "--name") ?? "root grant", parseTtl(flag(args, "--ttl") ?? "4h"), null, has(args, "--pop"), flags(args, "--closes-on"));
    console.log(`id=${cap.id}\ntoken=${token}\nexpires_at=${cap.expires_at}`);
    return;
  }
  if (cmd === "tree") { const walk = (n: Cap, d: number) => { const state = n.revoked ? "REVOKED" : (now() > n.expires_at ? "expired" : `expires in ${Math.floor((n.expires_at - now()) / 60)}m`); console.log(`${"  ".repeat(d)}${n.id}  ${JSON.stringify(n.name)}  ${n.summary}  [${state}]`); for (const k of n.children) walk(k, d + 1); }; for (const n of treeData()) walk(n, 0); return; }
  if (cmd === "requests") { for (const e of [...Deno.readDirSync(REQS)].sort((a, b) => a.name < b.name ? -1 : 1)) { const r = JSON.parse(Deno.readTextFileSync(join(REQS, e.name))); if (reqStatus(r) !== "pending") continue; console.log(`${r.id}  from ${r.cap}  reason: ${r.reason}\n  wants: ${JSON.stringify(r.want)}`); } return; }
  if (cmd === "approve") {
    const r = load(REQS, args[0]); if (!r) { console.error(`no such request ${args[0]}`); Deno.exit(1); }
    if (reqStatus(r) !== "pending") { console.error(`request ${args[0]} is ${reqStatus(r)}`); Deno.exit(1); }
    const [cap, token] = await mint(r.type, r.want, `escalation ${r.id} for ${r.cap}`, parseTtl(flag(args, "--ttl") ?? "1h"), null, has(args, "--pop"), flags(args, "--closes-on"));
    cap.escalation = { request: r.id, source_cap: r.cap, reason: r.reason }; save(CAPS, cap);
    r.status = "approved"; r.token = token; r.minted_cap = cap.id; r.decided = now(); save(REQS, r);
    audit({ event: "approve", request: r.id, cap: cap.id });
    console.log(`approved: minted ${cap.id} (fresh owner grant)`);
    return;
  }
  if (cmd === "deny") { const r = load(REQS, args[0]); if (!r || r.status !== "pending") { console.error(`no pending request ${args[0]}`); Deno.exit(1); } r.status = "denied"; r.decided = now(); save(REQS, r); audit({ event: "deny", request: r.id }); console.log("denied"); return; }
  if (cmd === "revoke") { const cap = load(CAPS, args[0]); if (!cap) { console.error(`no capability ${args[0]}`); Deno.exit(1); } cap.revoked = true; save(CAPS, cap); audit({ event: "revoke", cap: cap.id }); console.log(`revoked ${cap.id} (and its whole subtree, checked at invoke time)`); return; }
  if (cmd === "event") { try { const closed = fireEvent(args[0]); console.log(closed.length ? `event ${JSON.stringify(args[0])}: closed ${closed.length} cap(s): ${closed.join(", ")}` : `event ${JSON.stringify(args[0])}: no capabilities close on it (0 closed)`); } catch (e) { console.error((e as Error).message); Deno.exit(1); } return; }
  if (cmd === "gc") { const removed = gcExpired(); console.log(`cleared ${removed.length} expired capabilit${removed.length === 1 ? "y" : "ies"}${removed.length ? ": " + removed.join(", ") : ""}`); return; }
  if (cmd === "audit") { try { for (const l of Deno.readTextFileSync(AUDIT).trim().split("\n")) { const e = JSON.parse(l); const want = flag(args, "--cap"); if (want && e.cap !== want) continue; console.log(JSON.stringify(e)); } } catch { /* none */ } return; }
  console.error("usage: capdel {serve|mint|tree|requests|approve|deny|revoke|event|gc|audit}"); Deno.exit(2);
}

if (import.meta.main) await main();
