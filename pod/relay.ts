// capdel-relay — a dstack pod app that is the public rendezvous for a laptop capdel
// broker (SPEC §3.7). The laptop dials OUT (`capdel tunnel`), long-polling this relay
// for requests and posting responses back; this relay never holds authority — it only
// forwards. A remote agent reaches a capability at
//   <pod>/capdel-relay/b/<broker-id>/caps/<id>/invoke   (Bearer <capdel-token>)
// and the enforcement happens on the laptop, in the broker. The relay also renders a
// READ-ONLY dashboard of the live grant tree (pulled through the tunnel with the owner
// secret, server-side — the browser never sees it).
//
// Env (ctx.env): CAPDEL_RELAY_SECRET (gates the laptop's _pull/_reply and the dashboard),
//                CAPDEL_OWNER_SECRET (lets the dashboard read the broker's /_tree, /_audit).

type Job = { req_id: string; method: string; path: string; headers: Record<string, string>; body: string | null };
type Reply = { status: number; body: string };

const queue = new Map<string, Job[]>();                         // broker-id -> pending jobs
const waiters = new Map<string, ((j: Job) => void)[]>();        // broker-id -> long-poll resolvers
const replies = new Map<string, (r: Reply) => void>();          // req_id -> reply resolver
const lastSeen = new Map<string, number>();                     // broker-id -> ts (liveness)
const recent: { ts: number; bid: string; method: string; path: string; status: number }[] = [];

const json = (o: unknown, s = 200) =>
  new Response(JSON.stringify(o), { status: s, headers: { "content-type": "application/json" } });
const html = (s: string) =>
  new Response(s, { headers: { "content-type": "text/html; charset=utf-8" } });

// Enqueue a job for a broker and await its reply. Both the remote-agent passthrough and
// the dashboard's own tree-fetch go through here — same path, same enforcement.
function relayCall(bid: string, method: string, path: string, headers: Record<string, string>,
                   body: string | null, timeoutMs = 30000): Promise<Reply> {
  const req_id = crypto.randomUUID();
  const job: Job = { req_id, method, path, headers, body };
  const w = waiters.get(bid);
  if (w && w.length) w.shift()!(job);
  else (queue.get(bid) ?? queue.set(bid, []).get(bid)!).push(job);
  return new Promise((resolve) => {
    const t = setTimeout(() => { replies.delete(req_id); resolve({ status: 504, body: '{"error":"tunnel timeout — broker offline?"}' }); }, timeoutMs);
    replies.set(req_id, (r) => { clearTimeout(t); resolve(r); });
  });
}

function secretOk(req: Request, url: URL, secret: string | undefined): boolean {
  if (!secret) return true;  // dev: no secret configured
  return req.headers.get("x-capdel-relay-secret") === secret || url.searchParams.get("key") === secret;
}

function connectedBrokers(): string[] {
  const now = Date.now();
  return [...lastSeen.entries()].filter(([, t]) => now - t < 60000).map(([b]) => b);
}

let mockupHtml: string | null = null;
async function getMockup(): Promise<string> {
  if (mockupHtml === null) mockupHtml = await Deno.readTextFile(new URL("./public/mockup.html", import.meta.url));
  return mockupHtml;
}

export default async function handler(req: Request, ctx: { env: Record<string, string> }): Promise<Response> {
  const env = ctx.env || {};
  const RELAY_SECRET = env.CAPDEL_RELAY_SECRET, OWNER_SECRET = env.CAPDEL_OWNER_SECRET;
  const url = new URL(req.url);
  const path = url.pathname;

  // --- public shareable mockup page (no broker, no secret) ---
  if (path === "/mockup" || path === "/mockup/") return html(await getMockup());

  // --- laptop side: long-poll for the next request aimed at this broker ---
  if (path.startsWith("/_pull/")) {
    if (!secretOk(req, url, RELAY_SECRET)) return new Response("forbidden", { status: 403 });
    const bid = path.slice("/_pull/".length);
    lastSeen.set(bid, Date.now());
    const q = queue.get(bid);
    if (q && q.length) return json(q.shift());
    return await new Promise<Response>((resolve) => {
      const arr = waiters.get(bid) ?? (waiters.set(bid, []), waiters.get(bid)!);
      const cb = (job: Job) => { clearTimeout(to); resolve(json(job)); };
      const to = setTimeout(() => {
        const i = arr.indexOf(cb); if (i >= 0) arr.splice(i, 1);
        resolve(new Response(null, { status: 204 }));
      }, 25000);
      arr.push(cb);
    });
  }

  // --- laptop side: post the response for a job it just executed ---
  if (path.startsWith("/_reply/")) {
    if (!secretOk(req, url, RELAY_SECRET)) return new Response("forbidden", { status: 403 });
    const req_id = path.slice("/_reply/".length).split("/").slice(1).join("/");
    const r = replies.get(req_id);
    const payload = await req.json().catch(() => null) as Reply | null;
    if (r && payload) { replies.delete(req_id); r(payload); }
    return json({ ok: !!(r && payload) });
  }

  // --- remote agent side: exercise a capability through the tunnel ---
  if (path.startsWith("/b/")) {
    const rest = path.slice(3);
    const slash = rest.indexOf("/");
    const bid = slash < 0 ? rest : rest.slice(0, slash);
    const cpath = slash < 0 ? "/" : rest.slice(slash);
    if (!connectedBrokers().includes(bid))
      return json({ error: `broker ${bid} not connected — start 'capdel tunnel' on the owner's machine` }, 502);
    const headers: Record<string, string> = {};
    const auth = req.headers.get("authorization"); if (auth) headers["Authorization"] = auth;
    const ct = req.headers.get("content-type"); if (ct) headers["Content-Type"] = ct;
    const body = (req.method === "GET" || req.method === "HEAD") ? null : await req.text();
    const res = await relayCall(bid, req.method, cpath + url.search, headers, body);
    recent.unshift({ ts: Date.now(), bid, method: req.method, path: cpath, status: res.status });
    if (recent.length > 50) recent.pop();
    return new Response(res.body, { status: res.status, headers: { "content-type": "application/json" } });
  }

  // --- read-only dashboard ---
  if (path === "/" || path === "") {
    if (!secretOk(req, url, RELAY_SECRET)) return html(renderLocked());
    const brokers = connectedBrokers();
    const bid = url.searchParams.get("broker") || brokers[0];
    let tree: unknown = null, treeErr: string | null = null;
    if (bid && OWNER_SECRET) {
      const r = await relayCall(bid, "GET", "/_tree", { Authorization: `Bearer ${OWNER_SECRET}` }, null, 8000);
      if (r.status === 200) tree = JSON.parse(r.body).tree;
      else treeErr = `broker returned ${r.status}: ${r.body}`;
    } else if (bid && !OWNER_SECRET) {
      treeErr = "CAPDEL_OWNER_SECRET not set on the relay — cannot read the grant tree";
    }
    return html(renderDashboard(brokers, bid, tree, treeErr, recent, url.searchParams.get("key")));
  }

  return json({ error: "capdel-relay: no such route" }, 404);
}

// ---------------------------------------------------------------- dashboard render

function esc(s: string): string {
  return s.replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!));
}

function renderNode(n: any): string {
  const now = Date.now() / 1000;
  const state = n.revoked ? '<span class="b rev">revoked</span>'
    : now > n.expires_at ? '<span class="b exp">expired</span>'
    : `<span class="b ok">${Math.max(0, Math.round((n.expires_at - now) / 60))}m left</span>`;
  const used = n.last_used ? ` · used ${Math.round((now - n.last_used) / 60)}m ago` : "";
  const kids = (n.children || []).map(renderNode).join("");
  return `<li><code class="id">${esc(n.id)}</code> <b>${esc(n.name)}</b> ${state}
    <div class="cap"><span class="t t-${esc(n.type)}">${esc(n.type)}</span> ${esc(n.summary)}<span class="dim">${used}</span></div>
    ${kids ? `<ul>${kids}</ul>` : ""}</li>`;
}

function renderDashboard(brokers: string[], bid: string | undefined, tree: any, treeErr: string | null,
                         recent: any[], key: string | null): string {
  const k = key ? `?key=${encodeURIComponent(key)}` : "";
  const conn = brokers.length
    ? brokers.map((b) => `<span class="chip ${b === bid ? "on" : ""}">${esc(b)}</span>`).join(" ")
    : '<span class="dim">no broker connected — run <code>capdel tunnel</code> on the owner\'s machine</span>';
  const treeHtml = tree && (tree as any[]).length ? `<ul class="tree">${(tree as any[]).map(renderNode).join("")}</ul>`
    : treeErr ? `<p class="err">${esc(treeErr)}</p>`
    : brokers.length ? '<p class="dim">no capabilities minted yet</p>'
    : "";
  const rows = recent.length ? recent.map((r) => `<tr><td class="dim">${new Date(r.ts).toISOString().slice(11, 19)}</td>
    <td>${esc(r.method)}</td><td><code>${esc(r.path)}</code></td>
    <td class="${r.status < 400 ? "ok" : "bad"}">${r.status}</td></tr>`).join("")
    : '<tr><td colspan="4" class="dim">no calls relayed yet</td></tr>';
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>capdel relay</title><style>
:root{--teal:#00838a;--pink:#ff48b0;--ink:#12252a;--dim:#6b8189;--line:#dbe6e8;--bg:#f5f9f9}
*{box-sizing:border-box}body{margin:0;font:15px/1.5 ui-sans-serif,system-ui,sans-serif;color:var(--ink);background:var(--bg)}
.wrap{max-width:920px;margin:0 auto;padding:28px 20px}
h1{font-size:20px;margin:0 0 2px}h1 .p{color:var(--pink)}h2{font-size:13px;text-transform:uppercase;letter-spacing:.06em;color:var(--teal);margin:26px 0 8px}
.sub{color:var(--dim);margin:0 0 18px;font-size:13px}
.chip{display:inline-block;padding:2px 9px;border-radius:11px;background:#e3eef0;color:var(--dim);font-size:12px}
.chip.on{background:var(--teal);color:#fff}
.card{background:#fff;border:1px solid var(--line);border-radius:10px;padding:14px 16px}
ul.tree{list-style:none;margin:0;padding:0}ul.tree ul{list-style:none;margin:4px 0 4px 18px;padding-left:12px;border-left:2px solid var(--line)}
ul.tree li{margin:8px 0}code.id{font-size:12px;color:var(--dim)}
.cap{font-size:13px;color:#33474d;margin:1px 0 0}.dim{color:var(--dim)}
.t{display:inline-block;min-width:34px;text-align:center;padding:0 6px;border-radius:5px;font-size:11px;font-weight:600;color:#fff;margin-right:4px}
.t-fs{background:var(--teal)}.t-exec{background:#b0006e;background:var(--pink)}.t-net{background:#8a5a00}
.b{font-size:11px;padding:1px 7px;border-radius:9px}.b.ok{background:#e0f0e6;color:#1a7a44}.b.exp{background:#eee;color:#888}.b.rev{background:#fbe0e0;color:#b32020}
table{width:100%;border-collapse:collapse;font-size:13px}td{padding:5px 8px;border-bottom:1px solid var(--line)}
td.ok{color:#1a7a44}td.bad{color:#b32020}.err{color:#b32020;font-size:13px}
footer{margin-top:26px;color:var(--dim);font-size:12px}a{color:var(--teal)}
</style></head><body><div class="wrap">
<h1>capdel <span class="p">relay</span></h1>
<p class="sub">read-only view of a laptop broker's delegated authority, pulled live through the dial-out tunnel — the pod never holds a capability</p>
<h2>Connection</h2><div>${conn}</div>
<h2>Delegated capabilities${bid ? ` · ${esc(bid)}` : ""}</h2>
<div class="card">${treeHtml || '<span class="dim">—</span>'}</div>
<h2>Recent relayed calls</h2>
<div class="card"><table><tr><th></th><th></th><th></th><th></th></tr>${rows}</table></div>
<footer>capdel-relay · <a href="/${k}">refresh</a> · a remote agent invokes at <code>/b/&lt;broker-id&gt;/caps/&lt;id&gt;/invoke</code></footer>
</div></body></html>`;
}

function renderLocked(): string {
  return `<!doctype html><meta charset="utf-8"><title>capdel relay</title>
<body style="font:15px system-ui;max-width:480px;margin:80px auto;color:#12252a">
<h1 style="font-size:19px">capdel relay</h1>
<p style="color:#6b8189">The live dashboard is gated. Append <code>?key=&lt;relay-secret&gt;</code> to view real capabilities,
or see the <a href="mockup" style="color:#03636a">read-only mockup</a>.</p></body>`;
}

// Dev harness: `deno run -A relay.ts` serves the same handler standalone for local testing.
if (import.meta.main) {
  const env = Deno.env.toObject();
  const port = Number(env.PORT || 8090);
  console.error(`capdel-relay (dev) on http://127.0.0.1:${port}`);
  Deno.serve({ port }, (req) => handler(req, { env }));
}
