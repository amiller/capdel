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
    const fwd = (h: string) => { const v = req.headers.get(h.toLowerCase()); if (v) headers[h] = v; };
    fwd("Authorization"); fwd("Content-Type");
    // PoP (issue #4): pass the holder's signature through untouched. The signed PATH is
    // broker-local (already stripped of the /b/<id> prefix in `cpath`); the relay must
    // not add, drop, or rewrite these, or the HMAC fails at the broker.
    fwd("Capdel-Nonce"); fwd("Capdel-Timestamp"); fwd("Capdel-Signature");
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
    // "Clear expired" sweep (issue #7): forward the owner-gated POST /_gc to the broker
    // through the tunnel, then re-read the tree so the dashboard reflects the cleaned
    // state. The relay still holds no capability — the owner secret gates the sweep the
    // same way it gates the /_tree read.
    let flash: string | null = null;
    if (url.searchParams.get("clear") === "1" && bid && OWNER_SECRET) {
      const g = await relayCall(bid, "POST", "/_gc", { Authorization: `Bearer ${OWNER_SECRET}` }, null, 8000);
      try {
        const j = JSON.parse(g.body);
        flash = g.status === 200
          ? `Cleared ${j.cleared} expired capabilit${j.cleared === 1 ? "y" : "ies"}.`
          : `clear expired failed — broker returned ${g.status}`;
      } catch { flash = `clear expired failed — broker returned ${g.status}`; }
    }
    let tree: unknown = null, treeErr: string | null = null;
    if (bid && OWNER_SECRET) {
      const r = await relayCall(bid, "GET", "/_tree", { Authorization: `Bearer ${OWNER_SECRET}` }, null, 8000);
      if (r.status === 200) tree = JSON.parse(r.body).tree;
      else treeErr = `broker returned ${r.status}: ${r.body}`;
    } else if (bid && !OWNER_SECRET) {
      treeErr = "CAPDEL_OWNER_SECRET not set on the relay — cannot read the grant tree";
    }
    const seen = bid && lastSeen.has(bid)
      ? Math.max(0, Math.round((Date.now() - (lastSeen.get(bid) || 0)) / 1000)) : null;
    return html(renderDashboard(brokers, bid, tree, treeErr, recent, url.searchParams.get("key"), flash, seen));
  }

  return json({ error: "capdel-relay: no such route" }, 404);
}

// ---------------------------------------------------------------- dashboard render
// Styled to match pod/public/mockup.html (issue #7): brand header + live connection, an
// "At a glance" tile row, the capability forest, and the recent-calls table — all driven
// by the REAL /_tree + recent[] data, not hand-built like the mockup.

function esc(s: string): string {
  return String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!));
}

function walk(nodes: any[], fn: (n: any) => void): void {
  for (const n of nodes) { fn(n); if (n.children?.length) walk(n.children, fn); }
}

function renderNode(n: any, depth = 0): string {
  const now = Date.now() / 1000;
  const left = Math.max(0, Math.round((n.expires_at - now) / 60));
  const expired = now > n.expires_at;
  // A revoked subtree is dead at invoke time whether or not it has expired; expired-only
  // caps are the ones the "clear expired" sweep will remove.
  const pill = n.revoked
    ? `<span class="pill rev">revoked${n.children?.length ? " · subtree killed" : ""}</span>`
    : expired ? `<span class="pill rev">expired</span>`
    : left < 3 ? `<span class="pill warn tnum">${left}m left</span>`
    : `<span class="pill ok tnum">${left}m left</span>`;
  const used = n.last_used
    ? ` <span class="used">· used ${Math.max(0, Math.round((now - n.last_used) / 60))}m ago</span>`
    : "";
  const chip = `<span class="chip ${esc(n.type)}">${esc(n.type)}</span>`;
  // Top-level nodes are owner roots. An approved escalation is itself a fresh owner root
  // (see capdel.cmd_approve), so it shows BOTH badges: owner root + escalated ▸ approved.
  const owner = depth === 0 ? '<span class="owner">owner root</span>' : "";
  const escBadge = n.escalation ? '<span class="esc">escalated ▸ approved</span>' : "";
  const lineage = n.escalation
    ? ` <span class="used">· minted from ${esc(n.escalation.request || "")} via ${esc(n.escalation.source_cap || "")}` +
      (n.escalation.reason ? ` (${esc(n.escalation.reason)})` : "") + `</span>`
    : "";
  const kids = (n.children || []).map((k: any) => renderNode(k, depth + 1)).join("");
  return `<li><div class="node${n.revoked ? " rev" : ""}">
      <span class="id">${esc(n.id)}</span><span class="nm">${esc(n.name)}</span>${chip}${owner}${escBadge}${pill}
      <div class="cap">${esc(n.summary)}${used}${lineage}</div></div>${kids ? `<ul>${kids}</ul>` : ""}</li>`;
}

function renderDashboard(brokers: string[], bid: string | undefined, tree: any, treeErr: string | null,
                         recent: any[], key: string | null, flash: string | null, seenSec: number | null): string {
  const all: any[] = tree && Array.isArray(tree) ? tree : [];
  const flat: any[] = [];
  walk(all, (n) => flat.push(n));
  const now = Date.now() / 1000;
  const live = flat.filter((n) => !n.revoked && now <= n.expires_at).length;
  const soon = flat.filter((n) => !n.revoked && now <= n.expires_at && (n.expires_at - now) < 180).length;
  const roots = all.length;
  const delegated = flat.length - roots;
  let depth = 0;
  const ddepth = (nodes: any[], d: number) => { depth = Math.max(depth, d); for (const n of nodes) if (n.children?.length) ddepth(n.children, d + 1); };
  ddepth(all, 1);
  const callsRelayed = recent.length;
  const denied = recent.filter((r) => r.status >= 400).length;
  const escCaps = flat.filter((n) => n.escalation);
  const escApproved = escCaps.length;
  let escAgo = "";
  if (escCaps.length) {
    const newest = escCaps.map((n) => n.created || 0).sort((a, b) => b - a)[0];
    if (newest) escAgo = ` · approved ${Math.max(0, Math.round((now - newest) / 60))}m ago`;
  }
  // Map cap-id -> name so the recent-calls table can show a holder name, not just an id.
  const idMap: Record<string, string> = {};
  walk(all, (n) => { idMap[n.id] = n.name; });

  const connBox = bid
    ? `<div class="conn"><span class="dot" aria-hidden="true"></span>
         <div><div class="who">${esc(bid)}</div><div class="seen tnum">connected${seenSec !== null ? ` · last seen ${seenSec}s ago` : ""}</div></div></div>`
    : '<span class="dim">no broker connected — run <code>capdel tunnel</code> on the owner\'s machine</span>';
  const brokerChips = brokers.length > 1
    ? `<div class="brokers">${brokers.map((b) =>
        `<a class="chip${b === bid ? " on" : ""}" href="/?broker=${encodeURIComponent(b)}${key ? "&amp;key=" + encodeURIComponent(key) : ""}">${esc(b)}</a>`).join(" ")}</div>`
    : "";

  const stats = `<div class="stats">
    <div class="tile"><div class="k">Capabilities live</div><div class="n tnum">${live}</div>
      <div class="s${soon ? " warn" : ""}">${soon ? `${soon} expiring within 3m` : "none expiring soon"}</div></div>
    <div class="tile"><div class="k">Delegation depth</div><div class="n tnum">${depth}</div>
      <div class="s">${roots} root${roots === 1 ? "" : "s"} · ${delegated} delegated</div></div>
    <div class="tile"><div class="k">Calls relayed</div><div class="n tnum">${callsRelayed}</div>
      <div class="s${denied ? " crit" : ""}">this session${denied ? ` · ${denied} denied` : ""}</div></div>
    <div class="tile pink"><div class="k">Escalations</div><div class="n tnum">${escApproved}</div>
      <div class="s">${escApproved ? `approved${escAgo}` : "none approved"}</div></div>
  </div>`;

  const forest = all.length
    ? `<div class="forest"><ul class="tree">${all.map((n) => renderNode(n, 0)).join("")}</ul></div>`
    : treeErr ? `<p class="err">${esc(treeErr)}</p>`
    : brokers.length ? '<p class="dim">no capabilities minted yet</p>' : "";

  const rows = recent.length
    ? recent.map((r) => {
        const m = String(r.path).match(/caps\/(cap-[0-9a-f]+)/);
        const holder = m ? (idMap[m[1]] || m[1]) : "—";
        return `<tr><td class="t tnum">${new Date(r.ts).toISOString().slice(11, 19)}</td>
          <td class="who"><span class="n2">${esc(holder)}</span></td>
          <td class="act"><span class="v">${esc(r.method)}</span> <span>${esc(r.path)}</span></td>
          <td><span class="st ${r.status < 400 ? "ok" : "deny"}">${r.status}</span></td></tr>`;
      }).join("")
    : '<tr><td colspan="4" class="dim">no calls relayed yet</td></tr>';

  const flashHtml = flash ? `<div class="flash">${esc(flash)}</div>` : "";
  const clearForm = (bid && brokers.length)
    ? `<form method="post" action="/?clear=1${key ? "&amp;key=" + encodeURIComponent(key) : ""}" class="clr-form">
         <button class="clr" type="submit">Clear expired</button></form>`
    : "";

  const refresh = key ? `/<span class="dim">?key=…</span>` : "/";
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>capdel relay</title>
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='88'>%F0%9F%94%91</text></svg>">
<style>
  :root{
    --bg:#eef4f4; --panel:#ffffff; --panel-2:#f6fafa; --inset:#eaf3f3;
    --ink:#0f2429; --ink-2:#33474d; --dim:#5f7981; --line:#d7e4e6; --rail:#cfe0e2;
    --teal:#00838a; --teal-deep:#03636a; --pink:#ff48b0;
    --good:#12794a; --good-bg:#e3f1e9; --warn:#8a5f00; --warn-bg:#f8efd6;
    --crit:#b32020; --crit-bg:#fbe3e3; --net:#8a5a00;
    --mono:ui-monospace,"SF Mono","JetBrains Mono",Menlo,Consolas,monospace;
    --sans:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
    color-scheme:light;
  }
  *{box-sizing:border-box}
  html,body{margin:0}
  body{background:var(--bg);color:var(--ink);font-family:var(--sans);
    font-size:14px;line-height:1.5;-webkit-font-smoothing:antialiased;
    background-image:radial-gradient(circle at 12% -8%,#e0eeee 0,transparent 46%);}
  .wrap{max-width:1000px;margin:0 auto;padding:34px 22px 56px}
  a{color:var(--teal-deep)}
  code,.mono{font-family:var(--mono);font-variant-ligatures:none}
  .tnum{font-variant-numeric:tabular-nums}
  .dim{color:var(--dim)}

  .demobar{max-width:1000px;margin:0 auto;padding:9px 22px;font-size:12px;color:var(--dim);
    display:flex;gap:8px;align-items:center;flex-wrap:wrap}
  .demobar b{color:var(--teal-deep);font-weight:600}
  .demobar .sep{opacity:.5}

  header{display:flex;align-items:flex-end;justify-content:space-between;gap:16px;flex-wrap:wrap}
  .brand{display:flex;align-items:baseline;gap:9px}
  .brand h1{margin:0;font-size:23px;letter-spacing:-.01em;font-weight:680}
  .brand .r{font-family:var(--mono);color:var(--pink);font-weight:600;font-size:20px}
  .brand .v{font-family:var(--mono);font-size:11px;color:var(--dim);align-self:center;
    border:1px solid var(--line);border-radius:5px;padding:1px 6px;margin-left:2px}
  .tag{margin:8px 0 0;color:var(--dim);font-size:13px;max-width:62ch}
  .conn{display:flex;align-items:center;gap:9px;background:var(--panel);border:1px solid var(--line);
    border-radius:9px;padding:8px 13px;font-size:13px}
  .conn .who{font-family:var(--mono);font-weight:600;color:var(--ink)}
  .conn .seen{color:var(--dim);font-size:12px}
  .dot{width:9px;height:9px;border-radius:50%;background:var(--good);position:relative;flex:none}
  .dot::after{content:"";position:absolute;inset:-4px;border-radius:50%;
    border:2px solid var(--good);opacity:.5;animation:pulse 2.4s ease-out infinite}
  @keyframes pulse{0%{transform:scale(.6);opacity:.6}70%{opacity:0}100%{transform:scale(1.5);opacity:0}}
  @media (prefers-reduced-motion:reduce){.dot::after{animation:none;opacity:.35}}
  .brokers{margin-top:8px;display:flex;gap:6px;flex-wrap:wrap}

  h2.sec{font-size:11.5px;text-transform:uppercase;letter-spacing:.13em;color:var(--teal-deep);
    margin:34px 0 12px;font-weight:670;display:flex;align-items:center;gap:10px}
  h2.sec::after{content:"";height:1px;flex:1;background:var(--line)}

  .stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}
  .tile{background:var(--panel);border:1px solid var(--line);border-radius:11px;padding:15px 16px;
    position:relative;overflow:hidden}
  .tile::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--teal)}
  .tile.pink::before{background:var(--pink)}
  .tile .k{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--dim)}
  .tile .n{font-size:30px;font-weight:670;letter-spacing:-.02em;margin:5px 0 2px;line-height:1}
  .tile .s{font-size:12px;color:var(--dim)}
  .tile .s.warn{color:var(--warn)} .tile .s.crit{color:var(--crit)}

  .forest{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:6px 4px}
  ul.tree,ul.tree ul{list-style:none;margin:0;padding:0}
  ul.tree>li{border-top:1px solid var(--line)}
  ul.tree>li:first-child{border-top:none}
  ul.tree ul{margin-left:26px;border-left:2px solid var(--rail)}
  .node{display:flex;align-items:center;gap:10px;padding:11px 16px;flex-wrap:wrap}
  ul.tree ul .node{padding-left:14px}
  .node .id{font-family:var(--mono);font-size:12px;color:var(--dim)}
  .node .nm{font-weight:600;color:var(--ink)}
  .node.rev .nm,.node.rev .id{color:#9aa;text-decoration:line-through}
  .cap{flex-basis:100%;padding:2px 0 0;font-family:var(--mono);font-size:12.5px;color:var(--ink-2)}
  ul.tree ul .cap{padding-left:0}
  .used{color:var(--dim);font-weight:400;font-size:12px;font-family:var(--sans)}

  .chip{font-family:var(--mono);font-size:10.5px;font-weight:700;letter-spacing:.03em;
    color:#fff;padding:2px 7px;border-radius:5px;text-transform:uppercase;text-decoration:none}
  .chip.fs{background:var(--teal)} .chip.exec{background:var(--pink)} .chip.net{background:var(--net)}
  a.chip.on{outline:2px solid var(--teal-deep);outline-offset:1px}
  .owner{font-size:10.5px;letter-spacing:.05em;text-transform:uppercase;color:var(--teal-deep);
    background:var(--inset);border:1px solid var(--line);border-radius:5px;padding:1px 7px;font-weight:600}
  .esc{font-size:10.5px;letter-spacing:.04em;text-transform:uppercase;color:#fff;background:var(--pink);
    border-radius:5px;padding:1px 7px;font-weight:700}
  .pill{margin-left:auto;font-size:11.5px;font-weight:600;padding:2px 10px;border-radius:20px;white-space:nowrap;
    font-variant-numeric:tabular-nums}
  .pill.ok{background:var(--good-bg);color:var(--good)}
  .pill.warn{background:var(--warn-bg);color:var(--warn)}
  .pill.rev{background:var(--crit-bg);color:var(--crit)}

  .flash{margin:0 0 14px;padding:9px 14px;border-radius:9px;background:var(--good-bg);
    border:1px solid #bfe2cf;color:var(--good);font-size:13px}
  .clr-form{display:inline}
  .clr{font:inherit;font-size:12px;font-weight:600;color:var(--teal-deep);background:var(--inset);
    border:1px solid var(--line);border-radius:7px;padding:5px 12px;cursor:pointer}
  .clr:hover{background:#dff}

  .logwrap{background:var(--panel);border:1px solid var(--line);border-radius:12px;overflow:hidden}
  .scroll{overflow-x:auto}
  table{width:100%;border-collapse:collapse;font-size:13px;min-width:560px}
  th{text-align:left;font-size:10.5px;text-transform:uppercase;letter-spacing:.08em;color:var(--dim);
    font-weight:600;padding:11px 16px;background:var(--panel-2);border-bottom:1px solid var(--line)}
  td{padding:9px 16px;border-bottom:1px solid var(--line);vertical-align:middle}
  tr:last-child td{border-bottom:none}
  td.t{font-family:var(--mono);color:var(--dim);font-size:12px;white-space:nowrap}
  td.who .n2{font-weight:600}
  td.act{font-family:var(--mono);font-size:12.5px;color:var(--ink-2)}
  td.act .v{color:var(--teal-deep);font-weight:600}
  .st{font-family:var(--mono);font-size:12px;font-weight:700;padding:1px 8px;border-radius:5px}
  .st.ok{background:var(--good-bg);color:var(--good)}
  .st.deny{background:var(--crit-bg);color:var(--crit)}

  footer{margin-top:30px;padding-top:16px;border-top:1px solid var(--line);color:var(--dim);font-size:12.5px}
  footer b{color:var(--ink-2);font-weight:600}
  footer code{font-size:12px;background:var(--inset);border:1px solid var(--line);border-radius:4px;padding:0 5px}
  .verbs{display:flex;gap:6px;flex-wrap:wrap;margin-top:9px}
  .verbs span{font-family:var(--mono);font-size:11px;color:var(--teal-deep);background:var(--inset);
    border:1px solid var(--line);border-radius:5px;padding:2px 8px}
  @media (max-width:680px){.stats{grid-template-columns:repeat(2,1fr)}.pill{margin-left:0}}
</style></head><body>
<div class="demobar"><b>Live</b><span class="sep">·</span>read-only view of a laptop broker's delegated authority, pulled through the dial-out tunnel — the pod never holds a capability.<span class="sep">·</span>Compare the <a href="mockup">hand-built mockup</a>.</div>
<div class="wrap">
  <header>
    <div>
      <div class="brand"><h1>capdel</h1><span class="r">relay</span><span class="v">read-only</span></div>
      <p class="tag">A live view of one laptop broker's delegated authority, pulled through the dial-out tunnel. The pod never holds a capability — enforcement happens on the owner's machine.</p>
    </div>
    ${connBox}
  </header>
  ${brokerChips}

  <h2 class="sec">At a glance${clearForm}</h2>
  ${flashHtml}
  ${stats}

  <h2 class="sec">Delegated capabilities${bid ? ` · ${esc(bid)}` : ""}</h2>
  ${forest}

  <h2 class="sec">Recent relayed calls</h2>
  <div class="logwrap"><div class="scroll">
    <table>
      <thead><tr><th>Time</th><th>Holder</th><th>Action</th><th>Result</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  </div></div>

  <footer>
    Two independent gates guard every remote call: the <b>relay secret</b> (to reach the pod at all) and the <b>capdel token</b> (what it may do). The owner secret that reads this grant tree stays in the relay's attested environment — the browser never sees it. <b>Clear expired</b> asks the broker to delete capabilities whose TTL has already passed (approved escalations are fresh owner roots that would otherwise linger).
    <div class="verbs"><span>mint</span><span>attenuate</span><span>invoke</span><span>escalate</span><span>approve</span><span>revoke</span><span>gc</span></div>
    <div style="margin-top:9px">capdel-relay · <a href="/${key ? `?key=${encodeURIComponent(key)}` : ""}">refresh</a> · a remote agent invokes at <code>/b/&lt;broker-id&gt;/caps/&lt;id&gt;/invoke</code></div>
  </footer>
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
  console.error(`capdel-relay (dev) on http://0.0.0.0:${port}`);
  Deno.serve({ port, hostname: "0.0.0.0" }, (req) => handler(req, { env }));
}
