# capdel — user journeys & analysis

Concrete stories of *when you'd actually reach for capdel*, grounded in a real setup:
a laptop running Claude Code with broad access, cheaper/unsupervised workers on a
remote box (zed) and phone (Paseo), a research corpus in `~/projects/oauth3/refs`, git
repos, and the oauth3 pod. Each journey names the pain *today*, the capdel flow, and —
honestly — where capdel is still weak and which open issue tracks it.

Capability types in play: **fs** (files), **exec** (commands), **net** (outbound host:port).

---

## J1 — "Read the research corpus, not my whole laptop"

**Situation.** Claude Code dispatches a subagent to summarize the PDFs in `refs/`.
**Today.** The subagent inherits your full user access (effectively
`--dangerously-skip-permissions`); nothing stops it reading `~/.ssh`, your browser
cookies, or `~/.env` files if a prompt-injected PDF steers it there.
**With capdel.** You mint `fs read ~/projects/oauth3/refs` and hand the subagent only
that token. It reads the papers; a read of `~/.ssh/id_rsa` returns `403 … escapes root`.
**Analysis.** The plainest win, works **today**, zero remote infra. This is the local
trust-differential case: the trusted agent (Claude) drafts a narrow grant for the
less-trusted worker. Weak spot: the *quality* of your mint — grant `~/projects` when
the task only needs `refs/` and you've over-scoped (nothing enforces "minimal").

## J2 — "Give a GLM worker on zed a slice, not my session"

**Situation.** You run an unsupervised GLM worker on zed to triage a repo and check
something on GitHub. You don't trust it with a shell on your laptop.
**Today (the anti-pattern).** A cron copies a cookie or an ssh key onto zed every few
minutes so the worker can act — now zed holds a *reusable, broad* credential you can't
easily revoke, and if the worker (or zed) is compromised, so is the whole account.
**With capdel.** The broker stays on your laptop; a dial-out tunnel exposes it through
the pod. The zed worker gets `fs read <one repo>` + `net api.github.com:443` — and
nothing else. It can't reach other repos or exfil to a random host; you watch it in the
dashboard and revoke when the task ends.
**Analysis.** *The* core use case — the reason capdel exists. Replaces credential-copying
with a narrow, revocable, watchable grant. Needs the tunnel (`pod/`). Weak spots:
tokens are **bearer** today, so a leaked token is replayable by whoever sees it — [#4
PoP]; and the tunnel is the "expose" switch, so treat it as opening a door.

## J3 — "Let a remote worker run a command *back on my laptop*"

**Situation.** A worker on another machine needs something that only exists on your
laptop — run `git status` in a local repo, hit a service bound to your home network.
**Today.** Basically impossible without giving it SSH or opening your laptop to inbound
traffic — so you don't, and instead pre-copy data around.
**With capdel.** An `exec` cap (`git status`, `cwd` one repo) or a `net` cap to an
internal `host:port` is reachable *through the tunnel*. The remote worker runs exactly
that one thing back on your machine and gets the output — no shell, no inbound port.
**Analysis.** The requirement nobody else in the landscape covers (remote → owner's
machine). Weak spot: `exec` runs as *you*, unconfined — a too-broad exec cap is real
power, and enforcement is userspace-only until kernel-backing lands [#8 Landlock].

## J4 — "It needs more mid-task — ask me, don't stall or over-grant"

**Situation.** A dispatched worker hits a wall: it needs to *write* a result, or read a
second folder you didn't foresee.
**Today.** Either it stalls, or (to avoid stalls) you pre-grant everything up front —
which is just over-provisioning by another name.
**With capdel.** It escalates: `{"want":{"ops":[…,"write"]},"reason":"…"}` — sending only
the delta. You see the request, the reason, and *exactly what it would grant*, and
approve; it picks up a fresh scoped token and continues. It never widened its own power.
**Analysis.** The "effective way of asking me for approval" from the design notes. Works
end-to-end today via CLI. Weak spot: the request only *reaches* you if you go look —
routing to Matrix/Paseo/a dashboard button is [#3]; and stale requests linger without a
TTL [#2].

## J5 — "Fan out a swarm; see and revoke the whole exposure"

**Situation.** You split a job across five workers — each needs a *different* narrow
slice (worker A one repo, B the GitHub API, C a scratch folder, …).
**Today.** You either give them all the same broad access, or hand-manage five sets of
credentials with no single view of who-can-do-what.
**With capdel.** You mint five differently-scoped tokens at dispatch time. The dashboard
shows the whole forest — every grant, its scope, expiry, last use — and you revoke the
batch when the run ends (revoking a root kills its subtree).
**Analysis.** The swarm case, and the one that most needs a *test environment* (below).
Weak spots: grants pile up and want a "clear expired" sweep + better lineage [#7]; and
per-worker isolation still relies on confining each worker *process* separately (capdel
bounds what a token does to *your* resources, not what the worker does on its own box).

---

## What works today vs. what's blocked

| Journey | Requirement | Works today? | Blocked on |
|---|---|---|---|
| J1 read corpus | local scoped fs | ✅ | — (mint quality is on you) |
| J2 GLM worker slice | remote scoped fs+net | ✅ (dev-grade) | #4 PoP for real trust |
| J3 command back on laptop | remote exec/net | ✅ (dev-grade) | #8 kernel confinement |
| J4 mid-task escalation | ask + approve | ✅ via CLI | #3 routing, #2 TTL |
| J5 swarm fan-out | many scoped tokens + legibility | ✅ mechanically | #7 cleanup, #2 TTL |

**Maturity read.** Every journey *runs* today — that's real, and the cold-subagent trial
proved a worker can self-serve from the token alone. But "runs" ≠ "safe to lean on": the
honest gates are **#4** (bearer tokens are replayable once they cross the public relay)
and **#8** (exec/fs enforced only in userspace, no kernel floor). Fix those two and J2/J3
graduate from "neat demo" to "I'd hand this to an untrusted model on zed." Everything
else (#2, #3, #7) is ergonomics that make the swarm case pleasant rather than possible.

**The one-line pitch, per audience.** To a *person*: "scoped, revocable keys for agents,
instead of copying credentials." To an *agent* (the skill): "mint a narrow capability
and hand your subagent only the token." To *you at 2am watching zed*: "the dashboard is
the whole exposure, and revoke kills it."
