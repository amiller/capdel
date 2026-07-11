# capdel — user journeys

A user journey here is a step-by-step walk through a flow, indexed by the **operator's
mental state** at each step — what they expect, want, worry about, and fear as they go —
not just what the software does. The user is *you*: a person with broad access to your
own machine, deciding whether and how to lend a slice of it to an agent you trust less.
Because trust is the whole product, the fears at each step *are* the design spec — so
each step notes where capdel reassures, and where it leaves an anxiety unanswered (with
the issue that tracks it).

There are two kinds of "user" here, so two kinds of journey. The **human operator**,
indexed by mental state — expectations, fears, wants (Journeys A and B). And the **agent
that holds a capability**, for which the analog of mental state is **context
availability**: what it has in context right now, what it must discover, and what it has
to infer and could get wrong (Journey C). For the *use cases* (what capdel is for), see
the flows at a glance; the journeys below walk those flows — the human's emotionally, the
agent's by what it knows.

**Flows at a glance:** read a corpus not the whole laptop · give a remote worker a slice
not your session · let a remote worker run a command back on your laptop · handle a
mid-task "I need more" · fan a swarm out and see total exposure.

---

## Journey A — Sending an untrusted worker to zed for the first time

*Flow: you have a task to offload to a cheaper/unsupervised model on another machine.*

### Stage 0 — The itch to delegate
**What happens:** You have a chunk of work — triage a repo, check something on GitHub —
that you'd love to hand to a GLM worker on zed and forget about.
**Your head:** *"I want the leverage, but I don't trust GLM the way I trust Claude. Last
time I solved this by cron-copying a cookie onto zed and it felt gross — now there's a
reusable credential sitting on a box I don't fully control."* — **want:** offload the
work; **fear:** giving away more than the task needs; **expectation:** this should be
quick, I shouldn't have to architect anything.
**Where capdel meets you:** The premise lands — "hand it a scoped key, not your
credential" is exactly the itch. But nothing has happened yet; the promise has to survive
the next five minutes.

### Stage 1 — Deciding what to grant
**What happens:** You (or Claude, drafting for you) decide the scope: which folder, which
commands, which host.
**Your head:** *"What does this task actually need? If I grant too little it'll bug me
mid-run; too much and I've recreated the problem. I don't actually know the minimal set."*
— **fear:** getting the scope wrong in a way I won't notice; **want:** something to tell
me "this is enough and no more."
**Where capdel meets you:** Half-reassured. The structural floor helps — whatever you
grant, the worker *can't exceed it*, so an over-broad *reason* can't widen it. But capdel
gives you **no help drafting the minimal scope** — that judgment is on you, and the
research says humans (and models) systematically mis-scope on the first try. This is the
first real anxiety capdel doesn't yet answer.

### Stage 2 — Minting and handing off the token
**What happens:** You run `mint`, get a token, drop `CAPDEL_URL` + the token into the
worker's environment on zed.
**Your head:** *"Okay, this token is now a thing that exists on zed. Is it a liability? If
zed gets popped, is my laptop owned? How is this different from the cookie I was trying to
avoid?"* — **fear:** the token leaking and being reused; **want:** to know the blast
radius is exactly the scope and nothing more, and that I can pull the plug.
**Where capdel meets you:** Mostly reassured, with one honest asterisk. It's *scoped*
(blast radius = that folder), *expiring* (TTL), and *revocable* (one command) — genuinely
better than the cookie. The asterisk: tokens are **bearer** today, so a leaked token is
replayable by whoever sees it, especially once it crosses the public relay — the lurking
doubt tracked by [#4 PoP]. Until that lands, your honest posture is "short TTL, nothing
sensitive behind it."

### Stage 3 — Letting go (the whole point)
**What happens:** You dispatch the worker and try to go do something else.
**Your head:** *"Can I actually look away? The entire reason I'm doing this is to NOT
babysit. But if I can't see what it's touching, I won't relax."* — **want:** peace of
mind on demand — the ability to glance and confirm, not a compulsion to watch.
**Where capdel meets you:** This is where it earns trust. The dashboard is the
reassurance object — one glance shows exactly what the worker can reach, when its access
expires, what it last did; `revoke` is the panic button that's always there. The mental
shift from "I must watch this" to "I can check if I want to" is the product working.

### Stage 4 — It hits a wall and asks
**What happens:** The worker needs something you didn't grant (write a result, a second
folder) and escalates. You're deep in something else.
**Your head:** *"Ugh, interrupted. …but okay — it's *asking*, not stalling and not going
rogue. That's the right behavior. Just don't nag me for trivia, and don't let a real ask
get lost."* — **fear:** death by a thousand approvals; missing the one that matters;
**want:** to decide in two seconds with enough context, ideally batched.
**Where capdel meets you:** Half. The *content* of the ask is well-judged — you see the
reason and the exact grant it would produce, so you're ruling on a shape, not a vibe. But
the ask only reaches you **if you go look** (`capdel requests`) — there's no ping to
Matrix/Paseo yet, so in this exact "I'm elsewhere" mental moment capdel can silently fail
you. The biggest emotional gap, tracked by [#3 routing] (and stale asks lingering, [#2]).

### Stage 5 — Approving
**What happens:** You read the request and approve.
**Your head:** *"Do I actually understand what I'm granting? Is what it *says* it needs
what it'll *actually get*? I don't want to be social-engineered into rubber-stamping."* —
**fear:** approving a benign-sounding request that grants more than it sounds like.
**Where capdel meets you:** Reassured by design: approval shows `granted_if_approved` —
the literal constraints — and mints exactly that, not whatever the worker narrated. You
approve the *shape*. (The residual: the *reason* is still the worker's words; rendering
the shape front-and-center is the mitigation, and matching it is on the dashboard-buttons
side of [#3].)

### Stage 6 — Done, and the cleanup anxiety
**What happens:** The task finishes. You move on.
**Your head:** *"Is it actually over? Did I leave a door open? What can that worker still
do right now?"* — **fear:** forgotten lingering access, the thing you find weeks later;
**want:** it to just clean itself up.
**Where capdel meets you:** Partially. TTL means access *does* die on its own, which
takes the edge off. But grants linger until that TTL and pile up in the tree, and there's
no "the task is done, close everything for this run" gesture — so the "did I leave the
door open?" anxiety isn't fully put to rest ([#2 TTL hygiene], [#7 cleanup], and the
deeper fix [#5 event-driven closure] — access that ends *when its reason ends*, not on a
timer).

---

## Journey B — The escalation ping arrives while you're heads-down

*Flow: you're doing your own work when a delegated worker needs more. A different mental
state entirely — you are the interrupted approver, not the deliberate delegator.*

### Stage 1 — The interruption
**What happens:** A worker you dispatched an hour ago hits a wall and files a request.
**Your head:** *"I'm in the middle of something. Whatever this is, I want to spend five
seconds on it and get back."* — **fear:** losing my own flow; **want:** the decision
pre-chewed so I don't have to reconstruct context.
**Where capdel meets you:** Weak *today* — capdel doesn't reach out at all, so either you
happen to check or the worker waits. This is precisely why [#3 routing] matters: the
right experience is a Matrix/Paseo ping with the reason and the grant inline.

### Stage 2 — Deciding without context
**What happens:** You look at the request cold.
**Your head:** *"Which worker is this? What was it doing? Is this ask reasonable for that
task, or is something off?"* — **fear:** approving something out of context because
reconstructing the context is more work than just saying yes.
**Where capdel meets you:** Partial. The request carries the requesting cap, the reason,
and the exact `want` — enough to judge *the grant*, but not *the task context* (what the
worker has been doing). Surfacing recent activity next to the request (the audit trail for
that cap) would close this — a dashboard-buttons refinement under [#3]/[#7].

### Stage 3 — Back to work, with a residue
**What happens:** You approve (or deny) and return to your task.
**Your head:** *"Fine. …but now there's a new grant live that I made in a hurry. I hope I
didn't just widen something I'll regret."* — **fear:** hasty approvals accumulating into
exposure I never audit.
**Where capdel meets you:** The dashboard is the pressure valve — everything you granted,
hasty or not, is visible in one place and revocable — but only if you go back and look.
Batching (rule on several at once) and a periodic "here's your live exposure" nudge would
turn this residue from anxiety into routine.

---

## Journey C — The agent's journey, indexed by context available

*Same flow as A, but the "user" is the subagent holding the token. Its mental state is
its context window: what it knows, what it must fetch, what it has to guess. Grounded in
the cold-subagent trial (2026-07-11), where an agent given only a URL + token and no docs
completed a task.*

### Stage 0 — Cold start: a URL, a token, a task, and nothing else
**In context:** `CAPDEL_URL`, a cap id, a token, and a task ("read the notes, write a
summary"). **Absent:** what the token permits, the API's shape, any documentation.
**The agent's situation:** it holds authority it cannot yet describe. Its first need is
not to act but to *learn what it holds* — and it has no training knowledge of capdel to
fall back on.
**Where capdel meets it:** one `GET $CAPDEL_URL/caps/<id>` returns the whole manifest —
scope, expiry, the op grammar, literal `curl` examples, the escalate path. The missing
context is exactly one request away, machine-readable. (Trial: the agent did this first,
unprompted, and called it "near-zero guessing.")

### Stage 1 — It now knows the shape, without being told
**In context:** the manifest — `root`, `ops=[list,read]`, the invoke body shape, that
escalation exists. The tool **taught itself at point of use**; nothing had to be in a
system prompt or a fixed tool list. This is the *discoverable-mid-flight* property — the
reason a static MCP tool list chosen at session start is a poor fit for authority that's
minted dynamically. The agent's context is now sufficient to act correctly.

### Stage 2 — Acting, and learning from denials
**In context update:** it lists (gets type/size), reads (works), tries to write → `403`
with `violated: "op 'write' not in granted ops"`. The key property: **a denial is a
context update, not a dead end.** The error names the exact unmet constraint, so the
agent's model of what it can do refreshes on failure — every wrong move is
self-correcting instead of guess-and-flail.

### Stage 3 — The two spots where it had to *infer* (and stumbled)
When it needed write it had to know three things: that it could ask, the shape of the
ask, and what approval returns.
- *Could ask* — **in context** (the manifest's `escalate` field). Fine.
- *Shape of the ask* — **was a gap.** It naturally sent a delta (`{ops:[…]}`) and, before
  the fix, got rejected for a missing `root`. It recovered from the error, but that was a
  wrong first guess caused by an under-specified schema. Now the API accepts the delta and
  echoes `granted_if_approved`. **Gap closed.**
- *What approval returns* — **was a gap.** Nothing told it approval mints a *new* token;
  it learned only by reading the poll payload. Now the escalate response says so. **Gap
  closed.**
These two inferences were the *entire* friction in the trial — both were places the API
made the agent guess. The fix in each case was the same move: **put the missing context
in the response.**

### Stage 4 — The continuation is handed to it, not looked up
**In context:** it polls the request URL; on approval the payload carries the new token
and cap id inline — exactly the context needed to proceed, *delivered* rather than
fetched. It swaps credentials and finishes.

## What the journeys reveal

Reading capdel by mental state instead of by feature re-orders the backlog around
*trust*, and two things jump out:

1. **The felt gaps are #3 and #4, not the exotic ones.** The moments where the user's
   fear goes *unanswered* are "the ask didn't reach me" (#3 routing) and "is this token a
   liability" (#4 PoP). Those, not the deeper research items, are what stop someone from
   actually relaxing and walking away.
2. **The trust arc peaks at Stage 3 and dips at Stage 6.** capdel is most convincing at
   "let go and glance" (the dashboard + revoke) and least convincing at "is it really
   over" (cleanup/closure). #5 (access that ends when its reason ends) is what would make
   the end of a journey feel as safe as the middle.
3. **For the agent, friendliness is context economy.** Journey C's rule: every piece of
   context the agent needs is either already in hand or one self-describing request away —
   discover authority in one GET, make each denial carry the missing constraint, hand
   continuation (new creds) inline, require no out-of-band docs. Every stumble in the
   trial was a spot where the API forced an *inference*; the fix was always to move that
   context into the response. The remaining frontier is an MCP wrapper (#6) for harnesses
   that can't make a discovery GET in the first place.

The one-line emotional pitch: *capdel is the difference between "I copied my credential
onto a box I don't trust and now I'm uneasy" and "I lent it a labeled key, I can see
what the key opens, and I can take it back."*
