# Tier 2 flow evidence — issue #7

Issue #7: _Live dashboard should match the mockup; add clear-expired + escalation-grant
lineage._ The issue body had no `## Acceptance` header; the acceptance below is derived
verbatim from its three concrete deliverables (disclosed in the PR).

## Derived Acceptance
1. The **live** `/` dashboard (rendered by `pod/relay.ts`) is restyled to match
   `pod/public/mockup.html` — brand header + live connection, "At a glance" stat tiles,
   capability forest, styled recent-calls table.
2. A **clear-expired** sweep purges expired capabilities (broker `POST /_gc` / `capdel gc`);
   the dashboard's "Clear expired" button runs it through the tunnel and the gone cap
   disappears.
3. An approved escalation renders its **lineage as data** (which request / from which cap /
   why), not only encoded in the cap name.

## How it was driven (real stack, this branch)
Local end-to-end stack on the box, all three processes from this worktree:
- broker: `python3.11 capdel.py serve` (CAPDEL_HOME=/tmp/capdel7, owner secret set)
- relay:  `deno run -A pod/relay.ts` (CAPDEL_RELAY_SECRET + CAPDEL_OWNER_SECRET, :8931)
- tunnel: `capdel.py tunnel --relay … --broker-id laptop-soc1024`

Grant tree built through the real API: a root fs cap → attenuated child `docs-reviewer` →
holder escalates (add `write`) → owner approves (mints a fresh owner root with escalation
provenance); plus a revoked subtree and a 3s-TTL cap that expires (the clear-expired
target). The zed browser bridge drove `http://172.17.0.1:8931/?key=relay-secret`.

## Asserted (via bridge evaluate against the live DOM)
**Step 1 — dashboard renders mockup styling + lineage + an expired cap (`01-dashboard.png`)**
- 3 section headings; **4 stat tiles** ("CAPABILITIES LIVE 4", "DELEGATION depth",
  "CALLS RELAYED", "ESCALATIONS 1 · approved 2m ago").
- Mockup structural classes all present: demobar, brand, pulsing `.dot`, `.forest`,
  `.logwrap`, 7 `.verbs`, **4 `.owner` root badges**, **1 `.esc` badge**, 6 `.pill` states.
- Connection box shows broker `laptop-soc1024`.
- Escalation root node visible text (the lineage, as DATA not name-parsing):
  _"cap-4b2f7ac071b0 … FS **OWNER ROOT ESCALATED ▸ APPROVED** 58m left
  fs list,read,write /tmp/capdel7-root/refs · **minted from req-e523ca46807c via
  cap-867ffb303426 (need to write summary)**"_.
- One node shows an **`expired`** pill (the 3s-TTL cap) — clear-expired target present.

**Step 2 — click the real "Clear expired" button (`02-after-clear.png`)**
- Browser navigated to `/?clear=1&key=…` (POST form submitted by the actual button).
- Flash rendered: **"Cleared 1 expired capability."**
- Pills 6 → 5; forest nodes 6 → 5; the `expired` pill is gone.
- `capdel.py audit` shows the `gc` event; the expired cap's JSON file was deleted on disk.

## Direct (Tier-1-style) corroborating checks
- `POST /_gc` with owner secret → `{"cleared":1,"ids":["cap-…"]}`; file unlinked; **401**
  without the owner secret.
- `/_tree` now exposes `escalation:{request,source_cap,reason}` + `created` on the
  approved-escalation node (previously lineage existed only inside the cap `name`).

## What I could NOT verify
I cannot visually view image files in this environment, so I verified the **rendered
structure and content** via DOM assertions (`evaluate`) and the raw HTML via `curl`,
not by eye. The two PNGs are valid, non-empty (1912×943) screenshots captured from the
live page — a human reviewer should eyeball them for visual parity with `mockup.html`.
