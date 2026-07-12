# PLAN — issue #7: Live dashboard should match the mockup; add clear-expired + escalation-grant lineage

Derived `## Acceptance` (the issue body has no `## Acceptance` header; restating its three
concrete deliverables as the done-conditions):

1. **Mockup styling on the live dashboard** — the real `/` dashboard (rendered by
   `pod/relay.ts` `renderDashboard`) uses the polished CSS/structure of
   `pod/public/mockup.html` (brand header + live connection, "At a glance" stat tiles,
   forest view, styled recent-calls table). A live session looks like the mockup.
2. **clear-expired sweep** — expired capabilities can be purged (they currently pile up
   until TTL and linger as dead files). A broker `gc` removes expired cap files; the
   dashboard has a "Clear expired" action that runs it through the tunnel; gone caps
   disappear from the tree.
3. **escalation-grant lineage as data** — an approved escalation records which request and
   which source cap (and reason) minted it; the dashboard renders that lineage as a badge
   + text instead of only encoding it in the cap name.

## Tasks
- [ ] A. `capdel.py`: record `escalation` provenance on `cmd_approve`; expose `escalation`
      + `created` in `tree_data`.
- [ ] B. `capdel.py`: add `gc_expired()` + owner-gated `POST /_gc` + CLI `capdel gc`.
- [ ] C. `pod/relay.ts`: restyle `renderDashboard`/`renderNode` with the mockup CSS +
      real-data structure (stats tiles, forest, table).
- [ ] D. `pod/relay.ts`: render escalation lineage (badge + "minted from req-… via cap-…").
- [ ] E. `pod/relay.ts`: "Clear expired" control → forwards `POST /_gc` through the tunnel;
      flash the count; re-read tree.
- [ ] Verify parse: `python3.11 -m py_compile capdel.py`; `deno check pod/relay.ts`.
- [ ] Verify Tier 2 (user-visible): run broker + relay + tunnel locally with python3.11;
      mint caps, escalate + approve (→ lineage), let one expire, drive the live dashboard
      through the zed browser bridge, assert the acceptance content, screenshot; click
      "Clear expired", assert the expired cap is gone. Save `.evidence/issue-7/`.
- [ ] Commit, push `ready-7`, open PR vs `main`, embed evidence, remove `ready` label.

## Tier
Tier 2 — user-visible dashboard change. Evidence = walked live dashboard screenshots +
asserted acceptance content, committed to the branch.
