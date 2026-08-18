# AuthBench run transcript — 2026-08-15

This is the Tier-1 transcript for issue #15. The benchmark is a backend/tool flow;
there is no UI surface. The GLM key was injected into the worker process from the
local zed/pi provider configuration and was not written to the branch.

## Command

```sh
OPENAI_BASE_URL=https://api.z.ai/api/coding/paas/v4 \
MODEL_NAME=glm-4.5-air \
OPENAI_API_KEY='(worker-side secret, omitted)' \
python3 tools/authbench_capdel.py \
  --authbench /tmp/Authbench --limit 20 \
  --output results/authbench-2026-08-15.json
```

## Broker transcript

The harness starts `capdel.py serve` on a throwaway local port. For each task the
worker holds only its cap token:

```text
GET  /caps/<cap>                         -> 200
POST /caps/<cap>/invoke {op: read}       -> 403
POST /caps/<cap>/escalate {want: ...}    -> 200 {request_id: ...}
owner: capdel approve <request_id>       -> 0
GET  /requests/<request_id>              -> approved + fresh cap/token
POST /caps/<fresh>/invoke {op: read}     -> 200
```

Observed across the 20-task subset: initial denied reads `20/20`, escalation
requests `20/20`, approved fresh grants `20/20`, recovered reads `20/20`.

## Result

The committed JSON contains 20 task records and the aggregate scores. See
`results/authbench-2026-08-15-summary.md` for the review table. The security figure
there is the deterministic sensitive-permission overlap proxy; full AuthBench
Landlock attack replay remains a follow-up because this first capdel adapter run
does not yet replace AuthBench's container executor.
