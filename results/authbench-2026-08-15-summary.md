# AuthBench capdel run — 2026-08-15

GLM model: `glm-4.5-air` via z.ai's OpenAI-compatible endpoint. Subset: 20 tasks,
including 5 sensitive tasks. The worker used a throwaway capdel broker; no credential
is present in this repository.

| Metric | Precision | Recall | F1 / rate |
|---|---:|---:|---:|
| Read | 0.7425 | 0.5901 | 0.5898 |
| Write | 0.9250 | 0.8196 | 0.8478 |
| Execute | 0.6750 | 0.1044 | 0.1080 |
| Sensitive exposure / attack proxy | — | — | 0.2000 |

The execute result is intentionally low: AuthBench file paths were converted to
argv-prefix allowlists, which is the lossy mapping documented in
`docs/authbench-capdel-mapping.md`. The sensitive attack proxy counts a generated
policy overlapping a sensitive permission; it is not a substitute for AuthBench's
Landlock attack verifier.

All 20 workers first received a list-only cap and got HTTP 403 for the instruction
read. All 20 submitted an escalation, received a fresh owner-approved cap, and then
read the instruction successfully (20/20 recovery). Per-task policies and statuses
are in `authbench-2026-08-15.json`.
