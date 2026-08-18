# AuthBench → capdel mapping

AuthBench describes the gold boundary as file-level `read`, `write`, and `execute`
permissions. capdel has three capability types, so the adapter keeps the file axes
separate and makes the lossy execute conversion explicit.

## File axes

For each AuthBench `read` or `write` path, the adapter groups paths by the narrowest
common directory and mints an `fs` capability with the corresponding operation. An
exact file is represented by its containing directory; the worker still sends the
file path in the brokered invoke request. `read` and `write` are never combined unless
both are present in the generated policy for that root. `scored_roots` and
`implicit_permissions` remain AuthBench scoring metadata, not authority grants.

Examples:

```text
AuthBench read  /app/input.txt       -> fs(root=/app, ops=[read])
AuthBench write /app/output.json     -> fs(root=/app, ops=[write])
AuthBench read  /data/raw/input.csv  -> fs(root=/data/raw, ops=[read])
```

The adapter must not widen a path to `/` merely because two paths have different
parents. When there is no useful shared directory, it emits one capability per
containing directory. A generated directory grant is therefore an intentional
over-approximation and is included in tightness scoring.

## Execute axis (lossy)

AuthBench's execute entries are filesystem paths such as `/usr/bin/python3`; capdel's
`exec` capability is an argv-prefix allowlist, such as `python3` or `python3 -m
pytest`, plus an optional `cwd-root`. The adapter maps the executable basename to an
argv prefix and records the source path in the result. This loses:

- the distinction between two binaries with the same basename;
- interpreter arguments and module-level restrictions when AuthBench gives only a
  binary path;
- the exact filesystem identity of the executable (PATH lookup may select another
  binary);
- shell/script interpreter relationships.

Consequently execute scores are reported separately and an execute mapping is never
claimed equivalent to AuthBench's file-level execute permission. The safe default is
to reject an unmappable path and report it as an adapter loss, rather than minting an
unbounded `exec` grant.

## Escalation experiment

The harness first mints only the generated caps. A worker probes the task's required
file operations through the capdel broker. A denied required operation creates an
owner-visible escalation request; the owner may approve the exact missing operation,
which yields a fresh capability. The result records whether the task reached full
sufficiency after zero, one, or two approved escalations. The original token is
checked again to ensure approval did not widen it.

This is the capdel-specific recovery measure: compare first-draft sufficiency with
post-approval sufficiency while keeping the generated policy's tightness and
sensitive exposure in the same result record.
