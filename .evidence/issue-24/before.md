# Issue #24 — broker self-confinement, BEFORE (plain broker) transcript

Rig: disposable Linux VM booted from `test/cloud-init.yaml` (Ubuntu 24.04, kernel
6.8.0-138-generic, Landlock present), branch `ready-24`, generated on the VM by
`.evidence/issue-24/capture.py`. Two brokers serve the SAME throwaway state with the
SAME caps (minted by the unconfined owner CLI); this file is the plain broker —
main's behavior, the blast radius self-confinement exists to bound.

$ capdel mint fs --root …/inside / fs --root …/outside / exec python3 --cwd-root …/inside
   (owner CLI, an unconfined process; identical grants for both brokers)

## plain broker (no --self-confinement): http://127.0.0.1:50799

`GET /_api/version` → 200 `{"server": "capdel/0.1", "commit": "aabaaf2", "pop_mode": "off", "schemes": ["bearer", "capdel-hmac-sha256"]}`
$ POST /caps/cap-8fbc16bc2ddb/invoke read (root INSIDE the working set) → HTTP 200 `{"content": "inside value\n", "offset": 0, "bytes": 13}`
$ POST /caps/cap-aa0368249179/invoke read (root OUTSIDE the working set) → HTTP 200 `{"content": "TOP-SECRET-capdel-24\n", "offset": 0, "bytes": 21}`
$ POST /caps/cap-f1b5d09fb275/invoke exec python3 ptrace(101) (on no deny list) → HTTP 200 `{"code": 0, "stdout": "", "stderr": "", "truncated": false}`

> **outside-root read LEAKS the secret**: the grant is the only barrier; any broker bug
> with the same reach reads the owner's machine. ✓ (this is the "before")
> **ptrace runs (code 0)**: no syscall floor exists on a plain broker. ✓
