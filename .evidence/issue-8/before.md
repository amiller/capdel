# Issue #8 — kernel-backed exec confinement, BEFORE (main, userspace-only) transcript

Broker: `http://127.0.0.1:4571` (disposable VM, `test/cloud-init.yaml`); fixture: `/srv/demo/work/root/leak` → `../../vault/secret.txt`, plus a `..` traversal argv.

`GET /_api/version` → `{'server': 'capdel/0.1', 'commit': '3acc82d', 'pop_mode': 'off', 'schemes': ['bearer', 'capdel-hmac-sha256']}`

## exec cap scoped to the root, indirect outside reads

```$ capdel mint exec --allow cat --cwd-root /srv/demo/work/root   →  id=cap-53f905220e13 token=ct-…```

$ POST /caps/cap-53f905220e13/invoke {"argv": ["cat", "leak"]} → HTTP 200 ```json
{
  "code": 0,
  "stdout": "TOP-SECRET-capdel-8\n",
  "stderr": "",
  "truncated": false
}
```
> **symlink read `cat leak`: BYPASSES userspace check (stdout carries the secret)**: ✓
$ POST /caps/cap-53f905220e13/invoke {"argv": ["cat", "../../vault/secret.txt"]} → HTTP 200 ```json
{
  "code": 0,
  "stdout": "TOP-SECRET-capdel-8\n",
  "stderr": "",
  "truncated": false
}
```
> **dotdot read `cat ../../vault/secret.txt`: BYPASSES userspace check (stdout carries the secret)**: ✓

**ALL CHECKS PASS**

