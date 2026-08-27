# Issue #8 — kernel-backed exec confinement, AFTER (this PR) transcript

Broker: `http://127.0.0.1:4571` (disposable VM, `test/cloud-init.yaml`); fixture: `/srv/demo/work/root/leak` → `../../vault/secret.txt`, plus a `..` traversal argv.

`GET /_api/version` → `{'server': 'capdel/0.1', 'commit': '7c1bfde', 'pop_mode': 'off', 'schemes': ['bearer', 'capdel-hmac-sha256']}`

## exec cap scoped to the root, indirect outside reads

```$ capdel mint exec --allow cat --cwd-root /srv/demo/work/root   →  id=cap-5b89fb7748f9 token=ct-…```

$ POST /caps/cap-5b89fb7748f9/invoke {"argv": ["cat", "leak"]} → HTTP 200 ```json
{
  "code": 1,
  "stdout": "",
  "stderr": "cat: leak: Permission denied\n",
  "truncated": false
}
```
> **symlink read `cat leak`: kernel-denied (nonzero code, no secret in stdout)**: ✓
$ POST /caps/cap-5b89fb7748f9/invoke {"argv": ["cat", "../../vault/secret.txt"]} → HTTP 200 ```json
{
  "code": 1,
  "stdout": "",
  "stderr": "cat: ../../vault/secret.txt: Permission denied\n",
  "truncated": false
}
```
> **dotdot read `cat ../../vault/secret.txt`: kernel-denied (nonzero code, no secret in stdout)**: ✓

## seccomp: denied syscall terminates with SIGSYS

$ capdel mint exec --allow python3 --deny-syscall getpid … → id=cap-09a5aa9935f0
$ POST /caps/cap-09a5aa9935f0/invoke argv=["python3","-c","import os; os.getpid()"] → HTTP 200 ```json
{
  "code": -31,
  "stdout": "",
  "stderr": "",
  "truncated": false
}
```
> **getpid denied → SIGSYS (code -31)**: ✓

## cgroups: memory_max_bytes exceeded → child OOM-killed

$ capdel mint exec --allow python3 --memory-max-bytes 33554432 … → id=cap-aaa2c030a9ce
$ POST /caps/cap-aaa2c030a9ce/invoke argv=["python3","-c","b = bytearray(256 * 1024 * 1024); print(len(b))"] → HTTP 200 ```json
{
  "code": -9,
  "stdout": "",
  "stderr": "",
  "truncated": false
}
```
> **256 MiB alloc under a 32 MiB cap → OOM kill (code -9)**: ✓

## test/kernel.py on this VM

```$ sudo python3 /opt/capdel/test/kernel.py  (exit 0)
PASS: Landlock denies outside-root reads, seccomp kills getpid with SIGSYS, cgroup memory_max_bytes OOM-kills an over-quota child

```
> **test/kernel.py exits 0**: ✓

**ALL CHECKS PASS**

