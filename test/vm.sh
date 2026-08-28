#!/usr/bin/env bash
# Tier 3 (issue #9): boot the disposable owner-host VM under qemu/KVM and verify exec
# capabilities against a REAL kernel — the thing containers cannot provide (they share
# the host kernel; the zed host kernel has no Landlock in its LSM list, so exec caps
# fail loudly there by design).
#
#   bash test/vm.sh [branch]     # branch defaults to the current one; must be pushed
#
# What it proves, host-side over the forwarded broker port:
#   1. /_api/version == the pushed branch's commit (pinned via CAPDEL_COMMIT: the VM broker
#      is self-confined (#24), so its `git rev-parse` fallback cannot read $HOME/.gitconfig)
#   2. an allowlisted exec runs                                  (policy + kernel OK)
#   3. a non-allowlisted exec is denied                          (policy)
#   4. ls /etc FAILS under the sandbox although `ls` IS allowlisted  (Landlock, not policy)
#   5. a broker-side read of a root OUTSIDE the broker's working set is kernel-denied (#24)
#   6. a working-set root still reads through the same broker      (#24 control)
#   7. an exec child syscall outside the broker allowlist dies with SIGSYS (#24 seccomp floor)
set -euo pipefail

cd "$(dirname "$0")/.."          # repo root
BRANCH="${1:-$(git rev-parse --abbrev-ref HEAD)}"
SHA="$(git rev-parse --short "origin/$BRANCH")" ||
  { echo "vm.sh: origin/$BRANCH not found — push the branch first"; exit 2; }
OWNER_SECRET="change-me-disposable-vm-secret"     # matches test/cloud-init.yaml; localhost-forwarded disposable VM
WORK="$(mktemp -d /tmp/capdel-vm-XXXX)"
IMG_CACHE=/tmp/noble-server-cloudimg-amd64.img
PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')

for t in qemu-system-x86_64 genisoimage; do
  command -v "$t" >/dev/null || { echo "vm.sh: $t not installed"; exit 2; }
done
[ -w /dev/kvm ] || { echo "vm.sh: /dev/kvm not writable — no KVM, VM boot would be glacial"; exit 2; }

echo "== vm: target branch ${BRANCH} @ ${SHA}"
if [ ! -f "$IMG_CACHE" ]; then
  echo "== vm: downloading noble cloud image (cached at $IMG_CACHE)"
  curl -fL --retry 3 -o "$IMG_CACHE" \
    https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img
fi

echo "== vm: building cloud-init seed (clone branch: ${BRANCH})"
sed -e "s/-b main /-b ${BRANCH} /" \
    -e "s/^\( *\)CAPDEL_HOME=/\1CAPDEL_COMMIT=${SHA}\n\1CAPDEL_HOME=/" test/cloud-init.yaml > "$WORK/user-data"
printf 'instance-id: capdel-vm-%s\nlocal-hostname: capdelvm\n' "$(date +%s)" > "$WORK/meta-data"
genisoimage -quiet -output "$WORK/seed.iso" -volid CIDATA -joliet -rock "$WORK/user-data" "$WORK/meta-data"

echo "== vm: booting (KVM, broker forwarded to 127.0.0.1:${PORT}; first boot runs cloud-init)"
qemu-system-x86_64 -enable-kvm -cpu host -m 2048 -smp 2 -display none -daemonize \
  -pidfile "$WORK/qemu.pid" -snapshot \
  -drive "file=$IMG_CACHE,if=virtio" \
  -drive "file=$WORK/seed.iso,format=raw,if=virtio,readonly=on" \
  -netdev "user,id=n0,hostfwd=tcp:127.0.0.1:${PORT}-:4571" -device virtio-net-pci,netdev=n0

cleanup() { [ -f "$WORK/qemu.pid" ] && kill "$(cat "$WORK/qemu.pid")" 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup EXIT

python3 - "$PORT" "$SHA" "$OWNER_SECRET" <<'EOF'
import json, sys, time, urllib.request, urllib.error

port, sha, owner = sys.argv[1], sys.argv[2], sys.argv[3]
base = f"http://127.0.0.1:{port}"

def http(method, path, token=None, body=None):
    req = urllib.request.Request(base + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None)
    if token: req.add_header("Authorization", f"Bearer {token}")
    if body is not None: req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())

# cloud-init: apt update + git install + clone + systemd unit — give it real time.
print(f"   waiting for the VM broker (cloud-init boot, up to 15 min)…", flush=True)
for i in range(450):
    try:
        s, d = http("GET", "/_api/version")
        if s == 200:
            break
    except (urllib.error.URLError, OSError):
        pass
    time.sleep(2)
else:
    sys.exit("vm broker never came up")

checks = []
checks.append(("version pin: VM broker serves the branch commit",
               d.get("commit") == sha, d))
s, d = http("POST", "/_mint", owner, {"type": "exec",
             "constraints": {"allow": [["ls"], ["cat"]], "cwd_root": "/srv/demo"},
             "name": "vm-exec", "ttl_s": 1800})
assert s == 200 and d.get("token"), f"mint exec -> {s} {d}"
tok, cap = d["token"], d["id"]

def run(argv):
    return http("POST", f"/caps/{cap}/invoke", tok, {"op": "run", "argv": argv})

s, d = run(["ls", "/srv/demo"])
checks.append(("allowlisted `ls /srv/demo` runs (kernel confinement engages)",
               s == 200 and d.get("code") == 0, d))
s, d = run(["rm", "-rf", "/srv/demo"])
checks.append(("non-allowlisted `rm -rf` denied by policy", s == 403, d.get("violated", d)))
s, d = run(["ls", "/etc"])
# THE kernel-tier check: policy allows `ls`, Landlock must still block the read of /etc.
checks.append(("`ls /etc` allowed by policy but FAILS under Landlock (real-kernel proof)",
               s == 200 and d.get("code") != 0, {"code": d.get("code"), "stderr": (d.get("stderr") or "")[:120]}))
s, d = http("GET", "/whoami", tok)
checks.append(("GET /whoami self-description from token only", s == 200 and d.get("id") == cap, d))

# --- broker self-confinement (#24): the broker process itself, not the exec child ---------
s, d = http("POST", "/_mint", owner, {"type": "fs",
             "constraints": {"root": "/root/leak-root", "ops": ["read"]},
             "name": "vm-outside-read", "ttl_s": 1800})
assert s == 200 and d.get("token"), f"mint outside fs -> {s} {d}"
outside_tok, outside_cap = d["token"], d["id"]
s, d = http("POST", f"/caps/{outside_cap}/invoke", outside_tok,
            {"op": "read", "path": "/root/leak-root/leak.txt"})
# policy is fine (path IS inside the granted root) — the KERNEL must refuse the broker's open
checks.append(("broker-side read outside the working set is kernel-denied (EACCES, not a policy 403)",
               s == 404 and "Permission denied" in d.get("error", ""), d))
s, d = http("POST", "/_mint", owner, {"type": "fs",
             "constraints": {"root": "/srv/demo/pub", "ops": ["read"]},
             "name": "vm-inside-read", "ttl_s": 1800})
assert s == 200 and d.get("token"), f"mint inside fs -> {s} {d}"
s, d = http("POST", f"/caps/{d['id']}/invoke", d["token"],
            {"op": "read", "path": "/srv/demo/pub/readme.txt"})
checks.append(("working-set root reads fine through the same broker (control)",
               s == 200 and d.get("content", "").strip() == "public note", d))
s, d = http("POST", "/_mint", owner, {"type": "exec",
             "constraints": {"allow": [["python3"]], "cwd_root": "/srv/demo/work"},
             "name": "vm-syscall-floor", "ttl_s": 1800})
assert s == 200 and d.get("token"), f"mint floor exec -> {s} {d}"
s, d = http("POST", f"/caps/{d['id']}/invoke", d["token"],
            {"op": "run", "argv": ["python3", "-c",
             "import ctypes; ctypes.CDLL(None).syscall(101, 0, 0, 0)"]})
checks.append(("exec child syscall outside the broker allowlist dies with SIGSYS (code -31)",
               s == 200 and d.get("code") == -31, d))

failed = 0
print(f"\n  vm checks — {len(checks)}\n  " + "-" * 60)
for name, ok, detail in checks:
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    if not ok:
        print(f"         detail: {detail}")
        failed += 1
print("  " + "-" * 60)
sys.exit(1 if failed else 0)
EOF
echo "== vm: all green"
