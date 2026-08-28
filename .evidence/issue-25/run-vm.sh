#!/usr/bin/env bash
# Issue #25: boot the disposable VM on a pushed branch and run .evidence/issue-25/capture.py
# through an exec capability — every probe is black-box HTTP against the live broker.
# Modeled on test/vm.sh (same cloud-init seed, same forwarded broker port).
#   bash .evidence/issue-25/run-vm.sh [branch]     # branch defaults to ready-25; must be pushed
set -euo pipefail

cd "$(dirname "$0")/../.."
BRANCH="${1:-ready-25}"
SHA="$(git rev-parse --short "origin/$BRANCH")" ||
  { echo "run-vm.sh: origin/$BRANCH not found — push the branch first"; exit 2; }
OWNER_SECRET="change-me-disposable-vm-secret"     # matches test/cloud-init.yaml; disposable VM
WORK="$(mktemp -d /tmp/capdel-vm-25-XXXX)"
IMG_CACHE=/tmp/noble-server-cloudimg-amd64.img
PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')

for t in qemu-system-x86_64 genisoimage; do
  command -v "$t" >/dev/null || { echo "run-vm.sh: $t not installed"; exit 2; }
done
[ -w /dev/kvm ] || { echo "run-vm.sh: /dev/kvm not writable — no KVM, VM boot would be glacial"; exit 2; }

echo "== vm: target branch ${BRANCH} @ ${SHA}"
if [ ! -f "$IMG_CACHE" ]; then
  curl -fL --retry 3 -o "$IMG_CACHE" \
    https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img
fi

echo "== vm: building cloud-init seed (clone branch: ${BRANCH})"
sed "s/-b main /-b ${BRANCH} /" test/cloud-init.yaml > "$WORK/user-data"
printf 'instance-id: capdel-vm-25-%s\nlocal-hostname: capdelvm\n' "$(date +%s)" > "$WORK/meta-data"
genisoimage -quiet -output "$WORK/seed.iso" -volid CIDATA -joliet -rock "$WORK/user-data" "$WORK/meta-data"

echo "== vm: booting (KVM, broker forwarded to 127.0.0.1:${PORT})"
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
        with urllib.request.urlopen(req, timeout=900) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())

print("   waiting for the VM broker (cloud-init boot, up to 15 min)…", flush=True)
for _ in range(450):
    try:
        s, d = http("GET", "/_api/version")
        if s == 200: break
    except (urllib.error.URLError, OSError):
        pass
    time.sleep(2)
else:
    sys.exit("vm broker never came up")
assert d.get("commit") == sha, f"vm serves {d.get('commit')}, expected {sha}"
print(f"   vm broker up, commit pinned: {d['commit']}")

# one runner cap: capture.py does the rest from inside the VM, black-box HTTP only
s, d = http("POST", "/_mint", owner, {"type": "exec",
          "constraints": {"allow": [["python3"]], "cwd_root": "/", "timeout_s": 900},
          "name": "issue-25 capture runner", "ttl_s": 1800})
assert s == 200 and d.get("token"), f"mint runner -> {s} {d}"
s, d = http("POST", f"/caps/{d['id']}/invoke", d["token"],
            {"op": "run", "argv": ["python3", ".evidence/issue-25/capture.py"], "cwd": "/opt/capdel"})
print(d.get("stdout", "") or d, end="")
sys.exit(0 if (s == 200 and d.get("code") == 0 and "CAPTURE-OK" in d.get("stdout", "")) else 1)
EOF
echo "== vm: capture green"
