#!/usr/bin/env python3
"""Kernel enforcement checks for issue #8; run on the disposable Linux VM."""
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import capdel


def main():
    if sys.platform != "linux":
        print("SKIP: issue #8 needs Linux")
        return 77
    scratch = sys.argv[1] if len(sys.argv) > 1 else None
    with tempfile.TemporaryDirectory(prefix="capdel-kernel-", dir=scratch) as tmp:
        root, outside = Path(tmp) / "inside", Path(tmp) / "outside"
        root.mkdir(); outside.write_text("secret\n")
        escaped = subprocess.run(
            [sys.executable, "-c", "import pathlib; print(pathlib.Path(__import__('sys').argv[1]).read_text())", str(outside)],
            cwd=root, preexec_fn=lambda: capdel.apply_kernel_limits({"cwd_root": str(root)}),
            capture_output=True, text=True)
        assert escaped.returncode != 0, escaped.stdout

        syscall = subprocess.run(
            [sys.executable, "-c", "import os; os.getpid()"], cwd=root,
            preexec_fn=lambda: capdel.apply_kernel_limits({"cwd_root": str(root), "deny_syscalls": ["getpid"]}),
            capture_output=True, text=True)
        assert syscall.returncode < 0 and -syscall.returncode == 31, syscall.returncode

        # memory_max_bytes: a child that exceeds its cgroup quota is OOM-killed (needs root)
        cgroup = capdel.prepare_cgroup({"memory_max_bytes": 32 * 1024 * 1024})
        proc = subprocess.Popen([sys.executable, "-c", "b = bytearray(256 * 1024 * 1024)"],
                                cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                preexec_fn=cgroup.attach_self)
        try:
            _, stderr = proc.communicate(timeout=120)
        finally:
            cgroup.cleanup()
        assert proc.returncode == -9, (proc.returncode, stderr)

        # disk_max_bps (issue #25): io.max only sees real block-device I/O, so the file
        # must live on a block-backed fs — /tmp is tmpfs on the VM; /var/tmp is the root
        # disk. Under a self-confined broker's exec cap (#24) both sit outside the working
        # set, so the VM rig passes a scratch dir on the same root disk instead.
        io_root = Path(tempfile.mkdtemp(prefix="capdel-io-", dir=scratch or "/var/tmp"))
        try:
            size, quota = 16 * 1024 * 1024, 4 * 1024 * 1024
            dd = ["/bin/dd", "if=/dev/zero", f"of={io_root / 'blob'}", "bs=1M",
                  f"count={size // (1024 * 1024)}", "oflag=direct"]
            t0 = time.monotonic()
            base = subprocess.Popen(dd, cwd=io_root, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, text=True)
            _, err = base.communicate(timeout=300)
            base_s = time.monotonic() - t0
            assert base.returncode == 0, (base.returncode, err)

            cgroup = capdel.prepare_cgroup({"cwd_root": str(io_root), "disk_max_bps": quota})
            t0 = time.monotonic()
            proc = subprocess.Popen(dd, cwd=io_root, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, text=True, preexec_fn=cgroup.attach_self)
            try:
                _, err = proc.communicate(timeout=300)
            finally:
                cgroup.cleanup()
            throttled_s = time.monotonic() - t0
            assert proc.returncode == 0, (proc.returncode, err)
            assert throttled_s >= size / quota - 0.5, (throttled_s, base_s)
            assert throttled_s >= 4 * base_s, (throttled_s, base_s)
        finally:
            import shutil; shutil.rmtree(io_root, ignore_errors=True)
    print("PASS: Landlock denies outside-root reads, seccomp kills getpid with SIGSYS, "
          "cgroup memory_max_bytes OOM-kills an over-quota child, "
          "cgroup io.max throttles an over-quota disk write")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
