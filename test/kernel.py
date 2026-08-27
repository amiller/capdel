#!/usr/bin/env python3
"""Kernel enforcement checks for issue #8; run on the disposable Linux VM."""
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import capdel


def main():
    if sys.platform != "linux":
        print("SKIP: issue #8 needs Linux")
        return 77
    with tempfile.TemporaryDirectory(prefix="capdel-kernel-") as tmp:
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
        proc = subprocess.Popen([sys.executable, "-c", "b = bytearray(256 * 1024 * 1024)"],
                                cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        cgroup = capdel.attach_cgroup(proc.pid, {"memory_max_bytes": 32 * 1024 * 1024})
        try:
            _, stderr = proc.communicate(timeout=120)
        finally:
            cgroup.cleanup()
        assert proc.returncode == -9, (proc.returncode, stderr)
    print("PASS: Landlock denies outside-root reads, seccomp kills getpid with SIGSYS, "
          "cgroup memory_max_bytes OOM-kills an over-quota child")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
