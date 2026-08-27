# issue #9 evidence — tier 3 (disposable VM, qemu/KVM, noble 24.04, kernel 6.8)

```
$ bash test/vm.sh ready-9
== vm: target branch ready-9 @ 6bd598c
== vm: building cloud-init seed (clone branch: ready-9)
== vm: booting (KVM, broker forwarded to 127.0.0.1:50347; first boot runs cloud-init)
   waiting for the VM broker (cloud-init boot, up to 15 min)…

  vm checks — 5
  ------------------------------------------------------------
  [PASS] version pin: VM broker serves the branch commit
  [PASS] allowlisted `ls /srv/demo` runs (kernel confinement engages)
  [PASS] non-allowlisted `rm -rf` denied by policy
  [PASS] `ls /etc` allowed by policy but FAILS under Landlock (real-kernel proof)
  [PASS] GET /whoami self-description from token only
  ------------------------------------------------------------
== vm: all green
exit=0
```
