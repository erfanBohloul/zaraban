# Issue 2: ASan crashes with a plain segfault on stack bugs

**Symptom**

`scripts/verify_env.sh` fails "ASan reports stack-buffer-overflow" with
`exit status 139` and no ASan report. Heap bugs (use-after-free) are still
reported correctly. `tests/test_runner.py::test_target_asan_crash_detection`
fails for the same reason.

**Cause**

Newer Linux kernels use stronger address randomization
(`vm.mmap_rnd_bits=32`). The program's stack can then be placed where clang
14's AddressSanitizer (Ubuntu 22.04) does not expect it, so ASan itself
crashes instead of reporting the error. This is a setting of the **host**
kernel, not of the container or our code.

**Fix (on the host, not in Docker)**

1. Check: `cat /proc/sys/vm/mmap_rnd_bits`. If it prints `32`, apply the fix.
2. Fix now:
   ```bash
   sudo sysctl vm.mmap_rnd_bits=28
   ```
3. Keep it after reboot:
   ```bash
   echo 'vm.mmap_rnd_bits=28' | sudo tee /etc/sysctl.d/99-asan.conf
   ```
4. Rerun `docker compose run --rm zaraban bash scripts/verify_env.sh`.

In CI, add `sudo sysctl vm.mmap_rnd_bits=28` as a step before the tests.
