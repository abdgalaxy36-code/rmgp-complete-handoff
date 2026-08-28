# rmgp-complete-handoff

Complete workspace + experiment-state backup for the CVE-2026-43499 (RMGP /
"popsicle") exploit targeting **SM-A376B / Exynos S5E8845 / A376BXXU1AZB7**.

**Read `CURRENT_STATE.md` first** — it is the authoritative "where we are" note:
what works (slide, skb leak, pipe oracle, **1st KernelSnitch pass / fops page
MATCH**), what is blocked (**2nd KernelSnitch pass / pipe buffer page leak**), the
exact fix applied, the exact build/run commands, and the precise point where the
live test was stopped (`prepare_kernel_page retry 1/8`, scan frozen at
`130000/131072` in `logs/run9.log`).

## Layout
- `RMGP/` — full patched source tree (builds as-is)
- `selftest/` — `a37-final.so` (built binary), `fh.bin`, `vhash.py`, `difftest.py`
- `logs/` — full experiment record (`run2.log`..`run9.log`, `adb.0.log`, `probe2.log`)
- `reference/REFERENCE_REPOS.txt` — manifest of upstream clones (not copied)
- `ORIGINAL_RMGP_HISTORY.bundle` — full original git history (`git clone` to restore)
- `CURRENT_STATE.md` — the handoff note

## Quick start
```
export ANDROID_NDK_HOME=/tmp/opencode/ndk
CC=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android35-clang
$CC -DAPP_PAYLOAD=1 -DKS_SELFTEST -fPIC -O2 -g -Isrc \
    -DTARGET_HEADER='"targets/a37xv2-A376BXXU1AZB7/target.h"' \
    src/main.c src/util.c src/slide_app.c src/fops.c src/pipe.c src/root.c src/preload.c \
    -shared -pthread -o a37-final.so
```
