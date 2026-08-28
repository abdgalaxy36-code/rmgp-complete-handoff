# A37 EXPLOIT — FULL SESSION HANDOFF (read first in new chat)
Device: SM-A376B, Exynos S5E8845, firmware A376BXXU1AZB7 (declined update AZG4),
kernel 6.1.138-android14-11, VA_BITS=39, PAGE_SIZE=4K, RANDOMIZE_BASE=y,
NR_CPUS=32/possible=0-7 but sysconf=16, RAM ~7.5G phys@0x80000000.
adb: `adb connect 127.0.0.1:5555` or user-provided wifi port; transport may
appear as emulator-5554. Termux python (/data/data/com.termux/files/usr/bin/
python3) has lz4; proot python3 doesn't.

## GOAL
Root via CVE-2026-43499 (RMGP repo at /tmp/opencode/RMGP). Build:
ANDROID_NDK_HOME=/tmp/opencode/ndk CC=.../aarch64-linux-android35-clang
$CC -DAPP_PAYLOAD=1 -fPIC -O2 -g -Isrc -DTARGET_HEADER='"targets/a37xv2-A376BXXU1AZB7/target.h"' src/main.c src/util.c src/slide_app.c src/fops.c src/pipe.c src/root.c src/preload.c -shared -pthread -o out.so

## RUN CMD (shell mode)
env SLIDE_SOURCE=tracefs EXPLOIT_ATTEMPTS=1 P0_ATTEMPT_TIMEOUT_SEC=400 \
 EXPLOIT_ATTEMPT_TIMEOUT_SEC=1500 /data/local/tmp/v2root --run-payload \
 /data/local/tmp/a37-final.so /data/local/tmp/v2root /path/log
NO sleep commands (user rule). Fresh reboot helps stage-2 pass odds.

## CHAIN STATUS
1 slide(tracefs) ✅ reliable | 2 skb-leak ✅ FIXED today (~20% pass) |
3 pipe-oracle ✅ | 4 kernel-page ❓ converges historically(obj_idx=7/24) but
post-fix unobserved | 5-7 writer→fops→root ⏸ blocked; writer mechanism proven
(pselect success=1 in Aug logs).

## TODAY'S FIXES (all in src/, built binary = /tmp/cve-slide.so = a37-final.so)
1. futex_hash replica EXACT: kernelsnitch/futex_hash.h — kernel uses FIVE-word
   jenkins chain const K=0xdeadbeff (NOT 0xdeadbeef!, NOT jhash2+offset-seed).
   Verified vs machine code via on-device harness + python emu (vhash.py/difftest.py).
2. MM_STRUCT_SZ=0x400 (slabinfo truth: objsize 1024, 32/slab, order3). BTF struct
   is 960 but SLUB cache stride is 1024 — engine default was right.
3. TOP-K collision selection in kernelsnitch_find_collisions (collect all
   confirmed>thr, pick slowest `wanted`) replaces first-come quota.
4. KS_SELFTEST infra (compile flag) comparing __futex_hash vs embedded patched
   kernel blob ks_kern_ref (blob=/tmp/fh.bin from futex_hash @file off 0x19f58c,
   patches: nop@7c, movz w10,#size@c0, nop@cc, mov w0,w8@dc).
5. Engine guard fixes: slide_app.c SYNC_PSELECT log line + slot-trigger region
   guards widened to DATA_ALIAS_DIAG_ONLY; util.c fops_data_probe_addr def guard;
   util.c verbose wiring in non-FRESH setup; unconditional KSDIAG timing dump.
6. VA39 WINDOWS (LATEST): IDENTITY/DIRECT_MAP/P0_PAGE_OFFSET → 0xffffffc000000000
   base, END 0xffffffc200000000; VMEMMAP_START≈0xffffffe400000000 (verify);
   + NEW runtime slide-shift: global ks_slide_delta (util.c def; set at all 4
   kaslr_slide assignment sites in slide.c/slide_app.c; extern in kernelsnitch.h)
   added to bruteforce #else range.start/end. RATIONALE: VA39 confirmed via
   ubfx x0,#30,#9 in vmemmap_populate_address; RANDOMIZE_BASE=y slides linear
   per boot ⇒ windows must be slide-derived: linear_base=0xffffffc000000000+slide.
   Old "mm leaked ffffff80/8d..." hits = FALSE POSITIVES (broken hash inside
   wrong 48-bit windows) — GIGO, do not trust as layout evidence.

## REMAINING BLOCKER (exact)
skb-leak still fails most runs (~20% pass). When it passes, mm-stage retries
never observed completing post-all-fixes (crash #8 hit during stage-4 timing).
CRASH LEAD: panics occurred during kernelsnitch TIMING phase even at pile=64 ⇒
suspect prior-stage corruption OR Samsung futex-path bug under pile pattern.
NEXT: audit stages2-3 write landings (find_pipe_buffer VMEMMAP window now
0xffffffe4... needs validation!) BEFORE more runs; then P0_ONLY probe expecting
mm leaked INSIDE 0xffffffc0..+slide region = honest convergence proof.

## KEY FILES
targets/a37xv2-A376BXXU1AZB7/{target.h,p0_fingerprint.h} (v2 prod profile)
NEXT_SESSION_PROTOCOL.md (VA39 audit steps 1-8 + evidence)
tools: /tmp/fh.bin (kernel hash bytes), /tmp/harness5.c (on-device oracle),
/tmp/vhash.py difftest.py symexec.py, /tmp/cbri.asm gfk.asm futex_hash.asm
(configfs read/get_futex_key disasm), /sdcard/Download/CVE-43499.zip (S25 v4 kit)
Historic evidence logs: Download/RootMyGalaxy-*failed*.log.txt (Aug app-era,
label a37-A376BXXS4AZG4-root-umh slide=pselect — OLD build w/ different offsets!)

## USER PREFS
No sleep cmds. Announce findings immediately. No device changes without stating
them. Don't treat grinding as solution — fix root causes offline first. User
offers research help when given precise technical asks.
