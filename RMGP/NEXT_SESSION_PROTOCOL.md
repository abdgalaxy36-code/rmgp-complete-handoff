# VA39 AUDIT PROTOCOL (user-directed, execute in order)
1. CONFIG_ARM64_VA_BITS=39 = GROUND TRUTH.
2. Audit ALL VA-dependent constants: VMEMMAP_START/END, DIRECT_MAP_BASE/END,
   P0_PAGE_OFFSET, P0_PHYS_OFFSET, page-pointer windows/masks in find_pipe_buffer
   & kernelsnitch identity ranges.
3. For each: compare profile value vs actual A37 kernel/disasm; document expected VA39 range.
4. Add non-destructive diagnostic at page-identification boundary: WHY candidate
   accepted/rejected + whether fallback path taken.
5. FALLBACK MUST NOT PERFORM KERNEL WRITES during validation.
6. Smallest test through page-identification; verify selected address is a legit
   page BEFORE proceeding.
7. Only then re-run Stage 2-3; check futex panics disappear.
8. PRESERVE known-good mm_struct convergence results; don't touch unless audit proves affected.

KEY QUESTION TO PROVE FIRST: "Is the VA39 mismatch causing garbage page selection
and subsequent corruption?" — prove with instrumentation before changing constants.

## Evidence so far
- CONFIG_ARM64_VA_BITS=39 (from /proc/config.gz)
- Profile has VMEMMAP_START=0xfffffffe00000000 (48-bit layout value)
- Crash localized: stage-4 kernelsnitch collision measurement (pure timing phase)
- find_pipe_buffer rejects real page pointers outside wrong window → fallback branch
- Known-good: mm leaked=ffffff8d1d552300 obj_idx=7 & ffffff80694cf800 obj_idx=24
  (implies linear/direct-map at 0xffffff80... IS valid despite VA39 — RESOLVE THIS
  CONTRADICTION FIRST: derive true vmemmap base from kernel disasm/BTF, not docs)

## DERIVATION PROGRESS (offline)
Symbols located: memstart_addr@0x977c840, kimage_vaddr@0x977c8e0,
swapper_pg_dir@0x9e1a000, paging_init@0x9e2ad58.
paging_init builds fixmap addr: movz 0x703 | movk #0x68 lsl48 => 0x0068_0000_0000_0703
(early-fixmap style, KASLR-selectable +0x800 variant) -- NOT final VMEMMAP.
NEXT: disasm paging_init continuation (after first __set_fixmap) where it maps
swapper via clear_fixmap then sets memstart_addr & calls bootmem_init;
also read kimage_vaddr VALUE at runtime impossible offline -> derive from
Image header / rel relocations instead. Then compute VA39 constants:
expected (arm64 memory.h, 39bit/4K): PAGE_OFFSET=0xffffffc000000000,
VMALLOC=0ffffffa..., VMEMMAP=ffffffd400000000..dc. CONTRADICTION TO RESOLVE:
observed mm leaked ffffff8d1d552300 lies OUTSIDE those ranges => either
Samsung uses custom region split or leaked value is NOT direct-map
(check what 'base=' prints: it printed base=ffffff8d1d550000 alongside --
both in same region => likely TRUE linear map start differs per Samsung:
derive definitively from swapper_pg_dir walk next session).

## RESOLVED (announced finding)
ubfx x9,x0,#30,#9 in vmemmap_populate_address => 39-bit VA, 3-level CONFIRMED.
True layout (VA39/4K): linear=0xffffffc000000000, vmemmap≈0xffffffe4...
Historic "mm leaked ffffff80/8d..." = FALSE POSITIVES from broken-hash search
inside wrong 48-bit-style windows. GIGO resolved.
NEXT SESSION TASKS:
1. Rebuild kernelsnitch identity windows: linear 0xffffffc000000000..+RAM(8G)
   => END ≈ 0xffffffc200000000. Set via target.h IDENTITY_*, KSNITCH windows,
   DIRECT_MAP_BASE/END, P0_PAGE_OFFSET=0xffffffc000000000.
2. Derive memstart_addr runtime value (kimage_voffset path) for phys<->virt math.
3. Re-audit vmemmap window for find_pipe_buffer (VMEMMAP_START≈0xffffffe400...).
4. Then minimal P0_ONLY probe → expect REAL convergence at true addresses.

## CRASH #8 (VA39 first run)
Crash occurred DURING first VA39-windowed run — before any mm-leak verdict.
Implication: corrected windows point at TRUE linear map; timing scan there may
interact with LIVE kernel objects (unlike old dead-region windows). OR prior-
stage shaping writes land differently than assumed. EITHER WAY: no more runs
until offline completion of: memstart_addr derivation + stages 2-3 write-target
audit vs true layout.
