# VA39 WRITE-LANDING AUDIT — COMPLETE (2026-08-27)

Date: 2026-08-27. Status: COMPLETE — all findings documented, code NOT patched.

## Summary
Comprehensive audit of SM-A376B VA layout completed. Discovered kernel uses
40-bit VA at runtime despite compile config saying 39-bit. Samsung modifies
TCR_EL1.T1SZ at boot.

## Key Findings
1. PAGE_OFFSET = 0xffffff8000000000 (not 0xffffffc000000000)
2. DIRECT_MAP_BASE = 0xffffff8000000000
3. DIRECT_MAP_END = 0xffffff8300000000 (12GB RAM)
4. VMEMMAP_START = needs device verification
5. Historic leaks at ffffff80... are REAL pointers (1704 hits)

## Evidence
- vmemmap_populate __pa() uses 2^39 constant with test < 2^38
- kfree uses 0xffffff80... and 0xfffffffe... constants
- free_unref_page inverse formula matches kfree constant
- Literal scan: 4x 0xffffff80..., 6x 0xfffffffe...

## Documents Created
1. AUDIT_FINDINGS_FULL.md — Complete findings (English)
2. AUDIT_METHODOLOGY.md — How each finding was obtained
3. CURRENT_CODE_STATE.md — What needs changing in code
4. BUILD_STATE.md — Build status and next steps
5. AUDIT_STATE.md — This file (live state)

## Next Steps
See BUILD_STATE.md Phase 0-5 for complete protocol.

## Code Status
**NOT PATCHED** — all files still have old wrong constants.
Target files requiring modification:
- src/targets/a37xv2-A376BXXU1AZB7/target.h (L40, L108-112)
- src/pipe.c (L357-360, L372-375, L477-547) — auto-fix via target.h
- src/common.h (L126-127) — auto-fix via target.h

## Session Interruption
All work paused here. Next session should:
1. Read BUILD_STATE.md for complete protocol
2. Execute Phase 0 (device verification) first
3. Then Phase 1-5 as documented

---
*Audit completed: 2026-08-27*
*Author: opencode*
