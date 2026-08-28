# Session Rules

## Exploit testing (A376B / CVE-2026-43499)
- ALWAYS reboot the phone immediately before running exploit attempts; fresh boot = clean slab state = much higher success probability.
- Never use `sleep` commands in tool calls; poll directly.
- Shell launch pattern:
  `env SLIDE_SOURCE=tracefs EXPLOIT_ATTEMPTS=1 P0_ATTEMPT_TIMEOUT_SEC=115 EXPLOIT_ATTEMPT_TIMEOUT_SEC=420 /data/local/tmp/cve-2026-43499-root --run-payload <app.so> <root-helper> <log>`
- Device adb: `adb connect 127.0.0.1:5555` then `-s 127.0.0.1:5555`.
- Termux python (`/data/data/com.termux/files/usr/bin/python3`) has lz4/BTF tooling; proot python3 does not.
- v2 profile dir: src/targets/a37xv2-A376BXXU1AZB7 (compact waiter + word_shift=1 + defer-alias-readback; e2s shaping knobs STRIPPED after bisection showed they break KernelSnitch leak).
- Engine guard-coupling patches applied: slide_app.c (SYNC log line + slot-trigger region guard), util.c (fops_data_probe_addr definition).
