# Session: Google Chrome 154.0.8037.57

## Binary paths
- chrome:          /tmp/chrome_rpm_extract/opt/google/chrome/chrome (281MB)
- chrome-sandbox:  /tmp/chrome_rpm_extract/opt/google/chrome/chrome-sandbox (15KB SUID)
- libwidevinecdm:  /tmp/chrome_rpm_extract/opt/google/chrome/WidevineCdm/_platform_specific/linux_x64/libwidevinecdm.so (21MB)
- liboptimization_guide_internal: /tmp/chrome_rpm_extract/opt/google/chrome/liboptimization_guide_internal.so (24MB)

## RE module
~/ablation/targets/google/chrome_154_re.py

## Status
- [x] Module scaffolded: PRODUCT/VERSION/VENDOR, BINARIES dict, full SANDBOX_PLT, CHROME/SANDBOX vuln profiles, sweep_sandbox(), sweep_chrome_main(), taint_sandbox(), format_string_scan_sandbox(), heap_scan_sandbox()
- [x] sandbox sweep run: TaintTracker=0, FormatString=0, HeapVuln=3 FP (strlen+9 alloc, scanner blind to LEA offset)
- [x] sandbox manual analysis: 7 functions mapped; TOCTOU by-design; no confirmed findings
- [ ] chrome main sweep run (sweep_chrome_main() -- ~10-20min CPU, run when time allows)
- [ ] libwidevinecdm sweep
- [ ] liboptimization_guide_internal sweep
- [ ] Confirmed findings registered

## Priority order
1. chrome-sandbox (SUID, 15KB, sandbox escape potential)
2. chrome main binary (Mojo IPC + WebRTC + media codec)
3. libwidevinecdm (DRM boundary)
4. liboptimization_guide_internal (on-device ML runner)

## Overlay table
(empty -- no confirmed function names yet)

## Next steps
1. `sweep_sandbox()` -- semantic sweep, review top hits per profile
2. `taint_sandbox()` -- getenv/read -> execv/syscall taint paths
3. `format_string_scan_sandbox()` + `heap_scan_sandbox()`
4. Manual `WindowAnalyzer.dump_text()` on any hits with score > 0.6
5. `PathSolver.solve_path()` on confirmed taint paths
6. For chrome main: run with restricted scan range first (0x400000-0x1000000)

## Notes
- Extracted from RPM to /tmp/chrome_rpm_extract/ (not persistent; re-extract if lost)
- chrome-sandbox uses SBX_CHROME_API_RQ, SBX_CHROME_API_PRV, SBX_D, SBX_HELPER_PID, SBX_PID_NS, SBX_NET_NS env vars
- Three CLI modes: normal (exec), --get-api, --adjust-oom-score
- Namespace creation via raw syscall() (SYS_clone); privilege drop via setresuid/setresgid
- chroot + chdir path present; chroot-without-chdir pattern worth checking manually
