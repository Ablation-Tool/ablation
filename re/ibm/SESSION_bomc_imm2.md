# BoMC IMM2 SH4 RE Session

**Target**: IBM BoMC IMM2 firmware — CR9 variant (imm2_tcoo18m-3.00.upd)
**Date**: 2026-10-25 (sessions 1 + 2)
**RE module**: `re/ibm/ibm_bomc_re.py`

---

## IMM2 Container Extraction

- `.upd` format: `0xDEADC0DE` header → outer TAR at 0x1605 → inner `imm2.tar` at 0x2205
- `imm2-rootfs.ext3.gz` at TAR offset 0x3a3805, 72,106,821 bytes compressed → 256MB ext3
- Mounted read-only at `/tmp/bomc_imm2/rootfs_mount`

## Architecture

**SH4 (Renesas SuperH-4 32-bit LSB)**, NOT ARM Cortex-M.
- Confirmed: ELF `e_machine=0x2A`, kernel boot string "Booting machvec"
- Linux 2.6.4 userspace
- Capstone: `CS_ARCH_SH + CS_MODE_SH4 + CS_MODE_LITTLE_ENDIAN`

## Exec Wrapper Architecture (libpm_lib.so)

All exec calls go through wrapper chain in `libpm_lib.so`:
- `secure_system`, `proc_system` → `*_nonblocking()` → `fork() + execve("/bin/sh", "-c", cmd)`
- Shell IS invoked. Shell metacharacters in `cmd` string are interpreted.
- Does NOT import `system@GLIBC_2.2` — custom wrappers only.

## libDataInterface.so Analysis

4.7MB SH4 stripped shared library (appweb web UI module).

**Scan method**: direct binary `bsrf rN` pattern scan (opcode `& 0xF00F == 0x0003`) across full
1.78MB `.text` section, backwards-tracing `mov.l @(d,PC), rN` to resolve PLT targets.

**5 direct exec callers found**:
| VA | Function | Calls |
|---|---|---|
| 0x1370c0 | `generateKVMLaunchScript` | secure_popen @ 0x139f1e |
| 0x1889c0 | `Get_FFDC_status` | secure_popen |
| 0x1a9020 | `SA_Get_FFDC_status` | proc_system + proc_popen |
| 0x1aaa20 | `SA_Generate_FFDC_data` | proc_system |
| 0x1acea0 | `SA_ExportProblems` | proc_system |

`SA_Get_FFDC_status`, `SA_Generate_FFDC_data`, `SA_ExportProblems` — all use hardcoded
command strings or SAcore library-generated paths. **SAFE**.

## BOMC-IMM2-001 (CONFIRMED HIGH)

**`generateKVMLaunchScript` → `secure_popen` — KVM IP address injection**

- Call site: `bsrf r2` at VA `0x139f1e` (bytes `03 02`)
- Pool entry at `0x13a06c` = `-1099698` = `0xFFEF384E` → target `0x2D770` (secure_popen PLT)
- PLT stub at `0x2d770`: `0xd004` → loads GOT offset `0x7dc` → GOT VA `0x4c0c70` = secure_popen
- Mode arg (`r4` → "r") from pool `0x13a070`
- Command string includes raw `ipAddress` from HTTP JSON request body
- `secure_popen` → `/bin/sh -c "launch_kvm.sh -i <raw_ip> ..."` → shell injection

**Secondary injection in launch_kvm.sh** (line 36):
```sh
isIPv6=`echo $HOST_IP | grep -q -e ":" || echo no`
```
`$HOST_IP` (= -i optarg = user-controlled) unquoted in backtick.

**All byte verifications PASSED.**

## Session 3 — libNexus.so Full Exec Call Site Sweep

**Binary**: `/usr/lib/provider/libNexus.so`, 2.8MB, SH4 32-bit LSB stripped
**PLT**: VA=0xd5864, 28-byte stubs, formula `stub_va(n) = 0xd5880 + n * 28`
**RELA plt**: 2435 entries, SHT_RELA (entsize=12, r_offset+r_info+r_addend)

**Results**: 53 exec call sites across 18 functions. All 18 analyzed.

| Function VA | CIM Method / Role | Verdict |
|---|---|---|
| 0x0fae54–0x0fdc14 (8 funcs) | BMU (BareMetalUpdate) ops | SAFE — hardcoded /bin/ds filenames + integer args |
| 0x0012e252 | DiagnosticService_Run + ResetCIM | SAFE — all commands hardcoded |
| 0x0013bbf2 | CertificateManager_CreateKeyPair | SAFE — hardcoded sshd.startup genkey |
| 0x0013dcb0 | CertificateManager_ImportCertificate | SAFE — service names from rodata constants |
| 0x00141a10 | **SoftwareInstallationService_InstallFromURI** | **CANDIDATE HIGH** — see BOMC-IMM2-002 |
| 0x00155bb2 | run_encap_cmd | SAFE — hardcoded encapsulation-lite-utility.sh |
| 0x00165b70 | TextRedirectionService_GetAuthenticationToken | SAFE — server-generated session key |
| 0x00181170 | SSH/telnetd/sfcbd restart handler | SAFE — all hardcoded restart scripts |
| 0x00195e10 | Port forwarding status (firetool) | SAFE — hardcoded |
| 0x001985dc | CIM_PublicKeyCertificate_InstAgent_Init | SAFE — hardcoded ssh-keygen |
| 0x001a1672/0x001a192e | ConfigurationDataService | SAFE — hardcoded system-profiles flags |
| 0x001a44d0 | System profiles enable/disable | SAFE — hardcoded |

### BOMC-IMM2-002 CONFIRMED HIGH

- **Method**: `CIM_SoftwareInstallationService_InstAgent_InstallFromURI` (WBEM over HTTPS:5989)
- **Chain**: user URI → `xferd_parse_uri()` → URI components (unsanitized) → snprintf into curl cmd → `async_secure_system()` → `/bin/sh -c`

## Session 4 — libxferd.so: xferd_parse_uri() analysis

**Binary**: `/lib/libxferd.so`, 42KB, SH4 32-bit LSB, 102 dynamic symbols
**Target function**: `xferd_parse_uri` at VA=0x61a0, 1052 bytes

**Call sequence in xferd_parse_uri**:
1. `memset` — zero output struct
2. `uriParseUriA` — RFC 3986 URI parse (uriparser library)
3. `strncpy`×4 + `strncpy_chk`×4 — raw copy of components to output struct
4. `sscanf "%[^:]:%s"` — split credentials on colon
5. `strtol` — parse port integer
6. `strcmp`×3 — match scheme against "sftp"/"tftp"/"http"/"https"
7. `uriFreeUriMembersA`×5 — error-path cleanup

**Sanitization check**: NO calls to `strpbrk`, `strchr`, or any filter function. Zero metacharacter sanitization.

**RFC 3986 sub-delimiters in path+host**: `;` `$` `&` `(` `)` `*` `!` — ALL shell metacharacters, ALL valid in URI path and reg-name per RFC 3986.

**Byte evidence (confirmed)**:
| VA | Bytes | Description |
|---|---|---|
| 0x00141afc | `03 03` | bsrf r3 → xferd_parse_uri PLT stub @ 0xdd5d8 |
| 0x00141c08 | `d8 ba f9 ff` | pool = -410920; target = 0x141b00 - 0x64528 = 0xdd5d8 ✓ |
| 0x000dd5d8 | `04 d0 ce 00` | xferd_parse_uri PLT stub (`d004` + `00ce`) ✓ |
| 0x00141f2c | `03 03` | bsrf r3 → async_secure_system PLT stub @ 0xe2d74 |
| 0x00141fcc | `44 0e fa ff` | pool = -389564; target = 0x141f30 - 0x5f1bc = 0xe2d74 ✓ |
| 0x000e2d74 | `04 d0 ce 00` | async_secure_system PLT stub ✓ |
| 0x00274c24 | `2f 75 73 72...` | SFTP curl format string: `/usr/bin/curl -o %s -u %s:%s sftp://%s%s:%d/%s...` ✓ |

**BOMC-IMM2-002 CONFIRMED HIGH** — all bytes pass.

**PoC**: URI = `sftp://host/fw.bin;id`
- Shell command: `/bin/sh -c "... sftp://host:22/fw.bin;id -k ..."`
- Shell splits at `;` → `id` executes as IMM2 root

## Session 5 — SerRedir (setuid+setgid) Analysis

**Binary**: `/sbin/SerRedir`, 18,196 bytes, SH4 ET_EXEC, rwsr-sr-x root:root  
**Purpose**: Serial console redirection daemon (proxies /dev/ttySC0 I/O)

**Import scan result**: ZERO exec-class imports — no system/popen/execve/fork.

| Category | Finding |
|---|---|
| dlopen | Hardcoded `/lib/libnvram.so` — not injectable |
| IPMI_DoIPMICmd | r4=0 (NetFn=Chassis), r5=2 (GetChassisStatus) — immediates only |
| strncpy | n=20 bound at call site; stack canary active |
| execv | `/sbin/SerRedir` hardcoded (from clish, see below) |
| GetVarValueSTRING | "keystroke" config → strncpy n=20 — bounded |

**Verdict: SAFE. No finding.**

---

## Session 6 — clish (setuid root) Analysis

**Binary**: `/bin/clish`, 51,304 bytes, SH4 ET_EXEC, rwsr-xr-x root  
**Purpose**: IBM CLI shell — setuid, connects to local Unix socket CLI daemon

### Import Analysis

- `fork` @ 0x401fdc, `execv` @ 0x4025c4 — exec-class sinks found
- execv target: **hardcoded `/sbin/SerRedir`** — no PATH injection
- `getenv` @ 0x40220c (called 3×: PRIVILEGES, USER, TERM)
- `prctl` @ 0x401f50

### Attack Surface Analysis

**Finding 1 — getenv("PRIVILEGES") → CLI daemon (CANDIDATE)**

```
getenv("PRIVILEGES") @ 0x40304a → r11
getenv("USER")       @ 0x403054 → r10

strtol(r11, NULL, 10) @ 0x403128 → privilege integer
write(cli_fd, ...)    @ 0x40315e → sends integer to CLI daemon via Unix socket
```

Privilege integer from ATTACKER-CONTROLLED env var sent to daemon. If daemon accepts without independent auth → attacker sets `PRIVILEGES=15` → Supervisor CLI.

**Finding 2 — strcmp(USER, "immroot") client-side guard**

```asm
0x403822: mov.l r5,"immroot"
0x403824: bsrf r2 → strcmp(r4=USER_result, r5="immroot")
0x403828: tst r0,r0
0x40382a: bf 0x403830          ; T=0 (not equal) → jump to error
0x40382e: mov #2,r1            ; T=1 (equal) → fall through
...
0x403830: mov #0,r1
0x403846: mov.l r4,"no username or privileges."
0x403848: bsrf → puts()        ; prints error + exits
```

CLIENT-SIDE only. `USER=immroot` bypasses the local guard.

### BOMC-IMM2-003 CANDIDATE MEDIUM

**Attack**: SSH to IMM2 + set `USER=immroot PRIVILEGES=15` in environment  
**If** `PermitUserEnvironment yes` in sshd_config: exploitable directly via SSH  
**Otherwise**: post-exploitation (requires shell from BOMC-IMM2-001/002 first)

**Needs confirmation**:
1. `/etc/ssh/sshd_config` — check PermitUserEnvironment
2. CLI daemon binary — confirm PRIVILEGES wire value trusted without cred check

---

## Session 7 — sshd_config + clid Daemon Confirmation

**Targets**: `/etc/ssh/sshd_config-immcli` + `/sbin/clid` (26KB SH4 ET_EXEC)

### sshd_config-immcli
`PermitUserEnvironment no` — confirmed. SSH env var injection not possible.
BOMC-IMM2-003 severity confirmed **MEDIUM** (post-exploitation only, not direct SSH).

Multiple sshd configs present (IMM2 runs parallel daemons per mode):
- `sshd_config-immcli` — normal CLI access (no PermitUserEnvironment)
- `sshd_config-immdebug` — also no PermitUserEnvironment
- `sshd_config-immsftp`, `sshd_config-immrecovery`, `sshd_config-immlockdown`

Note: `PermitRootLogin yes` in sshd_config-immcli (direct root SSH allowed).

### clid Daemon Analysis

**Binary**: `/sbin/clid`, 26,420 bytes, SH4 ET_EXEC  
**Socket**: `/tmp/clisocket` (confirmed via binary string scan)  
**PLT imports** (48 entries): `accept`, `bind`, `listen`, `read`, `write`, `close`, `fork`, `pthread_create`, `aim_config_set_int`, `aim_config_get_int`, `cli_parse_and_execute`, `StartBackupRestoreSession`, `StopBackupRestoreSession` — and notably:

**NO `getsockopt`, NO `getpeereid`, NO `getpeername`** — zero socket credential verification capability.

**Critical wire read**:
```
VA 0x402bc8: 0103  bsrf r1 → read PLT @ 0x401f50
             e604  mov #4,r6   (delay slot: count=4)
```
Reads 4-byte privilege integer from the Unix socket. No credential check precedes this.

**Byte verification**:
| VA | Bytes | Description |
|---|---|---|
| 0x402bc8 | `01 03` | bsrf r1 → read PLT 0x401f50 ✓ |
| 0x402bca | `e6 04` | delay slot: mov #4,r6 ✓ |
| dynstr | absent | getsockopt/getpeer* not present ✓ |

### BOMC-IMM2-003 CONFIRMED MEDIUM

**CONFIRMED** — verdict upgraded from CANDIDATE.

**Confirmation basis**:
1. clid has NO SO_PEERCRED/getsockopt → cannot verify caller identity
2. clid reads 4-byte integer from wire (r6=4 confirmed at 0x402bc8)
3. PermitUserEnvironment=no → requires prior shell access (post-exploitation)

**Privilege level semantics**: `system-profiles` binary uses `export PRIVILEGES="0002"` (Operator). Supervisor = 15 (max level).

**Full attack chain**:
```
BOMC-IMM2-002 (sftp://host/fw.bin;id → /bin/sh as root)
  ↓
Shell on IMM2 as root
  ↓
USER=immroot PRIVILEGES=15 /bin/clish
  ↓
clish: strtol("15")→15 → write(clisocket, &15, 4) → clid trusts it
clish: strcmp(USER,"immroot") → bypass local guard
  ↓
Admin CLI session (Supervisor level)
```

---

## Session 8 — imm2-uboot.bin U-Boot Analysis

**Binary**: `imm2-uboot.bin`, 360,180B, SH4 LE raw, U-Boot 2009.06p (built 2015-08-27)  
**Extracted from**: imm2.tar inside imm2_tcoo18m-3.00.upd → /tmp/bomc_imm2/uboot/

| Finding | Severity | Notes |
|---|---|---|
| TFTP fallback: unsigned image execution | INFERRED HIGH (chained) | Requires TFTPREC=1 + all partitions invalid + attacker at 192.168.70.200 |
| Console escape on ttySC2 | LOW (physical only) | No password; sf/run/setenv available; separate from SerRedir console |
| U-Boot 2009.06p known CVEs | INFERRED MEDIUM | Decade-old, likely unpatched net stack |

**TFTP fallback**: hardcoded ETH=192.168.70.225, server=192.168.70.200. TFTPREC flag gates
the path. TFTP-fetched image has NO RSA verification (local boot only verifies /boot/uImage.sig
via TPM). Script-type uImage executes as U-Boot command list → sf write → firmware implant.
Not a standalone finding — requires BOMC-IMM2-002 chain to corrupt eMMC partitions first.

**upd.flash**: initramfs installer script. Writes rootfs via `dd of=/dev/mmcblk0p2`. Platform
check via awk on imm2.xml. No injection in installer itself.

## Session 9 — rdumount Full Taint Trace

**Binary**: `/tmp/bomc_work/rdumount`, x86_64 ELF, not stripped, debug_info, 79,744 bytes

**system() call sites** (2 total):

| VA | Function | Verdict |
|---|---|---|
| 0x406610 | `Linux::execCmd(char*)` | ELIMINATED — only reachable with RODATA_CONST or `snprintf("%d",pid)` arg |
| 0x406873 | `System::makeDierForLog` | ELIMINATED — `system("mkdir /var/log/IBM_Support/")` RODATA_CONST |

**Virtual dispatch map (RdUmountUI vtable @ 0x409d70)**:

| Offset | VA | Function |
|---|---|---|
| +0x00 | 0x405024 | `RdUmountUI::parse()` |
| +0x08 | 0x404caa | `RdUmountUI::go()` |
| +0x10 | 0x405290 | (inherited) |
| +0x38 | 0x406f30 | `Linux::getCommandOutput` |

**Linux vtable (osP global)**:
- `vtable[2]` = `Linux::execCmd` (offset 0x10)
- `vtable[7]` = `Linux::getCommandOutput` (offset 0x38)

**Taint trace**:
- `go()` → `doQuery("rdmount")` → `getCommandOutput("ps -elf | grep rdmount")` → RODATA_CONST
- `go()` → `verify_pid(atoi(argv[i]))` → `snprintf("%d", pid)` → `getCommandOutput("ps " + decimal_int)` → integer-sanitized

No attacker-controlled data reaches any system() call. **No finding.**

## Session 10 — asu64 Full Exec-Class Sweep

**Binary**: `/tmp/bomc_work/asu64`, x86_64 ELF, 21MB, not stripped, debug_info

**PLT addresses**: `system@plt=0x6b8fb0`, `popen@plt=0x6b8050`

**popen() — 15 sites, ALL RODATA_CONST**

| Function | Count | Commands |
|---|---|---|
| `checkOSBitWithSoftwareBit()` | 1 | `popen("uname -m", "r")` |
| `ibmcKCS::OpenIPMI_CheckKernel()` | 2 | `"uname -r"`, `"dmesg | grep..."` |
| `ibmcKCS::OpenIPMI_InstallDriver()` | 5 | `/etc/init.d/ipmi start`, `modprobe ipmi_*` ×4 |
| `OpenIPMI_CheckKernel()` [free fn] | 2 | same as class version |
| `OpenIPMI_InstallDriver()` [free fn] | 5 | same as class version |

**system() — 6 sites**

| VA | Function | Verdict |
|---|---|---|
| 0x6d88fd, 0x6d8a85 | `checkPatchable(char*)` | ELIMINATED — argv[0] (session 1) |
| 0x96c4ff | `LinOS::reboot()` | SAFE — `system("reboot")` RODATA_CONST |
| 0x6e2d68 | `ImmUsbLanCfg::CState(std::string)` | SAFE — `StartCState("")`, `StopCState(" --stop")` hardcoded |
| 0x6e2857 | `ImmUsbLanCfg::RumImmUsbLanCfgCmd(std::string)` | SAFE — 9 callers all use hardcoded or hardware-enum args |
| 0x6e3269 | `ImmUsbLanCfg::PingImmInterface(std::string addr)` | CANDIDATE MEDIUM (BOMC-ASU-002) |

**BOMC-ASU-002 update**: `PingImmInterface` has 0 direct callers. fn ptr stored at CIM descriptor table entries (0x440a08, 0x10e9700, 0x1532f68). CIM dispatch context: invoked via WBEM `ExecMethod` on HTTPS:5989. addr = WBEM method argument, no sanitization path observed. Requires authenticated CIM credentials.

## Session 11 — DSA102 LiveOS Squashfs Full Sweep

**Source**: `CR9BoMC_IMM370_UEFI232_DSA102_FC.iso → LiveOS/squashfs.img`
**Format**: Squashfs 4.0 zlib, 146,391,035 bytes → inner `ext3fs.img` (5.9GB sparse) → RHEL 6.4 x86_64 rootfs (built 2015-09-23)
**Mount**: outer squashfs @ `/mnt/dsa_outer`, inner ext3 @ `/mnt/dsa_inner`
**ELF count**: 1,712

**Setuid sweep**: ZERO setuid/setgid binaries

> LiveOS boots as root (PID 1 = root). Setuid is architecturally unnecessary. Known-setuid binaries (`su`, `passwd`, `ping`, `sudo`) all have the bit stripped. `sudo` is `--x--x--x` (execute-only, no setuid).

**Exec-class scan**: 196 / 1712 ELFs have exec-class imports

| Binary | Imports | Verdict |
|---|---|---|
| `/bin/exec_nosol` | `execl` | SAFE — `execl("/bin/bash", "/bin/tcstart.sh")` hardcoded |
| `/bin/exec_sol` | `execl` | SAFE — `execl("/bin/bash", "/bin/tcsolstart.sh")` hardcoded |
| `/bin/exec_term` | `execl` | SAFE — `execl("/bin/bash", ...)` hardcoded startup |
| `/bin/linlpcfg` | `system` | SAFE — `system("whoami...")` root-check only, RODATA_CONST |
| `/usr/lib64/libdbfaj.so` | `execl popen system` | THIRD-PARTY (Brocade FC HBA library) — out of scope |
| `/usr/bin/bcu` | `system` | THIRD-PARTY (Emulex HBA tool) — out of scope |
| 190 standard binaries | various | RHEL 6.4 baseline — not traced |

**VERDICT**: NO FINDING.

Note: `exec_nosol`/`exec_sol` carry a `.note.SuSE` ELF section — compiled for SuSE Linux with GCC 4.1.2 (~2007) and bundled into the RHEL-based LiveOS as pre-built vendor stubs.

## Next Targets

1. SHA256 similarity check (1e) — CR7/CR8/CR9 binary variants
2. BOMC-ASU-002 — CIM dispatch trace (lower priority; requires CIM framework analysis)

## SH4 Ablation Gap

`ablation/core/disasm_engine.py` does NOT support SH4. Gap logged. New module needed per
"gaps become modules" rule. Template: length_underflow.py. Wire: `from_context(ctx)`, `scan()`.
