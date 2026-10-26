# /goal — IBM-RE Full Collection RE

Full RE of all IBM firmware targets at `/media/cowboy/research/IBM-RE/` per
`/media/cowboy/research/IBM-RE/FIRMWARE_TARGETS.md`. All findings go into
`re/ibm/` per CLAUDE.md rules. Every session ends with `FORGE.audit_module()`
PASS and a `SESSION_<target>.md` update. Every confirmed finding is
byte-verified before the verdict is written.

Work in tier order. Within each tier, shortest-to-longest by analysis
complexity. Stop only when every target below has a verdict of SAFE,
CONFIRMED, or DEFERRED-WITH-REASON.

RE module: `re/ibm/ibm_bomc_re.py` (existing — extend it for BoMC remaining
targets). New targets each get their own `re/ibm/<target>_re.py`.

---

## ALREADY COMPLETE — do not repeat

BoMC IMM2 sessions 1–9:
- `libDataInterface.so` — BOMC-IMM2-001 CONFIRMED HIGH (KVM IP injection)
- `libNexus.so`         — sweep complete, 17 SAFE
- `libxferd.so`         — BOMC-IMM2-002 CONFIRMED HIGH (sftp:// URI → shell)
- `SerRedir`            — SAFE
- `clish + clid`        — BOMC-IMM2-003 CONFIRMED MEDIUM (PRIVILEGES wire)
- `imm2-uboot.bin`      — SAFE (no standalone finding; chained post-BOMC-IMM2-002 only)
- `rdumount`            — SAFE (both system() sites eliminated; snprintf("%d",pid) sanitizes PID)

---

## PENDING — complete in this order

### BoMC IMM2 — finish the open queue

**1. `re/ibm/ibm_bomc_re.py`**

- [x] ~~1a. IMM2 U-Boot (imm2-uboot.bin, 360KB SH4)~~ — DONE (session 8)
- [x] ~~1b. rdumount (x86_64, 79744 bytes, 2 system() sites)~~ — DONE (session 9), ALL SAFE
- [x] ~~1c. asu64 (x86_64, 21MB, 15 popen() + Linux::execCmd() callers)~~ — DONE (session 10). 19/21 eliminated; BOMC-ASU-002 CANDIDATE MEDIUM (PingImmInterface via CIM WBEM).
- [x] ~~1d. LiveOS squashfs (146MB DSA Linux env)~~ — DONE (session 11). Zero setuid; no IBM-authored exec-class finding.
- [x] ~~1e. SHA256 similarity check on CR7/CR8/CR9 ASU/rdumount binaries~~ — DONE (session 12). BOMC-RDM-001 and BOMC-ASU-002 apply to all 7 ISOs.

---

### Tier 1 — rare/niche, highest Ablation module value

**2. dxexec** (DEC Alpha AXP, 6MB COFF, `/media/cowboy/research/IBM-RE/dxexec`)
`re/ibm/dxexec_re.py`
- [x] Alpha disasm gap filled: `insn_alpha.py` (AlphaEcoffScanner). FORGE PASS.
- [x] Binary confirmed IBM DataExplorer 3.1.4. Exec-class sweep complete.
- DX-001 system() CANDIDATE MEDIUM — argument taint pending (session 13)
- DX-002/003 execve/execlp ELIMINATED (libc chain calls)
- DX-004 popen SAFE (exported, no internal callers)

**3. IPLROM.image.9705071651** (RS/6000 XCOFF, 623KB, 1817 symbols, POWER2)
`re/ibm/prep_iplrom_re.py`
- [x] COMPLETE (sessions prior to 13). FORGE PASS. Zero confirmed findings.
- IPLROM-NET-001 ELIMINATED 2026-10-18 (BOOTP src fields are firmware-controlled, not network data).
- Phase 2 done 2026-10-24: 735 symbols, 5 microcode blobs, 8 text sections fully mapped.

**4. cd7200_bootfile.exe** (PPC32 ELF, 27MB bare-metal, no section headers)
`re/ibm/cd7200_re.py`
- [x] COMPLETE (sessions 2026-10-03, 2026-10-08). Zero confirmed findings.
- CD7200-001 ELIMINATED: security-password reference is a filter, not a reader. No vulnerability.
- New ablation module: ppc32_func_discovery.py (commit 9e5af87), 18 919 functions found.

**5. zOS-IOC/iocchk** (z/OS Program Object, 84KB, s390x LE)
`re/ibm/zos_ioc_re.py`
- [x] COMPLETE (session 14, 2026-10-25). FORGE PASS. IOC-001 SAFE.
- Actual format: z/OS Program Object (IEWPLMH), not raw GOFF.
- No exec-class sinks. No credentials. All SVCs are LE boilerplate (CEEPIPI, ABEND U4093).
- SVC 0 EXCP apparent at 0x3e34 is a false positive from a data table — dismissed.
- Purpose: read-only IOC DLL reference checker using IBM binder API (__iew_*).

**6. z390-PTFs/uq33628, uq33629, uq33906** (SMP/E MCS format, EBCDIC card-image)
`re/ibm/z390_ptf_re.py`
- [x] COMPLETE (session 14, 2026-10-25). FORGE PASS. PTF-001 SAFE.
- Format: SMP/E MCS (not XMIT). 80-byte EBCDIC card-image records, '++ PTF' header.
- Product: IBM Content Manager OnDemand 5655-A88 (1999).
- APARs: PQ23885 (preview exit IODEXPVW), PQ24468 (IAFC migration SRT exit).
- IODIADEL: APF authorized (AC=1), PL/I, DB2 CAF — expected for archive batch utility. No vuln.
- DB2 schema recovered from DBRM: VUSERIN2, VCOLIND, VPRO08, VCIK01.

**7. hyper-protect SE headers** (IBMSecEx, 720B each, s390x Ultravisor)
`re/ibm/hpse_re.py`
- [x] COMPLETE (session 14, 2026-10-25). FORGE PASS. HPSE-001 SAFE.
- Format: ASCII magic "IBMSecEx", big-endian, version 0.1.0, 720 bytes total.
- Parsed: nonce (0x10, per-image unique), measurements (0x50-0x8F, 64B SHA-256),
  2 host key slots (0xA0-0x2CF, 576B encrypted). No credentials or code.
- Differing fields between headers: nonce, image size (f_0x30), feature flags (f_0x48).

**8. NC-AS400/qzrdu0mm.sav** (OS/400 SAVLIB, 182KB)
`re/ibm/as400_re.py`
- [x] COMPLETE (session 14, 2026-10-25). FORGE PASS. AS400-001 SAFE.
- savf2zip not installed; hex-parsed SAVLIB EBCDIC records.
- 9 objects (PACKDEV library): QZRDPACK, QZRDPDSP/CL, QZRDPEXT/CL, DSPPCKF, EXTPCKF,
  QDZRDPDSP, QHZRDCMD1 — pack file display/extract utilities. V3R1 ILE C + CLP.
- Three versions (1997 × 2, 1998): same 9 objects. No network/auth code.

**9. MQSeries-RarePlatforms/cpqnsk51/IC44753** (NonStop PAK, 13.2MB, MIPS)
`re/ibm/nonstop_re.py`
- [x] COMPLETE (session 14, 2026-10-25). FORGE PASS. NSK-001 SAFE.
- Actual binary in MQSeries-UNIX/CompaqNSK/IC44753.bin (GOAL-listed dir was empty).
- Format: Tandem Guardian PAK tape archive. Binaries are Tandem SRL/OMF — NOT MIPS ELF.
- HIPER APAR IC44753: 4 reliability fixes (repository sync, duplicate keys, channel loop).
- No exec-class sinks (no Unix shell on NSK), no credentials, no injection surface.
- INSTAPAR uses FUP DUP with fixed Guardian paths (not shell commands).

---

### Tier 1 — PPC firmware blobs

**10. pSeries raw firmware images** (5 × ~1MB PowerPC)
`firmware-7025-F40/TR97069.img`, `firmware-7043-140/tig97161.img`,
`firmware-7043-240/DOR97069.img`, `firmware-7248-43p/beta112.img`,
`firmware-7020-40p/P12H0456.IMG`
`re/ibm/pseries_fw_re.py`
- [x] COMPLETE (session 14, 2026-10-25). FORGE PASS. PSERIES-FW-001 SAFE.
- Format: IBM/Apple PPS Microcode flat binary (Open Firmware / CHRP, 1994-1996).
- No ELFs, no successfully decompressed compressed payload, no network boot strings.
- No credentials, IPs, or debug ports. TR97069+DOR97069 share level 12H0656.

**11. collections/firmware/system-firmware/01VL930_139_040.img** (308MB POWER7)
`re/ibm/power7_fw_re.py`
- [x] COMPLETE (session 14, 2026-10-25). FORGE PASS. POWER7-FW-001 SAFE.
- IBM UFI container (UI\x00\x03, FW930.41, build 2021-03-03).
- 29 ELF headers scanned; 4 CHRP false positives; 25 real ELFs.
- Largest ELF (2.3MB ePAPR boot shim, PPC64 LE ELFv2, not stripped):
  SinkArgClassifierPPC64 = 0 exec-class sites. No credentials.
- ARM BE ELFs = IBM FSP service processor firmware (14 ELFs, 7 A/B pairs).

---

### Tier 1 — MCU/ROM targets

**12. collections/dhe/network/workspace/tips/multi.rom** (52KB x86 real-mode)
`re/ibm/tokenring_rom_re.py`
- Disassemble as 16-bit x86 at offset 0 (BIOS ROM extension entry at
  0x03 per standard). Sweep for hardcoded I/O port sequences, PCI
  config writes, exec or self-modify patterns.

**13. dcconnect hardware 7526** (3 × 128KB, arch TBD)
`7526b323.bin`, `7526b325.bin`, `7526b331.bin`
`re/ibm/dcconnect_7526_re.py`
- [x] COMPLETE (session 14, 2026-10-25). FORGE PASS. DCCONNECT-7526-001 SAFE.
- Actually 4 BIN files (B3.23, B3.25, B3.31, B3.41); arch = x86 real-mode (FA=CLI at 0x32).
- 50-byte ASCII version header + machine code. No hardcoded passwords or IPs.
- "PASSWORD:" is config menu label; value in NVRAM, not binary.

**14. dcconnect hardware 7527** (4 × 128KB, likely x86 real-mode)
`7527v122.bin`, `pft0120d.bin`, `pft0121.bin`, `pft0121m.bin`
`re/ibm/dcconnect_7527_re.py`
- [x] COMPLETE (session 14, 2026-10-25). FORGE PASS. DCCONNECT-7527-001 SAFE.
- x86 real-mode (FA 06 50 = CLI PUSH ES PUSH AX at offset 0, no header).
- IBM + PAR Microsystems joint product (POS/retail, V01.20d to V01.22, 1987-1996).
- Password dialog strings ("Enter your current password:") are UI labels; values in NVRAM.
- DTWMatcher not applied (no 16-bit x86 function start scanner in ablation).
- 525 strings each; no hardcoded IPs; no security regression across versions.

---

### Tier 2 — high-value Linux environments

**15. HMC-V11/network-ppc/base.img** (1.76GB squashfs, PowerPC HMC Linux)
`re/ibm/hmc_re.py`
- [x] COMPLETE (session 14, 2026-10-25). FORGE PASS. HMC-001 SAFE.
- IBM Linux 10 (hmc10p), RHEL9-based. Mounted OK. 65268 inodes.
- Setuid: 26 files, all standard Linux utils; 0 IBM HMC authored.
- IBM HMC native ELFs: only 2 (AuthImage X.509 cert verifier + hard_reboot wrapper).
  Both: SinkArgClassifier = 0 exec-class sinks. SAFE.
- HMC app is Java (Semeru JDK 17 + JARs) — minimal native attack surface.
- Exec import scan (2102 PPC ELFs): 753 with exec — all Linux OS packages, not IBM HMC.
- pkexec 0.117-14.el9.ibm.1: IBM RHEL9 backport includes CVE-2021-4034 fix.

**16. IBM4690 POS OS** (`4690gsa-csd.iso` + `4690saem-csd.iso`, x86)
`re/ibm/pos4690_re.py`
- [x] COMPLETE (session 14, 2026-10-25). FORGE PASS. POS4690-001 SAFE.
- Arch: IBM 4690 OS 286 protected-mode `.286` load modules — NOT ELF.
  BinaryContext/SemanticSearcher/SinkArgClassifier not applicable.
- GSA ISO: 53 files (14 × .286, 10 × .dat, 20 × .bat, 7 × .doc). SAEM ISO: 15 files.
- String sweep: 0 credentials, 0 net listeners, 0 crypto keys, 0 IPs in binary modules.
- Track data refs all in .DOC APAR documentation (MSR format specs), not binary.
- IR48076: customer card ≠ credit card confusion — historical bug patched by PTF Q001.
- IR25274: encrypted operator passwords = security improvement, not finding.

**17. VIOS/sp01/U828079.bff** (AIX BFF, 6MB, PowerPC)
`re/ibm/vios_re.py`
- [x] COMPLETE (session 14, 2026-10-25). FORGE PASS. VIOS-001 SAFE.
- Package: bos.net.nfs.client 6.1.4.2 — AIX NFS client, NOT VIOS-specific.
- 0 VIOS commands (ioscli/cfgdev/mkvdev absent). Format: XCOFF (not ELF).
- BinaryContext not applicable. popen() in 2 XCOFF modules = rpc.rwalld + rpc.rusersd (expected).
- XCOFF support gap logged (base AIX package, deferred).

---

### Tier 2 — simulators (Ablation ISA validation)

**18. POWER7/POWER9/POWER10 functional simulators** (x86_64 RPMs)
`re/ibm/power_sim_re.py`
- [x] COMPLETE (session 14, 2026-10-25). FORGE PASS. POWERSIM-001 SAFE.
- New ablation module: `undocumented_ppc_opcodes.PPCOpcodeScanner` (FORGE PASS).
- decode.map P7: 1461 ops, P9: 2576 ops. P10 (systemsim): no decode.map.
- sp_attn: primary opcode 0 (XO 0x100 P7 / 0x200 P9), NOT in public POWER ISA spec. Absent in P10.
- rvwinkle: POWER7 CMU "Runlatch Winkle" — P7-only, removed in P9.
- Power mgmt: doze/nap/sleep/rvwinkle (P7) → stop (P9). P10: stop x42, sp_attn removed.
- Known FP: CMU-routed public instructions (sc, rfid, hrfid, isel, dst*) — documented in module.

---

### Tier 3 — exotic platform binaries, Ablation multi-arch corpus

**19. TWS-ExoticPlatforms IRIX** (MIPS ELFs, 55MB tar)
`re/ibm/tws_irix_re.py`
- [x] COMPLETE (session 14, 2026-10-25). FORGE PASS. TWSIRIX-001 SAFE.
- 5 MIPS N32 ELFs: instmecho, TWScomponents, TWSconfig, TWSbackup, TWSupdate_file.
- All installer/migration utilities. 0 daemons, 0 setuid, 0 network-facing.
- BinaryContext gap: MIPS N32 function detection = 0 functions; string sweep sufficient.
- execl('/bin/ucomp'): hardcoded IBM binary. system(cp-p): admin-only argv. SAFE.

**20. TWS-ExoticPlatforms OSF/1** (Alpha/MIPS, Tru64)
`re/ibm/tws_osf1_re.py`
- [x] COMPLETE (session 14, 2026-10-25). FORGE PASS. TWSOSF1-001 SAFE.
- 5 DEC Alpha AXP ECOFF binaries (Tru64 UNIX, same source tree as IRIX target).
- AlphaEcoffScanner: 0 findings — Tru64 ECOFF dynamic linking format != ELF PLT/GOT.
- String sweep: identical exec-class pattern to IRIX (execl hardcoded, system cp-p argv).
- Tooling gap: Tru64 ECOFF dynamic linking parser needed for AlphaEcoffScanner.

---

## DONE CRITERIA (per target)

- `FORGE.audit_module()` PASS
- `SESSION_<target>.md` written with findings table
- Every finding byte-verified
- Every eliminated finding has a documented reason
- `re/ibm/<target>_re.py` committed (ablation repo) or noted as local-only

## ABLATION MODULE GAPS TO FILL (in target order)

| Module | From | Status |
|---|---|---|
| `insn_alpha.py` | dxexec RE (target 2) | DONE (session 13) |
| `undocumented_ppc_opcodes.py` | simulator RE (target 18) | DONE (session 14) |
| SH4 `disasm_engine.py` gap | IMM2 sessions | OPEN (logged session 2) |

All new ablation modules follow `length_underflow.py` template.
`from_context(ctx)` classmethod. `scan()` → findings list. `report()` → str.
FORGE gate before every commit.
