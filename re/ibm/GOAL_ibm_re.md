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
- binwalk sweep each for embedded ELFs, FFS volumes, compressed regions.
  If ELF found: BinaryContext + exec-class sweep.
  Otherwise: string scan for hardcoded credentials, URLs, debug ports.

**11. collections/firmware/system-firmware/01VL930_139_040.img** (308MB POWER7)
`re/ibm/power7_fw_re.py`
- binwalk -e first (UI\x00\x03 container). Map internal FW sections.
  Extract PPC ELFs. SemanticSearcher sweep on largest ELF only
  (time-box to 2 sessions).

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
- Arch detect: try 8051 (0x02 = LJMP), 68000 (0x4E71 = NOP),
  x86 real-mode (0xFA = CLI). Once arch confirmed: basic exec sweep.

**14. dcconnect hardware 7527** (4 × 128KB, likely x86 real-mode)
`7527v122.bin`, `pft0120d.bin`, `pft0121.bin`, `pft0121m.bin`
`re/ibm/dcconnect_7527_re.py`
- FA 06 50 B8 pattern at offset 0 = x86 CLI + prefix. Disassemble
  as 16-bit x86. Compare variants with DTWMatcher. Sweep for
  hardcoded credentials, network config.

---

### Tier 2 — high-value Linux environments

**15. HMC-V11/network-ppc/base.img** (1.76GB squashfs, PowerPC HMC Linux)
`re/ibm/hmc_re.py`
- Mount: `mount -t squashfs -o loop,ro base.img /mnt/hmc`
  Setuid/setgid sweep. Exec-class import scan on all PPC ELFs.
  SemanticSearcher on top 5 largest ELFs. Time-box to 4 sessions max.

**16. IBM4690 POS OS** (`4690gsa-csd.iso` + `4690saem-csd.iso`, x86)
`re/ibm/pos4690_re.py`
- Mount ISO. Find core POS ELFs. Sweep for payment-card handling
  primitives (PAN, track data), network listeners, hardcoded credentials.

**17. VIOS/sp01/U828079.bff** (AIX BFF, 6MB, PowerPC)
`re/ibm/vios_re.py`
- Extract with `restore -xvf U828079.bff` or parse BFF header.
  Extract PPC ELFs. Sweep for VIOS-specific commands
  (ioscli, cfgdev, mkvdev) with exec-class sinks.

---

### Tier 2 — simulators (Ablation ISA validation)

**18. POWER7/POWER9/POWER10 functional simulators** (x86_64 RPMs)
`re/ibm/power_sim_re.py`
- rpm2cpio | cpio to extract. Find simulator binary (sim_ppc or
  systemsim). Sweep for undocumented POWER ISA opcodes not in public
  manuals — compare opcode dispatch tables across POWER7/POWER9/POWER10.
  New ablation module: `undocumented_ppc_opcodes.py`.

---

### Tier 3 — exotic platform binaries, Ablation multi-arch corpus

**19. TWS-ExoticPlatforms IRIX** (MIPS ELFs, 55MB tar)
`re/ibm/tws_irix_re.py`
- Extract tar. Find MIPS ELFs. BinaryContext + SemanticSearcher.
  Sweep for exec-class sinks in scheduler/job dispatch paths.

**20. TWS-ExoticPlatforms OSF/1** (Alpha/MIPS, Tru64)
`re/ibm/tws_osf1_re.py`
- If Alpha ELFs present: feed into dxexec Alpha patterns (target 2).
  If MIPS: same sweep as IRIX. Focus on unique patterns vs IRIX.

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
| `undocumented_ppc_opcodes.py` | simulator RE (target 18) | OPEN |
| SH4 `disasm_engine.py` gap | IMM2 sessions | OPEN (logged session 2) |

All new ablation modules follow `length_underflow.py` template.
`from_context(ctx)` classmethod. `scan()` → findings list. `report()` → str.
FORGE gate before every commit.
