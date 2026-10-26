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
- [ ] 1c. asu64 (x86_64, 21MB, 15 popen() + Linux::execCmd() callers) —
      trace all 15 popen call sites; confirm, eliminate, or defer each.
- [ ] 1d. LiveOS squashfs (146MB DSA Linux env) — mount, setuid sweep,
      exec-class import scan on all ELFs.
- [ ] 1e. SHA256 similarity check on CR7/CR8/CR9 ASU/rdumount binaries —
      determine if findings transfer across variants.

---

### Tier 1 — rare/niche, highest Ablation module value

**2. dxexec** (DEC Alpha AXP, 6MB COFF, `/media/cowboy/research/IBM-RE/dxexec`)
`re/ibm/dxexec_re.py`
- Alpha disasm gap: build SH4-style bsrf scanner equivalent for
  Alpha BSR/JSR patterns. New ablation module: `insn_alpha.py`.
- Confirm binary as IBM DataExplorer. Sweep for exec-class sinks.

**3. IPLROM.image.9705071651** (RS/6000 XCOFF, 623KB, 1817 symbols, POWER2)
`re/ibm/iplrom_re.py`
- Load as XCOFF; confirm all 1817 symbols parse correctly via
  BinaryContext. Sweep for hardcoded credentials, debug backdoors,
  privileged POWER2 instructions (TLBIA, MFMSR).

**4. cd7200_bootfile.exe** (PPC32 ELF, 27MB bare-metal, no section headers)
`re/ibm/cd7200_re.py`
- BinaryContext bare-metal load (base=0x0, entry=0x416c).
  Sweep for network stack (TFTP, FTP, telnet) exec-class sinks.

**5. zOS-IOC/iocchk** (z/OS GOFF/XOBJ, 84KB, s390x)
`re/ibm/zos_ioc_re.py`
- No Ghidra. Raw binary analysis: extract GOFF section headers,
  identify TEXT/DATA/BSS records, dump symbol table if present.
  String scan + SVC opcode sweep (0x0A xx pattern).
  Look for hardcoded credentials or privileged z/OS SVC calls
  (SVC 0=EXCP, SVC 3=WAIT, SVC 13=ABEND). No full disasm needed.

**6. z390-PTFs/uq33628, uq33629, uq33906** (EBCDIC XMIT, s390)
`re/ibm/z390_ptf_re.py`
- Decode EBCDIC→ASCII. Extract PTF header: APAR number, FMID, LMOD names.
  Identify which z/OS components are patched.
  No code RE required unless a critical security-relevant LMOD appears.

**7. hyper-protect SE headers** (IBMSecEx, 720B each, s390x Ultravisor)
`re/ibm/hpse_re.py`
- Parse both SE headers byte-by-byte: magic (IBMSecEx), version,
  measurement fields, key material offsets. Map structure against
  public IBM Ultravisor documentation. No code — pure format RE.

**8. NC-AS400/qzrdu0mm.sav** (OS/400 SAVLIB, 182KB)
`re/ibm/as400_re.py`
- savf2zip if available, else hex-parse SAVLIB header (QSYS format:
  magic 0x00 + 32-byte obj name EBCDIC). Identify object types
  (*PGM, *SRVPGM, *MODULE). Log format only; no TIMI disasm attempted
  without a V3R1 system.

**9. MQSeries-RarePlatforms/cpqnsk51/IC44753** (NonStop PAK, 13.2MB, MIPS)
`re/ibm/nonstop_re.py`
- PAK container: dump file table. Identify MIPS ELFs inside.
  If present: BinaryContext + SemanticSearcher sweep for MQ
  message-passing primitives and exec-class sinks.

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
| `insn_alpha.py` | dxexec RE (target 2) | OPEN |
| `undocumented_ppc_opcodes.py` | simulator RE (target 18) | OPEN |
| SH4 `disasm_engine.py` gap | IMM2 sessions | OPEN (logged session 2) |

All new ablation modules follow `length_underflow.py` template.
`from_context(ctx)` classmethod. `scan()` → findings list. `report()` → str.
FORGE gate before every commit.
