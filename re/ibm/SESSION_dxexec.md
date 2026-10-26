# dxexec Session Log

Target: IBM DataExplorer dxexec
Format: DEC Alpha AXP ECOFF, OSF/1 3.11-4, 6MB stripped

---

## Session 13 — 2026-10-25 — AlphaEcoffScanner + exec-class sweep

### Architecture gap

BinaryContext returns `arch=x86_64, func_starts=0` on OSF/1 Alpha ECOFF.
Root cause: 24-byte FILHDR with 64-bit `symptr` (not 32-bit), 64-byte section
headers with 64-bit addresses — neither LIEF nor capstone recognise the format.

### New module: insn_alpha.py

Written `ablation/analyzers/insn_alpha.py` (`AlphaEcoffScanner`) to fill the gap.
Key findings from binary analysis used to build the module:

- FILHDR: `<HHI Q I HH>` (24 bytes, `Q` for 64-bit symptr at offset 8)
- AOUTHDR: 80 bytes, gp_value at offset 72 from AOUTHDR start
- Section headers: 64 bytes, 64-bit vaddr/size at offsets 16/24
- Confirmed: gp_value=0x1400FC380, text_va=0x120034a30, text_size=0x4d1900
- .dynsym: 3103 entries × 24-byte Elf64_Sym = 0x122f0 bytes (validated by .hash nchain=3103)
- GOT[N] = dynsym[N] mapping confirmed (GOT[2921]=system VA, GOT[2982]=execve VA, etc.)
- Internal callers use BSR (PC-relative); exec-class functions are statically linked

FORGE gate: **PASS** (0 CRITICAL, 0 HIGH, 3 LOW, 1 INFO)
pytest: **1904 passed**

### Findings

| ID | Sink | Caller VA | Verdict |
|---|---|---|---|
| DX-001 | system | 0x12028d76c | CANDIDATE MEDIUM — argument taint pending |
| DX-002 | execve | 0x12031e128, 0x12031ec2c, 0x12031fa5c | ELIMINATED — libc chain calls |
| DX-003 | execlp | 0x12032180c | ELIMINATED — libc chain call |
| DX-004 | popen | (no callers) | SAFE — exported, unused internally |

### Open items

- DX-001: Manual `WindowAnalyzer.dump_text()` on 0x12028d76c ± 32 instructions to
  trace argument construction ($a0 before BSR to system()). Required before
  upgrading from CANDIDATE to CONFIRMED.

### Key constants (for future cross-reference)

```python
gp_value    = 0x1400FC380
text_va     = 0x120034a30
text_size   = 0x4d1900
system_va   = 0x1202e9550  # dynsym[2921]
execve_va   = 0x12031f810  # dynsym[2982]
popen_va    = 0x12031f9d0  # dynsym[2986]
execlp_va   = 0x120321860  # dynsym[3005]
```
