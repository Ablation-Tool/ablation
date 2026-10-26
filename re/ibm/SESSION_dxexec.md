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

### trace_arg() result for DX-001 (session 13, later in session)

Extended `insn_alpha.py` with `AlphaArgTrace` dataclass and `trace_arg()` backward
scan method. Results for DX-001 system() call at 0x12028d76c:

```
$a0 (r16): BIS_MOV — MOV r10 → r16  (bis r10,r10,r16)  @ 0x12028d768
r10 ($s1): BIS_MOV — MOV r16 → r10  (bis r16,r16,r10)  @ 0x12028d6bc
```

Interpretation: the wrapper function at **0x12028d6a0** receives a command string
in its own `$a0`, saves it to `$s1` (callee-saved) for preservation across
intermediate calls, then restores `$s1 → $a0` and passes it straight to `system()`.

This is a **pass-through / wrapper pattern**. The command arg is dynamic (not a
constant). DX-001 remains **CANDIDATE MEDIUM** — exploitability depends on whether
the wrapper at 0x12028d6a0 is reachable from attacker-controlled input.

insn_alpha.py additions committed in a878b1aa:
- `AlphaArgTrace` dataclass
- `trace_arg(caller_va, reg=16, window=32)` backward scanner
- `_CALLEE_SAVED` set: BSR skipped for r9-r15 (callee-saved registers preserved across calls)
- `bis Ra, Ra, Rc` now correctly recognized as BIS_MOV (Ra==Rb case)
- `_load()` caching; `_try_read_string()` helper

### Open items

- DX-001: CANDIDATE MEDIUM — wrapper at 0x12028d6a0; need call-graph to find all
  callers and determine if any accept attacker-controlled input.
  Further analysis would require identifying the function name (stripped binary)
  or disassembling its callers with `trace_arg()` on each BSR that targets 0x12028d6a0.

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
