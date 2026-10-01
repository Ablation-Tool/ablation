# LoongArch64 Analysis Stack

Pure-Python LoongArch64 (LA64) decoder, CFG builder, and interprocedural
taint tracker. Targets stripped ELF binaries compiled for the lp64 ABI —
TencentOS 4.6 server packages, Loongson firmware, EDK2/GRUB2 EFI modules,
and kernel drivers.

Capstone 5.x has no LoongArch support. The entire decode path is pure Python.
Instruction table source: binutils 2.41 `opcodes/loongarch-opc.c`.

---

## Quick start

```python
from ablation.analyzers.taint_tracker_loongarch64 import LoongArch64TaintTracker

tt = LoongArch64TaintTracker.from_path("libc-2.38.so.loongarch64")
findings = tt.run_interprocedural()
print(tt.report(findings))
```

---

## Modules

### `loongarch_decoder`

Fixed-width 32-bit LE instruction decoder. Covers integer ALU, immediate,
CSR/TLB/privilege, single/double float, FP compare, load/store, atomics,
barriers, float load/store, and all branch/call/return instructions.
LSX/LASX encodings decode as `.word` (Step 3 deferral).

```python
from ablation.analyzers.loongarch_decoder import LoongArchDecoder

dec = LoongArchDecoder()
for frame in dec.decode_frames(section_bytes, base_addr=0x400000):
    if frame.is_call:
        print(f"call @ {frame.va:#x} -> {frame.target:#x}")
    if frame.is_ret:
        print(f"ret  @ {frame.va:#x}")
```

`LoongArchFrame` fields:

| Field | Type | Description |
|---|---|---|
| `va` | int | Virtual address |
| `width` | int | Always 4 |
| `insn` | int | Raw 32-bit word |
| `mnemonic` | str | Instruction mnemonic |
| `op_str` | str | Comma-separated ABI-named operands |
| `is_branch` | bool | Conditional or unconditional branch |
| `is_call` | bool | `bl` or `jirl $ra,rj,0` |
| `is_ret` | bool | `jirl $zero,$ra,0` |
| `target` | int | Resolved PC-relative target VA (0 = indirect/unknown) |

**`jirl` polymorphism:**

| rd | rj | offset | Classification |
|---|---|---|---|
| `$zero` | `$ra` | 0 | `is_ret = True` |
| `$ra` | any | any | `is_call = True` |
| `$zero` | any≠`$ra` | any | `is_branch = True` |

### `isa_loongarch64`

Register model, lp64 ABI classification, and mnemonic sets.

```python
from ablation.analyzers.isa_loongarch64 import (
    ARG_REGS, RET_REGS, CALLER_SAVED, CALLEE_SAVED,
    LOAD_MNEMS, STORE_MNEMS, ALU3_MNEMS, ALUI_MNEMS,
    canon_reg, reg_by_num,
)

print(ARG_REGS)      # ("$a0", "$a1", ..., "$a7")
print(canon_reg("$r4"))  # "$a0"
```

lp64 register roles:

| Range | ABI names | Role |
|---|---|---|
| r0 | `$zero` | Hardwired zero |
| r1 | `$ra` | Return address (caller-saved) |
| r2 | `$tp` | Thread pointer (OS-managed) |
| r3 | `$sp` | Stack pointer |
| r4–r11 | `$a0`–`$a7` | Arguments / return values |
| r12–r20 | `$t0`–`$t8` | Caller-saved temporaries |
| r21 | `$r21` | Platform-reserved |
| r22 | `$fp` | Frame pointer (callee-saved) |
| r23–r31 | `$s0`–`$s8` | Callee-saved |

### `insn_loongarch64`

Instruction model and operand parser. Splits `op_str` from decoder frames into
typed `Reg` / `Imm` operands.

```python
from ablation.analyzers.insn_loongarch64 import from_loongarch_frames

insns = list(from_loongarch_frames(dec.decode_frames(data, base)))
for insn in insns:
    if insn.mnemonic == "addi.d":
        rd, rj, imm = insn.reg(0), insn.reg(1), insn.imm(2)
```

### `cfg_loongarch64`

CFG builder. Identifies leaders, splits at every terminator, links successors.
Calls are treated as fall-through (callee abstracted). Indirect branches add
no successors.

```python
from ablation.analyzers.cfg_loongarch64 import build_cfg

cfg = build_cfg(insns, entry=func_va)
for block in cfg:
    print(block)
```

### `analysis_loongarch64`

Flow-sensitive, path-insensitive fixpoint analysis over a CFG with loop widening.

```python
from ablation.analyzers.analysis_loongarch64 import analyze_cfg
from ablation.analyzers.taint_tracker_loongarch64 import State

init = State()
init.taint_reg("$a0", "network")
result = analyze_cfg(insns, initial=init, entry=func_va)
for f in result.findings:
    print(f)
```

### `taint_tracker_loongarch64`

Interprocedural source-to-sink taint tracker.

**Sources** (return value → `$a0`):
`recv`, `recvfrom`, `recvmsg`, `read`, `fread`, `fgets`, `gets`, `getchar`, `fgetc`

**Sinks** (check `$a0`–`$a7` on call):
`system`, `execve`, `execl`, `execvp`, `popen`,
`strcpy`, `strcat`, `sprintf`, `vsprintf`, `snprintf`, `vsnprintf`,
`memcpy`, `memmove`, `gets`

```python
from ablation.analyzers.taint_tracker_loongarch64 import LoongArch64TaintTracker

tt = LoongArch64TaintTracker.from_path(binary_path)

# Intraprocedural (fast)
findings = tt.run()

# Interprocedural BFS depth 4 (recommended)
findings = tt.run_interprocedural(depth=4)

print(tt.report(findings))
```

---

## Taint propagation rules

| Instruction class | Propagation |
|---|---|
| ALU 3-reg (`add.d`, `mul.d`, …) | `rd = taint(rj) ∪ taint(rk)` |
| ALU reg-imm (`addi.d`, `ori`, …) | `rd = taint(rj)` |
| `andi rd, rj, mask` | `rd = taint(rj)` with `bound = mask` if mask is 2ⁿ−1 |
| Load (`ld.d`, `ldx.d`, …) | `rd = mem_taint(base, off)` |
| Store (`st.d`, `stx.d`, …) | `mem(base, off) = taint(rd)` |
| Atomic (`amadd.d`, …) | `rd = old_mem_taint; mem = taint(rk) ∪ old` |
| `lu12i.w`, `pcaddi` | `rd = clean` (address constant) |
| `addi.d $sp,$sp,-N` | stack frame allocation, rebases `$sp`-relative memory |
| `addi.d $fp,$sp,N` | records `$fp = $sp + N` in frame-pointer map |
| Float ops | not tracked at GPR level |

---

## PLT/GOT resolution

`_load_elf()` merges PLT stub addresses into the symbol map before scanning.
Each entry from `ELFParser.get_plt_got_table()` (reads `.rela.plt`, resolves
via `.dynsym`) contributes `plt_stub_va → imported_function_name`.

Result: every `bl <plt_stub_va>` call in the taint tracker resolves to the
exact imported name (e.g. `recv`, `strcpy`) without the ±16-byte tolerance
scan. The `_PLT_TOL` heuristic in `_name_at` remains as a fallback for
stripped binaries with no `.rela.plt`.

LoongArch PLT stubs are 4 instructions × 4 bytes = 16 bytes (same as AArch64):
```
pcalau12i  $t3, page_off    ; PC-relative page load — GOT page addr
ld.d       $t3, $t3, off    ; load function pointer from GOT slot
jirl       $zero, $t3, 0    ; indirect branch — no return address saved
nop                         ; alignment pad
```
The stub terminates with `jirl $zero,rj,0` (indirect branch, not call), so
it is correctly classified as `is_branch=True` by the decoder, not as a call.

LoongArch relocation types (psABI v2.30, `elf_parser.R_LARCH_*`):

| Constant | Value | Meaning |
|---|---|---|
| `R_LARCH_NONE` | 0 | no-op |
| `R_LARCH_JUMP_SLOT` | 5 | GOT entry for lazy-bind PLT call |
| `R_LARCH_RELATIVE` | 3 | base-address-relative fixup |
| `R_LARCH_IRELATIVE` | 12 | GNU IFUNC indirect relocation |
| `R_LARCH_TLS_TPREL64` | 11 | thread-local initial-exec offset |

---

## Function start detection

`from_path()` uses two heuristics:
1. Symbol table entries (`st_value` in `.symtab` / `.dynsym`) within `.text`.
2. `addi.d $sp, $sp, -N` (N > 0) instruction pattern — standard GCC/Clang prologue.

`from_path_full()` adds three DWARF/CFI data sources via `dwarf_loongarch64`:

| Source | Section | Stripped? | Yields |
|---|---|---|---|
| `.eh_frame` FDE records | `.eh_frame` | Present (GCC default) | Function start VAs |
| DWARF subprogram | `.debug_info` | Requires `-g` | Name + start + end VA |
| BTF func_info | `.BTF` + `.BTF.ext` | Kernel modules | Name + VA |

**Use `from_path_full()` for stripped TencentOS binaries** — `.eh_frame` recovers
leaf functions and tail-call-optimised bodies that have no `addi.d $sp` prologue.

```python
# Stripped binary — use from_path_full for complete function coverage
tt = LoongArch64TaintTracker.from_path_full("libssl.so.3.0.loongarch64")
findings = tt.run_interprocedural()
```

When `.debug_info` is present (debug packages), `high_pc` values are stored in
`tt._dwarf_ends` and used by `run()`/`run_interprocedural()` for precise function
end VAs instead of the next-function-start approximation.

### `dwarf_loongarch64` module

```python
from ablation.analyzers.dwarf_loongarch64 import (
    extract_eh_frame_starts,  # Set[int] — FDE initial_locations
    extract_debug_funcs,      # Dict[int, Tuple[str, int]] — va -> (name, end_va)
    extract_btf_funcs,        # Dict[int, str] — va -> name (kernel modules)
)
```

All three functions are best-effort: any missing section or parse error returns
an empty result without raising.

---

## Corpus

Development corpus: `/media/cowboy/research/TencentOS/LoongArch-RE/`
Primary validation targets (DWARF ground truth):
- `glibc-debuginfo` — standard library function boundaries and types
- `openssl-debuginfo` — crypto dispatch and TLS state machine
- `qemu-loongarch64-static-debuginfo` — user-mode emulator
- `kernel-debuginfo` (6.6.x) — privileged code, CSR instructions, atomics
