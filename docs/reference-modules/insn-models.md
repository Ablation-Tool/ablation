# Instruction Models insn_arc, insn_x86

Instruction representation, operand parsing, and disassembler backends for ARC EM/HS (`insn_arc.py`) and x86/x86-64 (`insn_x86.py`). These modules define the `Insn` dataclass that every taint tracker, CFG builder, and analysis engine operates on.

---

## Why this exists

1. **Taint trackers and CFG builders need a unified instruction type, not raw strings.** Capstone, objdump, and hand-written listings all produce different text forms. The `Insn` dataclass provides a single normalized representation with typed operands (`Reg`, `Imm`, `Mem`) that downstream tools query without parsing strings themselves.

2. **ARC has no Capstone backend; x86 has three text formats.** `insn_arc.py` provides a pure-Python decoder for GNU objdump text output: the only practical disassembly path for ARC EM/HS. `insn_x86.py` handles Intel listing, AT&T objdump auto-converted, and Capstone structured output. Without this layer, each tool would implement its own text parser.

3. **Operand typing enables safe taint propagation.** A `Reg` operand carries the register name; a `Mem` operand carries base/index/displacement; an `Imm` carries the immediate value. Taint trackers query `insn.operands[0]` and branch on type rather than parsing instruction text for every propagation step.

---

## Modules

| Module | Arch | Backends |
|:---|:---|:---|
| `insn_arc.py` | ARC EM/HS (ARCv2) | GNU objdump text / hand listing |
| `insn_x86.py` | x86 / x86-64 | Intel listing, AT&T objdump, Capstone structured |

---

## Insn dataclass

```python
@dataclass(frozen=True)
class Insn:
    va: int            # virtual address
    size: int          # instruction byte count
    mnemonic: str      # normalized (lower-case, no suffix)
    operands: tuple    # (Reg | Imm | Mem | RegList | ...) typed operands
```

All `Insn` instances are frozen hashable, so they can be used as CFG block contents directly.

---

## Operand types

```python
Reg(name: str)                    # register, name is canonical from isa_*
Imm(value: int, size: int = 0)    # immediate
Mem(base, index, disp, segment)   # memory reference
```

---

## Backends

**`insn_arc.py`**: `from_listing(text)` / `from_objdump(text)`:

```python
from ablation.analyzers.insn_arc import from_listing, from_capstone

insns = list(from_listing("""
    0x10: mov_s r0,r1
    0x12: j_s [blink]
"""))
```

**`insn_x86.py`**: three entry points:

```python
from ablation.analyzers.insn_x86 import from_listing, from_objdump, from_capstone

# From Intel hand listing
insns = list(from_listing("  0: mov rdi, [rbp+0x10]\n  7: call 0x1234"))

# From objdump (AT&T auto-converted to Intel)
insns = list(from_objdump(subprocess.check_output(["objdump", "-d", binary])))

# From Capstone structured output  
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
insns = list(from_capstone(md.disasm(code, va)))
```

---

## AT&T → Intel conversion (`insn_x86.py`)

`att_to_intel(line)` converts objdump AT&T syntax to Intel before parsing. Key transformations:
- Reversed operand order (`movq %rsi,%rdi` → `mov rdi, rsi`)
- Size suffixes stripped (`movq` → `mov`, `cmpb` → `cmp`)
- `%reg` prefixes stripped
- `$imm` → bare immediate
- `disp%base,%index,scale` → `[base+index*scale+disp]`

---

## See also

- [ISA Models](isa-models.md): register canon and ABI constants imported by these modules
- [Analysis Engine](analysis-engine.md): uses `Insn` lists as CFG block contents
- [Taint Analysis](taint-analysis.md): taint trackers that consume `Insn` sequences
