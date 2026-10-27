<a id="isa-and-abi-models"></a>
# Architecture & ABI Models

Normalize x86 instruction listings and provide shared x86/x86-64 register, calling-convention, and Linux syscall models for analysis tools.

**Files:** `ablation/analyzers/insn_x86.py` · `ablation/analyzers/isa_x86.py`

---

## What these modules do

`insn_x86.py` turns Capstone instructions or objdump-style text into a common `Insn` representation with typed operands. `isa_x86.py` supplies architecture facts that would otherwise be duplicated across instruction parsers, taint trackers, and control-flow analysis.

Together they let downstream code ask consistent questions such as:

- Is this operand a register, immediate, memory reference, or symbol?
- Which register family does `eax`, `ax`, or `al` belong to?
- Which registers carry arguments under System V AMD64, Microsoft x64, or i386 cdecl?
- Which registers does a call clobber, and which syscall number and argument registers apply in this mode?

## Supported modes and ABIs

| Mode | ABI | Argument passing |
|:---|:---|:---|
| `Mode.X64` | `Abi.SYSV64` | Integer arguments in `rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9`; floating-point arguments in XMM registers. |
| `Mode.X64` | `Abi.WIN64` | Integer arguments in `rcx`, `rdx`, `r8`, `r9`; 32 bytes of shadow space. |
| `Mode.X86` | `Abi.CDECL32` | Arguments on the stack; integer return values in `eax`/`edx`. |

`Abi.default_for(mode)` selects System V for x86-64 and cdecl for 32-bit x86. Select `Abi.WIN64` explicitly for Microsoft x64 code.

## Instruction parsing

Use `from_capstone()` when raw instruction bytes are available:

```python
from ablation.analyzers.insn_x86 import from_capstone
from ablation.analyzers.isa_x86 import Mode

code = bytes.fromhex('4889d8')  # mov rax, rbx
insns = from_capstone(code, mode=Mode.X64, base=0x1000)

for insn in insns:
    print(hex(insn.address), insn.mnemonic, insn.op_str)
    print('next instruction:', hex(insn.next_ip()))
```

Use `from_objdump()` or `from_listing()` for textual disassembly:

```python
from ablation.analyzers.insn_x86 import from_objdump
from ablation.analyzers.isa_x86 import Mode

listing = '1000: 48 89 d8    mov %rbx,%rax'
insns = from_objdump(listing, mode=Mode.X64)
```

`att_to_intel()` and `looks_like_att()` help normalize AT&T operands. `rip_relative_target()` resolves a RIP-relative memory operand to its target address.

### Operand types

| Type | Meaning |
|:---|:---|
| `Reg` | A register name, including SIMD and segment registers recognized by the model. |
| `Imm` | An immediate integer. |
| `Mem` | A memory expression with base, index, scale, displacement, and optional size. |
| `Sym` | A symbolic target such as a function or label. |

Use `insn.reg(i)`, `insn.imm(i)`, or `insn.mem(i)` when a typed operand is required; these accessors return `None` when the operand has another type.

## Register aliases and widths

`reg_info()` returns a `RegInfo` record containing the spelling used, register family, lowest bit, and width:

```python
from ablation.analyzers.isa_x86 import Mode, is_reg, reg_info

for name in ('rax', 'eax', 'ax', 'al'):
    info = reg_info(name, Mode.X64)
    print(name, info.family, info.low, info.width, hex(info.mask))

assert is_reg('xmm0', Mode.X64)
assert not is_reg('not_a_register', Mode.X64)
```

In x86-64 mode, all four examples above belong to the `rax` family, but they represent different widths. This distinction matters: a 32-bit write zero-extends, while 8-bit and 16-bit writes preserve other bits. SIMD aliases such as `ymm0` and `zmm0` belong to the `xmm0` family with different widths.

## Calling-convention queries

```python
from ablation.analyzers.isa_x86 import Abi, abi_for

sysv = abi_for(Abi.SYSV64)
print(sysv.arg_regs)
print(sysv.caller_saved)
print(sysv.callee_saved)

win64 = abi_for(Abi.WIN64)
assert win64.shadow_space == 32
```

An `AbiModel` also exposes floating-point argument and return registers, return registers, and whether stack arguments are used.

## Linux syscall models

```python
from ablation.analyzers.isa_x86 import INPUT_SYSCALLS, Mode, syscall_model

model = syscall_model(Mode.X64)
print(model.nr_reg)       # rax
print(model.arg_regs)     # rdi, rsi, rdx, r10, r8, r9
print(model.numbers[0])   # read
assert 'read' in INPUT_SYSCALLS
```

The x86 and x86-64 models have different syscall registers and number tables. `INPUT_SYSCALLS` is a shared set of syscall names commonly treated as input sources; it is not a complete list of every possible attacker-controlled source.

## Mnemonic normalization

`normalize_mnemonic()` returns `(prefixes, canonical_mnemonic)`. It separates prefixes such as `lock` and `rep`, normalizes common AT&T spellings and operand-size suffixes, and folds condition-code aliases for jumps, conditional moves, and byte-set instructions.

`imm_bound_after_and()` computes a conservative upper bound after a non-negative immediate `AND`; it returns `None` when the sign-extended mask does not justify that bound.

## Limitations

- These modules model x86 and x86-64 only. Other architecture-specific ISA modules provide their own interfaces.
- A parsed `Insn` is a syntactic representation, not proof that bytes are reachable instructions or that a calculated path is feasible.
- The syscall tables cover common Linux entries rather than every syscall on every platform. Windows and other operating systems require separate models.
- Calling-convention models describe defaults. Compiler optimizations, hand-written assembly, variadic functions, and custom conventions require manual review.

## See also

- [Control & Data-Flow Analysis](control-flow-graph-construction.md): uses architecture models when building CFGs and data-flow analyses.
- [Data-Flow Taint Analysis](taint-analysis.md): relies on register and calling-convention semantics.
- [Register & Argument Tracking](call-argument-annotation.md): applies argument provenance at call sites.
