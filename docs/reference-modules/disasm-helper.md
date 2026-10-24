# _disasm_helper: Shared Disassembly Utility

## Why this exists

Three gaps motivated this module:

1. Ten modules in `modules/` assumed a `ctx.disasm_func()` method that does not exist on `BinaryContext`. Each called it and silently returned nothing.
2. Duplicating capstone setup across every module that needs disassembly produces inconsistent arch-to-mode mapping and makes arch support fixes require touching every module.
3. A single helper with explicit arch-to-capstone-constant dispatch ensures consistent behavior and a single place to add new architecture support.

## disasm_func

Disassembles the function at `func_va` using the architecture from `ctx.arch`, reading bytes from `ctx.path` starting at `func_va - ctx.base_va`.

Returns a list of capstone `CsInsn` objects. Returns `[]` on any error including missing capstone, file read failure, VA out of range, or unsupported architecture.

```python
from modules._disasm_helper import disasm_func

insns = disasm_func(ctx, func_va)
for insn in insns:
    print(f"0x{insn.address:x}  {insn.mnemonic}  {insn.op_str}")
```

## Architecture support

| `ctx.arch` values | Capstone mode |
| ----------------- | ------------- |
| `x86_64` | CS_ARCH_X86 + CS_MODE_64 |
| `x86`, `i386`, `i686` | CS_ARCH_X86 + CS_MODE_32 |
| `arm64`, `aarch64` | CS_ARCH_AARCH64 + CS_MODE_ARM |
| `arm`, `armv7`, `armv7l` | CS_ARCH_ARM + CS_MODE_ARM |
| `mips`, `mipsel` | CS_ARCH_MIPS + CS_MODE_MIPS32 with endianness |
| `ppc64`, `ppc64le`, `powerpc` | CS_ARCH_PPC + CS_MODE_64 with endianness |

Unsupported architectures return `[]` without raising.

## Parameters

`ctx`: a `BinaryContext` instance. Uses `ctx.arch` (str), `ctx.path` (str), and `ctx.base_va` (int).

`func_va`: virtual address of the function start. Must be within the binary's mapped range.

`max_bytes`: maximum bytes to disassemble starting from `func_va`. Default 4096. Disassembly stops at a capstone decoding boundary or at `max_bytes`, not at the function end. Callers must check that returned instruction addresses fall within the intended function.

## Notes

Capstone is a soft dependency. If capstone is not installed, `disasm_func()` returns `[]` without raising. Modules that use this helper degrade gracefully when capstone is absent.

This module is internal infrastructure. It is not a scanner and does not produce findings.
