<a id="binaryliftersh2a"></a>
# Renesas SH-2A Flat-ROM Lifting

The SH-2A backend of `BinaryLifter` lifts Renesas SuperH functions to annotated structural pseudo-C. It supports headerless flat ROM images where virtual addresses equal file offsets and models common calls, branches, delay slots, loads, stores, and returns.

## Why flat-ROM support is explicit

A headerless ROM does not carry the section map an ELF lifter expects. Directly treating file offsets as virtual addresses can be useful, but only when that mapping matches the target. Making this a dedicated backend keeps the assumption visible instead of silently applying it to every binary.

The decoder supplies calls, delay slots, and common memory operations; the lifter organizes them into a bounded review form. Users gain a faster way to navigate SH-2A routines without mistaking structural output for complete semantics. This is a focused compatibility backend that can later consume richer CFG or instruction support, while the raw decoder remains available for independent verification. Rebased images and unmodeled extensions still need manual mapping and review.

## Usage

```python
from ablation.analyzers.binary_lifter import BinaryLifter

lifter = BinaryLifter.from_path('/path/to/sh7058.bin', arch='sh2a')
print(lifter.lift_function(0x1000))
```

`sh-2a` and `sh2` are aliases. The default `BinaryLifter` architecture is ARM64, so selecting SH-2A explicitly is required.

Provide known function names through the public constructor when available:

```python
lifter = BinaryLifter(
    '/path/to/sh7058.bin', arch='sh2a',
    func_names={0x2400: 'can_rx_handler'},
)
print(lifter.lift_function(0x2400))
```

`with_taint(findings)` copies compatible register annotations from taint findings. The older `_names` and `_taint_map` attributes are implementation details; prefer the constructor and `with_taint()` interfaces for new code.

## Flat-ROM behavior

ELF and PE backends translate virtual addresses through a section map. When no section map exists, the SH-2A backend reads the function VA directly as a file offset. This is valid only when the ROM's analysis address equals its buffer offset. Rebased or segmented images need an appropriate mapping rather than blind use of this fallback.

The lifter stops at the first modeled return plus its delay-slot instruction and honors `max_insns`. This avoids walking indefinitely through padding but can truncate functions with earlier conditional returns or unusual control flow.

## Output model

- BSR calls become named calls when a direct target and name are known.
- JSR through a register remains an indirect call expression.
- BT/BF branches use `T`/`!T`; the lifter does not recover the instruction that established the T bit.
- Delay-slot instructions remain visible after the associated call, branch, or return.
- Unmodeled instructions, including many SH-2A extensions, remain comments.
- Loads, stores, and immediate moves receive simple pseudo-C expressions; this is not complete semantic IR.

## Limitations

This backend is a bounded structural walk, not a full CFG-structured decompiler. Indirect targets, loops, alternate returns, extension instructions, and missing function names reduce readability. Verify conditions and security-relevant arguments against `EcuSH2aDecoder` output before drawing conclusions.

## Related workflows

- [Native Binary Lifting](binary-lifter.md)
- [Renesas V850 / RH850 Lifting & Taint Analysis](v850-rh850.md)
- [Motorola M68K / CPU32 Decoding](ecu-m68k-decoder.md)
