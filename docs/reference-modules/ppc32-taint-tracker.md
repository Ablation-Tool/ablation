<a id="ppc32tainttracker"></a>
# PowerPC Decompilation & Taint Analysis

Analyze 32- and 64-bit PowerPC ELF functions with structural pseudo-C lifting and architecture-specific taint trackers. Specialized backends cover IBM PPC476, NXP PowerPC VLE, and AIX XCOFF32; those formats should not be treated as interchangeable with generic PowerPC ELF.

## Generic structural lifting

```python
from ablation.analyzers.binary_lifter import BinaryLifter

lifter = BinaryLifter.from_path('/path/to/powerpc.elf', arch='ppc32')
print(lifter.lift_function(0x10010400))
```

Use `arch='ppc64'` for the 64-bit structural backend. Both backends emit calls, branches, and returns with ABI register names; unmodeled arithmetic remains comments. For PPC32, argument and initial return registers follow the `r3`–`r10` convention. For PPC64, the backend uses the ELFv2 register model.

## PPC32 taint analysis

```python
from ablation.analyzers.taint_tracker_ppc32 import PPC32TaintTracker

tracker = PPC32TaintTracker.from_path('/path/to/ppc32.elf', endian='big')
findings = tracker.run()
paths = tracker.run_interprocedural(depth=4)
print(tracker.report(findings))
```

`from_context(ctx, endian=...)` is also available. The tracker models common PPC32 instructions, PLT calls, and GOT2 position-independent call sequences. Its default endianness is big; select `little` explicitly where needed. GOT2 and raw-dynamic-symbol fallbacks help with some embedded ELFs, but do not guarantee resolution of every vendor-specific relocation layout.

## PPC64 taint analysis

```python
from ablation.analyzers.taint_tracker_ppc64 import PPC64TaintTracker

tracker = PPC64TaintTracker.from_path('/path/to/ppc64.elf', endian='little')
findings = tracker.run()
paths = tracker.run_interprocedural(depth=4)
```

The 64-bit tracker has its own instruction and ABI model. Do not substitute the PPC32 tracker for a 64-bit binary.

## Specialized paths

- [IBM PPC476 Pseudo-C Lifting](ppc476-lifter.md): linear, register-tracked PPC32 big-endian lifting with PLT argument annotations.
- [PowerPC VLE Decoding](ecu-vle-decoder.md): pure-Python 16-/32-bit VLE decoding and function-start recovery for NXP automotive ROMs.
- [AIX XCOFF32 Decompilation](xcoff32-decompiler.md): AIX function descriptors, TOC-relative names, and PPC32 pseudo-C.

## Limitations

- The generic lifter is structural, not a full C decompiler.
- `read`-like sources often taint a returned byte count rather than proving that the receive buffer is tracked. Verify buffer data flow independently.
- Incorrect endianness, missing PLT/GOT mappings, unresolved indirect calls, and incomplete function boundaries can silently reduce coverage.
- A taint path is a review candidate. Confirm source control, call reachability, sanitization, and sink arguments before reporting a vulnerability.

## Related workflows

- [Native Binary Lifting](binary-lifter.md)
- [PowerPC VLE Decoding](ecu-vle-decoder.md)
- [AIX XCOFF32 Decompilation](xcoff32-decompiler.md)
