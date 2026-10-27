<a id="loongarch64-compiler-bug-detection"></a>
# LoongArch & nanoMIPS Analysis

Decode LoongArch64 and variable-width nanoMIPS instructions, then classify dangerous-call arguments with LoongArch64-specific calling conventions.

**Files:** `ablation/analyzers/loongarch_decoder.py` · `ablation/analyzers/nanomips_decoder.py` · `ablation/analyzers/sink_arg_classifier_loongarch64.py`

---

## LoongArch64 decoding

LoongArch64 instructions are fixed-width 32-bit little-endian words. `LoongArchDecoder` provides typed operands and frame-level control-flow information for binaries that Capstone does not handle.

```python
from ablation.analyzers.loongarch_decoder import LoongArchDecoder

decoder = LoongArchDecoder()
frames = decoder.decode_frames(text_bytes, base_addr=0x400000)

for frame in frames:
    if frame.is_call:
        print(f'call 0x{frame.va:x} -> 0x{frame.target:x}')
    elif frame.is_ret:
        print(f'return 0x{frame.va:x}')
```

`decode_one(data, va)` decodes one word. `decode_frames()` returns `LoongArchFrame` records with the address, mnemonic, operands, and control-flow metadata. `LoongArchOperand.reg_name` translates register indices into lp64 ABI names such as `$a0`, `$sp`, and `$fp`.

Use `LoongArchDisasm` when a disassembler-compatible frame interface is needed. Confirm that the input buffer begins on a four-byte instruction boundary; unsupported encodings and data embedded in `.text` require review rather than guessed semantics.

## nanoMIPS frame and instruction decoding

nanoMIPS instructions can be 16, 32, or 48 bits. The first halfword determines frame width, so the decoder must preserve variable-width boundaries instead of stepping through fixed 32-bit words.

```python
from ablation.analyzers.nanomips_decoder import NanoMIPSDecoder

decoder = NanoMIPSDecoder(endian='little')
frames = decoder.decode_frames(code_bytes, base_addr=0x80000000)

for frame in frames:
    print(
        f'0x{frame.va:x} [{frame.width * 8}-bit] '
        f'{frame.mnemonic} {frame.op_str}'
    )
```

When the installed Capstone provides `CS_MODE_NANOMIPS`, `has_full_decode()` reports full instruction support. Without it, the module still recovers frame widths and selected branch/call/return patterns, but unknown mnemonics are shown as `???`.

`NanoMIPSDisasm.stream()` provides a streaming interface, `find_function_starts()` proposes function boundaries, and `report_frames()` formats decoded frames. Endianness must match the target; incorrect endianness invalidates width and opcode decisions.

## LoongArch64 dangerous-call classification

`SinkArgClassifierLA64` classifies arguments at registered execution sinks using LoongArch64 register conventions:

```python
from ablation.analyzers.sink_arg_classifier_loongarch64 import SinkArgClassifierLA64

classifier = SinkArgClassifierLA64.from_path('/path/to/loongarch64-binary')
classifier.add_sink('vendor_exec', arg_pos=0)
results = classifier.classify_all()
print(classifier.report(results))
```

Use `from_context(ctx)` to reuse an existing binary context. Review `ARG_PROPAGATED` and `UNKNOWN` sites with taint analysis and manual disassembly. `RODATA_CONST` and fixed-format results reduce triage only when the recovered address and formatting behavior are correct.

## KASAN and compiler-defect analysis

For debug kernel builds, `LoongArchDecoderV2.from_system_map()` identifies KASAN/KCOV instrumentation addresses. For the GCC max-not-min pattern, use `LA64MaxNotMinScanner` and validate candidates in the production build rather than treating a debug hit as proof.

- [KASAN Finding Validation](../workflows/kasan-oracle.md)
- [Compiler Defects & Hardening](compiler-defects.md)

## Limitations

- Frame decoding is not complete semantic emulation. Unsupported instructions, self-modifying code, and data in text regions can reduce coverage.
- nanoMIPS fallback mode does not claim full mnemonic semantics when full Capstone support is absent.
- Sink verdicts are provenance heuristics, not proof of attacker control, runtime reachability, or exploitability.
- Architecture and ABI selection must match the actual target. Do not run the LoongArch64 classifier against nanoMIPS or another ISA.

## See also

- [Dangerous Call Classification](sink-arg-classifier.md): shared sink-verdict concepts and other architecture variants.
- [Function Discovery](stripped-function-discovery.md): recovers candidate functions before detailed analysis.
- [Data-Flow Taint Analysis](taint-analysis.md): confirms source-to-sink data flow.
