# FAQ

Common questions about Ablation.

---

## What does Ablation actually do?

Ablation is a static binary analysis toolkit for vulnerability research. It takes a stripped binary (firmware, kernel module, ECU ROM, application binary) and automates the work of finding attacker-controlled data paths that reach security-sensitive operations: format strings, shell injection, memory corruption, authentication bypasses.

It does not emulate, execute, or debug binaries. Everything is static.

---

## What architectures are supported?

ARM64, x86-64, x86-32, ARM32, Thumb/Thumb-2, MIPS-32, MIPS-64, nanoMIPS, PPC-32, PPC-64, RISC-V 32, RISC-V 64, ARC EM/HS, V850/RH850, LoongArch64, SH-2A, and BEAM (Erlang/Elixir). Plus ECU-specific ISAs: PPC VLE, MC68K/CPU32, TMS320C28x, M88K/MC88100, and HiSilicon custom RV32.

See [Decompiler and IR Lifter Concepts](concepts-decompiler.md#complete-tool-and-isa-reference) for the full reference.

---

## Why not just use Ghidra?

Ablation does not use Ghidra and does not depend on it. See [Why Ablation does not use Ghidra](concepts-decompiler.md#why-ablation-does-not-use-ghidra) in the concepts doc.

---

## What's the difference between a lifter and a decompiler?

A lifter translates machine code to architecture-neutral IR. A decompiler takes IR further to high-level C with SSA, loop structuring, and type inference. Ablation's `BinaryLifter` is a lifter. It stops at IR — you get pseudo-C that preserves the shape of the original code, not reconstructed source.

See [Decompiler and IR Lifter Concepts](concepts-decompiler.md) for the full explanation.

---

## TaintTracker is returning no results. Why?

Most common causes:

1. **No PLT symbols resolved.** `BinaryContext` needs to resolve PLT entries to import names. Check `ctx.summary()` — if PLT count is 0 on an ELF binary, the binary may be statically linked or use a non-standard PLT layout. Use `SinkArgClassifier` as a PLT-independent fallback.

2. **Wrong architecture.** The default is ARM64. For MIPS, PPC, etc., pass `arch=` explicitly.

3. **All sinks are RODATA_CONST.** If `SinkArgClassifier.classify_all()` shows every shell sink as RODATA_CONST, the binary likely has no command injection path. That's a real result.

4. **Binary is stripped of all function starts.** Check `ctx.func_starts` count. If it is very low, run `GoX86StripScanner` (for Go), `FlatBinaryFuncStartScanner` (for ECU ROMs), or `SemanticSearcher` queries to locate candidates manually.

---

## What is FORGE and why does it block my commit?

FORGE is a mandatory pre-commit security audit for new Ablation modules. It checks every new `ablation/analyzers/*.py` for the 10 most common security issues in binary analysis tools: path traversal, shell injection, integer overflow in parsers, etc.

The gate must pass before any new module is committed. See [FORGE](reference-modules/forge.md) and [Development](development.md#forge-gate).

---

## Can I use Ablation on Windows PE binaries?

Yes. `BinaryContext.load_or_build()` auto-detects PE format and builds an equivalent context (IAT as PLT, prologue scan for function starts, RIP-relative xref index). Seven dedicated Windows analyzers cover CFG, SafeSEH, ETW, RPC, COM, kernel pool overflow, and BYOVD. See [Windows PE Security Suite](reference-modules/windows-pe.md).

---

## What is the SemanticSearcher and when should I use it?

`SemanticSearcher` uses BERT embeddings to find functions that semantically resemble a vulnerability description. Use it at the start of every new binary or new vulnerability class — before any manual disassembly.

```python
candidates = SemanticSearcher.from_context(ctx, corpus).query('format string user input')
```

It operates over the disassembly corpus, not source code, so it works on stripped binaries.

---

## How do I persist findings between sessions?

Three mechanisms:

1. **`BinaryContext` name overlay** — `ctx.set_name(va, name, source='confirmed')` persists to the SHA-256-keyed cache. Names reappear on next `load_or_build()`.
2. **`FindingRegistry`** — stores confirmed findings with CWE, severity, and BERT embedding. Used for flywheel replay in future engagements.
3. **`re/<vendor>/<target>_re.py`** — per-target RE module in the local `re/` directory. Never committed to the ablation repo.

---

## Can I analyze encrypted firmware?

Yes, if you can recover the key. Ablation includes tools for the decryption side: `EntropyMapper` identifies encrypted regions, `XorSolver` recovers XOR keys, `FirmwareContainerKeyExtractor` handles FortiOS firmware key recovery, and `FortiGateCertKeyScanner` fingerprints recovered keys against a known-family corpus.

See [Firmware Analysis](reference-modules/firmware-analysis.md) and the [Fortinet Firmware workflow](workflows/fortinet-firmware.md).

---

## What file formats are supported for input?

ELF (32 and 64-bit, all supported ISAs), Windows PE (.exe, .dll, .sys), IBM AIX XCOFF (32 and 64-bit), flat ROM images (ECU firmware), BEAM files (Erlang/Elixir), DEX (Android), compiled MicroPython `.mpy`, ArkTS ABC (HarmonyOS), PS3 SELF (via decryptor), PEF (Mac OS 8/9 PowerPC), and various firmware container formats (SquashFS, CramFS, VMDK/OVF, BFF, PAK).
