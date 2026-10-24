# BinaryContext: New Analysis Helpers

## Why these methods exist

Four gaps motivated this addition:

1. No packing pre-screen existed. Running full analysis on a packed binary wastes analysis time and produces false results.
2. PUSHAD-at-entry is a mechanical packer signature on x86 that can be checked in under 32 bytes, earlier than any semantic analysis.
3. Alternate Data Stream references in PE binaries are a data-hiding technique not covered by any existing Ablation scanner.
4. CPUID followed by a conditional branch is a reliable VM-detection heuristic used in malware; no Ablation method returned those VAs.

## New methods

### `plt_sparsity_warning(threshold=6)`

Returns a warning string when the PLT import count is below `threshold`, or `None` when not sparse.

The canonical packer footprint is 3 to 5 imports: `VirtualAlloc`, `LoadLibrary`, `GetProcAddress`. Use alongside `EntropyAnalyzer` to gate pre-analysis packing detection. Returns `None` when not sparse.

```python
warning = ctx.plt_sparsity_warning()
if warning:
    print(warning)
    # [PLT_SPARSE] 4 import(s) below threshold 6 — possible packer stub: ...
```

### `pushad_at_entry()`

Returns `True` when a `PUSHAD` or `PUSHA` instruction appears within the first 32 bytes of the ELF entry point. x86 only; returns `False` for all other architectures.

On x86 firmware, PUSHAD at entry is a strong packer signature: the packer saves all registers, unpacks to a new region, then POPAD and JMP to the original entry point. Requires lief for EP location.

```python
if ctx.pushad_at_entry():
    print("x86 packer detected: PUSHAD at entry point")
```

### `ads_reference_vas()`

Returns a list of VAs of `CreateFileA`/`NtCreateFile` call sites whose nearby string table contains a colon character, indicating an Alternate Data Stream path.

Only meaningful for PE binaries. Returns `[]` for ELF targets.

```python
ads_vas = ctx.ads_reference_vas()
for va in ads_vas:
    print(f"ADS reference at 0x{va:x}: {ctx.name(va)}")
```

### `cpuid_locations()`

Returns VAs of `CPUID` instructions that are followed by a conditional branch within the next 5 instructions. x86 and x86-64 only.

CPUID plus conditional branch is a VM-detection heuristic: malware checks the hypervisor bit in ECX or inspects the vendor string to detect analysis environments.

```python
cpuid_vas = ctx.cpuid_locations()
if cpuid_vas:
    print(f"{len(cpuid_vas)} CPUID+branch patterns found (VM detection)")
```

## Severity and triage

These methods return VAs or warning strings, not `Finding` objects. Callers are responsible for creating findings via `FindingRegistry.register()`. Suggested severities:

| Method | Suggested severity | Condition |
| ------ | ------------------ | --------- |
| `plt_sparsity_warning()` | MEDIUM | packing confirmed by EntropyAnalyzer |
| `pushad_at_entry()` | HIGH | True on a non-test binary |
| `ads_reference_vas()` | HIGH | any VA returned |
| `cpuid_locations()` | MEDIUM | 3 or more VAs returned |
