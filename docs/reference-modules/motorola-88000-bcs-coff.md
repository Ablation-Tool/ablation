# Legacy Binary Formats

This page joins two unrelated legacy ingestion paths: Motorola MC88100 BCS COFF executables and Tandem Guardian PAK archives. They serve different platforms and should not be treated as one file format or one analysis pipeline.

---

## Why these paths exist

Legacy artifacts often fail before analysis begins: the host tools do not recognize the container or instruction set. A string scan may find a few clues, but it cannot establish function addresses, executable contents, or a safe extraction layout.

`coff_m88k_parser` and `M88kDecoder` recover MC88100 sections and instructions without Capstone. `GuardianPakExtractor` recovers files from Tandem's PAK/BACKUP archive layers without a NonStop system. Both are small enabling components: they make later architecture-specific review possible without claiming to provide a complete decompiler or live-platform model.

---

## Motorola MC88100 BCS COFF

The COFF parser recognizes magic `0x016d`, reads 44-byte section headers, and exposes text/data bytes and entry metadata. The decoder handles selected fixed-width, big-endian MC88100 operations, direct call targets, and `OR.U`/`OR` constant-construction pairs.

```python
from ablation.core.coff_m88k_parser import parse
from ablation.analyzers.insn_m88k import M88kDecoder

binary = parse('/path/to/mc88100.coff')
decoder = M88kDecoder(binary)

for insn in decoder.disassemble_va(binary.entry, max_insns=40):
    print(insn)

print([hex(va) for va in sorted(decoder.function_starts())])
for code_va, data_va in sorted(decoder.string_refs().items()):
    print(f'{code_va:#x} -> {data_va:#x}')
```

`function_starts()` collects direct BSR and BSR.N targets inside `.text`. It does not scan for `subu`/`st` prologues, despite an older version of this page saying so. These candidates omit functions reached only indirectly and can include targets that are not authoritative boundaries.

`string_refs()` reports address pairs that resolve into `.data`; the referenced bytes are not automatically printable strings, attacker input, or taint evidence. Some triadic operations remain placeholders, and no generic `BinaryLifter` backend is provided.

See [Motorola MC88100 COFF Disassembly](m88k-decoder.md) for the focused decoder reference.

---

## Tandem Guardian PAK

A Guardian patch can have a `.ZIP` suffix without being a ZIP archive. Its outer PAK stream contains zlib-compressed chunks; those chunks contain Guardian BACKUP records. Record type codes vary between archive runs, so the extractor uses record sizes and content signatures instead of treating one observed type code as authoritative.

File-header records preserve the three-component `$VOLUME.SUBVOLUME.FILENAME` namespace. Consecutive data records are joined into the corresponding `GuardianFile` payload.

```python
from pathlib import Path
from ablation.core.guardian_pak_extractor import iter_files

raw = Path('/path/to/patch.zip').read_bytes()
for item in iter_files(raw):
    print(item.path, len(item.data), item.arch)
    if item.filename == 'MQMSVR':
        mips_payload = item.data
```

The recovered `arch` label is `mips32be` for the validated Himalaya K-series artifacts. This lets users move from archive inventory to MIPS-aware analysis without requiring the original NonStop host.

See [Guardian PAK Extraction](guardian-pak-extractor.md) for chunk rules, disk extraction, and safety limits.

---

## What these components add

Both paths remove a container-specific dead end while preserving a clean boundary for later tools. Additional M88K instruction semantics can extend the decoder; additional validated Guardian record idioms can extend the extractor. Neither requires the other, and either can be replaced independently.

Successful parsing is not a security result. Verify candidate functions and references against raw bytes, and review extracted MIPS programs for actual imports, call reachability, and input provenance before assigning a vulnerability verdict.

---

## Limitations

- M88K instruction and function discovery coverage is partial; indirect calls and unsupported function-code fields need manual analysis.
- COFF section metadata must be correct before virtual addresses can be trusted.
- Guardian chunk decompression and file accumulation do not enforce a global expanded-output budget. Pre-screen untrusted input and apply external resource limits.
- Guardian `extract_to()` maps archive components into directories but does not provide a general hostile-path containment proof. Prefer in-memory `iter_files()` for untrusted archives and validate output names before writing them.
- Corrupt compressed Guardian chunks are skipped by the current iterator, so successful extraction does not prove complete archive recovery.
- Recovered architecture labels and filenames do not establish runtime reachability or safe payload behavior.

---

## See also

- [Motorola MC88100 COFF Disassembly](m88k-decoder.md)
- [Guardian PAK Extraction](guardian-pak-extractor.md)
- [MIPS Decompilation & Taint Analysis](mips.md)
- [Legacy Binary Parsing](binary-format-and-platform-identification.md)
