# IBM z/OS Artifact Analysis

`ablation.zos_re` is a standalone, Python-standard-library-only toolchain for offline z/OS reverse engineering. It does not import or invoke Capstone, Ghidra, Radare2, `xmi`, or another disassembler/extractor.

## Capabilities

- **NETDATA and IEBCOPY:** Parses segmented INMR01/02/03/06 control records and text units, reassembles data records, handles PDS and PDSE directories, reconstructs primary members, resolves aliases by TTR, and rejects encrypted `AMSCIPHR` input explicitly.
- **Safe raw extraction:** Preserves primary bytes and metadata, validates dataset/member names, and creates relative alias links that work with relative or absolute output paths.
- **Unified load images:** Parses linked `IEWPLMH` program objects and traditional PDS load modules containing CESD, IDR, control, RLD, and TEXT records. Produces text bytes, file-offset/RVA mappings, symbols, entry metadata, EBCDIC strings, and SHA256 provenance.
- **Native S/390 decoding:** Decodes instruction lengths and common RR, RX, RS, SI, RI, RIL, RRE, RXE, RSE, and SS formats. Models direct branches, calls, conditional branches, and returns. Unknown opcodes retain their bytes and are marked `known=false`; they are never assigned invented mnemonics.
- **Function recovery:** Recognizes LE PPA trampolines, C++ PPA records with signed PPA offsets, non-XPLINK save/store prologs, and XPLINK register-4 save sequences. Optional recursive control-flow recovery follows branch targets without treating every call target as part of the caller.
- **Definition side-decks:** Parses FB80 EBCDIC input, both import syntaxes, CODE/DATA statements, and continued symbols. Continuation markers are removed from reconstructed symbols.
- **IBM C++ symbols:** Demangles verified constructor, destructor, operator, nested-name, qualifier, reference, pointer, and basic-type forms. Unsupported encodings remain `unparsed`. Correlates recovered names with side-deck symbols without inferring addresses.

## Command-line use

Run from the Ablation repository root:

```bash
python3 -m ablation.zos_re netdata-list INPUT.xmit
python3 -m ablation.zos_re netdata-extract INPUT.xmit OUTPUT_DIR
python3 -m ablation.zos_re image-info PROGRAM.bin --output IMAGE_DIR
python3 -m ablation.zos_re disasm PROGRAM.bin --start 0x0 --length 0x100
python3 -m ablation.zos_re functions PROGRAM.bin FUNCTIONS_DIR --cfg
python3 -m ablation.zos_re sid SIDEBIN SID_OUTPUT_PREFIX
python3 -m ablation.zos_re correlate PROGRAM.bin MATCHES.json SID1.bin SID2.bin
python3 -m ablation.zos_re pipeline INPUT.xmit OUTPUT_DIR --deep --cfg
```

`pipeline` extracts every dataset, parses each primary member, and writes `pipeline.json`. `--deep` also writes load images, strings, symbols, functions, and optional instruction-level CFG data. Unrecognized non-executable members remain `uninterpreted`; they are not forced through a loader.

Existing output files are not overwritten unless `--overwrite` is supplied where supported.

## Evidence and confidence

Function records distinguish:

- `PPA_LE`: high-confidence Language Environment PPA trampoline.
- `PPA_CPP`: high-confidence C++ PPA record, including signed PPA offsets.
- `SAVE_STORE_PROLOG`: medium-confidence non-XPLINK save/store candidate.
- `XPLINK_SAVE_STORE`: medium-confidence register-4 XPLINK save candidate.

Container entry fields and CESD labels are retained as anchors. An entry field alone is not promoted to a function. A zero PPA count is not reported as zero functions. CFG completion and unknown-instruction counts are recorded separately.

## Validation and failure behavior

- NETDATA must terminate with INMR06; truncated segments and text units are rejected.
- PDS directory entries and member sub-blocks are bounds-checked. Aliases must resolve to one primary target.
- PDS load modules must reach EOM and exact end-of-file. Conflicting overlapping TEXT and uncovered gaps are reported.
- Program objects without `IEWPSEGM` use the LMH text-record fallback and leave entry RVA `null`.
- Raw bytes and hashes are preserved in output metadata.

## Limitations

- The native decoder is intentionally conservative and does not yet cover every S/390, z/Architecture, floating-point, or privileged instruction. Unknown instructions remain explicit.
- RLD records and mappings are retained, but load-time relocation is not applied.
- Function candidates are not a claim of complete boundaries or complete program coverage. Medium-confidence prologs require analyst review.
- IBM C++ demangling is partial; templates and unfamiliar encodings can remain `unparsed`.
- No z/OS execution, Binder call-target resolution, vulnerability verdict, or dynamic validation is implied.
- Encrypted `AMSCIPHR` payloads and non-NETDATA tape formats are outside this module's current scope.

## Tests and quality gate

```bash
python3 -m pytest -q tests/test_zos_re.py
```

The suite includes synthetic format tests, malformed/truncated input tests, CLI tests, and IOC corpus golden tests. Corpus tests skip when `IBM_RE` is unavailable; set `IBM_RE=/path/to/IBM-RE` to enable them elsewhere.

Before committing new or modified Python files, run FORGE on each file as required by the project:

```bash
python3 -m ablation.analyzers.forge module ablation/zos_re/MODULE.py
```

## Source map

- `ablation/zos_re/netdata.py` — NETDATA, IEBCOPY, PDS/PDSE, aliases, safe extraction.
- `ablation/zos_re/loadmodule.py` — unified PDS and IEWPLMH loaders.
- `ablation/zos_re/image.py` — load-image model, output, and strings.
- `ablation/zos_re/s390.py` — native S/390 instruction decoding.
- `ablation/zos_re/functions.py` — PPA/prolog recovery and CFG construction.
- `ablation/zos_re/sid.py` — side-decks, IBM C++ demangling, inventory comparison, correlation.
- `ablation/zos_re/cli.py` — native command-line pipeline.
