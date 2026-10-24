# Supplementary Capability Records: Phase 1 Unmapped Files

Six files identified by the COVERAGE agent as uncovered in the Phase 1 audit.
Each gets one capability record below. Directory checks included.

---

## Directory inventory

**`ablation/export/`** — 2 Python files (plus `__init__.py`):
- `json_export.py`
- `sarif.py`

**`ablation/integrations/`** — 1 Python file (plus `__init__.py`):
- `binja_plugin.py`

No other files exist in either directory.

---

## Capability: CLI Entry Point (`ablation.cli`)

- **name:** `ablation.cli.main` / `cmd_*` dispatch functions
- **category:** CLI / Package Entry Point
- **paths:** `ablation/ablation/cli.py` (lines 1–1317)
- **entry_point:** `main()` via argparse; installed as `ablation = "ablation.cli:main"` in `pyproject.toml`; also `ablation-search`, `ablation-taint`, `ablation-cfg`, `ablation-sigs` secondary entry points pointing to per-module `_cli` functions
- **what_it_does:** Implements the `ablation` command-line tool using argparse. Dispatches 30+ subcommands to their respective analyzer modules with lazy imports, validates binary paths, and handles `--json`/`--sarif` output flags for commands that support structured export. Also embeds a versioned `_RECENT_UPDATES` news string surfaced by `ablation news`.
- **inputs:** Command-line arguments (binary path, hex VA, query string, flags). Binary files validated by `_require_binary()` before dispatch.
- **outputs:** Printed analysis results to stdout; optionally writes JSON or SARIF 2.1.0 files via `--json FILE` / `--sarif FILE` flags. Exit code 1 on error.
- **scope:** All subcommands registered:

  | Subcommand | Analyzer dispatched | Output formats |
  |---|---|---|
  | `analyze` | `BinaryContext`, `EntropyMapper` | text; `--entropy` flag |
  | `search` | `SemanticSearcher`, `CorpusBuilder` | text |
  | `taint` | `TaintTracker` (x86), `ARM32TaintTracker`; flags `--interprocedural`, `--flow-sensitive`, `--depth` | text |
  | `overflow` | `ARM32IntOverflowScanner` | text |
  | `window` | `WindowAnalyzer`; flags `--window`, `--back`, `--calls`, `--funcs` | text |
  | `profile` | `FuncProfiler` | text |
  | `cfg` | `CFGBuilder`; flag `--insns` | text |
  | `crypto` | `scan_firmware_file` (core) | colored text |
  | `corpus` | `CorpusBuilder`; flags `--product`, `--version`, `--sigs` | text |
  | `sweep` | `PatternLibrary.sweep()`, `SemanticSearcher`; flags `--top-k`, `--min-score` | text / JSON / SARIF |
  | `driver` | `KernelDriverAnalyzer` | text / JSON |
  | `byovd` | `BYOVDDetector` | text / JSON |
  | `fmtstr` | `FormatStringScanner` | text / JSON |
  | `heap` | `HeapVulnScanner` | text / JSON |
  | `mips` | `MIPS32TaintTracker`; flag `--le` | text / JSON |
  | `mips64` | `MIPS64TaintTracker`; flags `--le`, `--interprocedural`, `--depth` | text / JSON |
  | `nanomips` | `NanoMIPSDisasm`; flags `--le`, `--base`, `--frames`, `--limit` | text / JSON |
  | `nanomips-taint` | `NanoMIPSTaintTracker`; flags `--le`, `--interprocedural`, `--depth` | text / JSON |
  | `ppc32` | `PPC32TaintTracker`; flags `--le`, `--interprocedural`, `--depth` | text / JSON |
  | `ppc64` | `PPC64TaintTracker`; flags `--le`, `--interprocedural`, `--depth` | text / JSON |
  | `riscv32` | `RISCV32TaintTracker`; flags `--interprocedural`, `--depth` | text / JSON |
  | `riscv64` | `RISCV64TaintTracker`; flags `--interprocedural`, `--depth` | text / JSON |
  | `arc` | `ARCTaintTracker`; flags `--be`, `--interprocedural`, `--depth` | text / JSON |
  | `arc-decode` | `ARCDisasm`; flags `--be`, `--base`, `--frames`, `--limit` | text / JSON |
  | `v850` | `V850TaintTracker`; flags `--be`, `--interprocedural`, `--depth` | text / JSON |
  | `v850-decode` | `V850Disasm`; flags `--be`, `--base`, `--frames`, `--limit` | text / JSON |
  | `loongarch64` | `LoongArch64TaintTracker`; flags `--interprocedural`, `--depth`, `--full` | text / JSON |
  | `loongarch64-decode` | `LoongArchDecoder`; flags `--base`, `--frames`, `--limit` | text / JSON |
  | `news` | `_RECENT_UPDATES` string | text |
  | `findings` | `FindingRegistry` | text / JSON / SARIF |
  | `sigs` | `SigLibrary`; flags `--db`, `--threshold`, `--dry-run`, `--list` | text |

- **status:** implemented
- **evidence:** No dedicated CLI tests found in Phase 1 audit; CLI is the package's public surface and all subcommands are reachable via `argparse`
- **docs:** No dedicated reference doc exists in `docs/reference-modules/`. The module-level docstring (lines 1–28) serves as the usage reference. The `_RECENT_UPDATES` string (lines 401–581) documents per-version subcommand additions through v3.4.0.
- **limitations:**
  - `--debug` flag (sys.argv check at line 1311) is not wired into argparse; it is detected post-parse via `sys.argv` scan — no `--help` entry
  - `cmd_loongarch64_decode` routes function-start discovery through `LoongArch64TaintTracker._get_func_starts()` rather than `LoongArchDecoder` directly
  - No `--sarif` output on per-arch taint subcommands (mips, mips64, arc, riscv32/64, ppc32/64, v850, nanomips, loongarch64); only `sweep` and `findings` emit SARIF
- **dependencies:** argparse, pathlib; all analyzer imports are lazy (inside cmd_* functions)
- **claims_to_verify:** Docstring states `ablation taint <binary>` is "arch-aware" — confirmed: ARM32 branches to `ARM32TaintTracker`, x86 to `TaintTracker`

---

## Capability: JSON Export (`ablation.export.json_export`)

- **name:** `sweep_to_json`, `findings_to_json`, `write_json`, `write_sarif`
- **category:** Export / Output Formatting
- **paths:** `ablation/ablation/export/json_export.py` (lines 1–66)
- **entry_point:** `sweep_to_json(sweep_results, binary_path, min_score=0.0) → dict`; `findings_to_json(findings) → dict`; `write_json(data, path, indent=2)`; `write_sarif(data, path, indent=2)`
- **what_it_does:** Converts `PatternLibrary.sweep()` results and `FindingRegistry.list_findings()` output to a flat custom JSON schema. `write_json` and `write_sarif` are thin wrappers around `json.dumps` + `Path.write_text` — both write the same way; the `write_sarif` name exists for call-site clarity.
- **inputs:** `sweep_results`: `dict[str, SweepResult]` from `PatternLibrary.sweep()`. `findings`: `List[dict]` from `FindingRegistry.list_findings()`. `binary_path`: string path to analyzed binary.
- **outputs:** Custom JSON dict with schema:
  ```
  sweep_to_json → {
    "binary": "<resolved_absolute_path>",
    "findings": [{"tag": str, "pattern": str, "hits": [{"va": "0xXXXX", "score": float}]}],
    "total_hits": int
  }
  findings_to_json → {
    "findings": [<raw finding dicts from FindingRegistry>],
    "total": int
  }
  ```
- **scope:** Sweep results and confirmed findings only; does not serialize BinaryContext or corpus data
- **status:** implemented
- **evidence:** Exercised by `cmd_sweep` and `cmd_findings` in cli.py when `--json FILE` flag is passed
- **docs:** `docs/reference-modules/json-and-sarif-export.md` — covers both this module and sarif.py accurately. Match verdict: **accurate**. Note: the reference doc shows `findings_to_json(findings, binary_path=...)` with an optional `binary_path` parameter that does not exist in the actual function signature (findings_to_json takes only `findings`). Minor discrepancy.
- **limitations:** `write_sarif()` in this module is identical to `write_json()` — it does not validate SARIF structure. Use `ablation.export.sarif` for actual SARIF generation.
- **dependencies:** json, pathlib (stdlib only)
- **claims_to_verify:** Reference doc claims `min_score=0.75` is the "standard sweep threshold" — the CLI default in `cmd_sweep` is `--min-score 0.30`; 0.75 is not the default anywhere in the codebase

---

## Capability: SARIF 2.1.0 Export (`ablation.export.sarif`)

- **name:** `sweep_to_sarif`, `findings_to_sarif`, `_severity_to_sarif`
- **category:** Export / Standards-Compliant Output
- **paths:** `ablation/ablation/export/sarif.py` (lines 1–203)
- **entry_point:** `sweep_to_sarif(sweep_results, binary_path, min_score=0.0) → dict`; `findings_to_sarif(findings, binary_path=None) → dict`
- **what_it_does:** Produces SARIF 2.1.0 documents consumable by GitHub Code Scanning, VS Code Problems panel, and OASIS-compliant SAST platforms. `sweep_to_sarif` maps each semantic pattern hit to a SARIF `result` with a `ruleId` derived from tag+query slug, `level: warning`, and an `artifactLocation` using the binary's `file://` URI. `findings_to_sarif` converts confirmed `FindingRegistry` findings using CWE as `ruleId` and maps severity to SARIF levels via `_severity_to_sarif`.
- **inputs:**
  - `sweep_results`: `dict[str, SweepResult]` from `PatternLibrary.sweep()`
  - `findings`: `List[dict]` from `FindingRegistry.list_findings()` — expected keys: `cwe`, `severity`, `title`, `vendor`, `product`, `created_at`
  - `binary_path`: string file path (converted to `file://` URI via `Path.as_uri()`)
- **outputs:** SARIF 2.1.0 dict with full `$schema`, `version`, `runs[].tool.driver` (name=Ablation, version from `importlib.metadata`), `runs[].artifacts`, `runs[].rules`, `runs[].results`. Suitable for `json.dumps` then upload or file write.
- **scope:** Sweep results and confirmed findings. Does not cover per-arch taint tracker output (no SARIF path from mips/ppc/riscv subcommands).
- **status:** implemented
- **evidence:** Exercised by `cmd_sweep --sarif FILE` and `cmd_findings --sarif FILE` in cli.py. Docstring includes `gh api` upload command as usage example.
- **docs:** `docs/reference-modules/json-and-sarif-export.md` — covers this module and json_export.py together. Match verdict: **accurate**. The reference doc correctly documents the known `ruleId` collision issue (two queries with same tag produce same ruleId).
- **limitations:**
  - `_rule_id()` can collide: if two different queries share a tag prefix after truncation/slugification, they get the same `ruleId`. The SARIF spec requires unique rule IDs; downstream tooling may merge results silently.
  - `findings_to_sarif()` uses `logicalLocations` when no `binary_path` is provided — this is legal SARIF but some consumers require `physicalLocation`
  - Version fallback to `"0.0.0"` when `importlib.metadata` fails (editable install without build metadata)
  - `address.absoluteAddress` in sweep results stores the integer VA — SARIF `address` is defined for binary analysis but less commonly supported than `region` by GitHub Code Scanning
- **dependencies:** importlib.metadata, pathlib, re, urllib.request.pathname2url (all stdlib)
- **claims_to_verify:** Module docstring shows GitHub Code Scanning upload command using `gzip -c | base64 -w0` — this is the correct API format for SARIF upload (verified against GitHub docs as of 2025)

---

## Capability: Binary Ninja Plugin (`ablation.integrations.binja_plugin`)

- **name:** `binja_plugin` — `annotate_from_corpus`, `sweep_binary`, `semantic_search`
- **category:** IDE Integration / Binary Ninja
- **paths:** `ablation/ablation/integrations/binja_plugin.py` (lines 1–222)
- **entry_point:** Not invoked directly — loaded by Binary Ninja as a plugin. Three `PluginCommand.register()` calls at module load if `binaryninja` import succeeds. Manual installation: copy file to `~/.binaryninja/plugins/`.
- **what_it_does:** Provides three Binary Ninja menu commands under `Ablation\`:
  1. **Annotate from Corpus** (`annotate_from_corpus`): computes SHA-256 of the open binary, queries `~/.ablation/func_id.db` for matching corpus entries, and renames functions in the Binary Ninja function list to corpus-recorded names (skips `fn_` and `sub_` prefixed names).
  2. **Sweep Binary** (`sweep_binary`): builds a temporary corpus in `/tmp/ablation_binja_<stem>.db`, runs `PatternLibrary.sweep()`, and tags each hit function with a `!` bookmark including pattern text and score.
  3. **Semantic Search** (`semantic_search`): prompts for a plain-English query via `bn.get_text_line_input`, runs `SemanticSearcher.query()`, navigates to the highest-scoring function VA, and displays the top-10 results in a message box.
- **inputs:** `BinaryView` (open binary in Binary Ninja session); query string from user input dialog for semantic search
- **outputs:** Binary Ninja function renames; function bookmark tags; navigation to function VA; message box summaries
- **scope:** Any binary format that Binary Ninja can open and that has been indexed via `ablation corpus`
- **status:** implemented
- **evidence:** No automated tests (Binary Ninja not available in CI); plugin is functional code, not a stub. The `_BN_AVAILABLE` guard at module level means it fails gracefully in non-BN environments.
- **docs:** A01 reference doc audit flagged `binary-ninja-plugin.md` as orphaned (code not in A01 scope). A reference doc `docs/reference-modules/binary-ninja-plugin.md` may exist — not checked during this audit. No match verdict assigned.
- **limitations:**
  - Sweep uses a `/tmp/` DB that is not cleaned up between sessions; multiple BN sessions on the same binary stem share the same temp DB
  - `semantic_search` skips corpus rebuild if the temp DB exists — stale corpus is silently reused
  - Only three plugin commands registered; no BN sidebar panel, no background analysis thread (sweep blocks the UI thread during corpus build and sweep run)
  - `annotate_from_corpus` skips names starting with `fn_` or `sub_` but does not check whether the new name would conflict with an existing BN name
  - No `ioctl-surface`, `driver`, `byovd`, or taint commands wired into the BN plugin
- **dependencies:** `binaryninja` (optional import; plugin no-ops if not present), `ablation.analyzers.corpus_builder`, `ablation.analyzers.semantic_search`, `ablation.analyzers.pattern_library`, hashlib, sqlite3, pathlib
- **claims_to_verify:** Module docstring states "On binary open: checks ~/.ablation/func_id.db for an existing corpus entry" — this is NOT implemented. There is no `BinaryView.register_for_binary_data_notification` or similar hook; corpus annotation only happens when the user explicitly invokes "Annotate from Corpus". The docstring describes intended behavior, not implemented behavior.

---

## Capability: KASAN/KCOV-Aware LoongArch64 Decoder V2 (`LoongArchDecoderV2`)

- **name:** `LoongArchDecoderV2`, `LoongArchFrameV2`, `LoongArchDisasmV2`
- **category:** Architecture Decoder / Debug Kernel Support
- **paths:** `ablation/ablation/analyzers/loongarch_decoder_v2.py` (lines 1–349)
- **entry_point:**
  - `LoongArchDecoderV2(instrumentation_vas=None, max_preamble=6)` — manual VA set
  - `LoongArchDecoderV2.from_system_map(map_path, max_preamble=6)` — parse kernel `System.map`
  - `.decode_frames_v2(data, base_addr) → List[LoongArchFrameV2]` — full decode with tagging
  - `.decode_frames_clean(data, base_addr) → Iterator[LoongArchFrameV2]` — noise-stripped
  - `.count_instrumentation(data, base_addr) → dict` — overhead statistics
- **what_it_does:** Extends `LoongArchDecoder` (V1) with a two-pass semantic layer for CONFIG_KASAN=y / CONFIG_KCOV=y debug kernels. V1 performs the opcode-table decode pass; V2 adds an SSL-style semantic pass that (1) tags every `bl` to a KASAN/KCOV VA as `is_instrumentation=True`, then (2) walks backwards up to 6 instructions from each tagged call and marks the KASAN shadow-address preamble sequence (`srli.d`, `lu12i.w`, `addi.d`, `ld.b`, etc.) with `idiom="kasan_shadow"`. `decode_frames_clean()` then yields only real program-logic instructions with the ghost calls removed. Directly observed on TencentOS 4.6 kernel 6.6.119-52.9.tl4.loongarch64+debug.
- **inputs:**
  - `data`: raw bytes of a `.text` section
  - `base_addr`: VA of first byte
  - `map_path` (for `from_system_map`): path to kernel `System.map` file (format: `<hex_va> <type> <symbol>`)
  - `instrumentation_vas`: optional `Set[int]` of KASAN/KCOV function VAs
- **outputs:**
  - `List[LoongArchFrameV2]` — each frame extends `LoongArchFrame` with:
    - `is_instrumentation: bool`
    - `idiom: str` — one of `"kasan_shadow"`, `"kasan"`, `"kcov"`, `"kcov_trace_pc"`, etc.
  - `count_instrumentation()` → `{"total": int, "instrumentation": int, "real": int, "pct_instrumentation": float}`
- **scope:**
  - LoongArch64 fixed-width 32-bit instructions only
  - KASAN symbol prefixes tracked: `__asan_load*`, `__asan_store*`, `__asan_report*`, `__kasan_*`, and 6 others
  - KCOV symbol prefixes tracked: `__sanitizer_cov_trace_pc`, `__sanitizer_cov_trace_switch`, `__sanitizer_cov_trace_cmp`, and variants
  - Preamble mnemonics recognized: `srli.d`, `lu12i.w`, `lu32i.d`, `lu52i.d`, `addi.d`, `addi.w`, `add.d`, `ld.b`, `andi`, `slti`, `sltui`, `or`
  - Store boundary mnemonics (preamble walk stops): 16 store variants including AMO instructions
- **status:** implemented
- **evidence:** No dedicated test file found; module has extensive inline documentation with observed idiom examples from TencentOS 4.6 debug kernel
- **docs:** No reference doc in `docs/reference-modules/` for this module specifically. The loongarch64 taint tracker is documented but V2 decoder is not.
- **limitations:**
  - `_classify_idiom()` always returns `"kasan"` regardless of whether the target is a KCOV or KASAN symbol — the idiom field is not disambiguated to `kcov_trace_pc` etc. without post-hoc symbol resolution
  - Preamble walk uses a fixed 6-instruction lookback window; kernel versions with longer preambles (e.g. with `lu32i.d`/`lu52i.d` for 64-bit shadow base) may not be fully tagged
  - `from_system_map()` silently skips lines with parse errors; a corrupted System.map file produces an empty VA set with no warning
  - `LoongArchDisasmV2` wrapper does not expose `count_instrumentation()` or `from_system_map()` — callers needing those must use `LoongArchDecoderV2` directly
  - Not wired into any CLI subcommand — `loongarch64-decode` routes through V1 `LoongArchDecoder`, not V2
- **dependencies:** `ablation.analyzers.loongarch_decoder` (LoongArchDecoder, LoongArchFrame), dataclasses, struct (stdlib)
- **claims_to_verify:** Docstring cites Cifuentes & Sendall 1998 (SSL) as theoretical grounding — this is accurate framing; V2 is the semantic pass over V1's syntactic decode, consistent with SSL methodology

---

## Capability: Demo Script (`docs/demo_curl.py`)

- **name:** `demo_curl.py`
- **category:** Documentation / Example Code
- **paths:** `ablation/docs/demo_curl.py` (lines 1–126)
- **entry_point:** Direct script execution: `python docs/demo_curl.py [binary_path]`. Defaults to `/usr/bin/curl` if no argument given.
- **what_it_does:** End-to-end walkthrough demonstrating 5 core Ablation capabilities against a real binary: (1) `BinaryContext.load_or_build()` for binary summary; (2) `XRefGraph.from_path()` + `.build()` for call graph and string cross-references; (3) `CFGBuilder` for CFG of the first 3 function starts; (4) `CorpusBuilder.build()` to index the binary into a demo DB at `/tmp/ablation_demo.db`; (5) `SemanticSearcher.query()` with 4 fixed vulnerability-class queries. Each section is timed and reports elapsed seconds. Designed to be run against `/usr/bin/curl` or any firmware ELF.
- **inputs:** Optional positional argument: path to any ELF binary. No flags.
- **outputs:** Printed sections to stdout with timing data, stats, and top-3 semantic search results per query. Writes corpus to `/tmp/ablation_demo.db`.
- **scope:** Exercises BinaryContext, XRefGraph, CFGBuilder, CorpusBuilder, SemanticSearcher only — no taint trackers, scanners, or export modules
- **status:** implemented (working example code, not a stub)
- **evidence:** Not a test file and not in `tests/` — it is a documentation example. No assertions.
- **docs:** No reference doc. File lives in `docs/` suggesting it is documentation-adjacent.
- **limitations:**
  - Writes to `/tmp/ablation_demo.db` unconditionally; re-runs on the same binary reuse this DB without a rebuild flag
  - `sorted(xg._func_starts)[:3]` accesses a private attribute directly — fragile against XRefGraph refactors
  - No error handling; will abort mid-run if any capability fails (e.g. sentence-transformers not installed)
  - Does not cover taint analysis, sweep patterns, export, or any arch-specific subcommand
  - The semantic search queries are fixed strings hardcoded in the script; output quality depends on corpus size and model
- **dependencies:** `ablation.analyzers.binary_context`, `ablation.analyzers.xref_graph`, `ablation.analyzers.cfg_builder`, `ablation.analyzers.corpus_builder`, `ablation.analyzers.semantic_search`; sentence-transformers (via SemanticSearcher); sys, time, pathlib (stdlib)
- **claims_to_verify:** Header comment says it accepts "any stripped ELF" — confirmed; BinaryContext handles stripped binaries without symbols

---

## Summary

**Significant capabilities:**

- **cli.py** — The package's entire public API from the command line. Authoritative list of all 30+ subcommands, their flags, and which analyzer each routes to. Critical for audit coverage because it defines what the tool does from a user perspective. The `_RECENT_UPDATES` string embedded in it (lines 401–581) is the most detailed per-version feature log in the codebase.

- **loongarch_decoder_v2.py** — A meaningful new analyzer capability: two-pass KASAN/KCOV instrumentation stripping for LoongArch64 debug kernels. Not exposed via any CLI subcommand yet; callers must use it programmatically or via `LoongArchDisasmV2`. Targeted specifically at TencentOS 4.6 debug builds. Fills a real gap when analyzing kernel modules with heavy sanitizer overhead.

- **binja_plugin.py** — The only GUI integration in the package. Provides corpus annotation, sweep, and semantic search within Binary Ninja. Has a documentation discrepancy: the "on binary open" auto-annotation described in the module docstring is not implemented.

**Support code:**

- **sarif.py** — Infrastructure for standards-compliant output. Well-implemented, has a known ruleId collision edge case documented in its own reference doc.

- **json_export.py** — Thin serialization layer. Four functions, 66 lines. The `write_sarif()` function is a copy of `write_json()` with a different name — not a SARIF validator.

- **demo_curl.py** — Documentation example, not a capability. Useful as an integration smoke test but contains no assertions and accesses private attributes.
