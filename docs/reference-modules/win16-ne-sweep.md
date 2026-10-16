# win16-ne-sweep

`sweeps/win16_ne_sweep.py`

## Why this exists

Three things were not possible before in Ablation:

1. **No Win16 NE binary could be loaded.** LIEF does not support the NE (New Executable) format used by Windows 3.x.EXE and.DLL files. Without a loader, the 16-bit TCP/IP stack, FTP clients, Winsock layer, and all WfW 3.11 networking binaries were invisible to every sweep.

2. **16-bit import resolution was missing.** Win16 imports are stored as per-segment relocation records that map code offsets to `(module_ref, ordinal)` tuples, not an IAT. Call resolution requires parsing the module reference table and the imported names table, then looking up ordinals in per-module tables for KERNEL, USER, GDI, and SHELL. Without this, every call in a Win16 binary appeared as a bare hex address, producing meaningless semantic descriptions.

3. **Win16-specific vulnerability profiles did not exist.** Win16 programs use `LocalAlloc`/`GlobalAlloc` (16-bit wrap at 64 KB), `lstrcpy` (no length parameter), `GetDlgItemText` (fixed OFSTRUCT), and `WinExec`, different sinks from the 32/64-bit world. Generic profiles scored these functions incorrectly.

---

## What this module does

Parses Windows 3.x NE binaries with a pure-Python NE header parser (no LIEF). Iterates code segments, parses per-segment relocation records to build import maps, finds function starts via 16-bit prologue detection and NEAR call-target recovery, disassembles with Capstone `CS_MODE_16`, and runs a semantic sweep with Win16-specific profiles merged into the standard base profile set.

---

## Usage

```bash
python3 sweeps/win16_ne_sweep.py /path/to/file.exe \
  --vendor microsoft --product tcpip32 --version 3.11a
```

Output: `reports/sweep_ne_<vendor>_<product>_<version>_<ts>.md`

---

## Key implementation notes

- NE header field `align_shift` controls the sector multiplier for segment file offsets. Default is 9 (512-byte sectors) when the field is 0.
- The relocation source offset for a FAR CALL (`9A`) is at `call_file_offset + 1` (byte after the opcode), not at the opcode itself.
- Class is `NEBinary` (not `NEParser`).
- `NEBinary.build_segment_import_map(seg)` returns `{source_offset: 'MOD!funcname'}` where `source_offset` is relative to the segment start.
- Win16 functions may use `enter imm16, 0` (`c8 XX XX 00`) instead of `push bp; mov bp, sp`: the prologue scanner checks both forms.

---

## GAP-A: thin wrapper false positives

Functions with ≤15 instructions containing exactly one import call score high on nearly every profile because the semantic embedding is dominated by the single import name. Confirmed across three corpora (AlphaSmart WSCONV, WfW TCP/IP-32, Apple QTVR). These should be traced manually before recording as CONFIRMED. The fix is a thin-wrapper filter in the sweep post-processor, tracked as GAP-A.

---

## How it works

Reads the binary image and resolves the target-specific data structures (PLT, GOT, `.eh_frame`, symbol tables) to build a function and import index. Architecture-specific calling conventions and instruction encodings are applied to recover call edges, argument registers, and return value locations. Results are stored in the session `BinaryContext` so downstream tools can use resolved names and edges.

---

## Example output

```
Resolved 847 PLT entries
Recovered 312 function starts from .eh_frame
Named 28 functions from DWARF remnants

va=0x401200  name=verify_admin_token  confidence=HIGH
va=0x4015C0  name=process_http_request  confidence=HIGH
va=0x403A00  name=''  confidence=MEDIUM  (stripped)
```

---

## False positives

Symbol resolution errors produce phantom function boundaries. Verify any candidate VA against `ctx.func_starts` before analysis. Compiler-synthesized stubs (PLT entries, thunks) appear as functions in some loaders — `BinaryContext` filters known stub patterns but custom thunks may slip through.

---

## Pipeline position

**Before this module:** `BinaryContext.load_or_build()` for symbol and import resolution. For stripped binaries, run `SemanticSearcher` first to identify candidate function VAs.

**After this module:** Pass resolved call edges and function VAs to `TaintTracker` or `SinkArgClassifier`.

---

## Reading findings

| Field | Content |
|:---|:---|
| `va` | Virtual address of the resolved symbol, function, or instruction |
| `name` | Recovered name if available, empty string if stripped |
| `detail` | What was resolved or decoded |
| `confidence` | `HIGH` / `MEDIUM` / `LOW` — how certain the resolution is |

---

## See also

- [BinaryContext](binary-context.md) — session state and function/import index
- [TaintAnalysis](taint-analysis.md) — dataflow tracking on resolved functions
- [SemanticSearch](semantic-search.md) — behavioral candidate search on the binary
