# win16-ne-sweep

`sweeps/win16_ne_sweep.py`

## Why this exists

Three things were not possible before in Ablation:

1. **No Win16 NE binary could be loaded.** LIEF does not support the NE New Executable format used by Windows 3.x.EXE and.DLL files. Without a loader, the 16-bit TCP/IP stack, FTP clients, Winsock layer, and all WfW 3.11 networking binaries were invisible to every sweep.

2. **16-bit import resolution was missing.** Win16 imports are stored as per-segment relocation records that map code offsets to `module_ref, ordinal` tuples, not an IAT. Call resolution requires parsing the module reference table and the imported names table, then looking up ordinals in per-module tables for KERNEL, USER, GDI, and SHELL. Without this, every call in a Win16 binary appeared as a bare hex address, producing meaningless semantic descriptions.

3. **Win16-specific vulnerability profiles did not exist.** Win16 programs use `LocalAlloc`/`GlobalAlloc` 16-bit wrap at 64 KB, `lstrcpy` no length parameter, `GetDlgItemText` fixed OFSTRUCT, and `WinExec`, different sinks from the 32/64-bit world. Generic profiles scored these functions incorrectly.

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

- NE header field `align_shift` controls the sector multiplier for segment file offsets. Default is 9 512-byte sectors when the field is 0.
- The relocation source offset for a FAR CALL (`9A`) is at `call_file_offset + 1` byte after the opcode, not at the opcode itself.
- Class is `NEBinary` (not `NEParser`).
- `NEBinary.build_segment_import_map(seg)` returns `{source_offset: 'MOD!funcname'}` where `source_offset` is relative to the segment start.
- Win16 functions may use `enter imm16, 0` (`c8 XX XX 00`) instead of `push bp; mov bp, sp`: the prologue scanner checks both forms.

---

## GAP-A: thin wrapper false positives

Functions with ≤15 instructions containing exactly one import call score high on nearly every profile because the semantic embedding is dominated by the single import name. Confirmed across three corpora (AlphaSmart WSCONV, WfW TCP/IP-32, Apple QTVR). These should be traced manually before recording as CONFIRMED. The fix is a thin-wrapper filter in the sweep post-processor, tracked as GAP-A.

---

## How it works

`NEBinary(path)` parses a Windows 3.x New Executable NE format. Reads the NE header, segment table, module reference table, and exported name table. For each code segment, reconstructs the segment data from file offsets and resolves imported ordinals against the Win16 KERNEL, USER, and GDI ordinal tables lines 47–503. `NEBinary.sweep()` disassembles each code segment with CS_ARCH_X86 + CS_MODE_16 and scans for dangerous Win16 API calls (`lstrcpy`, `lstrcat`, `sprintf`, `GetDlgItemText`) that allow attacker-controlled input to overflow fixed-size buffers.

---

## Example output

```
# _render_report() markdown output:
# Win16 NE Sweep Report

**Vendor:** Microsoft  **Product:** WfW  **Version:** 3.11
**Generated:** 2026-01-12 14:30 UTC  **Targets:** 2 binaries

---

## COMMDLG.DLL

**Path:** `/target/COMMDLG.DLL`  **Arch:** `x86-16`  **Segments:** 8  **Functions found:** 34
**Imports from:** KERNEL, USER, GDI

### Semantic Sweep

**lstrcpy_overflow** — top score `0.7800` @ `seg2:0x0348`
  calls: lstrcpy, lstrcat, GetDlgItemText
```

---

## False positives

**Ordinal-only imports.** Some WfW 3.x binaries import by ordinal without name. For known ordinals in the built-in KERNEL, USER, and GDI tables (lines 47–503 of `win16_ne_sweep.py`), names are resolved automatically. Unknown ordinals are displayed as `module#N`: look them up in the Win16 SDK headers.

---

## Pipeline position

**Before this module:** Confirm the binary is a Win16 NE executable (NE magic at the offset stored at MZ+0x3c).

**After this module:** Review hits for `lstrcpy_overflow` and `unbounded_input` profiles. Escalate VA hits to a Win16 disassembler or OllyDbg 1.10 under WINE for manual taint tracing.

---

## Reading output

`NEBinary` is the parsed representation of a Win16 NE binary. The CLI sweep writes findings to `reports/sweep_ne_<vendor>_<product>_<version>_<ts>.md`.

The semantic sweep returns a `dict` keyed by vulnerability profile name, each value a list of candidate function dicts:

| Field | Type | Content |
|:---|:---|:---|
| `name` | `str` | Function name (from ordinal table or auto-generated `sub_NNNN`) |
| `va` | `int` | Segment-relative VA of the function |
| `score` | `float` | Semantic similarity score (0.0–1.0) |
| `seg_name` | `str` | NE segment name (e.g., `seg_1`) |
| `insn_count` | `int` | Number of disassembled instructions |

---

## See also

- [BinaryContext](binary-context.md): session state and function/import index
- [TaintAnalysis](taint-analysis.md): dataflow tracking on resolved functions
- [SemanticSearch](semantic-search.md): behavioral candidate search on the binary
