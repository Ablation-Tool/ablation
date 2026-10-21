# win16-mz-dos-sweep

`sweeps/win16_mz_dos_sweep.py`

## Why this exists

Three things were not possible before in Ablation:

1. **No 16-bit real-mode MS-DOS executable could be loaded.** MZ (Mark Zbikowski) is the original DOS executable format used by all real-mode DOS programs. Before this module, any binary with a two-byte `MZ` magic was opaque to Ablation: no header parser, no function-start recovery, no disassembly pipeline. TCP/IP-32 3.11a ships seven DOS network utilities (ARP, PING, TRACERT, NBTSTAT, NETSTAT, IPCONFIG, ROUTE) in this format; they were the only unsweepable binaries in the collection.

2. **Large-model DOS programs use segment-relative addressing that breaks flat-address disassemblers.** These utilities are compiled with Microsoft's LARGE memory model: CS is not zero, there are hundreds of far-call relocations, and function entry points are CS:IP pairs relative to a dynamically chosen load segment. Treating the code section as a flat address stream produces wrong disassembly. This module recovers function starts from near-call targets and `push bp; mov bp, sp` prologues within the flat code section, then disassembles each function in CS_MODE_16 at its correct flat offset.

3. **No DOS-specific vulnerability profiles existed.** DOS real-mode programs use `rep movsb/movsw/stosw` for memory operations, `INT 21h` for I/O, and CX-controlled copy loops, all different from the 32/64-bit world. Generic profiles either miss these patterns or produce high false-positive rates. This module introduces three profiles: `dos_unbounded_copy` (rep movs/stos without CX guard, excluding compile-time constant CX), `dos_int21_recv_path` (INT 21h near a memory-loaded AH), and `dos_fixed_stack_alloc` (sub sp, N > 0x100 near external input paths).

---

## What this module does

Parses a real-mode MZ executable header to find the code section start, recovers function starts from near-call targets (E8 rel16 BFS) and prologue scanning, disassembles each function with Capstone `CS_MODE_16`, and scores against three DOS-specific profiles. A constant-CX filter suppresses the common false-positive class where `mov cx, LITERAL` precedes `rep movs`, this is a compile-time-bounded struct copy, not a missing bound check.

---

## Usage

```bash
python3 sweeps/win16_mz_dos_sweep.py /path/to/PING.EXE \
  --vendor microsoft --product tcpip32 --version 3.11a
```

Multiple paths:

```bash
python3 sweeps/win16_mz_dos_sweep.py *.EXE --vendor microsoft ...
```

Output: `reports/sweep_mz_<vendor>_<product>_<version>_<ts>.md`

---

## Key implementation notes

- MZ header: `code_offset = header_paragraphs × 16`. `image_size = (page_count-1) × 512 + (last_page_extra or 512)`.
- Near call recovery: scan the flat code bytes for `E8 rel16` (opcode 0xE8) and collect `(offset + 3 + rel16) & 0xFFFF` as function starts. Rel16 is signed.
- Prologue scan: `55 89 E5` (push bp; mov bp, sp: MASM/MSVC), `55 8B EC` (same, alternate encoding), `C8 xx xx 00` (enter N, 0).
- `entry_offset()` = `initial_cs × 16 + initial_ip`. For large-model programs this is non-zero.
- All disassembly uses flat offsets from the start of the code section (not logical CS:IP pairs). VAs in the report are code-section-relative byte offsets.
- The constant-CX filter: a `rep movs/stos` hit is suppressed when the nearest preceding `mov cx, <operand>` has an immediate literal operand (starts with `0x` or is all digits). CX from `[mem]` or a register is not filtered.

---

## False-positive class: DOS_UNBOUNDED_COPY after constant-CX filter

After the constant-CX filter, remaining `dos_unbounded_copy` hits are functions where CX comes from a caller argument (`[bp+N]`) or from a memory variable. These are generic memset/memcpy-class utility functions. Without a DOS taint tracker (GAP-H), confirming these requires manual caller-chain tracing to determine whether network-controlled data can reach CX.

Confirmed on TCP/IP-32 3.11a: 171 hits across 7 utilities after filter; all spot-checked hits are `_fmemset`-class functions (zero-fill with caller-supplied count). No confirmed finding.

---

## How it works

`MZDosBinary(path)` parses a 16-bit real-mode MS-DOS MZ executable. Handles large-model DOS programs with multiple code segments — typical of WfW 3.11 network utilities (ARP.EXE, PING.EXE, TRACERT.EXE). The parser reads the MZ header's segment relocation table, reconstructs the load image, and resolves far-call segment:offset addresses. `MZDosBinary.sweep()` disassembles each code segment with CS_ARCH_X86 + CS_MODE_16 and scans for unsafe interrupt calls (INT 21h with no input validation) and unbounded string operations.

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

## Reading output

`sweep(path)` returns `MZSweepResult`.

| Field | Type | Content |
|:---|:---|:---|
| `binary` | `str` | Basename of the analyzed file |
| `func_count` | `int` | Number of function starts found |
| `hits` | `List[MZSweepHit]` | Vulnerability profile matches above threshold |
| `errors` | `List[str]` | Parse or disassembly errors (non-fatal) |

Each `MZSweepHit`:

| Field | Type | Content |
|:---|:---|:---|
| `offset` | `int` | Code-section byte offset of the function start |
| `profile` | `str` | Vulnerability profile name that matched |
| `score` | `float` | Semantic similarity score (0.0–1.0) |
| `insn_count` | `int` | Number of instructions in the function |

---

## See also

- [BinaryContext](binary-context.md) — session state and function/import index
- [TaintAnalysis](taint-analysis.md) — dataflow tracking on resolved functions
- [SemanticSearch](semantic-search.md) — behavioral candidate search on the binary
