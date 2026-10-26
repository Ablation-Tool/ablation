# Streaming and Windowed Disassembly

Dump a configurable-size disassembly window centered on any target VA: annotating PLT call targets and `.rodata` string references inline: for LLM-native bulk disassembly analysis that avoids the round-trip overhead of per-instruction calls.

---

## Why this exists <sup>[↑](#streaming-and-windowed-disassembly)</sup>

1. **Per-instruction disassembly calls fragment LLM context across dozens of round trips: each call to `get_disassembly` in the `AgentLoop` tool registry returns a small slice, requiring the model to accumulate context across many calls to understand a function.** `WindowAnalyzer.dump_text()` returns a single annotated disassembly block default 1536 bytes that the LLM can pattern-match in one pass, reducing round trips from ON instructions / page_size to 1 for typical function analysis.

2. Inline annotation of PLT call targets and `.rodata` strings makes the disassembly immediately readable: instead of `call 0x3000`, the output shows `call 0x3000  ; PLT -> recv`, and instead of `lea rdi, [rip+0x1234]`, the output shows `lea rdi, [rip+0x1234]  ; "==diff==> %s:%d loading cli context fail"`. An analyst (or LLM) can read the annotated dump and immediately understand the function's behavior without cross-referencing the PLT or string tables.

3. `WindowAnalyzer.find_func_starts()` heuristically identifies function starts within the window: detecting `endbr64` CET entry point markers and push-rbp prologues in the window, providing function boundary hints in stripped binaries where `.eh_frame` FDE entries are absent.

---

## How it works <sup>[↑](#streaming-and-windowed-disassembly)</sup>

```mermaid
flowchart TD
    A(["WindowAnalyzer.from_path(path)\n  or .from_context(ctx)"]):::input --> B["dump(va, window=1536) → List[str]\n  Decode [va - window//2, va + window//2]\n  Using Capstone for the binary's ISA\n  Return raw annotated instruction strings"]:::primary
    B:::primary --> C["Per instruction annotation:\n  CALL target → resolve PLT name:\n    'call 0x3000  ; PLT -> recv'\n  LEA [rip+disp] → resolve .rodata string:\n    'lea rdi, [...]  ; \"error loading config\"'\n  CALL internal → if named: '; -> parse_request'"]:::secondary
    C:::secondary --> D["dump_text(va, window=1536) → str\n  Joins dump() list as formatted text block\n  Suitable for LLM context injection"]:::tertiary
    D:::tertiary --> E["find_func_starts(va, window, align_back) → List[int]\n  Scan window for endbr64 (0xF3 0x0F 0x1E 0xFA)\n  and PUSH RBP (0x55) prologue patterns\n  Returns sorted list of heuristic starts"]:::tertiary
    E:::tertiary --> F(["calls_in_window(va, window, align_back) → List[Tuple[int,int,str]]\n  All CALL instructions in window:\n  (call_va, target_va, resolved_name)"]):::output
    classDef input     fill:#0d47a1,stroke:#1565c0,color:#fff
    classDef primary   fill:#e65100,stroke:#bf360c,color:#fff
    classDef secondary fill:#004d40,stroke:#00695c,color:#fff
    classDef tertiary  fill:#4a148c,stroke:#6a1b9a,color:#fff
    classDef neutral   fill:#37474f,stroke:#546e7a,color:#fff
    classDef output    fill:#1b5e20,stroke:#2e7d32,color:#fff
    linkStyle 0 stroke:#bf360c,stroke-width:2px
    linkStyle 1 stroke:#00695c,stroke-width:2px
    linkStyle 2 stroke:#6a1b9a,stroke-width:2px
    linkStyle 3 stroke:#6a1b9a,stroke-width:2px
    linkStyle 4 stroke:#2e7d32,stroke-width:3px
```

---

## Usage <sup>[↑](#streaming-and-windowed-disassembly)</sup>

```python
from ablation.analyzers.window_analyzer import WindowAnalyzer
from ablation.analyzers.binary_context import BinaryContext

ctx = BinaryContext.load_or_build('/path/to/target.elf')
wa = WindowAnalyzer.from_context(ctx)

# Dump disassembly window centered on a VA
text = wa.dump_text(va=0x41366, window=1536)
print(text)

# Get list form (for programmatic processing)
lines = wa.dump(va=0x41366, window=1536)
for line in lines:
    print(line)

# Find function starts in window (stripped binary)
starts = wa.find_func_starts(va=0x41366, window=4096)
print(f"Heuristic function starts: {[f'{s:#x}' for s in starts]}")

# Find all calls in window
calls = wa.calls_in_window(va=0x41366, window=1536)
for call_va, target_va, name in calls:
    print(f"  {call_va:#x} → {name or target_va:#x}")
```

---

## Example output <sup>[↑](#streaming-and-windowed-disassembly)</sup>

The following illustrates annotated disassembly output format. Actual instructions and strings are binary-specific.

```
0x41366: push   rbp
0x41367: mov    rbp, rsp
0x4136a: sub    rsp, 0x20
0x4136e: call   0x3000          ; PLT -> recv
0x41373: test   eax, eax
0x41375: js     0x41390
0x41377: lea    rdi, [rip+0x...]; "error: connection reset"
0x4137e: call   0x3010          ; PLT -> fprintf
```

---

## False positives <sup>[↑](#streaming-and-windowed-disassembly)</sup>

**`find_func_starts()` is heuristic, it detects `endbr64` and `PUSH RBP` patterns that may appear as instruction data sequences, not actual function prologues.** Confirm heuristic starts against `ctx.func_starts` or `.eh_frame` FDE entries before using them as analysis entry points.

**Window size may split a function at an inconvenient boundary.** Use `ctx.func_containing(va)` to find the function start VA, then set `va` to the function start and `window` to `ctx.func_size(va)` for a complete function window.

---

## Pipeline position <sup>[↑](#streaming-and-windowed-disassembly)</sup>

`WindowAnalyzer.dump_text()` is the standard manual disassembly tool in the RE workflow (CLAUDE.md step 9: "WindowAnalyzer.dump_text() for manual disasm only when automated tools don't have the sink"). Use automated tools `TaintTracker`, `SinkArgClassifier` first; `dump_text()` is for the cases where a finding needs manual confirmation or the automated tool has no configured sink for the observed pattern.

---

## Reading output <sup>[↑](#streaming-and-windowed-disassembly)</sup>

`WindowAnalyzer.dump_textva, window, align_back, header` returns an annotated disassembly string with a header line and separator. Each disassembly line has the form:

```
0x<va>: <mnemonic>  <operands>          ; <annotation>
```

Annotations are added for PLT call targets, string references, and named VAs registered in `BinaryContext`.

`WindowAnalyzer.dumpva, window, align_back` returns `List[str]`: the same lines without the header block, for programmatic processing.

`WindowAnalyzer.calls_in_windowva, window` returns `List[call_va, target_va, label]`: all call/bl instruction targets in the window.

---

## See also <sup>[↑](#streaming-and-windowed-disassembly)</sup>

- [LLM Analyst Loop](llm-analyst-loop.md): `get_disassembly` tool calls `WindowAnalyzer.dump_text()` internally
- [Persistent Analysis Context](persistent-analysis-context.md): `BinaryContext` that provides PLT and string tables to `WindowAnalyzer`
- [Single Function Profiling](single-function-profiling.md): `FuncProfiler` provides a higher-level profile using the same underlying data
