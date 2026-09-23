# Vulnerability Hunting Workflow

Ablation's core workflow starts from a stripped binary with no symbols and ends with a
confirmed, disclosure-ready finding.

**Time to first candidate:** under 5 minutes.
**Time to confirmed finding:** 30 to 90 minutes.

---

## Overview

```
stripped binary
      |
      v
[BinaryContext]    -- 0.5s: PLT, exports, strings, xref index, call graph
      |
      v
[CorpusBuilder]    -- behavioral description per function (calls + strings + neighbors)
      |
      v
[SemanticSearcher] -- BERT sweep: 35s for 19k functions
      |
      v
  candidates       -- ranked list, top 5-10 per vuln class
      |
      v
[manual triage]    -- callers, callees, strings: 2-3 min per candidate
      |
      v
[capstone trace]   -- disassemble the suspicious function, trace the data flow
      |
      v
[TaintTracker]     -- automated x86-64 taint from packet input to dangerous sink
      |
      v
  confirmation     -- reproducible trigger condition, root cause, instruction address
      |
      v
[NameRegistry]     -- register confirmed function names
[PatternLibrary]   -- register confirmed query for replay on future targets
[FindingRegistry]  -- log finding with CVSS, impact, trigger
```

---

## Phase 1: Context build (0.5s)

```python
from ablation.analyzers.binary_context import BinaryContext

ctx = BinaryContext.load_or_build('/path/to/binary.so')
print(ctx.summary())
print(ctx.names_table())   # previously confirmed function names appear here
```

Check `names_table()` at session start before doing anything else. If this binary was analyzed
in a prior session, named functions appear in all callee and caller output automatically. That
context narrows the search before the sweep begins.

---

## Phase 2: Sweep (35-60s)

Define vulnerability profiles as plain-English descriptions of the vulnerable function's
behavior -- what it does, what it calls, what the flaw looks like:

```python
PROFILES = [
    ("tlv_zero_length",
     "PROTOCOL_PARSER | role=tlv_advance | calls: memcpy memmove | "
     "vuln: TLV pointer advance loop with no minimum length check; "
     "zero-length field causes infinite loop"),

    ("memcpy_from_packet",
     "AV_PARSER | role=buffer_copy | calls: memcpy | "
     "vuln: memcpy called with length from untrusted packet field without bounds check"),

    ("integer_overflow_alloc",
     "AV_SCANNER | role=allocation | calls: malloc realloc | "
     "vuln: integer multiplication before malloc without overflow check"),

    ("format_string",
     "LOGGER | role=error_handler | calls: printf fprintf sprintf | "
     "vuln: format string argument from untrusted packet data"),
]
```

The role hint (`AV_PARSER`, `PROTOCOL_PARSER`, etc.) steers BERT toward the right functional
cluster. Include both what the function calls and what the vulnerability class looks like.

Run the sweep:

```python
from ablation.analyzers.xref_graph import XRefGraph
from ablation.analyzers.semantic_search import SemanticSearcher

xg = XRefGraph.from_path('/path/to/binary.so').build()
searcher = SemanticSearcher('/path/to/binary.so', xg=xg)
searcher.build_corpus()

for profile_name, query in PROFILES:
    results = searcher.query(query, top_k=8)
    hits = [r for r in results if r.score >= 0.30]
    if hits:
        print(f"\n[{profile_name}]")
        for r in hits[:5]:
            print(f"  {ctx.name(r.va):<50s}  score={r.score:.3f}")
```

Also run the pattern library to replay confirmed patterns from prior engagements:

```python
from ablation.analyzers.pattern_library import PatternLibrary

pl = PatternLibrary()
pl_hits = pl.sweep(searcher, top_k=8, min_score=0.30)
print(pl.fmt_sweep(pl_hits, binary_name='binary.so'))
```

---

## Phase 3: Triage (2-3 min per candidate)

For each candidate above score 0.35, get context before opening a disassembler:

```python
va = 0x17b660

# What protocols or data does this function process?
print("strings:", ctx.strings_in_func(va))

# What external functions does it call?
print("callees:", ctx.callees_of(va))

# Where is it called from?
print("callers:", ctx.callers_of(va))
```

**Triage decision:**

- Protocol-specific strings (`"diameter"`, `"websocket"`, `"scada"`) AND memory functions
  (`memcpy`, `malloc`, `free`) AND callers in a network-facing function: **high priority,
  trace manually**
- Only internal helpers, no network-facing callers: **eliminate, mark as FP**
- Memory functions present but strings point to trusted input (config file, signature DB):
  **eliminate, mark as FP**

Log every elimination. False positives recur. Logging prevents re-triaging the same function
in the next session.

---

## Phase 4: Manual trace

For high-priority candidates, disassemble the function and trace the data flow. Use capstone
for targeted disassembly:

```python
import capstone
from pathlib import Path

data = Path('/path/to/binary.so').read_bytes()

cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
cs.detail = True

# text_offset and func_offset require section VA-to-file-offset calculation
chunk = data[func_offset:func_offset + 512]
for insn in cs.disasm(chunk, va):
    print(f"  0x{insn.address:x}  {insn.mnemonic:<10s} {insn.op_str}")
```

What to look for:

- **Zero-length loop:** `movzx eax, word ptr [rcx + N]` then `add rcx, rax` with no
  `cmp rax, MIN` guard before the addition
- **Width truncation:** `movzx eax, word ptr [...]` (16-bit from wire), then used as a full
  32 or 64-bit value in a size calculation downstream
- **Unchecked copy:** `mov rsi, <length_from_packet>` with no `cmp rsi, MAX` before
  `call memcpy`

---

## Phase 5: Automated taint (optional)

For complex functions, use TaintTracker to trace data flow from a source instruction to a
dangerous sink:

```python
from ablation.analyzers.taint_tracker_x86 import TaintTracker

tracker = TaintTracker('/path/to/binary.so')
result = tracker.trace(
    func_va=0x17b660,
    source_va=0x17b84c,
    source_reg='rax',
    sink_patterns=['memcpy', 'malloc', 'add rcx']
)
print(result.summary())
```

---

## Phase 6: Confirm and register

When the root cause is identified, the trigger condition is understood, and the instruction
address is known, register everything:

```python
# Name the function
ctx.set_name(0x17b660, 'ips_diameter_parse_message', source='confirmed')

# Register the finding
from ablation.analyzers.finding_registry import FindingRegistry
fr = FindingRegistry()
fr.add_finding(
    binary_sha=ctx.sha256[:16],
    va=0x17b660,
    func_name='ips_diameter_parse_message',
    vuln_class='infinite_loop',
    cvss=7.5,
    trigger='Diameter packet with AVP Length field = 0x000000',
    root_cause='advance_ptr += avp_length with no avp_length >= MIN_HEADER_SIZE floor check',
    confirmed=True,
)

# Register the query -- replays on future targets automatically
from ablation.analyzers.pattern_library import PatternLibrary
pl = PatternLibrary()
pl.record_hit(
    query="TLV pointer advance loop with no minimum length check",
    binary_sha=ctx.sha256[:16],
    va=0x17b660,
    confirmed=True,
    vuln_class='infinite_loop',
    cvss=7.5,
)
```

---

## False positive checklist

Before confirming any finding, verify:

- [ ] The length field comes from the network, not from a trusted internal source (signature
      file, config file, hardcoded constant)
- [ ] The dangerous operation (add, memcpy, malloc) uses the untrusted length directly -- not
      a separately computed safe value
- [ ] The function is reachable from a network-facing entry point (trace the caller chain)
- [ ] No guard check exists between the length read and the dangerous operation -- check all
      branches, not just the hot path
- [ ] The callee actually uses the length parameter -- verify it is not silently discarded

---

## Session continuity

Update `targets/<vendor>/SESSION_<target>.md` at the end of every session:

- Binary path and SHA256 prefix
- New named functions added to the overlay
- Confirmed findings with instruction addresses and root cause
- Pending work -- which candidates remain unresolved and why

This file is committed to the repo. The next session reads it first.

---

## See also

- [Getting Started](../getting-started.md)
- [Module Reference: SemanticSearcher](../module-reference/semantic-search.md)
- [Module Reference: TaintTracker](../module-reference/core.md)
- [Module Reference: PatternLibrary](../module-reference/semantic-search.md)
