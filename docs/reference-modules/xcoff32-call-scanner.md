# XCOFF32CallScanner: stride BL call-site scanner for XCOFF32 PPC32 BE

## Why this exists

1. Capstone linear scan failure: Capstone `cs.disasm()` stops at any embedded trap instruction or NULL-word function table in `.text`. For `yppasswd` (AIX 4.3.3 ML11, 15226 bytes), Capstone returned 43 of 2658 instructions; the embedded `tweq r1,r1` + NULL-word function table at 0x100001ac was the root cause. All callers-of() results from that session were wrong.  Gap ID: **AIX-XCOFF32-GAP-001**.

2. XCOFF32Info coupling: `XCOFF32Info.callers_of()` (aix_bff_extractor.py) already uses a stride scan but couples it to `XCOFF32Info`'s own parse path. It doesn't integrate with `XcoffBinary` (xcoff_parser.py) or `BinaryContext`.

3. Auto stub naming: After LDREL classification (`classify_toc_slots()`), stub VAs can be auto-named and all import call sites found in a single `.text` pass.

## Usage

```python
from ablation.core.xcoff_parser import parse
from ablation.analyzers.xcoff32_call_scanner import XCOFF32CallScanner

binary = parse('/tmp/yppasswd_431.xcoff')
scanner = XCOFF32CallScanner.from_binary(binary)

# All BL instructions: {target_va: [caller_vas]}
all_calls = scanner.scan_all()

# Named import calls — auto-resolved via LDREL
named = scanner.named_calls()
for import_name, callers in named.items():
    print(f'{import_name}: {[hex(v) for v in callers]}')

# Single stub:
gets_callers = scanner.calls_to(0x10002740)

# Manual stub registration (if LDREL unavailable):
scanner.set_stub(0x10002740, 'gets')

# From BinaryContext:
scanner = XCOFF32CallScanner.from_context(ctx)
```

## How it works

Every 4-byte-aligned word in `.text` is checked against the PPC32 BL opcode mask:

- **Mask**: `0xFC000003`; **Match**: `0x48000001`
- Opcode bits[0:5] = 18, AA=0 (relative), LK=1 (link)
- Branch target: `insn_va + sign_extend(LI) * 4` where LI = bits[6:29]

This scan is immune to embedded function tables, trap words, or any other non-instruction bytes — 4-byte stride, no disassembler state.

Stub auto-detection uses `classify_toc_slots()` (xcoff_parser) to map each FUNC_IMPORT TOC slot to a glink stub VA by searching for `lwz r12, TOC_SLOT(r2); stw r2, 0x14(r1)` — the standard AIX XCOFF32 glink stub pair.

## Pipeline position

**Before this module:** Identify the binary as XCOFF32 (`BinaryContext.load_or_build()` auto-detects magic 0x01DF). Parse with `xcoff_parser.parse()` to get `XcoffBinary`. Optionally run `classify_toc_slots()` first if you want named stubs.

**After this module:** Pass caller VAs to `WindowAnalyzer.dump_text()` or manual Capstone to trace register state at each call site. Use `SinkArgClassifierPPC32` to classify r3 at sink calls.

## Notes

- **XCOFF32 only**: returns empty results for ppc64.
- Indirect calls via `bctr` (XCOFF32 function pointer calls, callrpc) are not tracked.
- Non-standard stubs (e.g., if the glink pattern is different): use `set_stub(va, name)` to register manually.
- `from_context(ctx)` re-parses from `ctx.path` — no caching. Use `from_binary(parse(path))` and save the scanner if scanning the same binary multiple times.

## Verified against yppasswd (AIX 4.3.3 ML11)

- Total BL instructions found: 189
- `gets()` stub 0x10002740 (TOC[0xa4]): 1 caller at 0x100010ac (in main)
- `crypt()` stub 0x100028a8 (TOC[0xe0]): 1 caller at 0x10001784
- `fputs()` stub 0x10002858 (TOC[0xd4]): 2 callers at 0x10001728, 0x10001870
