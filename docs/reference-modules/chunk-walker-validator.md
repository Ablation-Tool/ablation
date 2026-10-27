# ChunkWalkerValidator

**File:** `modules/chunk_walker_validator.py`

## Why this exists

Detects TLV/chunk parsers in stripped x86-64 binaries that advance the chunk pointer by raw user-supplied length without rounding up to the next 4-byte boundary. Many protocols SCTP RFC 9260, DNS RFC 1035, GRE, PPTP, IS-IS require chunk/TLV boundaries to be 4-byte aligned; a parser that does `ptr += raw_length` instead of `ptr += raw_length + 3 & ~3` will misparse the next chunk because padding bytes become the next type and length fields.

## Key constants

| Constant | Value | Applied to |
|---|---|---|
| `_MAX_BINARY_BYTES` | 256 MB | Binary file read cap |

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. `Path.stat().st_size` guard before `lief.parse()`; `lief.parse()` in `try/except Exception`; `_MAX_BINARY_BYTES=256MB`. No HTTP reads.

---

## How it works

`ChunkWalkerValidator.scan()` runs a Capstone linear sweep over the `.text` section. For each instruction, it applies a two-phase pattern match:

1. Chunk header read: a `movzwl` or `movzbl` instruction reading from a memory operand into a register (the `length_reg`). This matches the typical 16-bit or 8-bit TLV length field read.
2. Pointer advance: within a lookahead window (`ADVANCE_LOOKAHEAD` instructions), an `add` or `lea` that advances a pointer register (`advance_reg`) by exactly `length_reg`. This is `ptr += raw_length`.
3. Alignment check: between steps 1 and 2, the scanner looks for the `length + 3 & ~3` rounding pattern: either an `add reg, 3; and reg, ~3` sequence or an equivalent `lea`. If found, `aligned=True`.
4. Next field read: within `READ_LOOKAHEAD` instructions after the advance, the scanner looks for the next chunk header read (a memory dereference through `advance_reg`). If found, its VA is stored in `read_va`.

A finding is emitted when an unaligned advance is detected (`aligned=False`). Aligned advances are also reported (`aligned=True`) to confirm correct protocol implementations.

---

## Example output

The following illustrates `ChunkWalkFinding.fmt()` output. Actual addresses are binary-specific.

```
ChunkWalkerValidator: sctp_parser_x86-64.elf

[UNALIGNED]  func=0x401a20  advance=0x401b44
  func   : 0x401a20
  advance: 0x401b44  rsi += rdx
  next_rd: 0x401b58

[ALIGNED]  func=0x402310  advance=0x402388
  func   : 0x402310
  advance: 0x402388  rdi += rcx
  next_rd: 0x4023a0
```

---

## False positives

**Non-chunk pointer arithmetic:** Any `add reg1, reg2` where `reg2` was loaded from memory by `movzwl`/`movzbl` matches the pattern, regardless of whether it is actually a TLV chunk advance. Length-limited string copies or struct field-guided copies trigger the pattern. Verify candidate VAs with `FuncProfiler` to confirm a TLV loop structure outer loop over chunk pointer, inner reads for type and value fields.

**Alignment pattern in copied register:** The scanner checks for alignment of `length_reg` only between the header read and the advance instruction. If alignment is computed from a copy of `length_reg` in a different register, the `aligned=True` flag is not set, producing a spurious `UNALIGNED` result.

---

## Pipeline position

**Before this module:** `BinaryContext.load_or_build()` with the target binary. Use `SemanticSearcher.query("TLV chunk parser length advance alignment")` to confirm the binary has TLV parsers before running the scanner.

**After this module:** For `aligned=False` findings, verify with `FuncProfiler` that the function contains a TLV parsing loop. Report confirmed SCTP/DNS/GRE chunk alignment bugs as misparse-on-malformed-input findings.

---

## Reading findings

`ChunkWalkerValidator.from_context(ctx).scan()` returns `List[ChunkWalkFinding]`:

| Attribute | Content |
|:---|:---|
| `func_va` | Start VA of the function containing the unaligned chunk advance |
| `advance_va` | VA of the pointer advance instruction (`ptr += raw_length`) |
| `advance_reg` | Register holding the chunk pointer being advanced |
| `length_reg` | Register holding the raw user-supplied length value |
| `aligned` | `True` if an alignment rounding pattern was found in the instruction lookahead |
| `read_va` | VA of the next field read after the advance 0 if not found in window |

`ChunkWalkFinding.fmt()` returns a formatted string tagged `[ALIGNED]` or `[UNALIGNED]`.

---

## See also

- [BinaryContext](binary-context.md): load target binary before calling `from_context()`
- [Single-Function Profiling](single-function-profiling.md): `FuncProfiler` for verifying TLV loop structure around flagged VAs
- [Semantic Searching](semantic-code-search.md): `SemanticSearcher` to identify TLV parser candidates before scanning
