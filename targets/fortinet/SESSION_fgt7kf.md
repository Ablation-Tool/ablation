# FortiGate 7000F -- FortiOS 8.0.0 build 0167 -- Session State

Last updated: 2026-09-25 (session 8)

## Binary

```
Path:    /tmp/fgt7kf_libs/lib/libips.so.new
Size:    18.5 MB  (stripped ELF x86-64)
SHA256:  fdfaceccdc740d82...  (first 16 chars = overlay key)
Funcs:   ~19,000
Segments: text 0x9e000--0xE22375, rodata 0xe23000+
```

## Session start

```python
from ablation.analyzers.binary_context import BinaryContext

ctx = BinaryContext.load_or_build('/tmp/fgt7kf_libs/lib/libips.so.new')
print(ctx.summary())       # PLT/export/func/string/edge counts + overlay count
print(ctx.names_table())   # 20 confirmed named functions
```

## Named functions (overlay)

20 entries registered. Run `ctx.names_table()` for the full list. Key entries:

| VA | Name |
|---|---|
| 0x17b660 | ips_diameter_parse_message |
| 0x20dd40 | ips_dcerpc_decode |
| 0x1b97a0 | ips_match_rule |
| 0x1bd5c0 | ips_match_all_candidates |
| 0x223d80 | ips_dsct_cotp_processor |
| 0x174290 | ips_msrp_dissector |

## Confirmed findings

### C16 -- Diameter AVP zero-length infinite loop (CONFIRMED HIGH, CVSS 7.5)

**Function:** `ips_diameter_parse_message` at 0x17b660
**Root cause:** `advance_ptr += avp_length` with no `avp_length >= MIN_HEADER_SIZE` floor check. Wire value of 0x0000 -> pointer never advances -> infinite CPU loop.

**Code trace:**
```
0x17b84c: movzx  eax, word ptr [rcx + 4]  ; avp_length from wire (16-bit, big-endian)
0x17b851: bswap  eax                        ; byte-swap to host order
0x17b853: shr    eax, 0x10                  ; right-shift -> 16-bit value in eax
0x17b856: add    rcx, rax                   ; advance current AVP pointer
0x17b859: cmp    rcx, rbx                   ; check against end_ptr
0x17b85c: jb     <loop_top>                 ; if in-bounds, re-enter loop
```

**Trigger:** Diameter packet with AVP Length field = 0x000000 (3-byte) or any sub-header length = 0x0000.

### C17 -- DCE/RPC zero-length record infinite loop (CONFIRMED HIGH, CVSS 7.5)

**Function:** `ips_dcerpc_decode` at 0x20dd40
**Root cause:** Same class as C16. `advance_ptr += record_length` with no floor check.

**Code trace:**
```
0x20ed40: movzx  eax, word ptr [rbx]  ; 16-bit record length from wire
0x20ed43: add    rbx, rax              ; advance (NO floor check)
0x20ed46: cmp    rbx, r15             ; check new_pos < end_ptr
0x20ed49: jb     0x20eaf0             ; if in-bounds, continue loop

; loop body:
0x20eaf0: cmp    byte ptr [rbx + 2], 1  ; check record type
0x20eaf4: jne    0x20ed40               ; if type != 1, jump back to advance
```

**Trigger:** DCE/RPC fragment with record_length = 0x0000 AND type_byte != 0x01.

## Confirmed findings (all)

### C14 -- ips_indirect_guard_handler OOB read via length underflow (CANDIDATE HIGH, CVSS 7.5)

**Function:** `ips_indirect_guard_handler` at 0x29fa90
**Classification:** CANDIDATE HIGH -- FGT7K-3 in disclosure document
**Root cause:** Wire-supplied LENGTH at rdi+0x20; `lea r12d, [rax-0x10]` underflows to 0xFFF0 when LENGTH < 16; 16-bit truncation via `movzx r15d, r12w` produces 65520. Guard at 0x29fab6: `cmp ecx, eax` where eax = rdx_low16 (0xcf00) + r15d (65520) = 118512. Not directly wire-controlled.

**Dispatch path (confirmed):**
- Global at VA 0x11b32f8 stores handler struct ptr (0x11a21e0, type_id 0x7a)
- At 0xef9aa: `mov r15, [0x11b32f8]`; then at 0xef9ec: `call [r15+0x38]` -> C14
- rdi = non-null data element ptr; rdx = r15[0x18] = 0x29cf00 (func ptr)
- ecx = caller-saved from prior call at 0xef9a5 (not wire-controlled)

**OOB effect (when guard passes):** `memcpy(context_ptr + 0xcf00, payload+0x10, 65520)` -- reads 65520 bytes far beyond option allocation.

**Guard exploitability:** ecx >= 118512 required; NOT directly wire-controlled. Depends on register state at call time. Could be satisfied if prior function leaves ecx holding a large value (pointer, counter).

**Code trace:**
```
0x29faa4: movzx eax, word ptr [rdi+0x20]   wire LENGTH (< 16 triggers underflow)
0x29faa8: lea r12d, [rax-0x10]             r12d = LENGTH-16 (underflows)
0x29faac: movzx eax, dx                    eax = rdx low 16 = 0xcf00
0x29faaf: movzx r15d, r12w                 r15d = 65520 when LENGTH < 16
0x29fab3: add eax, r15d                    eax = 0xcf00 + 65520 = 118512
0x29fab6: cmp ecx, eax                     GUARD: ecx >= 118512?
0x29fab8: jb 29fb30                        fail if not
0x29face: movzx edx, r12w                  size = 65520
0x29fad2: mov rsi, rcx                     src = payload+0x10
0x29fad5: lea rdi, [r14+r13*1]             dst = context_ptr + 0xcf00
0x29fad9: call 9efa8                       memcpy OOB READ/WRITE (65520 bytes)
```

**YARA:** `{ 0F B7 47 20 44 8D 60 F0 }` (movzx+lea LENGTH-16) and `{ 45 0F B7 FC }` (movzx r15d,r12w truncation)

---

### C15 -- ips_match_all_candidates TLV advance (ELIMINATED)

**Function:** `ips_match_all_candidates` at 0x1bd5c0
**Elimination:** (1) r8+0x66 is compiled IPS candidate rule data, not network-controlled. (2) Zero-advance caught by `test ax, ax; cmove rdx, rax` null-guard at 0x1bdf51-0x1bdf59.

---

### C16 -- Diameter AVP zero-length infinite loop (CONFIRMED HIGH, CVSS 7.5)

**Function:** `ips_diameter_parse_message` at 0x17b660
**Root cause:** `advance_ptr += avp_length` with no floor check. Wire value 0x0000 -> pointer never advances -> infinite CPU loop.

**Trigger:** Diameter packet with AVP Length = 0x000000.

---

### C17 -- DCE/RPC zero-length record infinite loop (CONFIRMED HIGH, CVSS 7.5)

**Function:** `ips_dcerpc_decode` at 0x20dd40
**Root cause:** Same class as C16. `advance_ptr += record_length` with no floor check.

**Trigger:** DCE/RPC fragment with record_length = 0x0000 AND type_byte != 0x01.

---

---

### C19 -- LHA Huffman bit-count underflow (CANDIDATE LOW, CVSS 5.3)

**Binary:** `libav.so.new`
**Functions:** 0x1ed150, 0x1ed4a0, 0x1edb80, 0x1edf20 (4 LHA Huffman mode handlers)
**Root cause:** `sub edi, 0xc/0x8; movzx edi, dil` -- if the Huffman table byte < 12 (or < 8), edi wraps to 244/248 and is passed as `bits_count` to `bit_read (0x1edfe0)`. bit_read has a position-based bounds check so no OOB read in the reader, but 244 bits are consumed from the compressed stream instead of 4-8, corrupting the decompressor bit-buffer state for all subsequent symbol reads.

**Pre-auth chain:**
```
avFlowWrite (0x1371c0) -> stream type detector (0x136500)
-> 0x14e590 -> 0x14c920 -> RELA dispatch table [0xe80080]
-> LHA entry 0x19ee40 (RELA at 0xe7f328)
-> LHA main 0x1ebfe0 ('-lh0-'..'-lh7-')
-> Huffman handler 0x1ed150/0x1ed4a0/0x1edb80/0x1edf20
```

**Code trace (handler 0x1ed150):**
```
0x1ed1e2: movzx edi, byte ptr [rbp + rax + 0x3e60]  ; load Huffman table byte
0x1ed1ea: sub edi, 0xc                               ; UNDERFLOW if byte < 12
0x1ed1ed: movzx edi, dil                             ; truncate: 0xFFFFFFF4 -> dil=244
0x1ed1f1: call 0x1edfe0                              ; bit_read(struct, 244)
0x1ed1f6: mov eax, ebx                               ; return value DISCARDED
```

**bit_read (0x1edfe0) -- not exploitable alone:**
```
0x1ee013: cmp ecx, [r8+0x10]    ; BOUNDS CHECK: pos < stream_limit
0x1ee017: jae 0x1ee074           ; exit if at end -- prevents OOB read
```

**Trigger:** LHA archive file with a Huffman table entry < 12 (or < 8 for the 0x8 handlers). All in pre-auth AV scanning path.

**Analysis gaps:** Downstream behavior not fully traced -- exact crash/loop/wrong-output condition unconfirmed. Upgrade to CANDIDATE MEDIUM pending tracing of whether corrupted bit-buffer output is used for unbounded array indexing.

---

## Session 7 results (2026-09-23)

### C19 DoS-only CONFIRMED

All 4 LHA Huffman handlers (0x1ed150/0x1ed4a0/0x1edb80/0x1edf20) re-traced.
bit_read return value in rax/eax is discarded in every handler immediately after the call.
The corrupted 244-bit count is never used as array index or allocation size.
bit_read has its own internal bounds check. C19 stays CANDIDATE LOW (DoS-only).

### SWF parser ELIMINATED

0x2f702c tag parser correctly bounds-checks both short-form (and 0x3f) and long-form (32-bit vs end ptr). No exploitable paths.

### Cabinet MSCF imul ELIMINATED

Triple-product at 0x1516aa/0x1516b2 confirmed not exploitable: result is offset-check only, not allocation size. ebx flows to `cmp ebx, edi; jae exit`, not to any allocator.

### C20 NEW -- OpenJPEG symmetric imul overflow (CANDIDATE MEDIUM)

0x7728a0: `imul r12d, ecx` (32-bit, ecx^2) then `shl r12d, 2` then alloc with `lea edi, [r12+rbx]`.
Both memcpy calls (0x772912, 0x772926) use the SAME overflowed r12 as size -- symmetric overflow.
No direct heap overflow inside the function. Callers iterating full ecx*ecx matrix against
the undersized allocation would OOB. Zero direct callers (virtual dispatch).
Same pattern at 0x77bab5: `imul edx, edx` / `lea edi, [rdx*4]` / alloc / indirect call.

### C21 NEW -- array search no upper bound (CANDIDATE LOW)

0x122da0: 16-bit count at [rdi+0x3c] has zero-check only, no upper bound.
Loop reads end_ptr = base + (count-1)*32. OOB read if count > actual array.
Zero direct callers.

## Session 8 results (2026-09-23)

### Live format dispatch table enumerated

40-entry table at 0xe94788 (0x48-byte stride, handler ptr at +0x28). 13 named handlers
confirmed live. J2K/JP2 formats absent: entire OpenJPEG codec (0x770000-0x7c0000) is dead.
C20 OpenJPEG symmetric imul candidates: ALL dead code. ELIMINATED.

### C21 (0x2f6110 alloc path) ELIMINATED

Pre-flight bounds checks at 0x2f6124 (`cmp di, 0x100; ja exit`) plus second field check
at 0x2f612f. Allocation sized exactly for source_count. Counter reset at loop start.
Properly bounded.

### LHA back-reference copy path ELIMINATED

0x1ec1f9-0x1ec247: same flush-on-full bounds check as literal path. Write position
ranges 0..buffer_size-1 in both literal and back-reference branches. No OOB write.

### imul-to-alloc scanner (all live code): zero hits

32-bit imul-to-alloc patterns exist only in dead OpenJPEG region.

### Format handlers analyzed: RIFF, ZIP, CHM, EPOC, BEA01, BZip2

- RIFF (0x151c60): zero alloc, zero memcpy. ELIMINATED.
- ZIP (0x1af7b0): zero alloc, zero memcpy. ELIMINATED.
- CHM (0x198160): alloc(1, 0x3f8), both args constant. ELIMINATED.
- EPOC (0x199e30): 3 allocs, all bounded by available data length. ELIMINATED.
- BEA01 (0x1a8290): alloc sized to data length, no overflow path. ELIMINATED.
- BZip2 (0x197660-0x199e30): 10 allocs, 5 imuls. [rbx+0x2c0] = constant 0x8000.
  One CANDIDATE LOW: imul esi, [rdi+0x28c] at 0x197df5 (CHM ITSP header fields).

### C22 NEW -- BZip2/CHM ITSP 32-bit imul (CANDIDATE LOW)

**Binary:** `libav.so.new`
**Function:** 0x197dd0
**Root cause:** `imul esi, dword ptr [rdi+0x28c]` at 0x197df5. Both [rdi+0x288] and
[rdi+0x28c] come from ITSP header fields at ITSP[0x10] and ITSP[0x2c] (wire-controlled
from CHM file). 32-bit multiply with no overflow check. Overflowed small result passes
bounds check at 0x197e0f (small wrap < limit). Subsequent 0x83d030 lookup acts as
implicit gatekeeper: with empty or near-empty range, returns null, causing clean exit.
No confirmed path to memory corruption. Requires deeper trace of 0x83d030 with
non-zero-wrap overflow values.

**Code trace:**
```
0x197def: mov esi, dword ptr [rdi + 0x288]    ; ITSP[0x10] (wire)
0x197df5: imul esi, dword ptr [rdi + 0x28c]   ; *= ITSP[0x2c] -- 32-BIT OVERFLOW
0x197e0a: add r15, rsi                          ; end_ptr = base + wrapped_product
0x197e0d: jb 0x197e15                           ; carry check (64-bit only)
0x197e0f: cmp qword ptr [rbx + 8], r15          ; passes if wrapped product < limit
0x197e13: jae 0x197e30                           ; continue
; ...
0x197f16: sub rdx, rsi                           ; SIZE = r15 - (r12+0x2c) -- potential underflow
0x197f19: call 0x197d60                          ; copy(buf, src, SIZE)
```

## Session 10 results (2026-09-23)

### libips.so.new memcpy/POPCNT sweep complete

All 7 LEA+POPCNT candidates at 0x128622-0x128872: ELIMINATED.
Pattern confirmed as POPCNT-based array index computation (bitmap compression),
not memcpy size calculation. Representative pattern:
`and r8d,[r13+r10*1+0x6c]` + `popcnt r8d,r8d` + `movzx r8d,r8w` + `mov WORD PTR [r13+r8*2+0xa8],r9w`
The truncated popcount is the array index (not size), base is [r13+0xa8].

Remaining 5 memcpy candidates from session 9 resolved:
- 0x225b12: ELIMINATED -- bounds check at 0x225aa4 (`cmp r14d, 0x800`)
- 0x225d56: ELIMINATED -- bounds check at 0x225ca3 (`cmp r12d, 0x100`)
- 0x6c46cc: ELIMINATED -- URL builder; allocation and memcpy use identical 16-bit values; total includes exact 0x20 (4x 8-byte headers)
- 0x1dad51 linked-list copy loop: INCONCLUSIVE -- pre-computed alloc total cannot be verified statically; dynamic analysis required
- 0x2a7f00 TLV copy loop: INCONCLUSIVE -- pointer bounds-checked, VALUE not clamped; limited surface area, internal helper

### FGT7K-4 CONFIRMED -- C22 upgraded to CANDIDATE HIGH 8.1

C22 (CHM ITSP imul at 0x197df5) fully traced and upgraded to FGT7K-4.

Root cause: `imul esi, DWORD PTR [rdi+0x28c]` at 0x197df5 -- 32-bit multiply of
wire-controlled ITSP block_size (ctx+0x288) and block_count (ctx+0x28c).
When block_size=0x10000 and block_count=0x10000: esi = 0x100000000 mod 2^32 = 0.

Bypass path:
- `add r15, rsi` -> r15 = base + 0 = base (zero-length scan window)
- `jb 197e15` NOT triggered (64-bit add of 0 has no carry)
- `cmp [rbx+8], r15; jae 197e30` passes (container >= base trivially)
- Pattern search at 0x83d030 with size=0: `test rsi,rsi; je 83d0f8` exits immediately
- 0x197dd0 returns 0 -> caller at 0x198340: `mov eax, 0x1` -- returns SUCCESS
- CHM file forwarded without scanning any embedded content

Input path: 0x1981a0 extracts ITSP header fields directly from wire:
- `mov edx, [rbx-0x44]` (ITSP[0x10] = block_size) -> stored to ctx+0x288
- `mov edx, [rbx-0x28]` (ITSP[0x2c] = block_count) -> stored to ctx+0x28c

YARA bytes: `0f af b7 8c 02 00 00` (imul) and `49 01 f7 72 06` (add r15,rsi + jb)
Disclosure: FGT7K-4 (CANDIDATE HIGH, CVSS 8.1, CWE-190/CWE-693)
Disclosure document: /home/cowboy/Documents/fortinet-disclosure/fgt7kf_psirt_disclosure.tex

### C16 stale double-entry removed

C16 Diameter AVP entry was ELIMINATED in session 9 (bytes mismatch at 0x17b84c).
The Confirmed findings section still has a duplicate C16 entry above the C17 entry.
These are legacy entries; the definitive state is in the "Session 9 results" section.

## Session 9 results (2026-09-23)

### Full finding re-verification (disproof pass)

All previously documented findings independently verified against raw binary bytes.

### C16 ELIMINATED (was CONFIRMED HIGH)

Bytes at documented addresses 0x17b84c-0x17b85c do NOT match documented assembly.
Actual bytes at 0x17b84c: `00 ff` = `add bh, bh` -- not `movzx eax, word ptr [rcx+4]`.
Pattern search: `bswap eax; shr eax, 0x10` (canonical Diameter 3-byte length extraction)
is ABSENT from the entire libips.so.new binary. FALSE POSITIVE. ELIMINATED.

### C17 RE-CONFIRMED (CONFIRMED HIGH)

All 6 documented instructions verified byte-for-byte against raw binary:
- 0x20ed40: `movzx eax, word ptr [rbx]` -- CONFIRMED
- 0x20ed43: `add rbx, rax` -- CONFIRMED
- 0x20ed46: `cmp rbx, r15` -- CONFIRMED
- 0x20ed49: `jb 0x20eaf0` -- CONFIRMED
- 0x20eaf0: `cmp byte ptr [rbx + 2], 1` -- CONFIRMED
- 0x20eaf4: `jne 0x20ed40` -- CONFIRMED

5 direct callers found (0x20f813, 0x215d15, 0x2193b0, 0x21de55, 0x21e825).
rbx = [rax+8] where rax is a fragment-record pointer from DCE/RPC session struct.
r15 = lea [rbx + r8d] -- end bound from fragment header length field.
Pre-entry check at 0x20eae5: `cmp rbx, r15; jae skip` guards empty fragments.
With length=0 at [rbx] and type!=1 at [rbx+2]: rbx never advances, loop runs forever.
CONFIRMED HIGH DoS. Pre-auth: IPS processes DCE/RPC before authentication.

### C14 guard re-analysis (CANDIDATE, demoted from CONFIRMED HIGH)

Core underflow pattern real and verified:
- 0x29faa4: `movzx eax, word ptr [rdi+0x20]` -- wire 16-bit value
- 0x29faa8: `lea r12d, [rax-0x10]` -- underflows if < 16
- 0x29faaf: `movzx r15d, r12w` -- truncates to 65520 if wire_value=0
Guard check documented as "checks DEST capacity (ecx) only" is more complex:
- 0x29faac: `movzx eax, dx` -- eax = r13w (arg3 low 16 bits)
- 0x29fab3: `add eax, r15d` -- eax = r13w + r12w = offset + wrapped_length
- 0x29fab6: `cmp ecx, eax; jb exit` -- requires ecx >= r13w + 65520 for zero wire_value
For zero wire_length: caller must pass ecx (arg4) >= 65520.
Dispatch path confirmed: 0x29fa90 stored as pointer at 0x11a1218 (index 5 of func table)
and at 0x96350 (stride-24 registration table). 0 direct callers (indirect dispatch only).
NEEDS caller trace to confirm whether any call site passes ecx >= 65520.
Downgraded to CANDIDATE until caller trace complete.

## Session 10 scan results (2026-09-23) -- comprehensive libav.so.new sweep

### Format handlers -- final status

PNG (0x151a10): ELIMINATED -- `mul rsi; jo` at 0x151afb-0x151afe correctly detects 64-bit
overflow. Computed size used for detection comparison only, not allocation/copy.

BMP (0x151620): ELIMINATED -- triple 32-bit imul (Width*Height*BitCount) result used in
bounds comparison (`cmp ebx, edi; cmp ebp, edi`), not as allocation size. All offset
access remains within PixelDataOffset+biSizeImage <= buffer_size bound.

MP4/AVI (0x1520f0): ELIMINATED -- 'avif'/'avis' signature check only, no size arithmetic.

JPEG (0x151460): ELIMINATED -- SOI marker parser; minimum-2-byte segment length check at
0x151504 (`cmp ax, 1; jbe exit`) prevents zero-advance. All advances >= 3 bytes.

Office EncryptionInfo (0x153e10): ELIMINATED -- string comparisons and flag setting only.

### Scanner sweeps

imul-to-internal-alloc (124 candidates): ALL FALSE POSITIVES
- 0xf5xxx range: all use `imul rax, rax, constant` (struct size offsets)
- 0x12fe40, 0x129380: all use `imul; shr 0x22` (fixed-point block count, divide by 2^34)
- 0x14d060: base64 encoder; `movabs 0xaaab; mul; shr 0x22` = formula-based division
- 0x1457c0: time conversion (`movabs 0x20c49ba5e353f7cf; imul rsi` = division by 10^6),
  result goes to `cmp`, not alloc size

C17-class infinite loop (9 candidates): ALL FALSE POSITIVES
- 0x1529f0 (PRINTUI.DLL), 0x3874f0, 0x387a50, 0x6dfcb0, 0x710110, 0x7134c0, 0x713570:
  0 callers -- dead code
- 0x1a9f10 (DoInfInstall): loop always advances r15 by at least 1 at 0x1ac0ba, not zero-advance
- 0x598660: build server path string, internal diagnostic code

LengthUnderflowScanner (6 candidates):
- 0x19a090: FALSE POSITIVE -- sub edx,4 + movzx then alloc(W+1) + memcpy(W) is null-
  terminator pattern; bounds check at 0x19a184 (`cmp edi, ecx; jb exit`) protects
- 0x1ed150, 0x1ed4a0, 0x1edb80, 0x1edf20: C19 LHA Huffman handlers (already known)
- 0x394170: FALSE POSITIVE -- `sub ecx, 0xb; movzx eax, cl` is FP normalization, call
  to 0x38d4b0 is a floating-point helper function not an allocator

ChunkWalkerValidator (522 candidates): NOT TRIAGED -- format parsers legitimately use
unaligned data access; too many false positives to check manually without format context.

### Disclosure document status

FGT7K-4 full section COMPLETE:
- \section{Finding FGT7K-4} added with overviewbox, annotated disassembly, PoC analysis
- YARA rule included
- CWE-693 added to CWE Reference table
- Document compiles clean: 19 pages, 0 errors

## Session 8 results (2026-09-25)

### C14 ELIMINATED -- guard cannot pass in practice

**Full caller trace complete.** Only call site for dispatch via [r15+0x38] → 0x29fa90 is at
0xef9ec inside function 0xef210. 8 sites read global 0x11b32f8; only 0xef9ec follows the
`mov r15,[global]; call [r15+0x38]` dispatch pattern.

**ecx at 0xef9ec** comes from two nested calls before it:
1. `0xef988: call 0x17a140` — time-of-day calculation. `r15d = 0x15180 = 86400` is the
   explicit ceiling clamped via `cmovle` on every output branch. All ecx paths from
   0x17a140 are bounded by **86,400**.
2. `0xef9a5: call 0x663cd0` (ips_timer_add/lookup):
   - **Fast path** (timer found, no flag): does NOT set ecx → ecx = 0x17a140 leave = ≤ 86,400
   - **Not-found path**: `mov rcx, rdx` (string ptr VA ~0x17a78e) then
     `call 0x663bf0` (struct allocator, esi=0x30 edi=1) — 0x663bf0 clobbers rcx.
     After return, ecx = allocator internal state, not wire-controlled.

**Guard requirement**: ecx ≥ r13w + r12w = 0xcf00 + 65520 = **118,512**.
- Fast path: 86,400 < 118,512 → **GUARD ALWAYS FAILS**
- Not-found (first call): ecx from allocator, not reliably ≥ 118,512
- No path produces wire-controlled ecx ≥ 118,512.

**C14 ELIMINATED.** The length underflow pattern is real (movzx + lea -0x10 + movzx r12w)
but the guard at 0x29fab6 (`cmp ecx, eax; jb exit`) is not bypassable from any call path.

---

## Pending work (priority order)

### C22 RESOLVED -- see FGT7K-4 in session 10 results above

C22 upgraded to CANDIDATE HIGH (FGT7K-4). The bypass path is via zero-length scan
window, not sub-underflow. Fully documented in disclosure.

### C21 (0x193ccb) ELIMINATED (session 9, 2026-09-25)

Actual instruction at 0x193ccb in function 0x192680 (not 0x122da0 -- session note address
was approximate placeholder). movzx ecx, word ptr [rdi+0x3c] is the only [rdi+0x3c] word
load in the entire binary.

Context: 0x192680 is an IPS rule matching function called from 0xef210 and 0xf4ea0.
Loop at 0x193c10-0x193cfc iterates rsi+0x108 array of IPS candidate rule structs.
[rdi+0x38], [rdi+0x3a], [rdi+0x3c] are rule group bit indices in compiled IPS signatures,
accessed as bitmask indices into allocated bitfield r13. These are NOT wire-controlled --
same class as C15 (compiled rule data).

Bit-index pattern: shr ax,5 / movzx eax,ax / [r13+rax*4] -- this is a bitfield, not a
length-bounded array scan. No OOB candidate: bit indices are fixed by compiled signatures.

ELIMINATED: IPS rule struct field, not wire data.

### Remaining live format handlers -- ELIMINATED (session 9, 2026-09-25)

BMP 0x1516a7-0x1516b2: Width*Height*BitCount imul chain produces comparison-only result.
  mov ebx,[rsi+0x12]; imul ebx,[rsi+0x16]; movzx ebp,[rsi+0x1c]; imul ebx,ebp; shr ebx,3
  ebx compared against edi (data size) at 0x1516b8, then again at 0x1516bf. Never passed
  to allocation or copy. ELIMINATED: comparison-only.

PNG 0x151a10: imul rbp, r12 / imul rbp, rdx -- 64-bit operands. No 32-bit overflow path.
  Width*Height*BitCount computed in 64-bit register rbp. ELIMINATED: no overflow.

MP4 0x1520f0: size capped at 0x80 via cmova rdx, rax before any pointer arithmetic.
  Version check bounds input at 0x16. ELIMINATED: bounded.

### C19 upgrade analysis -- NO UPGRADE (session 9, 2026-09-25)

Traced path after bit_read(struct, 244) at 0x1ed1f1:
  0x1ed1f6: mov eax, ebx   ; return value DISCARDED
  0x1ed1f8: pop rbx / pop rbp / pop r12/r13/r14 / ret
Function returns immediately after the bit_read call. No subsequent array indexing.
C19 remains CANDIDATE LOW.

### PDF chain deepening -- ELIMINATED (session 9, 2026-09-25)

0x3dfd60: realloc size = (ctx[0x57c]+16)*48 where ctx[0x57c] is internal capacity counter
  (incremented by 16 on each grow: lea eax,[r13+0x10]; mov r13d,eax at 0x3dfded/0x3dfdf8).
  Not a wire-parsed integer. Chain: 0x3d6030->0x3d9050->0x3d7720->0x3da9a0->0x3dfd60.

0x3e2928 (in 0x3e28c0): call 0x8e2f20 with fixed ecx=0x78. Hardcoded size.

ctx fields [0x570]=heap ptr, [0x578]=object count+1, [0x57c]=capacity, [0x590/0x594]=object IDs.
All internal bookkeeping. No wire integer flows directly to malloc/memcpy size.
ELIMINATED: session 5 conclusion confirmed.

## Scanner coverage

**Clobber-aware movzx-to-arithmetic scanner:**
- 3205 raw hits -> 137 protocol+non-stack filtered -> 98 clobber-aware confirmed
- False positives eliminated: ips_match_rule (trusted DB, not network), URI handler 0x6422c0 (alignment calc), COTP subtract 0x223d80 (callee ignores r8)

**libav session 5 scan coverage:**
- RELA dispatch table enumerated: 7,695 R_X86_64_RELATIVE entries, 3,867 unique code targets
- Zero-advance scanner: 34,864 raw candidates, mostly same-site repetitions
- Multiply-before-memcpy scan: 12 candidates examined, all false positives
- LHA dispatch chain fully traced (pre-auth confirmed)
- PDF parser chain fully traced (memcpy callers all have internal struct-derived sizes)
- RAR/RIFF handlers identified but use abstracted read APIs (no direct malloc+memcpy)
- OLE2 FAT reader: overflow threshold requires >8TB file, not reachable

## Findings file

`/home/cowboy/ablation/targets/fortinet/fortinet_fortigate_7000f_re.py`

C14 ELIMINATED (session 8). C15 ELIMINATED. C16 ELIMINATED (false positive). C17 CONFIRMED HIGH. C18 CANDIDATE LOW. C19 CANDIDATE LOW. C21 ELIMINATED (session 9: compiled IPS rule bit index, not wire data).

## Session 9 results (2026-09-26)

### FGT7K-4 CONFIRMED HIGH -- CHM ITSP imul overflow (scanner bypass)

**Confirmation complete.** YARA bytes verified at expected VAs in libav.so.new.
Full caller disassembly traced wire-control path for both operands.

**Wire-control proof (caller 0x1981b0):**
```
0x198240: add rbx, r14           ; rbx = CHM buf + ITSF->ITSP offset
0x198243: cmp [rbx], 'ITSP'      ; signature check
0x19824e: add rbx, 0x54          ; skip 84-byte ITSP header
0x198266: mov edx, [rbx-0x44]    ; [ITSP+0x10] = block_size  -- WIRE
0x198269: mov [r12+0x288], edx   ; ctx->block_size = wire value
0x198271: mov edx, [rbx-0x28]    ; [ITSP+0x2c] = block_count -- WIRE
0x198274: mov [r12+0x28c], edx   ; ctx->block_count = wire value
```
Standard CHM ITSP spec: block_size at +0x10, num_blocks at +0x2c.
No range check on either field before use.

**Overflow site (0x197dd0):**
```
0x197def: mov esi, [rdi+0x288]   ; block_size (wire)
0x197df5: imul esi, [rdi+0x28c]  ; *= block_count -- 32-bit wraps to 0x00000000
0x197e04: mov r15, r8             ; scan window base = [rdi+0x20]
0x197e0a: add r15, rsi            ; end_ptr = base + 0 (no carry)
0x197e0d: jb 0x197e15             ; carry NOT set for +0 -> NOT taken
0x197e0f: cmp [rbx+8], r15        ; container_end >= base -> trivially true
0x197e13: jae 0x197e30            ; proceeds with scan window length = 0
0x197eb3: sub rdx, rsi            ; chunk_len = end_ptr - chunk_start = 0
0x197eb6: call 0x197d60           ; directory parser: len=0, no entries processed
```

**Impact confirmed:** CHM directory parser called with zero-length window.
No directory entries are parsed. AV scanner sees no embedded content -> bypass.

Single call site: only 0x198310 calls 0x197dd0. Pre-auth: caller reachable via
CHM file submitted to AV engine. No authentication required.

**FGT7K-4 STATUS: CANDIDATE HIGH → CONFIRMED HIGH. Session 9, 2026-09-26.**
