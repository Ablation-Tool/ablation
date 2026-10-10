# PPC32TaintTracker

**File:** `ablation/analyzers/taint_tracker_ppc32.py`

Interprocedural taint analysis for 32-bit PowerPC (big-endian and little-endian).
Traces network-sourced data from read/recv/pread/fgets to command-execution sinks
(system, execl, popen) and memory-corruption sinks (strcpy, sprintf, memcpy).

Targets: Cisco 7200/3700 IOS (big-endian), Huawei S6720/S6720EI boot ROM (big-endian
GOT2 PIC), MikroTik RB600 (big-endian), VxWorks embedded (big-endian), POWER LE
Linux userspace (little-endian), older Fortinet hardware (big-endian).

---

## Usage

```python
from ablation.analyzers.taint_tracker_ppc32 import PPC32TaintTracker

tracker = PPC32TaintTracker.from_path('/path/to/bootload', endian='big')
findings = tracker.run_interprocedural(depth=4)
for f in findings:
    print(f)
```

`endian` defaults to `'big'`. Pass `'little'` for POWER LE Linux userspace binaries.

---

## ABI model

PPC32 System V / EABI:

| Register | Role |
|---|---|
| r0 | Volatile scratch (holds LR in prologue: `mflr r0`) |
| r1 | Stack pointer (never tainted) |
| r2 | Small data anchor / TOC (EABI/POWER, never tainted) |
| r3–r10 | Integer argument registers; r3 = return value |
| r13–r31 | Callee-saved |
| r30 | PIC base register in GOT2 PIC binaries |

External calls always use `bctrl` (branch via CTR) with the target loaded from
GOT2: `lwz rX, N(r30)` / `mtctr rX` / `[crclr cr1eq]` / `bctrl`.

---

## GOT2 PIC support (Huawei / embedded Linux)

PPC32 GOT2 PIC binaries reserve r30 as the per-compilation-unit GOT2 anchor.
Each function prologue captures the PC using a `bcl 20,31,$+4` / `mflr r30`
sequence and then adds a linker-computed offset:

```
bcl  20,31,$+4      ; LR ← bcl_addr + 4  (= mflr_addr)
mflr r30            ; r30 ← LR  (= mflr_addr)
addis r30, r30, HI  ; r30 += sign_extend(HI) << 16
addi  r30, r30, LO  ; r30 += sign_extend(LO)
```

`lr_val` for the base computation is the address of the `mflr` instruction itself.
Different compilation units use different HI/LO constants, so r30 is a per-function
value. The tracker pre-computes r30 for every function in `_func_r30`.

GOT2 entries that point to PLT stubs are indexed in `_got2_va_to_name`. At each
`bctrl` site the tracker computes `got2_va = r30 + disp` and resolves the name.

### LIEF limitation on Huawei PPC32

Huawei bootloaders use vendor-specific ELF relocation type `0x40000054`, which
LIEF reports as invalid and discards. This causes LIEF to return 0 JUMP_SLOT
relocations.

The tracker calls `_load_plt_from_dynsym_raw()` to load SHN_UNDEF dynamic
symbols with non-zero `st_value` directly from the raw ELF section headers.
These are the true PLT stub VAs.  This fallback runs **only when LIEF populated
zero PLT entries** (`if not self._plt:`), which is always the case for Huawei
binaries with the vendor reloc type.

On SYSV PIC binaries (IBM HPS, glibc `.so`), LIEF correctly populates `_plt`
from `.rela.plt` R_PPC_JMP_SLOT entries.  The guard prevents
`_load_plt_from_dynsym_raw()` from running on these binaries; undefined
symbols in SYSV PIC have `st_value=0` and adding them would corrupt the PLT map.

### GCC `crclr cr1eq` between mtctr and bctrl

GCC PPC32 emits `crclr cr1eq` (or `creqv`) between `mtctr rX` and `bctrl` as
a variadic calling convention indicator. The 2-instruction look-back pattern
(`prev2=lwz, prev1=mtctr`) breaks when this extra instruction is present.

The resolver handles this: when `prev1` is not `PPC_INS_MTCTR` but `prev2` is,
and `prev3` (the instruction 3 before `bctrl`) is `PPC_INS_LWZ`, the window
shifts one slot back to recover the `lwz+mtctr` pair.

### Prologue window

PPC32 prologues save LR (`mflr r0`), spill callee-saved registers (`stmw r30`
or individual `stw r30`/`stw r31`), and set up the frame pointer before the
`bcl`/`mflr r30` pair. The `bcl` sits at instruction index 7+ on a typical
function, so a 64-byte (16-instruction) window is used.

---

## Sources and sinks

**Sources** (mark r3 tainted after call):
`recv`, `recvfrom`, `recvmsg`, `read`, `pread`, `fread`, `fgets`, `gets`, `getenv`
and their `@plt` aliases.

**Note on buffer-based sources**: `read(fd, buf, n)` and `pread`/`recv` write
into the buffer argument (r4 before the call). The return value in r3 is a byte
count. Register-level taint tracks r3; actual buffer contents flow through memory
and are not tracked. Findings require the return value to reach a sink register
without intermediate clobbering, which is uncommon. Use `SinkArgClassifier` for
broader argument-provenance classification when taint finds nothing.

**Sinks** (fire when the listed arg register is tainted):

| Sink | Tainted arg | Notes |
|---|---|---|
| `system`, `popen` | r3 | command string |
| `execl`, `execle`, `execlp` | r3 | path |
| `execv`, `execvp`, `execve` | r3 | path |
| `strcpy`, `strcat` | r4 | src |
| `strcpy_s`, `strcat_s` | r5 | src (Huawei secure variants) |
| `sprintf` | r4 | fmt |
| `sprintf_s` | r5 | fmt |
| `snprintf` | r5 | fmt |
| `snprintf_s` | r6 | fmt |
| `memcpy`, `memmove` | r5 | count |
| `memcpy_s` | r6 | src |
| `malloc`, `calloc`, `realloc` | r3/r4 | size |

---

## Taint propagation

Register taint propagates through arithmetic (`add`/`addi`/`subf`/`mullw`/`divw`),
logic (`and`/`or`/`xor`/`rlwinm`), moves (`mr`), and pointer dereferences (`lwz`
from a tainted base register). `li`/`lis` (immediate loads) and `mflr` clear
destination taint. Loads from a non-tainted base register also clear destination
taint (the destination is being overwritten with an untainted value; prior taint
does not survive the overwrite).

Stack-level taint (tainted value stored via `stw` and later re-loaded via `lwz`)
is not tracked. Binaries that route all network data through stack buffers before
passing them to sinks will show 0 findings; use `SinkArgClassifier` for those.

---

## Interprocedural depth

`run_interprocedural(depth=4)` seeds from functions that call a source, then
follows tainted arguments through direct BL calls up to `depth` hops. GOT2
indirect calls (`bctrl`) to unresolved internal function-pointer entries are
treated as clobbering r3–r10.

---

## Known limitations

1. **Memory taint**: stack buffers are not modelled. Any flow that routes tainted
   data through a local buffer before the sink call is invisible to the tracker.

2. **Unresolved GOT2 entries**: only PLT stubs (SHN_UNDEF dynsym entries) are
   in `_got2_va_to_name`. GOT2 entries pointing to internal function pointers or
   data constants appear as `??` and clobber r3.

3. **LIEF relocation bug (Huawei-specific)**: LIEF silently discards relocations
   with vendor-specific types. `_load_plt_from_dynsym_raw()` works around this
   for Huawei GOT2-PIC binaries (triggered by `if not self._plt:` guard).
   SYSV PIC binaries (glibc `.so`) are not affected; LIEF handles their
   standard R_PPC_JMP_SLOT relocations correctly.
