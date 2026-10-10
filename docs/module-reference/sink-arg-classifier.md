# SinkArgClassifier

**File:** `ablation/analyzers/sink_arg_classifier.py`

Classifies what argument is passed to exec-class sinks (system, popen, execve, execl, execvp) and
assigns a provenance verdict: the string is either a hardcoded RODATA literal, an snprintf output
built from a RODATA format string, a propagated function argument, or an unresolved unknown.

---

## Why this exists

Three things that were not possible in Ablation before this module:

1. Triage an entire firmware rootfs for exec-sink exposure in one call, without loading each binary
   individually. Before `batch_plt_intersect`, identifying which files even imported system/popen
   required iterating every ELF and parsing its imports by hand.

2. Know with confidence that a system() call is not injectable. Pattern-match alone cannot say "this
   call is safe." RODATA_CONST and SNPRINTF_RODATA verdicts give that answer automatically and
   eliminate the majority of call sites from manual review.

3. Handle ARM32 LE and ARM64 LE firmware trees in batch triage. The initial x86-64-only
   implementation returned empty results for all ARM-family binaries. Huawei VRP S6730
   (ARM32 LE) and NE40E (ARM64 LE) firmware contained hundreds of exec-class imports that
   batch_plt_intersect() silently dropped.

---

## Usage

```python
from ablation.analyzers.sink_arg_classifier import SinkArgClassifier, batch_plt_intersect

# Batch triage: which files in this tree import exec sinks?
# Works on x86-64, ARM32 LE, and ARM64 LE ELFs.
hits = batch_plt_intersect('/path/to/firmware/rootfs/')
for path, sinks in sorted(hits.items()):
    print(path, sinks)

# Full argument classification (x86-64 only)
clf = SinkArgClassifier.from_path('/path/to/binary.so')
for r in clf.classify_all():
    print(r.fmt())

# Vendor-specific sinks
clf.add_sink('fadcsystem', arg_pos=1)
clf.add_sink('sys_vdom_exec', arg_pos=1)
results = clf.classify_all()
```

---

## Verdicts

`RODATA_CONST` means the sink argument is a pointer directly into `.rodata`. No injection is
possible regardless of caller context.

`SNPRINTF_RODATA` means the sink argument is a stack buffer filled by snprintf with a `.rodata`
format string. Injection requires controlling a `%s` argument in that format string. Integer-only
formats (`%d`, `%u`) are safe.

`ARG_PROPAGATED` means the argument arrived in an entry register. The caller controls it, so the
question moves up one level.

`UNKNOWN` means provenance was not resolved in the look-back window. Treat the same as
ARG_PROPAGATED for severity purposes.

---

## ARM PLT support

`batch_plt_intersect` dispatches to an arch-appropriate PLT parser based on the ELF machine type.

**ARM32 LE** uses `.rel.plt` with 8-byte REL entries (no addend). The reloc type for a PLT import
is `R_ARM_JUMP_SLOT = 22`. Stub layout: 20-byte header followed by 12-byte stubs. The slot index
in `.rel.plt` maps directly to the stub index, so stub VA = plt_base + 20 + slot_index * 12. This
was confirmed on Huawei VRP S6730 V200R024 ARM32 LE firmware.

**ARM64 LE** uses `.rela.plt` with 24-byte RELA entries, but r_info is packed little-endian: the
low 32 bits hold the reloc type and the high 32 bits hold the symbol index. The x86-64 path read
r_info as a big-endian uint64, which inverted the two halves and produced sym_idx = 0 for every
entry. The fix uses `struct.unpack('<QQq', ...)` with `R_AARCH64_JUMP_SLOT = 0x402` and stub VA =
plt_base + 32 + slot_index * 16. Confirmed on Huawei VRP NE40E V800R023 and V800R024 ARM64 LE
firmware (HiSilicon Hi1280 MPU).

For full argument classification on ARM32 or ARM64, use the appropriate taint tracker
(ARM32TaintTracker or ARM64TaintTracker) rather than SinkArgClassifier, which only classifies
x86-64 argument registers.

---

## batch_plt_intersect

```python
hits = batch_plt_intersect('/path/to/rootfs/', sinks=['system', 'popen'])
```

Returns a dict mapping ELF paths to the list of matching sink names. Files with no matches are
omitted. Pass `recursive=False` to scan a flat directory. The function walks symlinks only if
they resolve to files directly, not if they are symlinked directories.

Any file whose PLT contains none of the target sinks is safe from exec-class injection through
those sinks and needs no further analysis.

---

## Limitations

Argument classification is x86-64 only. ARM32 and ARM64 binaries are supported for triage
(batch_plt_intersect) but not for provenance classification.

The look-back window for argument tracing is bounded. A command string built more than one
function hop before the sink will likely resolve as ARG_PROPAGATED or UNKNOWN rather than
SNPRINTF_RODATA.

Stack slots written by two separate 4-byte movabs pairs remain UNKNOWN. This is a known
limitation of the GAP-002 fix for GCC packed-string optimization.
