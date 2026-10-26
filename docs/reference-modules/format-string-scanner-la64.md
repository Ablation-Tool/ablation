# FormatStringScannerLA64

  - [Why this exists](#why-this-exists)
  - [How it works](#how-it-works)
  - [Format argument positions](#format-argument-positions)
  - [Usage](#usage)
  - [Adding firmware-specific wrappers](#adding-firmware-specific-wrappers)
  - [Example output](#example-output)
  - [Verdicts](#verdicts)
  - [SAC limitations that apply here](#sac-limitations-that-apply-here)
  - [Pipeline position](#pipeline-position)
  - [See also](#see-also)

**File:** `ablation/analyzers/format_string_scanner_la64.py`

---

## Why this exists <sup>[↑](#formatstringscannnerla64)</sup>

`FormatStringScanner` (x86-64) cannot run on LoongArch64 binaries: it requires Capstone's x86 backend, which does not exist for LA64. Its `.rodata` detection method — recognising a RIP-relative `LEA` instruction — has no equivalent on LA64.

LA64 builds `.rodata` pointers with two-instruction PC-relative sequences:

```
pcaddu12i $rD, imm              → $rD = PC + imm * 4   (one-insn form)
pcalau12i $rD, hi20             → $rD = page(PC) + hi20 * 0x1000
addi.d    $a1, $rD, lo12        → $a1 = $rD + lo12     (two-insn form)
```

`SinkArgClassifierLA64` already detects both forms in its `_trace_arg()` method and returns `RODATA_CONST` when the resolved address falls inside `.rodata`. `FormatStringScannerLA64` reuses that infrastructure with a different sink registry: instead of exec sinks (`execv`, `system`, …), it registers the printf family (`printf`, `fprintf`, `snprintf`, `syslog`, `err`, …).

---

## How it works <sup>[↑](#formatstringscannnerla64)</sup>

1. **Build classifier.** Creates a `SinkArgClassifierLA64` instance, clears its default exec-sink registry, and registers all printf-family functions with their correct format-argument positions.
2. **PLT extraction.** The underlying SAC LA64 decodes every 16-byte PLT stub from raw ELF bytes (no Capstone, no LIEF required). Returns a `{stub_va: symbol_name}` map.
3. **Call site scan.** `LoongArchDecoderV2.decode_frames_clean()` walks `.text` and returns every `bl` targeting a fmt-sink PLT stub. The BL split-field encoding (`lo16 = (insn >> 10) & 0xFFFF; hi10 = insn & 0x3FF; offs26 = (hi10 << 16) | lo16`) is handled internally.
4. **Backward trace.** For each call site, `_trace_arg()` walks up to 80 instructions backward from the call to find what loaded the format register. Outcome is one of `RODATA_CONST`, `ARG_PROPAGATED`, or `UNKNOWN`.
5. **Report.** `RODATA_CONST` results are suppressed (safe). `ARG_PROPAGATED` → **HIGH** (CWE-134); `UNKNOWN` → **MEDIUM** (manual review needed).

---

## Format argument positions <sup>[↑](#formatstringscannnerla64)</sup>

LoongArch64 lp64d ABI: first argument in `$a0`, second in `$a1`, third in `$a2`.

| Function | fmt position | arg_pos |
|----------|-------------|---------|
| `printf(fmt, ...)` | `$a0` | 0 |
| `vprintf(fmt, ap)` | `$a0` | 0 |
| `warn(fmt, ...)` | `$a0` | 0 |
| `warnx(fmt, ...)` | `$a0` | 0 |
| `vwarn(fmt, ap)` | `$a0` | 0 |
| `vwarnx(fmt, ap)` | `$a0` | 0 |
| `fprintf(f, fmt, ...)` | `$a1` | 1 |
| `vfprintf(f, fmt, ap)` | `$a1` | 1 |
| `sprintf(buf, fmt, ...)` | `$a1` | 1 |
| `vsprintf(buf, fmt, ap)` | `$a1` | 1 |
| `asprintf(ptr, fmt, ...)` | `$a1` | 1 |
| `vasprintf(ptr, fmt, ap)` | `$a1` | 1 |
| `dprintf(fd, fmt, ...)` | `$a1` | 1 |
| `vdprintf(fd, fmt, ap)` | `$a1` | 1 |
| `syslog(pri, fmt, ...)` | `$a1` | 1 |
| `vsyslog(pri, fmt, ap)` | `$a1` | 1 |
| `err(eval, fmt, ...)` | `$a1` | 1 |
| `errx(eval, fmt, ...)` | `$a1` | 1 |
| `verr(eval, fmt, ap)` | `$a1` | 1 |
| `verrx(eval, fmt, ap)` | `$a1` | 1 |
| `snprintf(buf, n, fmt, ...)` | `$a2` | 2 |
| `vsnprintf(buf, n, fmt, ap)` | `$a2` | 2 |

---

## Usage <sup>[↑](#formatstringscannnerla64)</sup>

```python
from ablation.analyzers.binary_context import BinaryContext
from ablation.analyzers.format_string_scanner_la64 import FormatStringScannerLA64

ctx = BinaryContext.load_or_build('/path/to/la64_binary')
scanner = FormatStringScannerLA64.from_context(ctx)
findings = scanner.scan()
print(scanner.report(findings))
```

Or from a path directly:

```python
scanner = FormatStringScannerLA64.from_path('/path/to/la64_binary')
findings = scanner.scan()
```

---

## Adding firmware-specific wrappers <sup>[↑](#formatstringscannnerla64)</sup>

Many firmware images define logging wrappers that forward to `printf`/`syslog` with an extra tag or priority argument prepended. Register them before calling `scan()`:

```python
# log_printf(tag, fmt, ...)  — fmt is second arg
scanner.add_extra_sink('log_printf', arg_pos=1)

# dbg_printf(fmt, ...)  — fmt is first arg
scanner.add_extra_sink('dbg_printf', arg_pos=0)

# err_printf(severity, module, fmt, ...)  — fmt is third arg
scanner.add_extra_sink('err_printf', arg_pos=2)

findings = scanner.scan()
```

Calling `add_extra_sink()` after `scan()` invalidates the cached classifier so the next `scan()` call rebuilds with the new registry.

---

## Example output <sup>[↑](#formatstringscannnerla64)</sup>

```
[FormatStringScannerLA64] 2 finding(s)  HIGH=1  MEDIUM=1
  HIGH    fmt_string  func=0x12340+0x88  syslog($a1?)  or $a1, $s3, $zero (callee-saved; SAC-LA64-CALLEE-001)
  MEDIUM  fmt_string  func=0x45670+0x3c  fprintf($a1?)  $a1 not found within 80-insn backward window
```

---

## Verdicts <sup>[↑](#formatstringscannnerla64)</sup>

| Verdict | Severity | Meaning |
|---------|----------|---------|
| `RODATA_CONST` | (suppressed) | Format string is a `.rodata` literal; safe |
| `ARG_PROPAGATED` | **HIGH** | Format arg traces to a function entry register (`$a0`–`$a7`); direct passthrough from caller |
| `UNKNOWN` | MEDIUM | Format arg origin not resolved within 80-instruction backward window |

---

## SAC limitations that apply here <sup>[↑](#formatstringscannnerla64)</sup>

These limitations from `SinkArgClassifierLA64` affect format string scanning identically:

- **SAC-LA64-CALLEE-001**: callee-saved `$s0–$s8/$fp` classified as `ARG_PROPAGATED`. Almost always holds a config path or argv, not network data. Trace the register back to function entry to confirm the source.
- **SAC-LA64-LIM-002**: `pcaddu12i` stored to stack slot by `st.d`, then loaded by `ld.d` in a different basic block → `UNKNOWN`. Read the store site; if it's a `pcaddu12i`, the format argument is `.rodata`.
- **SAC-LA64-LIM-003**: struct field dereference → `UNKNOWN`. Identify the struct type and trace the field to its origin.

---

## Pipeline position <sup>[↑](#formatstringscannnerla64)</sup>

Run after `SinkArgClassifierLA64.classify_all()` (exec sinks) and before `TaintTrackerLA64` (full taint). Format string findings identified here are HIGH priority for manual taint trace because CWE-134 is often directly exploitable without a full call chain.

```
BinaryContext → SemanticSearcher → SinkArgClassifierLA64 → FormatStringScannerLA64 → TaintTrackerLA64
```

---

## See also <sup>[↑](#formatstringscannnerla64)</sup>

- `format_string_scanner.py` — x86-64 equivalent (Capstone-based, RIP-relative LEA detection)
- `sink_arg_classifier_loongarch64.py` — provides the backward trace infrastructure this module wraps
- `loongarch_decoder_v2.py` — BL split-field decoding, KASAN/KCOV stripping
- `docs/reference-modules/sink-arg-classifier-la64.md` — SAC-LA64-CALLEE-001/LIM-001/002/003 catalog
