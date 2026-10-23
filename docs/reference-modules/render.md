# render

`ablation/core/render.py` provides colored terminal output for every Ablation command. It detects what the terminal supports at import time and picks the best color mode automatically. Anyone running an Ablation command on a color terminal gets colored output. Output piped to a file or redirected to CI logs falls back to plain text without breaking anything.

---

## Why this exists

Three things were not possible before this module:

1. **No shared color primitives.** Every script that wanted colored output duplicated the same ANSI escape constants and box-drawing functions. There was no single place to change the color scheme or add a new semantic color.

2. **No automatic fallback.** Scripts used raw escape codes unconditionally, so output piped to a file or read by a downstream tool was littered with literal `\033[38;2;...m` sequences. Checking `isatty()` and `NO_COLOR` was left to individual scripts, and most did not bother.

3. **No color in Ablation's own output.** `ForgeReport.report()`, `ablation analyze`, and similar commands printed plain monochrome text even on terminals that support 24-bit color. The render module fixes that for every caller at once.

---

## Color detection

Detection runs once at import time. The result is stored in `render.MODE`.

| Mode | Condition |
|------|-----------|
| `plain` | stdout is not a TTY, or `NO_COLOR` is set |
| `truecolor` | `COLORTERM=truecolor` or `COLORTERM=24bit` |
| `ansi256` | `256color` in `TERM` |
| `ansi16` | TTY present but no 256-color signal |

No configuration is required. The right mode is picked for the environment.

---

## Color constants

```python
from ablation.core.render import RED, ORANGE, YELLOW, GREEN, BLUE, PURPLE, GRAY, WHITE
from ablation.core.render import RESET, BOLD, DIM
```

| Constant | Semantic use |
|----------|-------------|
| `RED` | Attack surface, confirmed vuln, CRITICAL/HIGH finding |
| `ORANGE` | Boundary, hardware I/O, partial trust |
| `YELLOW` | Transformation, sink, code generation |
| `GREEN` | Safe path, clean finding, gate passed |
| `BLUE` | Static data, read-only resource, cache hit |
| `PURPLE` | Crypto, auth, key material |
| `GRAY` | Annotations, secondary text, borders |
| `WHITE` | Primary labels, container headers |

These are suggestions, not rules. Use whatever color fits the output.

---

## Drawing functions

```python
from ablation.core.render import box, sbox, section, arrow, strip
```

`box(lines, color=WHITE)`: double-border box. Use for top-level containers.

`sbox(lines, color=GRAY)`: single-border box. Use for data blocks and reports.

`section(title, color=GRAY)`: horizontal rule with a title. Use for layer headers.

`arrow(label='', color=GRAY)`: a `│` with an optional inline label.

`strip(s)`: removes all ANSI escape sequences from a string. Use when computing display widths.

Each function respects `render.MODE`, in plain mode they emit no escape codes.

---

## Usage

```python
from ablation.core.render import box, sbox, section, RED, GREEN, GRAY, BOLD, DIM, RESET

print(box([BOLD + 'FORGE  ·  Production Gate' + RESET], color=GRAY))
print(section('FINDINGS', RED))
print(sbox([
    RED + '[CRITICAL] CryptoAudit arity mismatch' + RESET,
    DIM + 'stage: DEVELOP — mypy catches this in 0.1s' + RESET,
], GRAY))
```

Color constants are empty strings in plain mode, so the same code works in every context.

---

## How it works

At import time, `render.py` checks `sys.stdout.isatty()`, the `NO_COLOR` environment variable, and `COLORTERM` / `TERM` to set the module-level `MODE` constant. All color constants (`RED`, `GREEN`, etc.) are then set to the appropriate ANSI escape sequences for the detected mode, or to empty strings if `MODE='plain'`. This means callers can concatenate color constants with strings unconditionally: in plain mode the concatenation produces no escape codes and the string is unchanged. `box()`, `sbox()`, `section()`, and `arrow()` build framed output strings using Unicode box-drawing characters; in plain mode they fall back to ASCII borders. `strip(s)` uses a compiled regex to remove all ANSI escape sequences for computing display-width of a colored string.

---

## Example output

```
┌─────────────────────────────────────────────┐
│  FORGE  ·  Production Gate                  │
└─────────────────────────────────────────────┘
══ FINDINGS ════════════════════════════════════
┌─────────────────────────────────────────────┐
│  [CRITICAL] CryptoAudit arity mismatch      │
│  stage: DEVELOP — mypy catches this in 0.1s │
└─────────────────────────────────────────────┘
```

In `plain` mode pipe/redirect, the same code prints:

```
+---------------------------------------------+
|  FORGE  ·  Production Gate                  |
+---------------------------------------------+
== FINDINGS ====================================
+---------------------------------------------+
|  [CRITICAL] CryptoAudit arity mismatch      |
|  stage: DEVELOP                             |
+---------------------------------------------+
```

---

## False positives

`render.py` does not emit security findings. The only failure mode is rendering: in rare terminal configurations where `COLORTERM` is not set but the terminal supports 256 colors, `MODE` may fall back to `ansi16`, producing less saturated colors than expected. Set `COLORTERM=truecolor` explicitly to force 24-bit mode.

---

## Pipeline position

**Before this module:** No prerequisites. Import at the top of any module that produces terminal output.

**After this module:** Pass the formatted strings from `box()`, `sbox()`, and `section()` directly to `print()`. No further processing is required: all escape codes are embedded in the returned strings, and `strip()` is available if display-width calculation is needed.

---

## Reading output

`render.py` provides module-level terminal formatting functions, no findings, no return values beyond strings:

| Function | Returns |
|:---|:---|
| `boxlines, color, width` | Multi-line framed box string |
| `sboxlines, color, width` | Single-line compact box string |
| `sectiontitle, color, width` | Section header string with separator |
| `arrowlabel, color` | Right-arrow label string |
| `strip(s)` | Input string with ANSI escape codes removed |

ANSI color constants (`RED`, `ORANGE`, `YELLOW`, `GREEN`, `GRAY`, `WHITE`, `BOLD`, `DIM`, `RESET`) are auto-selected based on terminal capability.

---

## See also

- [BinaryContext](binary-context.md): session foundation for all analysis
- [SemanticSearch](semantic-search.md): function candidate identification
- [FindingRegistry](registry.md): persistent finding storage
