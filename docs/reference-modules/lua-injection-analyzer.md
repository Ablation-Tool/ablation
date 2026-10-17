# LuaInjectionAnalyzer

## Why this exists

Four things were not possible before in Ablation:

1. **Detecting Python→Lua injection**, before this module, no scanner could find unsanitized format() calls feeding into `LuaRuntime.execute()`. FAZ-SIEM-001 (CRITICAL RCE) required full manual reading of compiler.py and rule.py to trace the path.

2. **Automating cross-product transfer**, FortiManager v8.0.0 was byte-identical to FortiAnalyzer for all 5 SIEM files. Without this scanner, verifying the FAZ findings transferred to FMG required reading the same code twice. The scanner confirms in under 1 second.

3. **Detecting assignment-mediated injection**, the FAZ-SIEM-002 pattern assigned a format result to a variable (`code = "record[\"{}\"]=...".format(key, val)`) and then passed that variable to the execute call. SourceSinkScanner regex matching cannot track variable assignments across statements; this module's AST scope visitor does.

4. **Subprocess lua injection**, `subprocess.run(['lua', '-e', formatted_code])` and `subprocess.run(['/usr/bin/env', 'lua',...])` patterns weren't detectable at all previously.

## What it does

Scans Python source files for taint paths from string format operations (`.format()`, f-strings, `%`-formatting) into Lua execution sinks (`lua.execute()`, `lua.eval()`, subprocess invocations of lua/luajit).

Three injection types:

| Type | Pattern |
|---|---|
| DIRECT | `lua.execute("...{}...".format(x))` |
| INDIRECT | `code = "...{}...".format(x); lua.execute(code)` |
| SUBPROCESS | `subprocess.run(['lua', '-e', f'...{x}...'])` |

Severity:
- **CRITICAL**: format arg includes a known user-input variable name (`description`, `log_str`, `value`, `request`, etc.)
- **HIGH**: format arg is any non-literal expression
- **MEDIUM**: subprocess-only path (indirect exploitation)

## Usage

```python
from ablation.analyzers.lua_injection_analyzer import LuaInjectionAnalyzer

# Scan a Django app directory
results = LuaInjectionAnalyzer.from_path('/path/to/fortianalyzer/rootfs_ext').scan()
print(LuaInjectionAnalyzer.report(results))

# With custom field names (escalate severity for domain-specific user inputs)
results = LuaInjectionAnalyzer.from_path(
    '/path/to/app',
    extra_user_input_names=frozenset({'rule_description', 'log_pattern'}),
).scan()

# From SourceContext
from ablation.analyzers.source_ingestion import SourceContext
ctx = SourceContext.from_path('/path/to/app')
results = LuaInjectionAnalyzer.from_context(ctx).scan()
```

CLI:
```
python3 -m ablation.analyzers.lua_injection_analyzer /path/to/app
python3 -m ablation.analyzers.lua_injection_analyzer /path/to/app --severity HIGH
```

## FAZ-SIEM-001 reproduction

The confirmed CRITICAL finding in FortiAnalyzer v8.0.0:

```python
# compiler/rule.py:15
lua_code = f"-- '{description}'\n{body}"
# ...
lua.execute(lua_code)
```

The scanner detects this as INDIRECT (variable `lua_code` assigned from f-string, then passed to execute). Variable `description` is in `_USER_INPUT_NAMES` → severity CRITICAL.

## FAZ-SIEM-002 reproduction

```python
# compiler/compiler.py:454-455
snippet = "record[\"{}\"] = \"{}\"".format(key, value)
lua.execute(snippet)
```

Detected as INDIRECT. Variable `value` is in `_USER_INPUT_NAMES` → CRITICAL.

## Known limitations

- **Module-level code not scanned**: `lua.execute()` outside any function body is not detected. Django apps never do this.
- **Intra-function taint only**: if a format result is returned from one function and passed to lua.execute in another, it won't be detected.
- **Severity uses name heuristics**: a local variable named `description` triggers CRITICAL even if it doesn't come from user input. False-positive risk is low in practice.
- **No cross-file tracking**: import chains (function A formats in file X, result passed to function B with execute in file Y) are not tracked.

---

## How it works

Iterates over all functions in the binary context using `ctx.func_starts`. For each function, disassembles the instruction stream with Capstone and applies the scanner's pattern or heuristic. Call sites matching the target pattern are collected and scored. A finding is emitted when the condition passes the configured confidence threshold. Results are sorted by severity then virtual address.

---

## Example output

```
[HIGH] TAINT_SINK   system() at 0x4023A0 in sub_401F00
  source: recv() → $rdi at 0x401F44
  chain: recv → strcpy(buf) → system(buf)
  arg_index: 0

[MEDIUM] DEPRECATED_FUNC   gets() at 0x403C10 in handle_input
  detail: unbounded read into stack buffer
```

---

## False positives

The most common false positive is a tainted argument that is immediately sanitized by the callee before use. Run `SinkSanitizerFilter` on all HIGH findings before manual review. Call sites where the argument is loaded from `.rodata` are not findings — `SinkArgClassifier` classifies these as `RODATA_CONST` and they should be excluded before the scanner runs.

---

## Pipeline position

**Before this module:** `BinaryContext.load_or_build()` and `SemanticSearcher.query()` to identify candidate functions. Run `SinkArgClassifier` first to eliminate `RODATA_CONST` call sites before passing candidates here.

**After this module:** Confirm feasibility with `PathSolver`. Register confirmed findings with `FindingRegistry`.

---

## Reading findings

`LuaInjectionAnalyzer.from_context(ctx).scan()` returns `List[LuaInjectionFinding]`:

| Attribute | Content |
|:---|:---|
| `path` | `Path` object of the file containing the injection site |
| `rel_path` | Repository-relative path string |
| `cwe` | CWE identifier (typically `'CWE-94'` — code injection) |
| `severity` | `'CRITICAL'` / `'HIGH'` / `'MEDIUM'` |
| `injection_type` | `'DIRECT'` (string directly from user input), `'INDIRECT'` (via variable), or `'SUBPROCESS'` (via subprocess call) |
| `exec_line` | Line number of the `lua.execute()` or subprocess call |
| `exec_text` | Source line text of the execute call |
| `format_line` | Line number of the format operation (f-string, `.format()`, `%`) |
| `format_text` | Source line text of the format operation |
| `var_name` | Variable name for `INDIRECT` paths (empty for `DIRECT`) |
| `description` | Human-readable explanation of the finding |

---

## See also

- [BinaryContext](binary-context.md) — function and import resolution before scanning
- [SinkArgClassifier](sink-arg-classifier.md) — eliminate RODATA_CONST call sites before taint
- [TaintAnalysis](taint-analysis.md) — confirm propagation from source to flagged sink
- [PathSolver](path-solver.md) — verify path feasibility for confirmed candidates
- [FindingRegistry](registry.md) — record confirmed findings
