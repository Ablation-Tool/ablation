# PerlTaintScanner

## Why this exists

Three things were not possible before in Ablation:

1. **Taint tracing Perl script layers that sit above setuid ELFs**, every prior engagement analysis ended at the ELF boundary. RSCT (IBM HMC V11), FortiOS diagnostic scripts, and dozens of embedded Linux targets ship thick Perl layers that call privileged binaries. TaintTracker and SinkArgClassifier are ELF-only; they never see `.pm`/`.pl`. The HMC engagement confirmed a real CWE-78 (ERRM_cli_utils.pm → rmcondition → unsanitized `$resource_name` in qx//) that required manual Perl analysis because no ablation tool could flag it. PerlTaintScanner closes that gap.

2. **Detecting Perl-specific sanitization patterns**, shell injection mitigations in Perl don't look like C. `quotemeta()` is the explicit safe function, but most mature RSCT/IBM Perl uses the single-quote wrapping idiom: `s/'/ /g` stripping followed by `"'". join("' '", @args). "'"`. A generic grep for `system(` or qx// cannot distinguish unsanitized from sanitized; it floods findings with false positives. PerlTaintScanner recognizes all three idioms and reports SANITIZED so true positives stand out.

3. **Cross-file parameter origin tracing**, Perl codebases split CLI scripts from utility `.pm` libraries. The injection point is in the `.pm` (`shift(@_)` receives tainted data), the source is in the calling `.pl` script (`$resource = shift @ARGV`). TaintTracker cannot cross this file boundary. PerlTaintScanner does one-hop caller resolution: when a sink variable comes from a function parameter, it scans all other loaded files for callers of that function and traces whether the call-site argument came from `@ARGV` or a Getopt variable.

## What it does

Scans `.pl` and `.pm` files for shell sink call sites with interpolated variables, then traces each variable backward to its origin:

| Sink type | Pattern |
|---|---|
| `backtick` | `` `...${var}...` `` |
| `qx` | `qx{...${var}...}`, `qx/...${var}.../` |
| `system` | `system("...${var}...")` |
| `open_pipe` | `open(FH, "...\|...${var}...")` |

Verdict classes:

| Verdict | Meaning |
|---|---|
| `INJECTABLE` | CLI arg (`@ARGV` / Getopt) → no sanitization → shell sink |
| `SANITIZED` | CLI arg source confirmed but sanitization detected before sink |
| `PARAM_UNKNOWN` | Function parameter source; callers not in scan set or unresolvable |
| `INTERNAL` | Source is internal state: no user-controlled path confirmed |
| `UNKNOWN` | Origin not resolved within look-back window |

Sanitization recognized:
- `quotemeta($var)`: explicit safe quoting
- `"'". join("' '", @args). "'"`: single-quote wrapping idiom
- `$var =~ s/'/ /g` + similar metachar substitutions

## Usage

```python
from ablation.analyzers.perl_taint_scanner import PerlTaintScanner

# Scan a directory of .pm/.pl files
scanner = PerlTaintScanner.from_path('/tmp/hmc_new_rpms/rsct.core/opt/rsct')
results = scanner.scan()
print(scanner.report(results))

# Scope to specific files (e.g., after SinkArgClassifier identifies Perl targets)
scanner = PerlTaintScanner.from_files([
    '/opt/rsct/pm/ERRM_cli_utils.pm',
    '/opt/rsct/bin/rmcondition',
])
injectable = [r for r in scanner.scan() if r.verdict == 'INJECTABLE']
```

CLI:
```
python3 -m ablation.analyzers.perl_taint_scanner /path/to/rsct/
python3 -m ablation.analyzers.perl_taint_scanner /path/to/rsct/ --injectable-only
python3 -m ablation.analyzers.perl_taint_scanner /path/to/rsct/ --no-internal
```

## ERRM_cli_utils.pm reproduction

The HMC engagement confirmed this pattern. `find_resource_name()` in ERRM_cli_utils.pm:

```perl
# ERRM_cli_utils.pm:462
my $resource_name = shift(@_);          # PARAM source
...
@listout = `$CTBINDIR/lsrsrc-api -I $DELIMITERI -s ${resource_class}${DELIMITERI}\"Name==\\\"$resource_name\\\"...\"`;
```

Caller in `rmcondition`:
```perl
# rmcondition:369
$resource = shift @ARGV;                # CLI arg
...
find_resource_name($resource, ...);
```

Scanner detects: `INJECTABLE`, `$resource_name` via `shift(@_)` in `find_resource_name`, resolved to `$ARGV` in `rmcondition`. Verdict: **INJECTABLE** (CWE-78).

## LPRM_cli_utils.pm SANITIZED detection

The HMC engagement also confirmed this sanitized pattern in LPRM_cli_utils.pm:

```perl
$optarg =~ s/'/ /g;                     # strip single-quotes
$optarg =~ s/"/\\"/g;
$optargs = "'" . join("' '", @optargs) . "'";  # single-quote wrap
@msgtext = `$main::LSMSG $main::PROGNAME $main::MSGCAT $msg $optargs`;
```

Scanner detects: `SANITIZED`, `$optargs` regex substitution present before backtick sink.

## Workflow placement

Run **before** TaintTracker when a target has a Perl scripting layer:

```
BinaryContext → SemanticSearcher → SinkArgClassifier → PerlTaintScanner (Perl layer) → TaintTracker (ELF sinks)
```

PerlTaintScanner is independent of BinaryContext, it works entirely on text files.

## Known limitations

- **Look-back window is function-scoped**: variable assignments before the current function's `sub` keyword are not traced. Module-level globals that flow into a sink require manual inspection.
- **One-hop caller resolution only**: if a function parameter passes through two hops (A calls B which calls C where the sink is), the intermediate hop is not followed. `PARAM_UNKNOWN` is returned.
- **Multi-line qx// not detected**: `qx` with the delimiter on a separate line from the variable is not matched by the current regex patterns.
- **Indirect Getopt hashes**: `$opts{$key}` where `$key` is a variable (not a literal key) will not match the Getopt source pattern.
- **No data flow through arrays**: if the CLI arg is pushed into `@array` and then shifted out in a loop, the array intermediary breaks the backward trace.

---

## How it works

`PerlTaintScanner` takes a list of Perl source `Path` objects. For each file, `_FileAnalysis._parse_functions()` splits the source into function scopes by scanning for `sub name {` declarations. `scan()` iterates each file's functions and applies regex patterns to identify taint sources (`$ENV{...}`, `param(...)`, `<STDIN>`, CGI input) and sink calls (`system`, backtick exec, `open`, `eval`, `DBI`). `_FileAnalysis.lines_in_func()` limits sink search to the current function scope. No binary parsing; no disassembly.

---

## Pipeline position

**Before:** Collect Perl source files (`.pl`, `.pm`, CGI scripts) from the target.

**After:** HIGH findings require manual confirmation that the taint source reaches the sink without sanitization. Check for `use strict` and `use warnings` as context.

---

## Reading findings

`PerlTaintScanner.from_path(path).scan()` returns `List[SinkHit]`:

| Attribute | Content |
|:---|:---|
| `file` | Source file path |
| `line_no` | Line number of the sink call |
| `line` | Raw source line text |
| `var` | The interpolated variable name at the sink |
| `sink_type` | `'backtick'` / `'qx'` / `'system'` / `'open_pipe'` |
| `verdict` | `'INJECTABLE'` — no sanitization found; `'SANITIZED'` — sanitization confirmed; `'PARAM_UNKNOWN'` — input source unclear; `'INTERNAL'` — constant or known-safe value; `'UNKNOWN'` — could not determine |
| `source_desc` | Human-readable description of the input source |
| `sanitization` | Description of sanitization found (empty if none) |
| `caller_file` | File where a `PARAM` resolved to an `ARGV` source (None if not applicable) |

---

## See also

- [BinaryContext](binary-context.md) — function and import resolution before scanning
- [SinkArgClassifier](sink-arg-classifier.md) — eliminate RODATA_CONST call sites before taint
- [TaintAnalysis](taint-analysis.md) — confirm propagation from source to flagged sink
- [PathSolver](path-solver.md) — verify path feasibility for confirmed candidates
- [FindingRegistry](registry.md) — record confirmed findings
