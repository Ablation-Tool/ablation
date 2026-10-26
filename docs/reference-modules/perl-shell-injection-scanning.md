# Perl Shell-Injection Scanning

Statically trace user-controlled input from Perl CLI argument sources `@ARGV`, `Getopt`, `STDIN` through all interpolated shell sink patterns backtick, `qx//`, `system`, `open PIPE`: classifying each finding by its taint source, sanitization status, and cross-file caller resolution depth.

---

## Why this exists

1. **Embedded Linux targets ship thick Perl layers above setuid ELF binaries.** IBM RSCT, HMC, Fortinet SNMP helpers, and many industrial device management systems implement their command interfaces as `.pm`/`.pl` files that call root-privileged binaries via `system()` and backtick. `TaintTracker` is ELF-only, it never touches these scripts. `PerlTaintScanner` closes that gap: it finds every shell sink with variable interpolation and traces each interpolated variable to its origin.

2. **Perl-specific sanitization idioms produce false positives in naive string scanners.** A generic grep for `` `$var` `` or `system("...$var...")` hits thousands of legitimately sanitized patterns: `quotemeta()`, single-quote wrapping `"'" . join("' '", @args . "'"`), and `s/'/ /g` substitutions before shell expansion. The scanner recognizes all three and reports `SANITIZED` rather than flooding the analyst with unreachable findings.

3. **The injection variable often enters through a different file.** The canonical RSCT pattern: `ERRM_cli_utils.pm` receives `$condition_name` via `shift(@_)`, passes it to `qx{lsrsrc -c $condition_name}`. The `.pm` file never touches `@ARGV`. But `rmcondition`: the CLI script: calls `ERRM_cli_utils::remove_condition$ARGV[0]`. The scanner resolves one caller hop and upgrades the verdict from `PARAM_UNKNOWN` to `INJECTABLE`.

---

## How it works

```mermaid
flowchart TD
    A(["PerlTaintScanner.from_path(root_dir)"]):::input --> B["Recursive rglob('*.pl') + rglob('*.pm')\n_FileAnalysis per file: parse sub ranges, find Getopt callers"]:::primary
    B:::primary --> C["scan() · iterate all files"]:::secondary
    C:::secondary --> D["_scan_file(analysis): regex scan for shell sinks"]:::tertiary
    D:::tertiary --> E["_RE_BACKTICK: `...$var...`\n_RE_QX_SIMPLE: qx{...$var...} / qx/.../\n_RE_SYSTEM: system(\"...$var...\")\n_RE_OPEN_PIPE: open(FH, \"...$var...|...\")"]:::tertiary
    E:::tertiary --> F["Extract interpolated variables via _RE_VARS\nSkip Perl special vars: $_, $ENV, $0, $1"]:::tertiary
    F:::tertiary --> G["_classify(analysis, sink_line, var, sink_type)"]:::tertiary
    G:::tertiary --> H["func_for_line(sink_line) → sub name\nlines_in_func(name) → backward-search window"]:::tertiary
    H:::tertiary --> I(["_check_sanitization: look for quotemeta/single-quote-wrap/s///\nbefore sink · returns sanitization desc if found"]):::output
    H:::tertiary --> J["Backward scan for var source:"]:::tertiary
    J:::tertiary --> K{"Pattern match?"}:::neutral
    K:::neutral -->|"shift(@_) / shift"| L["PARAM → resolve one hop in caller files"]:::tertiary
    K:::neutral -->|"$opts{key} / Getopt"| M["CLI_ARG: Getopt/getopts flag"]:::tertiary
    K:::neutral -->|"$ARGV[N]"| N(["CLI_ARG: @ARGV index"]):::output
    K:::neutral -->|"<STDIN>"| O(["CLI_ARG: STDIN"]):::output
    K:::neutral -->|"my $var = ... (non-user source)"| P(["INTERNAL"]):::output
    K:::neutral -->|"not found in window"| Q(["UNKNOWN"]):::output
    L:::tertiary --> R{"Caller passes @ARGV / Getopt?"}:::neutral
    R:::neutral -->|yes| S(["INJECTABLE: CLI → param → sink, unsanitized"]):::output
    R:::neutral -->|no| T(["PARAM_UNKNOWN: param source confirmed; caller set not injecting"]):::output
    M:::tertiary --> U{"sanitized?"}:::neutral
    U:::neutral -->|yes| V(["SANITIZED"]):::output
    U:::neutral -->|no| S:::output
    classDef input     fill:#0d47a1,stroke:#1565c0,color:#fff
    classDef primary   fill:#e65100,stroke:#bf360c,color:#fff
    classDef secondary fill:#004d40,stroke:#00695c,color:#fff
    classDef tertiary  fill:#4a148c,stroke:#6a1b9a,color:#fff
    classDef neutral   fill:#37474f,stroke:#546e7a,color:#fff
    classDef output    fill:#1b5e20,stroke:#2e7d32,color:#fff
    linkStyle 0 stroke:#bf360c,stroke-width:2px
    linkStyle 1 stroke:#00695c,stroke-width:2px
    linkStyle 2 stroke:#6a1b9a,stroke-width:2px
    linkStyle 3 stroke:#6a1b9a,stroke-width:2px
    linkStyle 4 stroke:#6a1b9a,stroke-width:2px
    linkStyle 5 stroke:#6a1b9a,stroke-width:2px
    linkStyle 6 stroke:#6a1b9a,stroke-width:2px
    linkStyle 7 stroke:#2e7d32,stroke-width:3px
    linkStyle 8 stroke:#6a1b9a,stroke-width:2px
    linkStyle 9 stroke:#546e7a,stroke-width:2px
    linkStyle 10 stroke:#6a1b9a,stroke-width:2px
    linkStyle 11 stroke:#6a1b9a,stroke-width:2px
    linkStyle 12 stroke:#2e7d32,stroke-width:3px
    linkStyle 13 stroke:#2e7d32,stroke-width:3px
    linkStyle 14 stroke:#2e7d32,stroke-width:3px
    linkStyle 15 stroke:#2e7d32,stroke-width:3px
    linkStyle 16 stroke:#546e7a,stroke-width:2px
    linkStyle 17 stroke:#2e7d32,stroke-width:3px
    linkStyle 18 stroke:#2e7d32,stroke-width:3px
    linkStyle 19 stroke:#546e7a,stroke-width:2px
    linkStyle 20 stroke:#2e7d32,stroke-width:3px
    linkStyle 21 stroke:#2e7d32,stroke-width:3px
```

### Verdict taxonomy

| Verdict | Priority | Meaning |
|---|---|---|
| `INJECTABLE` | 0 | CLI argument → no sanitization → shell sink: confirmed injection path |
| `PARAM_UNKNOWN` | 1 | Function parameter source confirmed; callers not in scan set |
| `UNKNOWN` | 2 | Source not resolved within backward-scan window |
| `SANITIZED` | 3 | CLI source confirmed but `quotemeta`, single-quote wrapping, or `s///` detected |
| `INTERNAL` | 4 | Source traced to internal state; no user input path confirmed |

### Sanitization patterns recognized

| Pattern | Description |
|---|---|
| `quotemeta($var)` | Escapes all non-alphanumeric characters for shell safety |
| `"'" . join"' '", @args . "'"` | Single-quote wrapping: prevents word-splitting and globbing |
| `s/'/ /g` | Strips single quotes from a variable before shell interpolation |

---

## Usage

```python
from ablation.analyzers.perl_taint_scanner import PerlTaintScanner

# Scan a directory
scanner = PerlTaintScanner.from_path('/tmp/rsct.core/opt/rsct')
results = scanner.scan()
print(scanner.report(results))

# Filter to injectable findings only
injectable = [r for r in results if r.verdict == 'INJECTABLE']
for hit in injectable:
    print(hit.fmt())
    print(f"  File: {hit.file}:{hit.line_no}")
    print(f"  Sink: {hit.sink_type}  Variable: ${hit.var}")
    print(f"  Line: {hit.line.strip()}")
    if hit.caller_file:
        print(f"  Resolved caller: {hit.caller_file}")

# Scan specific files (e.g., after locating a suspect module)
scanner = PerlTaintScanner.from_files([
    '/opt/rsct/pm/ERRM_cli_utils.pm',
    '/opt/rsct/bin/rmcondition',
    '/opt/rsct/bin/lsrsrc',
])
results = scanner.scan()
print(scanner.report(results))

# Count by verdict
from collections import Counter
counts = Counter(r.verdict for r in results)
print(counts)
```

---

## Example output

```
PerlTaintScanner results:

[!] INJECTABLE   $condition_name  [qx]  ERRM_cli_utils.pm:847
  src: function param (shift) in sub 'remove_condition' → caller rmcondition:$ARGV[0]

[!] INJECTABLE   $resource_name   [backtick]  ERRM_cli_utils.pm:1203
  src: Getopt/getopts flag ($resource_name = $opts{...})

[?] PARAM        $cmd             [system]  cli_helper.pm:312
  src: function param (shift) in sub 'run_cmd'

[-] SANITIZED    $input           [qx]  safe_wrapper.pm:44
  src: Getopt/getopts flag ($input = $opts{...})
  san: quotemeta($input) applied before sink

Summary: INJECTABLE=2, PARAM_UNKNOWN=1, SANITIZED=1
```

---

## False positives

**`PARAM_UNKNOWN` on internal callers with controlled data.** When the scan set includes only the `.pm` library but not the CLI script that calls it, a genuine injection through `shift(@_)` appears as `PARAM_UNKNOWN` rather than `INJECTABLE`. Extend the scan to include all `.pl` scripts in the target's `bin/` directory and re-run: the scanner will follow the one-hop caller resolution and upgrade the verdict.

**`UNKNOWN` on dynamically assigned variables.** When a variable receives its value from a hash lookup (`$cmd = $actions{$key}`) rather than a direct assignment, the backward scan does not match any source pattern and reports `UNKNOWN`. These warrant manual inspection: trace whether `$actions` is populated from user input at any point in the file.

**`s///` sanitization bypasses.** The scanner detects `s/'/ /g` but does not verify that the substitution is applied to the correct variable or that it is applied before the sink rather than after. When a `SANITIZED` finding appears with `s///` as the sanitization type, verify manually that the substitution is performed on the exact variable passed to the sink.

---

## Pipeline position

**Before this module:** Identify that the target has a Perl layer: look for `.pm`/`.pl` files in the firmware's `/opt`, `/usr/lib`, or management daemon directories.

**After this module:** For `INJECTABLE` findings: confirm with `TaintTracker` on the underlying ELF binary that the Perl-called binary does not re-sanitize the argument before its own shell execution. For `PARAM_UNKNOWN` findings: expand the scan to include caller `.pl` files and re-run.

---

## Reading findings

| Field | Content |
|:---|:---|
| `file` | Absolute path of the `.pm`/`.pl` file |
| `line_no` | 0-indexed line number of the sink instruction |
| `line` | Full line text at the sink |
| `var` | Interpolated variable name (without `$`) |
| `sink_type` | `backtick` / `qx` / `system` / `open_pipe` |
| `verdict` | See verdict taxonomy above |
| `source_desc` | Human-readable: "Getopt flag", "@ARGV index", "shift param", etc. |
| `sanitization` | Description of the sanitization found, if any |
| `caller_file` | File where a `PARAM` source resolved to a user input, if cross-file resolution succeeded |

---

## See also

- [Taint Analysis](taint-analysis.md): ELF taint tracing for the C/C++ binary layer called by Perl scripts
- [Sink Arg Classifier](sink-arg-classifier.md): classify argument provenance at ELF `system()` call sites
- [Source Entry Classifier](architectural-risk-detection.md): source RE entry point classification for web API layers
