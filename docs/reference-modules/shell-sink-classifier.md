# ShellSinkClassifier

Two-pass shell script exec-sink classifier: maps every exec-class call site to a verdict (RODATA_CONST / ARG_PROPAGATED / UNKNOWN / EVAL_SINK) by tracking variable provenance from source to sink.

---

## Why this exists

1. **Shell CGI triage was manual.** VIVOTEK FD8369A has 60+ shell CGI handlers. Before this module, finding which ones had attacker-controlled values in command position required reading each script by hand.

2. **Pattern grep produces noise.** Grepping for `$VAR` in command position flags every variable reference, including benign `${RM}="/bin/rm"` assignments. This module tracks provenance from assignment to use so RODATA_CONST sinks are separated from ARG_PROPAGATED ones before manual review.

3. **Sourced-file and eval sinks were untracked.** `. ${module}` and `eval "${cmd}"` with attacker-sourced values are first-class vulnerabilities. The module assigns EVAL_SINK to every eval regardless of contents and tracks SOURCE sinks the same as VAR_CMD.

---

## How it works

```
Pass 1 — _build_var_table()
  Read all assignment lines (VAR=value, VAR=$(cmd), read VAR, VAR=$N)
  For each RHS: classify provenance as INTERNAL | EXTERNAL | UNKNOWN
  External sources: positional params ($1/$@/$*), CGI env vars (QUERY_STRING,
    HTTP_*, CGI_*, CONTENT_TYPE, ...), external command output (xmlparser,
    confclient, stormgr, getcgi, awk, sed, cut, decode.sh, urldecode, base64)

Pass 2 — _classify_script()
  For each non-comment line:
    - VAR_CMD: $VAR or ${VAR} in command position (first token, or after |;&)
      Walk var_table to resolve provenance chain. If any var in chain is
      EXTERNAL → ARG_PROPAGATED. If any is UNKNOWN → UNKNOWN. Else RODATA_CONST.
    - EVAL: eval keyword → always EVAL_SINK
    - SOURCE: source / dot (.) keyword → same provenance resolution as VAR_CMD
    - SH_C: sh/bash -c with variable argument → same resolution

Continuation lines (trailing \) are joined before analysis.
```

---

## ShellSinkClassifier

```python
from ablation.analyzers.shell_sink_classifier import ShellSinkClassifier

# Single script
clf = ShellSinkClassifier.from_path('/path/to/upload_vadp')
results = clf.classify()

# All shell scripts in a directory (recursive, by shebang or extension)
clf = ShellSinkClassifier.from_dir('/media/fw/rootfs/usr/bin', exts={'.sh', '.cgi'})
results = clf.classify()

# List of paths (used internally by CGISurfaceMapper)
clf = ShellSinkClassifier([Path('/a.sh'), Path('/b.cgi')])
results = clf.classify()

print(ShellSinkClassifier.report(results))
```

### ShellSinkResult fields

| Field | Content |
|:---|:---|
| `script_path` | Absolute path of the script |
| `line_num` | 1-indexed line number of the sink |
| `line` | Raw line text |
| `sink_type` | `VAR_CMD` / `EVAL` / `SOURCE` / `SH_C` |
| `command_fragment` | The token that triggered detection |
| `verdict` | `RODATA_CONST` / `ARG_PROPAGATED` / `UNKNOWN` / `EVAL_SINK` |
| `vars_involved` | Variable names resolved in the sink |
| `var_provenances` | `{var_name: provenance}` for each var in `vars_involved` |

---

## Usage

```python
from ablation.analyzers.shell_sink_classifier import ShellSinkClassifier

clf = ShellSinkClassifier.from_path('/media/fw/rootfs/usr/bin/upload_vadp')
results = clf.classify()

# Triage: only look at what needs RE
risky = [r for r in results if r.verdict in ('ARG_PROPAGATED', 'EVAL_SINK', 'UNKNOWN')]
for r in risky:
    print(f"L{r.line_num} {r.verdict:<18} {r.line.strip()[:80]}")

# Full formatted report
print(ShellSinkClassifier.report(results))
```

---

## Example output

```
[ShellSinkClassifier] /usr/bin/upload_vadp — 12 sinks found

L554    ARG_PROPAGATED     VAR_CMD    ${NEW_PACK}/${NEW_INIT_SCR} chkver /tmp/pkg
        vars: NEW_PACK=EXTERNAL, NEW_INIT_SCR=EXTERNAL

L558    EVAL_SINK          EVAL       eval "$FUNC_CMD"
        vars: FUNC_CMD=UNKNOWN

L980    ARG_PROPAGATED     VAR_CMD    ${NEW_PACK}/${NEW_INIT_SCR} upgrade /tmp/pkg
        vars: NEW_PACK=EXTERNAL, NEW_INIT_SCR=EXTERNAL

Summary: ARG_PROPAGATED=4, EVAL_SINK=6, UNKNOWN=1, RODATA_CONST=1
```

---

## False positives

**UNKNOWN for well-known system tools:** `${RM}`, `${FIND}` etc. are set as `/bin/rm`, `/usr/bin/find` in a preamble block, but if that block is in a different file (sourced) the classifier sees UNKNOWN. Check whether the script starts with `. /etc/common_functions` and read that file to confirm.

**ARG_PROPAGATED on awk/cut output used as argument (not command):** `FILE=$(awk '...' /etc/config)` is classified EXTERNAL because `awk` is in the external set. If the resulting variable is only used as an argument to a fixed command (not in command position), there is no sink and the classifier will not flag it. Only command-position uses trigger a result.

**Line-number skew on continuation lines:** A multi-line assignment using `\` continuation is joined before analysis. The displayed line number is the first line of the joined block; the actual exec sink may be 1-2 lines lower.

---

## Pipeline position

**Before this module:** none required; works standalone on any shell script path.

**After this module:** feed ARG_PROPAGATED and UNKNOWN results to manual review or `PathSolver`. EVAL_SINK results need manual inspection to check whether the eval operand can be controlled from an HTTP request.

---

## See also

- [CGISurfaceMapper](cgi-surface-mapper.md): runs ShellSinkClassifier across an entire firmware CGI tree and builds a prioritized attack-surface table
