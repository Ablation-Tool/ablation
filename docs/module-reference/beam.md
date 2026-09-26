# Erlang / BEAM Analysis

**File:** `ablation/analyzers/beam_context.py`

`BeamContext` extracts the full attack surface from a compiled Erlang `.beam` file.
The model mirrors ELF binary RE: exports ≈ ELF exports, imports ≈ PLT, atoms ≈
string table, literals ≈ `.rodata`. Once the surface is mapped, dangerous import
patterns and atom/string signals drive the same triage flow as binary RE.

---

## BeamContext

Build a context from a `.beam` file and query every surface it exposes.

### What gets extracted

| Chunk | Field | Analog in ELF |
|---|---|---|
| ExpT | `exports` | ELF exported symbols |
| ImpT | `imports` | PLT entries |
| AtU8 / Atom | `atoms` | String table |
| LitT | `literals` | `.rodata` constants (ETF-decoded) |
| StrT | `strings` | Raw string table segments |
| Dbgi | `ast_functions` | DWARF debug info — source file, function names, line numbers |

### Build and load

```python
from ablation.analyzers.beam_context import BeamContext

ctx = BeamContext.from_path('/path/to/module.beam')
print(ctx.summary())
# Module: my_module
# Exports: 12  Imports: 34  Atoms: 187  Literals: 5
# Debug info: yes (42 functions)
```

### Atom and string search

```python
# Scan atoms for sensitive keywords
for atom in ctx.atoms:
    if any(kw in atom for kw in ('password', 'secret', 'token', 'key', 'admin')):
        print(f"[atom] {atom}")

# Scan string table segments
for s in ctx.strings:
    if 'sql' in s.lower() or 'exec' in s.lower():
        print(f"[str]  {s}")
```

### Dangerous import detection

```python
# All dangerous imports at or above CODE_EVAL severity
from ablation.analyzers.beam_context import BeamContext, SEVERITY_CODE_EVAL

ctx = BeamContext.from_path('/path/to/module.beam')
dangerous = ctx.dangerous_imports(min_severity=SEVERITY_CODE_EVAL)
for imp in dangerous:
    print(f"[{imp.severity}] {imp.module}:{imp.function}/{imp.arity}")
```

### Severity tiers

| Constant | Meaning |
|---|---|
| `SEVERITY_DISPATCH` | Dynamic dispatch (`erlang:apply`) — low signal alone; extremely common in OTP |
| `SEVERITY_NETWORK` | Outbound network connections (`ssl:connect`, `gen_tcp:connect`, `httpc:request`) |
| `SEVERITY_INFO` | Local system enumeration (`inet:getifaddrs`) |
| `SEVERITY_CODE_EVAL` | Runtime code loading / ETF AST evaluation (`erl_eval:exprs`, `code:load_binary`) |
| `SEVERITY_CODE_EXEC` | OS-level process execution / port driver spawn (`os:cmd`, `erlang:open_port`) |

### High-risk import signatures

| Module | Function | Severity | What it does |
|---|---|---|---|
| `os` | `cmd` | CODE_EXEC | Execute OS shell command |
| `erlang` | `open_port` | CODE_EXEC | Spawn OS subprocess or port driver |
| `erl_eval` | `exprs` | CODE_EVAL | Evaluate Erlang AST at runtime |
| `code` | `load_binary` | CODE_EVAL | Hot-load module from binary blob |
| `ssl` | `connect` | NETWORK | Outbound TLS connection |
| `gen_tcp` | `connect` | NETWORK | Outbound TCP connection |
| `erlang` | `apply` | DISPATCH | Dynamic dispatch (high volume) |

### Obfuscation detection

```python
if ctx.obfuscated:
    print(f"Obfuscation indicators: {ctx.obfuscation_indicators}")
    # e.g. ['missing Dbgi chunk', 'stripped atom table']
```

Missing or stripped chunks (Dbgi, AtU8) indicate deliberate obfuscation. A missing
Dbgi chunk means no source-level function names or line numbers — triage falls back
to export/import analysis only.

### Source-level function list

When the Dbgi chunk is present, `ast_functions` gives AST-level function definitions
with source file and line numbers:

```python
for fn in ctx.ast_functions:
    print(fn)   # "handle_call/3  line 142"
```

---

## Sweeping a release directory

OTP applications compile to a directory of `.beam` files under `ebin/`. Sweep the
whole directory at once:

```python
from ablation.analyzers.beam_context import sweep_beam_dir, fmt_sweep, SEVERITY_CODE_EXEC

results = sweep_beam_dir('/path/to/app/ebin/', min_severity=SEVERITY_CODE_EXEC)
print(fmt_sweep(results))
```

Output groups modules by severity tier and lists the dangerous import signatures
found in each, analogous to a SemanticSearcher sweep result.

### Diffing releases

```python
from ablation.analyzers.beam_context import sweep_beam_diff, fmt_sweep_diff

diff = sweep_beam_diff(
    '/path/to/app-1.0/ebin/',
    '/path/to/app-1.1/ebin/',
)
print(fmt_sweep_diff(diff))
# Shows: added/removed exports, new dangerous imports, changed function arities
```

---

## CLI

```bash
# Summarize a single .beam file
python3 -m ablation.analyzers.beam_context /path/to/module.beam

# Sweep a release directory
python3 -m ablation.analyzers.beam_context --dir /path/to/ebin/

# Diff two releases
python3 -m ablation.analyzers.beam_context --diff /path/v1/ebin/ /path/v2/ebin/

# Filter by minimum severity
python3 -m ablation.analyzers.beam_context --dir /path/to/ebin/ --min-severity CODE_EXEC
```
