# BeamContext

Extracts the attack surface from compiled Erlang `.beam` files and OTP release directories. Maps BEAM structure to ELF-equivalent concepts: exports to exported symbols, imports to PLT entries, atoms to the string table, literals to `.rodata`. Detects dangerous import patterns (`os:cmd`, `erlang:open_port`, `erl_eval:exprs`, `code:load_binary`) and obfuscation indicators across single modules or full release sweeps.

- [What is Erlang, OTP, and the BEAM VM?](#what-is-erlang-otp-and-the-beam-vm)
  - [Erlang language and runtime model](#erlang-language-and-runtime-model)
  - [OTP and the application ecosystem](#otp-and-the-application-ecosystem)
  - [The BEAM VM and .beam files](#the-beam-vm-and-beam-files)
  - [ETF: External Term Format](#etf-external-term-format)
  - [Why BEAM targets appear in RE work](#why-beam-targets-appear-in-re-work)
- [Why this exists](#why-this-exists)
- [Module relationships](#module-relationships)
- [How BEAM files are structured](#how-beam-files-are-structured)
- [API reference](#api-reference)
  - [`BeamContext`](#beamcontext-class)
  - [`BeamImport`](#beamimport)
  - [`BeamExport`](#beamexport)
  - [`BeamAstFunction`](#beastfunction)
  - [Severity constants](#severity-constants)
  - [Dangerous import table](#dangerous-import-table)
- [Usage](#usage)
  - [Single module](#single-module)
  - [Atom and string search](#atom-and-string-search)
  - [Sweeping a release directory](#sweeping-a-release-directory)
  - [Diffing releases](#diffing-releases)
  - [CLI](#cli)
- [Example output](#example-output)
- [Safe usage](#safe-usage)
- [False positives](#false-positives)
- [Limitations](#limitations)
- [Pipeline position](#pipeline-position)
- [Reading output](#reading-output)
- [See also](#see-also)

---

## What is Erlang, OTP, and the BEAM VM? <sup>[↑](#beamcontext)</sup>

**Erlang** is a concurrent, functional programming language developed at Ericsson by Joe Armstrong, Robert Virding, and Mike Williams between 1986 and 1990. It was designed for telecommunication switching systems that must remain operational through hardware failures, software upgrades, and network partitions — the original requirements were nine-nines availability (99.9999999% uptime). Erlang processes are lightweight virtual-machine threads, not OS threads: a typical BEAM runtime runs millions of concurrent processes with per-process garbage collection and preemptive scheduling. The language is dynamically typed with a pattern-matching syntax that treats everything as immutable values.

Erlang source compiles to BEAM bytecode. Unlike Python or JavaScript VMs, the BEAM VM was designed from the start for hot code reload: a running system can load a new version of a module without stopping. This property makes BEAM infrastructure attractive for high-availability network services, and it is also the mechanism that `code:load_binary/3` exploits for runtime code injection.

### Erlang language and runtime model <sup>[↑](#beamcontext)</sup>

Erlang programs are collections of **modules**. Each module is one source file (`.erl`) and compiles to one `.beam` file. Modules export explicitly named functions; unexported functions are private. The compiler generates an `ExpT` (export table) chunk listing exported `{function, arity}` pairs and an `ImpT` (import table) chunk listing external functions the module calls.

The Erlang standard library is split between the base runtime (`erlang:` BIFs — built-in functions) and the `stdlib`, `kernel`, and other OTP applications. `erlang:open_port/2` and `os:cmd/1` are the primary OS execution surfaces. `erl_eval:exprs/2` evaluates an Erlang AST at runtime, equivalent to Python's `eval`. `code:load_binary/3` hot-loads a new module version from a binary blob, equivalent to `ClassLoader.defineClass` in Java.

Elixir, LFE (Lisp-Flavoured Erlang), Gleam, and other languages compile to BEAM bytecode. An Elixir Mix release produces `.beam` files with module names prefixed by `Elixir.` (e.g. `Elixir.MyApp.Worker`). `BeamContext` handles both Erlang and Elixir BEAM files transparently; atom decoding and chunk parsing are identical.

### OTP and the application ecosystem <sup>[↑](#beamcontext)</sup>

**OTP** (Open Telecom Platform) is the Erlang standard library and set of design patterns shipped with the Erlang/OTP distribution. It provides `gen_server`, `gen_statem`, `supervisor`, and `application` behaviours that structure fault-tolerant systems into supervision trees. An OTP **release** is a self-contained directory tree with one `ebin/` subdirectory per application, each containing the compiled `.beam` files. The release directory also contains `sys.config`, `vm.args`, and boot scripts.

`BeamContext` detects OTP-stdlib origin: when the `.beam` path matches `.../erlang/lib/<app>-<vsn>/ebin/`, `ctx.otp_app` is set and `ctx.is_otp()` returns True. `sweep_beam_dir()` supports `exclude_otp=True` to skip standard library modules and focus on application code.

### The BEAM VM and .beam files <sup>[↑](#beamcontext)</sup>

**BEAM** stands for Bogdan/Björn's Erlang Abstract Machine (named after early implementers). A `.beam` file is an IFF (Interchange File Format) container — the same format created by Electronic Arts and Commodore for the Amiga in 1985. The IFF `FORM` marker is renamed `FOR1` in BEAM files; the form type is `BEAM`. IFF containers carry named chunks with four-byte ASCII tags and 32-bit big-endian length fields.

The relevant chunks:

| Chunk ID | Contents | Analog in ELF |
|:---|:---|:---|
| `AtU8` / `Atom` | Atom table: all string identifiers in the module | String table (`.strtab`) |
| `ExpT` | Export table: `{atom_idx, arity, label}` tuples | Exported symbols |
| `ImpT` | Import table: `{module_idx, fn_idx, arity}` tuples | PLT entries |
| `Code` | BEAM bytecode: header + opcode stream | `.text` section |
| `LitT` | Literals: zlib-compressed ETF terms | `.rodata` constants |
| `StrT` | Raw string table segments | `.rodata` strings |
| `Dbgi` | Debug info: AST in ETF (optional; stripped by obfuscators) | DWARF debug info |

All function names, module names, and attribute values are atoms. All atoms in a module are in the `AtU8` (UTF-8, OTP 20+) or `Atom` (Latin-1, older) chunk. `BeamContext` tries `AtU8` first and falls back to `Atom`. The ImpT entries reference atoms by index, so all external function calls are fully recoverable by resolving `(module_idx, fn_idx)` against the atom table.

### ETF: External Term Format <sup>[↑](#beamcontext)</sup>

**ETF** (External Term Format) is Erlang's binary serialization format — the format used by `term_to_binary/1` and `binary_to_term/1`. The BEAM format uses ETF extensively: the `Dbgi` chunk stores the module AST as an ETF term, the `LitT` chunk stores compile-time constants as ETF terms, and the `Abst` chunk (now superseded by `Dbgi`) stored abstract code as ETF.

ETF is not self-describing in a human-readable way; reading it requires decoding type tags (integers, tuples, lists, atoms, binaries). `BeamContext` includes a full ETF decoder (`_etf_to_python`, `_decode_etf`) to parse `Dbgi` into function name/arity/line records and `LitT` into string representations of compile-time constants.

### Why BEAM targets appear in RE work <sup>[↑](#beamcontext)</sup>

**RabbitMQ:** The most widely deployed BEAM application in enterprise infrastructure. RabbitMQ is a message broker used for inter-service communication in microservice architectures, fintech pipelines, and IoT gateways. It ships as an OTP release with hundreds of `.beam` files. Security research into RabbitMQ plugins, management API handlers, and federation modules requires BEAM analysis.

**ejabberd:** A high-scale XMPP server written in Erlang, used in production by WhatsApp (before rewrite), Facebook Messenger, and many enterprise chat systems. ejabberd processes incoming XMPP stanzas in Erlang processes and routes through OTP supervision trees. Plugin modules loaded at runtime use `code:load_binary`.

**Riak:** A distributed NoSQL key-value store from Basho. Riak's conflict resolution, bucket policies, and MapReduce hooks are implemented as BEAM modules that can be hot-loaded into a running cluster. User-supplied Erlang code in Riak MapReduce jobs was a historical remote code execution surface.

**CouchDB:** An Apache document database with Erlang as its primary implementation language. CouchDB map/reduce views compile JavaScript but the core database, replication engine, and HTTP API layer are BEAM code.

**Elixir services:** Any Elixir Phoenix web application, Nerves embedded firmware, or Livebook notebook produces BEAM bytecode. Elixir on Nerves targets (Raspberry Pi, BeagleBone) embed BEAM services in firmware images.

---

## Why this exists <sup>[↑](#beamcontext)</sup>

Two things blocked BEAM security analysis before this module:

**1. No Erlang-native equivalent of PLT scanning.** In ELF binaries, the PLT is the authoritative list of external function calls. Finding `system` or `popen` in a C binary means scanning the import table. In BEAM, the equivalent is the ImpT Import Table chunk, but it encodes calls as `{Module, Function, Arity}` tuples in ETF, not as symbol table entries. No tool exposed this as a queryable Python API. `BeamContext.imports` provides `dangerous_imports(min_severity=...)` with the same interface as a PLT scan.

**2. Obfuscation detection required manual chunk inspection.** Erlang obfuscators strip or corrupt the `Dbgi` debug chunk and the `AtU8` atom table. Without these chunks, a BEAM file has no readable function names or source locations. `BeamContext.obfuscated` and `ctx.obfuscation_indicators` expose this as a flag rather than requiring the analyst to read the IFF chunk headers manually.

---

## Module relationships <sup>[↑](#beamcontext)</sup>

`BeamContext` is a standalone module with no ablation dependencies beyond standard library (`zlib`, `dataclasses`, `pathlib`).

**Used by:**
- OTP release analysis: `sweep_beam_dir()` over an extracted release `ebin/` directory
- Elixir Mix release analysis: same sweep pattern; Elixir module names appear as `Elixir.App.Module`
- Version diff analysis: `sweep_beam_diff()` to identify newly introduced dangerous imports across releases

**Related modules:**
- [BinaryContext](binary-context.md): for native `.so` NIFs (Native Implemented Functions) loaded via `erlang:load_nif/2` — the BEAM module uses `load_nif` to load C code; the `.so` is the actual execution surface
- [FindingRegistry](registry.md): record confirmed dangerous import findings
- [TaintTracker](taint-tracker-alpha.md): when `os:cmd` or `erlang:open_port` is confirmed, trace the argument source through calling functions

---

## How BEAM files are structured <sup>[↑](#beamcontext)</sup>

A BEAM file is an IFF Interchange File Format container.

```
  IFF header (12 bytes):
    "FOR1"   4 bytes: IFF form marker
    length   4 bytes BE: total file size minus 8
    "BEAM"   4 bytes: form type identifier

  Each chunk that follows:
    chunk_id  4 bytes ASCII tag (e.g. "AtU8", "Code")
    length    4 bytes BE: payload size
    payload   length bytes, padded to 4-byte alignment
```

```mermaid
flowchart TD
    A(["module.beam: IFF container"]):::input --> B["IFF header\n'FOR1' · length · 'BEAM'"]:::primary

    B:::primary --> C["AtU8 / Atom chunk\nAtom table: count + (len + bytes) per atom\nAll other tables reference atoms by index\nAtU8 = UTF-8 (OTP 20+); Atom = Latin-1 fallback"]:::secondary

    B:::primary --> D(["ExpT chunk\nExports: [(atom_idx, arity, label), ...]\nMirror of ELF exported symbols"]):::output

    B:::primary --> E(["ImpT chunk\nImports: [(module_idx, fn_idx, arity), ...]\nMirror of PLT entries\nResolved to 'os:cmd/1' via atom table"]):::output

    B:::primary --> F(["Code chunk\nBEAM bytecode: header + opcode stream"]):::output

    B:::primary --> G(["LitT chunk\nLiterals: zlib-compressed ETF terms\nMirror of .rodata constants"]):::output

    B:::primary --> H(["Dbgi chunk (optional)\nDebug info: AST in ETF\nStripped by obfuscators\nIf absent: obfuscated=True"]):::output

    C:::secondary --> I(["BeamContext built\nctx.atoms · ctx.exports · ctx.imports\nctx.literals · ctx.ast_functions\nctx.obfuscated"]):::output
    classDef input     fill:#0d47a1,stroke:#1565c0,color:#fff
    classDef primary   fill:#e65100,stroke:#bf360c,color:#fff
    classDef secondary fill:#004d40,stroke:#00695c,color:#fff
    classDef tertiary  fill:#4a148c,stroke:#6a1b9a,color:#fff
    classDef neutral   fill:#37474f,stroke:#546e7a,color:#fff
    classDef output    fill:#1b5e20,stroke:#2e7d32,color:#fff
    linkStyle 0 stroke:#bf360c,stroke-width:2px
    linkStyle 1 stroke:#00695c,stroke-width:2px
    linkStyle 2 stroke:#2e7d32,stroke-width:3px
    linkStyle 3 stroke:#2e7d32,stroke-width:3px
    linkStyle 4 stroke:#2e7d32,stroke-width:3px
    linkStyle 5 stroke:#2e7d32,stroke-width:3px
    linkStyle 6 stroke:#2e7d32,stroke-width:3px
    linkStyle 7 stroke:#2e7d32,stroke-width:3px
```

The atom table is the foundation of all other tables. Exports, imports, and literals all reference atoms by index. `BeamContext` tries `AtU8` first and falls back to `Atom`.

The ImpT entries encode calls as three atom indices: `module_atom_idx, function_atom_idx, arity`. `BeamContext` resolves these to readable `"os:cmd/1"` strings using the atom table.

---

## API reference <sup>[↑](#beamcontext)</sup>

### `BeamContext` class <sup>[↑](#beamcontext)</sup>

**File:** `ablation/analyzers/beam_context.py`

```python
from ablation.analyzers.beam_context import BeamContext
```

| Method / Field | Signature / Type | Description |
|:---|:---|:---|
| `from_path` | `cls, path: str` → `BeamContext` | Parse a `.beam` file; raises `ValueError` for non-BEAM |
| `from_bytes` | `cls, data: bytes, path: str` → `BeamContext` | Parse from raw bytes |
| `dangerous_imports` | `self, min_severity: str` → `List[BeamImport]` | Imports at or above severity threshold; default `SEVERITY_DISPATCH` |
| `search_atoms` | `self, keyword: str, case_sensitive: bool` → `List[str]` | Atom table substring search |
| `search_literals` | `self, keyword: str` → `List[str]` | ETF-decoded literal substring search |
| `summary` | `self` → `str` | One-block human-readable summary |
| `is_otp` | `self` → `bool` | True when path matches OTP stdlib ebin layout |
| `fmt_atoms` | `self` → `str` | Formatted atom list for display |
| `path` | `str` | Path passed to `from_path` |
| `module_name` | `str` | Erlang module name from atom table |
| `atoms` | `List[str]` | All atoms in the module |
| `exports` | `List[BeamExport]` | Exported functions |
| `imports` | `List[BeamImport]` | All imported functions; dangerous ones have `dangerous=True` |
| `literals` | `List[str]` | ETF-decoded literal string representations |
| `strings` | `List[str]` | Raw `StrT` chunk segments |
| `chunks` | `List[str]` | Four-byte chunk IDs present in the file |
| `source_file` | `str` | Original `.erl` filename (only with debug info) |
| `ast_functions` | `List[BeamAstFunction]` | Function name/arity/line records from `Dbgi` |
| `ast_records` | `List[str]` | Record names from `Dbgi` |
| `ast_includes` | `List[str]` | Included `.hrl` filenames from `Dbgi` |
| `has_debug_info` | `bool` | True when `Dbgi` chunk is present and parsed |
| `obfuscated` | `bool` | True when obfuscation indicators are found |
| `obfuscation_indicators` | `List[str]` | List of indicator strings (e.g. `'missing Dbgi chunk'`) |
| `otp_app` | `str` | OTP application name when path is in an OTP stdlib ebin |

### `BeamImport` <sup>[↑](#beamcontext)</sup>

| Field | Type | Description |
|:---|:---|:---|
| `module` | `str` | Erlang module name (e.g. `'os'`) |
| `function` | `str` | Function name (e.g. `'cmd'`) |
| `arity` | `int` | Argument count |
| `dangerous` | `bool` | True when `(module, function)` is in `DANGEROUS_IMPORTS` |
| `severity` | `str` | One of the `SEVERITY_*` constants; empty string when not dangerous |

`str(imp)` produces `"os:cmd/1 [CODE_EXEC]"` for dangerous imports or `"io:format/2"` for safe ones.

### `BeamExport` <sup>[↑](#beamcontext)</sup>

| Field | Type | Description |
|:---|:---|:---|
| `function` | `str` | Exported function name |
| `arity` | `int` | Argument count |

`str(exp)` produces `"handle_call/3"`.

### `BeamAstFunction` <sup>[↑](#beamcontext)</sup>

Present only when `has_debug_info` is True.

| Field | Type | Description |
|:---|:---|:---|
| `name` | `str` | Function name |
| `arity` | `int` | Argument count |
| `line` | `int` | Source line number in the original `.erl` file |

`str(fn)` produces `"handle_call/3  line 142"`.

### Severity constants <sup>[↑](#beamcontext)</sup>

Ordered lowest to highest signal strength:

| Constant | Value | Meaning |
|:---|:---|:---|
| `SEVERITY_DISPATCH` | `"DISPATCH"` | Dynamic dispatch via `erlang:apply`; very common in OTP routing |
| `SEVERITY_NETWORK` | `"NETWORK"` | Outbound connections: `ssl:connect`, `gen_tcp:connect`, `httpc:request` |
| `SEVERITY_INFO` | `"INFO"` | Local system enumeration: `inet:getifaddrs` |
| `SEVERITY_CODE_EVAL` | `"CODE_EVAL"` | Runtime code loading or ETF AST evaluation |
| `SEVERITY_CODE_EXEC` | `"CODE_EXEC"` | OS-level process execution or port driver spawn |

Pass any constant to `dangerous_imports(min_severity=...)` to filter findings at or above that tier. `SEVERITY_CODE_EXEC` returns only the highest-signal findings.

### Dangerous import table <sup>[↑](#beamcontext)</sup>

The complete `DANGEROUS_IMPORTS` dict from source:

| Module | Function | Severity | What it does |
|:---|:---|:---|:---|
| `os` | `cmd` | CODE_EXEC | Execute OS shell command via `/bin/sh -c` |
| `erlang` | `open_port` | CODE_EXEC | Spawn OS subprocess or port driver |
| `erl_eval` | `exprs` | CODE_EVAL | Evaluate Erlang AST at runtime |
| `file` | `eval` | CODE_EVAL | Evaluate Erlang source file |
| `code` | `load_binary` | CODE_EVAL | Hot-load module from binary blob |
| `code` | `load_abs` | CODE_EVAL | Load module from absolute filesystem path |
| `code` | `load_file` | CODE_EVAL | Load module from path relative to code path |
| `ssl` | `connect` | NETWORK | Outbound TLS connection |
| `httpc` | `request` | NETWORK | Outbound HTTP(S) request |
| `gen_tcp` | `connect` | NETWORK | Outbound TCP connection |
| `gen_udp` | `open` | NETWORK | UDP socket open |
| `inet` | `getifaddrs` | INFO | Enumerate local network interfaces |
| `erlang` | `apply` | DISPATCH | Dynamic dispatch (very common) |

`erlang:open_port({spawn, "ls -la"}, [])` executes an OS command in a subprocess. It is Erlang's equivalent of `popen`. Unlike `os:cmd` (which shells through `/bin/sh`), `open_port` with `{spawn_executable, "/bin/sh"}` passes arguments directly. Both patterns are CODE_EXEC severity.

---

## Usage <sup>[↑](#beamcontext)</sup>

### Single module <sup>[↑](#beamcontext)</sup>

```python
from ablation.analyzers.beam_context import BeamContext, SEVERITY_CODE_EXEC

ctx = BeamContext.from_path('/path/to/module.beam')
print(ctx.summary())

# Find imports at CODE_EXEC severity or above
dangerous = ctx.dangerous_imports(min_severity=SEVERITY_CODE_EXEC)
for imp in dangerous:
    print(f"[{imp.severity}] {imp.module}:{imp.function}/{imp.arity}")

# Check for obfuscation before relying on function names
if ctx.obfuscated:
    print(f"Obfuscation indicators: {ctx.obfuscation_indicators}")

# AST-level function list (only when debug info is present)
for fn in ctx.ast_functions:
    print(fn)  # "handle_call/3  line 142"
```

### Atom and string search <sup>[↑](#beamcontext)</sup>

```python
# Scan atom table for credential-related identifiers
for atom in ctx.atoms:
    if any(kw in atom for kw in ('password', 'secret', 'token', 'key', 'admin')):
        print(f"[atom] {atom}")

# Scan raw string table for SQL or shell patterns
for s in ctx.strings:
    if 'sql' in s.lower() or 'exec' in s.lower():
        print(f"[str]  {s}")
```

### Sweeping a release directory <sup>[↑](#beamcontext)</sup>

OTP applications compile to a directory of `.beam` files under `ebin/`. Sweep the whole directory at once:

```python
from ablation.analyzers.beam_context import sweep_beam_dir, fmt_sweep, SEVERITY_CODE_EXEC

# Exclude OTP stdlib modules, report only CODE_EXEC findings
results = sweep_beam_dir('/path/to/app/ebin/', exclude_otp=True)
print(fmt_sweep(results, min_severity=SEVERITY_CODE_EXEC))
```

`sweep_beam_dir()` supports `dangerous_only=True` to skip modules with no dangerous imports entirely.

### Diffing releases <sup>[↑](#beamcontext)</sup>

Identify newly introduced dangerous imports across versions:

```python
from ablation.analyzers.beam_context import sweep_beam_diff, fmt_sweep_diff

diff = sweep_beam_diff(
    '/path/to/app-1.0/ebin/',
    '/path/to/app-1.1/ebin/',
)
print(fmt_sweep_diff(diff))
# Modules with new dangerous imports in v1.1 appear as ADDED entries
```

### CLI <sup>[↑](#beamcontext)</sup>

```bash
# Analyze a single module
python3 -m ablation.analyzers.beam_context /path/to/module.beam

# Sweep an entire ebin/ directory
python3 -m ablation.analyzers.beam_context --dir /path/to/ebin/

# Diff two release directories
python3 -m ablation.analyzers.beam_context --diff /path/v1/ebin/ /path/v2/ebin/

# Filter to CODE_EXEC severity only
python3 -m ablation.analyzers.beam_context --dir /path/to/ebin/ --min-severity CODE_EXEC
```

---

## Example output <sup>[↑](#beamcontext)</sup>

`ctx.summary()` on a RabbitMQ plugin module:

```
module:    rabbit_shovel_worker
path:      /opt/rabbitmq/plugins/rabbitmq_shovel-3.11.0/ebin/rabbit_shovel_worker.beam
chunks:    AtU8 Code ExpT ImpT LitT StrT Dbgi
atoms:     87
exports:   6 (start/2, stop/1, handle_call/3, handle_cast/2, handle_info/2, init/1)
imports:   23 total, 4 dangerous
obfuscated: NO
source:    rabbit_shovel_worker.erl

Dangerous imports:
  [CODE_EXEC]  erlang:open_port/2
  [CODE_EVAL]  code:load_binary/3
  [NETWORK]    ssl:connect/3
  [NETWORK]    gen_tcp:connect/3
```

`fmt_sweep()` output for a sweep of an ejabberd ebin/:

```
=== ejabberd_hooks.beam ===
  [CODE_EVAL]  erl_eval:exprs/2
  [DISPATCH]   erlang:apply/3  (×12)

=== mod_roster.beam ===
  [CODE_EXEC]  os:cmd/1
  [NETWORK]    gen_tcp:connect/3
```

---

## Safe usage <sup>[↑](#beamcontext)</sup>

**Check `ctx.obfuscated` before relying on function names.** An obfuscated BEAM file has its `Dbgi` chunk stripped, so `ast_functions` is empty and export/import analysis is the only available path. Reporting zero dangerous imports on an obfuscated module without flagging the obfuscation is a false negative.

**Filter `erlang:apply` separately from code-execution findings.** `erlang:apply` at DISPATCH severity appears in almost every OTP application as a routing mechanism. Mixing DISPATCH findings with CODE_EXEC findings hides the actual high-risk imports. Pass `min_severity=SEVERITY_CODE_EXEC` for executive summary output.

**Use `sweep_beam_dir()` for OTP applications.** An OTP release has dozens of `.beam` files. Analyzing one module in isolation misses import chains that cross module boundaries.

**Verify magic bytes before constructing.** `BeamContext.from_path()` raises `ValueError` for non-BEAM files. Filter a sweep directory for `b'FOR1'` at offset 0 before passing paths so the error does not terminate the sweep.

---

## False positives <sup>[↑](#beamcontext)</sup>

**`erlang:apply` at DISPATCH severity:** this fires in virtually every OTP supervisor, `gen_server`, and behaviour module as the standard dynamic dispatch mechanism. It is not a security signal on its own. Escalate only when `erlang:apply` is called with an attacker-controlled module or function name.

**`gen_tcp:connect` and `ssl:connect` at NETWORK severity:** outbound connections are expected in any networked Erlang service. These are NETWORK severity (not CODE_EXEC) precisely because they are common. Escalate when the connection target is constructed from external input (an atom from an incoming message, a config value that an unprivileged user controls).

**`code:load_binary` in OTP release handlers:** OTP's hot-upgrade mechanism (`release_handler`) calls `code:load_binary` as a normal part of in-place upgrades. Filter by `is_otp()` before escalating CODE_EVAL findings in OTP stdlib modules. For application modules, confirm that the binary argument is read from a controlled source rather than from a network socket or user-controlled payload.

---

## Limitations <sup>[↑](#beamcontext)</sup>

1. BEAM bytecode is not disassembled. `BeamContext` reads the `Code` chunk header but does not decode individual BEAM opcodes. Taint analysis across the bytecode — tracing `os:cmd` argument sources — is not available from this module alone. Use the AST from `Dbgi` for source-level analysis when debug info is present.

2. ETF decoding is best-effort. `_etf_to_python` decodes standard ETF term types (integers, floats, atoms, tuples, lists, strings, binaries). Non-standard or nested term types fall back to a hex repr. Dbgi chunks with complex nested ASTs may produce partially decoded `ast_functions` lists.

3. Elixir macro-expanded modules can be large. Elixir's `use`, `import`, and `defmacro` produce module code that imports many standard library functions. `sweep_beam_dir()` on an Elixir release may produce a large number of NETWORK-severity findings from `gen_tcp` imports in macro-expanded boilerplate; filter to `CODE_EXEC` for the first-pass triage.

4. NIFs are opaque. A module that calls `erlang:load_nif/2` loads a native `.so` library which then replaces Erlang function implementations with C code. `BeamContext` detects the `load_nif` import but cannot analyze the `.so` directly; use `BinaryContext` on the extracted native library.

---

## Pipeline position <sup>[↑](#beamcontext)</sup>

Before this module: confirm the file starts with `FOR1` magic and `BEAM` form type. `BeamContext.from_path()` performs this check and raises `ValueError` on mismatch.

After this module: for `CODE_EXEC` findings (`os:cmd`, `erlang:open_port`), examine the exported functions that call these imports using the AST from `ast_functions` (if debug info is present). For NIF modules (`erlang:load_nif` in import list), extract the `.so` path from the atom table and run `BinaryContext.load_or_build()` on the native library. Feed confirmed findings to `FindingRegistry`.

---

## Reading output <sup>[↑](#beamcontext)</sup>

`BeamContext.from_path(path)` returns a `BeamContext` object — the parsed module surface, not a list of findings. Call `ctx.dangerous_imports(min_severity=...)` to get findings.

| Attribute | Content |
|:---|:---|
| `path` | Path to the `.beam` file |
| `module_name` | Erlang module name string |
| `atoms` | `List[str]`: all atom strings in the module |
| `exports` | `List[BeamExport]`: exported functions as `function/arity` |
| `imports` | `List[BeamImport]`: all imported functions; dangerous ones have `dangerous=True` and a `severity` string |
| `literals` | `List[str]`: ETF-decoded literal string representations |
| `strings` | `List[str]`: raw StrT byte segments |
| `chunks` | `List[str]`: four-byte chunk IDs present in the file |
| `source_file` | Original `.erl` filename (only when `has_debug_info` is True) |
| `ast_functions` | `List[BeamAstFunction]`: function names with source line numbers |
| `ast_records` | `List[str]`: Erlang record names from `Dbgi` |
| `ast_includes` | `List[str]`: included `.hrl` filenames from `Dbgi` |
| `has_debug_info` | `bool`: True when the `Dbgi` chunk was present and parsed |
| `obfuscated` | `bool`: True when obfuscation indicators found |
| `obfuscation_indicators` | `List[str]`: indicator strings such as `'missing Dbgi chunk'` |
| `otp_app` | `str`: OTP application name when path is in an OTP stdlib ebin |

---

## See also <sup>[↑](#beamcontext)</sup>

- [BinaryContext](binary-context.md): native binary context for NIF `.so` libraries loaded via `erlang:load_nif/2`
- [TaintTracker](taint-tracker-alpha.md): trace dangerous call arguments to their sources when `os:cmd` or `erlang:open_port` is confirmed
- [FindingRegistry](registry.md): record confirmed findings from BEAM analysis
