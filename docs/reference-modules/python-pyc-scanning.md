<a id="pycbytecodescanner"></a>
# Python, Perl & Electron Analysis

  - [What is Python bytecode?](#what-is-python-bytecode)
    - [The .pyc file format](#the-pyc-file-format)
    - [Code object structure](#code-object-structure)
    - [Opcode encoding and CPython versions](#opcode-encoding-and-cpython-versions)
    - [Python 3.8–3.12 breaking changes](#python-38312-breaking-changes)
    - [xdis vs. the built-in dis module](#xdis-vs-the-built-in-dis-module)
    - [Firmware deployment context](#firmware-deployment-context)
    - [Security-relevant patterns in bytecode](#security-relevant-patterns-in-bytecode)
    - [RE implications](#re-implications)
  - [Why this exists](#why-this-exists)
  - [How it works](#how-it-works)
  - [Usage](#usage)
  - [Example output](#example-output)
  - [False positives](#false-positives)
  - [Pipeline position](#pipeline-position)
  - [Reading output](#reading-output)
  - [See also](#see-also)

**File:** `ablation/analyzers/pyc_bytecode_scanner.py`

---

## What is Python bytecode? <sup>[↑](#pycbytecodescanner)</sup>

Python is an interpreted language. When a Python interpreter runs a `.py` source file for the first time, it compiles the source to an intermediate form called bytecode and stores the result in a `.pyc` file for subsequent reuse. The bytecode is not machine code: it is a sequence of opcodes for the CPython virtual machine (a stack-based register machine with a value stack and a block stack), with supporting data structures that carry the constant pool, variable names, and source line mappings. The `.pyc` file contains a serialized "code object" hierarchy that the CPython VM executes without re-parsing the source.

Bytecode is not a public API. CPython changes opcode numbers, opcode names, and code object field layouts between minor releases. A `.pyc` compiled by Python 3.8 will not load in Python 3.11: the interpreter reads a magic number from the first 4 bytes of the `.pyc` and rejects any file whose magic number does not match the running version. This is by design: the bytecode format is considered an implementation detail, not a compatibility target.

The security implication is significant. Embedded firmware that ships Python as part of its management plane typically ships only the compiled `.pyc` files, not the source `.py` files. This is the exact situation in Fortinet FortiSwitch, FortiAnalyzer, and FortiManager firmware: the Python management plane is a large application (hundreds of modules) compiled to `.pyc` and deployed without source. An analyst who cannot parse the `.pyc` files cannot audit the management plane.

### The .pyc file format <sup>[↑](#pycbytecodescanner)</sup>

A `.pyc` file has a header followed by a marshalled code object. The header format has changed across Python versions:

**Python 3.3 and earlier:** 8-byte header: 4-byte magic number + 4-byte source file modification timestamp.

**Python 3.4–3.7:** 12-byte header: 4-byte magic + 4-byte bit field (flags) + 4-byte timestamp or 4-byte source file size (depending on flags).

**Python 3.8+:** 16-byte header: 4-byte magic + 4-byte bit field + 8-byte source file size or hash (depending on flags). Python 3.8 added hash-based validation to allow reproducible builds that did not depend on timestamps.

The magic number uniquely identifies the CPython version:

| Magic (little-endian u16) | CPython version |
|---|---|
| 3495 | Python 3.8.0 |
| 3550 | Python 3.10.0 |
| 3600 | Python 3.12.0 |
| ...full table in `xdis.magics` | |

After the header, `marshal.loads()` decodes the remaining bytes into a code object. The code object is a complex nested structure: functions defined at module level produce nested code objects referenced from the parent code object's `co_consts`.

### Code object structure <sup>[↑](#pycbytecodescanner)</sup>

A CPython code object (`types.CodeType`) contains the following security-relevant fields:

| Field | Type | Security relevance |
|---|---|---|
| `co_code` | `bytes` | The bytecode instruction stream. Raw opcode + arg bytes. |
| `co_names` | `tuple[str]` | All attribute, global, and import names referenced by the code. `'system'` here means `os.system` was used. |
| `co_consts` | `tuple` | All literal constants: strings, numbers, nested code objects. Hardcoded passwords, tokens, IPs appear here. |
| `co_varnames` | `tuple[str]` | Local variable names. |
| `co_freevars` | `tuple[str]` | Variables from enclosing scope (closures). |
| `co_cellvars` | `tuple[str]` | Variables shared with nested functions. |
| `co_filename` | `str` | Source file path. Reveals internal directory structure. |
| `co_firstlineno` | `int` | Source line of the first statement. |
| `co_flags` | `int` | Flags: generator, coroutine, varargs, varkeywords. |
| `co_stacksize` | `int` | Maximum stack depth. |

The `co_names` tuple is the highest-value field for fast security screening. Any function call to an attribute goes through `LOAD_ATTR` or `LOAD_METHOD` with the attribute name as an index into `co_names`. Similarly, `import os` stores `'os'` in `co_names`. Therefore: if `'system'` and `'os'` both appear in `co_names` in the same code object, the code object contains a call to `os.system()`.

`co_consts` contains every string and numeric literal used in the code. Hardcoded credentials show up here as plain-text strings before any encoding or hashing. API keys, private keys in PEM format, JWT secrets, and internal IP addresses all appear verbatim in `co_consts` if they were written as string literals in the source.

Nested code objects (functions, class bodies, comprehensions) appear as code object values inside `co_consts`. `PycBytecodeScanner` walks the full code object tree recursively to find patterns in inner functions as well as the module-level code.

### Opcode encoding and CPython versions <sup>[↑](#pycbytecodescanner)</sup>

CPython bytecode consists of `(opcode, arg)` pairs. In Python 3.5 and earlier, every instruction was 1 byte opcode + 0 or 2 bytes arg (HAVE_ARGUMENT boundary: opcodes < 90 take no argument). Python 3.6 switched to a 2-byte "wordcode" format where every instruction is exactly 2 bytes: 1 byte opcode + 1 byte arg (with a 0 placeholder arg for instructions that don't use it). Python 3.12 moved to a "co_code" → "co_code_adaptive" model with CACHE instructions interleaved between regular instructions, making raw byte counting incorrect.

Security-relevant opcodes across CPython versions:

| Opcode name | Opcode number (3.11) | Action |
|---|---|---|
| `LOAD_GLOBAL` | 116 | Load a global name from `co_names`. Precedes all unqualified function calls. |
| `LOAD_ATTR` | 106 | Load attribute. Used for `os.system`, `subprocess.Popen`, etc. |
| `IMPORT_NAME` | 108 | Import a module. `co_names[namei]` is the module name. |
| `CALL_FUNCTION` | 131 | Call a callable (Python 3.11 and earlier). |
| `CALL` | 171 | Call a callable (Python 3.12+: replaces `CALL_FUNCTION`). |
| `MAKE_FUNCTION` | 132 | Creates a function object from a nested code object in `co_consts`. |
| `BUILD_STRING` | 157 | Concatenates stack items into a string: used in f-string command construction. |
| `FORMAT_VALUE` | 155 | Format a value for f-string interpolation. Command injection via f-string shows up here. |

The opcode number for `LOAD_GLOBAL` changed between 3.11 and 3.12 (from 116 to a new specializing form). Direct bytecode parsing with hard-coded opcode numbers breaks across versions. `xdis` abstracts over these differences and provides stable opcode names.

### Python 3.8–3.12 breaking changes <sup>[↑](#pycbytecodescanner)</sup>

Each Python minor release since 3.8 has changed the bytecode format in ways that break analysis tools built for a specific version:

**Python 3.8**: Added `LOAD_CLASSDEREF`, `END_ASYNC_FOR`. Introduced hash-based `.pyc` validation (PEP 552). `co_posonlyargcount` added to `types.CodeType`.

**Python 3.9**: Added `CONTAINS_OP`, `IS_OP`, `JUMP_IF_NOT_EXC_MATCH`. Removed `CONTINUE_LOOP`. The 39 new or renamed opcodes between 3.8 and 3.9 broke all hardcoded opcode-number analysis tools.

**Python 3.10**: Added `MATCH_MAPPING`, `MATCH_SEQUENCE`, `MATCH_KEYS`, `COPY_DICT_WITHOUT_KEYS`, `GET_LEN` for structural pattern matching (PEP 634). Pattern matching introduces complex bytecode patterns that naive scanners misinterpret.

**Python 3.11**: Largest restructure since 3.6. Introduced "specializing adaptive interpreters": `co_code` is now replaced by `co_quickened` in running interpreters. Added `RESUME`, `PUSH_EXC_INFO`, `CHECK_EXC_MATCH`. Renamed 15+ opcodes. Added 16 `CACHE` pseudo-instructions between certain instructions. `co_exceptiontable` replaced some exception handling opcodes. The `dis` module in 3.11 exposes a different view than the raw `co_code` bytes.

**Python 3.12**: `co_code` deprecated, replaced by `co_code_adaptive`. `CALL_FUNCTION`/`CALL_FUNCTION_KW`/`CALL_FUNCTION_EX` all replaced by a new `CALL` family. `co_linetable` encoding changed (again). Several exception-handling opcodes renamed.

`xdis` tracks all these changes and provides a stable cross-version API. `PycBytecodeScanner` relies on `xdis.disassemble_file()` and `xdis.Code` abstraction to extract `co_names`, `co_consts`, and nested code objects without version-specific branching.

### xdis vs. the built-in dis module <sup>[↑](#pycbytecodescanner)</sup>

Python's built-in `dis` module can disassemble bytecode for the running interpreter's version only. A Python 3.11 `dis.dis()` call on a `.pyc` compiled by Python 3.8 raises an error because the magic number does not match. This is a fundamental limitation: the analysis host and the firmware target never run the same Python version.

`xdis` (by Rocky Bernstein, MIT license) is a cross-version bytecode library that maintains a compatibility table for every CPython version since 2.7. It reads the magic number, selects the matching opcode table and `CodeType` field set, and returns a consistent `Code` object regardless of the compiled version. `xdis` is the only practical tool for cross-version `.pyc` analysis.

`uncompyle6` (decompiler, also by Bernstein) uses `xdis` internally to reconstruct Python source from bytecode. It is useful for manual analysis of flagged modules. However, decompilation fails frequently on Python 3.10+ code (structural pattern matching, exception table changes) and is too slow for bulk firmware scanning. `PycBytecodeScanner` uses `xdis` directly without decompilation, which provides complete coverage at scanning speed.

### Firmware deployment context <sup>[↑](#pycbytecodescanner)</sup>

Embedded firmware that uses Python for its management plane typically deploys `.pyc` files in one of these layouts:

**FortiSwitch / FortiManager (Fortinet):** `/opt/pyc/` tree, or inline within the firmware squashfs at `/usr/share/pylib/`. Files are compiled with the Python version embedded in the firmware image. The FortiSwitch 7.0.x firmware uses Python 3.9; 7.2.x uses Python 3.10. The management daemon `httpsd` imports hundreds of these modules at startup.

**Cisco ASA with REST API:** The ASDM REST API layer includes a Python management component in `disk0:/rest-api.tar`. Modules are compiled `.pyc` files.

**Industrial SCADA / HMI controllers:** Several industrial control systems (Schneider Electric, ABB) embed Python as a scripting engine with exposed APIs for hardware I/O. Compiled `.pyc` files implement the logic engine.

**Linux-based routers and switches:** OpenWRT-based firmware sometimes includes Python scripts for provisioning. These are usually `.py` source (readable directly) but may be `.pyc` on space-constrained flash.

### Security-relevant patterns in bytecode <sup>[↑](#pycbytecodescanner)</sup>

The following `co_names` patterns indicate security-relevant operations that warrant manual review:

**Command execution:**
- `system` in `co_names` with `os` in any `IMPORT_NAME` → `os.system()` call
- `popen`, `check_output`, `run`, `call`, `communicate` in `co_names` → `subprocess` family
- `spawn`, `spawnl`, `spawnv` in `co_names` → `os.spawn*` family
- `exec_command` in `co_names` → Fabric/Paramiko SSH command execution

**Code execution:**
- `eval` in `co_names` → arbitrary Python evaluation (dynamic code)
- `exec` in `co_names` → dynamic code execution
- `compile` in `co_names` → source compilation at runtime

**Network and crypto:**
- `urlopen`, `urlretrieve`, `Request` → urllib HTTP requests from management plane
- `SSLContext`, `wrap_socket`, `create_default_context` → TLS configuration (check for `check_hostname=False`)
- `jwt`, `decode`, `encode` → JWT handling

**Secrets in co_consts:**
- Base64-encoded strings ≥32 characters → possible key material
- Strings matching `/etc/ssl/`, `/etc/key`, `-----BEGIN` → certificate or key file references
- Strings matching `\b[0-9a-f]{32,}\b` → hardcoded hash or API key

### RE implications <sup>[↑](#pycbytecodescanner)</sup>

**co_names provides a call graph without decompilation.** A module's `co_names` reveals which attributes and globals it uses, which implicitly reveals which modules it imports and which functions it calls. Building a call graph from `co_names` across all modules in a firmware tree takes seconds and identifies which modules touch security-sensitive functions.

**co_filename reveals internal paths.** The source file path compiled into the code object is an absolute path on the developer's build system. FortiSwitch `.pyc` files reveal the Fortinet build server paths: `/home/builduser/fortiswitch/`, `/build/fortios-python-lib/`, etc. These paths also identify when the same code was compiled on different build systems (indicating vendor vs. in-house vs. contractor origin).

**co_firstlineno enables source-map correlation.** When Fortinet releases a security advisory for a CVE in the Python management plane, the line number in the advisory can be mapped to the function boundaries in the `.pyc` using `co_firstlineno` from the nested code objects. This allows precise confirmation that a patched version no longer has the vulnerable code, without having the source.

---

## Why this exists <sup>[↑](#pycbytecodescanner)</sup>

1. **FortiSwitch and similar appliances ship only compiled `.pyc` bytecode on the management plane: no `.py` source files.** `PycBytecodeScanner` was built to close `FSW-PYC-GAP`: without it, the entire Python layer of FortiSwitch firmware was opaque to static analysis. `xdis` parses the marshalled code object tree across Python versions 3.4–3.12+, which Python's built-in `marshal.loads()` cannot do when the `.pyc` was compiled by a different Python version than the analysis host.

2. **Every `.pyc` file stores `co_names` in each code object: the list of all attribute and global names referenced by `LOAD_ATTR`, `LOAD_GLOBAL`, and `STORE_ATTR` opcodes.** If a module calls `os.system()`, the string `"system"` appears in `co_names` and `"os"` appears in `co_names`. This provides reliable signal without decompilation, no AST reconstruction, no control-flow analysis, just co_names inspection. The approach is version-agnostic and handles all Python bytecode formats including 3.12's new opcode encoding.

3. `PycBytecodeScanner.scan_dir()` processes an entire directory tree of `.pyc` files in a single pass: the typical firmware structure places `.pyc` files in `/opt/pyc/` or alongside application code. Scanning the directory produces a `List[PycScanResult]` that can be filtered by confidence and finding type without individual per-file invocations.

---

## How it works <sup>[↑](#pycbytecodescanner)</sup>

```mermaid
flowchart TD
    A(["PycBytecodeScanner.scan_file(path)"]):::input --> B["xdis: parse .pyc marshal header\n  version detection, magic bytes\n  unmarshal root code object"]:::primary
    B:::primary --> C["Recursive walk of code object tree:\n  Root code object → nested code objects\n  (functions, comprehensions, class bodies)"]:::secondary
    C:::secondary --> D["For each code object:\n  Inspect co_names:\n    'system' + 'os' → os.system() call\n    'subprocess' → subprocess module use\n    'eval', 'exec' → code execution\n    'popen', 'run', 'check_output' → subprocess patterns\n  Inspect co_consts:\n    Password/key patterns\n    Base64-encoded strings\n    Hardcoded IP/path patterns"]:::tertiary
    D:::tertiary --> E["PycScanResult:\n  path: str\n  python_version: str\n  findings: List[dict]\n  is_clean() → bool\n  confidence() → str"]:::tertiary
    E:::tertiary --> F(["scan_dir(dir_path) → List[PycScanResult]\n  Recursive .pyc traversal\n  report(results) → formatted str"]):::output
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
    linkStyle 4 stroke:#2e7d32,stroke-width:3px
```

---

## Usage <sup>[↑](#pycbytecodescanner)</sup>

```python
from ablation.analyzers.pyc_bytecode_scanner import PycBytecodeScanner

scanner = PycBytecodeScanner()

# Scan a single .pyc file
result = scanner.scan_file('/path/to/module.pyc')
print(result.confidence())
for finding in result.findings:
    print(f"  {finding}")

# Scan a directory tree
results = scanner.scan_dir('/mnt/firmware/opt/pyc/')
print(scanner.report(results))

# Filter to non-clean results
dirty = [r for r in results if not r.is_clean()]
print(f"{len(dirty)}/{len(results)} files with findings")

# Scan raw bytes (in-memory)
with open('/path/to/module.pyc', 'rb') as f:
    pyc_bytes = f.read()
result_raw = scanner.scan_raw(pyc_bytes, name='module.pyc')
```

---

## Example output <sup>[↑](#pycbytecodescanner)</sup>

The following illustrates the scan report format. Actual findings are firmware-specific.

```
PycBytecodeScanner report:
  /opt/pyc/mgmt/auth.cpython-39.pyc  [Python 3.9]  CLEAN
  /opt/pyc/mgmt/cli.cpython-39.pyc   [Python 3.9]
    os.system(): 'system' in co_names  (code_object: run_command, line 42)
    subprocess:  'subprocess' import detected
    co_consts credential: 'admin123!' matched /pass|secret/i
  /opt/pyc/mgmt/update.cpython-39.pyc  [Python 3.9]
    os.popen(): 'popen' in co_names  (code_object: <module>, line 88)
  /opt/pyc/net/sniffer.cpython-39.pyc  [Python 3.9]  CLEAN
  ...
  Total: 147 files, 3 with findings  (HIGH: 2, MEDIUM: 1)
  Source paths: /build/fortiswitch/src/pylib/mgmt/  (build system: linux-build01)
```

The `Source paths` line shows the `co_filename` prefix extracted from the code objects, which reveals the build system's internal directory structure.

---

## Detection pattern reference <sup>[↑](#pycbytecodescanner)</sup>

The scanner checks `co_names` and `co_consts` against these patterns in every code object, including nested functions:

| Pattern type | Match criterion | Confidence |
|---|---|---|
| `os.system()` | `'system'` in `co_names` AND `'os'` in any IMPORT_NAME | HIGH |
| `subprocess` | `'subprocess'` in IMPORT_NAME | HIGH |
| `subprocess.run/call/Popen` | `'run'`/`'call'`/`'Popen'` in `co_names` with `'subprocess'` import | HIGH |
| Backtick equivalent | `'__import__'` + `'system'` | HIGH |
| `exec()` / `eval()` | `'exec'`/`'eval'` in `co_names` | HIGH |
| `compile()` | `'compile'` in `co_names` + `'exec'` | MEDIUM |
| `ctypes.cdll` | `'ctypes'` import + `'CDLL'` in `co_names` | MEDIUM |
| `os.popen` | `'popen'` in `co_names` with `'os'` import | HIGH |
| Hardcoded credential | String ≥16 chars matching `/pass|secret|key|token|apikey/i` in `co_consts` | MEDIUM |
| PEM key material | String starting `'-----BEGIN'` in `co_consts` | HIGH |
| JWT secret | Base64url string ≥32 chars in `co_consts` | MEDIUM |
| Hardcoded IP | String matching `\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}` in `co_consts` | LOW |
| Internal path | String starting `/etc/`/`/opt/`/`/usr/` in `co_consts` | LOW (info) |

---

## False positives <sup>[↑](#pycbytecodescanner)</sup>

**`co_names` inspection detects the presence of attribute names, not confirmed call sites.** A module that imports `os` and uses `os.path.system` unlikely but possible would trigger `os.system` detection even if it never calls `os.system()`. Confirm with decompilation (`uncompyle6`) or bytecode inspection (`dis`) on flagged files before reporting.

**`is_clean()` returns `True` when no dangerous `co_names` patterns are found, but a module could contain dangerous logic implemented through ctypes, cffi, or dynamic attribute lookup that does not use predictable name strings.** `is_clean()` means no detected patterns, not confirmed safety.

**Test files and test fixtures trigger detections.** A unit test file that imports `subprocess` to test subprocess-calling code will flag with HIGH confidence even though the test file itself is not vulnerable. Exclude test directories from `scan_dir()` by filtering paths with `/test/`, `/tests/`, `test_`, or `_test.py` suffixes.

**Minified JavaScript bundled into `.pyc` via `importlib`.** Some frameworks (Django, Flask) ship compressed template caches as string constants. A 40KB base64-encoded minified JS file stored in `co_consts` triggers the "base64-encoded string" credential heuristic. Verify by base64-decoding the flagged constant and checking whether it decodes to source code rather than key material.

**Dynamic attribute access via `getattr()`.** Code that calls `getattr(os, 'system')` instead of `os.system()` avoids putting `'system'` in `co_names`. The string `'system'` appears in `co_consts` instead. The scanner catches this via `co_consts` string matching when the attribute name is a literal, but dynamic construction (`getattr(module, 'sys' + 'tem')`) will not be detected. Manual review of code objects with high `co_consts` entropy is recommended for obfuscated modules.

---

## Pipeline position <sup>[↑](#pycbytecodescanner)</sup>

Run `PycBytecodeScanner.scan_dir()` as the first pass on any firmware with a Python management layer: before source auditing or dynamic analysis. The scan completes in seconds and identifies which modules need deeper analysis. For flagged modules, proceed to `uncompyle6` decompilation or manual bytecode inspection with `dis`.

**Before this module:** Firmware extraction to get the filesystem. Locate the Python bytecode directory (`/opt/pyc/`, `/usr/lib/python*/`, `/usr/share/pylib/`). For squashfs firmware, use `unsquashfs` and confirm the extracted path before scanning.

**Recommended scan sequence:**
1. `PycBytecodeScanner.scan_dir(pyc_root)` → collect HIGH confidence results
2. For each HIGH result: `uncompyle6 -o /tmp/decompiled/ result.path` → source reconstruction
3. Manual code review of decompiled source at flagged lines
4. If decompilation fails (Python 3.12+): `python3 -c "import dis, importlib; dis.dis(importlib.util.source_from_cache('file.pyc'))"` for bytecode inspection
5. For `co_consts` credential hits: verify by decoding the constant and confirming it is a live secret (not a test fixture or example value)
6. Register confirmed credentials as findings in `FindingRegistry` with `cwe='CWE-798'` (hardcoded credential)

**After this module:** If a Python module calls native code via `ctypes` or a C extension module, the vulnerability may be in the native layer, not the Python wrapper. Use `BinaryContext.load_or_build()` and `TaintTracker` on the `.so` extension module to trace the data path from the Python call into the native code.

---

## Version compatibility matrix <sup>[↑](#pycbytecodescanner)</sup>

`PycBytecodeScanner` supports `.pyc` files compiled by:

| CPython version | Magic range | Co_code format | xdis support |
|---|---|---|---|
| 3.4–3.5 | 3310–3360 | 1-byte op + 0/2-byte arg (HAVE_ARGUMENT) | Full |
| 3.6 | 3379 | 2-byte wordcode | Full |
| 3.7 | 3393–3394 | 2-byte wordcode | Full |
| 3.8 | 3495–3500 | 2-byte wordcode, hash-based .pyc | Full |
| 3.9 | 3540–3550 | 2-byte wordcode | Full |
| 3.10 | 3600–3620 | 2-byte wordcode | Full |
| 3.11 | 3640–3680 | 2-byte wordcode + CACHE pseudo-instructions | Full |
| 3.12 | 3700–3720 | Adaptive bytecode co_code_adaptive | Partial (xdis 6.1+) |
| 3.13 | 3750+ | Further specialization changes | Partial (xdis 6.2+) |

Firmware bytecode version by target:
- FortiSwitch 7.0.x: Python 3.9 (magic ≈ 3540)
- FortiSwitch 7.2.x: Python 3.10 (magic ≈ 3600)
- FortiSwitch 7.4.x: Python 3.11 (magic ≈ 3650)
- FortiManager 7.x: Python 3.9–3.11 depending on release
- Cisco ASDM REST API: Python 2.7 or 3.6 depending on ASA version

When the firmware's Python version is unknown, read the magic number with:

```python
import struct
with open('module.pyc', 'rb') as f:
    magic = struct.unpack('<H', f.read(2))[0]
print(f"Magic: {magic}")
# Look up in xdis.magics.magics dict
```

---

## Reading output <sup>[↑](#pycbytecodescanner)</sup>

`PycBytecodeScanner.scan_file(path)` returns a `PycScanResult`, not a list of findings.

| Attribute | Content |
|:---|:---|
| `path` | Path to the `.pyc` file |
| `filename` | Original `.py` source path from the code object's `co_filename` |
| `python_version` | Detected Python version string: for example `'3.11'` |
| `danger_hits` | `FrozenSet[str]`: dangerous names found in any code object's `co_names` |
| `const_hits` | `FrozenSet[str]`: credential or key patterns found in `co_consts` |
| `confidence` | Property: `'clean'` / `'HIGH'` (os module + danger hits) / `'LOW'` (danger hits only) |
| `error` | `None` on success; error string if `xdis` parse fails (version mismatch, corrupt file) |
| `code_objects` | `List[xdis.Code]`: all parsed code objects in the module, including nested functions |

Use `scan_dir(path)` to scan a directory tree and return `List[PycScanResult]`.

`PycBytecodeScanner.report(results)` returns a formatted multi-line scan summary string. Pass `verbose=True` to include the full `danger_hits` set for each file.

---

## PerlTaintScanner <sup>[↑](#pycbytecodescanner)</sup>

**File:** `ablation/analyzers/perl_taint_scanner.py`

Perl is used in legacy network management planes, CGI scripts on embedded web servers, and old-generation SCADA HMI interfaces. The Perl interpreter has a built-in "taint mode" (`-T` flag) that marks external input as tainted and refuses to pass it to certain operations: but taint mode is almost never enabled in production code. `PerlTaintScanner` implements static taint analysis over Perl source without requiring the interpreter.

### What is Perl taint analysis? <sup>[↑](#pycbytecodescanner)</sup>

Perl taint analysis tracks which variables receive input from `STDIN`, CGI parameters (`$ENV{QUERY_STRING}`, `$cgi->param()`), file reads, and socket receives, and follows those values through string concatenation, interpolation, and function arguments. When a tainted value reaches a backtick execution (`` `$cmd` ``), `system($cmd)`, `exec($cmd)`, `open(FH, "$cmd|")`, or `eval($cmd)`, a finding is reported.

Perl's string interpolation syntax makes command injection both common and subtle. The pattern:

```perl
my $name = $cgi->param('name');
`ls -la /home/$name`;
```

is a classic CGI command injection. The backtick operator executes a shell command and returns its output: any unvalidated CGI parameter interpolated into the backtick expression is injectable. The scanner identifies all backtick, `system`, `exec`, `open(...|)`, and `IPC::Open2`/`IPC::Open3` call sites and traces the arguments backward through variable assignments to find CGI or STDIN sources.

### Usage <sup>[↑](#pycbytecodescanner)</sup>

```python
from ablation.analyzers.perl_taint_scanner import PerlTaintScanner

scanner = PerlTaintScanner.from_path('/path/to/cgi-bin')
hits = scanner.scan()
print(scanner.report(hits))

for hit in hits:
    print(hit.fmt())
```

`from_path()` collects Perl source below a file or directory. `from_files([...])` scans an explicit file list. Each `SinkHit` includes the taint source, sink, file/line, snippet, and severity; validate reachability and any transformations before reporting injection.

---

## Electron Security Scanner <sup>[↑](#pycbytecodescanner)</sup>

**File:** `ablation/analyzers/electron_security_scanner.py`

Electron applications combine Chromium renderer content with a Node.js main process. Unsafe window preferences, missing sender checks, unvalidated URLs, and exposed IPC handlers can turn renderer or web content compromise into access to Node.js capabilities and sensitive data.

### Usage <sup>[↑](#pycbytecodescanner)</sup>

Extract an `app.asar` into a review directory, then scan its JavaScript:

```python
from ablation.analyzers.electron_security_scanner import ElectronSecurityScanner

findings = ElectronSecurityScanner.from_path('/path/to/app.asar.unpacked').scan()
print(ElectronSecurityScanner.report(findings))

main_findings = ElectronSecurityScanner.scan_file('/path/to/app.asar.unpacked/main.js')
for finding in main_findings:
    print(finding.fmt())
```

The scanner checks for insecure `nodeIntegration` and `contextIsolation` combinations, IPC handlers without sender verification, server-controlled URLs loaded into privileged windows, production developer tools, unsafe deep links, TLS bypasses, and missing context bridges. Findings include file, line, class, CWE, severity, explanation, and source snippet. Confirm actual runtime settings and sender reachability; regex matches alone do not prove exploitability.

---

## Integrated scan workflow <sup>[↑](#pycbytecodescanner)</sup>

```python
from ablation.analyzers.pyc_bytecode_scanner import PycBytecodeScanner
from ablation.analyzers.perl_taint_scanner import PerlTaintScanner
from ablation.analyzers.electron_security_scanner import ElectronSecurityScanner

pyc_scanner = PycBytecodeScanner()
pyc_results = pyc_scanner.scan_dir('/firmware/extract/usr/lib/python/')

perl_scanner = PerlTaintScanner.from_path('/firmware/extract/var/www/cgi-bin/')
perl_hits = perl_scanner.scan()

electron_findings = ElectronSecurityScanner.from_path(
    '/firmware/extract/usr/share/gui/'
).scan()

print(pyc_scanner.report(pyc_results))
print(perl_scanner.report(perl_hits))
print(ElectronSecurityScanner.report(electron_findings))
```

---

## Limitation: Python 3.12 adaptive bytecode <sup>[↑](#pycbytecodescanner)</sup>

Python 3.12 introduced "adaptive specialization": the CPython interpreter overwrites bytecode in-place at runtime with specialized versions. A `.pyc` on disk contains the non-specialized form, but a running process's code objects may have been mutated. When extracting `.pyc` files from a live firmware process via `/proc/<pid>/mem`, the extracted code objects may contain specialized opcodes not in the static opcode table. `PycBytecodeScanner` handles this by using `xdis`'s `HAVE_ARGUMENT_EX` table rather than checking raw opcode numbers, but specialized opcode variants may produce `UNKNOWN_OPCODE` scan results. These should be re-analyzed with `dis` against a matching Python 3.12 interpreter.

---

## Limitation: pyc from older FortiOS versions <sup>[↑](#pycbytecodescanner)</sup>

FortiOS 6.x firmware was compiled with Python 3.6. FortiOS 7.0–7.2 uses Python 3.9. FortiOS 7.4+ uses Python 3.10/3.11. When analyzing a mixed-version firmware archive (upgrade bundles often contain both old and new components), the magic number in each `.pyc` file will differ. `PycBytecodeScanner` logs the detected version per file and skips files where `xdis` cannot locate a matching opcode table, reporting them as `parse_error`. Do not interpret `parse_error` as clean: manual analysis with a matching Python version is required.

---

## See also <sup>[↑](#pycbytecodescanner)</sup>

- [Source Code Auditing](source-code-auditing.md): for `.py` source; complement to .pyc scanning
- [Fortinet Build Track Classification](fortinet-build-track-classification.md): FortiSwitch firmware analysis context
- [Firmware Extraction](firmware-extraction.md): extract `.pyc` files from firmware image before scanning
- [Java .class and JAR Analysis](java-class-jar-parsing.md): analogous scanning for JVM bytecode
- [BEAM Context](beam.md): analogous approach for Erlang BEAM bytecode
- [SQL Injection Scanner](sql-injection-scanner.md): if Python code constructs SQL queries, trace the SQL string argument
- [Taint Analysis](taint-analysis.md): for Python extensions written in C (`.so` modules compiled against CPython)
- [Apache Module Analysis](apache-module-analysis.md): web layer analysis for Apache-based management planes that dispatch to Python CGI
- [Pre-Auth Exposure](preauth-exposure.md): confirms which Python route handlers are reachable before authentication
- [FindingRegistry](finding-validation.md): register confirmed Python findings with CWE-78 (OS command injection) or CWE-798 (hardcoded credential); byte-verify the finding VA before registering
