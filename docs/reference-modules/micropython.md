# MpyLifter

Lift compiled MicroPython `.mpy` v6 bytecode files to readable pseudo-Python source, extract imported module names, and flag dangerous import and call patterns `exec`, `eval`, `os`, `machine`, `uctypes`: identifying firmware-embedded scripting attack surfaces without requiring the MicroPython runtime: via `modules/mpy_lifter.py` `MpyLifter`.

---

## Why this exists <sup>[↑](#mpylifter)</sup>

1. Embedded firmware increasingly ships with compiled MicroPython modules. Network appliances, IoT gateways, and industrial controllers embed `.mpy` files alongside native code. These modules run with full hardware access (`machine.mem32`, `machine.mem16`, `machine.mem8`) and can execute arbitrary Python expressions via `eval`/`exec`. Binary analysis tools that only process ELF or PE binaries miss the entire scripting layer of these devices.

2. `.mpy` files are not source code and require a bytecode-aware lifter. A compiled `.mpy` v6 file stores a qstr table (interned string constants), a constant object table, and a recursive code-object tree with VM opcodes. `MpyLifter` decodes all three structures without launching the MicroPython VM, producing readable pseudo-Python that exposes function definitions, imports, constant values, and call patterns.

3. `MpyLifter.dangerous_calls()` classifies security-relevant patterns into three finding types. `DANGEROUS_IMPORT` covers imports of `os`, `machine`, `uctypes`, `subprocess`, and similar modules. `DANGEROUS_CALL` covers calls to `exec`, `eval`, `compile`, and `open`. `DANGEROUS_ATTR` covers attribute access on dangerous modules such as `machine.mem32` and `uctypes.addressof`. Each finding carries a `function` field (code object name) and an `offset` field (bytecode instruction offset) for precise location.

---

## How it works <sup>[↑](#mpylifter)</sup>

```mermaid
flowchart TD
    A(["MpyLifter.from_path(path) or .from_bytes(data)"]):::input --> B["_parse():\n  MpyHeader: magic, version=6, features, qstr_win\n  qstr table: {id → str} · all string constants\n  const object table: int, float, str, bytes literals\n  Recursive code-object tree: functions + nested lambdas"]:::primary
    B:::primary --> C["lift_module() → str\n  Walk root code object + all children via _lift_code()\n  Per opcode: IMPORT_NAME, LOAD_GLOBAL, LOAD_ATTR resolved\n  via qstr table → pseudo-Python string (indented, readable)"]:::secondary
    C:::secondary --> D["imports() → list[str]\n  Walk all code objects\n  Collect IMPORT_NAME qstr values (deduplicated, in-order)\n  → module names as found in bytecode"]:::tertiary
    D:::tertiary --> E(["dangerous_calls() → list[dict]\n  Walk all code objects\n  IMPORT_NAME + name in _DANGEROUS_IMPORTS → DANGEROUS_IMPORT\n  LOAD_NAME/LOAD_GLOBAL + name in _DANGEROUS_NAMES → DANGEROUS_CALL\n  LOAD_ATTR + attr in _DANGEROUS_ATTRS → DANGEROUS_ATTR\n  Each: {type, detail, offset, function, severity}\n  → report(findings) → str ASCII table"]):::output
    classDef input     fill:#0d47a1,stroke:#1565c0,color:#fff
    classDef primary   fill:#e65100,stroke:#bf360c,color:#fff
    classDef secondary fill:#004d40,stroke:#00695c,color:#fff
    classDef tertiary  fill:#4a148c,stroke:#6a1b9a,color:#fff
    classDef neutral   fill:#37474f,stroke:#546e7a,color:#fff
    classDef output    fill:#1b5e20,stroke:#2e7d32,color:#fff
    linkStyle 0 stroke:#bf360c,stroke-width:2px
    linkStyle 1 stroke:#00695c,stroke-width:2px
    linkStyle 2 stroke:#6a1b9a,stroke-width:2px
    linkStyle 3 stroke:#2e7d32,stroke-width:3px
```

---

## Usage <sup>[↑](#mpylifter)</sup>

```python
from modules.mpy_lifter import MpyLifter

# MpyLifter
lifter = MpyLifter.from_path('/path/to/extracted/module.mpy')

# MpyLifter
print(lifter.lift_module())

# MpyLifter
print("Imports:", lifter.imports())

# MpyLifter
# MpyLifter
findings = lifter.dangerous_calls()
for f in findings:
    print(f"  [{f['severity']}] {f['type']}: {f['detail']}  "
          f"(in {f['function']} @ offset {f['offset']})")

# MpyLifter
print(MpyLifter.report(findings))
```

---

## Example output <sup>[↑](#mpylifter)</sup>

The following is a schematic example showing output structure and field names. Values are illustrative.

```
lift_module():
  import machine
  import os

  def update_firmware(url):
      data = fetch(url)
      machine.mem32[<addr>] = <value>
      exec(data)

imports(): ['machine', 'os', 'uio']

dangerous_calls():
  [HIGH]   DANGEROUS_CALL    exec        (in update_firmware @ offset 14)
  [HIGH]   DANGEROUS_ATTR    mem32       (in update_firmware @ offset 8)
  [HIGH]   DANGEROUS_IMPORT  machine     (in <module> @ offset 2)

MpyLifter.report(findings):
  Type                   Sev    Function                     Detail
  -------------------------------------------------------------------------------
  DANGEROUS_CALL         HIGH   update_firmware              exec
  DANGEROUS_ATTR         HIGH   update_firmware              mem32
  DANGEROUS_IMPORT       HIGH   <module>                     machine
```

---

## False positives <sup>[↑](#mpylifter)</sup>

**`DANGEROUS_IMPORT` fires on any import of `os` or `machine`**: most MicroPython hardware drivers import `machine` for pin control and PWM. An `DANGEROUS_IMPORT` finding for `machine` is informational; escalate only when `DANGEROUS_ATTR` findings for `mem32`, `mem16`, or `mem8` also appear in the same function, indicating direct memory writes rather than safe peripheral API use.

**`DANGEROUS_ATTR` for `mem32` read access vs write access**: `machine.mem32[addr]` (read) is less dangerous than `machine.mem32[addr] = val` (write). The finding fires for either form; read the lifted pseudo-Python from `lift_module()` to determine whether the access is read-only or a write that could overwrite firmware or peripheral registers.

---

## Pipeline position <sup>[↑](#mpylifter)</sup>

Run `MpyLifter` on every `.mpy` file extracted from firmware containers. Combine with `BinaryContext.load_or_build()` on the native ELF loader to cover both the compiled C layer and the MicroPython scripting layer. Use firmware extraction tooling to locate `.mpy` files within firmware squashfs images before analysis.

---

## Reading output <sup>[↑](#mpylifter)</sup>

`MpyLifter.lift_module()` returns a `str`: multi-line Python-like pseudocode for the entire `.mpy` module. Additional methods:

- `MpyLifter.imports()` → `List[str]`: all imported module names found in the bytecode
- `MpyLifter.dangerous_calls()` → `List[dict]`: calls to `exec`, `eval`, `os`, `machine`, `uctypes`, etc.; each dict has `type`, `qstr`, `va`, `severity`

---

## See also <sup>[↑](#mpylifter)</sup>

- [MicroPython .mpy Lifter](mpy-lifter.md): detailed constructor patterns, opcode reference, and version compatibility table
- [Firmware Extraction](firmware-extraction.md): squashfs and CRAMFS extraction to locate embedded `.mpy` files
- [Hardware Root Discovery](hardware-root-discovery.md): native firmware analysis for the C/assembler layer alongside MicroPython modules
