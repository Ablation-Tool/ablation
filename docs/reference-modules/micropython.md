<a id="mpylifter"></a>
# MicroPython .mpy v6 Lifting

`MpyLifter` parses MicroPython `.mpy` version 6 files, lifts bytecode code objects to pseudo-Python, extracts imports, and flags security-relevant names and attributes. It runs without a MicroPython runtime and does not execute the module.

## Why a format-specific lifter helps

Firmware can ship Python-like behavior without Python source, but MicroPython `.mpy` is not CPython `.pyc`. Its QSTR names, constant objects, and recursive code objects need a version-specific reader before imports or calls can be interpreted reliably.

The lifter recovers those structures and presents supported bytecode as pseudo-Python, while name-based checks point users toward process, dynamic-execution, and hardware surfaces. This makes small embedded scripts reviewable without a device runtime. It is a focused v6 component that could gain another version backend or richer control-flow support, not a universal Python decompiler. Native/Viper objects and dangerous-name matches remain explicit boundaries requiring native analysis or call-site verification.

## Usage

```python
from modules.mpy_lifter import MpyLifter

lifter = MpyLifter.from_path('/path/to/module.mpy')
print(lifter.lift_module())
print(lifter.imports())

findings = lifter.dangerous_calls()
print(lifter.report(findings))
```

`MpyLifter.from_bytes(data)` parses an in-memory file. `from_path()` rejects files larger than 4 MB; raw-byte callers should apply their own input limits. A version other than the module's supported `.mpy` v6 format raises `ValueError`.

## What is recovered

The parser reads the feature flags, small-integer width, QSTR table, constant objects, and recursive code-object tree. `lift_module()` returns pseudo-Python for supported bytecode operations, including names, constants, imports, attribute access, calls, and nested code objects.

`imports()` returns deduplicated imported module names in bytecode order. `dangerous_calls()` returns dictionaries describing matching imports, dynamic-execution names, and hardware/process-sensitive attributes. `report()` formats those findings as text.

QSTR identifiers make names recoverable even when source files are absent. That does not restore comments, formatting, exact expressions, or all high-level control flow.

## Bytecode versus native objects

MicroPython `.mpy` is different from CPython `.pyc`; their marshal formats and opcode tables are not interchangeable. This lifter supports the v6 MicroPython layout implemented by `modules/mpy_lifter.py`.

Native and Viper code objects are not lifted to Python. They are marked as `<native/viper code — not lifted>` and require analysis of the contained machine code and target architecture. Feature flags indicating native content therefore do not mean native-code decompilation is available.

## Limitations

- Only the implemented `.mpy` v6 parser path is supported; other versions need a compatible parser.
- Pseudo-Python is partial and should be checked against decoded bytecode when a security decision depends on exact behavior.
- Dangerous-name findings are candidates, not proof that a call executes or receives attacker-controlled input.
- Raw-byte parsing bypasses the path-based size check, so callers must enforce safe input sizes.
- Native/Viper objects and C extensions require separate native analysis.

## Related workflows

- [CPython .pyc Security Scanning](python-pyc-scanning.md)
- [Native Binary Lifting](binary-lifter.md)
