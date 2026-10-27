<a id="pycbytecodescanner"></a>
# CPython .pyc Security Scanning

`PycBytecodeScanner` uses `xdis` to parse CPython bytecode across interpreter versions and reports security-relevant names, constants, imports, and path metadata. It scans `.pyc` code objects; it does not decompile them to Python source and does not analyze Perl or Electron.

## Scan files or a directory

```python
from ablation.analyzers.pyc_bytecode_scanner import PycBytecodeScanner

scanner = PycBytecodeScanner()
result = scanner.scan_file('/path/to/module.pyc')
print(scanner.report([result]))

results = scanner.scan_dir('/path/to/extracted-firmware')
print(scanner.report(results))
```

`scan_file()` returns a `PycScanResult` containing the path, filename, detected Python version, findings, and any parse error. `scan_dir()` recursively scans `.pyc` files. `scan_raw()` supports bytecode held in memory when its format/magic can be identified.

`xdis` is required and raises an informative `ImportError` if unavailable. Cross-version support comes from `xdis` marshal and opcode handling rather than the host interpreter's `marshal` or `dis` modules. The implementation includes explicit version mappings through CPython 3.12 and otherwise relies on what the installed `xdis` release supports.

## What findings mean

The scanner recursively inspects code-object names and constants. Command/process execution names, dynamic evaluation, network/TLS APIs, embedded paths, credential-like strings, and related constants are converted into prioritized review signals.

Names alone do not establish exact call semantics. For example, `os` and `system` in one code object are suggestive but do not prove a reachable `os.system()` call with attacker-controlled input. Constants can be documentation, test data, hashes, or dead code. Inspect disassembly and surrounding modules before reporting a vulnerability.

The scanner reports source filenames embedded in code objects, which can reveal build-layout information. This metadata does not provide the original source text.

## Version and format boundaries

CPython changes opcode numbers, instruction encoding, code-object fields, and `.pyc` headers between releases. Use a current compatible `xdis` rather than hard-coded host opcode tables. A `.pyc` cannot be loaded safely with arbitrary host `marshal.loads()` as a cross-version analysis strategy.

MicroPython `.mpy` is a different format and belongs to [MicroPython .mpy v6 Lifting](micropython.md). Native Python extension modules (`.so`, `.pyd`) require native analysis. This scanner performs no source decompilation and no sandboxed execution of the target module.

## Limitations

- Parse errors are returned in results; inspect them instead of treating an empty finding list as clean.
- The scanner's version labels and actual compatibility depend on the installed `xdis` version and input magic.
- Name/constant rules can create false positives and cannot prove reachability, source control, or exploitability.
- Obfuscation, unsupported newer bytecode, and missing code objects reduce coverage.
- Confirm candidate behavior with version-aware disassembly and manual data-flow review.

## Related workflows

- [MicroPython .mpy v6 Lifting](micropython.md)
- [Java Class / JAR Security Analysis](java-class-jar-parsing.md)
- [Firmware Extraction](firmware-extraction.md)
