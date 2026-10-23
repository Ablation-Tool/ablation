# AntiAnalysisStringDetector

## Why this exists

One thing was not possible before in Ablation:

1. **Detect analyst/sandbox detection checklists embedded in binary rodata.** Malware families like Qakbot embed lists of security tool names to detect whether they are running inside a sandbox or under monitoring. No prior Ablation module scanned for these tool-name string arrays. `AntiAnalysisStringDetector` searches the raw binary for 72 known tool name strings across five categories. Finding 3 or more strings from the same category is a defense-evasion finding independent of the execution path.

## Usage

```python
from modules.anti_analysis_string_detector import AntiAnalysisStringDetector

detector = AntiAnalysisStringDetector('/path/to/binary')
findings = detector.scan()
print(detector.report(findings))
```

With an existing `BinaryContext`:

```python
from ablation.analyzers.binary_context import BinaryContext
ctx = BinaryContext.load_or_build('/path/to/binary')
detector = AntiAnalysisStringDetector.from_context(ctx)
findings = detector.scan()
```

## Output: AntiAnalysisFinding

| Field | Type | Description |
|-------|------|-------------|
| `category` | str | Tool category: `debugger`, `dynamic_analysis`, `network_analysis`, `sandbox`, `edr_av` |
| `matched` | list[str] | Tool names found in the binary |
| `match_count` | int | Total matches in this category |
| `severity` | str | `HIGH` for 5 or more matches; `MEDIUM` for 3 or 4 |

## Tool categories

| Category | Count | Sample tools |
|----------|-------|-------------|
| `debugger` | 18 | x64dbg, OllyDbg, WinDbg, IDA Pro, Ghidra, Radare2 |
| `dynamic_analysis` | 13 | Process Monitor, Process Hacker, API Monitor, Autoruns, Regshot |
| `network_analysis` | 13 | Wireshark, Fiddler, Burp Suite, mitmproxy, TCPView |
| `sandbox` | 16 | Sandboxie, VMware Tools, VirtualBox Guest, Cuckoo |
| `edr_av` | 12 | Malwarebytes, Windows Defender, Kaspersky, Bitdefender |

Minimum 3 matches per category to flag.

## FORGE audit

Gate: **PASSED** 2026-10-23. No HIGH or CRITICAL issues.

Tested on synthetic binary with 5 debugger tool name strings: `debugger` category flagged HIGH with `match_count=5`.

## Pipeline position

**Before this module:** no prerequisites.

**After this module:** finding confirms defense-evasion intent. Use `ELFAnomalyScanner` and `EntropyAnalyzer` to check for packing. An anti-analysis binary with packed sections is a confirmed active-defense malware sample.

## See also

- [ELFAnomalyScanner](elf-anomaly-scanner.md): structural ELF anomalies
- [EntropyAnalyzer](entropy-analyzer.md): packed section detection
- [BuildIntegrityAnalyzer](build-integrity-analyzer.md): hardening context
