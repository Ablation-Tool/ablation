<img src="assets/ablation-1b-riveted-plate-header-1280.png" width="640" alt="ABLATION">

# Ablation Software Reverse Engineering Framework

![](https://komarev.com/ghpvc/?username=Ablation-Tool&color=grey)

Ablation is an autonomous reverse engineering (ARE) framework. It does everything Ghidra, IDA Pro, and Binary Ninja do, without the tedious GUI work, without the license fees, and without relying on any legacy RE tool.

---

## Claude Code Integration

Claude drives the entire workflow autonomously: builds the corpus, sweeps all vulnerability patterns, pulls disassembly and data flow analysis on every candidate, and returns findings with the exact functions and reasons they are vulnerable.

No binary path needed. No command flags. No manual steps. Just tell it what to do.

```
Reverse engineer this firmware and find vulnerabilities.
```

---

Ablation adds what Ghidra, IDA Pro, and Binary Ninja do not have:

- **Semantic search** across every function in plain English using BERT behavioral fingerprints
- **Autonomous Claude Code workflow**: tell Claude to reverse engineer a target and it drives the full pipeline without manual steps
- **LLM decompilation** via a ReAct loop with `claude-sonnet-5`; works on fully stripped binaries
- **Data flow analysis** that tracks attacker-controlled input through the binary to dangerous functions
- **Cross-binary analysis** across every shared library in a firmware image simultaneously
- **Self-improving pattern library**: confirmed vulnerability findings register as new patterns and replay on future binaries automatically
- **Version diffing** with DTW and Matrix Profile; confirms whether a CVE was patched across firmware releases

Ghidra takes 1 to 4 hours to load a 50 MB binary. Ablation loads the same binary in 35 seconds.

---

Ablation does everything IDA Pro does: disassembly, decompilation, function signatures, call graph, cross-references, import/export analysis, scripting, and binary diffing. Then it goes further.

Ablation adds what IDA Pro does not have:

- **Semantic search** across every function in plain English
- **Autonomous Claude Code workflow**
- **Self-improving pattern library** that replays confirmed findings on future binaries
- **Cross-binary analysis** across every shared library in a firmware image simultaneously
- **Version diffing** with DTW and Matrix Profile

IDA Pro costs $3,000+ per seat. Ablation is open source.

---

Ablation does everything Binary Ninja does: disassembly, decompilation, data flow analysis, function signatures, cross-references, scripting, and binary diffing. Then it goes further.

Ablation adds what Binary Ninja does not have:

- **Semantic search** across every function in plain English
- **Autonomous Claude Code workflow**
- **Self-improving pattern library** that replays confirmed findings on future binaries
- **Cross-binary analysis** across every shared library in a firmware image simultaneously
- **Version diffing** with DTW and Matrix Profile

---

## Install

```bash
pip install git+https://github.com/Ablation-Tool/ablation
```

With LLM features:

```bash
pip install "git+https://github.com/Ablation-Tool/ablation#egg=ablation[llm]"
```

---

## Run

```bash
ablation corpus firmware.so --product my-target --version 1.0 --sigs
ablation sweep  firmware.so --json results.json
ablation search firmware.so "TLV parser that advances pointer without bounds check"
ablation cfg    firmware.so 0x17b660 --insns
ablation taint  firmware.so
ablation findings --sarif findings.sarif
```

---

## Requirements

- Python >= 3.10
- `capstone`, `numpy`, `lief`, `sentence-transformers`, `pyelftools`
- Optional: `anthropic` for LLM features

---

## License

See [LICENSE](LICENSE).

---

## Maintainer

Nicholas Michael Kloster & Claude
