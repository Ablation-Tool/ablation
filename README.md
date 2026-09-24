<img src="assets/ablation-1b-riveted-plate-header-1280.png" width="640" alt="ABLATION">

# Ablation

![](https://komarev.com/ghpvc/?username=Ablation-Tool&color=grey)

**Hand it any binary. It reverse engineers it.**

Ablation is a reverse engineering platform built from scratch. It does everything Ghidra does: disassembly, decompilation, call graph, cross-references, string extraction, function identification, import/export analysis, scripting, and binary diffing. Then it goes further.

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
