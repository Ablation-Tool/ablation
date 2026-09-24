<img src="assets/ablation-1b-riveted-plate-header-1280.png" width="640" alt="ABLATION">

# Ablation

![](https://komarev.com/ghpvc/?username=Ablation-Tool&color=grey)

**Hand it any binary. It reverse engineers it.**

Ablation is an autonomous reverse engineering framework. Give it any binary: firmware, PE, Mach-O, Go, shared library. No symbols required. No source required. It builds a behavioral corpus across all functions, searches it in plain English, disassembles and decompiles candidates on demand, and traces taint from source to sink.

Built from scratch in Python. Not a wrapper for Ghidra, IDA Pro, or Binary Ninja.

---

## Features

- **Semantic search** across all functions in plain English using BERT behavioral fingerprints
- **30-pattern vulnerability sweep** covering buffer overflow, heap overflow, UAF, format string, integer overflow, auth bypass, DoS, and more
- **Disassembly and CFG** on demand per candidate; no upfront full-binary analysis
- **LLM decompilation** via a ReAct loop with `claude-sonnet-5`; works on fully stripped binaries
- **Static taint analysis** from network sources to dangerous sinks; interprocedural; Z3 path feasibility
- **Cross-binary analysis** across every shared library in a firmware image simultaneously
- **Cross-version diffing** with DTW, Matrix Profile, and semantic tiebreaking; confirms whether a CVE was patched
- **Self-improving pattern library**: confirmed findings register as new patterns and replay on future binaries
- **Autonomous Claude Code workflow**: copy `CLAUDE.md`, say *reverse engineer this firmware*, and Claude drives the full pipeline

---

## Real results

| Finding | Method |
|---|---|
| Zero-length loop DoS in production protocol parser | Semantic sweep, CFG loop analysis |
| Second DoS variant in same binary | Automatic pattern replay from first finding |
| Pre-auth management API exposure (CVSS 9.1) | Semantic sweep, taint trace to unauthenticated handler |

---

## Install

```bash
pip install git+https://github.com/Ablation-Tool/ablation
```

With LLM decompilation and analyst features:

```bash
pip install "git+https://github.com/Ablation-Tool/ablation#egg=ablation[llm]"
```

---

## Quick start

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

Commercial license required for commercial use. Non-commercial research use permitted. See [LICENSE](LICENSE) for full terms.
