<img src="assets/ablation-1b-riveted-plate-header-1280.png" width="640" alt="ABLATION">

# Ablation

![](https://komarev.com/ghpvc/?username=Ablation-Tool&color=grey)

Ablation is a reverse engineering framework for stripped binaries. It builds a behavioral corpus across every function, searches it in plain English, disassembles and decompiles candidates on demand, and traces taint from source to sink. Give it any binary: firmware, PE, Mach-O, Go, shared library. No symbols required. No source required.

Ablation integrates with Claude Code for autonomous operation. Copy `CLAUDE.md` into a project, tell Claude to reverse engineer a target, and it drives the full pipeline without further input.

## Install

```bash
pip install git+https://github.com/Ablation-Tool/ablation
```

With LLM features:

```bash
pip install "git+https://github.com/Ablation-Tool/ablation#egg=ablation[llm]"
```

## Run

```bash
ablation corpus firmware.so --product my-target --version 1.0 --sigs
ablation sweep  firmware.so --json results.json
ablation search firmware.so "TLV parser that advances pointer without bounds check"
ablation cfg    firmware.so 0x17b660 --insns
ablation taint  firmware.so
ablation findings --sarif findings.sarif
```

## Requirements

- Python >= 3.10
- `capstone`, `numpy`, `lief`, `sentence-transformers`, `pyelftools`
- Optional: `anthropic` for LLM features

## License

See [LICENSE](LICENSE).
