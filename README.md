<img src="assets/ablation-1b-riveted-plate-header-1280.png" width="640" alt="ABLATION">

# Ablation

![](https://komarev.com/ghpvc/?username=Ablation-Tool&color=grey)

Ablation is an autonomous LLM-driven reverse engineering framework. Tell Claude to reverse engineer a binary and it does: semantic search across every function, disassembly and decompilation on demand, data flow tracking from attacker-controlled input to dangerous functions, and confirmed vulnerability findings.

Hand it any binary: enterprise firmware, Windows PE, macOS Mach-O, Go binaries, shared libraries. No symbols required. No source required. No manual setup. Claude drives the full pipeline using Ablation as its RE engine, sweeps 30 vulnerability patterns, pulls CFG and taint on every candidate, and returns confirmed findings with disassembly showing exactly why each function is vulnerable.

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
