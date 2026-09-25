<img src="assets/ablation-1b-riveted-plate-header-1280.png" width="640" alt="ABLATION">

# Ablation Reverse Engineering Framework

![](https://komarev.com/ghpvc/?username=Ablation-Tool&color=grey)

Ablation is a reverse engineering framework. Paired with Claude Code, it becomes fully autonomous. It is not an MCP (Model Context Protocol) server, nor does the Ablation workflow run through MCP to execute these tasks. It does everything Ghidra, IDA Pro, and Binary Ninja do, without the tedious GUI work, without the license fees, and without relying on any legacy RE tool.

---

## Claude Code Integration

Claude drives the entire workflow autonomously: builds the corpus, sweeps all vulnerability patterns, pulls disassembly and data flow analysis on every candidate, and returns findings with the exact functions and reasons they are vulnerable.

No binary path needed. No command flags. No manual steps. Just tell it what to do.

```
Reverse engineer this firmware and find vulnerabilities.
```

**Recommended model:** Ablation was built and tested against `claude-sonnet-4-6` (released January 2026). That is the proven engine. To set it in Claude Code:

```
/model claude-sonnet-4-6
```

`claude-sonnet-4-5` works as well.

---

Ablation adds what Ghidra, IDA Pro, and Binary Ninja do not have:

- **Semantic search** across every function in plain English using BERT behavioral fingerprints
- **Autonomous Claude Code workflow**: tell Claude to reverse engineer a target and it drives the full pipeline without manual steps
- **LLM decompilation** via a ReAct loop with `claude-sonnet-5`; works on fully stripped binaries
- **Data flow analysis** that tracks attacker-controlled input through the binary to dangerous functions
- **Cross-binary analysis** across every shared library in a firmware image simultaneously
- **Self-improving pattern library**: confirmed vulnerability findings register as new patterns and replay on future binaries automatically
- **Version diffing** with DTW and Matrix Profile; confirms whether a CVE was patched across firmware releases
- **Windows kernel driver analysis**: IRP/IOCTL dispatch extraction, kernel API risk classification, rootkit callback detection, SSDT hook and SMEP-disable pattern scanning (`ablation driver`)
- **Format string vulnerability scan**: 28 printf/syslog/err family sinks; backward trace classifies format arg as safe (string literal) or vulnerable (stack slot, argument register); two-hop vsnprintf detection (`ablation fmtstr`)
- **Heap vulnerability scanner**: integer overflow before alloc, use-after-free, double-free, and off-by-one NUL terminator patterns; grounded in TAOSSA Ch5/Ch6 (`ablation heap`)
- **MIPS 32+nM taint tracker**: O32 ABI, load-delay slot aware, big-endian and little-endian; recv/read to system/strcpy/execve sinks; RouterOS and embedded CPE firmware (`ablation mips`)
- **MIPS 64 taint tracker**: N64 ABI (8 arg regs), 64-bit ops LD/SD/DADDU/DMULT, delay-slot aware; big-endian Cisco IOS/OCTEON and little-endian RouterOS 64 (`ablation mips64`)
- **nanoMIPS frame decoder**: variable-length P16/P32/P48 instruction walker; function-start detection; full decode with capstone 6.x, frame-boundary fallback on 5.x; Ingenic SoC and MediaTek embedded (`ablation nanomips`)
- **BYOVD detector**: scores signed drivers for Bring Your Own Vulnerable Driver primitives; 8 attack paths including MmMapIoSpace, MDL kernel write, MSR_LSTAR, and SSDT hook (`ablation byovd`)

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

## Real-World Results

Ablation has been used to analyze production firmware and kernel drivers from Fortinet, Cisco, Axis, Fujitsu, MikroTik, Orka, TencentOS, Enigma2, and Skydio.

**Architectures:**
`x86 - 32` `x86 - 64` `ARM - 32` `ARM - 64` `MIPS 32+nM` `MIPS - 64` `PowerPC` `Windows .sys`

Three vulnerabilities discovered in Cisco Secure Firewall Management Center (FMC) using Ablation were published in Cisco Security Advisory [cisco-sa-fmc2-multivulns-HXgcqRG](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fmc2-multivulns-HXgcqRG):

| CVE | Title | CVSS |
|---|---|---|
| CVE-2026-76420 | Peer Impersonation | 9.0 Critical |
| CVE-2026-76412 | Privilege Escalation to root | 8.5 High |
| CVE-2026-76413 | Single Sign-On Token Forgery | 8.5 High |

---

## Feedback

Found a bug, have an idea, or want to see something added to the tool? Reach out directly.

- [Open an issue](https://github.com/Ablation-Tool/ablation/issues) on GitHub
- X: [@ablation_tool](https://x.com/ablation_tool)
- Signal: [@deadbug.06](https://signal.me/#p/deadbug.06)
- Email: ablation@nuclide-research.com

**Ideas and feature requests:** describe the RE task you want to accomplish and what Ablation currently can't do. All suggestions are welcome.

**Bug reports:** include your Python version, OS, the command that failed, and the full error output.

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
ablation corpus  firmware.so --product my-target --version 1.0 --sigs
ablation sweep   firmware.so --json results.json
ablation search  firmware.so "TLV parser that advances pointer without bounds check"
ablation cfg     firmware.so 0x17b660 --insns
ablation taint   firmware.so
ablation findings --sarif findings.sarif
ablation driver  driver.sys
ablation driver  driver.sys --json driver_report.json
ablation fmtstr  firmware.so
ablation fmtstr  firmware.so --json fmt_findings.json
ablation heap    firmware.so
ablation heap    firmware.so --json heap_findings.json
ablation mips    router.elf
ablation mips    router.elf --le --json mips_findings.json
ablation mips64  iosd --json mips64_findings.json
ablation mips64  routeros64.elf --le --interprocedural --depth 6
ablation nanomips ingenic.bin --le --base 0x80000000
ablation nanomips ingenic.bin --le --frames --limit 100
ablation byovd   driver.sys
ablation byovd   driver.sys --json byovd_report.json
ablation news
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
