<img src="assets/ablation-1b-riveted-plate-header-1280.png" width="640" alt="ABLATION">

# Ablation Reverse Engineering Framework

![](https://komarev.com/ghpvc/?username=Ablation-Tool&color=grey)

Ablation is a reverse engineering framework. Paired with Claude Code, it becomes fully autonomous. It does everything Ghidra, IDA Pro, and Binary Ninja do, without the tedious GUI work, without the license fees, and without relying on any legacy RE tool.

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
- **MIPS32 taint tracker**: O32 ABI, load-delay slot aware, big-endian and little-endian; recv/read to system/strcpy/execve sinks; RouterOS and embedded CPE firmware (`ablation mips`)
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

## Updates

Full release notes live in [updates/](updates/).

**[v2.4.0](updates/v2.4.0.md) (2026-09-24): Format string scanner, MIPS32 taint, BYOVD detector, heap scanner, IOCTL surface, cross-binary taint**

Six new analyzers ship in this release.

- **Format string scanner** (`ablation fmtstr`): 28 printf/syslog/err sinks; backward trace from each call site; SAFE (LEA .rodata), VULNERABLE (stack slot or arg), SUSPICIOUS (global/computed); two-hop vsnprintf detection
- **MIPS32 taint tracker** (`ablation mips`): O32 ABI; load-delay slot aware; big-endian and little-endian; recv/read to system/execve/strcpy/sprintf; intraprocedural and interprocedural BFS
- **BYOVD detector** (`ablation byovd`): scores Windows drivers 0-100 across 8 attack paths; signed driver + METHOD_NEITHER IOCTL + dangerous primitive = BYOVD_CONFIRMED
- **Heap vulnerability scanner** (`ablation heap`): INT_OVERFLOW_BEFORE_ALLOC, USE_AFTER_FREE, DOUBLE_FREE, OFF_BY_ONE_ALLOC; grounded in TAOSSA ch.5 and ch.6
- **IOCTL attack surface** (`ioctl_attack_surface.py`): per-IOCTL handler disassembly window; METHOD_NEITHER flagged; dangerous API annotations
- **Cross-binary taint** (`cross_binary_taint.py`): follows taint across `.so` boundaries via LibGraph; seeds at export crossings; BFS through callee chains

**[v2.0.0](updates/v2.0.0.md) (2026-09-24): Windows kernel driver RE**

`ablation driver <file.sys>` analyzes Windows kernel drivers. Run it against any `.sys` file and it returns a full report in under a second.

- **IRP/IOCTL dispatch**: disassembles DriverEntry and recovers all 28 MajorFunction slot assignments; decodes each CTL_CODE into DeviceType, Access, Function, and Method; flags METHOD_NEITHER (raw user pointer) as the highest-risk transfer type
- **Kernel API audit**: classifies 40+ kernel APIs across 12 risk classes: physical memory mapping, token stealing via PsInitialSystemProcess, APC injection, process attachment, SSDT hooking, virtual memory manipulation, driver loading, DKOM, pool allocation, and MDL misuse
- **Callback detection**: tags 20+ kernel callbacks as edr_like, rootkit_risk, or info; ObRegisterCallbacks + PsSetCreateProcessNotifyRoutineEx + KeRegisterBugCheckReasonCallback in a single driver identifies a rootkit
- **Dangerous patterns**: detects the CR0 WP-disable sequence (SSDT hook prerequisite), the CR4 SMEP-disable sequence, MSR_LSTAR reads (KASLR defeat) and writes (syscall hijack), UTF-16LE `L"KeServiceDescriptorTable"`, RDMSR/WRMSR, CLI/STI/HLT, SWAPGS, IRETQ, and direct I/O port access
- **Driver classification**: identifies WDM, KMDF, and minifilter drivers by import profile; extracts the PDB path; detects Authenticode signatures; recovers pool tags from `ExAllocatePoolWithTag` call sites

`ablation news` prints this update log inline.

---

## Real-World Results

Ablation has been used to analyze production firmware and kernel drivers from Fortinet, Cisco, Axis, Fujitsu, MikroTik, Orka, TencentOS, Enigma2, and Skydio, covering x86-64, ARM64, ARM32, MIPS32, PowerPC, and Windows .sys.

Three vulnerabilities discovered in Cisco Secure Firewall Management Center (FMC) using Ablation were published in Cisco Security Advisory [cisco-sa-fmc2-multivulns-HXgcqRG](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fmc2-multivulns-HXgcqRG):

| CVE | Title | CVSS |
|---|---|---|
| CVE-2026-76420 | Peer Impersonation | 9.0 Critical |
| CVE-2026-76412 | Privilege Escalation to root | 8.5 High |
| CVE-2026-76413 | Single Sign-On Token Forgery | 8.5 High |

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

## Feedback

Found a bug, have an idea, or want to see something added to the tool? Reach out directly.

- [Open an issue](https://github.com/Ablation-Tool/ablation/issues) on GitHub
- Email: [ablation@nuclide-research.com](mailto:ablation@nuclide-research.com)
- X: [@ablation_tool](https://x.com/ablation_tool)
- Signal: [@deadbug.06](https://signal.me/#p/deadbug.06)

**Bug reports:** include your Python version, OS, the command that failed, and the full error output.

**Ideas and feature requests:** describe the RE task you want to accomplish and what Ablation currently can't do. All suggestions are welcome.

---

## License

See [LICENSE](LICENSE).

---

## Maintainer

Nicholas Michael Kloster & Claude
