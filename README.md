<img src="assets/ablation-1b-riveted-plate-wordmark-transparent-2560.png" width="520" alt="ABLATION">

![](https://komarev.com/ghpvc/?username=Ablation-Tool&color=grey) [![NIST SP 800-218](https://img.shields.io/badge/NIST%20SP%20800--218-SSDF-grey)](docs/ABLATION-STANDARDS.md) [![CISA Secure by Design](https://img.shields.io/badge/CISA-Secure%20by%20Design-grey)](docs/ABLATION-STANDARDS.md) [![MIL-HDBK-115C](https://img.shields.io/badge/MIL--HDBK--115C-Compliant-grey)](docs/ABLATION-STANDARDS.md) [![Cash App](https://img.shields.io/badge/Cash_App-%24nicholaskloster2-4a4a4a?style=flat-square&labelColor=333333)](https://cash.app/$nicholaskloster2) [![Bitcoin](https://img.shields.io/badge/Bitcoin-Donate-4a4a4a?style=flat-square&labelColor=333333)](./SPONSORS.md#bitcoin)


Ablation is a self-contained reverse engineering framework.

It depends on neither legacy tools nor an MCP server, which removes the attack surface associated with MCP.

When used with Codex or Claude Code, it operates as an autonomous reverse engineering system.



---

![demo](assets/screencast-2026-09-30.gif)

## Capabilities

<details>
<summary><strong>Analysis</strong> </summary>

| Capability | |
|:---|:---|
| [**The Flywheel**](docs/module-reference/flywheel.md) | Every confirmed finding replays as a search pattern on every future binary. A vulnerability confirmed on one vendor's firmware surfaces automatically when sweeping a different vendor's binary because confirmed findings are stored and replayed at engagement start. |
| [**Semantic Code Search**](docs/module-reference/semantic-search.md) | Finds functions by describing what they do because stripped binaries have no symbols to search. Queries are scoped to the target binary so results return in under a second. |
| [**On-Demand Analysis**](docs/module-reference/on-demand-analysis.md) | Loads in seconds because it only analyzes the code being examined. Traditional disassemblers parse the entire file into a database before you can do anything. |
| [**Binary Lifting**](docs/module-reference/binary-lifter.md) | Translates machine code to readable pseudo-C across 19 architectures. ARM64 and x86-64 get register-level taint tracking so data flow is visible in the lifted output. |
| [**Hypothesis Engine**](docs/module-reference/hypothesis-engine.md) | Tracks competing theories about what a function does and scores evidence against each one. Sessions persist across engagements so analysis resumes where it left off. |
| [**C++ Vtable Reconstruction**](docs/module-reference/cpp-vtable-reconstructor.md) | Recovers C++ virtual dispatch tables from stripped ELF binaries on any architecture and names each slot. A generated type-annotation script propagates slot names through every call site so the decompiler shows method names instead of function pointer offsets. |
| [**Cross-Library Analysis**](docs/module-reference/taint-analysis.md) | Traces an argument across up to three shared library hops so taint paths that cross library boundaries reach their sink rather than stopping at the first call. |
| [**DAG Adapter Language**](docs/module-reference/encoding-dag.md) | Describes instruction set encodings as directed acyclic graphs so every architecture shares the same analysis code path. Without it, each ISA requires its own exception handler and the analyzer count scales with the architecture count. |
| [**PPC32 GOT2 Resolver**](docs/module-reference/ppc32-got2-resolver.md) | Resolves indirect calls in stripped GOT2-PIC PPC32 binaries at 98.6% coverage so taint paths through BCTRL stubs do not dead-end at the first unresolved call. |
| [**Dynamic Sandbox**](docs/module-reference/dynamic-sandbox.md) | Executes leaf functions in an emulated sandbox to fingerprint behavior where static analysis alone cannot distinguish branches. |

</details>

<details>
<summary><strong>Security Analysis</strong> </summary>

| Capability | |
|:---|:---|
| [**Taint Analysis**](docs/module-reference/taint-analysis.md) | Follows network input through the call graph to security-sensitive sinks across 14 architectures. Library call sites do not stop the trace because register-level tracking resolves shared library stubs. |
| [**Pre-Authentication Exposure**](docs/module-reference/preauth-exposure.md) | Finds every code path from the network entry point to a security-sensitive operation that runs before authentication. Manual review starts at the authentication boundary because the output is a reachability map, not a raw disassembly. |
| [**Finding Validation**](docs/module-reference/preauth-exposure.md) | Generates a working HTTP request that reproduces each confirmed finding at the protocol level. The request includes the expected response delta and CWE classification so a PSIRT submission arrives with working proof. |
| [**Source Code Auditing**](docs/module-reference/source-audit.md) | Scores every source file by risk and batches the low-risk ones so manual review covers only the files most likely to contain vulnerabilities. |
| [**Compiler Defect Detection**](docs/module-reference/compiler-defects.md) | Finds security defects that the compiler introduced through miscompilation. Optimizer defects that silently select the wrong comparison operand can produce hundreds of confirmed vulnerabilities across a single firmware image. |
| [**Cryptographic Analysis**](docs/module-reference/crypto.md) | Recovers cryptographic key material directly from compiled firmware and audits TLS and JWT configurations, so cryptographic findings do not require source access or a decryption oracle. |
| [**Sink Arg Classifier**](docs/module-reference/sink-arg-classifier.md) | Classifies what value reaches each exec-class sink so a taint hit is either confirmed as externally controlled or eliminated as a constant before manual review begins. |

</details>

<details>
<summary><strong>Runtimes & Formats</strong> </summary>

| Capability | |
|:---|:---|
| [**LoongArch64**](docs/module-reference/loongarch64.md) | The only public reverse engineering toolkit built specifically for LoongArch64. It covers the full analysis pipeline so no architecture-specific workarounds are needed. |
| [**nanoMIPS**](docs/module-reference/nanomips.md) | Follows tainted data through nanoMIPS binaries interprocedurally, resolving branch targets and PLT stubs that no other public tool handles. |
| [**Windows PE Security Analysis**](docs/module-reference/windows-pe.md) | Audits a Windows PE binary for security weaknesses in a single pass. It checks CFG bypass exports, SafeSEH gaps, unauthenticated RPC endpoints, COM registration gaps, and kernel pool overflows so the full attack surface is visible before manual review begins. |
| [**Windows Kernel Driver & BYOVD**](docs/module-reference/kernel-drivers.md) | Classifies signed kernel drivers for BYOVD capability before they are deployed. Physical memory access, privilege token manipulation, and callback removal each trigger a finding. |
| [**Android / APK Analysis**](docs/module-reference/android.md) | Maps the APK attack surface and ranks native libraries by risk before manual analysis begins. |
| [**Erlang / BEAM Analysis**](docs/module-reference/beam.md) | Decodes BEAM bytecode to readable pseudo-IR so Erlang and Elixir applications can be analyzed without source. High-risk import patterns and obfuscation indicators surface without executing the application. |
| [**Go Binary Reverse Engineering**](docs/workflows/go-binaries.md) | Recovers function names from stripped Go binaries because the runtime embeds a metadata table that survives stripping. |
| [**Game & Legacy RE**](docs/module-reference/game-re.md) | Labels stripped game binary functions by engine so analysis starts at the game logic layer instead of the engine layer. Also handles PS3 Cell SPU and classic Mac OS PEF binaries. |
| [**Firmware Extraction**](docs/module-reference/firmware-analysis.md) | Decrypts vendor-encrypted firmware without a key because predictable patterns in inner partitions reveal it. Handles vendor-modified squashfs images including ARM64 BCJ-filtered variants. |
| [**Firmware Key Corpus**](docs/module-reference/firmware-analysis.md) | Classifies recovered firmware keys against a cross-image family table. An anomalous key count flags a potential finding before decryption begins. |
| [**HarmonyOS / ArkTS Analysis**](docs/module-reference/harmonyos.md) | Analyzes HarmonyOS HAP packages and ArkTS bytecode so OpenHarmony targets can be assessed without source access. Surfaces exported abilities, permission grants, and native library attack surface before manual review begins. |
| [**PS3 SELF Decryptor**](docs/module-reference/ps3-self-decryptor.md) | Decrypts PS3 SELF (Signed ELF) files to plain ELF because lief and BinaryContext reject SCE-format magic. Keyset detection is automatic from the key_rev field so no manual key lookup is needed. |
| [**MicroPython .mpy Lifter**](docs/module-reference/mpy-lifter.md) | Lifts .mpy v6 bytecode to readable pseudo-Python so MicroPython firmware on ESP32, STM32, and CC13xx targets can be analyzed without source. Flags dangerous imports and machine-level memory access calls in the lifted output. |

</details>

<details>
<summary><strong>Workflow</strong> </summary>

| Capability | |
|:---|:---|
| [**Version Diffing**](docs/workflows/cross-version.md) | Checks whether the logic changed, not whether the file changed, so a cosmetic recompile cannot hide an unpatched vulnerability. |
| [**Cross-Target Learning**](docs/module-reference/cross-target-learning.md) | Every confirmed finding seeds future semantic searches, so the tool gets sharper with each engagement. |
| [**KASAN-Oracle**](docs/workflows/kasan-oracle.md) | Scans a KASAN debug build first because debug builds expose control flow that stripping removes. Confirmed candidates from the debug build then validate against the stripped production binary, so the debug image acts as a ground-truth oracle rather than a secondary target. |
| [**Module Quality Gate**](docs/module-reference/forge.md) | FORGE audits every user-written module before it can be stored, so local extensions meet the same standard as the modules that ship with Ablation. |
| [**Coverage Gate**](docs/ABLATION-STANDARDS.md) | The taint engine requires 85% statement coverage on every commit, so a regression in taint logic fails the test suite before it reaches a firmware engagement. |
| [**Kernel Module Subsystem Classifier**](docs/module-reference/kernel-module-subsystem-classifier.md) | Classifies a Linux kernel module by its source tree path to determine attack surface before analysis begins. Network-reachable modules surface first so manual review starts at the highest-risk code. |

</details>

<details>
<summary><strong>Automotive RE</strong> </summary>

| Capability | |
|:---|:---|
| [**ECU Architecture Detector**](docs/module-reference/ecu-arch-detector.md) | Identifies the ISA of a flat ECU ROM from raw bytes alone. PPC32, SH-2A, TriCore, RH850, V850, M68K, C28x, and M32R all produce recognizable structural signatures without symbols or file headers. |
| [**ROM Layout Analyzer**](docs/module-reference/ecu-rom-layout-analyzer.md) | Splits a flat ROM into CODE, CALIBRATION, and IVT regions before analysis begins. The interrupt vector table is excluded from function discovery so taint trackers start from clean application code boundaries. |
| [**Calibration Parsers**](docs/module-reference/ecu-cal-parsers.md) | Reads TunerPro XDF, ASAM A2L, RomRaider XML, open_damos, and ConesCAN definition files and injects human-readable table labels into BinaryContext. Every array in the ROM has a name when the taint tracker reaches it. |
| [**CAN DBC Parser**](docs/module-reference/can-dbc-parser.md) | Reads CAN signal database files and makes message and signal definitions available during binary analysis. No other RE tool brings CAN signal context into the taint analysis pipeline. |
| [**ECU Security Access Scanner**](docs/module-reference/ecu-security-access-scanner.md) | Audits UDS SecurityAccess implementations for weak seed generation, static keys, and bypassable challenge-response logic. Runs before taint analysis so weak authentication findings are confirmed before deeper code tracing begins. |

</details>

---

## 19 Decompilers

| ISA / Runtime | Variants |
|---|---|
| x86 | x86-32 · x86-64 |
| ARM | ARM-32 · ARM-64 |
| MIPS | MIPS-32 · nanoMIPS · MIPS-64 |
| PowerPC | PPC-32 · PPC-64 |
| RISC-V | RISC-V 32 · RISC-V 64 |
| ARC | ARC EM/HS |
| V850 | V850-32 |
| LoongArch | LoongArch64 |
| DEX | Dalvik · ART |
| ARK | ArkTS |
| BEAM | Erlang · Elixir |

---
## Real-World Results
Ablation has been used to analyze production firmware and kernel drivers from Cisco, Fortinet, TencentOS, Huawei, and more.

Following coordinated disclosure, the Cisco Product Security Incident Response Team (PSIRT) adopted Ablation for internal vulnerability triage and continues to use it to evaluate ongoing disclosure reports. Cisco Adaptive Security Appliance (ASA) LINA is among the artifacts analyzed, with findings submitted through CERT/CC VINCE.

| CVE | Product | Title | CVSS | Advisory |
|---|---|---|---|---|
| CVE-2026-76420 | Secure Firewall Management Center (FMC) | Peer Impersonation | 9.0 Critical | [cisco-sa-fmc2-multivulns-HXgcqRG](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fmc2-multivulns-HXgcqRG) |
| CVE-2026-76412 | Secure Firewall Management Center (FMC) | Privilege Escalation to root | 8.5 High | [cisco-sa-fmc2-multivulns-HXgcqRG](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fmc2-multivulns-HXgcqRG) |
| CVE-2026-76413 | Secure Firewall Management Center (FMC) | Single Sign-On Token Forgery | 8.5 High | [cisco-sa-fmc2-multivulns-HXgcqRG](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fmc2-multivulns-HXgcqRG) |
| CVE-2026-76447 | Identity Services Engine (ISE) | OCSP Responder Authentication Bypass | 5.3 Medium | [cisco-sa-ise-multiauth-bypass-sgD2HbL4](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-multiauth-bypass-sgD2HbL4) 



---

## Acknowledgments
This project was greatly informed and inspired by several key literary works.

**Research Papers**

| Title | Authors |
|---|---|
| [Reverse Compilation Techniques](https://scholar.google.com/citations?view_op=view_citation&hl=en&user=iseZ69MAAAAJ&citation_for_view=iseZ69MAAAAJ:u-x6o8ySG0sC) · [Specifying the Semantics of Machine Instructions](https://ieeexplore.ieee.org/document/693702) · [UQBT: Adaptable Binary Translation at Low Cost](https://ieeexplore.ieee.org/document/825697) · [Machine-Adaptable Dynamic Binary Translation](https://dl.acm.org/doi/10.1145/351397.351414) | [Dr. Cristina Cifuentes](https://scholar.google.com/citations?hl=en&user=iseZ69MAAAAJ) |
| [Design of a Retargetable Decompiler for a Static Platform-Independent Malware Analysis](https://www.researchgate.net/publication/220849941_Design_of_a_Retargetable_Decompiler_for_a_Static_Platform-Independent_Malware_Analysis) | [Petr Zemek](https://github.com/s3rvac), Lukáš Ďurfina, Jakub Křoustek, Dušan Kolář, Tomas Hruska, Karel Masařík, Alexander Meduna |
| [Finding Taint-Style Vulnerabilities in Linux-based Embedded Firmware with SSE-based Alias Analysis](https://arxiv.org/abs/2109.12209) | Cheng, Zheng, Liu, Guan, Liu, Li, Zhu, Ye, Sun |
| [iResolveX: Multi-Layered Indirect Call Resolution via Static Reasoning and Learning-Augmented Refinement](https://arxiv.org/abs/2601.17888) | Monika Santra, Bokai Zhang, Mark Lim, [Vishnu Asutosh Dasu](https://github.com/vdasu), Dongrui Zeng, [Gang Tan](https://github.com/gangtan) |
| [Extracting Protocol Format as State Machine via Controlled Static Loop Analysis](https://arxiv.org/abs/2305.13483) | [Qingkai Shi](https://github.com/qingkaishi), Xiangzhe Xu, Xiangyu Zhang |
| [NEMETYL: Message Type Identification of Binary Network Protocols using Continuous Segment Similarity](https://arxiv.org/abs/2002.03391) | [Stephan Kleber](https://github.com/vs-uulm), Rens Wouter van der Heijden, [Frank Kargl](https://github.com/fkargl) |
| [Imperfect Forward Secrecy: How Diffie-Hellman Fails in Practice](https://dl.acm.org/doi/10.1145/2810103.2813707) | [David Adrian](https://github.com/dadrian), Karthikeyan Bhargavan, [Zakir Durumeric](https://github.com/zakird), Pierrick Gaudry, Matthew Green, [J. Alex Halderman](https://github.com/jhalderm), [Nadia Heninger](https://github.com/factorable), Drew Springall, Emmanuel Thomé, [Luke Valenta](https://github.com/lukevalenta) |
| [Nonce-Disrespecting Adversaries: Practical Forgery Attacks on GCM in TLS](https://www.usenix.org/conference/woot16/workshop-program/presentation/bock) | [Hanno Böck](https://github.com/hannob), [Aaron Zauner](https://github.com/azet), Sean Devlin, [Juraj Somorovsky](https://github.com/jurajsomorovsky), [Philipp Jovanovic](https://github.com/Daeinar) |
| [Whitening Sentence Representations for Better Semantics and Faster Retrieval](https://arxiv.org/abs/2103.15316) | [Jianlin Su](https://github.com/bojone), [Jiarun Cao](https://github.com/jiaruncao), Weijie Liu, Yangyiwen Ou |
| [Constant Propagation with Conditional Branches](https://dl.acm.org/doi/abs/10.1145/103135.103136) | Mark N. Wegman, F. Kenneth Zadeck |
| [A Simple, Fast Dominance Algorithm](https://www.cs.princeton.edu/techreports/2005/737.pdf) | Cooper, Harvey, Kennedy |
| [libdft: Practical Dynamic Data Flow Tracking for Commodity Systems](https://dl.acm.org/doi/10.1145/2151024.2151042) | [Vasileios P. Kemerlis](https://github.com/vkemerlis), [Georgios Portokalidis](https://github.com/portokalidis), [Kangkook Jee](https://github.com/jikk), Angelos D. Keromytis |

**Books** supplied by [www.oreilly.com](https://www.oreilly.com) | [github.com/oreillymedia](https://github.com/oreillymedia)

| Title | Authors |
|---|---|
| The Art of Software Security Assessment | [Mark Dowd](https://github.com/mdowd79), John McDonald, [Justin Schuh](https://github.com/jschuh) |
| Practical Binary Analysis | [Dennis Andriesse](https://github.com/dennisaa) |
| Practical Malware Analysis | Michael Sikorski, Andrew Honig |
| Practical Reverse Engineering | Bruce Dang, Alexandre Gazet, [Elias Bachaalany](https://github.com/0xeb) |
| Hacking: The Art of Exploitation (2e) | Jon Erickson |
| Learning Linux Binary Analysis | [Ryan O'Neill](https://github.com/elfmaster) |
| Windows Internals Part 1 & 2 | [Pavel Yosifovich](https://github.com/zodiacon), [Mark Russinovich](https://github.com/markrussinovich), David Solomon, [Alex Ionescu](https://github.com/ionescu007), [Andrea Allievi](https://github.com/AaLl86) |
| Rootkits: Subverting the Windows Kernel | Greg Hoglund, Jamie Butler |
| Advanced Compiler Design and Implementation | Steven Muchnick |
| Engineering a Compiler | Keith Cooper, Linda Torczon |
| Practical IoT Hacking | [Fotios Chantzis](https://github.com/ithilgore), Ioannis Stais, Paulino Calderon, Evangelos Deirmentzoglou, Beau Woods |
| Inside the Android OS: Building, Customizing, Managing and Operating Android System Services | [G. Blake Meike](https://github.com/bmeike) |
| Malware Analysis and Detection Engineering | [Abhijit Mohanta](https://github.com/amohanta), Anoop Saldanha |
| Evasive Malware | [Kyle Cucci](https://github.com/d4rksystem) |
| Hacking Cryptography | [Kamran Khan](https://github.com/krkhan), [Bill Cox](https://github.com/waywardgeek) |
| Real-World Cryptography | David Wong |

**Honorable Mention**

[Microsoft Excel (Data Analysis ToolPak)](https://support.microsoft.com/en-us/office/use-the-analysis-toolpak-to-perform-complex-data-analysis-6c67ccf0-f4a9-487c-8dec-bdb5a2cefab6) When analyzing closed infrastructure or securing black-box systems, this exact process is called timing analysis or telemetry reverse engineering. Without source code, the Data Analysis ToolPak mathematically deconstructs how an application works on the backend by strictly observing its inputs and outputs.

---



## Install

```bash
pip install git+https://github.com/Ablation-Tool/ablation
```

---

## Requirements

- Python >= 3.10
- `capstone`, `numpy`, `lief`, `sentence-transformers`, `pyelftools`

---

## Responsible Use

Ablation is built for authorized security research. Use it only against systems you own or have explicit written permission to test. Running it against systems without authorization violates computer fraud laws in most jurisdictions. The author is not responsible for misuse.

---
