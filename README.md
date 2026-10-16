<img src="branding/ablation-1b-riveted-plate-wordmark-transparent-2560.png" width="520" alt="ABLATION">

![](https://komarev.com/ghpvc/?username=Ablation-Tool&color=grey) [![NIST SP 800-218](https://img.shields.io/badge/NIST%20SP%20800--218-SSDF-grey)](docs/standards-ablation.md) [![CISA Secure by Design](https://img.shields.io/badge/CISA-Secure%20by%20Design-grey)](docs/standards-ablation.md) [![MIL-HDBK-115C](https://img.shields.io/badge/MIL--HDBK--115C-Compliant-grey)](docs/standards-ablation.md) [![Sponsor Me](https://img.shields.io/badge/Sponsor%20Me-grey)](docs/SPONSORS.md)


Ablation is a self-contained reverse engineering framework.

It depends on neither legacy tools nor an MCP server, which removes the attack surface associated with MCP.

When used with Codex or Claude Code, it operates as an autonomous reverse engineering system.



---

<details>
<summary><strong>Claude Code Setup & Configuration</strong></summary>

### Quick Start

#### 1. Launch Session
```bash
cd ~/ablation && claude
```

#### 2. Set Model
```text
/model claude-sonnet-4-6
```
or
```text
/model claude-sonnet-4-5
```

#### 3. Define Objective
```text
/goal reverse engineer [whatever you want]
```

#### 4. Check Effort Level
Not sure what effort level to be set on? Ask inline without interrupting the main context:
```text
/btw What effort level should we be set on right now?
```

---

### Recommended Configuration (`/config`)

```text
Auto-compact                             true
Continue automatically at usage limit    true
Switch models when a message is flagged  Switch automatically
Show tips                                false
Claude-drafted feedback                  off
Reduce motion                            false
Thinking mode                            true
Fast mode (Opus 5.5)                     false
Prompt suggestions                       true
Session recap                            true
Rewind code (checkpoints)                true
Dynamic workflows                        true
Ultracode keyword trigger                false
Dynamic workflow size                    unrestricted
Artifacts                                false
Verbose output                           true
Terminal progress bar                    true
Show turn duration                       true
Time format                              auto
Default permission mode                  Manual
Worktree base ref                        fresh
Use auto mode during plan                true
Respect .gitignore in file picker        true
Skip the /copy picker                    false
Copy on select                           true
Auto-scroll                              true
Open agents view by default              false
← opens agents                           false
Auto-update channel                      disabled (config)
Theme                                    Dark mode (colorblind-friendly)
Local notifications                      Auto
Push when actions required               true
Push when Claude decides                 true
Output style                             Explanatory
Language                                 Default (English)
Editor mode                              normal
Question auto-continue timeout           never
Show last response in external editor    true
Show PR status footer                    true
Model                                    claude-sonnet-4-6
Auto-connect to IDE (external terminal)  true
Claude in Chrome enabled by default      true
Enable Remote Control for all sessions   false
Dialog expiry                            never
Messages from your other sessions        accept
```

</details>

---

![demo](demos/claude-code-demo.gif)

## Capabilities

<details>
<summary><strong>Core Analysis Engine</strong> </summary>

| Capability | |
|:---|:---|
| [**On-Demand Analysis**](docs/reference-modules/on-demand-analysis.md) | Loads in seconds because it only analyzes the code being examined. A 2 GB firmware image opens as fast as a small one because nothing is parsed until it is needed. |
| [**Binary Lifting**](docs/reference-modules/binary-lifter.md) | Translates machine code to readable pseudo-C across 31 architectures. All backends use per-register state machines seeded from each ISA's calling convention; ARM64 and x86-64 additionally carry taint annotations so data flow is visible in the lifted output. |
| [**Semantic Code Search**](docs/reference-modules/semantic-search.md) | Finds functions by describing what they do because stripped binaries have no symbols to search. Queries are scoped to the target binary so results return in under a second. |
| [**Hypothesis Engine**](docs/reference-modules/hypothesis-engine.md) | Tracks competing theories about what a function does and scores evidence against each one. Sessions persist across engagements so analysis resumes where it left off. |
| [**DAG Adapter Language**](docs/reference-modules/encoding-dag.md) | Every architecture shares the same analysis code path because each ISA compiles to a directed acyclic graph. Adding a new ISA takes one grammar file, so the architecture count grows without multiplying the codebase. |
| [**Entropy Mapper**](docs/reference-modules/entropy-mapper.md) | Maps binary sections by Shannon entropy to classify encrypted, compressed, and plaintext regions before analysis begins. Sections approaching H=8.0 indicate AES or compressed data so analysis effort concentrates on decrypted plaintext regions first. |

</details>

<details>
<summary><strong>Learning & Continuity</strong> </summary>

| Capability | |
|:---|:---|
| [**The Flywheel**](docs/reference-modules/flywheel.md) | Every confirmed finding replays as a search pattern on every future binary. A vulnerability confirmed on one vendor's firmware surfaces automatically when sweeping a different vendor's binary because confirmed findings are stored and replayed at engagement start. |
| [**Cross-Target Learning**](docs/reference-modules/cross-target-learning.md) | Extracts a transferable signature from every confirmed finding and stores it in the pattern library so the tool grows sharper across targets. The Flywheel replays those signatures; this module generates them. |
| [**KASAN-Oracle**](docs/workflows/kasan-oracle.md) | Scans a KASAN debug build first because debug builds expose control flow that stripping removes. Confirmed candidates from the debug build then validate against the stripped production binary, so the debug image acts as a ground-truth oracle rather than a secondary target. |

</details>

<details>
<summary><strong>Vulnerability Discovery & Validation</strong> </summary>

| Capability | |
|:---|:---|
| [**Taint Analysis**](docs/reference-modules/taint-analysis.md) | Follows network input through the call graph to security-sensitive sinks across 16 architectures. Library call sites do not stop the trace because register-level tracking resolves shared library stubs. |
| [**Cross-Library Analysis**](docs/reference-modules/taint-analysis.md) | Traces an argument across up to three shared library hops so taint paths that cross library boundaries reach their sink rather than stopping at the first call. |
| [**Pre-Authentication Exposure**](docs/reference-modules/preauth-exposure.md) | Finds every code path from the network entry point to a security-sensitive operation that runs before authentication. Manual review starts at the authentication boundary because the output is a reachability map, not a raw disassembly. |
| [**Sink Arg Classifier**](docs/reference-modules/sink-arg-classifier.md) | Classifies what value reaches each exec-class sink so a taint hit is either confirmed as externally controlled or eliminated as a constant before manual review begins. |
| [**Finding Validation**](docs/reference-modules/finding-validation.md) | Generates a working HTTP request that reproduces each confirmed finding at the protocol level. The request includes the expected response delta and CWE classification so a PSIRT submission arrives with working proof. |
| [**Compiler Defect Detection**](docs/reference-modules/compiler-defects.md) | Finds security defects that the compiler introduced through miscompilation. Optimizer defects that silently select the wrong comparison operand can produce hundreds of confirmed vulnerabilities across a single firmware image. |
| [**Source Code Auditing**](docs/reference-modules/source-audit.md) | Scores every source file by risk and batches the low-risk ones so manual review covers only the files most likely to contain vulnerabilities. |
| [**Cryptographic Analysis**](docs/reference-modules/crypto.md) | Recovers cryptographic key material directly from compiled firmware and audits TLS and JWT configurations, so cryptographic findings do not require source access or a decryption oracle. |
| [**Protocol FSM Extractor**](docs/reference-modules/proto-fsm.md) | Extracts the handshake state machine from network protocols in stripped ARM64 binaries using static loop and BSS state-variable analysis. Authentication state transitions become explicit without a running server or traffic capture. |
| [**BMP LSB Key Extractor**](docs/reference-modules/lsb-stego-extractor.md) | Recovers cryptographic key material hidden in BMP pixel LSBs using a Shamir-style Lagrange polynomial secret-sharing scheme. Firmware and APK packages that conceal keys in image assets are handled without prior knowledge of the encoding. |
| [**Format String Scanner**](docs/reference-modules/vuln-scanners.md) | Identifies format string vulnerabilities across the full printf family, syslog, and custom logging functions by tracing format argument provenance in x86-64 ELF binaries. Every call site where the format argument is not a .rodata string literal is a finding. |
| [**Heap Vulnerability Scanner**](docs/reference-modules/vuln-scanners.md) | Detects heap use-after-free, double-free, and overflow patterns in x86-64 and LoongArch64 binaries using a forward symbolic pass tracking pointer state across allocation and free operations. Static analysis produces heap findings in firmware that cannot be fuzz-tested. |
| [**SQL Injection Scanner**](docs/reference-modules/vuln-scanners.md) | Detects raw SQL injection in C/C++ binaries that call the MySQL C API or SQLite3 directly without a prepared-statement layer. Chains format-string builder analysis to SQL sink tracing so snprintf-to-mysql_query patterns surface that a format string scanner alone would miss. |
| [**RPC Server Analyzer**](docs/reference-modules/rpc-server-analyzer.md) | Enumerates Windows RPC server interfaces and flags those registered with RPC_C_AUTHN_LEVEL_NONE so any caller can reach the interface without credentials. Pairs with Windows PE Security Analysis for RPC coverage. |
| [**IOCTL Attack Surface**](docs/reference-modules/ioctl-attack-surface.md) | Maps the IOCTL dispatch surface of a Windows kernel driver and flags METHOD_NEITHER codes before manual review begins. An integer-overflow path from a user-supplied length to a kernel allocation is a HIGH finding. |
| [**Length Underflow Scanner**](docs/reference-modules/length-underflow.md) | Detects integer underflow in protocol parsers where a user-supplied length field has a fixed header size subtracted, wraps on truncation, and reaches a downstream allocation or copy without a prior bounds check. |
| [**Setuid Auth Oracle**](docs/reference-modules/setuid-auth-oracle-scanner.md) | Identifies setuid binaries that call getspnam and crypt without PAM mediation, exposing a brute-force oracle because exit-code-based result disclosure bypasses rate limiting that pam_tally2 and faillock enforce. Absence of pam_start in the PLT surfaces candidates without a taint run. |
| [**Lua Injection Analyzer**](docs/reference-modules/lua-injection-analyzer.md) | Detects unsanitized user-controlled strings passed to a Lua runtime via Python format operations. Built from two CRITICAL findings in FortiAnalyzer and FortiManager where no other scanner detected the class. |

</details>

<details>
<summary><strong>Specialized Recovery</strong> </summary>

| Capability | |
|:---|:---|
| [**C++ Vtable Reconstruction**](docs/reference-modules/cpp-vtable-reconstructor.md) | Recovers C++ virtual dispatch tables from stripped ELF binaries on any architecture and names each slot. A generated type-annotation script propagates slot names through every call site so the decompiler shows method names instead of function pointer offsets. |
| [**PPC32 GOT2 Resolver**](docs/reference-modules/ppc32-got2-resolver.md) | Resolves indirect calls in stripped GOT2-PIC PPC32 binaries at 98.6% coverage so taint paths through BCTRL stubs do not dead-end at the first unresolved call. |
| [**Dynamic Sandbox**](docs/reference-modules/dynamic-sandbox.md) | Executes leaf functions in an emulated sandbox to fingerprint behavior where static analysis alone cannot distinguish branches. |
| [**Firmware Extraction**](docs/reference-modules/firmware-analysis.md) | Decrypts vendor-encrypted firmware without a key because predictable patterns in inner partitions reveal it. Handles vendor-modified squashfs images including ARM64 BCJ-filtered variants. |
| [**Firmware Key Corpus**](docs/reference-modules/firmware-key-corpus.md) | Classifies recovered firmware keys against a cross-image family table. An anomalous key count flags a potential finding before decryption begins. |

</details>

<details>
<summary><strong>Platform & Runtime Support</strong> </summary>

| Capability | |
|:---|:---|
| [**Windows PE Security Analysis**](docs/reference-modules/windows-pe.md) | Audits a Windows PE binary for security weaknesses in a single pass. It checks CFG bypass exports, SafeSEH gaps, unauthenticated RPC endpoints, COM registration gaps, and kernel pool overflows so the attack surface is visible before manual review begins. |
| [**Windows Kernel Driver & BYOVD**](docs/reference-modules/kernel-drivers.md) | Classifies signed kernel drivers for BYOVD capability before they are deployed. Physical memory access, privilege token manipulation, and callback removal each trigger a finding. |
| [**Android / APK Analysis**](docs/reference-modules/android.md) | Maps the APK attack surface and ranks native libraries by risk before manual analysis begins. |
| [**HarmonyOS / ArkTS Analysis**](docs/reference-modules/harmonyos.md) | Analyzes HarmonyOS HAP packages and ArkTS bytecode so OpenHarmony targets can be assessed without source access. Surfaces exported abilities, permission grants, and native library attack surface before manual review begins. |
| [**Go Binary Reverse Engineering**](docs/workflows/go-binaries.md) | Recovers function names from stripped Go binaries because the runtime embeds a metadata table that survives stripping. |
| [**Erlang / BEAM Analysis**](docs/reference-modules/beam.md) | Decodes BEAM bytecode to readable pseudo-IR so Erlang and Elixir applications can be analyzed without source. High-risk import patterns and obfuscation indicators surface without executing the application. |
| [**MicroPython .mpy Lifter**](docs/reference-modules/mpy-lifter.md) | Lifts .mpy v6 bytecode to readable pseudo-Python so MicroPython firmware on ESP32, STM32, and CC13xx targets can be analyzed without source. Flags dangerous imports and machine-level memory access calls in the lifted output. |
| [**Game & Legacy RE**](docs/reference-modules/game-re.md) | Labels stripped game binary functions by engine so analysis starts at the game logic layer instead of the engine layer. Also handles PS3 Cell SPU and classic Mac OS PEF binaries. |
| [**PS3 SELF Decryptor**](docs/reference-modules/ps3-self-decryptor.md) | Decrypts PS3 SELF (Signed ELF) files to plain ELF because lief and BinaryContext reject SCE-format magic. Keyset detection is automatic from the key_rev field so no manual key lookup is needed. |
| [**MCP Server Security Scanner**](docs/reference-modules/mcp-tool-taint-scanner.md) | Scans MCP server source for unauthenticated endpoints, exec-class methods in allowed tool lists, and network-wide socket bindings. All three issue classes appeared in production MCP servers where no other scanner detected them. |
| [**LoongArch64**](docs/reference-modules/loongarch64.md) | The only public reverse engineering toolkit built specifically for LoongArch64. Every analysis phase works without architecture-specific workarounds. |
| [**nanoMIPS**](docs/reference-modules/nanomips.md) | Follows tainted data through nanoMIPS binaries interprocedurally, resolving branch targets and PLT stubs that no other public tool handles. |

</details>

<details>
<summary><strong>Automotive ECU Analysis</strong> </summary>

| Capability | |
|:---|:---|
| [**ECU Architecture Detector**](docs/reference-modules/ecu-arch-detector.md) | Identifies the ISA of a flat ECU ROM from raw bytes alone. PPC32, SH-2A, TriCore, RH850, V850, M68K, C28x, and M32R all produce recognizable structural signatures without symbols or file headers. |
| [**ROM Layout Analyzer**](docs/reference-modules/ecu-rom-layout-analyzer.md) | Splits a flat ROM into CODE, CALIBRATION, and IVT regions before analysis begins. The interrupt vector table is excluded from function discovery so taint trackers start from clean application code boundaries. |
| [**Calibration Parsers**](docs/reference-modules/ecu-cal-parsers.md) | Reads TunerPro XDF, ASAM A2L, RomRaider XML, open_damos, ConesCAN, and Nissan Pytrex definition files and injects human-readable table labels into BinaryContext. Every array in the ROM has a name when the taint tracker reaches it. |
| [**CAN DBC Parser**](docs/reference-modules/can-dbc-parser.md) | Reads CAN signal database files and makes message and signal definitions available during binary analysis. No other RE tool brings CAN signal context into the taint analysis pipeline. |
| [**ECU Security Access Scanner**](docs/reference-modules/ecu-security-access-scanner.md) | Audits UDS SecurityAccess implementations for weak seed generation, static keys, and bypassable challenge-response logic. Runs before taint analysis so weak authentication findings are confirmed before deeper code tracing begins. |
| [**TriCore Taint Analysis**](docs/reference-modules/tricore-taint-tracker.md) | Follows attacker-controlled data to security-sensitive sinks in Infineon TriCore AURIX TC1.6x ECU firmware using the GHS EABI and IAR EABI calling conventions. Automotive targets on TriCore receive the same interprocedural taint coverage as ARM64 and x86-64. |
| [**RH850 Taint Analysis**](docs/reference-modules/rh850-taint-tracker.md) | Follows attacker-controlled data through Renesas RH850 ECU firmware using the GHS CC-RH and IAR RH850 ABIs. Flat ROM support handles images shipped without ELF headers because most automotive RH850 firmware ships without them. |

</details>

<details>
<summary><strong>Workflow & Quality Gates</strong> </summary>

| Capability | |
|:---|:---|
| [**Version Diffing**](docs/workflows/cross-version.md) | Checks whether the logic changed, not whether the file changed, so a cosmetic recompile cannot hide an unpatched vulnerability. |
| [**Kernel Module Subsystem Classifier**](docs/reference-modules/kernel-module-subsystem-classifier.md) | Classifies a Linux kernel module by its source tree path to determine attack surface before analysis begins. Network-reachable modules surface first so manual review starts at the highest-risk code. |
| [**Module Quality Gate**](docs/reference-modules/forge.md) | FORGE audits every user-written module before it can be stored, so local extensions meet the same standard as the modules that ship with Ablation. Every HIGH and CRITICAL finding is tagged with the pipeline stage where it would surface without the audit, from a free static-check catch at develop time to an 18x-cost find in production. |
| [**Coverage Gate**](docs/standards-ablation.md) | The taint engine requires 85% statement coverage on every commit, so a regression in taint logic fails the test suite before it reaches a firmware engagement. |
| [**YARA Rule Generation**](docs/reference-modules/yara-generator.md) | Synthesizes YARA detection rules from PE and ELF scanner findings so confirmed vulnerability signatures are immediately deployable in detection pipelines without manual rule authoring. |

</details>

<details>
<summary><strong>30 Decompilers</strong></summary>

<details>
<summary><strong>Native CPUs</strong> </summary>

| ISA | Variants |
|---|---|
| [**x86**](docs/reference-modules/binary-lifter.md) | x86-32 · x86-64 |
| [**ARM**](docs/reference-modules/binary-lifter.md) | ARM-32 · ARM-64 · Thumb |
| [**MIPS**](docs/reference-modules/binary-lifter.md) | MIPS-32 · [nanoMIPS](docs/reference-modules/nanomips.md) · MIPS-64 |
| [**PowerPC**](docs/reference-modules/ppc32-taint-tracker.md) | PPC-32 · PPC-64 · [VLE](docs/reference-modules/ecu-vle-decoder.md) · [PPC476 Book E](docs/reference-modules/ppc476-lifter.md) |
| [**RISC-V**](docs/reference-modules/binary-lifter.md) | RV32 · RV64 · [HiSilicon ext](docs/reference-modules/hisi-rv32-ext.md) |
| [**ARC**](docs/reference-modules/binary-lifter.md) | ARC EM/HS |
| [**LoongArch**](docs/reference-modules/loongarch64.md) | LoongArch64 |
| [**Intel MCS**](docs/reference-modules/isa-8051.md) | 8051 |

</details>

<details>
<summary><strong>Automotive ECUs</strong> </summary>

| ISA | Variants |
|---|---|
| [**V850 / RH850**](docs/reference-modules/rh850-taint-tracker.md) | V850-32 · RH850 |
| [**Renesas SH**](docs/reference-modules/binary-lifter-sh2a.md) | SH-2A |
| [**Motorola**](docs/reference-modules/ecu-m68k-decoder.md) | M68K / CPU32 · [MC88100](docs/reference-modules/m88k-decoder.md) |
| [**Infineon**](docs/reference-modules/tricore-taint-tracker.md) | TriCore TC1.6x |
| [**TI DSP**](docs/reference-modules/ecu-c28x-decoder.md) | TMS320C28x |

</details>

<details>
<summary><strong>VMs & Runtimes</strong> </summary>

| ISA | Variants |
|---|---|
| [**DEX**](docs/reference-modules/android.md) | Dalvik · ART |
| [**ARK**](docs/reference-modules/harmonyos.md) | ArkTS |
| [**MicroPython**](docs/reference-modules/mpy-lifter.md) | .mpy v6 |

</details>

</details>

## Project Background

<details>
<summary><strong>Real-World Results</strong></summary>

## Real-World Results
Ablation has been used to analyze production firmware and kernel drivers from Cisco, Fortinet, TencentOS, Huawei, and more.

Following coordinated disclosure, the Cisco Product Security Incident Response Team (PSIRT) adopted Ablation for internal vulnerability triage and continues to use it to evaluate ongoing disclosure reports. Cisco Adaptive Security Appliance (ASA) LINA is among the artifacts analyzed, with findings submitted through CERT/CC VINCE.

| CVE | Product | Title | CVSS |
|---|---|---|---|
| [CVE‑2026‑76420](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fmc2-multivulns-HXgcqRG) | Secure Firewall Management Center (FMC) | Peer Impersonation | 9.0 Critical |
| [CVE‑2026‑76412](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fmc2-multivulns-HXgcqRG) | Secure Firewall Management Center (FMC) | Privilege Escalation to root | 8.5 High |
| [CVE‑2026‑76413](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fmc2-multivulns-HXgcqRG) | Secure Firewall Management Center (FMC) | Single Sign-On Token Forgery | 8.5 High |
| [CVE‑2026‑76447](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-multiauth-bypass-sgD2HbL4) | Identity Services Engine (ISE) | OCSP Responder Authentication Bypass | 5.3 Medium |



---

</details>

<details>
<summary><strong>Acknowledgments</strong></summary>

## Acknowledgments
The code couldn't exist without their ideas. Though no code was written by these authors, doctors, and engineers their work has direct influence on the production of code that makes Ablation what it is.

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

</details>

<details>
<summary><strong>Demonstrations</strong></summary>

### Ablation in Action

![Ablation in Action](demos/Ablation-In-Action-01.gif)

### How to Use Ablation

![How to Use Ablation](demos/How-To-Use-Ablation.gif)

### Learn as You RE

![Learn as You RE](demos/Learn-As-You-RE.gif)

</details>

## Getting Started

<details>
<summary><strong>Install</strong></summary>

## Install

```bash
pip install ablation-tool
```

---

</details>

<details>
<summary><strong>Requirements</strong></summary>

## Requirements

- Python >= 3.10
- `capstone`, `numpy`, `lief`, `sentence-transformers`, `pyelftools`

---

</details>

<details>
<summary><strong>Responsible Use</strong></summary>

## Responsible Use

Ablation is built for authorized security research. Use it only against systems you own or have explicit written permission to test. Running it against systems without authorization violates computer fraud laws in most jurisdictions. The author is not responsible for misuse.

---

</details>

<details>
<summary><strong>Standards</strong></summary>

## Standards

**[NIST SP 800-218](https://csrc.nist.gov/pubs/sp/800/218/final)**

This defines how software should be built, organized around four practice areas: preparing the development environment, protecting the codebase from unauthorized changes, writing software with security built into every layer, and responding when vulnerabilities surface after release.

What this means for Ablation in practice is a mandatory ten-section security audit on every module before it touches the repository.

The audit covers input validation, memory handling, integer safety, error handling, concurrency, dependency security, injection prevention, secrets handling, logging, and residual risks.

No module is committed without passing it.

Taint trackers, which are the modules that matter most if they get something wrong, carry an additional requirement: 85% statement coverage enforced by a hard gate in the test suite, verified against byte-exact synthetic instruction sequences that test ABI register behavior, not just whether the code runs without crashing.

Dependencies are pinned with exact hashes and scanned weekly for known CVEs.

**[CISA Secure by Design](https://www.cisa.gov/securebydesign)**

CISA asks software manufacturers to commit to three things: take ownership of the security outcomes of the people who rely on the software, be transparent about its limitations, and treat security as a requirement rather than a recommendation.

For a RE framework, taking ownership of security outcomes has a specific meaning.

A taint tracker that misses a vulnerability does not just produce a wrong answer.

It produces a result someone may act on as evidence the binary is clean.

That is why a false negative in any Ablation taint tracker is classified as a CRITICAL defect.

Every tracker ships with a documented known-anomalies file describing the exact conditions under which it can produce false negatives, so a researcher knows when to apply manual verification on top of the automated result.

The precommit gate is not advisory. No code enters the repository without passing it.

**[MIL-HDBK-115C](https://www.nsa.gov)**

The US Department of Defense handbook for reverse engineering methodology. 

It defines four phases:

**Phase 1.** Every engagement starts with a session file recording the target description, artifact hash, tool selection, and documentation plan before any analysis runs. The rule that semantic search runs before manual disassembly maps to the following phase.

**Phase 2** Requires characterizing a binary at the function level before doing detailed trace work. The DynamicSandbox covers the following.

**Phase 3.** The structured retrospective written at the close of every completed project maps to the final phase.

**Phase 4.** The standards document tracks 29 specific requirements drawn from all three frameworks. All 29 are met.

</details>

<details>
<summary><strong>Contact</strong></summary>

## Contact

Feel free to contact me if you have any questions, ideas, complaints or bugs.

📧 ablation@nuclide-research.com  
𝕏 [@showxlate](https://x.com/showxlate)

</details>

---

---

## All Capabilities

<details>
<summary><strong>Core analysis engine</strong></summary>

| Capability | |
|:---|:---|
| [**On-Demand Analysis**](docs/reference-modules/on-demand-analysis.md) <br> [code](ablation/analyzers/binary_context.py) | Cached binary context and targeted function analysis; retain symbols, imports, cross-references and analyst names between sessions. |
| [**Binary Lifting**](docs/reference-modules/binary-lifter.md) <br> [code](ablation/analyzers/binary_lifter.py) | Native instructions to pseudo-C using architecture-specific register state and calling conventions; support varies by backend. |
| [**Semantic Code Search**](docs/reference-modules/semantic-search.md) <br> [code](ablation/analyzers/semantic_search.py) | Search functions by behavioral descriptions; normalize assembly, embed descriptions and rank semantic similarity. |
| [**Hypothesis Engine**](docs/reference-modules/hypothesis-engine.md) <br> [code](ablation/analyzers/hypothesis_engine.py) | Persist competing explanations, collect evidence, rank probes and update confidence. |
| [**DAG Adapter Language**](docs/reference-modules/encoding-dag.md) <br> [code](ablation/analyzers/encoding_dag.py) | Define fixed-width instruction bitfields, round-trip encodings, semantic operations and dataflow edges through EncodingDAG. |
| [**Entropy Mapper**](docs/reference-modules/entropy-mapper.md) <br> [code](ablation/analyzers/entropy_mapper.py) | Sliding-window Shannon entropy, region classification and transition detection to guide unpacking and analysis. |

</details>

<details>
<summary><strong>Learning and continuity</strong></summary>

| Capability | |
|:---|:---|
| [**The Flywheel**](docs/reference-modules/flywheel.md) <br> [code](ablation/analyzers/pattern_library.py) · [code](ablation/analyzers/finding_registry.py) | Replay stored confirmed finding descriptions and successful semantic queries against later binaries. |
| [**Cross-Target Learning**](docs/reference-modules/cross-target-learning.md) <br> [code](ablation/analyzers/pattern_library.py) · [code](ablation/analyzers/finding_registry.py) | Persist transferable finding descriptions, embeddings and search patterns for reuse across products and vendors. |
| [**KASAN-Oracle**](docs/workflows/kasan-oracle.md) <br> [code](ablation/analyzers/loongarch_decoder_v2.py) | Workflow for deriving candidates from instrumented/debug builds and checking corresponding production code; includes instrumentation-aware decoding. |

</details>

<details>
<summary><strong>Vulnerability discovery and validation</strong></summary>

| Capability | |
|:---|:---|
| [**Taint Analysis**](docs/reference-modules/taint-analysis.md) <br> [code](ablation/analyzers/taint_tracker.py) · [code](ablation/analyzers/taint_tracker_arm64.py) | Source-to-sink register/dataflow tracking, with architecture-specific intraprocedural, interprocedural and flow-sensitive implementations. |
| [**Cross-Library Analysis**](docs/reference-modules/taint-analysis.md) <br> [code](ablation/analyzers/cross_binary_taint.py) · [code](ablation/analyzers/lib_graph.py) | Resolve imports and exports across a firmware library set and propagate supported argument taint across library boundaries. |
| [**Pre-Authentication Exposure**](docs/reference-modules/preauth-exposure.md) <br> [code](ablation/analyzers/preauth_route_auditor.py) | Recover supported Flatui route/auth-wrapper structures, associate handlers and identify pre-authentication handlers with sensitive sinks. |
| [**Sink Arg Classifier**](docs/reference-modules/sink-arg-classifier.md) <br> [code](ablation/analyzers/sink_arg_classifier.py) | Classify command arguments as constant, formatted constant, argument-propagated or unknown before deeper tracing. |
| [**Finding Validation**](docs/reference-modules/finding-validation.md) <br> [code](modules/path_solver.py) · [code](ablation/analyzers/finding_registry.py) | Bounded x86-64 symbolic path solving produces entry-register constraints/models; a registry stores findings and submission metadata. It does not establish automatic HTTP reproduction for every find... |
| [**Compiler Defect Detection**](docs/reference-modules/compiler-defects.md) <br> [code](ablation/analyzers/loongarch64_max_not_min_scanner.py) · [code](ablation/analyzers/compiler_security_gate.py) | Detect the implemented LoongArch64 min/max miscompilation pattern and run supported security scans on compiler output. |
| [**Source Code Auditing**](docs/reference-modules/source-audit.md) <br> [code](ablation/analyzers/source_audit_compressor.py) · [code](ablation/analyzers/source_taint_tracker.py) | Ingest repositories, profile/rank files, map entry points and sinks, trace source paths and support review coverage accounting. |
| [**Cryptographic Analysis**](docs/reference-modules/crypto.md) <br> [code](modules/crypto_audit.py) · [code](ablation/analyzers/xor_solver.py) | Key/secret discovery, repeating-XOR recovery, crypto implementation fingerprinting and JWT/SAML/TLS posture checks. |
| [**Protocol FSM Extractor**](docs/reference-modules/proto-fsm.md) <br> [code](modules/proto_fsm.py) | Infer an ARM64 protocol state graph from BSS state accesses and a selected handshake-function cluster; includes MMTLS-oriented assumptions. |
| [**BMP LSB Key Extractor**](docs/reference-modules/lsb-stego-extractor.md) <br> [code](ablation/analyzers/lsb_stego_extractor.py) | Read BMP pixel least-significant bits and reconstruct keys for the implemented seed/polynomial encoding scheme. |
| [**Format String Scanner**](docs/reference-modules/vuln-scanners.md) <br> [code](ablation/analyzers/format_string_scanner.py) | Flag supported printf-family, syslog and logging call sites with potentially unsafe format-argument provenance in x86-64 ELF. |
| [**Heap Vulnerability Scanner**](docs/reference-modules/vuln-scanners.md) <br> [code](ablation/analyzers/heap_vuln_scanner.py) · [code](modules/heap_uaf_scanner.py) | x86-64 allocation-overflow, use-after-free, double-free and off-by-one/pointer-state heuristics; LoongArch64 allocation-arithmetic overflow scanning. |
| [**SQL Injection Scanner**](docs/reference-modules/vuln-scanners.md) <br> [code](ablation/analyzers/sql_sink_scanner.py) | Trace formatted query construction into supported MySQL C API and SQLite sinks in native binaries. |
| [**RPC Server Analyzer**](docs/reference-modules/rpc-server-analyzer.md) <br> [code](ablation/analyzers/rpc_server_analyzer.py) | Recover Windows RPC interface/endpoint indicators and examine supported registration/authentication patterns. |
| [**IOCTL Attack Surface**](docs/reference-modules/ioctl-attack-surface.md) <br> [code](modules/ioctl_attack_surface.py) | Decode driver IOCTLs and inspect METHOD_NEITHER, buffer-length handling, probe APIs and allocation/copy patterns. |
| [**Length Underflow Scanner**](docs/reference-modules/length-underflow.md) <br> [code](ablation/analyzers/length_underflow.py) | Find supported x86-64 parser patterns where subtracting a header size from a narrow length can wrap before allocation or copying. |
| [**Setuid Auth Oracle**](docs/reference-modules/setuid-auth-oracle-scanner.md) <br> [code](modules/setuid_auth_oracle_scanner.py) | Identify raw shadow-password validation/import patterns without PAM mediation as authentication-oracle candidates. |
| [**Lua Injection Analyzer**](docs/reference-modules/lua-injection-analyzer.md) <br> [code](ablation/analyzers/lua_injection_analyzer.py) | Detect Python strings formatted into Lua source before execution through supported Lua interfaces. |

</details>

<details>
<summary><strong>Specialized recovery</strong></summary>

| Capability | |
|:---|:---|
| [**C++ Vtable Reconstruction**](docs/reference-modules/cpp-vtable-reconstructor.md) <br> [code](modules/cpp_vtable_reconstructor.py) | Recover ELF virtual tables, name slots from available evidence and generate annotations for virtual dispatch analysis. |
| [**PPC32 GOT2 Resolver**](docs/reference-modules/ppc32-got2-resolver.md) <br> [code](modules/ppc32_got2_resolver.py) | Recover GOT2 bases and resolve supported indirect BCTRL targets in stripped PPC32 big-endian PIC binaries. |
| [**Dynamic Sandbox**](docs/reference-modules/dynamic-sandbox.md) <br> [code](ablation/analyzers/dynamic_sandbox.py) | Probe ARM64 or x86-64 leaf functions in Unicorn, capture return/register state and writes, and compare behavioral signatures. |
| [**Firmware Extraction**](docs/reference-modules/firmware-analysis.md) <br> [code](ablation/analyzers/fortios_firmware_extractor.py) · [code](ablation/analyzers/firmware_container_key_extractor.py) | Format/vendor-specific container parsing, supported Fortinet XOR/key recovery and inner-partition decryption, plus selected filesystem extraction. |
| [**Firmware Key Corpus**](docs/reference-modules/firmware-key-corpus.md) <br> [code](ablation/analyzers/fortigate_cert_key_scanner.py) · [code](ablation/analyzers/fortibuild_track_classifier.py) | Fingerprint recovered Fortinet certificate keys, compare known key families and classify expected keys by firmware build track. |

</details>

<details>
<summary><strong>Platform and runtime support</strong></summary>

| Capability | |
|:---|:---|
| [**Windows PE Security Analysis**](docs/reference-modules/windows-pe.md) <br> [code](sweeps/pe_sweep.py) · [code](ablation/analyzers/cfg_bypass_detector.py) | PE sweeps and dedicated CFG, SEH, RPC, COM, ETW, symbol and pool-allocation analyses. |
| [**Windows Kernel Driver & BYOVD**](docs/reference-modules/kernel-drivers.md) <br> [code](ablation/analyzers/kernel_driver_analyzer.py) · [code](ablation/analyzers/byovd_detector.py) | Inspect driver imports, IOCTLs, callbacks, pool operations and dangerous primitives; rank BYOVD-related capability indicators. |
| [**Android / APK Analysis**](docs/reference-modules/android.md) <br> [code](ablation/core/apk_parser.py) · [code](ablation/analyzers/dex_analyzer.py) | Parse APK/AXML/DEX, review manifest exposure and dangerous APIs, inventory native libraries and prioritize findings. |
| [**HarmonyOS / ArkTS Analysis**](docs/reference-modules/harmonyos.md) <br> [code](ablation/analyzers/abc_parser.py) · [code](ablation/analyzers/abc_disasm.py) | Parse extracted Ark ABC bytecode, enumerate classes/methods/strings, disassemble and produce JavaScript-like pseudocode. |
| [**Go Binary Reverse Engineering**](docs/workflows/go-binaries.md) <br> [code](ablation/analyzers/go_pclntab.py) · [code](modules/go_binary_re.py) | Recover supported pclntab function metadata, analyze stripped Go ELF/Mach-O binaries and inspect garble-obfuscated layouts. |
| [**Erlang / BEAM Analysis**](docs/reference-modules/beam.md) <br> [code](ablation/analyzers/beam_context.py) | Read BEAM module/export/import/atom data, lift supported bytecode, scan risky imports and compare module sets. |
| [**MicroPython .mpy Lifter**](docs/reference-modules/mpy-lifter.md) <br> [code](modules/mpy_lifter.py) | Parse supported .mpy v6 files, lift bytecode to pseudo-Python and flag dangerous imports/calls and direct memory access. |
| [**Game & Legacy RE**](docs/reference-modules/game-re.md) <br> [code](ablation/analyzers/engine_pattern_library.py) · [code](modules/spu_disassembler.py) | Label known game-engine code and provide selected PS3/Cell, classic Mac, old Windows/DOS and other legacy-format tools. |
| [**PS3 SELF Decryptor**](docs/reference-modules/ps3-self-decryptor.md) <br> [code](ablation/analyzers/ps3_self_decryptor.py) | Decrypt supported Signed ELF containers using registered keysets, detect key revision and emit a loadable ELF. |
| [**MCP Server Security Scanner**](docs/reference-modules/mcp-tool-taint-scanner.md) <br> [code](ablation/analyzers/mcp_tool_taint_scanner.py) | Scan Python/JavaScript/TypeScript MCP source for exposed bindings, missing-authentication patterns and dangerous tool methods. |
| [**LoongArch64**](docs/reference-modules/loongarch64.md) <br> [code](ablation/analyzers/loongarch_decoder.py) · [code](ablation/analyzers/taint_tracker_loongarch64.py) | Dedicated decoding, CFG/dataflow, lifting, taint, syscall classification and DWARF/CFI/BTF function-boundary recovery. |
| [**nanoMIPS**](docs/reference-modules/nanomips.md) <br> [code](ablation/analyzers/nanomips_decoder.py) · [code](ablation/analyzers/taint_tracker_nanomips.py) | Variable-width decoding, function/frame discovery and supported intra/interprocedural taint analysis. |

</details>

<details>
<summary><strong>Automotive ECU analysis</strong></summary>

| Capability | |
|:---|:---|
| [**ECU Architecture Detector**](docs/reference-modules/ecu-arch-detector.md) <br> [code](ablation/analyzers/ecu_arch_detector.py) | Rank candidate instruction sets for raw ECU ROMs using reset vectors, signatures and structural heuristics. |
| [**ROM Layout Analyzer**](docs/reference-modules/ecu-rom-layout-analyzer.md) <br> [code](ablation/analyzers/ecu_rom_layout_analyzer.py) | Classify raw-ROM regions as code, calibration, interrupt vectors or erased data and identify application-code regions. |
| [**Calibration Parsers**](docs/reference-modules/ecu-cal-parsers.md) <br> [code](ablation/analyzers/ecu_xdf_parser.py) · [code](ablation/analyzers/ecu_a2l_parser.py) | Parse TunerPro XDF, ASAM A2L, RomRaider XML, open_damos, Conescan and Nissan/Pytrex definitions into calibration tables and labels. |
| [**CAN DBC Parser**](docs/reference-modules/can-dbc-parser.md) <br> [code](modules/can_dbc_parser.py) | Parse CAN message/signal definitions, bit layouts, value tables and comments for analysis context. |
| [**ECU Security Access Scanner**](docs/reference-modules/ecu-security-access-scanner.md) <br> [code](ablation/analyzers/ecu_security_access_scanner.py) | Fingerprint the implemented static-seed UDS/KWP2000 SecurityAccess patterns in M68K/CPU32 and PPC32 ROMs. |
| [**TriCore Taint Analysis**](docs/reference-modules/tricore-taint-tracker.md) <br> [code](ablation/analyzers/taint_tracker_tricore.py) | TriCore ECU source-to-sink analysis with supported GHS/IAR ABI and flat-image handling. |
| [**RH850 Taint Analysis**](docs/reference-modules/rh850-taint-tracker.md) <br> [code](ablation/analyzers/taint_tracker_rh850.py) | RH850 ECU register/argument taint tracking with supported ABI and flat-ROM analysis paths. |

</details>

<details>
<summary><strong>Workflow and quality gates</strong></summary>

| Capability | |
|:---|:---|
| [**Version Diffing**](docs/workflows/cross-version.md) <br> [code](ablation/analyzers/version_delta.py) · [code](ablation/analyzers/dtw_matcher.py) | Match corresponding functions, follow identities across releases and localize instruction-category changes. |
| [**Kernel Module Subsystem Classifier**](docs/reference-modules/kernel-module-subsystem-classifier.md) <br> [code](ablation/analyzers/kernel_module_subsystem_classifier.py) | Infer a Linux module's subsystem and attack-surface priority from its source-tree/install path. |
| [**Module Quality Gate**](docs/reference-modules/forge.md) <br> [code](ablation/analyzers/forge.py) | FORGE audit records, severity-based gates and local-module registration/loading; audit behavior depends on configured analysis. |
| [**Coverage Gate**](docs/standards-ablation.md) <br> [code](pyproject.toml) · [code](.github/workflows/ci.yml) | Configured 85% statement-coverage threshold for the selected labeled taint-engine modules; not a whole-repository coverage guarantee. |
| [**YARA Rule Generation**](docs/reference-modules/yara-generator.md) <br> [code](ablation/core/yara_generator.py) | Generate YARA text from supported findings/strings and supplied technique templates. |

</details>

<details>
<summary><strong>Binary loading, discovery and navigation</strong></summary>

| Capability | |
|:---|:---|
| [**Binary format and platform identification**](docs/INDEX.md) <br> [code](ablation/core/binary_parser.py) · [code](ablation/core/elf_parser.py) | Detect ELF/PE/Mach-O and inspect file/OS/architecture metadata through the appropriate parser. |
| [**ELF internals and hardening**](docs/INDEX.md) <br> [code](ablation/core/binary_parser.py) · [code](ablation/core/elf_parser.py) | Parse ELF32/64 program/section headers, symbols, dependencies, RPATH/RUNPATH and GOT/PLT; inspect NX, PIE, RELRO and canary indicators. |
| [**PE internals and indicators**](docs/INDEX.md) <br> [code](ablation/core/binary_parser.py) · [code](ablation/core/elf_parser.py) | Inspect sections, imports, strings, resources and selected malware/anti-debug/IOC patterns. |
| [**Mach-O internals**](docs/INDEX.md) <br> [code](ablation/core/binary_parser.py) · [code](ablation/core/elf_parser.py) | Inspect load commands, segments, dylib dependencies and code-signing information. |
| [**Call and string cross-references**](docs/INDEX.md) <br> [code](ablation/analyzers/binary_context.py) · [code](ablation/analyzers/xref_graph.py) | Find callers, callees, referenced strings, functions referencing strings, containing functions, exports and import names. |
| [**Persistent analysis context**](docs/INDEX.md) <br> [code](ablation/analyzers/binary_context.py) · [code](ablation/analyzers/xref_graph.py) | Cache binary metadata and cross-reference structures and reload analyst naming overlays. |
| [**Native-library inventory**](docs/INDEX.md) <br> [code](ablation/analyzers/binary_context.py) · [code](ablation/analyzers/xref_graph.py) | Rank a directory of ELF libraries by architecture, functions, exports, JNI presence and security-relevant strings. |
| [**Stripped function discovery**](docs/INDEX.md) <br> [code](ablation/analyzers/arm32_function_scanner.py) · [code](ablation/analyzers/static_elf32_func_start_scanner.py) | Recover candidate entries from architecture-specific prologues, calls, reset vectors and available metadata. |
| [**Flat-ROM function discovery**](docs/INDEX.md) <br> [code](ablation/analyzers/arm32_function_scanner.py) · [code](ablation/analyzers/static_elf32_func_start_scanner.py) | Harvest call targets and prologues without ELF headers, using the supported ECU decoder/layout paths. |
| [**i386 absolute cross-references**](docs/INDEX.md) <br> [code](ablation/analyzers/i386_absolute_xref_scanner.py) · [code](ablation/analyzers/dwarf_loongarch64.py) | Find x86-32 string/data references encoded as absolute immediates. |
| [**Debug metadata recovery**](docs/INDEX.md) <br> [code](ablation/analyzers/i386_absolute_xref_scanner.py) · [code](ablation/analyzers/dwarf_loongarch64.py) | Recover LoongArch function boundaries from .eh_frame, DWARF and BTF where available. |
| [**Swift symbol demangling**](docs/INDEX.md) <br> [code](ablation/analyzers/i386_absolute_xref_scanner.py) · [code](ablation/analyzers/dwarf_loongarch64.py) | Best-effort Swift symbol decoding with an optional swift-demangle fallback. |

</details>

<details>
<summary><strong>Disassembly, graphs and symbolic analysis</strong></summary>

| Capability | |
|:---|:---|
| [**Streaming and windowed disassembly**](docs/INDEX.md) <br> [code](ablation/core/disasm_engine.py) · [code](ablation/analyzers/window_analyzer.py) | Produce instruction streams or annotated address windows with calls, strings and function boundaries. |
| [**Single-function profiling**](docs/INDEX.md) <br> [code](ablation/core/disasm_engine.py) · [code](ablation/analyzers/window_analyzer.py) | Combine callee names, strings, argument values and sink flags in one function report. |
| [**Optional angr-backed analysis**](docs/INDEX.md) <br> [code](ablation/core/disasm_engine.py) · [code](ablation/analyzers/window_analyzer.py) | Extended disassembly engine supports caller/xref resolution and register/block dataflow via angr. |
| [**Control-flow graph construction**](docs/INDEX.md) <br> [code](ablation/analyzers/dataflow_engine.py) · [code](ablation/analyzers/structurizer.py) | Architecture-specific block/edge construction, branch targets, return handling and selected delay-slot semantics. |
| [**Generic dataflow worklist**](docs/INDEX.md) <br> [code](ablation/analyzers/dataflow_engine.py) · [code](ablation/analyzers/structurizer.py) | Monotone-framework propagation with supported lattice/state joins across a CFG. |
| [**Constant propagation and reaching definitions**](docs/INDEX.md) <br> [code](ablation/analyzers/dataflow_engine.py) · [code](ablation/analyzers/structurizer.py) | Track definitions/constants and perform sparse conditional constant propagation. |
| [**Dominators and loop analysis**](docs/INDEX.md) <br> [code](ablation/analyzers/dataflow_engine.py) · [code](ablation/analyzers/structurizer.py) | Build dominator/post-dominator information and identify natural loops. |
| [**Structured control-flow recovery**](docs/INDEX.md) <br> [code](ablation/analyzers/dataflow_engine.py) · [code](ablation/analyzers/structurizer.py) | Render supported CFG regions as sequences, conditions, loops, breaks, continues and returns. |
| [**Call-argument annotation**](docs/INDEX.md) <br> [code](ablation/analyzers/reg_annotator.py) · [code](ablation/analyzers/arm32_reg_annotator.py) | Forward symbolic register propagation for supported x86-64/ARM32 call sites. |
| [**Interprocedural argument provenance**](docs/INDEX.md) <br> [code](ablation/analyzers/reg_annotator.py) · [code](ablation/analyzers/arm32_reg_annotator.py) | Seed callees with caller values and follow supported argument chains across functions. |
| [**Lightweight ARM32 symbolic execution**](docs/INDEX.md) <br> [code](ablation/analyzers/reg_annotator.py) · [code](ablation/analyzers/arm32_reg_annotator.py) | Track argument/buffer relationships and protocol field writes without an SMT solver. |
| [**ARM64 symbolic slicing**](docs/reference-modules/core.md) <br> [code](modules/sse_slicer.py) · [code](modules/arm64_global_tracker.py) | Backward/forward structured-expression slicing for memory addresses and stores. |
| [**Global-symbol and BSS tracking**](docs/reference-modules/core.md) <br> [code](modules/sse_slicer.py) · [code](modules/arm64_global_tracker.py) | Resolve named global/GOT relationships and find state, buffer or decrypt-loop accesses. |
| [**Call-site backward slicing**](docs/reference-modules/core.md) <br> [code](modules/sse_slicer.py) · [code](modules/arm64_global_tracker.py) | Recover x0-x7 symbolic values at selected ARM64 calls. |
| [**Interprocedural field-writer discovery**](docs/reference-modules/core.md) <br> [code](modules/sse_slicer.py) · [code](modules/arm64_global_tracker.py) | Locate functions writing a selected field when its structure pointer crosses call boundaries. |

</details>

<details>
<summary><strong>Instruction, ABI and labeled-taint APIs</strong></summary>

| Capability | |
|:---|:---|
| [**Instruction-stream import and normalization**](docs/INDEX.md) <br> [code](ablation/analyzers/insn_x86.py) · [code](ablation/analyzers/insn_arm32.py) | Convert supported Capstone, objdump or hand-written listings into common per-ISA instruction/operand objects; normalize aliases and x86 syntax. |
| [**Calling-convention and syscall models**](docs/INDEX.md) <br> [code](ablation/analyzers/isa_x86.py) · [code](ablation/analyzers/isa_arm32.py) | Encode supported register aliases, argument/return registers, caller/callee saves and syscall conventions separately from decoders. |
| [**Named taint sources and bounds**](docs/INDEX.md) <br> [code](ablation/analyzers/taint_tracker_x86_labeled.py) · [code](ablation/analyzers/taint_tracker_arm32_labeled.py) | Preserve source labels and supported bounds on attacker-controlled contributions rather than a single boolean taint flag. |
| [**Frame, pointer and memory-range state**](docs/INDEX.md) <br> [code](ablation/analyzers/taint_tracker_x86_labeled.py) · [code](ablation/analyzers/taint_tracker_arm32_labeled.py) | Track supported frame slots, spilled pointers, constants, memory ranges and register aliases across instruction streams. |
| [**Configurable taint reporting**](docs/INDEX.md) <br> [code](ablation/analyzers/taint_tracker_x86_labeled.py) · [code](ablation/analyzers/taint_tracker_arm32_labeled.py) | Policies control supported branch, memory-address, return-address, syscall-argument and bounded-index findings. |
| [**CFG fixpoint dataflow**](docs/INDEX.md) <br> [code](ablation/analyzers/analysis_x86.py) · [code](ablation/analyzers/analysis_arm32.py) | Iterate supported per-architecture state joins across blocks and loops; separate from the binary-path scanners' linear/BFS modes. |
| [**Instrumentation-noise removal**](docs/INDEX.md) <br> [code](ablation/analyzers/loongarch_decoder_v2.py) · [code](ablation/analyzers/syscall_loongarch64.py) | Tag/filter supported LoongArch KASAN/KCOV call and shadow-address idioms using instrumentation symbols or addresses. |
| [**LoongArch syscall labeling**](docs/INDEX.md) <br> [code](ablation/analyzers/loongarch_decoder_v2.py) · [code](ablation/analyzers/syscall_loongarch64.py) | Classify supported Linux syscall numbers, labels and security-relevant categories. |

</details>

<details>
<summary><strong>Semantic matching and retained knowledge</strong></summary>

| Capability | |
|:---|:---|
| [**Single/multi-binary corpus building**](docs/INDEX.md) <br> [code](ablation/analyzers/corpus_builder.py) · [code](ablation/analyzers/func_id_db.py) | Populate a function-identity database with descriptions, product/version metadata and inferred records. |
| [**Function identity database**](docs/INDEX.md) <br> [code](ablation/analyzers/corpus_builder.py) · [code](ablation/analyzers/func_id_db.py) | Store function names, roles, signatures, structures and call chains across binary versions. |
| [**Analyst naming registry**](docs/INDEX.md) <br> [code](ablation/analyzers/corpus_builder.py) · [code](ablation/analyzers/func_id_db.py) | Persist, bulk-update and reload confirmed function names per binary. |
| [**Signature-based auto-naming**](docs/INDEX.md) <br> [code](ablation/analyzers/corpus_builder.py) · [code](ablation/analyzers/func_id_db.py) | Match unknown functions against behavioral signatures with thresholds and dry-run support. |
| [**SAX approximate indexing**](docs/INDEX.md) <br> [code](ablation/analyzers/sax_index.py) · [code](ablation/analyzers/subsequence_searcher.py) | Index opcode-category sequences for fast structural candidate lookup. |
| [**Behavioral subsequence search**](docs/INDEX.md) <br> [code](ablation/analyzers/sax_index.py) · [code](ablation/analyzers/subsequence_searcher.py) | Find exact or approximate opcode-category subpatterns within functions. |
| [**Structural similarity and orphan detection**](docs/reference-modules/structural.md) <br> [code](ablation/analyzers/sax_index.py) · [code](ablation/analyzers/subsequence_searcher.py) | Compare opcode histograms, constants, calls and other structural signals to identify unmatched functions. |
| [**Embedding fine-tuning**](docs/INDEX.md) <br> [code](ablation/analyzers/sax_index.py) · [code](ablation/analyzers/subsequence_searcher.py) | Generate structural homolog pairs, fine-tune similarity models and evaluate homolog/non-homolog separation. |
| [**Finding-corpus mining**](docs/INDEX.md) <br> [code](sweeps/corpus_miner.py) · [code](modules/cve_byte_patterns.py) | Extract confirmed local findings, summarize CWE frequency and identify repeated cross-target patterns or scanner gaps. |
| [**CVE byte-signature checks**](docs/INDEX.md) <br> [code](sweeps/corpus_miner.py) · [code](modules/cve_byte_patterns.py) | Match implemented architecture-specific vulnerable-byte signatures for selected patch-verification tasks. |
| [**Version-aware scan caching**](docs/INDEX.md) <br> [code](sweeps/corpus_miner.py) · [code](modules/cve_byte_patterns.py) | Invalidate persisted scanner results when either target bytes or scanner source changes. |
| [**Vendor sink profiles**](docs/INDEX.md) <br> [code](sweeps/corpus_miner.py) · [code](modules/cve_byte_patterns.py) | Load vendor-specific sinks and known-safe command patterns from profiles. |

</details>

<details>
<summary><strong>Additional vulnerability scanners and triage</strong></summary>

| Capability | |
|:---|:---|
| [**Architecture-specific sink provenance**](docs/INDEX.md) <br> [code](ablation/analyzers/sink_arg_classifier_arm32.py) · [code](ablation/analyzers/sink_arg_classifier_mips.py) | Separate classifiers for ARM32, MIPS32, PPC32, i386 and PPC64 big-endian calling conventions. |
| [**Transitive sink-wrapper discovery**](docs/INDEX.md) <br> [code](ablation/analyzers/sink_propagator.py) · [code](ablation/analyzers/sanitizer_detector.py) | Find supported wrappers around dangerous x86-64 string/exec sinks. |
| [**Sanitizer recognition**](docs/INDEX.md) <br> [code](ablation/analyzers/sink_propagator.py) · [code](ablation/analyzers/sanitizer_detector.py) | Identify allowlist-style validators and assess coverage of shell metacharacters. |
| [**Sanitizer-gated sink filtering**](docs/INDEX.md) <br> [code](ablation/analyzers/sink_propagator.py) · [code](ablation/analyzers/sanitizer_detector.py) | Reclassify supported argument-propagated sites whose paths include recognized validation. |
| [**File-versus-socket input discrimination**](docs/INDEX.md) <br> [code](ablation/analyzers/sink_propagator.py) · [code](ablation/analyzers/sanitizer_detector.py) | Classify ARM64 fgets sources using FILE-pointer provenance to reduce configuration-file false positives. |
| [**scanf-family overflow candidates**](docs/INDEX.md) <br> [code](ablation/analyzers/sscanf_sink_classifier.py) · [code](ablation/analyzers/deprecated_func_scanner.py) | Identify unbounded string conversion specifications at supported formatted-input call sites. |
| [**Deprecated unsafe-function scanning**](docs/INDEX.md) <br> [code](ablation/analyzers/sscanf_sink_classifier.py) · [code](ablation/analyzers/deprecated_func_scanner.py) | Flag imported inherently unsafe functions such as gets/mktemp/tmpnam/getwd as review candidates. |
| [**ARM32 allocation arithmetic overflow**](docs/INDEX.md) <br> [code](ablation/analyzers/sscanf_sink_classifier.py) · [code](ablation/analyzers/deprecated_func_scanner.py) | Trace supported multiply operations with input-derived operands into allocation sizes. |
| [**PPC32 heap-slot overflow**](docs/INDEX.md) <br> [code](ablation/analyzers/sscanf_sink_classifier.py) · [code](ablation/analyzers/deprecated_func_scanner.py) | Detect fixed-slot allocation followed by supported unbounded string-copy patterns. |
| [**TLV/chunk alignment checks**](docs/INDEX.md) <br> [code](modules/chunk_walker_validator.py) · [code](ablation/analyzers/epilogue_share_scanner.py) | Identify supported parser pointer advances that omit expected alignment rounding. |
| [**Shared-epilogue detection**](docs/INDEX.md) <br> [code](modules/chunk_walker_validator.py) · [code](ablation/analyzers/epilogue_share_scanner.py) | Detect tail blocks shared through jumps so analysis can account for compiler-merged epilogues. |
| [**Fork/exec classification**](docs/INDEX.md) <br> [code](modules/chunk_walker_validator.py) · [code](ablation/analyzers/epilogue_share_scanner.py) | Distinguish worker-child, exec-after-fork and exit-in-child patterns in supported x86-64 functions. |
| [**Apache module analysis**](docs/INDEX.md) <br> [code](ablation/analyzers/apache_module_analyzer.py) · [code](ablation/analyzers/cmdb_surface_mapper.py) | Inspect supported APR/Apache binary module hooks and security-relevant authentication/session patterns. |
| [**CMDB-to-sink mapping**](docs/INDEX.md) <br> [code](ablation/analyzers/apache_module_analyzer.py) · [code](ablation/analyzers/cmdb_surface_mapper.py) | Associate supported Fortinet database-table accesses with functions that also invoke execution sinks. |
| [**HTTP method-enum recovery**](docs/INDEX.md) <br> [code](ablation/analyzers/apache_module_analyzer.py) · [code](ablation/analyzers/cmdb_surface_mapper.py) | Infer supported Flatui route method identifiers from route-registration evidence. |
| [**Firmware-flasher trust checks**](docs/INDEX.md) <br> [code](ablation/analyzers/apache_module_analyzer.py) · [code](ablation/analyzers/cmdb_surface_mapper.py) | Flag PE firmware-update capability lacking recognized signature-verification imports as a review candidate. |
| [**VxWorks static-archive scanning**](docs/INDEX.md) <br> [code](modules/vxworks_archive_scanner.py) · [code](ablation/analyzers/compiler_security_gate.py) | Inspect PPC32 archive members for unbounded copies within selected stack-frame sizes. |
| [**Post-link compiler security gate**](docs/reference-modules/compiler_security_gate.md) <br> [code](modules/vxworks_archive_scanner.py) · [code](ablation/analyzers/compiler_security_gate.py) | Run supported binary scanners against newly compiled artifacts and aggregate findings. |

</details>

<details>
<summary><strong>C++ and architecture-specific recovery</strong></summary>

| Capability | |
|:---|:---|
| [**ARM64 virtual-call resolution**](docs/INDEX.md) <br> [code](ablation/analyzers/vtable_resolver.py) · [code](modules/elf_vtable_reconstructor.py) | Infer vtables, constructor vptr writes and supported BLR targets. |
| [**x86-64 relocation-based vtables**](docs/INDEX.md) <br> [code](ablation/analyzers/vtable_resolver.py) · [code](modules/elf_vtable_reconstructor.py) | Reconstruct virtual table slots from ELF RELA entries. |
| [**Live virtual-dispatch slots**](docs/INDEX.md) <br> [code](ablation/analyzers/vtable_resolver.py) · [code](modules/elf_vtable_reconstructor.py) | Find x86-64 indirect-call slot uses and distinguish referenced slots from unobserved ones. |
| [**PS3 OPD virtual tables**](docs/INDEX.md) <br> [code](ablation/analyzers/vtable_resolver.py) · [code](modules/elf_vtable_reconstructor.py) | Recover PPC64 Cell PPU virtual tables through function descriptors. |
| [**Verified PPC32 import callers**](docs/INDEX.md) <br> [code](ablation/analyzers/ppc32_plt_tracer.py) · [code](ablation/analyzers/ppc64_elfv1_resolver.py) | Trace PLT thunk calls while checking the caller's active GOT2 base. |
| [**PPC64 ELFv1 resolution**](docs/INDEX.md) <br> [code](ablation/analyzers/ppc32_plt_tracer.py) · [code](ablation/analyzers/ppc64_elfv1_resolver.py) | Resolve OPD function descriptors, TOC-related metadata and glink import stubs. |
| [**Unnamed ARM64 library-call classification**](docs/INDEX.md) <br> [code](ablation/analyzers/ppc32_plt_tracer.py) · [code](ablation/analyzers/ppc64_elfv1_resolver.py) | Classify PLT entries using argument/return behavior and a library-function summary database. |
| [**Classic Mac ABI clobber scanning**](docs/INDEX.md) <br> [code](ablation/analyzers/ppc32_plt_tracer.py) · [code](ablation/analyzers/ppc64_elfv1_resolver.py) | Detect supported PPC32 PEF argument-register clobbers across intervening calls. |
| [**Data-structure pattern classification**](docs/INDEX.md) <br> [code](ablation/analyzers/ppc64_dynds_classifier.py) · [code](ablation/analyzers/ppc64_vmx_density.py) | Identify supported PPC64/Cell list/tree/traversal patterns from structural signals. |
| [**VMX/AltiVec density ranking**](docs/INDEX.md) <br> [code](ablation/analyzers/ppc64_dynds_classifier.py) · [code](ablation/analyzers/ppc64_vmx_density.py) | Locate vector-heavy PPC64 functions as candidates for math, physics or rendering code. |
| [**PPC32/PPC476 dedicated lifting**](docs/INDEX.md) <br> [code](ablation/analyzers/ppc64_dynds_classifier.py) · [code](ablation/analyzers/ppc64_vmx_density.py) | Additional pseudo-code/decompiler entry points for PowerPC and IBM Book E binaries. |

</details>

<details>
<summary><strong>Firmware, containers and legacy formats</strong></summary>

| Capability | |
|:---|:---|
| [**Firmware signature and secret triage**](docs/INDEX.md) <br> [code](ablation/core/firmware_analyzer.py) · [code](ablation/analyzers/firmware_container.py) | Locate embedded format signatures, security-relevant strings, version indicators and entropy changes. |
| [**Partition-table extraction**](docs/INDEX.md) <br> [code](ablation/core/firmware_analyzer.py) · [code](ablation/analyzers/firmware_container.py) | Enumerate and extract supported fixed-record firmware container partitions. |
| [**Hardware-root discovery**](docs/INDEX.md) <br> [code](ablation/core/firmware_analyzer.py) · [code](ablation/analyzers/firmware_container.py) | Identify MMIO load/store references to known peripheral address ranges. |
| [**AMI modified CramFS**](docs/INDEX.md) <br> [code](modules/ami_cramfs_extractor.py) · [code](modules/huawei_squashfs_extractor.py) | Extract supported BMC filesystems with AMI-specific extended inode layouts. |
| [**Huawei modified SquashFS**](docs/INDEX.md) <br> [code](modules/ami_cramfs_extractor.py) · [code](modules/huawei_squashfs_extractor.py) | Extract supported vendor SquashFS/XZ layouts, including handling of ARM64 BCJ-filtered blocks. |
| [**Apple bv41 decompression**](docs/INDEX.md) <br> [code](modules/ami_cramfs_extractor.py) · [code](modules/huawei_squashfs_extractor.py) | Probe, iterate and stream-decode Apple's proprietary chunked LZ4 framing. |
| [**FortiMail VM key extraction**](docs/INDEX.md) <br> [code](ablation/analyzers/fortimail_vmdk_extractor.py) · [code](ablation/analyzers/fortibuild_track_classifier.py) | Extract supported key files from OVF/VMDK firmware layouts and their filesystem partitions. |
| [**Fortinet build-track classification**](docs/INDEX.md) <br> [code](ablation/analyzers/fortimail_vmdk_extractor.py) · [code](ablation/analyzers/fortibuild_track_classifier.py) | Parse product/version/build-track names and predict the known certificate-key family. |
| [**AIX plain BFF extraction**](docs/INDEX.md) <br> [code](ablation/core/bff_extractor.py) · [code](modules/bff_decompressor.py) | Parse backup-by-name archives and extract contained files/directories. |
| [**Compressed BFF detection and LZW attempt**](docs/INDEX.md) <br> [code](ablation/core/bff_extractor.py) · [code](modules/bff_decompressor.py) | Identify compression variants and attempt supported LZW decompression through uncompress; Huffman variants report that AIX tooling is required. |
| [**AIX big archive extraction**](docs/INDEX.md) <br> [code](ablation/core/bff_extractor.py) · [code](modules/bff_decompressor.py) | Extract members from the AIX <bigaf> library/archive format. |
| [**AIX XCOFF32/64 analysis**](docs/INDEX.md) <br> [code](ablation/core/xcoff_parser.py) · [code](modules/xcoff_executable_analyzer.py) | Parse executable sections and loader symbols; enumerate imports/exports and candidate function entries. |
| [**Standalone XCOFF symbol resolution**](docs/INDEX.md) <br> [code](ablation/core/xcoff_parser.py) · [code](modules/xcoff_executable_analyzer.py) | Recover library imports and exported code addresses without a full BinaryContext session. |
| [**IBM W-Code parsing**](docs/INDEX.md) <br> [code](ablation/core/xcoff_parser.py) · [code](modules/xcoff_executable_analyzer.py) | Parse supported XLC intermediate records and builtin-catalog references. |
| [**Motorola 88000 BCS COFF**](docs/INDEX.md) <br> [code](ablation/core/coff_m88k_parser.py) · [code](ablation/core/guardian_pak_extractor.py) | Parse legacy executable sections and feed the dedicated M88K decoder/context path. |
| [**Tandem Guardian PAK**](docs/INDEX.md) <br> [code](ablation/core/coff_m88k_parser.py) · [code](ablation/core/guardian_pak_extractor.py) | Decompress supported Guardian BACKUP records and extract NonStop files. |
| [**AppleDouble resource forks**](docs/INDEX.md) <br> [code](ablation/core/coff_m88k_parser.py) · [code](ablation/core/guardian_pak_extractor.py) | Parse classic Mac resource-fork and metadata containers. |
| [**PowerPC PEF/CFM**](docs/INDEX.md) <br> [code](ablation/core/coff_m88k_parser.py) · [code](ablation/core/guardian_pak_extractor.py) | Parse classic Mac code/data sections, imports and supported container metadata. |
| [**Installer payload analysis**](docs/INDEX.md) <br> [code](modules/installer_binary_analyzer.py) · [code](sweeps/win16_ne_sweep.py) | Extract supported BitRock LZMA payloads, carve PE candidates and optionally unpack UPX; recognize NSIS/Inno signatures. |
| [**Windows 16-bit NE**](docs/INDEX.md) <br> [code](modules/installer_binary_analyzer.py) · [code](sweeps/win16_ne_sweep.py) | Parse segmented New Executable binaries and sweep supported imports/calls/security patterns. |
| [**Windows LE/VxD**](docs/INDEX.md) <br> [code](modules/installer_binary_analyzer.py) · [code](sweeps/win16_ne_sweep.py) | Parse Linear Executable drivers, inspect device-descriptor data and sweep supported ring-0 code patterns. |
| [**MS-DOS MZ**](docs/INDEX.md) <br> [code](modules/installer_binary_analyzer.py) · [code](sweeps/win16_ne_sweep.py) | Parse real-mode headers/relocations and analyze supported multi-segment 16-bit code. |

</details>

<details>
<summary><strong>Language and application runtimes</strong></summary>

| Capability | |
|:---|:---|
| [**DEX disassembly and lifting**](docs/INDEX.md) <br> [code](ablation/analyzers/dex_disasm.py) · [code](ablation/analyzers/dex_lifter.py) | Decode instructions to annotated smali and supported pseudo-Java. |
| [**Android Binder surface**](docs/INDEX.md) <br> [code](ablation/analyzers/dex_disasm.py) · [code](ablation/analyzers/dex_lifter.py) | Correlate exported services and DEX classes to identify Binder IPC exposure. |
| [**JNI bridge reconstruction**](docs/INDEX.md) <br> [code](ablation/analyzers/dex_disasm.py) · [code](ablation/analyzers/dex_lifter.py) | Associate native declarations, loadLibrary uses, peer-pointer fields and native exports. |
| [**Specialized JNI protocol analysis**](docs/INDEX.md) <br> [code](modules/deep_jni_analysis.py) · [code](modules/analyze_all_jni.py) | Scripts for deeper vtable, field-write and protocol analysis, including libhijoyptt-specific assumptions. |
| [**Go string recovery**](docs/INDEX.md) <br> [code](ablation/analyzers/go_string_resolver.py) · [code](ablation/analyzers/go_subprocess_scanner.py) | Resolve length-delimited strings under the supported AMD64 Go register ABI. |
| [**Go subprocess surface**](docs/INDEX.md) <br> [code](ablation/analyzers/go_string_resolver.py) · [code](ablation/analyzers/go_subprocess_scanner.py) | Find os/exec call sites and recover static command-path arguments where possible. |
| [**Go dangerous-call graph**](docs/INDEX.md) <br> [code](ablation/analyzers/go_string_resolver.py) · [code](ablation/analyzers/go_subprocess_scanner.py) | Build/cache caller maps, filter application namespaces and resolve supported interface tables. |
| [**Stripped Go x86-64 boundaries**](docs/INDEX.md) <br> [code](ablation/analyzers/go_string_resolver.py) · [code](ablation/analyzers/go_subprocess_scanner.py) | Recover function entries from pclntab when conventional symbols/debug info are absent. |
| [**Java class/JAR parsing**](docs/INDEX.md) <br> [code](modules/java_re.py) · [code](modules/java_decompiler.py) | Read constant pools, methods, fields, descriptors, manifests and archives. |
| [**Java security pattern scans**](docs/INDEX.md) <br> [code](modules/java_re.py) · [code](modules/java_decompiler.py) | Flag supported reflection, serialization, class-loading, Runtime.exec, SSRF, XXE, JNDI, weak randomness and hardcoded-secret patterns. |
| [**JVM/Spring exposure inspection**](docs/INDEX.md) <br> [code](modules/java_re.py) · [code](modules/java_decompiler.py) | Inspect JVM flags/debug endpoints, agents and supported Spring Actuator/application-context surfaces. |
| [**Python .pyc scanning**](docs/INDEX.md) <br> [code](ablation/analyzers/pyc_bytecode_scanner.py) · [code](ablation/analyzers/perl_taint_scanner.py) | Inspect supported code objects for dangerous bytecode/name/constant patterns without source files. |
| [**Perl shell-injection scanning**](docs/INDEX.md) <br> [code](ablation/analyzers/pyc_bytecode_scanner.py) · [code](ablation/analyzers/perl_taint_scanner.py) | Trace supported Perl input sources into system/exec/qx/backtick-style sinks. |
| [**Electron application auditing**](docs/INDEX.md) <br> [code](ablation/analyzers/pyc_bytecode_scanner.py) · [code](ablation/analyzers/perl_taint_scanner.py) | Scan extracted JavaScript for unsafe Electron settings, IPC and execution patterns. |
| [**Browser-extension auditing**](docs/INDEX.md) <br> [code](ablation/analyzers/pyc_bytecode_scanner.py) · [code](ablation/analyzers/perl_taint_scanner.py) | Inspect extension manifests, permissions, external messaging and privileged JavaScript patterns. |

</details>

<details>
<summary><strong>Source repository auditing</strong></summary>

| Capability | |
|:---|:---|
| [**Repository ingestion and search**](docs/INDEX.md) <br> [code](ablation/analyzers/source_ingestion.py) · [code](ablation/analyzers/source_entry_classifier.py) | Build a local/remote source index, categorize languages and retrieve matching text/context. |
| [**Route authentication classification**](docs/INDEX.md) <br> [code](ablation/analyzers/source_ingestion.py) · [code](ablation/analyzers/source_entry_classifier.py) | Map supported source HTTP routes to authentication-wrapper levels. |
| [**Source dangerous-sink detection**](docs/INDEX.md) <br> [code](ablation/analyzers/source_ingestion.py) · [code](ablation/analyzers/source_entry_classifier.py) | Scan supported eval, subprocess, SSRF, path traversal and internal-endpoint patterns. |
| [**Tenant-isolation checks**](docs/INDEX.md) <br> [code](ablation/analyzers/source_ingestion.py) · [code](ablation/analyzers/source_entry_classifier.py) | Identify supported database accesses without expected user/project/organization scoping. |
| [**Architectural-risk detection**](docs/INDEX.md) <br> [code](ablation/analyzers/source_ingestion.py) · [code](ablation/analyzers/source_entry_classifier.py) | Flag unsafe rendering combined with extensible dispatch or shared context that may increase future exposure. |

</details>

<details>
<summary><strong>Automotive and embedded details</strong></summary>

| Capability | |
|:---|:---|
| [**C166/C167 decoding**](docs/INDEX.md) <br> [code](ablation/analyzers/ecu_c166_decoder.py) · [code](ablation/analyzers/ecu_c28x_decoder.py) | Decode supported instructions, find functions, inspect XRAM accesses and parse interrupt vectors. |
| [**TI C28x decoding**](docs/INDEX.md) <br> [code](ablation/analyzers/ecu_c166_decoder.py) · [code](ablation/analyzers/ecu_c28x_decoder.py) | Decode supported DSP instructions and recover candidate function starts. |
| [**M68K/CPU32 decoding**](docs/INDEX.md) <br> [code](ablation/analyzers/ecu_c166_decoder.py) · [code](ablation/analyzers/ecu_c28x_decoder.py) | Decode supported ECU instructions and discover function entries. |
| [**Renesas SH-2A decoding**](docs/INDEX.md) <br> [code](ablation/analyzers/ecu_c166_decoder.py) · [code](ablation/analyzers/ecu_c28x_decoder.py) | Handle supported instruction widths, calls, functions and delay-slot-aware CFG/lifting. |
| [**PowerPC VLE decoding**](docs/INDEX.md) <br> [code](ablation/analyzers/ecu_c166_decoder.py) · [code](ablation/analyzers/ecu_c28x_decoder.py) | Handle supported mixed 16/32-bit e200 ECU instructions and function discovery. |
| [**HiSilicon RISC-V extensions**](docs/INDEX.md) <br> [code](ablation/analyzers/hisi_rv32_ext.py) · [code](modules/isa_8051.py) | Decode supported proprietary riscv31 opcodes, widths and multi-register memory operations. |
| [**8051 ISA modeling**](docs/INDEX.md) <br> [code](ablation/analyzers/hisi_rv32_ext.py) · [code](modules/isa_8051.py) | Model MCS-51 registers, separate memory spaces, instruction semantics and selected security-analysis facts. |
| [**TI COFF/archive loading**](docs/INDEX.md) <br> [code](ablation/analyzers/hisi_rv32_ext.py) · [code](modules/isa_8051.py) | Parse supported TI COFF2 objects and archive symbols/sections. |
| [**TI neural-network artifacts**](docs/INDEX.md) <br> [code](ablation/analyzers/hisi_rv32_ext.py) · [code](modules/isa_8051.py) | Identify supported TVM/NNC-generated symbols and inspect inference-artifact metadata/patterns. |
| [**TI SDK package sweeping**](docs/INDEX.md) <br> [code](ablation/analyzers/hisi_rv32_ext.py) · [code](modules/isa_8051.py) | Dispatch supported COFF, ARM, ARM64 and flat-ROM artifacts across package directories/archives. |
| [**Calibration table interpretation**](docs/INDEX.md) <br> [code](ablation/analyzers/ecu_cal_def.py) · [code](ablation/analyzers/ecu_open_damos_parser.py) | Represent axes, scaling and table metadata; read supported calibration values and produce address labels. |
| [**Calibration variant/relocation support**](docs/INDEX.md) <br> [code](ablation/analyzers/ecu_cal_def.py) · [code](ablation/analyzers/ecu_open_damos_parser.py) | Resolve supported inherited definition variants, identify ROMs and locate fingerprint-relocated open_damos tables. |

</details>

<details>
<summary><strong>Windows security details</strong></summary>

| Capability | |
|:---|:---|
| [**Control Flow Guard review**](docs/INDEX.md) <br> [code](ablation/analyzers/cfg_bypass_detector.py) · [code](ablation/analyzers/seh_chain_analyzer.py) | Inspect CFG metadata and supported exported-target/bypass opportunity patterns. |
| [**SEH and SafeSEH review**](docs/INDEX.md) <br> [code](ablation/analyzers/cfg_bypass_detector.py) · [code](ablation/analyzers/seh_chain_analyzer.py) | Inspect x86 handler registration/chains, protections and suspicious handler patterns. |
| [**COM attack-surface mapping**](docs/INDEX.md) <br> [code](ablation/analyzers/cfg_bypass_detector.py) · [code](ablation/analyzers/seh_chain_analyzer.py) | Find supported COM registrations and privilege-boundary/hijacking indicators. |
| [**ETW provider extraction**](docs/INDEX.md) <br> [code](ablation/analyzers/cfg_bypass_detector.py) · [code](ablation/analyzers/seh_chain_analyzer.py) | Recover provider/event indicators and assess supported telemetry patterns. |
| [**Kernel pool flow checks**](docs/INDEX.md) <br> [code](ablation/analyzers/cfg_bypass_detector.py) · [code](ablation/analyzers/seh_chain_analyzer.py) | Track supported pool allocations toward copies/writes using bounded instruction-window heuristics. |
| [**PDB integration**](docs/INDEX.md) <br> [code](ablation/analyzers/cfg_bypass_detector.py) · [code](ablation/analyzers/seh_chain_analyzer.py) | Read PE debug references, fetch/load supported PDB information and inject recovered names into context. |

</details>

<details>
<summary><strong>Cryptography and authentication details</strong></summary>

| Capability | |
|:---|:---|
| [**Repeating-XOR key recovery**](docs/INDEX.md) <br> [code](ablation/analyzers/xor_solver.py) · [code](ablation/analyzers/crypto_pattern_detector.py) | Use known plaintext, key-length scoring and frequency/transposition methods. |
| [**Affine mapping analysis**](docs/INDEX.md) <br> [code](ablation/analyzers/xor_solver.py) · [code](ablation/analyzers/crypto_pattern_detector.py) | Inspect supported affine byte mappings as a helper for encoded data recovery. |
| [**Hash/AES implementation recognition**](docs/INDEX.md) <br> [code](ablation/analyzers/xor_solver.py) · [code](ablation/analyzers/crypto_pattern_detector.py) | Detect hash constants and supported custom ARM32/Thumb AES-CBC patterns. |
| [**JWT analysis and weak-secret testing**](docs/INDEX.md) <br> [code](ablation/analyzers/xor_solver.py) · [code](ablation/analyzers/crypto_pattern_detector.py) | Decode tokens, inspect algorithms and test candidate weak signing secrets; token-construction helpers are present. |
| [**SAML and key-material review**](docs/INDEX.md) <br> [code](ablation/analyzers/xor_solver.py) · [code](ablation/analyzers/crypto_pattern_detector.py) | Inspect assertion structure/wrapping indicators and search for embedded key material. |
| [**RSA/ECDSA and randomness checks**](docs/INDEX.md) <br> [code](ablation/analyzers/xor_solver.py) · [code](ablation/analyzers/crypto_pattern_detector.py) | Helpers inspect RSA/prime properties, ECDSA nonce reuse, RNG/hash/key-management weaknesses and selected timing/nonce risks. |
| [**Crypto/C2 encoding indicators**](docs/INDEX.md) <br> [code](ablation/analyzers/xor_solver.py) · [code](ablation/analyzers/crypto_pattern_detector.py) | Recognize selected XOR, RC4, Base64, Salsa/ChaCha, AES and arithmetic-encoding patterns. |

</details>

<details>
<summary><strong>TLS and web/API analysis</strong></summary>

| Capability | |
|:---|:---|
| [**TLS certificate and protocol probing**](docs/INDEX.md) <br> [code](ablation/core/tls_analyzer.py) · [code](modules/tls_enum.py) | Inspect certificates, key strength, legacy versions/ciphers, DH-related properties and handshake behavior. |
| [**TLS policy checks**](docs/INDEX.md) <br> [code](ablation/core/tls_analyzer.py) · [code](modules/tls_enum.py) | Probe HSTS, redirects, mTLS, pinning-related headers, SCT/CT indicators and ACME-related exposure. |
| [**TLS session/downgrade surfaces**](docs/INDEX.md) <br> [code](ablation/core/tls_analyzer.py) · [code](modules/tls_enum.py) | Probe supported resumption, downgrade, inspection/proxy and zero-trust gateway configurations. |
| [**Unknown HTTP API mapping**](docs/INDEX.md) <br> [code](modules/api_re.py) | Discover paths/versions/methods, harvest OpenAPI and infer parameter/schema/error/state behavior. |
| [**API authorization checks**](docs/INDEX.md) <br> [code](modules/api_re.py) | Probe supported object/function-level authorization, mass assignment and excessive-data exposure cases. |
| [**API injection and validation checks**](docs/INDEX.md) <br> [code](modules/api_re.py) | Probe supported parameter pollution, content-type switching, SSRF, NoSQL, host-header and other input-handling surfaces. |
| [**API authentication and token checks**](docs/INDEX.md) <br> [code](modules/api_re.py) | Inspect JWT/OAuth flows, state/PKCE, default credentials, rate limiting and timing behavior. |
| [**Additional API protocols**](docs/INDEX.md) <br> [code](modules/api_re.py) | Discovery/probes for GraphQL, gRPC reflection, SOAP/WSDL, JSON-RPC and WebSocket interfaces. |
| [**Business-logic and version exposure**](docs/INDEX.md) <br> [code](modules/api_re.py) | Probe state changes, pagination, hidden parameters, shadow versions and webhook behaviors. |
| [**Nginx fingerprinting and exposure**](docs/INDEX.md) <br> [code](modules/nginx_enum.py) | Inspect server/version disclosure, status/debug endpoints, autoindex and sensitive paths. |
| [**Nginx configuration probes**](docs/INDEX.md) <br> [code](modules/nginx_enum.py) | Check supported alias traversal, proxy SSRF, host-header, smuggling, authentication, ingress and rate-limit surfaces. |
| [**Version-linked web checks**](docs/INDEX.md) <br> [code](modules/nginx_enum.py) | Identify selected historical nginx CVE indicators; matches still require target-specific verification. |

</details>

<details>
<summary><strong>Host, process and privilege enumeration</strong></summary>

| Capability | |
|:---|:---|
| [**Host platform inventory**](docs/INDEX.md) <br> [code](modules/process_enum.py) · [code](modules/syscall_trace.py) | Detect OS, architecture, kernel/libc and selected security/capability settings. |
| [**Process and memory-map inventory**](docs/INDEX.md) <br> [code](modules/process_enum.py) · [code](modules/syscall_trace.py) | Enumerate processes, loaded modules, executable/RWX regions, open files and environment data. |
| [**System-call tracing**](docs/INDEX.md) <br> [code](modules/process_enum.py) · [code](modules/syscall_trace.py) | Invoke supported strace/ptrace-based tracing and summarize file, network and process operations. |
| [**Injection and persistence indicators**](docs/INDEX.md) <br> [code](modules/process_enum.py) · [code](modules/syscall_trace.py) | Inspect supported process-hollowing, preload/library-hijack, ptrace, cron, services and named-pipe patterns. |
| [**Linux privilege-escalation triage**](docs/INDEX.md) <br> [code](modules/privesc_enum.py) · [code](modules/windows_enum.py) | Enumerate SUID, sudo, capabilities, writable paths/cron, credential-file exposure, Docker access and kernel/namespace conditions. |
| [**Windows live enumeration**](docs/INDEX.md) <br> [code](modules/privesc_enum.py) · [code](modules/windows_enum.py) | Inspect COM registration differences, RPC endpoints, ETW sessions, pipes, policies, services, autoruns, privileges and loaded modules. |
| [**Windows escalation indicators**](docs/INDEX.md) <br> [code](modules/privesc_enum.py) · [code](modules/windows_enum.py) | Check supported unquoted-service, installer-policy, token, scheduled-task and UAC/driver indicators. |

</details>

<details>
<summary><strong>Forensics and malware triage</strong></summary>

| Capability | |
|:---|:---|
| [**Windows artifact discovery**](docs/INDEX.md) <br> [code](modules/forensics_enum.py) · [code](modules/process_enum.py) | Locate MFT/LNK/Prefetch/EVTX-related artifacts and markers; this is not full decoding of those formats. |
| [**Volatile and Linux artifact triage**](docs/INDEX.md) <br> [code](modules/forensics_enum.py) · [code](modules/process_enum.py) | Inspect process/procfs/memory-access indicators, histories, deleted executables and selected volatile evidence. |
| [**Timestamp/log anomaly checks**](docs/INDEX.md) <br> [code](modules/forensics_enum.py) · [code](modules/process_enum.py) | Identify selected timestomping, empty/deleted log and related metadata indicators. |
| [**Rootkit/bootkit indicators**](docs/INDEX.md) <br> [code](modules/forensics_enum.py) · [code](modules/process_enum.py) | Match supported SSDT/callback/hiding, DPC/timer, raw-disk and boot-sector patterns. |
| [**Malware behavior indicators**](docs/INDEX.md) <br> [code](modules/forensics_enum.py) · [code](modules/process_enum.py) | Inspect keylogger, clipboard, mutex, downloader/backdoor, fileless and reflective-loading API/string combinations. |
| [**Packing and anti-analysis indicators**](docs/INDEX.md) <br> [code](modules/forensics_enum.py) · [code](modules/process_enum.py) | Detect selected packed-section, PEB/debugger, opaque/junk-code, anti-disassembly and sandbox-environment patterns. |
| [**Office/PDF triage**](docs/INDEX.md) <br> [code](modules/forensics_enum.py) · [code](modules/process_enum.py) | Scan raw document markers for macro and exploit indicators without full document interpretation. |
| [**ELF recovery from physical-memory dumps**](docs/INDEX.md) <br> [code](modules/physmem_elf_vfs.py) · [code](modules/video_container.py) | Find supported ELF64 images and reconstruct candidates using contiguous mappings and proximity heuristics. |
| [**Video-container forensics**](docs/INDEX.md) <br> [code](modules/physmem_elf_vfs.py) · [code](modules/video_container.py) | Parse MP4/MOV, MKV/WebM and AVI structures for appended payloads, suspicious metadata, malformed sizes and encrypted-track markers. |
| [**IOC candidate extraction**](docs/INDEX.md) <br> [code](modules/physmem_elf_vfs.py) · [code](modules/video_container.py) | Extract supported URL/address/path/key/certificate and other suspicious-string candidates. |
| [**ATT&CK labeling**](docs/INDEX.md) <br> [code](modules/physmem_elf_vfs.py) · [code](modules/video_container.py) | Map recognized finding categories to configured ATT&CK technique labels. |

</details>

<details>
<summary><strong>Network discovery and traffic inspection</strong></summary>

| Capability | |
|:---|:---|
| [**Local network inventory**](docs/INDEX.md) <br> [code](modules/network_analyze.py) · [code](modules/net_sniffer.py) | Enumerate interfaces, connections, listening ports and firewall rules. |
| [**Raw packet capture**](docs/INDEX.md) <br> [code](modules/network_analyze.py) · [code](modules/net_sniffer.py) | Capture supported traffic and parse selected IPv4/TCP/UDP headers. |
| [**PCAP inspection**](docs/INDEX.md) <br> [code](modules/network_analyze.py) · [code](modules/net_sniffer.py) | Packet-level DNS queries, HTTP metadata and selected cleartext credential extraction. |
| [**Host/service discovery**](docs/INDEX.md) <br> [code](modules/network_analyze.py) · [code](modules/net_sniffer.py) | ICMP/TCP discovery, banners, mDNS, SSDP, ARP observations and basic TTL/application fingerprinting. |
| [**Web-path enumeration**](docs/INDEX.md) <br> [code](modules/network_analyze.py) · [code](modules/net_sniffer.py) | Discover directories, listings and other supported web paths. |
| [**Industrial/IoT probes**](docs/INDEX.md) <br> [code](modules/network_analyze.py) · [code](modules/net_sniffer.py) | Exposure checks for supported Modbus, MQTT, CoAP, SNMP, NTP and NetFlow/IPFIX services. |
| [**Additional industrial/debug probes**](docs/INDEX.md) <br> [code](modules/syscall_trace.py) · [code](modules/lateral_movement.py) | Probe BACnet, EtherNet/IP and supported debugger interfaces. |
| [**Internal-network reconnaissance**](docs/INDEX.md) <br> [code](modules/syscall_trace.py) · [code](modules/lateral_movement.py) | Parse ARP/routes, discover subnets/names and inspect remote-management/database surfaces. |
| [**Credential/token/key discovery**](docs/INDEX.md) <br> [code](modules/syscall_trace.py) · [code](modules/lateral_movement.py) | Enumerate accessible configuration credentials, API tokens, SSH keys and cloud-metadata surfaces. |
| [**Remote-management and identity probes**](docs/INDEX.md) <br> [code](modules/syscall_trace.py) · [code](modules/lateral_movement.py) | Supported SMB/NTLM, RPC, WinRM, RDP, WMI, SSH and Active Directory-related surface checks. |
| [**Credential-testing helpers**](docs/INDEX.md) <br> [code](modules/syscall_trace.py) · [code](modules/lateral_movement.py) | Explicit SSH/FTP credential-spray and related authentication-testing helpers exist as callable functions. |
| [**C2/exfiltration indicators**](docs/INDEX.md) <br> [code](modules/syscall_trace.py) · [code](modules/lateral_movement.py) | Inspect supported beaconing, DNS/HTTP/IRC/ICMP/covert-channel, tunneling, cloud-storage and ransomware-precursor patterns. |
| [**IOS/IOS-XE appliance enumeration**](docs/INDEX.md) <br> [code](modules/ios_enum.py) · [code](modules/nxos_enum.py) | HTTP/API, SNMP, CDP/LLDP, Telnet/TFTP, configuration parsing and supported AAA/network/security-management checks. |
| [**Appliance configuration secret helpers**](docs/INDEX.md) <br> [code](modules/ios_enum.py) · [code](modules/nxos_enum.py) | Type-7 decoding and selected SNMP-community/enable-secret credential-testing helpers. |
| [**SD-WAN/Meraki management probes**](docs/INDEX.md) <br> [code](modules/hyperflex_enum.py) · [code](modules/nexus_dashboard_enum.py) | Management-API exposure probes for supported SD-WAN and cloud-managed network products. |

</details>

<details>
<summary><strong>Containers, cloud infrastructure and services</strong></summary>

| Capability | |
|:---|:---|
| [**Docker inventory and posture**](docs/INDEX.md) <br> [code](modules/docker_enum.py) · [code](modules/k8s_enum.py) | Enumerate containers, images, volumes, networks, mounts, capabilities, privileged modes, sockets, ports and environment secrets. |
| [**Container isolation/escape surface**](docs/INDEX.md) <br> [code](modules/docker_enum.py) · [code](modules/k8s_enum.py) | Inspect supported host mounts, namespace/capability, resource and image-layer risks. |
| [**Kubernetes inventory**](docs/INDEX.md) <br> [code](modules/docker_enum.py) · [code](modules/k8s_enum.py) | Enumerate pods, services, namespaces, secrets and ConfigMaps through kubectl or supported direct API calls. |
| [**Kubernetes identity and RBAC**](docs/INDEX.md) <br> [code](modules/docker_enum.py) · [code](modules/k8s_enum.py) | Inspect service-account bundles, SelfSubjectAccessReview permissions and cluster-admin/role bindings. |
| [**Kubernetes policy/posture**](docs/INDEX.md) <br> [code](modules/docker_enum.py) · [code](modules/k8s_enum.py) | Review network policies, admission/webhooks, pod security, hostPath/projected storage, ingress, mesh mTLS and resource settings. |
| [**Cluster management exposure**](docs/INDEX.md) <br> [code](modules/docker_enum.py) · [code](modules/k8s_enum.py) | Probe supported etcd, kubelet, dashboards, node services, cloud metadata and Orka endpoints. |
| [**Messaging/streaming enumeration**](docs/INDEX.md) <br> [code](modules/network_analyze.py) · [code](modules/streaming_enum.py) | Inspect supported Kafka, Flink, NiFi, schema registries, RabbitMQ, NATS, Pulsar and event-store/registry surfaces. |
| [**Streaming operational helpers**](docs/INDEX.md) <br> [code](modules/network_analyze.py) · [code](modules/streaming_enum.py) | Kafka topic/sample consumption and Flink JAR-submission helpers are present, alongside enumeration. |
| [**Database/storage exposure**](docs/INDEX.md) <br> [code](modules/network_analyze.py) · [code](modules/streaming_enum.py) | Probe supported Redis, Elasticsearch, MinIO, InfluxDB and database endpoints. |
| [**Observability exposure**](docs/INDEX.md) <br> [code](modules/network_analyze.py) · [code](modules/streaming_enum.py) | Probe Prometheus, Grafana, Jaeger, Loki, OpenTelemetry, Alertmanager, Thanos and related collectors. |
| [**Orchestration/management exposure**](docs/INDEX.md) <br> [code](modules/network_analyze.py) · [code](modules/streaming_enum.py) | Probe supported vCenter, Rancher, Consul, Linkerd, Kong, Traefik, Temporal, Argo, Nomad and AWX/NSO surfaces. |
| [**CI/CD and artifact services**](docs/INDEX.md) <br> [code](modules/network_analyze.py) · [code](modules/streaming_enum.py) | Probe supported Jenkins, GitLab, Tekton, Argo CD, Flux, Crossplane, SonarQube, Artifactory and Nexus endpoints. |
| [**Secrets/access infrastructure**](docs/INDEX.md) <br> [code](modules/network_analyze.py) · [code](modules/streaming_enum.py) | Probe supported Vault and Boundary management exposure. |
| [**DNS service posture**](docs/INDEX.md) <br> [code](modules/network_analyze.py) · [code](modules/streaming_enum.py) | Probe zone transfer, recursion, dynamic-update and DoT/DoH-related surfaces. |
| [**NX-OS/ACI/APIC fabric enumeration**](docs/INDEX.md) <br> [code](modules/ios_enum.py) · [code](modules/nxos_enum.py) | NX-API, fabric nodes/endpoints, tenants/contracts, L3Out, VMM, audit/config data and selected management probes. |
| [**VXLAN/DCNM exposure**](docs/INDEX.md) <br> [code](modules/ios_enum.py) · [code](modules/nxos_enum.py) | Inspect supported VTEP and management exposure and retrieve firmware/license/version details. |
| [**HyperFlex/UCS/Intersight**](docs/INDEX.md) <br> [code](modules/hyperflex_enum.py) · [code](modules/nexus_dashboard_enum.py) | Inspect Connect APIs, cluster/storage interfaces, iSCSI-related exposure and selected management endpoints. |
| [**Nexus Dashboard**](docs/INDEX.md) <br> [code](modules/hyperflex_enum.py) · [code](modules/nexus_dashboard_enum.py) | Enumerate supported dashboard, NDI/NDFC/NDO, telemetry and provisioning surfaces. |

</details>


<details>
<summary><strong>VoIP and real-time communications</strong></summary>

| Capability | |
|:---|:---|
| [**SIP service and extension discovery**](docs/INDEX.md) <br> [code](modules/sip_enum.py) | Probe OPTIONS/REGISTER behavior, enumerate extensions and examine supported authentication/registration patterns. |
| [**Media and signaling posture**](docs/INDEX.md) <br> [code](modules/sip_enum.py) | Parse SDP, inspect RTP/SRTP expectations, AMI, WebRTC and selected media/interception indicators. |
| [**Legacy voice protocols**](docs/INDEX.md) <br> [code](modules/sip_enum.py) | Probe supported H.323, SCCP/Skinny, MGCP and media-gateway surfaces. |
| [**Voice abuse indicators**](docs/INDEX.md) <br> [code](modules/sip_enum.py) | Heuristics/probes for signaling manipulation, DTMF exposure, covert channels, flooding and denial-of-service susceptibility. |

</details>

<details>
<summary><strong>AI, agent and MCP security</strong></summary>

| Capability | |
|:---|:---|
| [**Inference endpoint enumeration**](docs/INDEX.md) <br> [code](modules/llm_enum.py) | Probe supported Ollama, LM Studio, LocalAI, Hugging Face and OpenAI-compatible services. |
| [**LLM behavior/security probes**](docs/INDEX.md) <br> [code](modules/llm_enum.py) | Test supported prompt-disclosure/injection, unsafe-output, excessive-agency and sensitive-information surfaces. |
| [**Model/data pipeline exposure**](docs/INDEX.md) <br> [code](modules/llm_enum.py) | Inspect model metadata, upload/fine-tune endpoints, RAG/vector-store/knowledge-graph and memory-poisoning surfaces. |
| [**Agent protocol exposure**](docs/INDEX.md) <br> [code](modules/llm_enum.py) | Probe supported MCP/A2A authentication, tool-schema, trust-boundary and orchestration interfaces. |
| [**AI control indicators**](docs/INDEX.md) <br> [code](modules/llm_enum.py) | Gather selected OWASP LLM, ATLAS and incident-response/posture indicators through implemented probes. |
| [**MCP manifest grammar fuzzing**](docs/INDEX.md) <br> [code](modules/mcp_grammar_fuzzer.py) | Atheris harness and seed validation for tool names, descriptions and schemas with prompt-injection indicators. |

</details>

<details>
<summary><strong>Research and payload-development helpers</strong></summary>

| Capability | |
|:---|:---|
| [**Shellcode templates**](docs/INDEX.md) <br> [code](ablation/core/shellcode_utils.py) · [code](modules/bare_adapter.py) | Supplied x86/x86-64/ARM64 shell and staged-loader construction helpers. |
| [**Payload formatting**](docs/INDEX.md) <br> [code](ablation/core/shellcode_utils.py) · [code](modules/bare_adapter.py) | Bad-byte checks, XOR/ADD encoding, NOP generation and buffer assembly helpers. |
| [**Crash-offset and ROP helpers**](docs/INDEX.md) <br> [code](ablation/core/shellcode_utils.py) · [code](modules/bare_adapter.py) | Cyclic patterns/offset lookup, common gadget detection and a minimal x86-64 chain-construction helper. |
| [**Exploitability-context checks**](docs/INDEX.md) <br> [code](ablation/core/shellcode_utils.py) · [code](modules/bare_adapter.py) | Helpers inspect canary, NX/ASLR and selected format-string indicators. |
| [**BARE integration**](docs/INDEX.md) <br> [code](ablation/core/shellcode_utils.py) · [code](modules/bare_adapter.py) | Convert supported findings for the external BARE tool to rank related Metasploit modules. |

</details>

<details>
<summary><strong>Assistant integration and workflow machinery</strong></summary>

| Capability | |
|:---|:---|
| [**LLM analyst loop**](docs/reference-modules/llm.md) <br> [code](ablation/analyzers/llm_analyst/agent_loop.py) · [code](ablation/analyzers/llm_analyst/rag_retriever.py) | Optional Claude tool-calling analysis loop with bounded iterations and stored results. |
| [**Prior-finding retrieval**](docs/INDEX.md) <br> [code](ablation/analyzers/llm_analyst/agent_loop.py) · [code](ablation/analyzers/llm_analyst/rag_retriever.py) | Supply related function identities/findings as context for subsequent analysis. |
| [**Assisted function naming**](docs/INDEX.md) <br> [code](ablation/analyzers/llm_analyst/agent_loop.py) · [code](ablation/analyzers/llm_analyst/rag_retriever.py) | Propose and batch-process names from strings, callees and prior evidence. |
| [**Assisted structure reconstruction**](docs/INDEX.md) <br> [code](ablation/analyzers/llm_analyst/agent_loop.py) · [code](ablation/analyzers/llm_analyst/rag_retriever.py) | Extract memory-access offsets/widths and propose structure layouts. |
| [**Assisted vulnerability hypotheses**](docs/INDEX.md) <br> [code](ablation/analyzers/llm_analyst/agent_loop.py) · [code](ablation/analyzers/llm_analyst/rag_retriever.py) | Generate candidate explanations of suspicious function behavior for later validation. |
| [**Evidence scoring and probe ranking**](docs/INDEX.md) <br> [code](ablation/analyzers/probe_ranker.py) · [code](ablation/analyzers/probe_adapters.py) | Weight evidence families, track contradictions/uncertainty and rank useful next analyses. |
| [**Analyzer probe adapters**](docs/INDEX.md) <br> [code](ablation/analyzers/probe_ranker.py) · [code](ablation/analyzers/probe_adapters.py) | Dispatch supported disassembly, CFG, xref, lifting, semantic, version, taint and manual evidence probes. |
| [**Stage commitments and audit trail**](docs/reference-modules/stage-commitment.md) <br> [code](ablation/analyzers/probe_ranker.py) · [code](ablation/analyzers/probe_adapters.py) | Hash stage artifacts, record approval states and verify persisted commitments. |
| [**Structured workflow documents**](docs/reference-modules/workflow-document.md) <br> [code](ablation/analyzers/probe_ranker.py) · [code](ablation/analyzers/probe_adapters.py) | Validate stage outputs, advance through configured transitions and serialize/reload sessions. |

</details>

<details>
<summary><strong>Outputs, integration and project tooling</strong></summary>

| Capability | |
|:---|:---|
| [**JSON and SARIF export**](docs/INDEX.md) <br> [code](ablation/export/json_export.py) · [code](ablation/export/sarif.py) | Export supported sweep/finding records to structured JSON or SARIF 2.1.0. |
| [**Markdown research reports**](docs/INDEX.md) <br> [code](ablation/export/json_export.py) · [code](ablation/export/sarif.py) | Render ranked sweep results, prior-finding correlations and verification notes. |
| [**Binary Ninja plugin**](docs/INDEX.md) <br> [code](ablation/export/json_export.py) · [code](ablation/export/sarif.py) | Apply corpus names, launch semantic search/sweeps and show stored findings inside Binary Ninja. |
| [**Terminal presentation**](docs/INDEX.md) <br> [code](ablation/export/json_export.py) · [code](ablation/export/sarif.py) | Colored/plain output, boxes and structured terminal reports. |
| [**Documentation prose checks**](docs/INDEX.md) <br> [code](ablation/export/json_export.py) · [code](ablation/export/sarif.py) | Lint documentation against configured writing-style patterns. |
| [**Generic vulnerability-profile sweeps**](docs/INDEX.md) <br> [code](sweeps/base_sweep.py) · [code](sweeps/fortinet_sweep.py) | Encode discovered functions and rank candidates against configured vulnerability profiles plus prior findings. |
| [**Fortinet multi-phase directory sweeps**](docs/INDEX.md) <br> [code](sweeps/base_sweep.py) · [code](sweeps/fortinet_sweep.py) | Prefilter ELF files by relevant imports and run the supported semantic, sink and follow-on analysis stages. |
| [**Bundled finding/signature seeds**](docs/INDEX.md) <br> [code](sweeps/base_sweep.py) · [code](sweeps/fortinet_sweep.py) | Ship initial finding and function-signature data to populate or bootstrap local analysis libraries. |
| [**Dependency and supply-chain tooling**](docs/INDEX.md) <br> [code](scripts/audit-deps.sh) · [code](scripts/generate-lockfile.sh) | Scripts for dependency auditing, hash-pinned requirements, SBOM generation and monitoring. |
| [**CI and release automation**](docs/INDEX.md) <br> [code](scripts/audit-deps.sh) · [code](scripts/generate-lockfile.sh) | Repository workflows for configured checks, coverage and package publishing. |

</details>

<details>
<summary><strong>30 Decompilers</strong></summary>

<details>
<summary><strong>Native CPUs</strong> </summary>

| ISA | Variants |
|---|---|
| [**x86**](docs/reference-modules/binary-lifter.md) | x86-32 · x86-64 |
| [**ARM**](docs/reference-modules/binary-lifter.md) | ARM-32 · ARM-64 · Thumb |
| [**MIPS**](docs/reference-modules/binary-lifter.md) | MIPS-32 · [nanoMIPS](docs/reference-modules/nanomips.md) · MIPS-64 |
| [**PowerPC**](docs/reference-modules/ppc32-taint-tracker.md) | PPC-32 · PPC-64 · [VLE](docs/reference-modules/ecu-vle-decoder.md) · [PPC476 Book E](docs/reference-modules/ppc476-lifter.md) |
| [**RISC-V**](docs/reference-modules/binary-lifter.md) | RV32 · RV64 · [HiSilicon ext](docs/reference-modules/hisi-rv32-ext.md) |
| [**ARC**](docs/reference-modules/binary-lifter.md) | ARC EM/HS |
| [**LoongArch**](docs/reference-modules/loongarch64.md) | LoongArch64 |
| [**Intel MCS**](docs/reference-modules/isa-8051.md) | 8051 |

</details>

<details>
<summary><strong>Automotive ECUs</strong> </summary>

| ISA | Variants |
|---|---|
| [**V850 / RH850**](docs/reference-modules/rh850-taint-tracker.md) | V850-32 · RH850 |
| [**Renesas SH**](docs/reference-modules/binary-lifter-sh2a.md) | SH-2A |
| [**Motorola**](docs/reference-modules/ecu-m68k-decoder.md) | M68K / CPU32 · [MC88100](docs/reference-modules/m88k-decoder.md) |
| [**Infineon**](docs/reference-modules/tricore-taint-tracker.md) | TriCore TC1.6x |
| [**TI DSP**](docs/reference-modules/ecu-c28x-decoder.md) | TMS320C28x |

</details>

<details>
<summary><strong>VMs & Runtimes</strong> </summary>

| ISA | Variants |
|---|---|
| [**DEX**](docs/reference-modules/android.md) | Dalvik · ART |
| [**ARK**](docs/reference-modules/harmonyos.md) | ArkTS |
| [**MicroPython**](docs/reference-modules/mpy-lifter.md) | .mpy v6 |

</details>

</details>
