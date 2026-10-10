<img src="assets/ablation-1b-riveted-plate-wordmark-transparent-2560.png" width="520" alt="ABLATION">

![](https://komarev.com/ghpvc/?username=Ablation-Tool&color=grey) [![NIST SP 800-218](https://img.shields.io/badge/NIST%20SP%20800--218-SSDF-grey)](docs/ABLATION-STANDARDS.md) [![CISA Secure by Design](https://img.shields.io/badge/CISA-Secure%20by%20Design-grey)](docs/ABLATION-STANDARDS.md) [![MIL-HDBK-115C](https://img.shields.io/badge/MIL--HDBK--115C-Compliant-grey)](docs/ABLATION-STANDARDS.md)


Ablation is a self-contained reverse engineering framework.

It depends on neither legacy tools nor an MCP server, which removes the attack surface associated with MCP.

When used with Codex or Claude Code, it operates as an autonomous reverse engineering system.



---

![demo](assets/screencast-2026-09-30.gif)

## Capabilities

<details>
<summary><strong>Analysis:</strong> semantic search, binary lifting, hypothesis engine, C++ vtable reconstruction, cross-library tracing, DAG adapter</summary>

| Capability | |
|:---|:---|
| [**Semantic Code Search**](docs/module-reference/semantic-search.md) | Finds functions by describing what they do because stripped binaries have no symbols to search. Queries are scoped to the target binary so results return in under a second. |
| [**On-Demand Analysis**](docs/module-reference/on-demand-analysis.md) | Loads in seconds because it only analyzes the code being examined. Traditional disassemblers parse the entire file into a database before you can do anything. |
| [**Binary Lifting**](docs/module-reference/binary-lifter.md) | Translates machine code to readable pseudo-C across 19 architectures. ARM64 and x86-64 get register-level taint tracking so data flow is visible in the lifted output. |
| [**Hypothesis Engine**](docs/module-reference/hypothesis-engine.md) | Tracks competing theories about what a function does and scores evidence against each one. Sessions persist across engagements so analysis resumes where it left off. |
| [**C++ Vtable Reconstruction**](docs/module-reference/cpp-vtable-reconstructor.md) | Recovers C++ virtual dispatch tables from stripped ELF binaries on any architecture and names each slot. A generated type-annotation script propagates slot names through every call site so the decompiler shows method names instead of function pointer offsets. |
| [**Cross-Library Analysis**](docs/module-reference/taint-analysis.md) | Traces an argument across up to three shared library hops so taint paths that cross library boundaries reach their sink rather than stopping at the first call. |
| [**DAG Adapter Language**](docs/module-reference/encoding-dag.md) | Describes instruction set encodings as directed acyclic graphs so every architecture shares the same analysis code path. Without it, each ISA requires its own exception handler and the analyzer count scales with the architecture count. |

</details>

<details>
<summary><strong>Security Analysis:</strong> taint analysis, exposure mapping, finding validation, source code auditing, compiler defect detection, cryptographic analysis</summary>

| Capability | |
|:---|:---|
| [**Taint Analysis**](docs/module-reference/taint-analysis.md) | Follows network input through the call graph to security-sensitive sinks across 14 architectures. Library call sites do not stop the trace because register-level tracking resolves shared library stubs. |
| [**Pre-Authentication Exposure**](docs/module-reference/preauth-exposure.md) | Finds every code path from the network entry point to a security-sensitive operation that runs before authentication. Manual review starts at the authentication boundary because the output is a reachability map, not a raw disassembly. |
| [**Finding Validation**](docs/module-reference/preauth-exposure.md) | Generates a working HTTP request that reproduces each confirmed finding at the protocol level. The request includes the expected response delta and CWE classification so a PSIRT submission arrives with working proof. |
| [**Source Code Auditing**](docs/module-reference/source-audit.md) | Scores every source file by risk and batches the low-risk ones so manual review covers only the files most likely to contain vulnerabilities. |
| [**Compiler Defect Detection**](docs/module-reference/compiler-defects.md) | Finds security defects that the compiler introduced through miscompilation. Optimizer defects that silently select the wrong comparison operand can produce hundreds of confirmed vulnerabilities across a single firmware image. |
| [**Cryptographic Analysis**](docs/module-reference/crypto.md) | Recovers cryptographic key material directly from compiled firmware and audits TLS and JWT configurations, so cryptographic findings do not require source access or a decryption oracle. |

</details>

<details>
<summary><strong>Runtimes & Formats:</strong> LoongArch64, nanoMIPS, Windows PE, BYOVD drivers, Android, Erlang/BEAM, Go, game engines, firmware</summary>

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

</details>

<details>
<summary><strong>Workflow:</strong> version diffing, cross-target learning, module quality gate, coverage gate</summary>

| Capability | |
|:---|:---|
| [**Version Diffing**](docs/workflows/cross-version.md) | Checks whether the logic changed, not whether the file changed, so a cosmetic recompile cannot hide an unpatched vulnerability. |
| [**Cross-Target Learning**](docs/module-reference/cross-target-learning.md) | Every confirmed finding seeds future semantic searches, so the tool gets sharper with each engagement. |
| [**Module Quality Gate**](docs/module-reference/forge.md) | FORGE audits every user-written module before it can be stored, so local extensions meet the same standard as the modules that ship with Ablation. |
| [**Coverage Gate**](docs/ABLATION-STANDARDS.md) | The taint engine requires 85% statement coverage on every commit, so a regression in taint logic fails the test suite before it reaches a firmware engagement. |

</details>

---

## Decompilers

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

## Framework Architecture & Module Orchestration

<details>
<summary><strong>Target Binary</strong> — ELF · PE · firmware</summary>

```
              ┌──────────────────────────────┐
              │         Target Binary        │
              │      ELF · PE · firmware     │
              └──────────────────────────────┘
                              │
                            load
                              ▼
```

<details>
<summary><strong>BinaryContext</strong> — PLT · Strings · Call Graph · XRefs</summary>

```
              ┌──────────────────────────────┐
              │         BinaryContext        │
              │  PLT · Strings · Call Graph  │
              │       XRefs · CFG · Funcs    │
              └──────────────────────────────┘
                              │
                           context
                              ▼
```

<details>
<summary><strong>Claude Code</strong> — Central Orchestrator</summary>

```
         ┌────────────────────────────────────┐
         │       Claude Code (Orchestrator)   │
         └────────────────────────────────────┘
    ┌─────┬──────┬───────┬──────┬───────┬──────┐
    ▼     ▼      ▼       ▼      ▼       ▼      ▼
 Corpus Taint  Diffing FmtStr  Heap  Multi  Driver
  · · · · · · · · · findings · · · · · · · · · ·▶
```

<details>
<summary><strong>Analysis Engines</strong> — Semantic · Taint · Diffing · FmtStr · Heap · MultiArch · Driver</summary>

```
 ┌──────────────────┐     ┌────────────────────┐
 │   Corpus Builder │────▶│  Semantic Search   │
 │  embedding DB    │     │  BERT fingerprints │
 └──────────────────┘     └────────────────────┘
 ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
 │ Taint Engine │  │   Diffing    │  │ Format String│
 │ data flow    │  │  DTW · delta │  │  specifiers  │
 └──────────────┘  └──────────────┘  └──────────────┘
 ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
 │ Heap Scanner │  │  Multi-Arch  │  │ Driver Engine│
 │ chunk · UAF  │  │ MIPS·PPC·RV  │  │ IOCTL·BYOVD  │
 └──────────────┘  └──────────────┘  └──────────────┘
                          │
                     findings ──▶ Claude
```

<details>
<summary><strong>Finding Registry</strong> — cross-target corpus · seeds future sweeps</summary>

```
  Claude ──▶ ┌──────────────────────────┐
             │     Finding Registry     │
             │    cross-target corpus   │
             └──────────────────────────┘
                           │
                    seeds future sweeps
                           │
                           ▼
                    Semantic Search
```

Every confirmed finding enters the registry and sharpens the semantic search embeddings used on the next target. The tool improves with each engagement.

</details>
</details>
</details>
</details>
</details>

---

## Example RE Workflow

End-to-end analysis of stripped binaries from an RPM bundle. Extraction through BinaryContext, string xrefs, and capstone disassembly to confirmed findings.

<details>
<summary><strong>target-package.rpm</strong> — third-party bundle · x86-64</summary>

```
              ┌──────────────────────────────┐
              │      target-package.rpm      │
              │   third-party bundle x86-64  │
              └──────────────────────────────┘
                              │
                     rpm2cpio / cpio
                              ▼
                  platform/linux-x86_64/
```

<details>
<summary><strong>Extracted Binaries</strong> — inference_engine · controller · libcore.so · libruntime.so</summary>

```
         platform/linux-x86_64/
         ├── bin/inference_engine    stripped PIE · x86-64
         ├── bin/controller          stripped PIE · x86-64
         ├── lib/libcore.so
         └── lib/libruntime.so
                   │
         ┌─────────┼─────────┐
         ▼         ▼         ▼
    [inference]  [libs]  [controller]
```

<details>
<summary><strong>Inference Engine Track</strong> — BinaryContext · string xrefs · disasm</summary>

```
  BinaryContext.load_or_build()
  32 func starts · 551 strings · PLT built
                │
                ▼
  ctx.strings scan
  ├── api_op_read      VA 0x51560
  ├── api_op_write     VA 0x51570
  └── license_key_flag VA 0x52e08
                │
                ▼
  ctx.string_xrefs()
  ├── both ops xref → 0x17499, 0x174af
  └── ctx.func_containing() → init fn 0x10000
                │
                ▼
  capstone disasm 0x17450
  ├── lea rsi → api_op_read  · call set::insert
  └── lea rsi → api_op_write · call set::insert
      CONFIRMED: exactly 2 blocklist entries
                │
                ▼
  capstone disasm 0x16511
  ├── cmp qword ptr [r9], 0
  ├── je  → model loads
  └── ne  → handleFatal
      empty set = bypass confirmed ──▶ F1
```

</details>

<details>
<summary><strong>Library Analysis Track</strong> — nm · disasm · op scan</summary>

```
  nm -D libcore.so
  ├── spawn  0xfdb20
  └── ctor   0xfcfd0
                │
                ▼
  capstone disasm libcore.so:0xfdbc7
  ├── cmp entry length == exe_path length
  └── memcmp at 0xfdbdb
      proper equality check · no prefix bypass ──▶ F2

  re.findall api_op:: in libruntime.so
  ├── 2481 distinct ops found
  └── 2 blocked · 2479 unblocked ──▶ F1
```

</details>

<details>
<summary><strong>Controller Track</strong> — BinaryContext · spawn path · arg validation</summary>

```
  BinaryContext.load_or_build()
  18 func starts · PLT · strings
                │
                ▼
  ctx.string_xrefs() on 5 path strings
  ├── ./worker1  ./worker2  ./worker3
  ├── ./worker4  ./inference_engine
  └── all xref at 0x9a04-0x9a5e
                │
                ▼
  capstone disasm 0x99e9
  ├── call CApp::progDir()
  └── call OsUtils::chdir()
      chdir to binary dir before spawn
                │
                ▼
  capstone disasm 0x11500
  ├── args vector from command pipe tokens
  └── passed raw to spawn() at 0x11699
      no validation ──▶ F2
```

</details>

<details>
<summary><strong>Findings</strong> — F1 HIGH · F2 LOW · F3 INFO</summary>

```
  ┌─────────────────────────────────────────────────────┐
  │ F1 · HIGH                                           │
  │ blocklist covers 2 of 2481 ops                      │
  │ upload malicious model via API                      │
  │ seccomp BPF not decoded — CIA open                  │
  └─────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────────────────┐
  │ F2 · LOW                                            │
  │ controller spawn allowlist is sound                 │
  │ but args vector unchecked                           │
  │ requires service user pipe access                   │
  └─────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────────────────┐
  │ F3 · INFO                                           │
  │ license gate = JSON field only                      │
  │ no cryptographic verification                       │
  └─────────────────────────────────────────────────────┘
```

</details>

</details>
</details>

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

## Module Map

<details>
<summary><strong>Input Formats</strong> — ELF · PE · Firmware · .mpy · APK/DEX · BEAM/Erlang</summary>

```
┌────────┐ ┌───────────┐ ┌──────────┐ ┌──────┐ ┌─────────┐ ┌────────────┐
│  ELF   │ │ PE/Driver │ │ Firmware │ │ .mpy │ │ APK/DEX │ │BEAM/Erlang │
└────────┘ └───────────┘ └──────────┘ └──────┘ └─────────┘ └────────────┘
                                    │
                                    ▼
```

Ablation accepts native binaries, compiled bytecode, and firmware images. Each format is normalized through a common loading interface before analysis begins.

<details>
<summary><strong>BinaryContext</strong> — PLT · Strings · XRef · Call Graph · CFG</summary>

```
                        ┌──────────────────────────┐
                        │       BinaryContext       │
                        │  PLT · XRef · Call Graph  │
                        │    Strings · CFG · Func   │
                        └──────────────────────────┘
               ┌──────────────┼──────────────┐
               ▼              ▼              ▼
        Taint Engine      Analysis       Scanners
```

The foundation every analyzer builds on. Resolves PLT stubs, indexes strings with cross-references, maps function boundaries, and builds the call graph on demand rather than up front.

<details>
<summary><strong>Taint Engine</strong> — 16 ISAs</summary>

```
        ┌──────────────────────────────────────────┐
        │               Taint Engine               │
        ├──────────┬───────────┬───────────────────┤
        │ x86-32   │  ARM32    │  PPC32  │  MIPS32 │
        │ x86-64   │  ARM64    │  PPC64  │ nanoMIPS│
        ├──────────┼───────────┼─────────┴─────────┤
        │ RISC-V32 │ RISC-V64  │  ARC EM/HS        │
        │ LoongArch│  V850     │  TriCore · RH850   │
        └──────────┴───────────┴───────────────────┘
                              │
                              ▼
                         [ FORGE ]
```

Follows network input through the call graph to security-sensitive sinks. Library call sites do not stop the trace because register-level tracking resolves shared library stubs.

→ [Taint Analysis](docs/module-reference/taint-analysis.md)

</details>

<details>
<summary><strong>Analysis Modules</strong> — Semantic Search · Version Diffing · Hypothesis Engine · Vtable Recon</summary>

```
  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
  │ Semantic Search │  │ Version Diffing │  │Hypothesis Engine│
  │  BERT · <1s     │  │ logic · not file│  │evidence scoring │
  └─────────────────┘  └─────────────────┘  └─────────────────┘
  ┌─────────────────┐  ┌─────────────────────────────────────┐
  │  Vtable Recon   │  │       Cross-Target Learning         │
  │ stripped C++ ELF│  │  confirmed findings seed all sweeps │
  └─────────────────┘  └─────────────────────────────────────┘
                                    │
                                    ▼
                               [ FORGE ]
```

| Module | What it does |
|---|---|
| [Semantic Search](docs/module-reference/semantic-search.md) | Finds functions by describing what they do. Results in under a second because queries are scoped to the target binary. |
| [Version Diffing](docs/workflows/cross-version.md) | Checks whether logic changed, not whether the file changed. A cosmetic recompile cannot hide an unpatched vulnerability. |
| [Hypothesis Engine](docs/module-reference/hypothesis-engine.md) | Tracks competing theories about what a function does and scores evidence against each one. Sessions persist across engagements. |
| [Vtable Recon](docs/module-reference/cpp-vtable-reconstructor.md) | Recovers C++ virtual dispatch tables from stripped ELF. A generated annotation script propagates slot names through every call site. |
| [Cross-Target Learning](docs/module-reference/cross-target-learning.md) | Every confirmed finding seeds future semantic searches. The tool gets sharper with each engagement. |

</details>

<details>
<summary><strong>Security Scanners</strong> — Pre-Auth · Crypto · Heap · Format String · BYOVD · MpyLifter</summary>

```
  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
  │  Pre-Auth    │  │    Crypto    │  │     Heap     │
  │  Exposure    │  │   Analysis   │  │   Scanner    │
  └──────────────┘  └──────────────┘  └──────────────┘
  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
  │Format String │  │BYOVD / Kernel│  │  MpyLifter   │
  │   Scanner    │  │driver audit  │  │ .mpy v6 · RE │
  └──────────────┘  └──────────────┘  └──────────────┘
                              │
                              ▼
                         [ FORGE ]
```

| Scanner | What it does |
|---|---|
| [Pre-Auth Exposure](docs/module-reference/preauth-exposure.md) | Maps every path from the network entry point to a sensitive operation that runs before authentication. |
| [Crypto Analysis](docs/module-reference/crypto.md) | Recovers key material from compiled firmware. Audits TLS and JWT configurations without source access. |
| [Heap Scanner](docs/module-reference/binary-lifter.md) | Chunk and UAF audit across all supported architectures. |
| [Format String](docs/module-reference/binary-lifter.md) | Specifier scanner. Flags format string sinks reachable from tainted input. |
| [BYOVD / Kernel](docs/module-reference/kernel-drivers.md) | Classifies signed kernel drivers for BYOVD capability before deployment. |
| [MpyLifter](docs/module-reference/mpy-lifter.md) | Lifts .mpy v6 bytecode to pseudo-Python. Detects dangerous imports, exec/eval, and machine.mem32 across ESP32, STM32, and CC13xx firmware. |

</details>

<details>
<summary><strong>FORGE Quality Gate → Finding Registry</strong></summary>

```
  Taint Engine ──┐
  Analysis     ──┼──▶ ┌─────────────────┐     ┌──────────────────┐
  Scanners     ──┘    │  FORGE Quality  │────▶ │ Finding Registry │
                      │     Gate        │     │  cross-target    │
                      └─────────────────┘     └────────┬─────────┘
                                                        │
                                              seeds future sweeps
                                                        │
                                                        ▼
                                               Semantic Search
```

Every module and finding passes a 10-section audit before it can be stored. Confirmed findings enter the Finding Registry, which cross-references patterns across targets and seeds future semantic searches.

→ [FORGE](docs/module-reference/forge.md)

</details>

</details>
</details>

---

## Responsible Use

Ablation is built for authorized security research. Use it only against systems you own or have explicit written permission to test. Running it against systems without authorization violates computer fraud laws in most jurisdictions. The author is not responsible for misuse.
