<img src="assets/ablation-1b-riveted-plate-wordmark-transparent-2560.png" width="640" alt="ABLATION">

# Ablation Reverse Engineering Framework

![](https://komarev.com/ghpvc/?username=Ablation-Tool&color=grey)

Ablation is a reverse engineering framework that provides the exact same core disassembly, decompilation, and binary analysis capabilities as industry-standard tools like Ghidra, IDA Pro, and Binary Ninja. Combined with an LLM, it transforms into a fully autonomous reverse engineering tool.


Ablation is built for the modern landscape, and more importantly, the human.


Now reverse engineering is accessible to anyone. No matter your wallet or your barrier of entry into education, you can learn about reverse engineering as you reverse engineer.

---

![demo](assets/demo.gif)

---

## Framework Architecture & Module Orchestration

```mermaid
flowchart TD
    Binary(["<b>Target Binary</b><br/><i>ELF · PE · firmware</i>"])
    Claude(["<b>Claude Code (Orchestrator)</b><br/><i>Central Agent Controller</i>"])

    Binary -->|"load"| BCtx["<b>BinaryContext</b><br/><i>PLT · Strings · Call Graph · XRefs</i>"]
    BCtx -->|"context"| Corpus["<b>Corpus Builder</b><br/><i>Semantic Embedding DB</i>"]
    BCtx -->|"context"| Taint["<b>Taint Engine</b><br/><i>Data Flow / Sinks</i>"]
    BCtx -->|"context"| Diffing["<b>Diffing Engine</b><br/><i>DTW / Version Delta</i>"]
    BCtx -->|"context"| FmtStr["<b>Format String</b><br/><i>Specifier Scanner</i>"]
    BCtx -->|"context"| Heap["<b>Heap Scanner</b><br/><i>Chunk / UAF Audit</i>"]
    BCtx -->|"context"| MultiArch["<b>Multi-Arch Engine</b><br/><i>MIPS · PPC · RISC-V · ARC · V850</i>"]
    BCtx -->|"context"| Driver["<b>Driver Engine</b><br/><i>Kernel IOCTL / BYOVD Audit</i>"]

    Corpus -->|"embeddings"| Semantic["<b>Semantic Search</b><br/><i>BERT Behavioral Fingerprints</i>"]

    Semantic -. "candidates" .-> Claude
    Taint -. "findings" .-> Claude
    Diffing -. "findings" .-> Claude
    FmtStr -. "findings" .-> Claude
    Heap -. "findings" .-> Claude
    MultiArch -. "findings" .-> Claude
    Driver -. "findings" .-> Claude

    Claude -->|"confirmed finding"| Registry["<b>Finding Registry</b><br/><i>Cross-Target Corpus</i>"]
    Registry -->|"seeds future sweeps"| Semantic

    classDef primary fill:#2a1a4a,stroke:#7c3aed,stroke-width:2px,color:#fff
    classDef foundation fill:#0d1117,stroke:#58a6ff,stroke-width:2px,color:#e5e7eb
    classDef engine fill:#171717,stroke:#404040,stroke-width:1px,color:#e5e7eb
    classDef feedback fill:#0d2818,stroke:#238636,stroke-width:2px,color:#e5e7eb

    class Claude,Binary primary
    class BCtx foundation
    class Corpus,Semantic,Taint,Diffing,FmtStr,Heap,MultiArch,Driver engine
    class Registry feedback
```

---

## Local Decompilers

```mermaid
mindmap
  root((Local Decompilers))
    x86 Family
      x86 - 32
      x86 - 64
    ARM Family
      ARM - 32
      ARM - 64
    MIPS Family
      MIPS 32+nM
      MIPS - 64
    PowerPC Family
      PPC - 32
      PPC - 64
    RISC-V Family
      RISC-V 32
      RISC-V 64
    Embedded / Other
      ARC EM/HS
      V850 - 32
```

---

## The Core Capabilities

- **Semantic Search via BERT:** Semantic search finds results based on meaning rather than exact keywords. BERT reads text and figures out what it means. Similar meanings get similar scores, so you can search by concept instead of exact words. By combining the two, it speeds up the main bottleneck of reverse engineering while finding the vulnerable functions.
- **Extreme Performance:** A 50 MB binary loads in 35 seconds. Ghidra and IDA Pro can take hours because they parse the entire file into a database before you can do anything. Ablation only analyzes the functions you are actively working on, so you start immediately.
- **Version Diffing:** Utilizing the Jaccard method to measure how much a function's behavior overlaps between releases and Dynamic Time Warping that tracks the "shape" of how a function executes across those versions of firmware or software that a vendor updated, Ablation confirms whether a patch actually changed the logic or just the packaging, because a cosmetic recompile can't hide an unpatched vulnerability.
- **Cross-Binary Analysis:** Analyze every shared library in a firmware image simultaneously, tracking data flows across binary boundaries.

---

## Specialized Attack Surface Scanners

- **Format String:** Uses backward tracing to mathematically prove whether a format argument is a safe string literal stored in read-only memory, or a vulnerable stack slot/argument register.
- **Heap Analysis:** Actively scans for integer overflows occurring immediately before an allocation, as well as use-after-free and double-free conditions.
- **MIPS32 Taint Tracking:** Traces data originating from network boundaries (`recv`/`read`) straight to system sinks (`execve`/`system`), accounting for MIPS-specific quirks like load-delay slots and endianness.
- **Windows Kernel Drivers:** Extracts IRP/IOCTL dispatch tables, scans for rootkit callbacks, checks for SMEP disablement, and scores drivers for Bring Your Own Vulnerable Driver (BYOVD) primitives.

---

## Encryption Analysis

- **Entropy Mapper:** Finds encrypted, compressed, or packed sections in a binary.
- **Crypto Audit:** Scans for weak or broken cryptography including JWT alg:none, weak secrets, embedded key material, and outdated TLS versions and ciphers.
- **XorSolver:** Recovers XOR cipher keys using known-plaintext attacks and frequency analysis, then decrypts the target section.

---

## Feature Comparison vs. Legacy Tools

**Everything legacy tools have**

| Feature | Ablation | Ghidra | IDA Pro | Binary Ninja |
|---|:---:|:---:|:---:|:---:|
| Disassembler | ✅ | ✅ | ✅ | ✅ |
| Decompiler | ✅ | ✅ | ✅ | ✅ |
| Scripting API | ✅ | ✅ | ✅ | ✅ |
| Multi-Architecture | ✅ | ✅ | ✅ | ✅ |
| Binary Diffing | ✅ | ✅ | ✅ | ✅ |

**Capabilities legacy tools don't have**

| Feature | Ablation | Ghidra | IDA Pro | Binary Ninja |
|---|:---:|:---:|:---:|:---:|
| Semantic Search | ✅ | ❌ | ❌ | ❌ |
| Autonomous Loop | ✅ | ❌ | ❌ | ❌ |
| Pattern Library | ✅ | ❌ | ❌ | ❌ |
| Cross-Binary Taint Tracking | ✅ | ❌ | ❌ | ❌ |
| Version Diffing via DTW | ✅ | ❌ | ❌ | ❌ |
| Finding Registry | ✅ | ❌ | ❌ | ❌ |
| Load Time (50 MB) | **35 sec** | 1-4 hrs | Heavy DB | Heavy DB |
| Cost | **Open Source** | Free / OSS | $3,000+ | Commercial |

---

## The Autonomous Loop

When executing commands like `ablation sweep firmware.so --json results.json`, Claude Code can interpret the JSON, identify suspicious functions, and automatically pivot to run `ablation cfg` to visualize logic or `ablation taint` to verify reachability.

This ReAct loop using `claude-sonnet-5` for decompilation effectively replaces the junior analyst role during triage, surfacing only confirmed, exploitable paths for human review.

**Recommended model:** `claude-sonnet-4-6` (released January 2026).

```
/model claude-sonnet-4-6
```

---

## Real-World Results

Ablation has been used to analyze production firmware and kernel drivers from Fortinet, Cisco, Axis, Fujitsu, MikroTik, Orka, TencentOS, Enigma2, and Skydio.

Following coordinated disclosure on Cisco FMC and ISE, the Cisco Product Security Incident Response Team (PSIRT) has adopted Ablation for internal vulnerability triage. Cisco PSIRT is actively using it to triage ongoing disclosure reports across Firepower Threat Defense (FTD), Cisco Secure Client (AnyConnect), HyperFlex, and Catalyst. Cisco Adaptive Security Appliance (ASA) LINA has also been reverse engineered using Ablation, with findings currently under coordinated triage via CERT/CC VINCE.

| CVE | Product | Title | CVSS | Advisory |
|---|---|---|---|---|
| CVE-2026-76420 | Secure Firewall Management Center (FMC) | Peer Impersonation | 9.0 Critical | [cisco-sa-fmc2-multivulns-HXgcqRG](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fmc2-multivulns-HXgcqRG) |
| CVE-2026-76412 | Secure Firewall Management Center (FMC) | Privilege Escalation to root | 8.5 High | [cisco-sa-fmc2-multivulns-HXgcqRG](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fmc2-multivulns-HXgcqRG) |
| CVE-2026-76413 | Secure Firewall Management Center (FMC) | Single Sign-On Token Forgery | 8.5 High | [cisco-sa-fmc2-multivulns-HXgcqRG](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fmc2-multivulns-HXgcqRG) |
| CVE-2026-76447 | Identity Services Engine (ISE) | OCSP Responder Authentication Bypass | 5.3 Medium | [cisco-sa-ise-multiauth-bypass-sgD2HbL4](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-multiauth-bypass-sgD2HbL4) |

---

## Example: Elasticsearch 8.19.19 x-pack-ml RE Workflow

End-to-end analysis of the ML native binaries bundled in FortiSOAR 8.0.0, from RPM extraction through BinaryContext, string xrefs, and capstone disassembly to confirmed findings.

```mermaid
flowchart TD
    RPM["elasticsearch-8.19.19-x86_64.rpm<br/>649MB · FortiSOAR 8.0.0 third-party bundle"]

    RPM -->|rpm2cpio / cpio| EXTRACT["x-pack-ml/platform/linux-x86_64/"]

    EXTRACT --> PI["bin/pytorch_inference<br/>397KB · stripped PIE · x86-64"]
    EXTRACT --> CTRL["bin/controller<br/>128KB · stripped PIE · x86-64"]
    EXTRACT --> LIBS["lib/libMlCore.so<br/>lib/libtorch_cpu.so"]

    subgraph TRACK_PI ["pytorch_inference track"]
        direction TB
        BCI["BinaryContext.load_or_build()<br/>32 func starts · 551 strings · PLT built"]
        BCI --> SS["ctx.strings scan<br/>aten::from_file VA 0x51560<br/>aten::save VA 0x51570<br/>validElasticLicenseKeyConfirmed 0x52e08"]
        SS --> XREF["ctx.string_xrefs()<br/>both ops xref → 0x17499, 0x174af<br/>ctx.func_containing() → init fn 0x10000"]
        XREF --> DA1["capstone disasm 0x17450<br/>lea rsi → aten::from_file · call set::insert<br/>lea rsi → aten::save · call set::insert<br/>CONFIRMED: exactly 2 blacklist entries"]
        DA1 --> DA2["capstone disasm 0x16511<br/>cmp qword ptr [r9], 0<br/>je → model loads · ne → handleFatal<br/>empty set = bypass confirmed"]
    end

    subgraph TRACK_LIBS ["library analysis"]
        direction TB
        NM["nm -D libMlCore.so<br/>spawn at 0xfdb20 · ctor at 0xfcfd0"]
        NM --> DA3["capstone disasm libMlCore.so:0xfdbc7<br/>cmp entry length == exe_path length<br/>memcmp at 0xfdbdb<br/>proper equality check · no prefix bypass"]
        LSCAN["re.findall aten:: in libtorch_cpu.so<br/>2481 distinct ops found<br/>2 blocked · 2479 unblocked"]
    end

    subgraph TRACK_CTRL ["controller track"]
        direction TB
        BCC["BinaryContext.load_or_build()<br/>18 func starts · PLT · strings"]
        BCC --> XREF2["ctx.string_xrefs() on 5 path strings<br/>./autodetect · ./categorize<br/>./data_frame_analyzer · ./normalize<br/>./pytorch_inference<br/>all xref at 0x9a04-0x9a5e"]
        XREF2 --> DA4["capstone disasm 0x99e9<br/>call CProgName::progDir()<br/>call COsFileFuncs::chdir()<br/>chdir to binary dir before spawn"]
        DA4 --> DA5["capstone disasm 0x11500<br/>args vector from command pipe tokens<br/>passed raw to spawn() at 0x11699<br/>no validation"]
    end

    PI --> BCI
    PI --> BCC
    LIBS --> NM
    LIBS --> LSCAN

    DA2 --> F1
    LSCAN --> F1["F1 · HIGH<br/>verifySafeModel blocks 2 of 2481 ops<br/>upload malicious .pt via ML API<br/>seccomp BPF not yet decoded, CIA impact open"]

    DA3 --> F2
    XREF2 --> F2["F2 · LOW<br/>controller spawn allowlist is sound<br/>but args vector unchecked<br/>requires elasticsearch user pipe access"]

    DA5 --> F2

    SS --> F3["F3 · INFO<br/>license gate = JSON field only<br/>no cryptographic verification"]

    classDef finding fill:#1a1a2e,stroke:#e94560,stroke-width:2px,color:#fff
    classDef tool fill:#16213e,stroke:#0f3460,stroke-width:1px,color:#e5e7eb
    classDef binary fill:#0f3460,stroke:#533483,stroke-width:2px,color:#fff
    classDef input fill:#533483,stroke:#7c3aed,stroke-width:2px,color:#fff

    class F1,F2,F3 finding
    class BCI,BCC,NM,LSCAN,SS,XREF,XREF2,DA1,DA2,DA3,DA4,DA5 tool
    class PI,CTRL,LIBS binary
    class RPM,EXTRACT input
```

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

## Feedback

Reach out directly. If there's anything you'd like added or improved on or just report a bug.

- [Open an issue](https://github.com/Ablation-Tool/ablation/issues) on GitHub
- X: [@ablation_tool](https://x.com/ablation_tool)
- Signal: [@deadbug.06](https://signal.me/#p/deadbug.06)
- Email: ablation@nuclide-research.com

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

---

## Reference Material Used to Build Ablation

**Books** (All obtained from O'Reilly Media | [www.oreilly.com](https://www.oreilly.com))

| Title | Author |
|---|---|
| The Art of Software Security Assessment | Dowd, McDonald, Schuh |
| Practical Binary Analysis | Dennis Andriesse |
| Practical Malware Analysis | Sikorski, Honig |
| Practical Reverse Engineering | Dang, Gazet, Bachaalany |
| Hacking: The Art of Exploitation (2e) | Jon Erickson |
| Learning Linux Binary Analysis | Ryan O'Neill |
| Windows Internals Part 1 & 2 | Yosifovich, Russinovich |
| Rootkits: Subverting the Windows Kernel | Hoglund, Butler |
| Advanced Compiler Design and Implementation | Muchnick |
| Engineering a Compiler | Cooper, Torczon |
| Security Engineering (3rd ed.) | Ross Anderson |
| Practical IoT Hacking | Chantzis et al. |
| The Art of Mac Malware | Patrick Wardle |
| Mathematical Concepts and Methods in Modern Biology | Robeva, Hodge |

**Research Papers**

| Title | Authors |
|---|---|
| [Finding Taint-Style Vulnerabilities in Linux-based Embedded Firmware with SSE-based Alias Analysis](https://arxiv.org/abs/2109.12209) | Cheng, Zheng, Liu, Guan, Liu, Li, Zhu, Ye, Sun |
| [iResolveX: Multi-Layered Indirect Call Resolution via Static Reasoning and Learning-Augmented Refinement](https://arxiv.org/abs/2601.17888) | Santra et al. |
| [Extracting Protocol Format as State Machine via Controlled Static Loop Analysis](https://arxiv.org/abs/2305.13483) | Shi, Xu, Zhang [@qingkaishi](https://github.com/qingkaishi) |
| [NEMETYL: Message Type Identification of Binary Network Protocols using Continuous Segment Similarity](https://arxiv.org/abs/2002.03391) | Kleber et al. [@vs-uulm](https://github.com/vs-uulm) |
| [Imperfect Forward Secrecy: How Diffie-Hellman Fails in Practice](https://dl.acm.org/doi/10.1145/2810103.2813707) | Adrian et al. [@dadrian](https://github.com/dadrian) |
| [Nonce-Disrespecting Adversaries: Practical Forgery Attacks on GCM in TLS](https://www.usenix.org/conference/woot16/workshop-program/presentation/bock) | Böck et al. [@hannob](https://github.com/hannob) |
| [Whitening Sentence Representations for Better Semantics and Faster Retrieval](https://arxiv.org/abs/2103.15316) | Su et al. [@bojone](https://github.com/bojone) |
| [Constant Propagation with Conditional Branches](https://dl.acm.org/doi/abs/10.1145/103135.103136) | Wegman, Zadeck |
| [A Simple, Fast Dominance Algorithm](https://www.cs.princeton.edu/techreports/2005/737.pdf) | Cooper, Harvey, Kennedy |
| [libdft: Practical Dynamic Data Flow Tracking for Commodity Systems](https://dl.acm.org/doi/10.1145/2151024.2151042) | Kemerlis et al. [@vkemerlis](https://github.com/vkemerlis) |

**Honorable Mention**

Microsoft Excel (Data Analysis ToolPak) When analyzing closed infrastructure or securing black-box systems, this exact process is called timing analysis or telemetry reverse engineering. Without source code, the Data Analysis ToolPak mathematically deconstructs how an application works on the backend by strictly observing its inputs and outputs.
