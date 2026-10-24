# Ablation Capability Taxonomy — Phase 1 Audit

**Date:** 2026-10-24  
**Source:** 402 capability records extracted from 20 unit notes files (A01–S01).  
**Method:** Bottom-up collapse of 272 raw category strings from notes into 10 top-level groups.

---

## Final Taxonomy (10 Top-Level Groups)

| # | Group | Capabilities | Notes |
|---|-------|-------------|-------|
| 1 | Binary Parsing & Session Infrastructure | 36 | Foundation layer: parse-once, cache, BinaryContext |
| 2 | Control Flow & ISA Models | 39 | CFG builders, ISA/ABI models, decoders, dataflow |
| 3 | Taint Analysis | 38 | Source-to-sink taint trackers, all architectures |
| 4 | Sink Classification | 17 | SinkArgClassifier variants, sanitizers, PE/static sinks |
| 5 | Vulnerability Scanners | 100 | Specific vuln-class detectors across all arches/formats |
| 6 | Firmware Extraction & Decryption | 19 | Unpacking, XOR recovery, container parsing |
| 7 | Platform-Specific Analysis | 88 | ECU/automotive, mobile, Go, IBM legacy, PS3/Cell BE |
| 8 | Semantic Search & Learning | 30 | Embeddings, pattern replay, LLM analysis, hypothesis engine |
| 9 | Host & Network Enumeration | 18 | Docker/K8s, network, forensics, SIP, lateral movement |
| 10 | Session Management & Tooling | 17 | FORGE, workflows, caching, sweeps, vendor config |
| — | **Total** | **402** | |

---

## Group Definitions and Category Mappings

### Group 1: Binary Parsing & Session Infrastructure (36)

**What it covers:** The BinaryContext parse-and-cache layer, format-specific binary parsers
(ELF, PE, XCOFF, M88K COFF, Mach-O), disassembly engines, and cross-reference indexing.
Every downstream tool receives a BinaryContext; this group owns that contract.

**Units primarily contributing:** A01 (11), C01 (25)

**Old category strings mapped here:**
- `Binary Parsing / Session Infrastructure`
- `Binary Lifting / Decompilation`
- `Language Runtime Analysis / BEAM`
- `Control Flow Analysis`
- `Binary Analysis / Cross-Reference`
- `Binary Analysis / Entropy`
- `Manual Review / Disassembly`
- `Program Analysis / Dataflow`
- `Decompilation / Control Flow Structuring`
- `Decompilation / Expression Lifting`
- `ISA Modeling / Instruction Encoding`
- `XCOFF32/64 Symbol Table Parser / BinaryContext Populator`
- `ELF32 BE Utility Wrapper`
- `Shared Encoding Utility`

---

### Group 2: Control Flow & ISA Models (68)

**What it covers:** CFG builders for all 10+ ISAs, per-arch ISA/ABI models, instruction
decode backends (insn_*.py), dataflow analysis engines (reaching defs, constant prop),
dominator analysis, function discovery, and function start scanners.

**Units primarily contributing:** A02 (19), A03 (20), A10 partial (ECU CFG/decoders mapped to Group 7)

**Old category strings mapped here:**
- `CFG Construction` (10 records)
- `CFG Dataflow Analysis` (9 records)
- `ISA/ABI model` (10 records)
- `Instruction model / backend` (9 records)
- `ISA Decoder / ECU (pure-Python)` → split: standard ISAs here, ECU-specific in Group 7
- `Function Discovery` (3 records)
- `ISA Detection / ECU` → Group 7
- `CFG / Function Boundary Analysis`
- `Instruction model / binary decoder`
- `Function Discovery + Naming`
- `Function Discovery + Naming (Linux kernel modules)`

---

### Group 3: Taint Analysis (41)

**What it covers:** All intraprocedural and interprocedural taint trackers — x86-64, x86-32,
ARM64, ARM32, MIPS32/64/nanoMIPS, PPC32/PPC64, RISC-V 32/64, ARC EM/HS, LoongArch64,
V850/RH850, TriCore, s390x. Includes labeled (annotation-enriched) variants, cross-binary
interprocedural chaining, BSS taint, and source-code taint trackers.

**Units primarily contributing:** A04 (11), A05 (12), A06 partial (taint variants)

**Old category strings mapped here:**
- `Taint Analysis` (6 records — x86-64/ARM64 core)
- `Taint Analysis / MIPS`, `Taint Analysis / MIPS64`, `Taint Analysis / MIPS (Labeled)`
- `Taint Analysis / nanoMIPS`
- `Taint Analysis / PPC32`, `Taint Analysis / PPC64`, `Taint Analysis / PPC (Labeled)`
- `Taint Analysis / RISC-V 32`, `Taint Analysis / RISC-V 64`, `Taint Analysis / RISC-V (Labeled)`
- `Taint Analysis / ARC`, `Taint Analysis / ARC (Labeled)`
- `Taint Analysis (labeled/bounded)` (2 records)
- `Taint Analysis / Cross-binary` (2 records)
- `Taint Analysis (specialized pattern)`
- `Taint Analysis (SAC upgrade)`
- `Taint Analysis (Windows kernel)`
- `Taint Analysis / Automotive ISA` (3 records)
- `Taint Analysis / Server ISA`
- `Taint Analysis — MIPS32; Function Profiling — MIPS32`
- `False-Positive Reduction / Taint Classification`
- `Call-Chain Taint Analysis`
- `Call-Chain Taint Analysis (Multi-level)`
- `Source Code Auditing / Taint Analysis`
- `EmTaint-inspired ARM64 SSE backward slicer — BSS/GOT writer finder`
- `IFDS-style demand-driven inter-procedural field-writer finder — ARM64`

---

### Group 4: Sink Classification (17)

**What it covers:** The SinkArgClassifier family — per-architecture classifiers that label
exec-sink call arguments as RODATA_CONST / SNPRINTF_RODATA / ARG_PROPAGATED / UNKNOWN.
Includes sanitizer detection/filtering, static-link sink scanning, network sink reachability,
and PE sink classification. This group is the primary filter before taint analysis runs.

**Units primarily contributing:** A07 (17)

**Old category strings mapped here:**
- (A07 records carry no explicit `category` field — all 17 records are from A07 and
  functionally constitute the Sink Classification group)
- `Verified PLT Import Caller Tracer`
- `BL Call-Site Scanner (stripped PPC64 BE)`
- `Sink Argument Classifier — PPC64 BE ELFv1`

---

### Group 5: Vulnerability Scanners (86)

**What it covers:** Single-purpose scanners targeting specific vulnerability classes:
command injection, format strings, heap corruption, SQL injection, sscanf overflow,
integer overflow/underflow, deprecated functions, privilege escalation, BYOVD, Windows
kernel drivers, web framework auth surfaces, source-code scanners (Lua, Perl, MCP),
build-time security gates, and compiler-bug detectors.

**Units primarily contributing:** A08 (25), A12 partial, A14 partial, M02 partial, M04 partial

**Old category strings mapped here:**
- `Vulnerability Detection / Format String`
- `Vulnerability Detection / Heap Corruption`
- `Vulnerability Detection / Heap Corruption / LoongArch64`
- `Vulnerability Detection / SQL Injection`
- `Vulnerability Detection / Code Injection / Source Analysis`
- `Vulnerability Detection / Shell Injection / Source Analysis`
- `Vulnerability Detection / Deprecated/Unsafe Functions`
- `Vulnerability Detection / Buffer Overflow / Input Parsing`
- `Vulnerability Detection / Integer Underflow / Protocol Parsing`
- `Vulnerability Detection / Integer Overflow / ARM32`
- `Vulnerability Detection / Privilege Escalation / POSIX` (2 records)
- `Vulnerability Detection / Process Analysis / Shell Injection`
- `Vulnerability Detection / Windows / BYOVD / Kernel Security`
- `Vulnerability Detection / Compiler Bug / LoongArch64`
- `Vulnerability Detection / Go Binary / Subprocess Injection`
- `Windows Kernel Driver Analysis / IOCTL Surface`
- `Attack Surface Classification / Linux Kernel Modules`
- `AI/MCP Security / Source Analysis`
- `Build System Integration / Post-Linker Security Gate`
- `Web Framework Analysis / Pre-Authentication Surface / Fortinet`
- `Web Framework Analysis / Apache Module Security`
- `Firmware-Specific Analysis / Fortinet CMDB / Attack Surface Triage`
- `Firmware-Specific Analysis / Fortinet / HTTP Method Enum Decoding`
- `Vulnerability Scanning / Privilege Escalation`
- `Vulnerability Scanning / Concurrency`
- `Vulnerability Scanner — Integer Handling` (3 records)
- `Vulnerability Scanner — Cryptographic Weakness` (2 records)
- `Vulnerability Scanner — Memory Corruption`
- `Vulnerability Scanner — Protocol Parsing`
- `Vulnerability Scanner — Authentication`
- `Vulnerability Scanner — CVE Pattern Matching`
- `Vulnerability Scanner — Exfiltration Risk`
- `Vulnerability Scanner — Side Channel`
- `Vulnerability Scanner — Concurrency`
- `Vulnerability Scanner — Race Condition`
- `Vulnerability Scanner — Process Injection (ATT&CK T1055)`
- `Vulnerability Scanner — Input Validation Bypass`
- `Vulnerability Scanner — Memory Safety`
- `Vulnerability Scanner — Logic Flaw (GotoFail)`
- `Vulnerability Scanner — Credential Exposure`
- `Vulnerability Scanner — Firmware Security (CWE-347)`
- `Vulnerability Scanner — Secure Boot / PKI`
- `Vulnerability Scanner / ECU`
- `Vulnerability Scanner / AI-MCU`
- `AI/LLM Security — Policy Controls`
- `Binary Hardening Analysis`
- `Supply Chain Security`
- `Software Composition Analysis`
- `Software Composition Analysis — FLIRT-style`
- `Hardware Analysis — MMIO Access`
- `Binary Analysis — Structural Integrity`
- `Binary Analysis — Packing Detection`
- `ABI Correctness / Vulnerability Scanner`
- `Dynamic Analysis / Behavioral Evidence`
- `Function Discovery / Dispatch Table Recovery`
- `Dead Code Detection / False-Positive Reduction`
- `Source Code Auditing / Auth Surface`
- `Source Code Auditing / Multi-tenant Security`
- `Source Code Auditing / Dangerous Sinks`
- `Source Code Auditing / Efficiency`
- `Source Code Auditing / Architectural Risk`

---

### Group 6: Firmware Extraction & Decryption (22)

**What it covers:** Firmware image extraction pipelines (FortiOS hardware, OVF/ZIP, partition
table parsing), XOR key recovery, cryptographic key extraction from firmware containers,
AIX installp/BFF archive decompression, Mac Classic resource forks.

**Units primarily contributing:** A09 partial (firmware extractors), A14 partial (XorSolver, BmpKeyExtractor)

**Old category strings mapped here:**
- `Firmware Unpacking / Container Parsing`
- `Firmware Unpacking / Fortinet`
- `Firmware Unpacking / Fortinet / Cryptography`
- `Firmware Analysis / Fortinet / Certificate Keys`
- `Firmware Analysis / Fortinet / Metadata Classification`
- `Firmware Unpacking / Fortinet / VM Disk`
- `Firmware Unpacking / AIX / XCOFF`
- `Firmware Unpacking / AIX / Compression Internals`
- `Binary Format Parsing / Legacy Executables`
- `Binary Format Parsing / Mac Classic / Resource Forks`
- `Binary Discovery / Archive Extraction`
- `Binary Discovery / Archive Extraction / Exec-Class Analysis`
- `Binary Discovery / Archive Extraction / AIX`
- `Firmware XOR Decryption`
- `Steganography / Key Extraction`
- `IBM AIX BFF archive decompressor`
- `Huawei VRP firmware squashfs v4 reader`
- `Self-extracting installer binary extractor`

---

### Group 7: Platform-Specific Analysis (65)

**What it covers:** All analysis tooling that targets a specific binary format or platform
beyond the standard ELF/PE coverage. Includes ECU automotive ISAs, Android/mobile (APK/DEX/ARK),
Go binary RE, IBM POWER legacy (PS3/Cell BE, PPC64 ELFv1 helpers), Windows PE security,
C++ vtable reconstruction, stripped Go analysis, Mac Classic PEF, XCOFF-based AIX.

**Units primarily contributing:** A10 (22), A11 (16), A13 (22 partial), M03 partial, M04 partial

**Old category strings mapped here:**
- `ISA Decoder / ECU (pure-Python)` (ECU-specific subset)
- `ISA Detection / ECU`
- `Function Discovery / ECU`
- `Vulnerability Scanner / ECU`
- `Automotive — CAN Protocol`
- `Automotive — ECU Calibration (Nissan/Pytrex)`
- `Platform-Specific Analysis — VxWorks PPC32`
- `HarmonyOS / ArkTS binary format parser`
- `ARK ISA bytecode disassembler`
- `ARK Bytecode → JavaScript-like pseudocode decompiler`
- `Android Binder IPC attack surface scanner`
- `Chrome/Edge/Firefox extension security auditor`
- `Android APK / DEX security scanner`
- `Android DEX bytecode disassembler (smali output)`
- `Android DEX → pseudo-Java IR lifter`
- `Electron application JS security scanner`
- `Go pclntab parser for function boundary recovery`
- `Go 1.17+ AMD64 string literal resolver`
- `Stripped x86-64 Go ELF function boundary recovery`
- `Java JAR/class constant-pool exec-class scanner`
- `Android JNI bridge surface scanner`
- `Batch native ELF library triage and security scoring`
- `Python .pyc bytecode dangerous-pattern scanner`
- `Windows PE Security / Control Flow Integrity`
- `Windows PE Security / Exception Handling`
- `Windows PE Security / EDR/Detection Coverage`
- `Windows PE Security / RPC Attack Surface`
- `Windows PE Security / COM Attack Surface`
- `Symbol Integration / Windows PE`
- `Windows malware / forensic binary analysis`
- `PS3/PPC64 ELFv1 C++ Vtable Scanner`
- `PS3 SELF Decryptor`
- `IBM XLC W-Code IR Parser`
- `Decompiler — IBM AIX XCOFF32 PPC32 BE`
- `Container Parser / Import Resolver`
- `Pseudo-code Lifter / Decompiler (Linear)`
- `Pseudo-code Lifter (Linear) — IBM PPC476 variant`
- `Decompiler (CFG-aware, typed)`
- `Verified PLT Import Caller Tracer` (PPC64 BE specific — Group 4 overlap)
- `BL Call-Site Scanner (stripped PPC64 BE)`
- `Sink Argument Classifier — PPC64 BE ELFv1`
- `Dynamic Data Structure Pattern Classifier`
- `ELFv1 OPD/glink Resolver`
- `Power10 PLT Stub Scanner`
- `VMX/AltiVec Density Scanner`
- `x86-64 Vtable Dispatch Site Scanner`
- `ARM64 Vtable Resolver (iResolveX-style)`
- `i386 R_386_PC32 Sink Scanner`
- `PPC32 Instruction Classifier (internal helper)`
- `PPC32 function discovery for stripped ELF binaries`
- `PPC32 GOT2 indirect call resolver`
- `PPC32 heap slot overflow pattern scanner`
- `Cell BE SPU (Synergistic Processing Unit) disassembler`
- `MCS-51 / Enhanced 8051 ISA model + CC254x bank resolver`
- `Java .class/.jar analysis + Spring actuator active probing`
- `Java .class/.jar RE — full constant pool parser + findings synthesis`
- `MicroPython .mpy v6 bytecode lifter + security scanner`
- `Bounded symbolic execution + Z3 path constraint solver — x86-64`
- `Video container forensics — polyglot/embedded payload detector`
- `XCOFF32/64 ELF RE surface analyzer`
- `XCOFF32/64 loader symbol standalone resolver`
- `Go binary RE — pclntab parser + vmnetd exploit primitives`
- `Go binary dangerous call scanner with SQLite cache + itab resolver`
- `Garble-obfuscated Go binary analysis`
- `ARM64 SSE forward/backward slicer — GOT-aware`
- `ARM32 disassembler (pure Python)`
- `ARM32 symbolic execution + vtable scanner`
- `ARM64 call-site argument tracer`
- `C++ vtable reconstructor — arch-agnostic, 3-layer pipeline`
- `x86-64 ET_DYN ELF vtable reconstructor via .rela.dyn`

---

### Group 8: Semantic Search & Learning (30)

**What it covers:** The AI/ML-assisted analysis layer. SemanticSearcher (sentence embeddings
over function descriptions), CorpusBuilder (populates the embedding corpus), PatternLibrary
(confirmed-pattern replay), FindingRegistry (de-duplication), LLM agent loop, hypothesis
engine (probe selection and scoring), DTWMatcher, MatrixProfileDiff, SAXIndex.

**Units primarily contributing:** A12 (20), A14 partial (EnginePatternLibrary, dynamic sandbox)

**Old category strings mapped here:**
- `LLM-assisted analysis / ReAct loop`
- `LLM tool dispatch`
- `LLM prompt construction`
- `RAG / prior finding retrieval`
- `semantic / embedding search`
- `corpus population`
- `function identity database`
- `pattern management / replay`
- `confirmed finding store`
- `function name overlay`
- `approximate function search / pre-filter`
- `behavioral pattern search`
- `hypothesis engine / probe selection`
- `hypothesis engine / probe execution`
- `hypothesis lifecycle orchestration`
- `data model`
- `scoring / state transitions`
- `cross-version function matching`
- `instruction-level patch diff`
- `behavioral signature matching`
- `Game Engine Code Labeling`
- `Cross-Version Function Tracking`
- `Dynamic Analysis / Behavioral Evidence`
- `Dynamic Analysis Safety Gate`
- `Hypothesis Engine Integration`
- `Cross-Version Diffing — Function Similarity`
- `Cross-Version Diffing — ML Fine-tuning`
- `Function Recognition — PLT Slot Classification`
- `String Analysis — Obfuscated String Decoding`
- `Malware Analysis — Defense Evasion Detection`

---

### Group 9: Host & Network Enumeration (18)

**What it covers:** Runtime enumeration and attack-surface analysis of live systems.
Docker/container posture, Kubernetes cluster enumeration, network packet analysis,
Cisco IOS/NX-OS/HyperFlex/APIC, SIP/VoIP, lateral movement, forensics, Windows live system,
streaming infrastructure, syscall tracing.

**Units primarily contributing:** M01 (18)

**Old category strings mapped here:**
- `Container enumeration / escape-vector detection`
- `Kubernetes and container supply-chain posture checks`
- `Cisco HyperFlex / UCS / Intersight enumeration`
- `Cisco IOS / IOS-XE / ASA enumeration, L2 attack surface`
- `Kubernetes cluster enumeration / posture`
- `Lateral movement / C2 / exfiltration detection`
- `Network sniffing / host discovery / service fingerprinting`
- `Network analysis / PCAP parsing / cloud/service mesh/broker enumeration`
- `Cisco Nexus Dashboard / NX-OS enumeration + CI/CD tool exposure`
- `Cisco NX-OS / APIC enumeration`
- `Physical memory / ELF forensics (live system)`
- `Privilege escalation enumeration (Linux and Windows)`
- `Process / memory / persistence enumeration and binary detection`
- `VoIP / SIP / RTP enumeration and attack surface detection`
- `Streaming / observability / orchestration infrastructure enumeration`
- `Syscall tracing / macOS/Linux kernel attack surface / industrial protocol probes`
- `Windows live system enumeration`

---

### Group 10: Session Management & Tooling (19)

**What it covers:** Infrastructure that orchestrates the RE session: FORGE quality gate,
WorkflowDocument stage pipeline, ScanResultVersionCache, StageCommitment audit chain,
VendorProfile sink registration, report generation, sweep orchestration scripts, and
misc shared utilities.

**Units primarily contributing:** S01 (17 sweeps + workflow docs), A14 partial (FORGE, ScanResultVersionCache, StageCommitment, WorkflowDocument, VendorProfile)

**Old category strings mapped here:**
- `Sweep` (10 records from S01)
- `Module Quality Gate + Local Module Store`
- `Caching Infrastructure`
- `Audit Chain / Tamper Evidence`
- `Session Management / Schema Validation`
- `Vendor Sink Configuration`
- `Syscall Classification` (LoongArch64 syscall table)
- `Register Annotation / Call-Site Analysis` (RegAnnotator, ARM32RegAnnotator — used across sessions)
- `Function Profiling / Reporting` (FuncProfiler)
- `Interprocedural Register Annotation` (IPRegAnnotator)
- `Cross-Reference Analysis (i386)`
- `Build Metadata Extraction`
- `Reporting — ATT&CK Technique Auto-Assignment`
- `Internal Infrastructure — Shared Disassembly`
- `Source Code Auditing / Ingestion`

---

## README Claim: "27 Categories"

The README states 27 categories. Based on this audit:

- The notes reveal **272 raw category strings** across 402 capability records. These are
  fine-grained per-module labels, not top-level categories.
- The 27 figure likely refers to a counted list in the original development notes that
  grouped major *feature areas* rather than individual modules. Possible breakdown:

| Count | Feature area (probable README intent) |
|-------|--------------------------------------|
| 10 | ISA-specific taint trackers (x86, ARM, MIPS, PPC, RISC-V, ARC, LoongArch64, V850, s390, MIPS-labeled) |
| 9 | Sink classifier variants (SAC x86-64, ARM32, i386×2, MIPS, PPC32, PPC64, ELFv1, S390X) |
| 3 | Firmware extraction pipelines (FortiOS, AIX/BFF, generic container) |
| 3 | Semantic/ML tools (SemanticSearcher, PatternLibrary, HypothesisEngine) |
| 2 | CFG builders (covered ISAs) + dataflow engines |

That accounts for 27 only if "categories" means coarse feature buckets. The actual
implementation contains ~10× that at granular level.

**Recommendation:** Replace the "27 categories" claim in the README with
"10 capability groups, 402 documented capabilities across 20 units".

---

## Uncategorized Records (67)

67 records (17%) have an empty `category` field. These come from units where the notes
author omitted the category label:

| Unit | Count | Reason |
|------|-------|--------|
| A07 | 17 | A07 format uses `**File:**`/`**Class:**`/`**Architecture scope:**` — no `category:` field |
| C01 | 25 | C01 format uses `**file:**`/`**entry point:**` — no `category:` field |
| M02 | 13 | M02 format uses `**File:**`/`**What it does:**` — no `category:` field |
| A10 | 5 | Some sub-cap records missing category |
| S01 | 7 | Some workflow-guide sections missing category |

**Action:** These 67 records still have `final_category` empty in capabilities.json
and are assigned to their functional group above based on unit context.

---

## Workflow Stage Distribution

Assigned by `_infer_workflow_stage()` from category strings. The high "analyze" count
reflects the broad default for tools without an obvious pipeline position.

| Stage | Count | Representative tools |
|-------|-------|---------------------|
| analyze | 201 | Taint trackers, register annotators, CFG analysis, ECU decoders |
| find_vulns | 108 | Vulnerability scanners, sink classifiers, sweeps |
| decode | 58 | CFG builders, ISA/ABI models, instruction backends |
| unpack | 17 | Firmware extractors, archive parsers, XOR decryption |
| verify | 7 | DynamicSandbox, PathSolver, hypothesis engine |
| ingest | 5 | BinaryContext, ELFParser, BinaryParser |
| report | 4 | FORGE, WorkflowDocument, ScanResultVersionCache |
| learn | 2 | SemanticSearcher, CorpusBuilder |

