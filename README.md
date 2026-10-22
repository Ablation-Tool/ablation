<img src="branding/ablation-1b-riveted-plate-wordmark-transparent-2560.png" width="520" alt="ABLATION">

![](https://komarev.com/ghpvc/?username=Ablation-Tool&color=grey) [![NIST SP 800-218](https://img.shields.io/badge/NIST%20SP%20800--218-SSDF-grey)](docs/standards-ablation.md) [![CISA Secure by Design](https://img.shields.io/badge/CISA-Secure%20by%20Design-grey)](docs/standards-ablation.md) [![MIL-HDBK-115C](https://img.shields.io/badge/MIL--HDBK--115C-Compliant-grey)](docs/standards-ablation.md) [![Sponsor Me](https://img.shields.io/badge/Sponsor%20Me-%23ea4aaa?logo=githubsponsors&logoColor=white)](docs/SPONSORS.md)


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
<summary><strong>31 Decompilers</strong></summary>

<details>
<summary><strong>Native CPUs</strong> </summary>

| ISA | Variants |
|---|---|
| [**x86**](docs/reference-modules/x86.md) | x86-32 · x86-64 |
| [**ARM**](docs/reference-modules/binary-lifter.md) | ARM-32 · ARM-64 · Thumb |
| [**MIPS**](docs/reference-modules/mips.md) | MIPS-32 · [nanoMIPS](docs/reference-modules/nanomips.md) · MIPS-64 |
| [**PowerPC**](docs/reference-modules/ppc32-taint-tracker.md) | PPC-32 · PPC-64 · [VLE](docs/reference-modules/ecu-vle-decoder.md) · [PPC476 Book E](docs/reference-modules/ppc476-lifter.md) · [XCOFF32 / AIX](docs/reference-modules/xcoff32-decompiler.md) |
| [**RISC-V**](docs/reference-modules/risc-v.md) | RV32 · RV64 · [HiSilicon ext](docs/reference-modules/hisi-rv32-ext.md) |
| [**ARC**](docs/reference-modules/binary-lifter.md) | ARC EM/HS |
| [**LoongArch**](docs/reference-modules/loongarch.md) | LoongArch64 |
| [**Intel&nbsp;MCS**](docs/reference-modules/isa-8051.md) | 8051 |

</details>

<details>
<summary><strong>Automotive ECUs</strong> </summary>

| ISA | Variants |
|---|---|
| [**V850&nbsp;/&nbsp;RH850**](docs/reference-modules/v850-rh850.md) | V850-32 · RH850 |
| [**Renesas&nbsp;SH**](docs/reference-modules/binary-lifter-sh2a.md) | SH-2A |
| [**Motorola**](docs/reference-modules/ecu-m68k-decoder.md) | M68K / CPU32 · [MC88100](docs/reference-modules/m88k-decoder.md) |
| [**Infineon**](docs/reference-modules/tricore-taint-tracker.md) | TriCore TC1.6x |
| [**TI&nbsp;DSP**](docs/reference-modules/ecu-c28x-decoder.md) | TMS320C28x |

</details>

<details>
<summary><strong>VMs & Runtimes</strong> </summary>

| ISA | Variants |
|---|---|
| [**DEX**](docs/reference-modules/dex.md) | Dalvik · ART |
| [**ARK**](docs/reference-modules/harmonyos.md) | ArkTS |
| [**MicroPython**](docs/reference-modules/micropython.md) |.mpy v6 |

</details>

</details>

<details>
<summary><strong>Core analysis engine</strong></summary>

| Capability | Code | |
|:---|:---|:---|
| [**On-Demand&nbsp;Analysis**](docs/reference-modules/on-demand-analysis.md) | [1](ablation/analyzers/binary_context.py) | Cached binary context and targeted function analysis; retain symbols, imports, cross-references and analyst names between sessions. |
| [**Binary&nbsp;Lifting**](docs/reference-modules/binary-lifting.md) | [1](ablation/analyzers/binary_lifter.py) | Native instructions to pseudo-C using architecture-specific register state and calling conventions; support varies by backend. |
| [**Semantic&nbsp;Code&nbsp;Search**](docs/reference-modules/semantic-code-search.md) | [1](ablation/analyzers/semantic_search.py) | Search functions by behavioral descriptions; normalize assembly, embed descriptions and rank semantic similarity. |
| [**Hypothesis&nbsp;Engine**](docs/reference-modules/hypothesis-engine-2.md) | [1](ablation/analyzers/hypothesis_engine.py) | Persist competing explanations, collect evidence, rank probes and update confidence. |
| [**DAG&nbsp;Adapter&nbsp;Language**](docs/reference-modules/encoding-dag.md) | [1](ablation/analyzers/encoding_dag.py) | Define fixed-width instruction bitfields, round-trip encodings, semantic operations and dataflow edges through EncodingDAG. |
| [**Entropy&nbsp;Mapper**](docs/reference-modules/entropy-mapper.md) | [1](ablation/analyzers/entropy_mapper.py) | Sliding-window Shannon entropy, region classification and transition detection to guide unpacking and analysis. |

</details>

<details>
<summary><strong>Learning and continuity</strong></summary>

| Capability | Code | |
|:---|:---|:---|
| [**The&nbsp;Flywheel**](docs/reference-modules/flywheel.md) | [1](ablation/analyzers/pattern_library.py)&nbsp;[2](ablation/analyzers/finding_registry.py) | Replay stored confirmed finding descriptions and successful semantic queries against later binaries. |
| [**Cross-Target&nbsp;Learning**](docs/reference-modules/cross-target-learning.md) | [1](ablation/analyzers/pattern_library.py)&nbsp;[2](ablation/analyzers/finding_registry.py) | Persist transferable finding descriptions, embeddings and search patterns for reuse across products and vendors. |
| [**KASAN-Oracle**](docs/workflows/kasan-oracle.md) | [1](ablation/analyzers/loongarch_decoder_v2.py) | Workflow for deriving candidates from instrumented/debug builds and checking corresponding production code; includes instrumentation-aware decoding. |

</details>

<details>
<summary><strong>Vulnerability discovery and validation</strong></summary>

| Capability | Code | |
|:---|:---|:---|
| [**Network&nbsp;Sink&nbsp;Finder**](docs/reference-modules/network-sink-finder.md) | [1](ablation/analyzers/network_sink_finder.py) | BFS callgraph reachability from network sources (recv/read/fgets/accept) crossed with SinkArgClassifier results. Turns the 50-line HACMP-003 pattern into 3 lines because depth-N reachability and SAC cross-reference were previously separate manual steps. |
| [**Taint&nbsp;Analysis**](docs/reference-modules/taint-analysis-2.md) | [1](ablation/analyzers/taint_tracker.py)&nbsp;[2](ablation/analyzers/taint_tracker_arm64.py) | Source-to-sink register/dataflow tracking, with architecture-specific intraprocedural, interprocedural and flow-sensitive implementations. |
| [**Cross-Library&nbsp;Analysis**](docs/reference-modules/cross-library-analysis.md) | [1](ablation/analyzers/cross_binary_taint.py)&nbsp;[2](ablation/analyzers/lib_graph.py) | Resolve imports and exports across a firmware library set and propagate supported argument taint across library boundaries. |
| [**Pre-Authentication&nbsp;Exposure**](docs/reference-modules/preauth-exposure.md) | [1](ablation/analyzers/preauth_route_auditor.py) | Recover supported Flatui route/auth-wrapper structures, associate handlers and identify pre-authentication handlers with sensitive sinks. |
| [**Sink&nbsp;Arg&nbsp;Classifier**](docs/reference-modules/sink-arg-classifier.md) | [1](ablation/analyzers/sink_arg_classifier.py) | Classify command arguments as constant, formatted constant, argument-propagated or unknown before deeper tracing. |
| [**Finding&nbsp;Validation**](docs/reference-modules/finding-validation.md) | [1](modules/path_solver.py)&nbsp;[2](ablation/analyzers/finding_registry.py) | Bounded x86-64 symbolic path solving produces entry-register constraints/models; a registry stores findings and submission metadata. It does not establish automatic HTTP reproduction for every find... |
| [**Compiler&nbsp;Defect&nbsp;Detection**](docs/reference-modules/compiler-defects.md) | [1](ablation/analyzers/loongarch64_max_not_min_scanner.py)&nbsp;[2](ablation/analyzers/compiler_security_gate.py) | Detect the implemented LoongArch64 min/max miscompilation pattern and run supported security scans on compiler output. |
| [**Source&nbsp;Code&nbsp;Auditing**](docs/reference-modules/source-code-auditing.md) | [1](ablation/analyzers/source_audit_compressor.py)&nbsp;[2](ablation/analyzers/source_taint_tracker.py) | Ingest repositories, profile/rank files, map entry points and sinks, trace source paths and support review coverage accounting. |
| [**Cryptographic&nbsp;Analysis**](docs/reference-modules/cryptographic-analysis.md) | [1](modules/crypto_audit.py)&nbsp;[2](ablation/analyzers/xor_solver.py) | Key/secret discovery, repeating-XOR recovery, crypto implementation fingerprinting and JWT/SAML/TLS posture checks. |
| [**Protocol&nbsp;FSM&nbsp;Extractor**](docs/reference-modules/proto-fsm.md) | [1](modules/proto_fsm.py) | Infer an ARM64 protocol state graph from BSS state accesses and a selected handshake-function cluster; includes MMTLS-oriented assumptions. |
| [**BMP&nbsp;LSB&nbsp;Key&nbsp;Extractor**](docs/reference-modules/lsb-stego-extractor.md) | [1](ablation/analyzers/lsb_stego_extractor.py) | Read BMP pixel least-significant bits and reconstruct keys for the implemented seed/polynomial encoding scheme. |
| [**Format&nbsp;String&nbsp;Scanner**](docs/reference-modules/format-string-scanner.md) | [1](ablation/analyzers/format_string_scanner.py) | Flag supported printf-family, syslog and logging call sites with potentially unsafe format-argument provenance in x86-64 ELF. |
| [**Heap&nbsp;Vulnerability&nbsp;Scanner**](docs/reference-modules/heap-vulnerability-scanner.md) | [1](ablation/analyzers/heap_vuln_scanner.py)&nbsp;[2](modules/heap_uaf_scanner.py) | x86-64 allocation-overflow, use-after-free, double-free and off-by-one/pointer-state heuristics; LoongArch64 allocation-arithmetic overflow scanning. |
| [**SQL&nbsp;Injection&nbsp;Scanner**](docs/reference-modules/sql-injection-scanner.md) | [1](ablation/analyzers/sql_sink_scanner.py) | Trace formatted query construction into supported MySQL C API and SQLite sinks in native binaries. |
| [**RPC&nbsp;Server&nbsp;Analyzer**](docs/reference-modules/rpc-server-analyzer.md) | [1](ablation/analyzers/rpc_server_analyzer.py) | Recover Windows RPC interface/endpoint indicators and examine supported registration/authentication patterns. |
| [**IOCTL&nbsp;Attack&nbsp;Surface**](docs/reference-modules/ioctl-attack-surface.md) | [1](modules/ioctl_attack_surface.py) | Decode driver IOCTLs and inspect METHOD_NEITHER, buffer-length handling, probe APIs and allocation/copy patterns. |
| [**Length&nbsp;Underflow&nbsp;Scanner**](docs/reference-modules/length-underflow.md) | [1](ablation/analyzers/length_underflow.py) | Find supported x86-64 parser patterns where subtracting a header size from a narrow length can wrap before allocation or copying. |
| [**Setuid&nbsp;Auth&nbsp;Oracle**](docs/reference-modules/setuid-auth-oracle-scanner.md) | [1](modules/setuid_auth_oracle_scanner.py) | Identify raw shadow-password validation/import patterns without PAM mediation as authentication-oracle candidates. |
| [**Lua&nbsp;Injection&nbsp;Analyzer**](docs/reference-modules/lua-injection-analyzer.md) | [1](ablation/analyzers/lua_injection_analyzer.py) | Detect Python strings formatted into Lua source before execution through supported Lua interfaces. |

</details>

<details>
<summary><strong>Specialized recovery</strong></summary>

| Capability | Code | |
|:---|:---|:---|
| [**C++&nbsp;Vtable&nbsp;Reconstruction**](docs/reference-modules/cpp-vtable-reconstructor.md) | [1](modules/cpp_vtable_reconstructor.py) | Recover ELF virtual tables, name slots from available evidence and generate annotations for virtual dispatch analysis. |
| [**PPC32&nbsp;GOT2&nbsp;Resolver**](docs/reference-modules/ppc32-got2-resolver.md) | [1](modules/ppc32_got2_resolver.py) | Recover GOT2 bases and resolve supported indirect BCTRL targets in stripped PPC32 big-endian PIC binaries. |
| [**Dynamic&nbsp;Sandbox**](docs/reference-modules/dynamic-sandbox.md) | [1](ablation/analyzers/dynamic_sandbox.py) | Probe ARM64 or x86-64 leaf functions in Unicorn, capture return/register state and writes, and compare behavioral signatures. |
| [**Firmware&nbsp;Extraction**](docs/reference-modules/firmware-extraction.md) | [1](ablation/analyzers/fortios_firmware_extractor.py)&nbsp;[2](ablation/analyzers/firmware_container_key_extractor.py) | Format/vendor-specific container parsing, supported Fortinet XOR/key recovery and inner-partition decryption, plus selected filesystem extraction. |
| [**Firmware&nbsp;Key&nbsp;Corpus**](docs/reference-modules/firmware-key-corpus.md) | [1](ablation/analyzers/fortigate_cert_key_scanner.py)&nbsp;[2](ablation/analyzers/fortibuild_track_classifier.py) | Fingerprint recovered Fortinet certificate keys, compare known key families and classify expected keys by firmware build track. |

</details>

<details>
<summary><strong>Platform and runtime support</strong></summary>

| Capability | Code | |
|:---|:---|:---|
| [**Windows&nbsp;PE&nbsp;Security&nbsp;Analysis**](docs/reference-modules/windows-pe.md) | [1](sweeps/pe_sweep.py)&nbsp;[2](ablation/analyzers/cfg_bypass_detector.py) | PE sweeps and dedicated CFG, SEH, RPC, COM, ETW, symbol and pool-allocation analyses. |
| [**Windows&nbsp;Kernel&nbsp;Driver&nbsp;&&nbsp;BYOVD**](docs/reference-modules/kernel-drivers.md) | [1](ablation/analyzers/kernel_driver_analyzer.py)&nbsp;[2](ablation/analyzers/byovd_detector.py) | Inspect driver imports, IOCTLs, callbacks, pool operations and dangerous primitives; rank BYOVD-related capability indicators. |
| [**Android&nbsp;/&nbsp;APK&nbsp;Analysis**](docs/reference-modules/android-apk-analysis.md) | [1](ablation/core/apk_parser.py)&nbsp;[2](ablation/analyzers/dex_analyzer.py) | Parse APK/AXML/DEX, review manifest exposure and dangerous APIs, inventory native libraries and prioritize findings. |
| [**HarmonyOS&nbsp;/&nbsp;ArkTS&nbsp;Analysis**](docs/reference-modules/harmonyos.md) | [1](ablation/analyzers/abc_parser.py)&nbsp;[2](ablation/analyzers/abc_disasm.py) | Parse extracted Ark ABC bytecode, enumerate classes/methods/strings, disassemble and produce JavaScript-like pseudocode. |
| [**Go&nbsp;Binary&nbsp;Reverse&nbsp;Engineering**](docs/workflows/go-binaries.md) | [1](ablation/analyzers/go_pclntab.py)&nbsp;[2](modules/go_binary_re.py) | Recover supported pclntab function metadata, analyze stripped Go ELF/Mach-O binaries and inspect garble-obfuscated layouts. |
| [**Erlang&nbsp;/&nbsp;BEAM&nbsp;Analysis**](docs/reference-modules/beam.md) | [1](ablation/analyzers/beam_context.py) | Read BEAM module/export/import/atom data, lift supported bytecode, scan risky imports and compare module sets. |
| [**MicroPython&nbsp;.mpy&nbsp;Lifter**](docs/reference-modules/micropython-mpy-lifter.md) | [1](modules/mpy_lifter.py) | Parse supported.mpy v6 files, lift bytecode to pseudo-Python and flag dangerous imports/calls and direct memory access. |
| [**Game&nbsp;&&nbsp;Legacy&nbsp;RE**](docs/reference-modules/game-re.md) | [1](ablation/analyzers/engine_pattern_library.py)&nbsp;[2](modules/spu_disassembler.py) | Label known game-engine code and provide selected PS3/Cell, classic Mac, old Windows/DOS and other legacy-format tools. |
| [**PS3&nbsp;SELF&nbsp;Decryptor**](docs/reference-modules/ps3-self-decryptor.md) | [1](ablation/analyzers/ps3_self_decryptor.py) | Decrypt supported Signed ELF containers using registered keysets, detect key revision and emit a loadable ELF. |
| [**MCP&nbsp;Server&nbsp;Security&nbsp;Scanner**](docs/reference-modules/mcp-tool-taint-scanner.md) | [1](ablation/analyzers/mcp_tool_taint_scanner.py) | Scan Python/JavaScript/TypeScript MCP source for exposed bindings, missing-authentication patterns and dangerous tool methods. |
| [**LoongArch64**](docs/reference-modules/loongarch64-2.md) | [1](ablation/analyzers/loongarch_decoder.py)&nbsp;[2](ablation/analyzers/taint_tracker_loongarch64.py) | Dedicated decoding, CFG/dataflow, lifting, taint, syscall classification and DWARF/CFI/BTF function-boundary recovery. |
| [**nanoMIPS**](docs/reference-modules/nanomips.md) | [1](ablation/analyzers/nanomips_decoder.py)&nbsp;[2](ablation/analyzers/taint_tracker_nanomips.py) | Variable-width decoding, function/frame discovery and supported intra/interprocedural taint analysis. |

</details>

<details>
<summary><strong>Automotive ECU analysis</strong></summary>

| Capability | Code | |
|:---|:---|:---|
| [**ECU&nbsp;Architecture&nbsp;Detector**](docs/reference-modules/ecu-architecture-detector.md) | [1](ablation/analyzers/ecu_arch_detector.py) | Rank candidate instruction sets for raw ECU ROMs using reset vectors, signatures and structural heuristics. |
| [**ROM&nbsp;Layout&nbsp;Analyzer**](docs/reference-modules/ecu-rom-layout-analyzer.md) | [1](ablation/analyzers/ecu_rom_layout_analyzer.py) | Classify raw-ROM regions as code, calibration, interrupt vectors or erased data and identify application-code regions. |
| [**Calibration&nbsp;Parsers**](docs/reference-modules/calibration-parsers.md) | [1](ablation/analyzers/ecu_xdf_parser.py)&nbsp;[2](ablation/analyzers/ecu_a2l_parser.py) | Parse TunerPro XDF, ASAM A2L, RomRaider XML, open_damos, Conescan and Nissan/Pytrex definitions into calibration tables and labels. |
| [**CAN&nbsp;DBC&nbsp;Parser**](docs/reference-modules/can-dbc-parser.md) | [1](modules/can_dbc_parser.py) | Parse CAN message/signal definitions, bit layouts, value tables and comments for analysis context. |
| [**ECU&nbsp;Security&nbsp;Access&nbsp;Scanner**](docs/reference-modules/ecu-security-access-scanner.md) | [1](ablation/analyzers/ecu_security_access_scanner.py) | Fingerprint the implemented static-seed UDS/KWP2000 SecurityAccess patterns in M68K/CPU32 and PPC32 ROMs. |
| [**TriCore&nbsp;Taint&nbsp;Analysis**](docs/reference-modules/tricore-taint-tracker.md) | [1](ablation/analyzers/taint_tracker_tricore.py) | TriCore ECU source-to-sink analysis with supported GHS/IAR ABI and flat-image handling. |
| [**RH850&nbsp;Taint&nbsp;Analysis**](docs/reference-modules/rh850-taint-analysis.md) | [1](ablation/analyzers/taint_tracker_rh850.py) | RH850 ECU register/argument taint tracking with supported ABI and flat-ROM analysis paths. |

</details>

<details>
<summary><strong>Workflow and quality gates</strong></summary>

| Capability | Code | |
|:---|:---|:---|
| [**Version&nbsp;Diffing**](docs/workflows/cross-version.md) | [1](ablation/analyzers/version_delta.py)&nbsp;[2](ablation/analyzers/dtw_matcher.py) | Match corresponding functions, follow identities across releases and localize instruction-category changes. |
| [**Kernel&nbsp;Module&nbsp;Subsystem&nbsp;Classifier**](docs/reference-modules/kernel-module-subsystem-classifier.md) | [1](ablation/analyzers/kernel_module_subsystem_classifier.py) | Infer a Linux module's subsystem and attack-surface priority from its source-tree/install path. |
| [**Module&nbsp;Quality&nbsp;Gate**](docs/reference-modules/forge.md) | [1](ablation/analyzers/forge.py) | FORGE audit records, severity-based gates and local-module registration/loading; audit behavior depends on configured analysis. |
| [**Coverage&nbsp;Gate**](docs/reference-modules/coverage-gate.md) | [1](pyproject.toml)&nbsp;[2](.github/workflows/ci.yml) | Configured 85% statement-coverage threshold for the selected labeled taint-engine modules; not a whole-repository coverage guarantee. |
| [**YARA&nbsp;Rule&nbsp;Generation**](docs/reference-modules/yara-generator.md) | [1](ablation/core/yara_generator.py) | Generate YARA text from supported findings/strings and supplied technique templates. |

</details>

<details>
<summary><strong>Binary loading, discovery and navigation</strong></summary>

| Capability | Code | |
|:---|:---|:---|
| [**Binary&nbsp;format&nbsp;and&nbsp;platform&nbsp;identification**](docs/reference-modules/binary-format-and-platform-identification.md) | [1](ablation/core/binary_parser.py)&nbsp;[2](ablation/core/elf_parser.py) | Detect ELF/PE/Mach-O and inspect file/OS/architecture metadata through the appropriate parser. |
| [**ELF&nbsp;internals&nbsp;and&nbsp;hardening**](docs/reference-modules/elf-internals-and-hardening.md) | [1](ablation/core/binary_parser.py)&nbsp;[2](ablation/core/elf_parser.py) | Parse ELF32/64 program/section headers, symbols, dependencies, RPATH/RUNPATH and GOT/PLT; inspect NX, PIE, RELRO and canary indicators. |
| [**PE&nbsp;internals&nbsp;and&nbsp;indicators**](docs/reference-modules/pe-internals-and-indicators.md) | [1](ablation/core/binary_parser.py)&nbsp;[2](ablation/core/elf_parser.py) | Inspect sections, imports, strings, resources and selected malware/anti-debug/IOC patterns. |
| [**Mach-O&nbsp;internals**](docs/reference-modules/mach-o-internals.md) | [1](ablation/core/binary_parser.py)&nbsp;[2](ablation/core/elf_parser.py) | Inspect load commands, segments, dylib dependencies and code-signing information. |
| [**Call&nbsp;and&nbsp;string&nbsp;cross-references**](docs/reference-modules/call-and-string-cross-references.md) | [1](ablation/analyzers/binary_context.py)&nbsp;[2](ablation/analyzers/xref_graph.py) | Find callers, callees, referenced strings, functions referencing strings, containing functions, exports and import names. |
| [**Persistent&nbsp;analysis&nbsp;context**](docs/reference-modules/persistent-analysis-context.md) | [1](ablation/analyzers/binary_context.py)&nbsp;[2](ablation/analyzers/xref_graph.py) | Cache binary metadata and cross-reference structures and reload analyst naming overlays. |
| [**Native-library&nbsp;inventory**](docs/reference-modules/native-library-inventory.md) | [1](ablation/analyzers/binary_context.py)&nbsp;[2](ablation/analyzers/xref_graph.py) | Rank a directory of ELF libraries by architecture, functions, exports, JNI presence and security-relevant strings. |
| [**Stripped&nbsp;function&nbsp;discovery**](docs/reference-modules/stripped-function-discovery.md) | [1](ablation/analyzers/arm32_function_scanner.py)&nbsp;[2](ablation/analyzers/static_elf32_func_start_scanner.py) | Recover candidate entries from architecture-specific prologues, calls, reset vectors and available metadata. |
| [**Flat-ROM&nbsp;function&nbsp;discovery**](docs/reference-modules/flat-rom-function-discovery.md) | [1](ablation/analyzers/arm32_function_scanner.py)&nbsp;[2](ablation/analyzers/static_elf32_func_start_scanner.py) | Harvest call targets and prologues without ELF headers, using the supported ECU decoder/layout paths. |
| [**i386&nbsp;absolute&nbsp;cross-references**](docs/reference-modules/i386-absolute-cross-references.md) | [1](ablation/analyzers/i386_absolute_xref_scanner.py)&nbsp;[2](ablation/analyzers/dwarf_loongarch64.py) | Find x86-32 string/data references encoded as absolute immediates. |
| [**Debug&nbsp;metadata&nbsp;recovery**](docs/reference-modules/debug-metadata-recovery.md) | [1](ablation/analyzers/i386_absolute_xref_scanner.py)&nbsp;[2](ablation/analyzers/dwarf_loongarch64.py) | Recover LoongArch function boundaries from.eh_frame, DWARF and BTF where available. |
| [**Swift&nbsp;symbol&nbsp;demangling**](docs/reference-modules/swift-symbol-demangling.md) | [1](ablation/analyzers/i386_absolute_xref_scanner.py)&nbsp;[2](ablation/analyzers/dwarf_loongarch64.py) | Best-effort Swift symbol decoding with an optional swift-demangle fallback. |

</details>

<details>
<summary><strong>Disassembly, graphs and symbolic analysis</strong></summary>

| Capability | Code | |
|:---|:---|:---|
| [**Streaming&nbsp;and&nbsp;windowed&nbsp;disassembly**](docs/reference-modules/streaming-and-windowed-disassembly.md) | [1](ablation/core/disasm_engine.py)&nbsp;[2](ablation/analyzers/window_analyzer.py) | Produce instruction streams or annotated address windows with calls, strings and function boundaries. |
| [**Single-function&nbsp;profiling**](docs/reference-modules/single-function-profiling.md) | [1](ablation/core/disasm_engine.py)&nbsp;[2](ablation/analyzers/window_analyzer.py) | Combine callee names, strings, argument values and sink flags in one function report. |
| [**Optional&nbsp;angr-backed&nbsp;analysis**](docs/reference-modules/optional-angr-backed-analysis.md) | [1](ablation/core/disasm_engine.py)&nbsp;[2](ablation/analyzers/window_analyzer.py) | Extended disassembly engine supports caller/xref resolution and register/block dataflow via angr. |
| [**Control-flow&nbsp;graph&nbsp;construction**](docs/reference-modules/control-flow-graph-construction.md) | [1](ablation/analyzers/dataflow_engine.py)&nbsp;[2](ablation/analyzers/structurizer.py) | Architecture-specific block/edge construction, branch targets, return handling and selected delay-slot semantics. |
| [**Generic&nbsp;dataflow&nbsp;worklist**](docs/reference-modules/generic-dataflow-worklist.md) | [1](ablation/analyzers/dataflow_engine.py)&nbsp;[2](ablation/analyzers/structurizer.py) | Monotone-framework propagation with supported lattice/state joins across a CFG. |
| [**Constant&nbsp;propagation&nbsp;and&nbsp;reaching&nbsp;definitions**](docs/reference-modules/constant-propagation-and-reaching-definitions.md) | [1](ablation/analyzers/dataflow_engine.py)&nbsp;[2](ablation/analyzers/structurizer.py) | Track definitions/constants and perform sparse conditional constant propagation. |
| [**Dominators&nbsp;and&nbsp;loop&nbsp;analysis**](docs/reference-modules/dominators-and-loop-analysis.md) | [1](ablation/analyzers/dataflow_engine.py)&nbsp;[2](ablation/analyzers/structurizer.py) | Build dominator/post-dominator information and identify natural loops. |
| [**Structured&nbsp;control-flow&nbsp;recovery**](docs/reference-modules/structured-control-flow-recovery.md) | [1](ablation/analyzers/dataflow_engine.py)&nbsp;[2](ablation/analyzers/structurizer.py) | Render supported CFG regions as sequences, conditions, loops, breaks, continues and returns. |
| [**Call-argument&nbsp;annotation**](docs/reference-modules/call-argument-annotation.md) | [1](ablation/analyzers/reg_annotator.py)&nbsp;[2](ablation/analyzers/arm32_reg_annotator.py) | Forward symbolic register propagation for supported x86-64/ARM32 call sites. |
| [**Interprocedural&nbsp;argument&nbsp;provenance**](docs/reference-modules/interprocedural-argument-provenance.md) | [1](ablation/analyzers/reg_annotator.py)&nbsp;[2](ablation/analyzers/arm32_reg_annotator.py) | Seed callees with caller values and follow supported argument chains across functions. |
| [**Lightweight&nbsp;ARM32&nbsp;symbolic&nbsp;execution**](docs/reference-modules/lightweight-arm32-symbolic-execution.md) | [1](ablation/analyzers/reg_annotator.py)&nbsp;[2](ablation/analyzers/arm32_reg_annotator.py) | Track argument/buffer relationships and protocol field writes without an SMT solver. |
| [**ARM64&nbsp;symbolic&nbsp;slicing**](docs/reference-modules/arm64-symbolic-slicing.md) | [1](modules/sse_slicer.py)&nbsp;[2](modules/arm64_global_tracker.py) | Backward/forward structured-expression slicing for memory addresses and stores. |
| [**Global-symbol&nbsp;and&nbsp;BSS&nbsp;tracking**](docs/reference-modules/global-symbol-and-bss-tracking.md) | [1](modules/sse_slicer.py)&nbsp;[2](modules/arm64_global_tracker.py) | Resolve named global/GOT relationships and find state, buffer or decrypt-loop accesses. |
| [**Call-site&nbsp;backward&nbsp;slicing**](docs/reference-modules/call-site-backward-slicing.md) | [1](modules/sse_slicer.py)&nbsp;[2](modules/arm64_global_tracker.py) | Recover x0-x7 symbolic values at selected ARM64 calls. |
| [**Interprocedural&nbsp;field-writer&nbsp;discovery**](docs/reference-modules/interprocedural-field-writer-discovery.md) | [1](modules/sse_slicer.py)&nbsp;[2](modules/arm64_global_tracker.py) | Locate functions writing a selected field when its structure pointer crosses call boundaries. |

</details>

<details>
<summary><strong>Instruction, ABI and labeled-taint APIs</strong></summary>

| Capability | Code | |
|:---|:---|:---|
| [**Instruction-stream&nbsp;import&nbsp;and&nbsp;normalization**](docs/reference-modules/instruction-stream-import-and-normalization.md) | [1](ablation/analyzers/insn_x86.py)&nbsp;[2](ablation/analyzers/insn_arm32.py) | Convert supported Capstone, objdump or hand-written listings into common per-ISA instruction/operand objects; normalize aliases and x86 syntax. |
| [**Calling-convention&nbsp;and&nbsp;syscall&nbsp;models**](docs/reference-modules/calling-convention-and-syscall-models.md) | [1](ablation/analyzers/isa_x86.py)&nbsp;[2](ablation/analyzers/isa_arm32.py) | Encode supported register aliases, argument/return registers, caller/callee saves and syscall conventions separately from decoders. |
| [**Named&nbsp;taint&nbsp;sources&nbsp;and&nbsp;bounds**](docs/reference-modules/named-taint-sources-and-bounds.md) | [1](ablation/analyzers/taint_tracker_x86_labeled.py)&nbsp;[2](ablation/analyzers/taint_tracker_arm32_labeled.py) | Preserve source labels and supported bounds on attacker-controlled contributions rather than a single boolean taint flag. |
| [**Frame,&nbsp;pointer&nbsp;and&nbsp;memory-range&nbsp;state**](docs/reference-modules/frame-pointer-and-memory-range-state.md) | [1](ablation/analyzers/taint_tracker_x86_labeled.py)&nbsp;[2](ablation/analyzers/taint_tracker_arm32_labeled.py) | Track supported frame slots, spilled pointers, constants, memory ranges and register aliases across instruction streams. |
| [**Configurable&nbsp;taint&nbsp;reporting**](docs/reference-modules/configurable-taint-reporting.md) | [1](ablation/analyzers/taint_tracker_x86_labeled.py)&nbsp;[2](ablation/analyzers/taint_tracker_arm32_labeled.py) | Policies control supported branch, memory-address, return-address, syscall-argument and bounded-index findings. |
| [**CFG&nbsp;fixpoint&nbsp;dataflow**](docs/reference-modules/cfg-fixpoint-dataflow.md) | [1](ablation/analyzers/analysis_x86.py)&nbsp;[2](ablation/analyzers/analysis_arm32.py) | Iterate supported per-architecture state joins across blocks and loops; separate from the binary-path scanners' linear/BFS modes. |
| [**Instrumentation-noise&nbsp;removal**](docs/reference-modules/instrumentation-noise-removal.md) | [1](ablation/analyzers/loongarch_decoder_v2.py)&nbsp;[2](ablation/analyzers/syscall_loongarch64.py) | Tag/filter supported LoongArch KASAN/KCOV call and shadow-address idioms using instrumentation symbols or addresses. |
| [**LoongArch&nbsp;syscall&nbsp;labeling**](docs/reference-modules/loongarch-syscall-labeling.md) | [1](ablation/analyzers/loongarch_decoder_v2.py)&nbsp;[2](ablation/analyzers/syscall_loongarch64.py) | Classify supported Linux syscall numbers, labels and security-relevant categories. |

</details>

<details>
<summary><strong>Semantic matching and retained knowledge</strong></summary>

| Capability | Code | |
|:---|:---|:---|
| [**Single/multi-binary&nbsp;corpus&nbsp;building**](docs/reference-modules/single-multi-binary-corpus-building.md) | [1](ablation/analyzers/corpus_builder.py)&nbsp;[2](ablation/analyzers/func_id_db.py) | Populate a function-identity database with descriptions, product/version metadata and inferred records. |
| [**Function&nbsp;identity&nbsp;database**](docs/reference-modules/function-identity-database.md) | [1](ablation/analyzers/corpus_builder.py)&nbsp;[2](ablation/analyzers/func_id_db.py) | Store function names, roles, signatures, structures and call chains across binary versions. |
| [**Analyst&nbsp;naming&nbsp;registry**](docs/reference-modules/analyst-naming-registry.md) | [1](ablation/analyzers/corpus_builder.py)&nbsp;[2](ablation/analyzers/func_id_db.py) | Persist, bulk-update and reload confirmed function names per binary. |
| [**Signature-based&nbsp;auto-naming**](docs/reference-modules/signature-based-auto-naming.md) | [1](ablation/analyzers/corpus_builder.py)&nbsp;[2](ablation/analyzers/func_id_db.py) | Match unknown functions against behavioral signatures with thresholds and dry-run support. |
| [**SAX&nbsp;approximate&nbsp;indexing**](docs/reference-modules/sax-approximate-indexing.md) | [1](ablation/analyzers/sax_index.py)&nbsp;[2](ablation/analyzers/subsequence_searcher.py) | Index opcode-category sequences for fast structural candidate lookup. |
| [**Behavioral&nbsp;subsequence&nbsp;search**](docs/reference-modules/behavioral-subsequence-search.md) | [1](ablation/analyzers/sax_index.py)&nbsp;[2](ablation/analyzers/subsequence_searcher.py) | Find exact or approximate opcode-category subpatterns within functions. |
| [**Structural&nbsp;similarity&nbsp;and&nbsp;orphan&nbsp;detection**](docs/reference-modules/structural.md) | [1](ablation/analyzers/sax_index.py)&nbsp;[2](ablation/analyzers/subsequence_searcher.py) | Compare opcode histograms, constants, calls and other structural signals to identify unmatched functions. |
| [**Embedding&nbsp;fine-tuning**](docs/reference-modules/embedding-fine-tuning.md) | [1](ablation/analyzers/sax_index.py)&nbsp;[2](ablation/analyzers/subsequence_searcher.py) | Generate structural homolog pairs, fine-tune similarity models and evaluate homolog/non-homolog separation. |
| [**Finding-corpus&nbsp;mining**](docs/reference-modules/finding-corpus-mining.md) | [1](sweeps/corpus_miner.py)&nbsp;[2](modules/cve_byte_patterns.py) | Extract confirmed local findings, summarize CWE frequency and identify repeated cross-target patterns or scanner gaps. |
| [**CVE&nbsp;byte-signature&nbsp;checks**](docs/reference-modules/cve-byte-signature-checks.md) | [1](sweeps/corpus_miner.py)&nbsp;[2](modules/cve_byte_patterns.py) | Match implemented architecture-specific vulnerable-byte signatures for selected patch-verification tasks. |
| [**Version-aware&nbsp;scan&nbsp;caching**](docs/reference-modules/version-aware-scan-caching.md) | [1](sweeps/corpus_miner.py)&nbsp;[2](modules/cve_byte_patterns.py) | Invalidate persisted scanner results when either target bytes or scanner source changes. |
| [**Vendor&nbsp;sink&nbsp;profiles**](docs/reference-modules/vendor-sink-profiles.md) | [1](sweeps/corpus_miner.py)&nbsp;[2](modules/cve_byte_patterns.py) | Load vendor-specific sinks and known-safe command patterns from profiles. |

</details>

<details>
<summary><strong>Additional vulnerability scanners and triage</strong></summary>

| Capability | Code | |
|:---|:---|:---|
| [**Architecture-specific&nbsp;sink&nbsp;provenance**](docs/reference-modules/sink-arg-classifier-mips.md) | [1](ablation/analyzers/sink_arg_classifier_arm32.py)&nbsp;[2](ablation/analyzers/sink_arg_classifier_mips.py) | Separate classifiers for ARM32, MIPS32, PPC32, i386 and PPC64 big-endian calling conventions. |
| [**Transitive&nbsp;sink-wrapper&nbsp;discovery**](docs/reference-modules/transitive-sink-wrapper-discovery.md) | [1](ablation/analyzers/sink_propagator.py)&nbsp;[2](ablation/analyzers/sanitizer_detector.py) | Find supported wrappers around dangerous x86-64 string/exec sinks. |
| [**Sanitizer&nbsp;recognition**](docs/reference-modules/sanitizer-recognition.md) | [1](ablation/analyzers/sink_propagator.py)&nbsp;[2](ablation/analyzers/sanitizer_detector.py) | Identify allowlist-style validators and assess coverage of shell metacharacters. |
| [**Sanitizer-gated&nbsp;sink&nbsp;filtering**](docs/reference-modules/sanitizer-gated-sink-filtering.md) | [1](ablation/analyzers/sink_propagator.py)&nbsp;[2](ablation/analyzers/sanitizer_detector.py) | Reclassify supported argument-propagated sites whose paths include recognized validation. |
| [**File-versus-socket&nbsp;input&nbsp;discrimination**](docs/reference-modules/file-versus-socket-input-discrimination.md) | [1](ablation/analyzers/sink_propagator.py)&nbsp;[2](ablation/analyzers/sanitizer_detector.py) | Classify ARM64 fgets sources using FILE-pointer provenance to reduce configuration-file false positives. |
| [**scanf-family&nbsp;overflow&nbsp;candidates**](docs/reference-modules/scanf-family-overflow-candidates.md) | [1](ablation/analyzers/sscanf_sink_classifier.py)&nbsp;[2](ablation/analyzers/deprecated_func_scanner.py) | Identify unbounded string conversion specifications at supported formatted-input call sites. |
| [**Deprecated&nbsp;unsafe-function&nbsp;scanning**](docs/reference-modules/deprecated-unsafe-function-scanning.md) | [1](ablation/analyzers/sscanf_sink_classifier.py)&nbsp;[2](ablation/analyzers/deprecated_func_scanner.py) | Flag imported inherently unsafe functions such as gets/mktemp/tmpnam/getwd as review candidates. |
| [**ARM32&nbsp;allocation&nbsp;arithmetic&nbsp;overflow**](docs/reference-modules/arm32-allocation-arithmetic-overflow.md) | [1](ablation/analyzers/sscanf_sink_classifier.py)&nbsp;[2](ablation/analyzers/deprecated_func_scanner.py) | Trace supported multiply operations with input-derived operands into allocation sizes. |
| [**PPC32&nbsp;heap-slot&nbsp;overflow**](docs/reference-modules/ppc32-heap-slot-overflow.md) | [1](ablation/analyzers/sscanf_sink_classifier.py)&nbsp;[2](ablation/analyzers/deprecated_func_scanner.py) | Detect fixed-slot allocation followed by supported unbounded string-copy patterns. |
| [**TLV/chunk&nbsp;alignment&nbsp;checks**](docs/reference-modules/tlv-chunk-alignment-checks.md) | [1](modules/chunk_walker_validator.py)&nbsp;[2](ablation/analyzers/epilogue_share_scanner.py) | Identify supported parser pointer advances that omit expected alignment rounding. |
| [**Shared-epilogue&nbsp;detection**](docs/reference-modules/shared-epilogue-detection.md) | [1](modules/chunk_walker_validator.py)&nbsp;[2](ablation/analyzers/epilogue_share_scanner.py) | Detect tail blocks shared through jumps so analysis can account for compiler-merged epilogues. |
| [**Fork/exec&nbsp;classification**](docs/reference-modules/fork-exec-classification.md) | [1](modules/chunk_walker_validator.py)&nbsp;[2](ablation/analyzers/epilogue_share_scanner.py) | Distinguish worker-child, exec-after-fork and exit-in-child patterns in supported x86-64 functions. |
| [**Apache&nbsp;module&nbsp;analysis**](docs/reference-modules/apache-module-analysis.md) | [1](ablation/analyzers/apache_module_analyzer.py)&nbsp;[2](ablation/analyzers/cmdb_surface_mapper.py) | Inspect supported APR/Apache binary module hooks and security-relevant authentication/session patterns. |
| [**CMDB-to-sink&nbsp;mapping**](docs/reference-modules/cmdb-to-sink-mapping.md) | [1](ablation/analyzers/apache_module_analyzer.py)&nbsp;[2](ablation/analyzers/cmdb_surface_mapper.py) | Associate supported Fortinet database-table accesses with functions that also invoke execution sinks. |
| [**HTTP&nbsp;method-enum&nbsp;recovery**](docs/reference-modules/http-method-enum-recovery.md) | [1](ablation/analyzers/apache_module_analyzer.py)&nbsp;[2](ablation/analyzers/cmdb_surface_mapper.py) | Infer supported Flatui route method identifiers from route-registration evidence. |
| [**Firmware-flasher&nbsp;trust&nbsp;checks**](docs/reference-modules/firmware-flasher-trust-checks.md) | [1](ablation/analyzers/apache_module_analyzer.py)&nbsp;[2](ablation/analyzers/cmdb_surface_mapper.py) | Flag PE firmware-update capability lacking recognized signature-verification imports as a review candidate. |
| [**VxWorks&nbsp;static-archive&nbsp;scanning**](docs/reference-modules/vxworks-archive-scanner.md) | [1](modules/vxworks_archive_scanner.py)&nbsp;[2](ablation/analyzers/compiler_security_gate.py) | Inspect PPC32 archive members for unbounded copies within selected stack-frame sizes. |
| [**Post-link&nbsp;compiler&nbsp;security&nbsp;gate**](docs/reference-modules/compiler_security_gate.md) | [1](modules/vxworks_archive_scanner.py)&nbsp;[2](ablation/analyzers/compiler_security_gate.py) | Run supported binary scanners against newly compiled artifacts and aggregate findings. |

</details>

<details>
<summary><strong>C++ and architecture-specific recovery</strong></summary>

| Capability | Code | |
|:---|:---|:---|
| [**ARM64&nbsp;virtual-call&nbsp;resolution**](docs/reference-modules/arm64-virtual-call-resolution.md) | [1](ablation/analyzers/vtable_resolver.py)&nbsp;[2](modules/elf_vtable_reconstructor.py) | Infer vtables, constructor vptr writes and supported BLR targets. |
| [**x86-64&nbsp;relocation-based&nbsp;vtables**](docs/reference-modules/x86-64-relocation-based-vtables.md) | [1](ablation/analyzers/vtable_resolver.py)&nbsp;[2](modules/elf_vtable_reconstructor.py) | Reconstruct virtual table slots from ELF RELA entries. |
| [**Live&nbsp;virtual-dispatch&nbsp;slots**](docs/reference-modules/live-virtual-dispatch-slots.md) | [1](ablation/analyzers/vtable_resolver.py)&nbsp;[2](modules/elf_vtable_reconstructor.py) | Find x86-64 indirect-call slot uses and distinguish referenced slots from unobserved ones. |
| [**PS3&nbsp;OPD&nbsp;virtual&nbsp;tables**](docs/reference-modules/ps3-opd-virtual-tables.md) | [1](ablation/analyzers/vtable_resolver.py)&nbsp;[2](modules/elf_vtable_reconstructor.py) | Recover PPC64 Cell PPU virtual tables through function descriptors. |
| [**Verified&nbsp;PPC32&nbsp;import&nbsp;callers**](docs/reference-modules/verified-ppc32-import-callers.md) | [1](ablation/analyzers/ppc32_plt_tracer.py)&nbsp;[2](ablation/analyzers/ppc64_elfv1_resolver.py) | Trace PLT thunk calls while checking the caller's active GOT2 base. |
| [**PPC64&nbsp;ELFv1&nbsp;resolution**](docs/reference-modules/ppc64-elfv1-resolution.md) | [1](ablation/analyzers/ppc32_plt_tracer.py)&nbsp;[2](ablation/analyzers/ppc64_elfv1_resolver.py) | Resolve OPD function descriptors, TOC-related metadata and glink import stubs. |
| [**Unnamed&nbsp;ARM64&nbsp;library-call&nbsp;classification**](docs/reference-modules/unnamed-arm64-library-call-classification.md) | [1](ablation/analyzers/ppc32_plt_tracer.py)&nbsp;[2](ablation/analyzers/ppc64_elfv1_resolver.py) | Classify PLT entries using argument/return behavior and a library-function summary database. |
| [**Classic&nbsp;Mac&nbsp;ABI&nbsp;clobber&nbsp;scanning**](docs/reference-modules/classic-mac-abi-clobber-scanning.md) | [1](ablation/analyzers/ppc32_plt_tracer.py)&nbsp;[2](ablation/analyzers/ppc64_elfv1_resolver.py) | Detect supported PPC32 PEF argument-register clobbers across intervening calls. |
| [**Data-structure&nbsp;pattern&nbsp;classification**](docs/reference-modules/data-structure-pattern-classification.md) | [1](ablation/analyzers/ppc64_dynds_classifier.py)&nbsp;[2](ablation/analyzers/ppc64_vmx_density.py) | Identify supported PPC64/Cell list/tree/traversal patterns from structural signals. |
| [**VMX/AltiVec&nbsp;density&nbsp;ranking**](docs/reference-modules/vmx-altivec-density-ranking.md) | [1](ablation/analyzers/ppc64_dynds_classifier.py)&nbsp;[2](ablation/analyzers/ppc64_vmx_density.py) | Locate vector-heavy PPC64 functions as candidates for math, physics or rendering code. |
| [**PPC32/PPC476&nbsp;dedicated&nbsp;lifting**](docs/reference-modules/ppc32-ppc476-dedicated-lifting.md) | [1](ablation/analyzers/ppc64_dynds_classifier.py)&nbsp;[2](ablation/analyzers/ppc64_vmx_density.py) | Additional pseudo-code/decompiler entry points for PowerPC and IBM Book E binaries. |

</details>

<details>
<summary><strong>Firmware, containers and legacy formats</strong></summary>

| Capability | Code | |
|:---|:---|:---|
| [**Firmware&nbsp;signature&nbsp;and&nbsp;secret&nbsp;triage**](docs/reference-modules/firmware-signature-and-secret-triage.md) | [1](ablation/core/firmware_analyzer.py)&nbsp;[2](ablation/analyzers/firmware_container.py) | Locate embedded format signatures, security-relevant strings, version indicators and entropy changes. |
| [**Partition-table&nbsp;extraction**](docs/reference-modules/partition-table-extraction.md) | [1](ablation/core/firmware_analyzer.py)&nbsp;[2](ablation/analyzers/firmware_container.py) | Enumerate and extract supported fixed-record firmware container partitions. |
| [**Hardware-root&nbsp;discovery**](docs/reference-modules/hardware-root-discovery.md) | [1](ablation/core/firmware_analyzer.py)&nbsp;[2](ablation/analyzers/firmware_container.py) | Identify MMIO load/store references to known peripheral address ranges. |
| [**AMI&nbsp;modified&nbsp;CramFS**](docs/reference-modules/ami-modified-cramfs.md) | [1](modules/ami_cramfs_extractor.py)&nbsp;[2](modules/huawei_squashfs_extractor.py) | Extract supported BMC filesystems with AMI-specific extended inode layouts. |
| [**Huawei&nbsp;modified&nbsp;SquashFS**](docs/reference-modules/huawei-modified-squashfs.md) | [1](modules/ami_cramfs_extractor.py)&nbsp;[2](modules/huawei_squashfs_extractor.py) | Extract supported vendor SquashFS/XZ layouts, including handling of ARM64 BCJ-filtered blocks. |
| [**Apple&nbsp;bv41&nbsp;decompression**](docs/reference-modules/apple-bv41-decompression.md) | [1](modules/ami_cramfs_extractor.py)&nbsp;[2](modules/huawei_squashfs_extractor.py) | Probe, iterate and stream-decode Apple's proprietary chunked LZ4 framing. |
| [**FortiMail&nbsp;VM&nbsp;key&nbsp;extraction**](docs/reference-modules/fortimail-vm-key-extraction.md) | [1](ablation/analyzers/fortimail_vmdk_extractor.py)&nbsp;[2](ablation/analyzers/fortibuild_track_classifier.py) | Extract supported key files from OVF/VMDK firmware layouts and their filesystem partitions. |
| [**Fortinet&nbsp;build-track&nbsp;classification**](docs/reference-modules/fortinet-build-track-classification.md) | [1](ablation/analyzers/fortimail_vmdk_extractor.py)&nbsp;[2](ablation/analyzers/fortibuild_track_classifier.py) | Parse product/version/build-track names and predict the known certificate-key family. |
| [**AIX&nbsp;plain&nbsp;BFF&nbsp;extraction**](docs/reference-modules/aix-plain-bff-extraction.md) | [1](ablation/core/bff_extractor.py)&nbsp;[2](modules/bff_decompressor.py) | Parse backup-by-name archives and extract contained files/directories. |
| [**Compressed&nbsp;BFF&nbsp;detection&nbsp;and&nbsp;LZW&nbsp;attempt**](docs/reference-modules/compressed-bff-detection-and-lzw-attempt.md) | [1](ablation/core/bff_extractor.py)&nbsp;[2](modules/bff_decompressor.py) | Identify compression variants and attempt supported LZW decompression through uncompress; Huffman variants report that AIX tooling is required. |
| [**AIX&nbsp;big&nbsp;archive&nbsp;extraction**](docs/reference-modules/aix-big-archive-extraction.md) | [1](ablation/core/bff_extractor.py)&nbsp;[2](modules/bff_decompressor.py) | Extract members from the AIX <bigaf> library/archive format. |
| [**AIX&nbsp;XCOFF32/64&nbsp;analysis**](docs/reference-modules/aix-xcoff32-64-analysis.md) | [1](ablation/core/xcoff_parser.py)&nbsp;[2](modules/xcoff_executable_analyzer.py) | Parse executable sections and loader symbols; enumerate imports/exports and candidate function entries. |
| [**Standalone&nbsp;XCOFF&nbsp;symbol&nbsp;resolution**](docs/reference-modules/standalone-xcoff-symbol-resolution.md) | [1](ablation/core/xcoff_parser.py)&nbsp;[2](modules/xcoff_executable_analyzer.py) | Recover library imports and exported code addresses without a full BinaryContext session. |
| [**IBM&nbsp;W-Code&nbsp;parsing**](docs/reference-modules/ibm-w-code-parsing.md) | [1](ablation/core/xcoff_parser.py)&nbsp;[2](modules/xcoff_executable_analyzer.py) | Parse supported XLC intermediate records and builtin-catalog references. |
| [**Motorola&nbsp;88000&nbsp;BCS&nbsp;COFF**](docs/reference-modules/motorola-88000-bcs-coff.md) | [1](ablation/core/coff_m88k_parser.py)&nbsp;[2](ablation/core/guardian_pak_extractor.py) | Parse legacy executable sections and feed the dedicated M88K decoder/context path. |
| [**Tandem&nbsp;Guardian&nbsp;PAK**](docs/reference-modules/tandem-guardian-pak.md) | [1](ablation/core/coff_m88k_parser.py)&nbsp;[2](ablation/core/guardian_pak_extractor.py) | Decompress supported Guardian BACKUP records and extract NonStop files. |
| [**AppleDouble&nbsp;resource&nbsp;forks**](docs/reference-modules/appledouble-resource-forks.md) | [1](ablation/core/coff_m88k_parser.py)&nbsp;[2](ablation/core/guardian_pak_extractor.py) | Parse classic Mac resource-fork and metadata containers. |
| [**PowerPC&nbsp;PEF/CFM**](docs/reference-modules/powerpc-pef-cfm.md) | [1](ablation/core/coff_m88k_parser.py)&nbsp;[2](ablation/core/guardian_pak_extractor.py) | Parse classic Mac code/data sections, imports and supported container metadata. |
| [**Installer&nbsp;payload&nbsp;analysis**](docs/reference-modules/installer-payload-analysis.md) | [1](modules/installer_binary_analyzer.py)&nbsp;[2](sweeps/win16_ne_sweep.py) | Extract supported BitRock LZMA payloads, carve PE candidates and optionally unpack UPX; recognize NSIS/Inno signatures. |
| [**Windows&nbsp;16-bit&nbsp;NE**](docs/reference-modules/windows-16-bit-ne.md) | [1](modules/installer_binary_analyzer.py)&nbsp;[2](sweeps/win16_ne_sweep.py) | Parse segmented New Executable binaries and sweep supported imports/calls/security patterns. |
| [**Windows&nbsp;LE/VxD**](docs/reference-modules/windows-le-vxd.md) | [1](modules/installer_binary_analyzer.py)&nbsp;[2](sweeps/win16_ne_sweep.py) | Parse Linear Executable drivers, inspect device-descriptor data and sweep supported ring-0 code patterns. |
| [**MS-DOS&nbsp;MZ**](docs/reference-modules/ms-dos-mz.md) | [1](modules/installer_binary_analyzer.py)&nbsp;[2](sweeps/win16_ne_sweep.py) | Parse real-mode headers/relocations and analyze supported multi-segment 16-bit code. |

</details>

<details>
<summary><strong>Language and application runtimes</strong></summary>

| Capability | Code | |
|:---|:---|:---|
| [**DEX&nbsp;disassembly&nbsp;and&nbsp;lifting**](docs/reference-modules/dex-disassembly-and-lifting.md) | [1](ablation/analyzers/dex_disasm.py)&nbsp;[2](ablation/analyzers/dex_lifter.py) | Decode instructions to annotated smali and supported pseudo-Java. |
| [**Android&nbsp;Binder&nbsp;surface**](docs/reference-modules/android-binder-surface.md) | [1](ablation/analyzers/dex_disasm.py)&nbsp;[2](ablation/analyzers/dex_lifter.py) | Correlate exported services and DEX classes to identify Binder IPC exposure. |
| [**JNI&nbsp;bridge&nbsp;reconstruction**](docs/reference-modules/jni-bridge-reconstruction.md) | [1](ablation/analyzers/dex_disasm.py)&nbsp;[2](ablation/analyzers/dex_lifter.py) | Associate native declarations, loadLibrary uses, peer-pointer fields and native exports. |
| [**Specialized&nbsp;JNI&nbsp;protocol&nbsp;analysis**](docs/reference-modules/deep-jni-analysis.md) | [1](modules/deep_jni_analysis.py)&nbsp;[2](modules/analyze_all_jni.py) | Scripts for deeper vtable, field-write and protocol analysis, including libhijoyptt-specific assumptions. |
| [**Go&nbsp;string&nbsp;recovery**](docs/reference-modules/go-string-recovery.md) | [1](ablation/analyzers/go_string_resolver.py)&nbsp;[2](ablation/analyzers/go_subprocess_scanner.py) | Resolve length-delimited strings under the supported AMD64 Go register ABI. |
| [**Go&nbsp;subprocess&nbsp;surface**](docs/reference-modules/go-subprocess-surface.md) | [1](ablation/analyzers/go_string_resolver.py)&nbsp;[2](ablation/analyzers/go_subprocess_scanner.py) | Find os/exec call sites and recover static command-path arguments where possible. |
| [**Go&nbsp;dangerous-call&nbsp;graph**](docs/reference-modules/go-dangerous-call-graph.md) | [1](ablation/analyzers/go_string_resolver.py)&nbsp;[2](ablation/analyzers/go_subprocess_scanner.py) | Build/cache caller maps, filter application namespaces and resolve supported interface tables. |
| [**Stripped&nbsp;Go&nbsp;x86-64&nbsp;boundaries**](docs/reference-modules/stripped-go-x86-64-boundaries.md) | [1](ablation/analyzers/go_string_resolver.py)&nbsp;[2](ablation/analyzers/go_subprocess_scanner.py) | Recover function entries from pclntab when conventional symbols/debug info are absent. |
| [**Java&nbsp;class/JAR&nbsp;parsing**](docs/reference-modules/java-class-jar-parsing.md) | [1](modules/java_re.py)&nbsp;[2](modules/java_decompiler.py) | Read constant pools, methods, fields, descriptors, manifests and archives. |
| [**Java&nbsp;security&nbsp;pattern&nbsp;scans**](docs/reference-modules/java-security-pattern-scans.md) | [1](modules/java_re.py)&nbsp;[2](modules/java_decompiler.py) | Flag supported reflection, serialization, class-loading, Runtime.exec, SSRF, XXE, JNDI, weak randomness and hardcoded-secret patterns. |
| [**JVM/Spring&nbsp;exposure&nbsp;inspection**](docs/reference-modules/jvm-spring-exposure-inspection.md) | [1](modules/java_re.py)&nbsp;[2](modules/java_decompiler.py) | Inspect JVM flags/debug endpoints, agents and supported Spring Actuator/application-context surfaces. |
| [**Python&nbsp;.pyc&nbsp;scanning**](docs/reference-modules/python-pyc-scanning.md) | [1](ablation/analyzers/pyc_bytecode_scanner.py)&nbsp;[2](ablation/analyzers/perl_taint_scanner.py) | Inspect supported code objects for dangerous bytecode/name/constant patterns without source files. |
| [**Perl&nbsp;shell-injection&nbsp;scanning**](docs/reference-modules/perl-shell-injection-scanning.md) | [1](ablation/analyzers/pyc_bytecode_scanner.py)&nbsp;[2](ablation/analyzers/perl_taint_scanner.py) | Trace supported Perl input sources into system/exec/qx/backtick-style sinks. |
| [**Electron&nbsp;application&nbsp;auditing**](docs/reference-modules/electron-application-auditing.md) | [1](ablation/analyzers/pyc_bytecode_scanner.py)&nbsp;[2](ablation/analyzers/perl_taint_scanner.py) | Scan extracted JavaScript for unsafe Electron settings, IPC and execution patterns. |
| [**Browser-extension&nbsp;auditing**](docs/reference-modules/browser-extension-auditing.md) | [1](ablation/analyzers/pyc_bytecode_scanner.py)&nbsp;[2](ablation/analyzers/perl_taint_scanner.py) | Inspect extension manifests, permissions, external messaging and privileged JavaScript patterns. |

</details>

<details>
<summary><strong>Source repository auditing</strong></summary>

| Capability | Code | |
|:---|:---|:---|
| [**Repository&nbsp;ingestion&nbsp;and&nbsp;search**](docs/reference-modules/repository-ingestion-and-search.md) | [1](ablation/analyzers/source_ingestion.py)&nbsp;[2](ablation/analyzers/source_entry_classifier.py) | Build a local/remote source index, categorize languages and retrieve matching text/context. |
| [**Route&nbsp;authentication&nbsp;classification**](docs/reference-modules/route-authentication-classification.md) | [1](ablation/analyzers/source_ingestion.py)&nbsp;[2](ablation/analyzers/source_entry_classifier.py) | Map supported source HTTP routes to authentication-wrapper levels. |
| [**Source&nbsp;dangerous-sink&nbsp;detection**](docs/reference-modules/source-dangerous-sink-detection.md) | [1](ablation/analyzers/source_ingestion.py)&nbsp;[2](ablation/analyzers/source_entry_classifier.py) | Scan supported eval, subprocess, SSRF, path traversal and internal-endpoint patterns. |
| [**Tenant-isolation&nbsp;checks**](docs/reference-modules/tenant-isolation-checks.md) | [1](ablation/analyzers/source_ingestion.py)&nbsp;[2](ablation/analyzers/source_entry_classifier.py) | Identify supported database accesses without expected user/project/organization scoping. |
| [**Architectural-risk&nbsp;detection**](docs/reference-modules/architectural-risk-detection.md) | [1](ablation/analyzers/source_ingestion.py)&nbsp;[2](ablation/analyzers/source_entry_classifier.py) | Flag unsafe rendering combined with extensible dispatch or shared context that may increase future exposure. |

</details>

<details>
<summary><strong>Automotive and embedded details</strong></summary>

| Capability | Code | |
|:---|:---|:---|
| [**C166/C167&nbsp;decoding**](docs/reference-modules/c166-c167-decoding.md) | [1](ablation/analyzers/ecu_c166_decoder.py)&nbsp;[2](ablation/analyzers/ecu_c28x_decoder.py) | Decode supported instructions, find functions, inspect XRAM accesses and parse interrupt vectors. |
| [**TI&nbsp;C28x&nbsp;decoding**](docs/reference-modules/ti-c28x-decoding.md) | [1](ablation/analyzers/ecu_c166_decoder.py)&nbsp;[2](ablation/analyzers/ecu_c28x_decoder.py) | Decode supported DSP instructions and recover candidate function starts. |
| [**M68K/CPU32&nbsp;decoding**](docs/reference-modules/m68k-cpu32-decoding.md) | [1](ablation/analyzers/ecu_c166_decoder.py)&nbsp;[2](ablation/analyzers/ecu_c28x_decoder.py) | Decode supported ECU instructions and discover function entries. |
| [**Renesas&nbsp;SH-2A&nbsp;decoding**](docs/reference-modules/renesas-sh-2a-decoding.md) | [1](ablation/analyzers/ecu_c166_decoder.py)&nbsp;[2](ablation/analyzers/ecu_c28x_decoder.py) | Handle supported instruction widths, calls, functions and delay-slot-aware CFG/lifting. |
| [**PowerPC&nbsp;VLE&nbsp;decoding**](docs/reference-modules/powerpc-vle-decoding.md) | [1](ablation/analyzers/ecu_c166_decoder.py)&nbsp;[2](ablation/analyzers/ecu_c28x_decoder.py) | Handle supported mixed 16/32-bit e200 ECU instructions and function discovery. |
| [**HiSilicon&nbsp;RISC-V&nbsp;extensions**](docs/reference-modules/hisilicon-risc-v-extensions.md) | [1](ablation/analyzers/hisi_rv32_ext.py)&nbsp;[2](modules/isa_8051.py) | Decode supported proprietary riscv31 opcodes, widths and multi-register memory operations. |
| [**8051&nbsp;ISA&nbsp;modeling**](docs/reference-modules/8051-isa-modeling.md) | [1](ablation/analyzers/hisi_rv32_ext.py)&nbsp;[2](modules/isa_8051.py) | Model MCS-51 registers, separate memory spaces, instruction semantics and selected security-analysis facts. |
| [**TI&nbsp;COFF/archive&nbsp;loading**](docs/reference-modules/ti-coff-archive-loading.md) | [1](ablation/analyzers/hisi_rv32_ext.py)&nbsp;[2](modules/isa_8051.py) | Parse supported TI COFF2 objects and archive symbols/sections. |
| [**TI&nbsp;neural-network&nbsp;artifacts**](docs/reference-modules/ti-neural-network-artifacts.md) | [1](ablation/analyzers/hisi_rv32_ext.py)&nbsp;[2](modules/isa_8051.py) | Identify supported TVM/NNC-generated symbols and inspect inference-artifact metadata/patterns. |
| [**TI&nbsp;SDK&nbsp;package&nbsp;sweeping**](docs/reference-modules/ti-sdk-package-sweeping.md) | [1](ablation/analyzers/hisi_rv32_ext.py)&nbsp;[2](modules/isa_8051.py) | Dispatch supported COFF, ARM, ARM64 and flat-ROM artifacts across package directories/archives. |
| [**Calibration&nbsp;table&nbsp;interpretation**](docs/reference-modules/calibration-table-interpretation.md) | [1](ablation/analyzers/ecu_cal_def.py)&nbsp;[2](ablation/analyzers/ecu_open_damos_parser.py) | Represent axes, scaling and table metadata; read supported calibration values and produce address labels. |
| [**Calibration&nbsp;variant/relocation&nbsp;support**](docs/reference-modules/calibration-variant-relocation-support.md) | [1](ablation/analyzers/ecu_cal_def.py)&nbsp;[2](ablation/analyzers/ecu_open_damos_parser.py) | Resolve supported inherited definition variants, identify ROMs and locate fingerprint-relocated open_damos tables. |

</details>

<details>
<summary><strong>Windows security details</strong></summary>

| Capability | Code | |
|:---|:---|:---|
| [**Control&nbsp;Flow&nbsp;Guard&nbsp;review**](docs/reference-modules/control-flow-guard-review.md) | [1](ablation/analyzers/cfg_bypass_detector.py)&nbsp;[2](ablation/analyzers/seh_chain_analyzer.py) | Inspect CFG metadata and supported exported-target/bypass opportunity patterns. |
| [**SEH&nbsp;and&nbsp;SafeSEH&nbsp;review**](docs/reference-modules/seh-and-safeseh-review.md) | [1](ablation/analyzers/cfg_bypass_detector.py)&nbsp;[2](ablation/analyzers/seh_chain_analyzer.py) | Inspect x86 handler registration/chains, protections and suspicious handler patterns. |
| [**COM&nbsp;attack-surface&nbsp;mapping**](docs/reference-modules/com-attack-surface-mapping.md) | [1](ablation/analyzers/cfg_bypass_detector.py)&nbsp;[2](ablation/analyzers/seh_chain_analyzer.py) | Find supported COM registrations and privilege-boundary/hijacking indicators. |
| [**ETW&nbsp;provider&nbsp;extraction**](docs/reference-modules/etw-provider-extraction.md) | [1](ablation/analyzers/cfg_bypass_detector.py)&nbsp;[2](ablation/analyzers/seh_chain_analyzer.py) | Recover provider/event indicators and assess supported telemetry patterns. |
| [**Kernel&nbsp;pool&nbsp;flow&nbsp;checks**](docs/reference-modules/kernel-pool-flow-checks.md) | [1](ablation/analyzers/cfg_bypass_detector.py)&nbsp;[2](ablation/analyzers/seh_chain_analyzer.py) | Track supported pool allocations toward copies/writes using bounded instruction-window heuristics. |
| [**PDB&nbsp;integration**](docs/reference-modules/pdb-integration.md) | [1](ablation/analyzers/cfg_bypass_detector.py)&nbsp;[2](ablation/analyzers/seh_chain_analyzer.py) | Read PE debug references, fetch/load supported PDB information and inject recovered names into context. |

</details>

<details>
<summary><strong>Cryptography and authentication details</strong></summary>

| Capability | Code | |
|:---|:---|:---|
| [**Repeating-XOR&nbsp;key&nbsp;recovery**](docs/reference-modules/repeating-xor-key-recovery.md) | [1](ablation/analyzers/xor_solver.py)&nbsp;[2](ablation/analyzers/crypto_pattern_detector.py) | Use known plaintext, key-length scoring and frequency/transposition methods. |
| [**Affine&nbsp;mapping&nbsp;analysis**](docs/reference-modules/affine-mapping-analysis.md) | [1](ablation/analyzers/xor_solver.py)&nbsp;[2](ablation/analyzers/crypto_pattern_detector.py) | Inspect supported affine byte mappings as a helper for encoded data recovery. |
| [**Hash/AES&nbsp;implementation&nbsp;recognition**](docs/reference-modules/hash-aes-implementation-recognition.md) | [1](ablation/analyzers/xor_solver.py)&nbsp;[2](ablation/analyzers/crypto_pattern_detector.py) | Detect hash constants and supported custom ARM32/Thumb AES-CBC patterns. |
| [**JWT&nbsp;analysis&nbsp;and&nbsp;weak-secret&nbsp;testing**](docs/reference-modules/jwt-analysis-and-weak-secret-testing.md) | [1](ablation/analyzers/xor_solver.py)&nbsp;[2](ablation/analyzers/crypto_pattern_detector.py) | Decode tokens, inspect algorithms and test candidate weak signing secrets; token-construction helpers are present. |
| [**SAML&nbsp;and&nbsp;key-material&nbsp;review**](docs/reference-modules/saml-and-key-material-review.md) | [1](ablation/analyzers/xor_solver.py)&nbsp;[2](ablation/analyzers/crypto_pattern_detector.py) | Inspect assertion structure/wrapping indicators and search for embedded key material. |
| [**RSA/ECDSA&nbsp;and&nbsp;randomness&nbsp;checks**](docs/reference-modules/rsa-ecdsa-and-randomness-checks.md) | [1](ablation/analyzers/xor_solver.py)&nbsp;[2](ablation/analyzers/crypto_pattern_detector.py) | Helpers inspect RSA/prime properties, ECDSA nonce reuse, RNG/hash/key-management weaknesses and selected timing/nonce risks. |
| [**Crypto/C2&nbsp;encoding&nbsp;indicators**](docs/reference-modules/crypto-c2-encoding-indicators.md) | [1](ablation/analyzers/xor_solver.py)&nbsp;[2](ablation/analyzers/crypto_pattern_detector.py) | Recognize selected XOR, RC4, Base64, Salsa/ChaCha, AES and arithmetic-encoding patterns. |

</details>

<details>
<summary><strong>TLS and web/API analysis</strong></summary>

| Capability | Code | |
|:---|:---|:---|
| [**TLS&nbsp;certificate&nbsp;and&nbsp;protocol&nbsp;probing**](docs/reference-modules/tls-certificate-and-protocol-probing.md) | [1](ablation/core/tls_analyzer.py)&nbsp;[2](modules/tls_enum.py) | Inspect certificates, key strength, legacy versions/ciphers, DH-related properties and handshake behavior. |
| [**TLS&nbsp;policy&nbsp;checks**](docs/reference-modules/tls-policy-checks.md) | [1](ablation/core/tls_analyzer.py)&nbsp;[2](modules/tls_enum.py) | Probe HSTS, redirects, mTLS, pinning-related headers, SCT/CT indicators and ACME-related exposure. |
| [**TLS&nbsp;session/downgrade&nbsp;surfaces**](docs/reference-modules/tls-session-downgrade-surfaces.md) | [1](ablation/core/tls_analyzer.py)&nbsp;[2](modules/tls_enum.py) | Probe supported resumption, downgrade, inspection/proxy and zero-trust gateway configurations. |
| [**Unknown&nbsp;HTTP&nbsp;API&nbsp;mapping**](docs/reference-modules/unknown-http-api-mapping.md) | [1](modules/api_re.py) | Discover paths/versions/methods, harvest OpenAPI and infer parameter/schema/error/state behavior. |
| [**API&nbsp;authorization&nbsp;checks**](docs/reference-modules/api-authorization-checks.md) | [1](modules/api_re.py) | Probe supported object/function-level authorization, mass assignment and excessive-data exposure cases. |
| [**API&nbsp;injection&nbsp;and&nbsp;validation&nbsp;checks**](docs/reference-modules/api-injection-and-validation-checks.md) | [1](modules/api_re.py) | Probe supported parameter pollution, content-type switching, SSRF, NoSQL, host-header and other input-handling surfaces. |
| [**API&nbsp;authentication&nbsp;and&nbsp;token&nbsp;checks**](docs/reference-modules/api-authentication-and-token-checks.md) | [1](modules/api_re.py) | Inspect JWT/OAuth flows, state/PKCE, default credentials, rate limiting and timing behavior. |
| [**Additional&nbsp;API&nbsp;protocols**](docs/reference-modules/additional-api-protocols.md) | [1](modules/api_re.py) | Discovery/probes for GraphQL, gRPC reflection, SOAP/WSDL, JSON-RPC and WebSocket interfaces. |
| [**Business-logic&nbsp;and&nbsp;version&nbsp;exposure**](docs/reference-modules/business-logic-and-version-exposure.md) | [1](modules/api_re.py) | Probe state changes, pagination, hidden parameters, shadow versions and webhook behaviors. |
| [**Nginx&nbsp;fingerprinting&nbsp;and&nbsp;exposure**](docs/reference-modules/nginx-fingerprinting-and-exposure.md) | [1](modules/nginx_enum.py) | Inspect server/version disclosure, status/debug endpoints, autoindex and sensitive paths. |
| [**Nginx&nbsp;configuration&nbsp;probes**](docs/reference-modules/nginx-configuration-probes.md) | [1](modules/nginx_enum.py) | Check supported alias traversal, proxy SSRF, host-header, smuggling, authentication, ingress and rate-limit surfaces. |
| [**Version-linked&nbsp;web&nbsp;checks**](docs/reference-modules/version-linked-web-checks.md) | [1](modules/nginx_enum.py) | Identify selected historical nginx CVE indicators; matches still require target-specific verification. |

</details>

<details>
<summary><strong>Host, process and privilege enumeration</strong></summary>

| Capability | Code | |
|:---|:---|:---|
| [**Host&nbsp;platform&nbsp;inventory**](docs/reference-modules/host-platform-inventory.md) | [1](modules/process_enum.py)&nbsp;[2](modules/syscall_trace.py) | Detect OS, architecture, kernel/libc and selected security/capability settings. |
| [**Process&nbsp;and&nbsp;memory-map&nbsp;inventory**](docs/reference-modules/process-and-memory-map-inventory.md) | [1](modules/process_enum.py)&nbsp;[2](modules/syscall_trace.py) | Enumerate processes, loaded modules, executable/RWX regions, open files and environment data. |
| [**System-call&nbsp;tracing**](docs/reference-modules/system-call-tracing.md) | [1](modules/process_enum.py)&nbsp;[2](modules/syscall_trace.py) | Invoke supported strace/ptrace-based tracing and summarize file, network and process operations. |
| [**Injection&nbsp;and&nbsp;persistence&nbsp;indicators**](docs/reference-modules/injection-and-persistence-indicators.md) | [1](modules/process_enum.py)&nbsp;[2](modules/syscall_trace.py) | Inspect supported process-hollowing, preload/library-hijack, ptrace, cron, services and named-pipe patterns. |
| [**Linux&nbsp;privilege-escalation&nbsp;triage**](docs/reference-modules/linux-privilege-escalation-triage.md) | [1](modules/privesc_enum.py)&nbsp;[2](modules/windows_enum.py) | Enumerate SUID, sudo, capabilities, writable paths/cron, credential-file exposure, Docker access and kernel/namespace conditions. |
| [**Windows&nbsp;live&nbsp;enumeration**](docs/reference-modules/windows-live-enumeration.md) | [1](modules/privesc_enum.py)&nbsp;[2](modules/windows_enum.py) | Inspect COM registration differences, RPC endpoints, ETW sessions, pipes, policies, services, autoruns, privileges and loaded modules. |
| [**Windows&nbsp;escalation&nbsp;indicators**](docs/reference-modules/windows-escalation-indicators.md) | [1](modules/privesc_enum.py)&nbsp;[2](modules/windows_enum.py) | Check supported unquoted-service, installer-policy, token, scheduled-task and UAC/driver indicators. |

</details>

<details>
<summary><strong>Forensics and malware triage</strong></summary>

| Capability | Code | |
|:---|:---|:---|
| [**Windows&nbsp;artifact&nbsp;discovery**](docs/reference-modules/windows-artifact-discovery.md) | [1](modules/forensics_enum.py)&nbsp;[2](modules/process_enum.py) | Locate MFT/LNK/Prefetch/EVTX-related artifacts and markers; this is not full decoding of those formats. |
| [**Volatile&nbsp;and&nbsp;Linux&nbsp;artifact&nbsp;triage**](docs/reference-modules/volatile-and-linux-artifact-triage.md) | [1](modules/forensics_enum.py)&nbsp;[2](modules/process_enum.py) | Inspect process/procfs/memory-access indicators, histories, deleted executables and selected volatile evidence. |
| [**Timestamp/log&nbsp;anomaly&nbsp;checks**](docs/reference-modules/timestamp-log-anomaly-checks.md) | [1](modules/forensics_enum.py)&nbsp;[2](modules/process_enum.py) | Identify selected timestomping, empty/deleted log and related metadata indicators. |
| [**Rootkit/bootkit&nbsp;indicators**](docs/reference-modules/rootkit-bootkit-indicators.md) | [1](modules/forensics_enum.py)&nbsp;[2](modules/process_enum.py) | Match supported SSDT/callback/hiding, DPC/timer, raw-disk and boot-sector patterns. |
| [**Malware&nbsp;behavior&nbsp;indicators**](docs/reference-modules/malware-behavior-indicators.md) | [1](modules/forensics_enum.py)&nbsp;[2](modules/process_enum.py) | Inspect keylogger, clipboard, mutex, downloader/backdoor, fileless and reflective-loading API/string combinations. |
| [**Packing&nbsp;and&nbsp;anti-analysis&nbsp;indicators**](docs/reference-modules/packing-and-anti-analysis-indicators.md) | [1](modules/forensics_enum.py)&nbsp;[2](modules/process_enum.py) | Detect selected packed-section, PEB/debugger, opaque/junk-code, anti-disassembly and sandbox-environment patterns. |
| [**Office/PDF&nbsp;triage**](docs/reference-modules/office-pdf-triage.md) | [1](modules/forensics_enum.py)&nbsp;[2](modules/process_enum.py) | Scan raw document markers for macro and exploit indicators without full document interpretation. |
| [**ELF&nbsp;recovery&nbsp;from&nbsp;physical-memory&nbsp;dumps**](docs/reference-modules/elf-recovery-from-physical-memory-dumps.md) | [1](modules/physmem_elf_vfs.py)&nbsp;[2](modules/video_container.py) | Find supported ELF64 images and reconstruct candidates using contiguous mappings and proximity heuristics. |
| [**Video-container&nbsp;forensics**](docs/reference-modules/video-container-forensics.md) | [1](modules/physmem_elf_vfs.py)&nbsp;[2](modules/video_container.py) | Parse MP4/MOV, MKV/WebM and AVI structures for appended payloads, suspicious metadata, malformed sizes and encrypted-track markers. |
| [**IOC&nbsp;candidate&nbsp;extraction**](docs/reference-modules/ioc-candidate-extraction.md) | [1](modules/physmem_elf_vfs.py)&nbsp;[2](modules/video_container.py) | Extract supported URL/address/path/key/certificate and other suspicious-string candidates. |
| [**ATT&CK&nbsp;labeling**](docs/reference-modules/attandck-labeling.md) | [1](ablation/core/attck_tagger.py) | Map recognized finding categories to configured ATT&CK technique labels. |

</details>

<details>
<summary><strong>Network discovery and traffic inspection</strong></summary>

| Capability | Code | |
|:---|:---|:---|
| [**Local&nbsp;network&nbsp;inventory**](docs/reference-modules/local-network-inventory.md) | [1](modules/network_analyze.py)&nbsp;[2](modules/net_sniffer.py) | Enumerate interfaces, connections, listening ports and firewall rules. |
| [**Raw&nbsp;packet&nbsp;capture**](docs/reference-modules/raw-packet-capture.md) | [1](modules/network_analyze.py)&nbsp;[2](modules/net_sniffer.py) | Capture supported traffic and parse selected IPv4/TCP/UDP headers. |
| [**PCAP&nbsp;inspection**](docs/reference-modules/pcap-inspection.md) | [1](modules/network_analyze.py)&nbsp;[2](modules/net_sniffer.py) | Packet-level DNS queries, HTTP metadata and selected cleartext credential extraction. |
| [**Host/service&nbsp;discovery**](docs/reference-modules/host-service-discovery.md) | [1](modules/network_analyze.py)&nbsp;[2](modules/net_sniffer.py) | ICMP/TCP discovery, banners, mDNS, SSDP, ARP observations and basic TTL/application fingerprinting. |
| [**Web-path&nbsp;enumeration**](docs/reference-modules/web-path-enumeration.md) | [1](modules/network_analyze.py)&nbsp;[2](modules/net_sniffer.py) | Discover directories, listings and other supported web paths. |
| [**Industrial/IoT&nbsp;probes**](docs/reference-modules/industrial-iot-probes.md) | [1](modules/network_analyze.py)&nbsp;[2](modules/net_sniffer.py) | Exposure checks for supported Modbus, MQTT, CoAP, SNMP, NTP and NetFlow/IPFIX services. |
| [**Additional&nbsp;industrial/debug&nbsp;probes**](docs/reference-modules/additional-industrial-debug-probes.md) | [1](modules/syscall_trace.py)&nbsp;[2](modules/lateral_movement.py) | Probe BACnet, EtherNet/IP and supported debugger interfaces. |
| [**Internal-network&nbsp;reconnaissance**](docs/reference-modules/internal-network-reconnaissance.md) | [1](modules/syscall_trace.py)&nbsp;[2](modules/lateral_movement.py) | Parse ARP/routes, discover subnets/names and inspect remote-management/database surfaces. |
| [**Credential/token/key&nbsp;discovery**](docs/reference-modules/credential-token-key-discovery.md) | [1](modules/syscall_trace.py)&nbsp;[2](modules/lateral_movement.py) | Enumerate accessible configuration credentials, API tokens, SSH keys and cloud-metadata surfaces. |
| [**Remote-management&nbsp;and&nbsp;identity&nbsp;probes**](docs/reference-modules/remote-management-and-identity-probes.md) | [1](modules/syscall_trace.py)&nbsp;[2](modules/lateral_movement.py) | Supported SMB/NTLM, RPC, WinRM, RDP, WMI, SSH and Active Directory-related surface checks. |
| [**Credential-testing&nbsp;helpers**](docs/reference-modules/credential-testing-helpers.md) | [1](modules/syscall_trace.py)&nbsp;[2](modules/lateral_movement.py) | Explicit SSH/FTP credential-spray and related authentication-testing helpers exist as callable functions. |
| [**C2/exfiltration&nbsp;indicators**](docs/reference-modules/c2-exfiltration-indicators.md) | [1](modules/syscall_trace.py)&nbsp;[2](modules/lateral_movement.py) | Inspect supported beaconing, DNS/HTTP/IRC/ICMP/covert-channel, tunneling, cloud-storage and ransomware-precursor patterns. |
| [**IOS/IOS-XE&nbsp;appliance&nbsp;enumeration**](docs/reference-modules/ios-ios-xe-appliance-enumeration.md) | [1](modules/ios_enum.py)&nbsp;[2](modules/nxos_enum.py) | HTTP/API, SNMP, CDP/LLDP, Telnet/TFTP, configuration parsing and supported AAA/network/security-management checks. |
| [**Appliance&nbsp;configuration&nbsp;secret&nbsp;helpers**](docs/reference-modules/appliance-configuration-secret-helpers.md) | [1](modules/ios_enum.py)&nbsp;[2](modules/nxos_enum.py) | Type-7 decoding and selected SNMP-community/enable-secret credential-testing helpers. |
| [**SD-WAN/Meraki&nbsp;management&nbsp;probes**](docs/reference-modules/sd-wan-meraki-management-probes.md) | [1](modules/hyperflex_enum.py)&nbsp;[2](modules/nexus_dashboard_enum.py) | Management-API exposure probes for supported SD-WAN and cloud-managed network products. |

</details>

<details>
<summary><strong>Containers, cloud infrastructure and services</strong></summary>

| Capability | Code | |
|:---|:---|:---|
| [**Docker&nbsp;inventory&nbsp;and&nbsp;posture**](docs/reference-modules/docker-inventory-and-posture.md) | [1](modules/docker_enum.py)&nbsp;[2](modules/k8s_enum.py) | Enumerate containers, images, volumes, networks, mounts, capabilities, privileged modes, sockets, ports and environment secrets. |
| [**Container&nbsp;isolation/escape&nbsp;surface**](docs/reference-modules/container-isolation-escape-surface.md) | [1](modules/docker_enum.py)&nbsp;[2](modules/k8s_enum.py) | Inspect supported host mounts, namespace/capability, resource and image-layer risks. |
| [**Kubernetes&nbsp;inventory**](docs/reference-modules/kubernetes-inventory.md) | [1](modules/docker_enum.py)&nbsp;[2](modules/k8s_enum.py) | Enumerate pods, services, namespaces, secrets and ConfigMaps through kubectl or supported direct API calls. |
| [**Kubernetes&nbsp;identity&nbsp;and&nbsp;RBAC**](docs/reference-modules/kubernetes-identity-and-rbac.md) | [1](modules/docker_enum.py)&nbsp;[2](modules/k8s_enum.py) | Inspect service-account bundles, SelfSubjectAccessReview permissions and cluster-admin/role bindings. |
| [**Kubernetes&nbsp;policy/posture**](docs/reference-modules/kubernetes-policy-posture.md) | [1](modules/docker_enum.py)&nbsp;[2](modules/k8s_enum.py) | Review network policies, admission/webhooks, pod security, hostPath/projected storage, ingress, mesh mTLS and resource settings. |
| [**Cluster&nbsp;management&nbsp;exposure**](docs/reference-modules/cluster-management-exposure.md) | [1](modules/docker_enum.py)&nbsp;[2](modules/k8s_enum.py) | Probe supported etcd, kubelet, dashboards, node services, cloud metadata and Orka endpoints. |
| [**Messaging/streaming&nbsp;enumeration**](docs/reference-modules/messaging-streaming-enumeration.md) | [1](modules/network_analyze.py)&nbsp;[2](modules/streaming_enum.py) | Inspect supported Kafka, Flink, NiFi, schema registries, RabbitMQ, NATS, Pulsar and event-store/registry surfaces. |
| [**Streaming&nbsp;operational&nbsp;helpers**](docs/reference-modules/streaming-operational-helpers.md) | [1](modules/network_analyze.py)&nbsp;[2](modules/streaming_enum.py) | Kafka topic/sample consumption and Flink JAR-submission helpers are present, alongside enumeration. |
| [**Database/storage&nbsp;exposure**](docs/reference-modules/database-storage-exposure.md) | [1](modules/network_analyze.py)&nbsp;[2](modules/streaming_enum.py) | Probe supported Redis, Elasticsearch, MinIO, InfluxDB and database endpoints. |
| [**Observability&nbsp;exposure**](docs/reference-modules/observability-exposure.md) | [1](modules/network_analyze.py)&nbsp;[2](modules/streaming_enum.py) | Probe Prometheus, Grafana, Jaeger, Loki, OpenTelemetry, Alertmanager, Thanos and related collectors. |
| [**Orchestration/management&nbsp;exposure**](docs/reference-modules/orchestration-management-exposure.md) | [1](modules/network_analyze.py)&nbsp;[2](modules/streaming_enum.py) | Probe supported vCenter, Rancher, Consul, Linkerd, Kong, Traefik, Temporal, Argo, Nomad and AWX/NSO surfaces. |
| [**CI/CD&nbsp;and&nbsp;artifact&nbsp;services**](docs/reference-modules/ci-cd-and-artifact-services.md) | [1](modules/network_analyze.py)&nbsp;[2](modules/streaming_enum.py) | Probe supported Jenkins, GitLab, Tekton, Argo CD, Flux, Crossplane, SonarQube, Artifactory and Nexus endpoints. |
| [**Secrets/access&nbsp;infrastructure**](docs/reference-modules/secrets-access-infrastructure.md) | [1](modules/network_analyze.py)&nbsp;[2](modules/streaming_enum.py) | Probe supported Vault and Boundary management exposure. |
| [**DNS&nbsp;service&nbsp;posture**](docs/reference-modules/dns-service-posture.md) | [1](modules/network_analyze.py)&nbsp;[2](modules/streaming_enum.py) | Probe zone transfer, recursion, dynamic-update and DoT/DoH-related surfaces. |
| [**NX-OS/ACI/APIC&nbsp;fabric&nbsp;enumeration**](docs/reference-modules/nx-os-aci-apic-fabric-enumeration.md) | [1](modules/ios_enum.py)&nbsp;[2](modules/nxos_enum.py) | NX-API, fabric nodes/endpoints, tenants/contracts, L3Out, VMM, audit/config data and selected management probes. |
| [**VXLAN/DCNM&nbsp;exposure**](docs/reference-modules/vxlan-dcnm-exposure.md) | [1](modules/ios_enum.py)&nbsp;[2](modules/nxos_enum.py) | Inspect supported VTEP and management exposure and retrieve firmware/license/version details. |
| [**HyperFlex/UCS/Intersight**](docs/reference-modules/hyperflex-ucs-intersight.md) | [1](modules/hyperflex_enum.py)&nbsp;[2](modules/nexus_dashboard_enum.py) | Inspect Connect APIs, cluster/storage interfaces, iSCSI-related exposure and selected management endpoints. |
| [**Nexus&nbsp;Dashboard**](docs/reference-modules/nexus-dashboard.md) | [1](modules/hyperflex_enum.py)&nbsp;[2](modules/nexus_dashboard_enum.py) | Enumerate supported dashboard, NDI/NDFC/NDO, telemetry and provisioning surfaces. |

</details>


<details>
<summary><strong>VoIP and real-time communications</strong></summary>

| Capability | Code | |
|:---|:---|:---|
| [**SIP&nbsp;service&nbsp;and&nbsp;extension&nbsp;discovery**](docs/reference-modules/sip-service-and-extension-discovery.md) | [1](modules/sip_enum.py) | Probe OPTIONS/REGISTER behavior, enumerate extensions and examine supported authentication/registration patterns. |
| [**Media&nbsp;and&nbsp;signaling&nbsp;posture**](docs/reference-modules/media-and-signaling-posture.md) | [1](modules/sip_enum.py) | Parse SDP, inspect RTP/SRTP expectations, AMI, WebRTC and selected media/interception indicators. |
| [**Legacy&nbsp;voice&nbsp;protocols**](docs/reference-modules/legacy-voice-protocols.md) | [1](modules/sip_enum.py) | Probe supported H.323, SCCP/Skinny, MGCP and media-gateway surfaces. |
| [**Voice&nbsp;abuse&nbsp;indicators**](docs/reference-modules/voice-abuse-indicators.md) | [1](modules/sip_enum.py) | Heuristics/probes for signaling manipulation, DTMF exposure, covert channels, flooding and denial-of-service susceptibility. |

</details>

<details>
<summary><strong>AI, agent and MCP security</strong></summary>

| Capability | Code | |
|:---|:---|:---|
| [**Inference&nbsp;endpoint&nbsp;enumeration**](docs/reference-modules/inference-endpoint-enumeration.md) | [1](modules/llm_enum.py) | Probe supported Ollama, LM Studio, LocalAI, Hugging Face and OpenAI-compatible services. |
| [**LLM&nbsp;behavior/security&nbsp;probes**](docs/reference-modules/llm-behavior-security-probes.md) | [1](modules/llm_enum.py) | Test supported prompt-disclosure/injection, unsafe-output, excessive-agency and sensitive-information surfaces. |
| [**Model/data&nbsp;pipeline&nbsp;exposure**](docs/reference-modules/model-data-pipeline-exposure.md) | [1](modules/llm_enum.py) | Inspect model metadata, upload/fine-tune endpoints, RAG/vector-store/knowledge-graph and memory-poisoning surfaces. |
| [**Agent&nbsp;protocol&nbsp;exposure**](docs/reference-modules/agent-protocol-exposure.md) | [1](modules/llm_enum.py) | Probe supported MCP/A2A authentication, tool-schema, trust-boundary and orchestration interfaces. |
| [**AI&nbsp;control&nbsp;indicators**](docs/reference-modules/ai-control-indicators.md) | [1](modules/llm_enum.py) | Gather selected OWASP LLM, ATLAS and incident-response/posture indicators through implemented probes. |
| [**MCP&nbsp;manifest&nbsp;grammar&nbsp;fuzzing**](docs/reference-modules/mcp-grammar-fuzzer.md) | [1](modules/mcp_grammar_fuzzer.py) | Atheris harness and seed validation for tool names, descriptions and schemas with prompt-injection indicators. |

</details>

<details>
<summary><strong>Research and payload-development helpers</strong></summary>

| Capability | Code | |
|:---|:---|:---|
| [**Shellcode&nbsp;templates**](docs/reference-modules/shellcode-templates.md) | [1](ablation/core/shellcode_utils.py)&nbsp;[2](modules/bare_adapter.py) | Supplied x86/x86-64/ARM64 shell and staged-loader construction helpers. |
| [**Payload&nbsp;formatting**](docs/reference-modules/payload-formatting.md) | [1](ablation/core/shellcode_utils.py)&nbsp;[2](modules/bare_adapter.py) | Bad-byte checks, XOR/ADD encoding, NOP generation and buffer assembly helpers. |
| [**Crash-offset&nbsp;and&nbsp;ROP&nbsp;helpers**](docs/reference-modules/crash-offset-and-rop-helpers.md) | [1](ablation/core/shellcode_utils.py)&nbsp;[2](modules/bare_adapter.py) | Cyclic patterns/offset lookup, common gadget detection and a minimal x86-64 chain-construction helper. |
| [**Exploitability-context&nbsp;checks**](docs/reference-modules/exploitability-context-checks.md) | [1](ablation/core/shellcode_utils.py)&nbsp;[2](modules/bare_adapter.py) | Helpers inspect canary, NX/ASLR and selected format-string indicators. |
| [**BARE&nbsp;integration**](docs/reference-modules/bare-integration.md) | [1](ablation/core/shellcode_utils.py)&nbsp;[2](modules/bare_adapter.py) | Convert supported findings for the external BARE tool to rank related Metasploit modules. |

</details>

<details>
<summary><strong>Assistant integration and workflow machinery</strong></summary>

| Capability | Code | |
|:---|:---|:---|
| [**LLM&nbsp;analyst&nbsp;loop**](docs/reference-modules/llm-analyst-loop.md) | [1](ablation/analyzers/llm_analyst/agent_loop.py)&nbsp;[2](ablation/analyzers/llm_analyst/rag_retriever.py) | Optional Claude tool-calling analysis loop with bounded iterations and stored results. |
| [**Prior-finding&nbsp;retrieval**](docs/reference-modules/prior-finding-retrieval.md) | [1](ablation/analyzers/llm_analyst/agent_loop.py)&nbsp;[2](ablation/analyzers/llm_analyst/rag_retriever.py) | Supply related function identities/findings as context for subsequent analysis. |
| [**Assisted&nbsp;function&nbsp;naming**](docs/reference-modules/assisted-function-naming.md) | [1](ablation/analyzers/llm_analyst/agent_loop.py)&nbsp;[2](ablation/analyzers/llm_analyst/rag_retriever.py) | Propose and batch-process names from strings, callees and prior evidence. |
| [**Assisted&nbsp;structure&nbsp;reconstruction**](docs/reference-modules/assisted-structure-reconstruction.md) | [1](ablation/analyzers/llm_analyst/agent_loop.py)&nbsp;[2](ablation/analyzers/llm_analyst/rag_retriever.py) | Extract memory-access offsets/widths and propose structure layouts. |
| [**Assisted&nbsp;vulnerability&nbsp;hypotheses**](docs/reference-modules/assisted-vulnerability-hypotheses.md) | [1](ablation/analyzers/llm_analyst/agent_loop.py)&nbsp;[2](ablation/analyzers/llm_analyst/rag_retriever.py) | Generate candidate explanations of suspicious function behavior for later validation. |
| [**Evidence&nbsp;scoring&nbsp;and&nbsp;probe&nbsp;ranking**](docs/reference-modules/evidence-scoring-and-probe-ranking.md) | [1](ablation/analyzers/probe_ranker.py)&nbsp;[2](ablation/analyzers/probe_adapters.py) | Weight evidence families, track contradictions/uncertainty and rank useful next analyses. |
| [**Analyzer&nbsp;probe&nbsp;adapters**](docs/reference-modules/analyzer-probe-adapters.md) | [1](ablation/analyzers/probe_ranker.py)&nbsp;[2](ablation/analyzers/probe_adapters.py) | Dispatch supported disassembly, CFG, xref, lifting, semantic, version, taint and manual evidence probes. |
| [**Stage&nbsp;commitments&nbsp;and&nbsp;audit&nbsp;trail**](docs/reference-modules/stage-commitment.md) | [1](ablation/analyzers/probe_ranker.py)&nbsp;[2](ablation/analyzers/probe_adapters.py) | Hash stage artifacts, record approval states and verify persisted commitments. |
| [**Structured&nbsp;workflow&nbsp;documents**](docs/reference-modules/workflow-document.md) | [1](ablation/analyzers/probe_ranker.py)&nbsp;[2](ablation/analyzers/probe_adapters.py) | Validate stage outputs, advance through configured transitions and serialize/reload sessions. |

</details>

<details>
<summary><strong>Outputs, integration and project tooling</strong></summary>

| Capability | Code | |
|:---|:---|:---|
| [**JSON&nbsp;and&nbsp;SARIF&nbsp;export**](docs/reference-modules/json-and-sarif-export.md) | [1](ablation/export/json_export.py)&nbsp;[2](ablation/export/sarif.py) | Export supported sweep/finding records to structured JSON or SARIF 2.1.0. |
| [**Markdown&nbsp;research&nbsp;reports**](docs/reference-modules/markdown-research-reports.md) | [1](ablation/export/json_export.py)&nbsp;[2](ablation/export/sarif.py) | Render ranked sweep results, prior-finding correlations and verification notes. |
| [**Binary&nbsp;Ninja&nbsp;plugin**](docs/reference-modules/binary-ninja-plugin.md) | [1](ablation/export/json_export.py)&nbsp;[2](ablation/export/sarif.py) | Apply corpus names, launch semantic search/sweeps and show stored findings inside Binary Ninja. |
| [**Terminal&nbsp;presentation**](docs/reference-modules/terminal-presentation.md) | [1](ablation/export/json_export.py)&nbsp;[2](ablation/export/sarif.py) | Colored/plain output, boxes and structured terminal reports. |
| [**Documentation&nbsp;prose&nbsp;checks**](docs/reference-modules/documentation-prose-checks.md) | [1](ablation/export/json_export.py)&nbsp;[2](ablation/export/sarif.py) | Lint documentation against configured writing-style patterns. |
| [**Generic&nbsp;vulnerability-profile&nbsp;sweeps**](docs/reference-modules/generic-vulnerability-profile-sweeps.md) | [1](sweeps/base_sweep.py)&nbsp;[2](sweeps/fortinet_sweep.py) | Encode discovered functions and rank candidates against configured vulnerability profiles plus prior findings. |
| [**Fortinet&nbsp;multi-phase&nbsp;directory&nbsp;sweeps**](docs/reference-modules/fortinet-multi-phase-directory-sweeps.md) | [1](sweeps/base_sweep.py)&nbsp;[2](sweeps/fortinet_sweep.py) | Prefilter ELF files by relevant imports and run the supported semantic, sink and follow-on analysis stages. |
| [**Bundled&nbsp;finding/signature&nbsp;seeds**](docs/reference-modules/bundled-finding-signature-seeds.md) | [1](sweeps/base_sweep.py)&nbsp;[2](sweeps/fortinet_sweep.py) | Ship initial finding and function-signature data to populate or bootstrap local analysis libraries. |
| [**Dependency&nbsp;and&nbsp;supply-chain&nbsp;tooling**](docs/reference-modules/dependency-and-supply-chain-tooling.md) | [1](scripts/audit-deps.sh)&nbsp;[2](scripts/generate-lockfile.sh) | Scripts for dependency auditing, hash-pinned requirements, SBOM generation and monitoring. |
| [**CI&nbsp;and&nbsp;release&nbsp;automation**](docs/reference-modules/ci-and-release-automation.md) | [1](scripts/audit-deps.sh)&nbsp;[2](scripts/generate-lockfile.sh) | Repository workflows for configured checks, coverage and package publishing. |

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
