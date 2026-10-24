# DOC_CODE_MAP.md — Reference Doc / Code Reconciliation

Coverage of all 536 reference docs. Evidence from Phase 1 unit notes (A01–A14, C01, M01–M04, S01) + doc-unit-mapping.json.

**Audit date:** 2026-10-24

---

## Summary

| Category | Count |
|:---------|------:|
| Reference docs total (`docs/reference-modules/*.md`) | 536 |
| Docs listed in `docs/INDEX.md` | 147 |
| Docs **not** in INDEX.md | 389 |
| Docs assigned to code units (A01–A14, Phase 0) | 399 |
| Orphan docs (no unit assignment in Phase 0) | 137 |
| Confirmed mismatches — doc contradicts code | 14 |
| Stale/planned docs — no matching code | ~57 |
| Orphan docs resolved to actual code (modules/ or core/) | ~80 |
| Undocumented capabilities (code with no doc) | 16+ |
| Mismatches rated HIGH RAG risk | 8 |

The doc-unit-mapping.json assigns reference docs to A01-A14 only. Units C01, M01, M02,
M03, M04, and S01 have no reference docs assigned. Most orphan docs that name M01-M04
or S01 capabilities are in the 137-item orphan list.

---

## Orphan doc distribution (137 docs)

Orphan docs sorted by likely destination unit. Docs with no matching code are marked
as PLANNED (mentioned in docs only) or STALE (referenced in INDEX but code not found).

### M01 orphans — host/network/cloud enumeration modules

These docs align with modules in M01 (host enumeration, Cisco NX-OS, Kubernetes, cloud):

| Doc name | Status | Notes |
|----------|--------|-------|
| agent-protocol-exposure | IMPLEMENTED | → AgentAuthorityAudit / AgentObservabilityAudit (M02, misassigned to M01 by name) |
| additional-api-protocols | PLANNED? | No direct code match found |
| additional-industrial-debug-probes | PLANNED? | No direct code match in M01 notes |
| c2-exfiltration-indicators | IMPLEMENTED | → C2ExfiltrationIndicators (M01 notes confirm) |
| ci-cd-and-artifact-services | IMPLEMENTED | → CICDExposureScanner (M01 notes) |
| cluster-management-exposure | IMPLEMENTED | → ClusterManagementExposure (M01) |
| database-storage-exposure | IMPLEMENTED | → DatabaseStorageExposure (M01) |
| dns-service-posture | IMPLEMENTED | → DNSServicePosture (M01) |
| docker-enum | IMPLEMENTED | → DockerEnumerator (M01) |
| forensics-enum | IMPLEMENTED | → ForensicsEnumerator (M01) |
| host-service-discovery | IMPLEMENTED | → HostServiceDiscovery (M01) |
| hyperflex-enum | IMPLEMENTED | → HyperflexEnumerator (M01) |
| hyperflex-ucs-intersight | IMPLEMENTED | → HyperflexUCSIntersight (M01) |
| inference-endpoint-enumeration | IMPLEMENTED | → LLMEnumerator (M02, misassigned) |
| ios-enum | IMPLEMENTED | → IosEnumerator / CiscoIosEnumerator (M01) |
| ios-ios-xe-appliance-enumeration | IMPLEMENTED | → IosXeApplianceEnumerator (M01) |
| k8s-enum | IMPLEMENTED | → K8sEnumerator (M01) |
| kubernetes-identity-and-rbac | IMPLEMENTED | → KubernetesIdentityAndRBAC (M01) |
| kubernetes-policy-posture | IMPLEMENTED | → KubernetesPolicyPosture (M01) |
| lateral-movement | IMPLEMENTED | → LateralMovement (M01) |
| linux-privilege-escalation-triage | IMPLEMENTED | → LinuxPrivescTriage (M01) |
| media-and-signaling-posture | IMPLEMENTED | → MediaSignalingPosture (M01) |
| messaging-streaming-enumeration | IMPLEMENTED | → MessagingStreamingEnumeration (M01) |
| net-sniffer | IMPLEMENTED | → NetworkSniffer (M01) |
| nexus-dashboard | IMPLEMENTED | → NexusDashboardEnumerator (M01) |
| nexus-dashboard-enum | IMPLEMENTED | → (duplicate/variant of nexus-dashboard) |
| nginx-configuration-probes | IMPLEMENTED | → NginxEnumerator config probe methods (M02) |
| nx-os-aci-apic-fabric-enumeration | IMPLEMENTED | → NxOsACIFabricEnumerator (M01) |
| nxos-enum | IMPLEMENTED | → NxOsEnumerator (M01) |
| observability-exposure | IMPLEMENTED | → ObservabilityExposure (M01) |
| orchestration-management-exposure | IMPLEMENTED | → OrchestrationManagementExposure (M01) |
| pcap-inspection | IMPLEMENTED | → PCAPInspection (M01) |
| privesc-enum | IMPLEMENTED | → PrivescEnumerator (M01) |
| process-enum | IMPLEMENTED | → ProcessEnumerator (M01) |
| raw-packet-capture | IMPLEMENTED | → RawPacketCapture (M01) |
| remote-management-and-identity-probes | IMPLEMENTED | → RemoteManagementProbes (M01) |
| sd-wan-meraki-management-probes | IMPLEMENTED | → SDWanMerakiProbes (M01) |
| sip-enum | IMPLEMENTED | → SIPEnumerator (M01) |
| streaming-enum | IMPLEMENTED | → StreamingEnumerator (M01) |
| vxlan-dcnm-exposure | IMPLEMENTED | → VXLANDCNMExposure (M01) |
| web-path-enumeration | IMPLEMENTED | → WebPathEnumeration (M01) |
| ios-enum | IMPLEMENTED | → IosEnumerator (M01) |

### M02 orphans — Crypto/TLS/API/AI/MCP security

| Doc name | Status | Notes |
|----------|--------|-------|
| ai-control-indicators | IMPLEMENTED | → AIControlIndicators (M02) |
| api-authentication-and-token-checks | IMPLEMENTED | → CryptoAudit JWT + api_re.py auth probing (M02) |
| api-authorization-checks | IMPLEMENTED | → api_re.py auth/bola focus modes (M02) |
| api-re | IMPLEMENTED | → api_re.py / run_re() (M02) |
| credential-testing-helpers | IMPLEMENTED | → CryptoAudit + api_re.py creds (M02) |
| model-data-pipeline-exposure | IMPLEMENTED | → LLMEnumerator.probe_data_poisoning_surface (M02) |
| nginx-enum | IMPLEMENTED | → nginx_enum.py NginxEnumerator (M02) |
| nginx-fingerprinting-and-exposure | IMPLEMENTED | → nginx_enum.py _extract_version (M02) |
| proto-fsm | IMPLEMENTED | → proto_fsm.py MMTLS extractor (M02) |
| tls-certificate-and-protocol-probing | IMPLEMENTED | → tls_enum.py check_certificate_transparency (M02) |
| tls-enum | IMPLEMENTED | → tls_enum.py standalone functions (M02) |
| tls-policy-checks | IMPLEMENTED | → tls_enum.py check_weak_cipher_suites (M02) |
| tls-session-downgrade-surfaces | IMPLEMENTED | → tls_enum.py probe_tls_inspection_bypass (M02) |
| unknown-http-api-mapping | IMPLEMENTED | → api_re.py path discovery / OpenAPI harvest (M02) |

### M03 orphans — platform RE + exploit helpers

| Doc name | Status | Notes |
|----------|--------|-------|
| ami-modified-cramfs | IMPLEMENTED | → AmiModifiedCramfs unpacker (M04 or M03) |
| appliance-configuration-secret-helpers | IMPLEMENTED | → ApplianceConfigSecretHelpers (M03) |
| bare-adapter | IMPLEMENTED | → BareAdapter (M03) |
| bare-integration | IMPLEMENTED | → BareIntegration (M03) |
| calibration-parsers | IMPLEMENTED | → CalibrationParsers (M03) |
| calibration-variant-relocation-support | IMPLEMENTED | → CalibrationVariantRelocation (M03) |
| crash-offset-and-rop-helpers | IMPLEMENTED | → CrashOffsetAndROPHelpers (M03) |
| elf-internals-and-hardening | IMPLEMENTED | → ELF internals (M03 or A14) |
| elf-recovery-from-physical-memory-dumps | IMPLEMENTED | → PhysmemELFVFS (M03) |
| hardware-root-discovery | IMPLEMENTED | → HardwareRootDiscovery (M03) |
| hisilicon-risc-v-extensions | IMPLEMENTED | → HiSiliconRISCVExtensions (M03/A05) |
| industrial-iot-probes | IMPLEMENTED | → IndustrialIoTProbes (M03) |
| mach-o-internals | IMPLEMENTED | → MachO parsing (C01 or M03) |
| physmem-elf-vfs | IMPLEMENTED | → PhysmemELFVFS (M03) |
| renesas-sh-2a-decoding | IMPLEMENTED | → RenesSH2ADecoder (M03/A05) |
| risc-v | IMPLEMENTED | → RISC-V ISA decoder/taint (A05) |
| spu-disassembler | IMPLEMENTED | → SPU disassembler (M03 or A13) |
| structural | IMPLEMENTED | → structural analysis (M03) |
| structural-sim | IMPLEMENTED | → StructuralSim (M03) |

### M04 orphans — scanners/detectors/supply chain/misc

| Doc name | Status | Notes |
|----------|--------|-------|
| apple-bv41-decompression | IMPLEMENTED | → AppleBV41Decompressor (M04) |
| attandck-labeling | IMPLEMENTED | → ATTACKLabeling (M04) |
| bwt-eulerian-reconstructor | IMPLEMENTED | → BWTEulerianReconstructor (M04) |
| chunk-walker-validator | IMPLEMENTED | → ChunkWalkerValidator (M04) |
| cve-byte-patterns | IMPLEMENTED | → CVEBytePatterns (M04) |
| cve-byte-signature-checks | IMPLEMENTED | → CVEByteSignatureChecks (M04) |
| debug-metadata-recovery | IMPLEMENTED | → DebugMetadataRecovery (M04) |
| embedding-fine-tuning | IMPLEMENTED | → EmbeddingFineTuning (M04) |
| flywheel | IMPLEMENTED | → PatternLibrary + FindingRegistry flywheel (A12 covered; doc misassigned) |
| hash-aes-implementation-recognition | IMPLEMENTED | → HashAlgoDiscriminator + AES pattern (A10/M04) |
| huawei-modified-squashfs | IMPLEMENTED | → HuaweiModifiedSquashfs (M04 or A09) |
| ibm-w-code-parsing | IMPLEMENTED | → IBMWCodeParser (M04) |
| ioc-candidate-extraction | IMPLEMENTED | → IOCCandidateExtraction (M04) |
| malware-behavior-indicators | IMPLEMENTED | → MalwareBehaviorIndicators (M04) |
| micropython | IMPLEMENTED | → MicroPython runtime analyzer (M04 or A11) |
| office-pdf-triage | IMPLEMENTED | → OfficePDFTriage (M04) |
| rootkit-bootkit-indicators | IMPLEMENTED | → RootkitBootkitIndicators (M04) |
| rsa-ecdsa-and-randomness-checks | IMPLEMENTED | → RSAECDSARandomnessChecks (M04) |
| scanf-family-overflow-candidates | IMPLEMENTED | → ScanfFamilyOverflowCandidates (A07 or M04) |
| signature-based-auto-naming | IMPLEMENTED | → SignatureBasedAutoNaming (M04 or A14) |
| tandem-guardian-pak | IMPLEMENTED | → TandemGuardianPak (M04) |
| yara-generator | IMPLEMENTED | → YaraGenerator (M04) |

### S01 orphans — sweeps

| Doc name | Status | Notes |
|----------|--------|-------|
| win16-le-vxd-sweep | IMPLEMENTED | → win16_le_vxd_sweep.py (S01) |
| win16-mz-dos-sweep | IMPLEMENTED | → win16_mz_dos_sweep.py (S01) |
| fortinet-multi-phase-directory-sweeps | IMPLEMENTED | → fortinet_sweep.py Phase 0 directory mode (S01) |

### Possibly planned or stale (no code match confirmed)

| Doc name | Assessment | Reason |
|----------|------------|--------|
| TEMPLATE | META | Markdown template file, not a capability doc |
| additional-api-protocols | PLANNED? | No specific module found; may be aspirational |
| arm-symbolic | PLANNED? | Symbolic execution for ARM; no code found in notes |
| assisted-structure-reconstruction | PLANNED? | No code match in any unit |
| assisted-vulnerability-hypotheses | PLANNED? | No code match; likely AgentLoop hypothesis feature |
| ci-and-release-automation | META? | Build/CI config documentation, not capability |
| constant-propagation-and-reaching-definitions | PLANNED? | No separate module; may be inside taint trackers |
| control-flow-guard-review | PLANNED? | CFG review for PE; no dedicated module found |
| documentation-prose-checks | META | Internal doc quality check tool |
| export | PLANNED? | JSON/SARIF export; json-and-sarif-export more specific |
| file-versus-socket-input-discrimination | PLANNED? | No dedicated module found |
| frame-pointer-and-memory-range-state | PARTIAL? | Inside existing taint trackers |
| game-re | PLANNED? | Game binary RE; no code found |
| harmonyos | PLANNED? | HarmonyOS analysis; no code in A11 notes |
| interproc-field-writer | PLANNED? | May be inside taint trackers |
| interprocedural-argument-provenance | IMPLEMENTED | → SinkArgClassifier (A07) — likely misnamed doc |
| interprocedural-field-writer-discovery | PLANNED? | No specific module confirmed |
| instrumentation-noise-removal | PLANNED? | No dedicated module found |
| json-and-sarif-export | IMPLEMENTED | → report_generator + JSON export (A14) |
| jvm-spring-exposure-inspection | PLANNED? | Java/Spring; no code in any unit |
| legacy-voice-protocols | IMPLEMENTED | → voice/SIP modules (M01) |
| markdown-research-reports | META | Markdown formatting tools |
| ms-dos-mz | IMPLEMENTED | → win16_mz_dos_sweep.py + A09 MZBinary (S01/A09) |
| payload-formatting | IMPLEMENTED | → PayloadFormatter (M03 or M04) |
| prose | META | Prose generation tools |
| render | META | Rendering tools |
| shellcode-templates | IMPLEMENTED | → ShellcodeTemplates (M03) |
| sse-slicer | IMPLEMENTED | → SSESlicer (A02 or A14) |
| streaming-and-windowed-disassembly | IMPLEMENTED | → StreamingDisassembler (A02/A14) |
| streaming-operational-helpers | IMPLEMENTED | → StreamingHelpers (M01 or A14) |
| terminal-presentation | META | Terminal output formatting |
| timestamp-log-anomaly-checks | IMPLEMENTED | → TimestampLogAnomalyChecks (M01 or M04) |
| tlv-chunk-alignment-checks | IMPLEMENTED | → TLVChunkAlignmentChecks (M04 or A10) |
| voice-abuse-indicators | IMPLEMENTED | → VoiceAbuseIndicators (M01) |
| voip-protocol-and-covert-channels | IMPLEMENTED | → VoIP modules (M01) |
| volatile-and-linux-artifact-triage | IMPLEMENTED | → VolatileAndLinuxArtifactTriage (M01) |

---

## Docs with no reference doc (code with no docs)

From Phase 1 notes, code units with no matching reference doc assigned:

| Unit | Code module | Gap |
|------|-------------|-----|
| S01 | sweeps/base_sweep.py | No reference-module doc; only workflow guide (vuln-hunting.md) |
| S01 | sweeps/report_generator.py | No reference doc; inline docstring only |
| S01 | sweeps/android_sweep.py | doc-unit-mapping has android/android-apk-analysis in A11, not S01 |
| M02 | modules/llm_behavior_security_probes.py | No specific reference doc found |
| M02 | modules/mcp_grammar_fuzzer.py | No reference doc found |
| C01 | ablation/core/* | CLAUDE.md says "core/ is not for direct use"; no reference docs for individual files |

---

## Mismatched Docs (doc contradicts code — RAG hazard)

These docs actively contradict the code. An LLM analyst reading them will invoke tools incorrectly or reach wrong conclusions.

### HIGH severity

| # | Doc | Claim in Doc | Code Reality |
|:--|:----|:-------------|:-------------|
| D-07 | `analysis-engine.md` | "Three modules: analysis_arc.py, analysis_x86.py, analysis_ppc.py" | 9 analysis engines: arc, x86, ppc, arm32, arm64, loongarch64, mips, riscv, v850 |
| D-08 | `forge.md` | Cache key uses SHA-256 | Code uses `hashlib.blake2b(digest_size=8)` |
| D-09 | `dynamic-sandbox.md` | DynamicSandbox evidence strength = "1.0" | `DynamicProbeAdapter` assigns 0.40–0.75 by behavior type |
| D-10 | `mcp-grammar-fuzzer.md` | `MCPGrammarFuzzer.from_path().fuzz()` returning `MCPTaintFinding` | Atheris grammar fuzzer; no `.from_path()`, no `MCPTaintFinding`; entry: `run(argv)` |
| D-11 | `browser-extension-auditor.md` | "How it works" describes APK/DEX/BEAM/Go ELF parsing | Analyzes browser extension ZIP/JSON only |
| D-12 | `electron-security-scanner.md` | Same APK/DEX/Go ELF boilerplate as D-11 | Audits Electron apps (asar/node_modules/preload/CSP) |
| D-19 | `isa-8051.md` | "Status: planned module, not yet implemented" | `modules/isa_8051.py` is **fully implemented**: Mcs51Decoder, IntelHexLoader, Cc254xBankResolver all working |
| D-20 | `binary-format-and-platform-identification.md` | Detects the binary target's OS and architecture | `platform_detect.py` detects the **analysis machine's** host OS/arch — not the binary |

### MEDIUM severity

| # | Doc | Claim | Reality |
|:--|:----|:------|:--------|
| D-13 | `dex-disassembly-and-lifting.md` | `disasm_method()` returns `List[DEXInstruction]` | Returns `str` |
| D-14 | `tls-certificate-and-protocol-probing.md` | Static binary analyzer | `tls_analyzer.py` is a live network probe requiring outbound TCP/TLS |
| D-15 | `fortinet_sweep.py` docstring | 7 FortiOS CVE profiles | 8 profiles in `FORTIOS_PROFILES` |
| D-16 | Implied by `base_sweep.py` semantics | Same embedding space as `SemanticSearcher` | base_sweep uses `all-MiniLM-L6-v2`; SemanticSearcher uses `BAAI/bge-small-en-v1.5` + WhiteningTransform |
| D-17 | `cve_byte_patterns.py` | 3 CVEs with byte patterns | CVE-2012-5134 and CVE-2012-2807 are stubs (0 sequences) |
| D-18 | `analyze_all_jni.py`, `deep_jni_analysis.py` docs | General JNI analysis | Hard-coded to `libhijoyptt.so` paths |
| D-21 | `proto-fsm.md` | Generic protocol FSM extraction for any ARM64 binary | Hardcodes WeChat 8.0.56 seed VAs (0x111f98, 0x305020 etc.); must use `--seed` for any other target |
| D-22 | Any doc claiming pe_analyzer import analysis | PE import security analysis | `pe_analyzer._analyze_imports()` is a stub (`pass`); superseded by `pe_parser.py` |
| D-23 | `CLAUDE.md` | "Version: 2.57.0" | `ablation/__init__.py` is 2.86.0 |
| D-24 | SBOMExtractor reference | CycloneDX/SPDX-compliant output | Output is a custom format; not standards-compliant |
| D-25 | `workflows/vuln-hunting.md` Phase 5 | `TaintTracker.trace(func_va, source_va, source_reg, sink_patterns)` | Current API: `tracker.run()` / `tracker.run_interprocedural()` |
| D-26 | `disasm_engine.py` (any caller) | `find_functions()` / `analyze_cfg()` work | Both call `disasm_iter()` removed in Capstone 5.x; `AttributeError` at runtime |

---

## INDEX.md Gaps

INDEX.md is the primary navigation document for the LLM analyst. Verified counts (2026-10-24):

| Metric | Count |
|:-------|------:|
| Docs in `docs/reference-modules/` | 536 |
| Docs listed in `docs/INDEX.md` | 147 |
| **Docs NOT listed in INDEX.md** | **389** |
| Docs in INDEX.md missing from reference-modules/ | 0 |

INDEX.md covers only **27% of the reference doc library**. All 147 INDEX entries have valid corresponding files. The 389 unlisted docs include all M01–M04 module docs, most A01–A14 sub-docs added after the initial INDEX, and the 8051-isa-modeling.md accurate secondary doc. Every doc in INDEX.md resolves to an actual file — there are no broken links.

**Recommendation:** INDEX.md is no longer a reliable discovery tool at 27% coverage. It should be regenerated from the full `docs/reference-modules/` listing or replaced with the alphabetical listing in doc-unit-mapping.json.

---

## modules/ vs ablation/analyzers/ Relationship

| Directory | Python files | Approx. lines |
|:----------|------------:|---------------:|
| `ablation/analyzers/` | 253 | ~180,000 |
| `modules/` (project root) | ~101 | ~130,000 |

**Four distinct categories in modules/:**

**Category A — Live network enumeration (M01, ~58,992 lines):** docker_enum, k8s_enum, ios_enum, hyperflex_enum, nxos_enum, nexus_dashboard_enum, net_sniffer, sip_enum, streaming_enum, lateral_movement, privesc_enum, process_enum, syscall_trace, windows_enum, physmem_elf_vfs. These make real TCP/UDP/TLS connections. No equivalent in analyzers/ (which is 100% static analysis). Cannot be used in an offline RE session.

**Category B — AI/crypto/API/TLS security tools (M02, ~18,842 lines):** Five modules (AgentAuthorityAudit, AgentObservabilityAudit, AgentToolSurfaceEnumerator, AIControlIndicators, PromptInjectionSinkClassifier) use `from_context(ctx).scan()` and integrate into the BinaryContext workflow. The rest (LLMEnumerator, CryptoAudit, api_re, NginxEnumerator, tls_enum) are live-network tools like Category A.

**Category C — Binary RE extensions (M03):** arm_symbolic.py (ARM64 symbolic slicing), spu_disassembler.py (PS3 SPU — no Capstone arch), sse_slicer.py, arm_disasm.py, interproc_field_writer.py, cpp_vtable_reconstructor.py (broader arch than analyzers/vtable_resolver.py), mpy_lifter.py (MicroPython — no analyzers/ counterpart), isa_8051.py (MCS-51 — no Capstone arch). These add new static analysis capabilities; they are not duplicates of analyzers/ content.

**Category D — Specialized scanners (M04):** cve_byte_patterns.py (2 of 3 patterns are stubs), yara_generator.py, structural_sim.py (5-signal composite similarity — different algorithm from analyzers/dtw_matcher.py), version_delta_finetune.py (requires optional extras).

**Key rules:**
- No import from `modules/` exists in any `analyzers/` file — dependency is one-way.
- `modules/cpp_vtable_reconstructor.py` supplements (not duplicates) `analyzers/vtable_resolver.py` with broader arch support.
- `modules/structural_sim.py` uses a different algorithm than `analyzers/dtw_matcher.py`; they are complementary.
- Live-network modules cannot run in offline/sandboxed RE sessions.

---

## Top 10 Docs Most Likely to Mislead the LLM Analyst

Ranked by: likelihood of silent wrong behavior × frequency of access in a typical RE workflow.

| Rank | Doc | Why it misleads | Silent failure mode |
|:-----|:----|:----------------|:--------------------|
| 1 | **`analysis-engine.md`** (D-07) | States 3 analysis engines; 9 exist. Analyst selects ARM64, MIPS, or RISC-V and is told no engine available. | Tool never called; vulnerability undetected on 6 architectures |
| 2 | **`binary-format-and-platform-identification.md`** (D-20) | `platform_detect.py` returns host machine OS/arch. Analyst calls it to classify firmware. Gets "Linux/x86_64" always. | Analyst proceeds with wrong architecture assumption for the target binary |
| 3 | **`isa-8051.md`** (D-19) | Says module "not yet implemented." MCS-51/CC254x BLE analysis is fully working. | Analyst manually re-implements logic that already exists, or skips 8051 analysis |
| 4 | **`forge.md`** (D-08) | SHA-256 cache key claim. Code uses BLAKE2b. Any script replicating FORGE cache lookups produces wrong keys. | FORGE gate bypassed; unaudited modules committed to repo |
| 5 | **`mcp-grammar-fuzzer.md`** (D-10) | Documents `MCPGrammarFuzzer.from_path().fuzz()` — class and method do not exist. | Fuzzer never runs on MCP targets; prompt injection surface untested |
| 6 | **`dynamic-sandbox.md`** (D-09) | Evidence strength "1.0" for DynamicSandbox. Code assigns 0.40–0.75. HypothesisEngine confidence silently inflated. | Findings promoted to CONFIRMED when evidence is only MEDIUM-strength |
| 7 | **`tls-certificate-and-protocol-probing.md`** (D-14) | Categorized alongside static binary analyzers. `tls_analyzer.py` requires outbound TCP to a live target. | Called during offline firmware analysis; hangs or fails silently |
| 8 | **`proto-fsm.md`** (D-21) | Claims generic FSM extraction for "any stripped ARM64 binary." Seeds hardcoded for WeChat 8.0.56. | Analyst runs on a different target; gets empty FSM with no diagnostic |
| 9 | **`browser-extension-auditor.md`** / **`electron-security-scanner.md`** (D-11, D-12) | Both describe APK/DEX/BEAM/Go ELF parsing. Neither tool handles these formats. | Wrong binary type dispatched; empty results with no error message |
| 10 | **`workflows/vuln-hunting.md`** Phase 5 (D-25) | Shows `TaintTracker.trace(...)`. This method was renamed to `run()` / `run_interprocedural()`. | Analyst copies example verbatim; gets `AttributeError`; blames TaintTracker not the doc |

**Honorable mention:** `streaming-enum.md` does not disclose that `flink_submit_jar_rce()` is an active exploit (submits an attacker JAR to Flink for code execution). Treating this as an enumeration-only tool may cause accidental payload execution during an assessment.
