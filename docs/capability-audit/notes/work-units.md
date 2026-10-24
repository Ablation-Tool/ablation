# Work Units for Capability Audit Phase 1

Total work units: 20

## A01: Core Infrastructure
**Files (11):**
  - beam_context
  - binary_context
  - binary_lifter
  - cfg_builder
  - dataflow_engine
  - encoding_dag
  - entropy_mapper
  - expr_lifter
  - structurizer
  - window_analyzer
  - xref_graph
**Reference docs (33):**
  - docs/reference-modules/analysis-engine.md
  - docs/reference-modules/beam.md
  - docs/reference-modules/binary-context.md
  - docs/reference-modules/binary-context-additions.md
  - docs/reference-modules/binary-format-and-platform-identification.md
  - docs/reference-modules/binary-lifter.md
  - docs/reference-modules/binary-lifter-sh2a.md
  - docs/reference-modules/binary-lifting.md
  - docs/reference-modules/binary-ninja-plugin.md
  - docs/reference-modules/build-integrity-analyzer.md
  - ... (23 more, see doc-unit-mapping.json)

## A02: CFG per-arch + Analysis engines
**Files (19):**
  - analysis_arc
  - analysis_arm32
  - analysis_arm64
  - analysis_loongarch64
  - analysis_mips
  - analysis_ppc
  - analysis_riscv
  - analysis_v850
  - analysis_x86
  - cfg_arc
  - cfg_arm32
  - cfg_arm64
  - cfg_loongarch64
  - cfg_mips
  - cfg_ppc
  - cfg_riscv
  - cfg_sh2a
  - cfg_v850
  - cfg_x86
**Reference docs (29):**
  - docs/reference-modules/affine-mapping-analysis.md
  - docs/reference-modules/aix-xcoff32-64-analysis.md
  - docs/reference-modules/android-apk-analysis.md
  - docs/reference-modules/anti-analysis-string-detector.md
  - docs/reference-modules/arm32-allocation-arithmetic-overflow.md
  - docs/reference-modules/arm64-symbolic-slicing.md
  - docs/reference-modules/arm64-virtual-call-resolution.md
  - docs/reference-modules/cfg-sh2a.md
  - docs/reference-modules/cross-library-analysis.md
  - docs/reference-modules/cryptographic-analysis.md
  - ... (19 more, see doc-unit-mapping.json)

## A03: ISA models + Instruction models
**Files (20):**
  - insn_arc
  - insn_arm32
  - insn_arm64
  - insn_loongarch64
  - insn_m88k
  - insn_mips
  - insn_ppc
  - insn_riscv
  - insn_v850
  - insn_x86
  - isa_arc
  - isa_arm32
  - isa_arm64
  - isa_loongarch64
  - isa_m88k
  - isa_mips
  - isa_ppc
  - isa_riscv
  - isa_v850
  - isa_x86
**Reference docs (5):**
  - docs/reference-modules/8051-isa-modeling.md
  - docs/reference-modules/insn-models.md
  - docs/reference-modules/isa-8051.md
  - docs/reference-modules/isa-models.md
  - docs/reference-modules/m88k-decoder.md

## A04: Taint trackers: x86/ARM/i386/Windows
**Files (11):**
  - bss_taint_tracker
  - taint_tracker
  - taint_tracker_arm32
  - taint_tracker_arm32_labeled
  - taint_tracker_arm64
  - taint_tracker_i386
  - taint_tracker_x86
  - taint_tracker_x86_32
  - taint_tracker_x86_labeled
  - tainted_string_tracker
  - windows_pool_taint_tracker
**Reference docs (18):**
  - docs/reference-modules/arm64-global-tracker.md
  - docs/reference-modules/call-and-string-cross-references.md
  - docs/reference-modules/configurable-taint-reporting.md
  - docs/reference-modules/global-symbol-and-bss-tracking.md
  - docs/reference-modules/kernel-pool-flow-checks.md
  - docs/reference-modules/named-taint-sources-and-bounds.md
  - docs/reference-modules/obfuscated-string-decoder.md
  - docs/reference-modules/sac-i386.md
  - docs/reference-modules/tainted-string-tracker.md
  - docs/reference-modules/windows-16-bit-ne.md
  - ... (8 more, see doc-unit-mapping.json)

## A05: Taint trackers: MIPS/PPC/RISC-V/ARC
**Files (12):**
  - taint_tracker_arc
  - taint_tracker_arc_labeled
  - taint_tracker_mips
  - taint_tracker_mips64
  - taint_tracker_mips_labeled
  - taint_tracker_nanomips
  - taint_tracker_ppc32
  - taint_tracker_ppc64
  - taint_tracker_ppc_labeled
  - taint_tracker_riscv
  - taint_tracker_riscv32
  - taint_tracker_riscv64
**Reference docs (9):**
  - docs/reference-modules/nanomips.md
  - docs/reference-modules/ppc32-func-discovery.md
  - docs/reference-modules/ppc32-got2-resolver.md
  - docs/reference-modules/ppc32-heap-slot-overflow.md
  - docs/reference-modules/ppc32-ppc476-dedicated-lifting.md
  - docs/reference-modules/ppc32-taint-tracker.md
  - docs/reference-modules/ppc64-taint-analysis.md
  - docs/reference-modules/sac-ppc32-be.md
  - docs/reference-modules/verified-ppc32-import-callers.md

## A06: Taint trackers: automotive + cross-binary + source audit
**Files (15):**
  - cross_binary_taint
  - lib_graph
  - priv_drop_before_exec
  - pthread_once_detector
  - source_arch_risk
  - source_audit_compressor
  - source_entry_classifier
  - source_ingestion
  - source_isolation_checker
  - source_sink_scanner
  - source_taint_tracker
  - taint_tracker_loongarch64
  - taint_tracker_rh850
  - taint_tracker_tricore
  - taint_tracker_v850
**Reference docs (34):**
  - docs/reference-modules/agent-authority-audit.md
  - docs/reference-modules/agent-observability-audit.md
  - docs/reference-modules/architectural-risk-detection.md
  - docs/reference-modules/container-isolation-escape-surface.md
  - docs/reference-modules/cross-target-learning.md
  - docs/reference-modules/crypto-audit.md
  - docs/reference-modules/dependency-confusion-scanner.md
  - docs/reference-modules/elf-anomaly-scanner.md
  - docs/reference-modules/firmware-pki-checker.md
  - docs/reference-modules/hardcoded-credential-scanner.md
  - ... (24 more, see doc-unit-mapping.json)

## A07: Sink classifiers + network analysis
**Files (17):**
  - argv_build_to_sink
  - network_sink_finder
  - pe_sink_classifier
  - sanitizer_detector
  - sink_arg_classifier
  - sink_arg_classifier_arm32
  - sink_arg_classifier_i386
  - sink_arg_classifier_mips
  - sink_arg_classifier_ppc32
  - sink_arg_classifier_ppc64
  - sink_arg_classifier_ppc64_elfv1
  - sink_arg_classifier_ppc64_elfv2
  - sink_arg_classifier_s390
  - sink_arg_classifier_x86_32
  - sink_propagator
  - sink_sanitizer_filter
  - static_link_sink_scanner
**Reference docs (29):**
  - docs/reference-modules/build-provenance-extractor.md
  - docs/reference-modules/cmdb-to-sink-mapping.md
  - docs/reference-modules/fortinet-build-track-classification.md
  - docs/reference-modules/hardware-root-finder.md
  - docs/reference-modules/internal-network-reconnaissance.md
  - docs/reference-modules/local-network-inventory.md
  - docs/reference-modules/network-analyze.md
  - docs/reference-modules/network-sink-finder.md
  - docs/reference-modules/pe-internals-and-indicators.md
  - docs/reference-modules/pe-parser.md
  - ... (19 more, see doc-unit-mapping.json)

## A08: Vulnerability scanners
**Files (25):**
  - apache_module_analyzer
  - byovd_detector
  - cmdb_surface_mapper
  - command_table_scanner
  - compiler_security_gate
  - deprecated_func_scanner
  - flatui_method_decoder
  - fork_exec_classifier
  - format_string_scanner
  - go_subprocess_scanner
  - heap_vuln_scanner
  - intoverflow_scanner_arm32
  - kernel_driver_analyzer
  - kernel_module_subsystem_classifier
  - la64_heap_vuln_scanner
  - length_underflow
  - loongarch64_max_not_min_scanner
  - lua_injection_analyzer
  - mcp_tool_taint_scanner
  - perl_taint_scanner
  - preauth_route_auditor
  - setuid_before_fork
  - setuid_obfuscated_exec
  - sql_sink_scanner
  - sscanf_sink_classifier
**Reference docs (43):**
  - docs/reference-modules/agent-tool-surface-enumerator.md
  - docs/reference-modules/android-binder-surface.md
  - docs/reference-modules/apache-module-analysis.md
  - docs/reference-modules/apache-module-analyzer.md
  - docs/reference-modules/api-injection-and-validation-checks.md
  - docs/reference-modules/byovd-capability-detection.md
  - docs/reference-modules/calibration-table-interpretation.md
  - docs/reference-modules/cmdb-surface-mapper.md
  - docs/reference-modules/command-table-scanner.md
  - docs/reference-modules/compiler-defects.md
  - ... (33 more, see doc-unit-mapping.json)

## A09: Firmware extractors + Windows PE + AIX
**Files (19):**
  - aix_bff_extractor
  - aix_big_ar_extractor
  - aix_type0f_stream_splitter
  - appledouble_extractor
  - ar_archive_scanner
  - cfg_bypass_detector
  - com_attack_surface_mapper
  - etw_provider_extractor
  - firmware_container
  - firmware_container_key_extractor
  - fortibuild_track_classifier
  - fortigate_cert_key_scanner
  - fortimail_vmdk_extractor
  - fortios_firmware_extractor
  - ne_format_parser
  - nested_archive_scanner
  - pdb_symbol_integrator
  - rpc_server_analyzer
  - seh_chain_analyzer
**Reference docs (56):**
  - docs/reference-modules/aix-bff-extractor.md
  - docs/reference-modules/aix-big-ar-extractor.md
  - docs/reference-modules/aix-big-archive-extraction.md
  - docs/reference-modules/aix-installp-decompressor.md
  - docs/reference-modules/aix-installp-step4-multilevel.md
  - docs/reference-modules/aix-plain-bff-extraction.md
  - docs/reference-modules/aix-type0f-stream-splitter.md
  - docs/reference-modules/ami-cramfs-extractor.md
  - docs/reference-modules/appledouble-extractor.md
  - docs/reference-modules/appledouble-resource-forks.md
  - ... (46 more, see doc-unit-mapping.json)

## A10: ECU/Automotive decoders + calibration
**Files (23):**
  - arc_decoder
  - ecu_a2l_parser
  - ecu_arch_detector
  - ecu_c166_decoder
  - ecu_c28x_decoder
  - ecu_cal_def
  - ecu_conescan_parser
  - ecu_m68k_decoder
  - ecu_open_damos_parser
  - ecu_rom_layout_analyzer
  - ecu_romraider_parser
  - ecu_security_access_scanner
  - ecu_sh2a_decoder
  - ecu_vle_decoder
  - ecu_xdf_parser
  - epilogue_share_scanner
  - flat_binary_func_start_scanner
  - hisi_rv32_ext
  - loongarch_decoder
  - nanomips_decoder
  - ti_coff_loader
  - ti_nnc_scanner
  - v850_decoder
**Reference docs (33):**
  - docs/reference-modules/c166-c167-decoding.md
  - docs/reference-modules/dead-security-check-scanner.md
  - docs/reference-modules/ecu-a2l-parser.md
  - docs/reference-modules/ecu-arch-detector.md
  - docs/reference-modules/ecu-architecture-detector.md
  - docs/reference-modules/ecu-c28x-decoder.md
  - docs/reference-modules/ecu-cal-parsers.md
  - docs/reference-modules/ecu-conescan-parser.md
  - docs/reference-modules/ecu-m68k-decoder.md
  - docs/reference-modules/ecu-nissan-parser.md
  - ... (23 more, see doc-unit-mapping.json)

## A11: Mobile + Language runtimes
**Files (16):**
  - abc_decompiler
  - abc_disasm
  - abc_parser
  - binder_scanner
  - browser_extension_auditor
  - dex_analyzer
  - dex_disasm
  - dex_lifter
  - electron_security_scanner
  - go_pclntab
  - go_string_resolver
  - go_x86_strip_scanner
  - java_jar_scanner
  - jni_bridge_scanner
  - library_inventory
  - pyc_bytecode_scanner
**Reference docs (26):**
  - docs/reference-modules/analyze-all-jni.md
  - docs/reference-modules/arm-disasm.md
  - docs/reference-modules/browser-extension-auditing.md
  - docs/reference-modules/browser-extension-auditor.md
  - docs/reference-modules/dex.md
  - docs/reference-modules/dex-disassembly-and-lifting.md
  - docs/reference-modules/disasm-helper.md
  - docs/reference-modules/docker-inventory-and-posture.md
  - docs/reference-modules/electron-application-auditing.md
  - docs/reference-modules/electron-security-scanner.md
  - ... (16 more, see doc-unit-mapping.json)

## A12: AI/LLM + semantic + flywheel + hypothesis
**Files (17):**
  - corpus_builder
  - dtw_matcher
  - evidence_scorer
  - finding_registry
  - func_id_db
  - hypothesis_engine
  - hypothesis_models
  - llm_analyst
  - matrix_profile_diff
  - name_registry
  - pattern_library
  - probe_adapters
  - probe_ranker
  - sax_index
  - semantic_search
  - sig_library
  - subsequence_searcher
**Reference docs (31):**
  - docs/reference-modules/analyst-naming-registry.md
  - docs/reference-modules/analyzer-probe-adapters.md
  - docs/reference-modules/behavioral-subsequence-search.md
  - docs/reference-modules/bundled-finding-signature-seeds.md
  - docs/reference-modules/calling-convention-and-syscall-models.md
  - docs/reference-modules/data-structure-pattern-classification.md
  - docs/reference-modules/dtw-function-homolog-matching.md
  - docs/reference-modules/evidence-scoring-and-probe-ranking.md
  - docs/reference-modules/finding-corpus-mining.md
  - docs/reference-modules/finding-registry.md
  - ... (21 more, see doc-unit-mapping.json)

## A13: PPC legacy + vtable + PS3 + XCOFF
**Files (20):**
  - pef_abi_clobber_scanner
  - pef_binary_analyzer
  - ppc32_lifter
  - ppc32_plt_tracer
  - ppc476_decompiler
  - ppc476_lifter
  - ppc64_be_call_scanner
  - ppc64_be_sink_classifier
  - ppc64_dynds_classifier
  - ppc64_elfv1_resolver
  - ppc64_power10_plt_stubs
  - ppc64_vmx_density
  - ps3_opd_vtable_scanner
  - ps3_self_decryptor
  - rel_dyn_pc32_scanner
  - vtable_dispatch_scanner
  - vtable_resolver
  - wcode_parser
  - xcoff32_decompiler
  - xcoff_symtab_parser
**Reference docs (28):**
  - docs/reference-modules/call-argument-annotation.md
  - docs/reference-modules/call-site-backward-slicing.md
  - docs/reference-modules/callsite-tracer.md
  - docs/reference-modules/classic-mac-abi-clobber-scanning.md
  - docs/reference-modules/cpp-vtable-reconstructor.md
  - docs/reference-modules/elf-vtable-reconstructor.md
  - docs/reference-modules/installer-binary-analyzer.md
  - docs/reference-modules/live-virtual-dispatch-slots.md
  - docs/reference-modules/pef-abi-clobber-scanner.md
  - docs/reference-modules/pef-binary-analyzer.md
  - ... (18 more, see doc-unit-mapping.json)

## A14: Function discovery + reporting + FORGE + misc
**Files (25):**
  - arm32_function_scanner
  - arm32_reg_annotator
  - arm64_fgets_fd_discriminator
  - caller_arg_resolver
  - crypto_pattern_detector
  - dwarf_loongarch64
  - dynamic_sandbox
  - engine_pattern_library
  - forge
  - func_profiler
  - func_reachability
  - i386_absolute_xref_scanner
  - i386_call_chain_resolver
  - ipreg_annotator
  - lsb_stego_extractor
  - opseq
  - reg_annotator
  - scan_result_version_cache
  - stage_commitment
  - static_elf32_func_start_scanner
  - syscall_loongarch64
  - vendor_profile
  - version_delta
  - workflow_document
  - xor_solver
**Reference docs (25):**
  - docs/reference-modules/assisted-function-naming.md
  - docs/reference-modules/business-logic-and-version-exposure.md
  - docs/reference-modules/caller-arg-resolver.md
  - docs/reference-modules/crypto.md
  - docs/reference-modules/dynamic-sandbox.md
  - docs/reference-modules/engine-pattern-library.md
  - docs/reference-modules/forge.md
  - docs/reference-modules/func-reachability.md
  - docs/reference-modules/function-identity-database.md
  - docs/reference-modules/function-profiler.md
  - ... (15 more, see doc-unit-mapping.json)

## C01: ablation/core/ parsers + platform detection
**Files (24):**
  - ablation/core/aix_installp_decompressor.py
  - ablation/core/aix_installp_step4_multilevel.py
  - ablation/core/apk_parser.py
  - ablation/core/attck_tagger.py
  - ablation/core/bff_extractor.py
  - ablation/core/binary_parser.py
  - ablation/core/bv41_decoder.py
  - ablation/core/bwt_eulerian_reconstructor.py
  - ablation/core/coff_m88k_parser.py
  - ablation/core/disasm_engine.py
  - ablation/core/elf_parser.py
  - ablation/core/firmware_analyzer.py
  - ablation/core/guardian_pak_extractor.py
  - ablation/core/macho_analyzer.py
  - ablation/core/pe_analyzer.py
  - ablation/core/pe_parser.py
  - ablation/core/platform_detect.py
  - ablation/core/prose.py
  - ablation/core/render.py
  - ablation/core/shellcode_utils.py
  - ablation/core/swift_demangle.py
  - ablation/core/tls_analyzer.py
  - ablation/core/xcoff_parser.py
  - ablation/core/yara_generator.py

## M01: modules/: Host/network/cloud/Cisco enumeration
**Files (17):**
  - modules/docker_enum.py
  - modules/forensics_enum.py
  - modules/hyperflex_enum.py
  - modules/ios_enum.py
  - modules/k8s_enum.py
  - modules/lateral_movement.py
  - modules/net_sniffer.py
  - modules/network_analyze.py
  - modules/nexus_dashboard_enum.py
  - modules/nxos_enum.py
  - modules/physmem_elf_vfs.py
  - modules/privesc_enum.py
  - modules/process_enum.py
  - modules/sip_enum.py
  - modules/streaming_enum.py
  - modules/syscall_trace.py
  - modules/windows_enum.py

## M02: modules/: Crypto/TLS/API/AI/MCP security
**Files (13):**
  - modules/agent_authority_audit.py
  - modules/agent_observability_audit.py
  - modules/agent_tool_surface_enumerator.py
  - modules/ai_control_indicators.py
  - modules/api_re.py
  - modules/crypto_audit.py
  - modules/llm_behavior_security_probes.py
  - modules/llm_enum.py
  - modules/mcp_grammar_fuzzer.py
  - modules/nginx_enum.py
  - modules/prompt_injection_sink_classifier.py
  - modules/proto_fsm.py
  - modules/tls_enum.py

## M03: modules/: Platform RE + exploit helpers
**Files (29):**
  - modules/ami_cramfs_extractor.py
  - modules/arm64_global_tracker.py
  - modules/arm_disasm.py
  - modules/arm_symbolic.py
  - modules/bare_adapter.py
  - modules/bff_decompressor.py
  - modules/callsite_tracer.py
  - modules/cpp_vtable_reconstructor.py
  - modules/elf_vtable_reconstructor.py
  - modules/go_binary_re.py
  - modules/go_dangerous_callers.py
  - modules/go_garble_re.py
  - modules/huawei_squashfs_extractor.py
  - modules/installer_binary_analyzer.py
  - modules/interproc_field_writer.py
  - modules/ioctl_attack_surface.py
  - modules/isa_8051.py
  - modules/java_decompiler.py
  - modules/java_re.py
  - modules/mpy_lifter.py
  - modules/path_solver.py
  - modules/ppc32_func_discovery.py
  - modules/ppc32_got2_resolver.py
  - modules/ppc32_heap_slot_scanner.py
  - modules/spu_disassembler.py
  - modules/sse_slicer.py
  - modules/video_container.py
  - modules/xcoff_executable_analyzer.py
  - modules/xcoff_loader_symbols.py

## M04: modules/: Scanners/detectors/supply chain/misc
**Files (41):**
  - modules/analyze_all_jni.py
  - modules/anti_analysis_string_detector.py
  - modules/attack_labeler.py
  - modules/build_integrity_analyzer.py
  - modules/build_provenance_extractor.py
  - modules/can_dbc_parser.py
  - modules/chunk_walker_validator.py
  - modules/cve_byte_patterns.py
  - modules/dead_security_check_scanner.py
  - modules/deep_jni_analysis.py
  - modules/dependency_confusion_scanner.py
  - modules/deprecated_crypto_scanner.py
  - modules/ecu_nissan_parser.py
  - modules/elf_anomaly_scanner.py
  - modules/entropy_analyzer.py
  - modules/firmware_auth_bypass_detector.py
  - modules/firmware_pki_checker.py
  - modules/hardcoded_credential_scanner.py
  - modules/hardware_root_finder.py
  - modules/heap_uaf_scanner.py
  - modules/lethal_trifecta_scanner.py
  - modules/libfunc_db.py
  - modules/metachar_filter_bypass_scanner.py
  - modules/mips_analyzer.py
  - modules/non_constant_time_comparator_scanner.py
  - modules/obfuscated_string_decoder.py
  - modules/policy_engine_absence_detector.py
  - modules/process_injection_combo_scanner.py
  - modules/sbom_extractor.py
  - modules/setuid_auth_oracle_scanner.py
  - modules/signal_handler_race_scanner.py
  - modules/signed_length_arg_scanner.py
  - modules/sizeof_ptr_detector.py
  - modules/structural_sim.py
  - modules/third_party_library_identifier.py
  - modules/toctou_scanner.py
  - modules/truncation_at_sink_scanner.py
  - modules/uninitialized_var_path_scanner.py
  - modules/version_delta_finetune.py
  - modules/vxworks_archive_scanner.py
  - modules/weak_prng_at_security_sink_scanner.py

## S01: sweeps/: All sweep drivers
**Files (10):**
  - sweeps/android_sweep.py
  - sweeps/base_sweep.py
  - sweeps/corpus_miner.py
  - sweeps/fortinet_sweep.py
  - sweeps/pe_sweep.py
  - sweeps/report_generator.py
  - sweeps/ti_sweep.py
  - sweeps/win16_le_vxd_sweep.py
  - sweeps/win16_mz_dos_sweep.py
  - sweeps/win16_ne_sweep.py

**Total files assigned: 384**
**Orphan reference docs (unassigned): 137 — see doc-unit-mapping.json**