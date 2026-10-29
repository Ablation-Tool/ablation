# Capability Documentation Audit

This audit covers every unique local Markdown target linked from the README's Capabilities section. It evaluates explanation quality as well as links and syntax. The governing contract is [Capability Documentation Standard](../documentation-standard.md).

## Baseline

The README contains 121 capability-document link instances resolving to 115 unique documents. No primary target is missing. The initial mechanical pass identified 44 pages without a clear user-value or architectural-role section, 36 without a clear purpose section, 13 without an identifiable mechanism section, and 106 prose findings across 25 pages. It also produced two candidate local-link findings: one confirmed broken cross-reference and one false positive caused by bracketed text inside inline code.

These measurements locate candidates for review; they do not prove quality or deficiency on their own. Final assessments require reading the page, preserving accurate detail, and checking consequential examples and claims.

## Evidence labels

- **Executed:** a deterministic example or an equivalent focused API check ran successfully.
- **Source-checked:** the example and consequential claims were compared with implementation or tests, but live, privileged, external, or target-specific behavior was not executed.
- **Existing tests:** relevant project tests cover the documented behavior.
- **Illustrative:** output demonstrates shape or interpretation rather than an observed run.

A document can use more than one label. No label asserts live-target validation without a live-target run.

## Review ledger

The final ledger records all 115 documents in README order, their revisions, and example-evidence status. Pages marked reviewed meet the documentation contract or have an explicit, documented reason why a criterion does not apply.

| # | Document | Review outcome | Example evidence |
|---:|:---|:---|:---|
| 1 | [x86.md](../reference-modules/x86.md) | Revised and reviewed | Target example retained; full-suite baseline |
| 2 | [binary-lifter.md](../reference-modules/binary-lifter.md) | Revised and reviewed | Target example retained; full-suite baseline |
| 3 | [mips.md](../reference-modules/mips.md) | Revised and reviewed | Target example retained; full-suite baseline |
| 4 | [nanomips.md](../reference-modules/nanomips.md) | Revised and reviewed | Target example retained; full-suite baseline |
| 5 | [ppc32-taint-tracker.md](../reference-modules/ppc32-taint-tracker.md) | Revised and reviewed | Target example retained; full-suite baseline |
| 6 | [ecu-vle-decoder.md](../reference-modules/ecu-vle-decoder.md) | Revised and reviewed | Target example retained; full-suite baseline |
| 7 | [ppc476-lifter.md](../reference-modules/ppc476-lifter.md) | Revised and reviewed | Target example retained; full-suite baseline |
| 8 | [xcoff32-decompiler.md](../reference-modules/xcoff32-decompiler.md) | Revised and reviewed | Target example retained; full-suite baseline |
| 9 | [risc-v.md](../reference-modules/risc-v.md) | Revised and reviewed | Target example retained; full-suite baseline |
| 10 | [hisi-rv32-ext.md](../reference-modules/hisi-rv32-ext.md) | Revised and reviewed | Target example retained; full-suite baseline |
| 11 | [loongarch.md](../reference-modules/loongarch.md) | Revised and reviewed | Target example retained; full-suite baseline |
| 12 | [loongarch64-v2.md](../reference-modules/loongarch64-v2.md) | Revised and reviewed | Target example retained; full-suite baseline |
| 13 | [taint-tracker-alpha.md](../reference-modules/taint-tracker-alpha.md) | Revised and reviewed | Target example retained; full-suite baseline |
| 14 | [isa-8051.md](../reference-modules/isa-8051.md) | Revised and reviewed | Target example retained; full-suite baseline |
| 15 | [microblaze-decoder.md](../reference-modules/microblaze-decoder.md) | Revised and reviewed | Target example retained; full-suite baseline |
| 16 | [versal-pdi.md](../reference-modules/versal-pdi.md) | Revised and reviewed | Target example retained; full-suite baseline |
| 17 | [zynqmp-boot-image.md](../reference-modules/zynqmp-boot-image.md) | Revised and reviewed | Target example retained; full-suite baseline |
| 18 | [v850-rh850.md](../reference-modules/v850-rh850.md) | Revised and reviewed | Target example retained; full-suite baseline |
| 19 | [binary-lifter-sh2a.md](../reference-modules/binary-lifter-sh2a.md) | Revised and reviewed | Target example retained; full-suite baseline |
| 20 | [ecu-m68k-decoder.md](../reference-modules/ecu-m68k-decoder.md) | Revised and reviewed | Target example retained; full-suite baseline |
| 21 | [m88k-decoder.md](../reference-modules/m88k-decoder.md) | Revised and reviewed | Decoder behavior source-checked; existing tests |
| 22 | [tricore-taint-tracker.md](../reference-modules/tricore-taint-tracker.md) | Revised and reviewed | Target example retained; full-suite baseline |
| 23 | [ecu-c28x-decoder.md](../reference-modules/ecu-c28x-decoder.md) | Revised and reviewed | Target example retained; full-suite baseline |
| 24 | [c166-c167-decoding.md](../reference-modules/c166-c167-decoding.md) | Revised and reviewed | Target example retained; full-suite baseline |
| 25 | [dex.md](../reference-modules/dex.md) | Revised and reviewed | Target example retained; full-suite baseline |
| 26 | [harmonyos.md](../reference-modules/harmonyos.md) | Revised and reviewed | Target example retained; full-suite baseline |
| 27 | [micropython.md](../reference-modules/micropython.md) | Revised and reviewed | Target example retained; full-suite baseline |
| 28 | [beam.md](../reference-modules/beam.md) | Revised and reviewed | Target example retained; full-suite baseline |
| 29 | [java-class-jar-parsing.md](../reference-modules/java-class-jar-parsing.md) | Revised and reviewed | Target example retained; full-suite baseline |
| 30 | [python-pyc-scanning.md](../reference-modules/python-pyc-scanning.md) | Revised and reviewed | Target example retained; full-suite baseline |
| 31 | [knowledge-graph.md](../reference-modules/knowledge-graph.md) | Revised and reviewed | Target example retained; full-suite baseline |
| 32 | [on-demand-analysis.md](../reference-modules/on-demand-analysis.md) | Reviewed; no revision required | Target example retained; full-suite baseline |
| 33 | [binary-lifting.md](../reference-modules/binary-lifting.md) | Revised and reviewed | Target example retained; full-suite baseline |
| 34 | [encoding-dag.md](../reference-modules/encoding-dag.md) | Reviewed; no revision required | Target example retained; full-suite baseline |
| 35 | [control-flow-graph-construction.md](../reference-modules/control-flow-graph-construction.md) | Reviewed; no revision required | Target example retained; full-suite baseline |
| 36 | [ssa.md](../reference-modules/ssa.md) | Revised and reviewed | Target example retained; full-suite baseline |
| 37 | [expr-lifter.md](../reference-modules/expr-lifter.md) | Revised and reviewed | Target example retained; full-suite baseline |
| 38 | [call-argument-annotation.md](../reference-modules/call-argument-annotation.md) | Revised and reviewed | Target example retained; full-suite baseline |
| 39 | [arm64-symbolic-slicing.md](../reference-modules/arm64-symbolic-slicing.md) | Revised and reviewed | Target example retained; full-suite baseline |
| 40 | [single-function-profiling.md](../reference-modules/single-function-profiling.md) | Reviewed; no revision required | Target example retained; full-suite baseline |
| 41 | [binary-format-and-platform-identification.md](../reference-modules/binary-format-and-platform-identification.md) | Reviewed; no revision required | Target example retained; full-suite baseline |
| 42 | [streaming-and-windowed-disassembly.md](../reference-modules/streaming-and-windowed-disassembly.md) | Reviewed; no revision required | Target example retained; full-suite baseline |
| 43 | [isa-models.md](../reference-modules/isa-models.md) | Revised and reviewed | Target example retained; full-suite baseline |
| 44 | [stripped-function-discovery.md](../reference-modules/stripped-function-discovery.md) | Reviewed; no revision required | Target example retained; full-suite baseline |
| 45 | [debug-metadata-recovery.md](../reference-modules/debug-metadata-recovery.md) | Reviewed; no revision required | Target example retained; full-suite baseline |
| 46 | [entropy-mapper.md](../reference-modules/entropy-mapper.md) | Reviewed; no revision required | Target example retained; full-suite baseline |
| 47 | [dynamic-sandbox.md](../reference-modules/dynamic-sandbox.md) | Reviewed; no revision required | Target example retained; full-suite baseline |
| 48 | [cryptographic-analysis.md](../reference-modules/cryptographic-analysis.md) | Revised and reviewed | Target example retained; full-suite baseline |
| 49 | [llm-analyst-loop.md](../reference-modules/llm-analyst-loop.md) | Revised and reviewed | Target example retained; full-suite baseline |
| 50 | [semantic-code-search.md](../reference-modules/semantic-code-search.md) | Reviewed; no revision required | Target example retained; full-suite baseline |
| 51 | [hypothesis-engine-2.md](../reference-modules/hypothesis-engine-2.md) | Reviewed; no revision required | Target example retained; full-suite baseline |
| 52 | [evidence-scoring-and-probe-ranking.md](../reference-modules/evidence-scoring-and-probe-ranking.md) | Reviewed; no revision required | Target example retained; full-suite baseline |
| 53 | [flywheel.md](../reference-modules/flywheel.md) | Reviewed; no revision required | Target example retained; full-suite baseline |
| 54 | [function-identity-database.md](../reference-modules/function-identity-database.md) | Reviewed; no revision required | Target example retained; full-suite baseline |
| 55 | [sax-approximate-indexing.md](../reference-modules/sax-approximate-indexing.md) | Reviewed; no revision required | Target example retained; full-suite baseline |
| 56 | [corpus-mining-cve-patterns.md](../reference-modules/corpus-mining-cve-patterns.md) | Revised and reviewed | Target example retained; full-suite baseline |
| 57 | [kasan-oracle.md](../workflows/kasan-oracle.md) | Reviewed; no revision required | Target example retained; full-suite baseline |
| 58 | [taint-analysis.md](../reference-modules/taint-analysis.md) | Revised and reviewed | Target example retained; full-suite baseline |
| 59 | [sink-arg-classifier.md](../reference-modules/sink-arg-classifier.md) | Revised and reviewed | Target example retained; full-suite baseline |
| 60 | [transitive-sink-wrapper-discovery.md](../reference-modules/transitive-sink-wrapper-discovery.md) | Revised and reviewed | Target example retained; full-suite baseline |
| 61 | [network-sink-finder.md](../reference-modules/network-sink-finder.md) | Reviewed; no revision required | Target example retained; full-suite baseline |
| 62 | [finding-validation.md](../reference-modules/finding-validation.md) | Revised and reviewed | Target example retained; full-suite baseline |
| 63 | [format-string-scanner.md](../reference-modules/format-string-scanner.md) | Reviewed; no revision required | Target example retained; full-suite baseline |
| 64 | [heap-vulnerability-scanner.md](../reference-modules/heap-vulnerability-scanner.md) | Reviewed; no revision required | Target example retained; full-suite baseline |
| 65 | [length-underflow.md](../reference-modules/length-underflow.md) | Revised and reviewed | Target example retained; full-suite baseline |
| 66 | [scanf-family-overflow-candidates.md](../reference-modules/scanf-family-overflow-candidates.md) | Reviewed; no revision required | Target example retained; full-suite baseline |
| 67 | [preauth-exposure.md](../reference-modules/preauth-exposure.md) | Revised and reviewed | Result-model check executed; no live HTTP test |
| 68 | [apache-module-analysis.md](../reference-modules/apache-module-analysis.md) | Reviewed; no revision required | Target example retained; full-suite baseline |
| 69 | [sql-injection-scanner.md](../reference-modules/sql-injection-scanner.md) | Reviewed; no revision required | Target example retained; full-suite baseline |
| 70 | [compiler-defects.md](../reference-modules/compiler-defects.md) | Revised and reviewed | Target example retained; full-suite baseline |
| 71 | [kernel-drivers.md](../reference-modules/kernel-drivers.md) | Reviewed; no revision required | Target example retained; full-suite baseline |
| 72 | [source-code-auditing.md](../reference-modules/source-code-auditing.md) | Revised and reviewed | Executed local source fixture and model checks |
| 73 | [shellcode-templates.md](../reference-modules/shellcode-templates.md) | Reviewed; no revision required | Target example retained; full-suite baseline |
| 74 | [firmware-parsing.md](../reference-modules/firmware-parsing.md) | Reviewed; no revision required | Executed all three documented parser paths |
| 75 | [firmware-extraction.md](../reference-modules/firmware-extraction.md) | Revised and reviewed | Result fields source-checked; no firmware extraction |
| 76 | [junos.md](../reference-modules/junos.md) | Revised and reviewed | Documentation-only revision; concurrent edits excluded |
| 77 | [firmware-signature-and-secret-triage.md](../reference-modules/firmware-signature-and-secret-triage.md) | Revised and reviewed | Target example retained; full-suite baseline |
| 78 | [caen-ascii-hex.md](../reference-modules/caen-ascii-hex.md) | Reviewed; no revision required | Executed example; 42 parser tests |
| 79 | [bflt.md](../reference-modules/bflt.md) | Reviewed; no revision required | Executed example; 42 parser tests |
| 80 | [jffs2.md](../reference-modules/jffs2.md) | Reviewed; no revision required | Executed JFFS2-to-bFLT example; 42 parser tests |
| 81 | [aix-xcoff32-64-analysis.md](../reference-modules/aix-xcoff32-64-analysis.md) | Reviewed; no revision required | Target example retained; full-suite baseline |
| 82 | [ecu-architecture-detector.md](../reference-modules/ecu-architecture-detector.md) | Reviewed; no revision required | Target example retained; full-suite baseline |
| 83 | [ecu-security-access-scanner.md](../reference-modules/ecu-security-access-scanner.md) | Reviewed; no revision required | Target example retained; full-suite baseline |
| 84 | [calibration-parsers.md](../reference-modules/calibration-parsers.md) | Reviewed; no revision required | Target example retained; full-suite baseline |
| 85 | [texas-instruments-firmware.md](../reference-modules/texas-instruments-firmware.md) | Revised and reviewed | Target example retained; full-suite baseline |
| 86 | [motorola-88000-bcs-coff.md](../reference-modules/motorola-88000-bcs-coff.md) | Revised and reviewed | Decoder/extractor behavior source-checked |
| 87 | [android-apk-analysis.md](../reference-modules/android-apk-analysis.md) | Reviewed; no revision required | Target example retained; full-suite baseline |
| 88 | [go-binaries.md](../workflows/go-binaries.md) | Revised and reviewed | Target example retained; full-suite baseline |
| 89 | [browser-extension-auditing.md](../reference-modules/browser-extension-auditing.md) | Reviewed; no revision required | Target example retained; full-suite baseline |
| 90 | [loongarch64-2.md](../reference-modules/loongarch64-2.md) | Revised and reviewed | Target example retained; full-suite baseline |
| 91 | [cpp-vtable-reconstructor.md](../reference-modules/cpp-vtable-reconstructor.md) | Revised and reviewed | Target example retained; full-suite baseline |
| 92 | [ppc32-got2-resolver.md](../reference-modules/ppc32-got2-resolver.md) | Revised and reviewed | Target example retained; full-suite baseline |
| 93 | [windows-pe.md](../reference-modules/windows-pe.md) | Revised and reviewed | Target example retained; full-suite baseline |
| 94 | [proto-fsm.md](../reference-modules/proto-fsm.md) | Reviewed; no revision required | Target example retained; full-suite baseline |
| 95 | [tls-certificate-and-protocol-probing.md](../reference-modules/tls-certificate-and-protocol-probing.md) | Reviewed; no revision required | Target example retained; full-suite baseline |
| 96 | [unknown-http-api-mapping.md](../reference-modules/unknown-http-api-mapping.md) | Reviewed; no revision required | Target example retained; full-suite baseline |
| 97 | [nginx-fingerprinting-and-exposure.md](../reference-modules/nginx-fingerprinting-and-exposure.md) | Reviewed; no revision required | Target example retained; full-suite baseline |
| 98 | [inference-endpoint-enumeration.md](../reference-modules/inference-endpoint-enumeration.md) | Reviewed; no revision required | Target example retained; full-suite baseline |
| 99 | [host-platform-inventory.md](../reference-modules/host-platform-inventory.md) | Reviewed; no revision required | Target example retained; full-suite baseline |
| 100 | [windows-artifact-discovery.md](../reference-modules/windows-artifact-discovery.md) | Reviewed; no revision required | Target example retained; full-suite baseline |
| 101 | [local-network-inventory.md](../reference-modules/local-network-inventory.md) | Reviewed; no revision required | Target example retained; full-suite baseline |
| 102 | [ios-ios-xe-appliance-enumeration.md](../reference-modules/ios-ios-xe-appliance-enumeration.md) | Reviewed; no revision required | Target example retained; full-suite baseline |
| 103 | [docker-inventory-and-posture.md](../reference-modules/docker-inventory-and-posture.md) | Reviewed; no revision required | Target example retained; full-suite baseline |
| 104 | [sip-service-and-extension-discovery.md](../reference-modules/sip-service-and-extension-discovery.md) | Reviewed; no revision required | Target example retained; full-suite baseline |
| 105 | [cross-version.md](../workflows/cross-version.md) | Revised and reviewed | Target example retained; full-suite baseline |
| 106 | [dtw-matrix-profile-similarity.md](../reference-modules/dtw-matrix-profile-similarity.md) | Reviewed; no revision required | Target example retained; full-suite baseline |
| 107 | [structural.md](../reference-modules/structural.md) | Revised and reviewed | Target example retained; full-suite baseline |
| 108 | [forge.md](../reference-modules/forge.md) | Reviewed; no revision required | Target example retained; full-suite baseline |
| 109 | [yara-json-sarif-export.md](../reference-modules/yara-json-sarif-export.md) | Revised and reviewed | Target example retained; full-suite baseline |
| 110 | [multi-phase-vulnerability-sweeps.md](../reference-modules/multi-phase-vulnerability-sweeps.md) | Revised and reviewed | Target example retained; full-suite baseline |
| 111 | [engine-pattern-library.md](../reference-modules/engine-pattern-library.md) | Reviewed; no revision required | Target example retained; full-suite baseline |
| 112 | [attandck-labeling.md](../reference-modules/attandck-labeling.md) | Reviewed; no revision required | Target example retained; full-suite baseline |
| 113 | [dependency-and-supply-chain-tooling.md](../reference-modules/dependency-and-supply-chain-tooling.md) | Revised and reviewed | Target example retained; full-suite baseline |
| 114 | [binary-ninja-plugin.md](../reference-modules/binary-ninja-plugin.md) | Revised and reviewed | Target example retained; full-suite baseline |
| 115 | [analysis-rubric.md](../prompts/analysis-rubric.md) | Revised and reviewed | Guide review; API execution not applicable |
| 116 | [android-cross-layer.md](../reference-modules/android-cross-layer.md) | Added and reviewed | Extensive CLI/API reference plus hands-on tutorial; B-Unit integration and converged trace; FORGE closure linked |

## Final verification

- The original 115 capability targets were reviewed; 65 were revised and 50 required no changes. Entry 116 was added with the Android cross-layer implementation.
- The related Guardian PAK reference was also rewritten because it documents a README-linked implementation and contained unrelated generic partition text.
- The final scoped check covered 120 documents: all capability targets plus the standard, this audit, the Guardian reference, the document index, and README. It found zero prose violations.
- All 1,793 local Markdown links and relative anchors in that scope resolve. Inline code and fenced examples are excluded from link detection.
- Deterministic CAEN, bFLT, and JFFS2 examples passed, including the JFFS2-to-bFLT handoff; all 42 focused parser tests passed. The revised source-scanner example and pre-auth result-model check also passed.
- The full project suite passed: **2,573 passed and 92 skipped**. Existing warnings do not change those results.
- No Python source was changed, so no new FORGE module audit was required for this documentation-only revision.
- Live network probes, privileged operations, firmware extraction, disassembler UI execution, and target-specific payloads were not run. Their examples are labeled as target-specific, source-checked, or illustrative rather than executed.
- Concurrent Junos implementation and test changes are outside this audit's commit scope. Only the documentation-standard additions and prose corrections on that page are included.

The audit establishes explanation and evidence quality for the current checkout. It does not establish that every target-specific result remains valid across deployments or future versions.
