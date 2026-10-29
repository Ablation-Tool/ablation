# Known Anomalies: CrossLayerTaintAnalyzer

**Module:** `ablation/analyzers/cross_layer_taint.py`
**Scope:** DEX fixed-point propagation and direct ARM JNI/native tracing

An anomaly is a condition that can produce a false-positive or false-negative analytical result. Every cross-layer result requires review against DEX and native instructions before it is treated as a vulnerability.

## CLT-KA-001: Shard-local method indices

**Trigger:** More than one `classes*.dex` is present.

**Impact:** If indices from different shards were combined, callers and native methods could be misattributed, producing both false positives and false negatives.

**Behavior:** `APKJNIMapper` rejects multi-DEX packages explicitly. General DEX parsing remains available; cross-layer analysis requires a single-DEX input.

## CLT-KA-002: Obfuscated or indirect DEX dispatch

**Trigger:** Sources, sinks, or intermediate calls use obfuscated names, reflection, interfaces, or virtual dispatch not resolved to a declared method.

**Impact:** False negative when a source or callee is missed; unresolved intermediate paths can also be misleading.

**Workaround:** Seed the relevant source/sink manually and inspect interface implementations and reflective call sites.

## CLT-KA-003: Register-only native argument propagation

**Trigger:** A JNI argument is passed on the native stack, transformed through unmodeled memory, or sent through an indirect call.

**Impact:** False negative. The native sink may be present in `native_sink_surface` without a corresponding source-to-sink finding.

**Workaround:** Review report warnings and trace stack arguments and indirect targets manually. Absence of a cross-layer finding is not evidence of safety.

## CLT-KA-004: Native memory and calling-convention approximations

**Trigger:** Complex heap aliasing, VFP/SIMD transfers, C++ virtual calls, stack-slot reuse, or non-ARM native code.

**Impact:** False negative through lost taint; false positive when a conservative register/memory approximation merges unrelated values.

**Workaround:** Verify the exact native argument registers, destination capacities, and call targets at each candidate site.

## CLT-KA-005: Source/sink API catalog mismatch

**Trigger:** An application uses custom network, camera, biometric, IPC, crypto, or command wrappers not present in the API catalog.

**Impact:** False negative at the missing source or sink; conversely, a catalog name can be used without security-sensitive semantics, creating a false-positive candidate.

**Workaround:** Add target-specific wrappers after confirming their behavior. Treat catalog matches as analytical labels, not proof.

## CLT-KA-006: Fixed-point and path-reconstruction limits

**Trigger:** Propagation requires more iterations than configured, or the shortest declared call path is not the path that carried a particular value.

**Impact:** False negative on premature termination; an explanatory Java path can overstate precision even when source and sink tags are correct.

**Behavior:** Iteration exhaustion is included in report warnings. Path reconstruction uses declared call edges and can emit an unresolved-intermediate marker.

**Workaround:** Increase `--iterations` until the run converges, then verify the exact value flow through the reported methods.
