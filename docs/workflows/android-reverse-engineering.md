# Android Cross-Layer Analysis Tutorial

This tutorial walks through an authorized static review of an Android APK or XAPK, from initial inventory to JNI mapping, cross-layer taint analysis, and manual confirmation. It is intended for a first end-to-end analysis.

For complete command and output-field references, see [Android Cross-Layer Analysis](../reference-modules/android-cross-layer.md).

## Before you start

You need:

- An APK or XAPK that you are authorized to analyze.
- The Ablation CLI and its declared Capstone/pyelftools dependencies.
- A writable directory for reports.
- Optionally, an isolated Android emulator or test device for runtime verification. Runtime testing is not required for the static workflow.

The examples use `app.xapk` and a `reports/` directory. Replace them with your paths. Do not run optional intent tests against a production device or an application you are not authorized to test.

## The review loop

Use this sequence:

```text
Inventory
  -> manifest and security configuration
  -> security-relevant DEX classes
  -> complete JNI bindings
  -> native call sites
  -> converged cross-layer trace
  -> manual or runtime confirmation
```

Do not begin with a dangerous function name and assume it is exploitable. First establish what exists, then reachability, then attacker control, then impact.

## Stage 1: Inventory the package

Create a report directory and run:

```bash
mkdir -p reports
ablation android inventory app.xapk --json reports/inventory.json
```

Review:

- Which APK is the `base` split?
- What are the package name, version, minimum SDK, and target SDK?
- Which architectures are bundled?
- How many DEX files and native libraries are present?
- Does any record contain an `error`?

Illustrative summary, not output from a specific target:

```text
format: xapk
base package: com.example.app
version: 1.0.0 (100)
DEX: classes.dex
native ABI: armeabi-v7a
```

The actual report is JSON, not this abbreviated display. Preserve the base APK filename for subsequent commands; it is not necessarily `base.apk`.

**Stop condition:** if the base manifest cannot be decoded or every APK record has an error, fix the input/container issue before interpreting downstream results.

## Stage 2: Review manifest and network security

Decode the base manifest:

```bash
ablation android xml app.xapk base.apk AndroidManifest.xml
```

Record the following in your notes:

| Question | Where to look |
|---|---|
| Is debugging enabled? | `<application android:debuggable>` |
| Is backup allowed? | `android:allowBackup`, `fullBackupContent`, `dataExtractionRules` |
| Which components are exported? | `activity`, `service`, `receiver`, and `provider` entries |
| Are exported components permission-guarded? | Component and application `android:permission` |
| Which deep links enter the app? | `VIEW` actions, `BROWSABLE` categories, schemes, hosts, and path patterns |
| Is cleartext traffic allowed? | `usesCleartextTraffic` and the network-security XML |
| Which permissions are security-sensitive? | Camera, biometric/fingerprint, location, contacts, SMS, storage, notifications, and services |

If `networkSecurityConfig` is present, decode its resource entry when the filename is known:

```bash
ablation android xml app.xapk base.apk res/xml/network_config.xml
```

A resource reference such as `@0x7f140005` does not itself prove a configuration; inspect the referenced XML. Debug-only trust overrides must not be confused with release trust behavior.

**Evidence checkpoint:** an exported activity with no permission is reachable attack surface. It is not yet an authorization bypass. Continue into its intent handling and authorization logic.

## Stage 3: Decompile security-relevant classes

Start with classes named by exported components, authentication/enrollment code, deep-link handlers, notification handlers, camera callbacks, and native declarations.

```bash
ablation android decompile app.xapk \
  --class com.example.app.FlowActivity \
  --output reports/FlowActivity.java.txt
```

To inspect one method and every overload with its name:

```bash
ablation android decompile app.xapk \
  --class com.example.app.FlowActivity \
  --method handleIntent \
  --output reports/FlowActivity-handleIntent.java.txt
```

If you omit `--class`, the command reports class/method/native counts rather than producing a large source dump.

Review for:

- Intent action, data URI, extras, and caller state.
- Dynamic feature checks and enrollment state.
- Nonce, challenge, timestamp, expiry, replay, and signature checks.
- Sensitive values in logs or exceptions.
- Calls to native methods and the arguments passed to them.

The output is pseudocode. Obfuscation and register reuse can produce misleading types or expressions. When a condition matters, verify it against `DEXDisasm` and exact `method_idx` call edges rather than relying on the emitted text alone.

## Stage 4: Map the JNI boundary before native review

Run:

```bash
ablation android jni app.xapk --json reports/jni-graph.json
```

First inspect `summary` and completeness fields:

- `bindings`
- `java_to_native_edges`
- `native_call_edges`
- `unresolved`
- `ambiguous`

Then review each binding:

```text
Java native declaration
  -> containing library
  -> native address
  -> canonical or JNINativeMethod
  -> confidence and optional table address
```

A complete binding means the implementation was recovered, not that the implementation is safe or reachable from attacker input.

### Canonical registration

A canonical `Java_*` export encodes the Java class and method. An overload suffix provides stronger signature evidence. Without it, check whether multiple declarations could share the name.

### Dynamic registration

A `JNINativeMethod` record contains name, signature, and function pointers. The mapper uses exact signatures and library-load evidence to recover bindings. Inspect `confidence` and `table_address`; a structurally valid record still deserves registration-call verification for high-impact findings.

### Ambiguity and multi-DEX

Do not select the first candidate from `ambiguous_registrations`. Use loader and registration-site evidence to disambiguate it.

If the package contains multiple DEX shards, the mapper rejects it. General DEX parsing still works, but shard-local method indices must not be combined into one graph. Supply a supported single-DEX package or use per-shard inspection while the composite model is unavailable.

## Stage 5: Inspect native implementations

The JNI report is read directly from embedded libraries. For standalone `elf-disasm`, extract a specific library to your report directory without extracting the whole package:

```python
from pathlib import Path
from ablation.core.android_package import AndroidPackage

with AndroidPackage.from_path('app.xapk') as package:
    for native in package.iter_native_libraries('armeabi-v7a'):
        if native.name == 'libnative.so':
            Path('reports/libnative.so').write_bytes(native.data)
```

Disassemble a bound address from `jni-graph.json`:

```bash
ablation elf-disasm reports/libnative.so 0x1234 --function
```

If the binding is marked Thumb and the target lacks symbol metadata:

```bash
ablation elf-disasm reports/libnative.so 0x1234 --function --thumb
```

Check:

1. The function prologue and argument handling.
2. JNI string/array/direct-buffer conversions.
3. Integer truncation, sign extension, and size calculations.
4. Destination capacities before memory copies.
5. Calls through PLT versus indirect calls.
6. Error paths that leave buffers, pointers, or native peers alive.

A resolved PLT name such as `memcpy` identifies the callee. It does not prove an overflow. Establish source, length, and destination independently.

## Stage 6: Run a cross-layer trace

Start with the default:

```bash
ablation android trace app.xapk --json reports/taint-6.json
```

If warnings report iteration exhaustion, increase the limit:

```bash
ablation android trace app.xapk --iterations 16 --json reports/taint-16.json
```

Use the converged report for analysis. Compare whether new candidates or warnings appeared.

### Understand the output groups

**`findings`** are source-to-sink candidates. Each includes source and sink kinds, locations, paths, and `static-taint-candidate` confidence.

**`native_entry_flows`** show selected source tags reaching Java native declarations. These are especially useful for prioritizing native functions even when no native sink was reached.

**`native_sink_surface`** lists direct native command/memory/crypto calls from bound entry functions, with or without a tainted Java source. Treat it as a review queue.

**`warnings`** describe precision limits such as unmodeled stack arguments or iteration exhaustion. Never hide them in a final report.

### Interpret zero results correctly

Zero source-tainted JNI entries can mean:

- no modeled flow exists;
- source or sink APIs are outside the catalog;
- obfuscation hid the relevant methods;
- reflection or indirect dispatch broke the path;
- native stack/heap/VFP propagation was not modeled;
- the analysis did not converge.

It does not mean the application is safe.

## Stage 7: Confirm or reject candidates manually

For each candidate, create a short evidence record:

| Field | What to establish |
|---|---|
| Source | Who controls the value, and is it security-sensitive? |
| Reachability | Which exported entry point, lifecycle state, or callback reaches the path? |
| Propagation | Which exact instructions carry the same value? |
| Validation | Are length, type, signature, freshness, caller, or state checks applied? |
| Sink impact | What command, memory write, cryptographic operation, or network request results? |
| Deployment | Do build type, device policy, server behavior, and user interaction permit it? |
| Evidence level | Structural, analytical, confirmed, or runtime? |

Reject a candidate when the exact instructions disprove the source/value relationship or when a validation check reliably blocks the impact. Record why; do not simply delete it.

## Optional runtime verification

Use runtime testing only in an isolated, authorized environment and only after static review identifies a concrete question.

For example, an exported deep-link activity can be launched with a harmless test URI on an emulator:

```bash
adb shell am start -W \
  -a android.intent.action.VIEW \
  -d 'bunit://example-test' \
  com.example.app/.FlowSelectionActivity
```

This command is illustrative and was not executed as part of the toolchain validation. Adapt the package, activity, and URI to your test application. Do not use real credentials, production challenges, or destructive payloads.

Useful observations:

- Is the activity reachable without the expected caller?
- Is the URI accepted, rejected, or ignored?
- Are enrollment, signature, expiry, and replay checks enforced?
- Does the application reach the native function observed statically?

Runtime success in reaching an activity is still not proof of authentication bypass. The security-sensitive state transition must be demonstrated safely.

## Stage 8: Write the report

A useful final report separates these sections:

1. **Target identity:** package hash, version, splits, architecture, and analysis date.
2. **Scope and method:** commands run, convergence, runtime status, and explicit exclusions.
3. **Confirmed configuration:** manifest and native facts with evidence.
4. **Attack surface:** exported components, deep links, JNI entry points, and native calls.
5. **Analytical candidates:** source-to-sink paths with warnings and confidence.
6. **Confirmed findings:** only claims supported by independent evidence.
7. **Limitations:** multi-DEX, obfuscation, indirect calls, resource bounds, and untested runtime behavior.
8. **Next actions:** exact checks or runtime tests needed to resolve remaining uncertainty.

Do not turn `native_sink_surface` into a vulnerability count. Do not report a missing taint path as a safety certification.

## Worked integration example: B-Unit

The real Bloomberg B-Unit review followed this workflow:

- Inventoried 20 embedded APKs and decoded the base manifest/network XML.
- Modeled 9,328 classes and 42,929 declared methods.
- Bound all 25 native declarations with no unresolved or ambiguous registrations.
- Identified exported enrollment/token activities and custom `bunit://` plus verified HTTPS deep links.
- Found notification challenge data flowing into a token activity, which established IPC attack surface but not challenge acceptance.
- Converged after 16 taint iterations with five Java candidates, zero source-tainted JNI entry flows, and five direct native memory-call review sites.

No runtime intent injection was performed. The report therefore labels exported authentication flow surface as confirmed, taint paths as analytical candidates, and authentication bypass as unproven.

Read the target-specific report at [Bloomberg B-Unit Android Reverse Engineering](../../re/bloomberg/ANDROID_BUNIT_RE.md).

## Performance and resource guidance

- Keep default archive limits for untrusted packages. Raise them deliberately for trusted large inputs.
- Use inventory before full tracing to avoid running an expensive analysis on the wrong artifact.
- Decompile selected classes instead of dumping the entire application.
- Start with fewer taint iterations, then increase until convergence is reported.
- Preserve warnings and any unresolved/ambiguous records with the report.
- Member limits do not cap total CPU or memory for a large package.

## Troubleshooting checklist

- **Wrong base APK:** use the exact embedded filename from `inventory`.
- **Method not found:** check class form, overload name, APK, and DEX shard.
- **Multi-DEX rejection:** use general per-shard DEX analysis or a supported single-DEX input.
- **No JNI implementation:** inspect bundled libraries, unresolved methods, and registration style before assuming dead code.
- **Ambiguous binding:** inspect loader and registration-site evidence instead of choosing arbitrarily.
- **Bad disassembly:** verify VA mapping, function boundary, architecture, and Thumb mode.
- **No taint results:** check convergence, API coverage, obfuscation, and indirect paths before concluding safety.

## Related documentation

- [Complete Android capability reference](../reference-modules/android-cross-layer.md)
- [Known anomalies](../reference-anomalies/cross-layer-taint.md)
- [FORGE audit](../reference-modules/android-cross-layer-forge-audit.md)
- [Android manifest/API analysis](../reference-modules/android-apk-analysis.md)
- [JNI bridge reconstruction](../reference-modules/jni-bridge-reconstruction.md)
- [DEX disassembly and lifting](../reference-modules/dex-disassembly-and-lifting.md)
- [Finding validation](../reference-modules/finding-validation.md)
