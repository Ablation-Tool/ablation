<a id="android-cross-layer-analysis"></a>
# Android Cross-Layer Analysis

Analyze Android applications end to end: inventory APK/XAPK splits, decode binary Android XML, inspect DEX classes and Java-like pseudocode, disassemble bundled ELF libraries, recover exact JNI bindings, and trace selected network, camera, biometric, and IPC inputs through DEX into native sinks.

This page is the complete capability reference. For a guided first analysis, see the [Android cross-layer analysis tutorial](../workflows/android-reverse-engineering.md).

  - [Who this is for](#who-this-is-for)
  - [What the workflow adds](#what-the-workflow-adds)
  - [Components](#components)
  - [Supported inputs and boundaries](#supported-inputs-and-boundaries)
  - [Quick start](#quick-start)
  - [CLI reference](#cli-reference)
    - [`android inventory`](#android-inventory)
    - [`android xml`](#android-xml)
    - [`android decompile`](#android-decompile)
    - [`android jni`](#android-jni)
    - [`android trace`](#android-trace)
    - [`elf-disasm`](#elf-disasm)
  - [Python API](#python-api)
    - [Inventory and decode an XAPK](#inventory-and-decode-an-xapk)
    - [Inspect DEX methods and calls](#inspect-dex-methods-and-calls)
    - [Disassemble an embedded ELF function](#disassemble-an-embedded-elf-function)
    - [Recover and inspect JNI bindings](#recover-and-inspect-jni-bindings)
    - [Run cross-layer tracing](#run-cross-layer-tracing)
  - [How JNI recovery works](#how-jni-recovery-works)
  - [How cross-layer propagation works](#how-cross-layer-propagation-works)
  - [Review methodology](#review-methodology)
  - [Operational safety](#operational-safety)
  - [Limitations and false results](#limitations-and-false-results)
  - [Troubleshooting](#troubleshooting)
  - [Validated example: Bloomberg B-Unit](#validated-example-bloomberg-b-unit)
  - [Quality and audit evidence](#quality-and-audit-evidence)

---

## Who this is for <sup>[↑](#android-cross-layer-analysis)</sup>

Use this workflow when you need to answer questions such as:

- What components, permissions, deep links, and security settings does an Android package declare?
- Which classes implement authentication, enrollment, camera, or IPC logic?
- Which Java `native` methods have implementations in bundled native libraries?
- Where does dynamic `RegisterNatives` registration send execution?
- Can selected Android inputs reach Java sinks, JNI entry points, or direct native command, memory, crypto, or network calls?

The workflow is intended for static reverse engineering and security review. It does not install or execute the target application, emulate Android, or contact application servers.

## What the workflow adds <sup>[↑](#android-cross-layer-analysis)</sup>

Earlier Android support focused on manifest findings, dangerous API references, and JNI registration signals. This workflow connects those signals into a single evidence path:

```text
APK or XAPK
  -> base and configuration APK inventory
  -> manifest and resource XML
  -> DEX classes, methods, instructions, and Java-like pseudocode
  -> native ELF symbols, disassembly, and direct calls
  -> canonical or dynamically registered JNI bindings
  -> DEX fixed-point source propagation
  -> JNI entry flows and native sink candidates
```

Each stage is independently available. You can stop after inventory, use only the DEX decompiler, or run the complete trace.

The most important distinction is between **evidence levels**:

| Level | Meaning | Example |
|---|---|---|
| Structural | An artifact or instruction sequence exists. | An activity is exported; a JNI table contains a function pointer. |
| Analytical | A model reports a candidate, path, or classification. | A source tag reaches a native memory call. |
| Confirmed | Independent evidence supports the behavior under stated conditions. | Destination capacity and attacker-controlled length are both established. |
| Runtime | A live target exhibited the behavior. | An authorized emulator accepted an injected intent and reached the reviewed state. |

A structural or analytical result is not automatically a vulnerability.

## Components <sup>[↑](#android-cross-layer-analysis)</sup>

| Component | File | Responsibility |
|---|---|---|
| `AndroidPackage` | `ablation/core/android_package.py` | Plain APK and XAPK opening, base/split inventory, bounded member reads, embedded APK access. |
| `APKParser` | `ablation/core/apk_parser.py` | Binary AXML, DEX tables, manifest metadata, native-library inventory. |
| `DEXDecompiler` | `ablation/analyzers/dex_decompiler.py` | Overload-aware class/method models, native declarations, exact call edges, Java-like class output. |
| `DEXDisasm` | `ablation/analyzers/dex_disasm.py` | Smali-style instruction output and payload skipping. |
| `DEXLifter` | `ablation/analyzers/dex_lifter.py` | Method-level Java-like pseudocode. |
| `ELFDisassembler` | `ablation/analyzers/elf_disassembler.py` | Byte-backed ELF symbols, ARM/Thumb disassembly, PLT labels, direct calls. |
| `APKJNIMapper` | `ablation/analyzers/apk_jni_mapper.py` | Canonical and `JNINativeMethod` bindings, loader evidence, Java-to-native and native call graphs. |
| `CrossLayerTaintAnalyzer` | `ablation/analyzers/cross_layer_taint.py` | DEX fixed-point propagation, JNI entry flows, direct ARM native sink tracing. |
| Android CLI | `ablation/cli.py` | `android inventory`, `xml`, `decompile`, `jni`, `trace`, and `elf-disasm` commands. |

Related components remain useful: `DexAnalyzer` performs broader dangerous-API and secret scanning, `BinderScanner` enumerates Binder services, and `JniBridgeScanner` provides a lightweight JNI surface scan.

## Supported inputs and boundaries <sup>[↑](#android-cross-layer-analysis)</sup>

| Input | Current behavior |
|---|---|
| Plain `.apk` | Opens directly with `AndroidPackage` or `APKParser`. |
| `.xapk` | Reads embedded base and configuration APKs without extraction. |
| Binary `AndroidManifest.xml` and other AXML | Decodes elements, attributes, namespaces, raw values, and text nodes. |
| Single-DEX applications | Supported by every stage, including JNI mapping and cross-layer tracing. |
| Multi-DEX applications | General DEX parsing works. JNI mapping and cross-layer tracing reject the package explicitly because method indices are shard-local. |
| ELF32/ELF64 | Byte-backed parsing and Capstone disassembly for supported architectures. |
| ARM32 and Thumb | Symbols, JNI registration pointers, PLT recovery, direct calls, and native taint. |
| AArch64 and x86 | Disassembly and direct-call support; cross-layer native taint is currently ARM-only. |
| Packed, encrypted, or heavily virtualized applications | Static coverage can be incomplete; no general unpacker or runtime devirtualization is provided. |

Default resource limits are 256 MiB per APK member and 1 MiB for XAPK `manifest.json`. `AndroidPackage.from_path(..., max_apk_bytes=...)` changes the per-APK/member limit. Limits apply to individual reads, not total package analysis time or memory.

## Quick start <sup>[↑](#android-cross-layer-analysis)</sup>

Run from the Ablation checkout with the CLI installed:

```bash
ablation android inventory app.xapk --json inventory.json
ablation android xml app.xapk base.apk AndroidManifest.xml
ablation android decompile app.xapk --class com.example.Native --method process
ablation android jni app.xapk --json jni-graph.json
ablation android trace app.xapk --iterations 16 --json taint-report.json
```

Replace `base.apk` with the actual embedded base name shown by `inventory`. Extraction is not required for these commands.

A typical first review is:

1. Inventory the package and inspect the base manifest.
2. Review exported components, deep links, permissions, backup, debugging, and cleartext settings.
3. Decompile security-relevant classes and check ambiguous pseudocode against DEX instructions.
4. Map every native declaration before opening a native function.
5. Disassemble a bound native implementation and inspect its direct calls.
6. Run a trace until it converges, then review candidates and warnings manually.

## CLI reference <sup>[↑](#android-cross-layer-analysis)</sup>

### `android inventory`

```bash
ablation android inventory PACKAGE [--json FILE]
```

Decodes the outer package and every embedded APK. Without `--json`, JSON is printed to standard output. With `--json`, the complete report is written to the specified file.

Top-level fields:

| Field | Meaning |
|---|---|
| `path` | Input path supplied by the caller. |
| `format` | `apk` or `xapk`. |
| `xapk_manifest` | Parsed outer `manifest.json`, or an empty object for a plain APK. |
| `apks` | One inventory record per embedded APK. |

Each APK record includes:

| Field | Meaning |
|---|---|
| `name`, `split_id` | Embedded filename and split identifier such as `base` or `config.armeabi_v7a`. |
| `size`, `sha256` | Uncompressed APK size and content hash. |
| `package`, `version_name`, `version_code` | Manifest identity. |
| `min_sdk`, `target_sdk` | Declared Android API levels. |
| `permissions` | Requested permission names. |
| `dex_files`, `native_libs` | DEX and native-library entry names. |
| `network_security_config` | Manifest resource reference, when present. |
| `error` | Decode failure recorded for this APK instead of silently omitting it. |

Inspect `error` before relying on a complete inventory.

### `android xml`

```bash
ablation android xml PACKAGE APK_NAME ENTRY
```

Decodes one binary XML entry from one embedded APK and prints namespace-aware XML.

Examples:

```bash
ablation android xml app.xapk base.apk AndroidManifest.xml
ablation android xml app.xapk base.apk res/xml/network_config.xml
```

Use this for security configuration, intent filters, exported flags, component permissions, network domains, certificate trust anchors, and backup/data-extraction rules. Resource references such as `@0x7f140005` remain references; this command does not reconstruct the entire resource table.

### `android decompile`

```bash
ablation android decompile PACKAGE \
  [--apk APK_NAME] [--dex DEX_NAME] \
  [--class CLASS_NAME] [--method METHOD_NAME] [--output FILE]
```

Behavior:

- Without `--class`, prints class, method, and native-method counts rather than dumping an entire application.
- With `--class`, emits all fields and methods in that class.
- With both `--class` and `--method`, emits every overload with that name.
- `--apk` selects an embedded APK; the default is the split marked `base`, or the first APK.
- `--dex` defaults to `classes.dex`.
- `--output` writes the text to a file instead of standard output.

Class names accept dotted Java form (`com.example.Native`) or DEX descriptor form (`Lcom/example/Native;`).

The output is **Java-like analysis pseudocode**. DEX register reuse, obfuscation, unresolved virtual dispatch, and incomplete type recovery can produce declarations or expressions that are not valid recovered Java. Verify security decisions against `DEXDisasm` output and call edges.

### `android jni`

```bash
ablation android jni PACKAGE [--json FILE]
```

Builds the native boundary before native vulnerability review.

The report contains:

| Field | Contents |
|---|---|
| `bindings` | Java native declaration, library, native address, registration style, confidence, optional table address, and Thumb flag. |
| `java_to_native_edges` | Callers, target native declarations, libraries, addresses, and DEX code-unit offsets. |
| `native_call_edges` | Direct native source/target addresses and names from bound entry functions. |
| `unresolved_native_methods` | Declarations for which no implementation was recovered. |
| `ambiguous_registrations` | Dynamic-table or canonical candidates that cannot be uniquely assigned. |
| `library_loads` | Recovered `System.load`/`loadLibrary` arguments and caller sites. |
| `summary` | Counts for bindings, edges, unresolved methods, and ambiguity. |

Binding fields worth preserving in notes:

- `java_method`: full DEX descriptor, including parameter and return types.
- `library` and `library_entry`: native library name and its containing APK entry.
- `native_address`: implementation virtual address as an integer in JSON.
- `binding_kind`: `canonical` or `JNINativeMethod`.
- `confidence`: for example `exact`, `name-only`, `exact-signature+loader`, or `unique-signature`.
- `table_address`: location of a recovered registration record, when applicable.
- `thumb`: whether an ARM implementation should be decoded as Thumb.

A `JNI_OnLoad` export alone does not prove how a method is registered. Dynamic records are recovered from `.rodata`, `.data.rel.ro`, and `.data`; validate high-impact conclusions against the registration call site.

### `android trace`

```bash
ablation android trace PACKAGE [--iterations N] [--json FILE]
```

Runs DEX propagation to a fixed point, then enters mapped ARM JNI functions with tainted arguments. The default iteration count is 6. Increase it when warnings report exhaustion:

```bash
ablation android trace app.xapk --iterations 16 --json taint-report.json
```

Source categories are `network`, `camera`, `biometric`, and `ipc`. Sink categories include Java or native `command`, `memory`, `crypto`, and `network`, plus `jni` entry events.

Output fields:

| Field | Meaning |
|---|---|
| `findings` | Source-to-sink candidates with source/sink kinds, locations, Java/native paths, and `static-taint-candidate` confidence. |
| `native_entry_flows` | Source-tainted Java arguments reaching a JNI declaration, including argument index and Java path. |
| `native_sink_surface` | Direct command/memory/crypto sink calls reachable from bound native entry functions, whether or not source taint reached them. |
| `warnings` | Iteration limits, unmodeled stack arguments, and other explicit precision limits. |
| `summary` | Counts for candidates, JNI entry flows, and sink surface. |

`native_sink_surface` is not a vulnerability list. It identifies functions worth reviewing. A finding with a source and sink still requires reachability, validation, destination-capacity, and deployment review.

### `elf-disasm`

```bash
ablation elf-disasm BINARY VA [--size BYTES] [--function] [--thumb]
```

Disassembles an ELF virtual address. `VA` and `--size` accept decimal or Python-style hexadecimal such as `0x1234`.

- `--size` defaults to `0x80` bytes.
- `--function` uses symbol or inferred function boundaries.
- `--thumb` forces Thumb mode. Without it, symbol metadata or an explicit registration flag determines the mode when available.

The Android JNI commands read embedded ELF bytes directly. This standalone command expects a filesystem path, so extract a library first when necessary.

## Python API <sup>[↑](#android-cross-layer-analysis)</sup>

### Inventory and decode an XAPK

```python
from ablation.core.android_package import AndroidPackage

with AndroidPackage.from_path('app.xapk', max_apk_bytes=256 * 1024 * 1024) as package:
    for record in package.inventory():
        print(record.split_id, record.package, record.version_name, record.error)

    manifest_xml = package.decode_xml('base.apk', 'AndroidManifest.xml')
    print(manifest_xml)
```

Use the context manager to close the outer ZIP. `iter_apks()` yields independent `APKParser` instances; close them when consuming manually.

### Inspect DEX methods and calls

```python
from ablation.analyzers.dex_decompiler import DEXDecompiler
from ablation.core.android_package import AndroidPackage

with AndroidPackage.from_path('app.xapk') as package:
    with next(package.iter_apks()) as apk:
        decompiler = DEXDecompiler(apk.read_dex('classes.dex'))

for method in decompiler.iter_native_methods():
    print(method.descriptor, hex(method.method_idx))

for call in decompiler.calls(method):
    print(call.caller_idx, call.target, hex(call.cu_offset))
```

Select a `DEXMethod` object or its index to decompile an exact overload. `decompile_class()` accepts dotted or descriptor class names.

### Disassemble an embedded ELF function

```python
from ablation.analyzers.elf_disassembler import ELFDisassembler

elf = ELFDisassembler.from_bytes(native_bytes, 'libnative.so')
exports = elf.exports()
address = exports['JNI_OnLoad']

for insn in elf.disassemble_function(address):
    print(insn.text())

for call in elf.direct_calls(elf.disassemble_function(address)):
    print(hex(call.site), hex(call.target), call.target_name)
```

Use `thumb=True` with `disassemble_function()` only when the target is known to be Thumb and metadata does not already establish it.

### Recover and inspect JNI bindings

```python
from ablation.analyzers.apk_jni_mapper import APKJNIMapper

with APKJNIMapper.from_path('app.xapk') as mapper:
    graph = mapper.analyze()

    for binding in graph.bindings:
        print(
            binding.java_method,
            binding.library,
            hex(binding.native_address),
            binding.binding_kind,
            binding.confidence,
        )

    print('unresolved:', graph.unresolved_native_methods)
    print('ambiguous:', graph.ambiguous_registrations)
```

Calling `analyze()` again resets and rebuilds the graph; it does not append duplicates.

### Run cross-layer tracing

```python
from ablation.analyzers.cross_layer_taint import CrossLayerTaintAnalyzer

with CrossLayerTaintAnalyzer.from_path('app.xapk') as analyzer:
    report = analyzer.analyze()

print(report.to_dict()['summary'])
for finding in report.findings:
    print(finding.source_kind, finding.sink_kind, finding.source, finding.sink)
print('warnings:', report.warnings)
```

For a custom mapper or iteration limit:

```python
from ablation.analyzers.apk_jni_mapper import APKJNIMapper
from ablation.analyzers.cross_layer_taint import CrossLayerTaintAnalyzer

with APKJNIMapper.from_path('app.xapk') as mapper:
    analyzer = CrossLayerTaintAnalyzer(mapper, max_iterations=16, native_depth=3)
    report = analyzer.analyze()
```

## How JNI recovery works <sup>[↑](#android-cross-layer-analysis)</sup>

Canonical registration is matched against JNI escaping rules and exact DEX declarations. Short canonical names provide class/method evidence; an encoded overload suffix provides stronger signature evidence.

Dynamic registration recovery scans native data sections for records with:

1. A pointer to a valid Java method name.
2. A pointer to a valid DEX method signature.
3. A pointer into an executable segment.

The mapper then uses exact signatures and recovered library-load evidence to select a declaration. Unique-signature and loader-confirmed matches have different confidence labels. Duplicate canonical exports and ambiguous dynamic candidates remain unresolved rather than being assigned arbitrarily.

## How cross-layer propagation works <sup>[↑](#android-cross-layer-analysis)</sup>

The DEX engine starts with known entry parameters and API calls, tracks origin tags through registers and declared invocations, and recomputes method argument/return summaries until no new origins appear or the iteration limit is reached.

For a mapped native declaration, Java argument origins are converted to ARM argument-register state. The native engine handles direct calls and selected stack spills, and checks command, memory, and crypto sinks. Internal direct callees are traversed up to `native_depth`, which defaults to 3.

This is not full Android framework modeling, symbolic execution, or proof of path feasibility. Unknown transformations and unresolved dispatch lose precision; conservative register and path approximations can also overstate a flow.

## Review methodology <sup>[↑](#android-cross-layer-analysis)</sup>

Use outputs in this order:

1. **Resolve completeness:** inspect inventory errors, unresolved JNI methods, and ambiguous registrations.
2. **Resolve address correctness:** confirm architecture, Thumb mode, function boundaries, and PLT labels.
3. **Resolve source semantics:** verify that a catalog source really exposes attacker-controlled or security-sensitive data.
4. **Resolve propagation:** inspect the exact DEX/native instructions, not only the reconstructed path.
5. **Resolve sink impact:** check command construction, destination capacity, length calculations, key/IV handling, and authorization.
6. **Resolve deployment reachability:** exported component, application state, user interaction, device policy, and server behavior.
7. **Use runtime evidence when authorized:** validate the surviving hypothesis in an isolated emulator or test environment.

## Operational safety <sup>[↑](#android-cross-layer-analysis)</sup>

- Analysis is local and read-only with respect to target packages. It does not run application code.
- Archive and parser limits reduce malformed-input and compressed-member resource risk but do not impose a global time budget.
- Output paths are caller-selected CLI paths; choose an appropriate report directory and avoid overwriting evidence unintentionally.
- Reports can contain package names, class names, endpoint URLs, strings, and target-specific paths. Review them before sharing.
- No runtime intent injection, server probing, or device modification is performed by these commands.

## Limitations and false results <sup>[↑](#android-cross-layer-analysis)</sup>

- **Multi-DEX:** JNI mapping and tracing require exactly one DEX and reject more rather than mixing shard-local indices.
- **Obfuscation:** original identifiers are not recovered. API catalog matching and source inference can miss custom wrappers.
- **Dynamic dispatch:** reflection, interface resolution, and indirect native calls are incomplete.
- **Native data flow:** complex heap aliases, VFP/SIMD paths, non-ARM native taint, and some stack-passed JNI arguments are not modeled.
- **JNI tables:** a structurally valid record is not proof that every table reaches `RegisterNatives`.
- **Pseudocode:** Java-like output is not recompilable recovered source.
- **Paths:** a declared-call path explains a candidate but may not be the exact runtime value path.
- **No finding:** absence of a cross-layer result is not proof of safety.

See [Known Anomalies: Cross-Layer Taint](../reference-anomalies/cross-layer-taint.md) for trigger conditions and workarounds.

## Troubleshooting <sup>[↑](#android-cross-layer-analysis)</sup>

| Symptom | Likely cause | Action |
|---|---|---|
| `No APK members found` | Input is not an APK/XAPK or has an unsupported container layout. | Check file type and ZIP contents before analysis. |
| `APK member ... exceeds ... limit` | Member exceeds the configured safety limit. | Confirm the artifact, then set a deliberate larger `max_apk_bytes` for trusted input. |
| `supports exactly one DEX per package` | JNI/tracing encountered multiple DEX shards. | Use general DEX parsing per shard or supply a single-DEX package; do not merge indices manually. |
| `method not found` | Wrong class descriptor, method name, APK, or DEX shard. | Check `inventory`, use full class form, and omit `--method` to inspect the class. |
| No JNI bindings | No native declarations, no bundled matching implementation, or unsupported layout. | Inspect native libraries and unresolved methods; distinguish missing code from failed matching. |
| Ambiguous registration | Multiple canonical/dynamic candidates match. | Use loader evidence and disassemble the registration site; do not select the first candidate. |
| Unexpected empty disassembly | Wrong VA, architecture, mapping, or Thumb mode. | Verify the ELF virtual address and symbol metadata; use `--thumb` only when justified. |
| Trace reports iteration exhaustion | Propagation did not converge within the configured limit. | Increase `--iterations` and compare output after convergence. |
| Zero cross-layer findings | Sources/sinks are unrecognized, paths are indirect, or no modeled flow exists. | Review known anomalies and seed target-specific wrappers manually; do not treat zero as safe. |

## Validated example: Bloomberg B-Unit <sup>[↑](#android-cross-layer-analysis)</sup>

The real B-Unit 1.25.0 XAPK provided a full integration target:

- 20 embedded APKs decoded without extraction.
- 9,328 classes and 42,929 declared methods modeled.
- 25 native declarations bound: 17 canonical and 8 dynamic registrations.
- 18 Java-to-native call edges, with zero unresolved or ambiguous methods.
- A 16-iteration trace converged without warnings.
- Five Java data-flow candidates, zero source-tainted JNI entry flows, and five direct native memory-call review sites reported.

The review also identified unprotected exported enrollment/token activities and custom/HTTPS deep-link challenge handling. That is confirmed IPC attack surface, not a demonstrated authentication bypass. Details and addresses are in [Bloomberg B-Unit Android Reverse Engineering](../../re/bloomberg/ANDROID_BUNIT_RE.md).

## Quality and audit evidence <sup>[↑](#android-cross-layer-analysis)</sup>

All 11 touched Python files, including the test module, have cached FORGE passes with zero unresolved findings. The review fixed multi-DEX misattribution, unbounded archive/parser reads, repeated-mapper state, duplicate canonical selection, and initialization cleanup.

- [FORGE audit and closure](android-cross-layer-forge-audit.md)
- [Known anomalies](../reference-anomalies/cross-layer-taint.md)
- [Hands-on workflow](../workflows/android-reverse-engineering.md)
- [Original Android APK analysis](android.md)
- [JNI bridge reconstruction](jni-bridge-reconstruction.md)
- [DEX disassembly and lifting](dex-disassembly-and-lifting.md)

[↑ Back to top](#android-cross-layer-analysis)
