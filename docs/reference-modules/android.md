# Android / APK Analysis

Zero-dependency analysis for Android APK files. No androguard, no apktool, no jadx. Pure Python stdlib only. Works on raw `.apk` files and APKPure `.xapk` containers.

Four analysis layers: **APKParser** reads the ZIP/AXML/DEX structure; **DexAnalyzer** scans DEX bytecode for security issues; **JniBridgeScanner** traces JNI bridges; **BinderScanner** maps the exported Binder service surface.

---

## What this is

Android APK files are ZIP containers with binary XML manifests, DEX bytecode, and native libraries. Static analysis tools like androguard and jadx require installation and do not run headlessly in scripts. This stack analyzes APKs with zero external dependencies. `APKParser` reads the ZIP, binary AXML manifest, and DEX structure. `DexAnalyzer` scans DEX bytecode for dangerous API patterns. `JniBridgeScanner` traces bridges between Java and native code. `BinderScanner` maps exported Binder service endpoints.

---

## Where it's used

- Android APK files from Google Play or direct device extraction
- APKPure XAPK containers
- Any APK where the goal is identifying dangerous API usage, JNI bridges, or exported Binder surface

---

## Safe usage

**Use the context manager form `APKParser.from_path()`.** The context manager closes the ZIP handle automatically. Without it, the ZIP file descriptor leaks on exception paths.

**Run DEX analysis on all `classes*.dex` files.** `APKParser.iter_dex()` yields every DEX in a multidex APK. Analyzing `classes.dex` only misses code split across secondary DEX files, including security-relevant classes in large apps. `APKJNIMapper` and `CrossLayerTaintAnalyzer` currently reject multi-DEX input rather than mixing shard-local method indices.

**Distinguish JNI canonical naming from dynamic registration.** `JniBridgeScanner` flags `JNI_OnLoad` exports as dynamic registration. Dynamic registration is not visible from symbol names alone; `APKJNIMapper` can recover `JNINativeMethod` tables statically, without loading the target library.

**Expect name-based search to fail on obfuscated APKs.** Obfuscated APKs use single-letter class and method names. String pool scanning and dangerous-import detection remain effective on obfuscated APKs because they target bytecode patterns, not identifiers.

---

## Why this exists

Three things made APK security analysis slow before this stack:

**1. External tool dependencies blocked scripted analysis.**
androguard, apktool, and jadx are GUI-focused tools with installation friction. Running them headlessly in a scan pipeline required subprocess wrappers, output parsing, and version compatibility management. APKParser uses only `zipfile`, `struct`, and `io` from the Python stdlib. It runs anywhere Python runs.

**2. DEX bytecode was opaque without disassembly.**
Finding `addJavascriptInterface` calls or `InMemoryDexClassLoader` usage required full decompilation or searching decompiled Java output. DEXDisasm decodes the DEX flat-table format directly: method references, string pool, field references, and the instruction stream are all addressable by offset from the binary file. No decompilation step is needed to find dangerous API patterns.

**3. JNI bridge reconstruction required manual symbol table reading.**
Knowing which Java methods have native implementations and whether those implementations use canonical naming (`Java_*`) or dynamic registration (`RegisterNatives`) required reading both the DEX access flags and the ELF symbol table. JniBridgeScanner cross-references both automatically and flags the harder-to-analyze dynamic registration case.

---

## Full analysis pipeline

```mermaid
flowchart TD
    A(["app.apk (or app.xapk)"]):::input --> B["APKParser.from_path(path)\nZIP container:\n  AndroidManifest.xml (binary AXML)\n  classes.dex · classes2.dex (multidex)\n  lib/arm64-v8a/*.so\n  assets/keys.bmp (optional steganographic keys)\nXAPK: outer ZIP lacks AndroidManifest.xml\n  → extract inner base.apk first"]:::primary

    B:::primary --> C["AXML parser\nBinary XML: ResXMLTree chunks\nSTART_ELEMENT + ATTRIBUTE chunks\nOffset fix: attr_base = body + _attr_start\n  NOT body+8+start\n  (garbage reads without this fix)"]:::secondary

    B:::primary --> D["DEX parser (all classes*.dex)\nFlat-table structure:\n  string_ids → type_ids → proto_ids\n  field_ids → method_ids → class_defs → data\n  code_items · string data"]:::tertiary

    C:::secondary --> E(["Manifest fields\npackage · min/target SDK · permissions\ncomponents · security flags\ndebugable · allowBackup · cleartext traffic"]):::output

    D:::tertiary --> F["DexAnalyzer.scan()\nString pool: AKIA* / AIza* (cloud keys)\nMethod refs: addJavascriptInterface / exec / Runtime\nManifest flags: debuggable / allowBackup\n→ findings by severity"]:::tertiary

    D:::tertiary --> G["JniBridgeScanner.scan()\nDEX: ACC_NATIVE (0x0100) flag on methods\nELF: Java_* exports (canonical naming)\n     JNI_OnLoad export (dynamic registration)\n→ bridge map + risk tier"]:::tertiary

    D:::tertiary --> H["BinderScanner.scan()\nService subclasses\nRaw onTransact override\nAIDL $Stub classes\n→ exported Binder surface"]:::tertiary

    F:::tertiary --> I(["LibraryInventory.from_dir()\nARM64 BL-target count\nSecurity string scoring\nPLT hook detection\n→ ranked .so triage table"]):::output
    G:::tertiary --> I:::output
    H:::tertiary --> I:::output
    classDef input     fill:#0d47a1,stroke:#1565c0,color:#fff
    classDef primary   fill:#e65100,stroke:#bf360c,color:#fff
    classDef secondary fill:#004d40,stroke:#00695c,color:#fff
    classDef tertiary  fill:#4a148c,stroke:#6a1b9a,color:#fff
    classDef neutral   fill:#37474f,stroke:#546e7a,color:#fff
    classDef output    fill:#1b5e20,stroke:#2e7d32,color:#fff
    linkStyle 0 stroke:#bf360c,stroke-width:2px
    linkStyle 1 stroke:#00695c,stroke-width:2px
    linkStyle 2 stroke:#6a1b9a,stroke-width:2px
    linkStyle 3 stroke:#2e7d32,stroke-width:3px
    linkStyle 4 stroke:#6a1b9a,stroke-width:2px
    linkStyle 5 stroke:#6a1b9a,stroke-width:2px
    linkStyle 6 stroke:#6a1b9a,stroke-width:2px
    linkStyle 7 stroke:#2e7d32,stroke-width:3px
    linkStyle 8 stroke:#2e7d32,stroke-width:3px
    linkStyle 9 stroke:#2e7d32,stroke-width:3px
```

---

## Usage

```python
from ablation.core.apk_parser import APKParser
from ablation.analyzers.dex_analyzer import DexAnalyzer
from ablation.analyzers.jni_bridge_scanner import JniBridgeScanner
from ablation.analyzers.binder_scanner import BinderScanner

with APKParser.from_path('app.apk') as apk:
    # Manifest: package name, SDK targets, permissions, exported components
    mf = apk.parse_manifest()
    print(mf.package, mf.min_sdk, mf.target_sdk)
    print(mf.dangerous_permissions())
    print(mf.exported_components())

    # DEX: scan all classes*.dex files for dangerous API usage
    # DexAnalyzer(apk) iterates all DEX files in the APK internally
    dex_findings = DexAnalyzer(apk).scan()
    for f in dex_findings:
        print(f.severity, f.category, f.title, f.source)

    # JNI bridges: find native method declarations and their .so implementations
    jni_findings = JniBridgeScanner(apk).scan()
    for f in jni_findings:
        print(f.severity, f.title, f.detail)

    # Binder surface: exported service endpoints
    binder_findings = BinderScanner(apk).scan()
    for f in binder_findings:
        print(f.severity, f.title, f.detail)
```

Use `sweeps/android_sweep.py` for a single command that runs all four layers and writes a finding report:

```python
from sweeps.android_sweep import run_sweep

run_sweep('app.apk')
```

---

## APKParser

**File:** `ablation/core/apk_parser.py`

### Construction

```python
from ablation.core.apk_parser import APKParser

# Context manager (preferred: closes the ZIP automatically)
with APKParser.from_path('/path/to/app.apk') as apk:
    mf = apk.parse_manifest()
    print(mf.package, mf.version_name, mf.version_code)
```

Use `AndroidPackage` for XAPK containers: it reads the embedded base and configuration APKs in memory and returns an `APKParser` for each. `APKParser.from_path()` itself opens a single APK; `APKParser.from_bytes()` handles an already embedded APK without extraction.

### AXML binary format

Android binary XML is a chunk-based format. The critical offset fix: in `ResXMLTree_attrExt`, the `attributeStart` field is relative to the start of the `ResXMLTree_attrExt` struct (which begins at `body+8`), not relative to the chunk body start. Using `attr_base = body + _attr_start` instead of `attr_base = body + 8 + _attr_start` silently reads garbage attribute data.

```
  AndroidManifest.xml (binary AXML)
  ┌─────────────────────────────────────────────────────────────
  │ RES_XML_TYPE chunk header (0x00080003)
  │   → file size, header size
  ├─────────────────────────────────────────────────────────────
  │ RES_STRING_POOL_TYPE (0x00080001)
  │   → string table: all attribute names and values as UTF-16
  ├─────────────────────────────────────────────────────────────
  │ RES_XML_START_NAMESPACE_TYPE (0x00100100)
  │   → android namespace URI
  ├─────────────────────────────────────────────────────────────
  │ RES_XML_START_ELEMENT_TYPE (0x00100102) per XML tag
  │   ResXMLTree_attrExt:
  │     attributeStart: RELATIVE to this struct's start (+8 from body)
  │     attributeCount: number of attributes
  │   per attribute (attributeStart + i*attributeSize bytes from body+8):
  │     ns_idx, name_idx, raw_value_idx, data_type, data
  └─────────────────────────────────────────────────────────────
```

### Manifest

```python
mf = apk.parse_manifest()
mf.package             # "com.example.app"
mf.version_name        # "1.2.3"
mf.min_sdk             # 24
mf.target_sdk          # 34
mf.permissions         # requested: ["android.permission.CAMERA", ...]
mf.dangerous_permissions()  # filtered to DANGEROUS-level perms only
mf.exported_components()    # only exported=true components
mf.debuggable          # True → not a production build
mf.allow_backup        # True → adb backup allowed (data exfil)
mf.uses_cleartext_traffic   # True → HTTP allowed
```

### DEX iteration

```python
for dex in apk.iter_dex():
    for s in dex.iter_strings():
        if s.startswith('AKIA'):
            print('AWS key:', s)
    for m in dex.iter_method_refs():
        if 'loadLibrary' in m.method_name:
            print('native lib load:', m)
```

### Native libs

```python
libs = apk.native_libs('arm64-v8a')
dest = apk.extract_native_lib('lib/arm64-v8a/libfoo.so', Path('/tmp/out/'))
```

---

## DexAnalyzer

**File:** `ablation/analyzers/dex_analyzer.py`

Security scanner over DEX string pool and method reference table. Runs on the full APK (iterates all `classes*.dex` files).

```python
from ablation.analyzers.dex_analyzer import DexAnalyzer

scanner = DexAnalyzer.from_path('/path/to/app.apk')
findings = scanner.scan()
print(DexAnalyzer.report(findings))
```

### Finding categories

| Severity | Category | What triggers it |
|---|---|---|
| CRITICAL | `manifest/debuggable` | `android:debuggable="true"` |
| CRITICAL | `api/js_interface` | `addJavascriptInterface` call |
| CRITICAL | `api/dynamic_dex_load` | `InMemoryDexClassLoader` |
| CRITICAL | `api/device_wipe` | `wipeData` |
| CRITICAL | `secret/aws_key` | `AKIA`-prefixed string |
| HIGH | `manifest/cleartext` | `usesCleartextTraffic=true` |
| HIGH | `manifest/allow_backup` | `android:allowBackup=true` |
| HIGH | `api/exec` | `Runtime.exec` |
| HIGH | `api/eval_js` | `evaluateJavascript` |
| HIGH | `secret/google_api_key` | `AIza`-prefixed string |
| HIGH | `secret/jwt_bearer` | `eyJ`-prefixed string |
| HIGH | `secret/private_key_pem` | `BEGIN PRIVATE KEY` |
| MEDIUM | `manifest/exported_N` | N exported components |
| LOW | `manifest/permission_N` | dangerous permission count |

---

## JniBridgeScanner

**File:** `ablation/analyzers/jni_bridge_scanner.py`

Reconstructs the Java-native boundary from DEX `class_data_item` access flags and ELF dynsym. Three-way classification: confirmed native in both DEX and ELF, ACC_NATIVE with no ELF symbol stripped or dynamically registered, and `Java_*` ELF symbols with no ACC_NATIVE flag helpers or dead code.

### Two JNI registration modes

```
  Mode 1: Canonical naming (easier to RE)
    ART resolves Java_pkg_ClassName_methodName automatically.
    ELF export: Java_com_example_Foo_bar
      → Java class: com.example.Foo, method: bar
    Symbol name directly encodes the Java-native binding.
    ARM64TaintTracker starts from the function VA directly.

  Mode 2: Dynamic registration via JNI_OnLoad (harder to RE)
    Library exports only JNI_OnLoad.
    JNI_OnLoad calls: env->FindClass("com/example/Foo")
                      env->RegisterNatives(klass, methods, count)
    'methods' is an array of JNINativeMethod structs:
      { char* name, char* signature, void* fnPtr }
    Function pointers may be stripped (no name in dynsym).
    ARM64TaintTracker must start from JNI_OnLoad,
    walk the RegisterNatives call's third argument (the array),
    and read the fnPtr values to recover the binding.
```

### Usage

```python
from ablation.analyzers.jni_bridge_scanner import JniBridgeScanner

scanner = JniBridgeScanner.from_path('/path/to/app.apk')
findings = scanner.scan()
print(JniBridgeScanner.report(findings))
```

### Finding categories

| Severity | Category | Meaning |
|---|---|---|
| HIGH | `jni/dynamic_registration` | `JNI_OnLoad`+`RegisterNatives`; function pointers not in symbol table |
| MEDIUM | `jni/canonical_naming` | `Java_*` symbols; naming is recoverable |
| HIGH | `jni/opaque_peer` | Class has `long` field with peer-like name; native holds raw pointer |
| INFO | `jni/load_sites` | Count of `System.loadLibrary` call sites |

---

## BinderScanner

**File:** `ablation/analyzers/binder_scanner.py`

Maps the exported Binder service surface from DEX class definitions and the manifest. Binder is Android's primary IPC mechanism. Exported services are the first-hop attack surface for privilege escalation and authentication bypass.

### Binder IPC dispatch path

```
  Client process calls:
    IBinder binder = context.getSystemService("my_service")
    IMyService iface = IMyService.Stub.asInterface(binder)
    iface.doSomething(arg)

  This generates a Binder transaction:
    code = TRANSACTION_doSomething  (= 1 for first method)
    data = Parcel(arg serialized)
    reply = Parcel()
    binder.transact(code, data, reply, 0)

  Server side receives in onTransact(code, data, reply, flags):
    switch (code):
      case TRANSACTION_doSomething:
        // deserialize from data Parcel
        // process
        // write to reply Parcel

  AIDL-generated $Stub.onTransact handles this dispatch automatically.
  Raw Binder subclasses write it manually: missing auth checks here are CRITICAL.
```

### Usage

```python
from ablation.analyzers.binder_scanner import BinderScanner

scanner = BinderScanner.from_path('/path/to/app.apk')
findings = scanner.scan()
print(BinderScanner.report(findings))
```

### Finding categories

| Severity | Category | Meaning |
|---|---|---|
| HIGH | `binder/exported_service` | Service exported=true; accepts binds from other apps |
| HIGH | `binder/raw_transact` | Class overrides `onTransact`; manual dispatch; missing auth check risk |
| MEDIUM | `binder/aidl_stub` | AIDL-generated `$Stub` class; dispatch by integer transaction code |
| MEDIUM | `binder/service_subclass` | Service subclass; potential Binder server |
| INFO | `binder/messenger` | Messenger IPC usage |

---

## android_sweep.py

**File:** `sweeps/android_sweep.py`

Orchestration script that runs the APK RE pass in one call: manifest analysis, DexAnalyzer, JniBridgeScanner, BinderScanner, and native lib ELF security properties.

```python
from sweeps.android_sweep import run_sweep

results = run_sweep('/path/to/app.apk')
# results: dict with keys manifest, dex_findings, jni_findings,
#          binder_findings, native_lib_findings
```

Or from the command line:

```bash
python sweeps/android_sweep.py /path/to/app.apk
```

XAPK containers are handled transparently. Pass the `.xapk` file directly.

---

## DEXDisasm

**File:** `ablation/analyzers/dex_disasm.py`

Disassembles DEX bytecode to smali-style text. Covers all 17 DEX instruction formats and annotates every reference with the full descriptor from the DEX flat tables: method signatures, field types, class names, and string literals.

### DEX flat-table structure

DEX does not use a traditional symbol table. All references are encoded as indices into four flat arrays:

```
  DEX file layout:
  ┌──────────────────────────────────────────────────────────
  │ header (112 bytes): magic, checksum, SHA-1, file_size...
  ├──────────────────────────────────────────────────────────
  │ string_ids[N]:   4-byte offsets into string_data section
  │   string_data[i]: ULEB128 length + UTF-16 chars
  ├──────────────────────────────────────────────────────────
  │ type_ids[N]:     4-byte indices into string_ids
  │   type descriptor: "Ljava/lang/String;" or "I" or "[B"
  ├──────────────────────────────────────────────────────────
  │ proto_ids[N]:    (shorty_idx, return_type_idx, params_off)
  │   shorty: "VLjava/lang/String;" encodes return+param types
  ├──────────────────────────────────────────────────────────
  │ field_ids[N]:    (class_idx, type_idx, name_idx)
  ├──────────────────────────────────────────────────────────
  │ method_ids[N]:   (class_idx, proto_idx, name_idx)
  │   every method reference (invoke-*) indexes into this table
  ├──────────────────────────────────────────────────────────
  │ class_defs[N]:   (class_idx, access_flags, superclass_idx,
  │                   interfaces_off, source_file_idx,
  │                   annotations_off, class_data_off,
  │                   static_values_off)
  │   class_data_item: static_fields, instance_fields,
  │                    direct_methods, virtual_methods
  │   encoded_method: (method_idx_diff, access_flags, code_off)
  │     access_flags & 0x0100 == 0x0100 → ACC_NATIVE
  └──────────────────────────────────────────────────────────
```

### Usage

```python
from ablation.core.apk_parser import APKParser
from ablation.analyzers.dex_disasm import DEXDisasm

with APKParser.from_path('/path/to/app.apk') as apk:
    dexes = list(apk.iter_dex())

dd = DEXDisasm(dexes[0])
smali = dd.disasm_method('Lcom/example/Foo;', 'onCreate')
print(smali)
```

Covers all 17 DEX formats: `10x`, `10t`, `11x`, `11n`, `12x`, `20t`, `21c`, `21h`, `21s`, `21t`, `22b`, `22c`, `22s`, `22t`, `22x`, `23x`, `30t`, `31c`, `31i`, `31t`, `32x`, `35c`, `3rc`, `45cc`, `4rcc`, `51l`. Unknown opcodes emit `data-XX` and advance one code unit so decoding continues past data payloads.

---

## DEXLifter

**File:** `ablation/analyzers/dex_lifter.py`

Lifts DEX bytecode to pseudo-Java IR without external dependencies or SSA construction.

```python
from ablation.analyzers.dex_lifter import DEXLifter

lifter = DEXLifter(dexes[0])
pseudo_java = lifter.lift_method('Lcom/thingclips/smart/sdk/ThingNfcPlugin;', 'findDeviceKeys')
print(pseudo_java)
```

### What the lifter translates

| DEX bytecode | Pseudo-Java output |
|---|---|
| `const-string v0, "uid"` | `String v0 = "uid";` |
| `iget-object v0, v1, Lf/Bar;->mField:Ljava/lang/String;` | `String v0 = v1.mField;` |
| `invoke-virtual {v0, v1}, Landroid/widget/TV;->setText(I)V` | `v0.setText(v1);` |
| `invoke-static + move-result-object vA` | `RetType vA = ClassName.method(args);` |
| `if-eqz v0,:L000a` | `if (v0 == null) goto:L000a;` |
| backward `goto:L0000` | `// loop end →:L0000` |

---

## LibraryInventory

**File:** `ablation/analyzers/library_inventory.py`

Batch triage scanner for directories of native ELF `.so` files. Returns a scored summary table for every library in one call.

### ARM64 internal function count

`internal` is the count of BL-call targets inside `.text` that are not in the dynamic export table. This measures implementation depth. A library with `internal=0` is a pure passthrough stub. One with `internal=4553` contains a protocol engine. Computed via single-pass opcode scan: `(w >> 26) == 0x25` identifies BL instructions; sign-extend the 26-bit immediate; targets in `.text` range but absent from dynsym are internal.

### Security scoring

| Signal | Points |
|---|---|
| Credential-field format string `sk=%s`, `password=%s`, and `token=%s` | +3 |
| Credential-field name or exec pattern `system(` and `/bin/sh` | +2 |
| Crypto primitive string `AES`, `HMAC`, `SHA256`, and `DTLS` | +1 |
| JNI count >= 50 | +2 |
| JNI count >= 10 | +1 |
| Internal function count >= 1000 | +2 |
| `SSL_CTX_set_keylog_callback` in symbols | +3 |
| `bytehook_hook_all` or `bytehook_hook_single` in PLT | +2 |

```python
from ablation.analyzers.library_inventory import LibraryInventory

inv = LibraryInventory.from_dir('/tmp/target/lib/arm64-v8a/')
entries = inv.scan()
print(LibraryInventory.report(entries))

for e in LibraryInventory.security_entries(entries, min_score=3):
    print(LibraryInventory.report_strings(e))
```

---

## How it works

`APKParser` opens the APK as a `zipfile.ZipFile` and parses `AndroidManifest.xml` from the binary AXML chunk format (chunk type `0x0003`). DEX files are parsed via `DEXFile`: the 112-byte header yields offsets to seven flat ID tables string_ids, type_ids, proto_ids, field_ids, method_ids, class_defs, data. `DexAnalyzer.scan()` iterates all `classes*.dex` files in the APK and matches the full string pool against 12 secret regex patterns and the method reference table against a dangerous class/method list. `JniBridgeScanner.scan()` cross-references DEX `ACC_NATIVE` flags with ELF dynsym exports from bundled `.so` files. `BinderScanner.scan()` identifies `android.os.Binder` subclasses, `$Stub` AIDL classes, and `onTransact()` overrides from class_defs and the manifest.

---

## Example output

```
DexAnalyzer report:
[CRITICAL] manifest/debuggable: Application is debuggable
  source:   manifest
  detail:   android:debuggable=true allows ADB debugging on any device

[CRITICAL] secret/aws_key: AWS access key found in DEX string pool
  source:   dex:classes.dex
  evidence: AKIAIOSFODNN7EXAMPLE

[HIGH    ] api/js_interface: addJavascriptInterface detected
  source:   dex:classes2.dex
  evidence: Landroid/webkit/WebView;->addJavascriptInterface(...)

JniBridgeScanner report:
[HIGH] jni/dynamic_registration
  3 lib(s) use RegisterNatives (JNI_OnLoad present)
  libnative.so libencode.so libauth.so

BinderScanner report:
[HIGH] binder/raw_transact
  com.vendor.sdk.AdminService overrides onTransact without permission check
```

---

## False positives

**DEX string pool includes documentation strings and error messages.** `Runtime.exec`, `DES`, and `MD5` appear in diagnostic log strings and exception message templates compiled into DEX. `DexAnalyzer` flags these on the string match: use `iter_method_refs()` to confirm the corresponding `Runtime.exec()` or `Cipher.getInstance("DES")` call is present before escalating.

**`generic_secret` matches template placeholder values.** Strings like `"secret=YOUR_SECRET_HERE"` or `"api_key=<replace>"` trigger the pattern. The `evidence` field exposes the raw string: discard matches under 16 characters or containing obvious placeholder text.

**ProGuard-obfuscated APKs produce incomplete method reference graphs.** On heavily obfuscated APKs, class and method names are single letters. String pool scanning and dangerous API detection remain effective; class-name-based analysis exported component names and Binder service class lookup is unreliable. Cross-reference findings with `DexDisasm` output at the method level.

---

## Pipeline position

**Before this module:** Confirm the target binary format APK, `.mpy`, BEAM, and Go ELF before loading. `BinaryContext` is not required for all runtime analyzers.

**After this module:** Feed dangerous call findings to `TaintTracker` or `FindingRegistry` for confirmed findings.

---

## Reading findings

Each layer returns typed finding objects. `DexAnalyzer(apk).scan()` returns `List[DexFinding]`:

| Attribute | Content |
|:---|:---|
| `severity` | `'CRITICAL'` / `'HIGH'` / `'MEDIUM'` / `'LOW'` |
| `category` | Finding category such as `'manifest/debuggable'`, `'api/js_interface'`, and `'secret/aws_key'` |
| `title` | Short description of the finding |
| `detail` | Extended explanation |
| `source` | `'manifest'`, `'dex:classes.dex'`, `'native'` |
| `evidence` | Raw string or API call that triggered the finding |

`JniBridgeScanner(apk).scan()` returns `List[JniBridgeFinding]`. `BinderScanner(apk).scan()` returns `List[BinderFinding]`. Both share the same field structure: `severity`, `category`, `title`, `detail`. `APKParser` returns metadata no findings.

---

## See also

- [BinaryContext](binary-context.md): native binary context when the runtime wraps a native library
- [TaintAnalysis](taint-analysis.md): trace dangerous calls found in the runtime layer
- [FindingRegistry](registry.md): record confirmed findings
