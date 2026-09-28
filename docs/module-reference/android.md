# Android / APK Analysis

Zero-dependency analysis for Android APK files. No androguard, no apktool, no
jadx — pure Python stdlib. Works on raw `.apk` files and APKPure `.xapk` containers.

Three layers: **APKParser** (ZIP + AXML + DEX format), **DexAnalyzer** (security
scanner over DEX bytecode), **JniBridgeScanner** (JNI bridge RE), **BinderScanner**
(exported Binder service surface).

---

## APKParser

**File:** `ablation/core/apk_parser.py`

Handles the full APK/XAPK container format down to the binary XML and DEX
flat-table sections.

### Construction

```python
from ablation.core.apk_parser import APKParser

# Context manager (preferred — closes the ZIP automatically)
with APKParser.from_path('/path/to/app.apk') as apk:
    mf = apk.parse_manifest()
    print(mf.package, mf.version_name, mf.version_code)
```

XAPK containers are supported: the parser transparently unpacks the inner
`base.apk` when the outer ZIP does not contain `AndroidManifest.xml` directly.

### Manifest

```python
mf = apk.parse_manifest()

# Basic identity
mf.package             # "com.example.app"
mf.version_name        # "1.2.3"
mf.version_code        # 42
mf.min_sdk             # 24
mf.target_sdk          # 34

# Permissions
mf.permissions         # requested: ["android.permission.CAMERA", ...]
mf.declared_permissions  # app-defined custom permissions
mf.dangerous_permissions()  # filtered to DANGEROUS-level perms only

# Components (Activity, Service, Receiver, Provider)
mf.components          # all ComponentInfo objects
mf.exported_components()  # only exported=true components

# Security flags
mf.debuggable          # True → APK debuggable (not production build)
mf.allow_backup        # True → adb backup allowed (data exfil)
mf.uses_cleartext_traffic  # True → HTTP allowed
```

### DEX iteration

```python
for dex in apk.iter_dex():
    print(dex.filename, dex.method_count, 'methods', dex.string_count, 'strings')

    # Strings (all — use for secret scanning)
    for s in dex.iter_strings():
        if s.startswith('AKIA'):
            print('AWS key:', s)

    # Method references (all cross-class calls in this DEX)
    for m in dex.iter_method_refs():
        # m.class_name: descriptor form, e.g. "Landroid/util/Log;"
        # m.method_name: "d", "e", "i", "w", "v"
        # m.proto_shorty: return+args type string, e.g. "VLjava/lang/String;"
        if 'loadLibrary' in m.method_name:
            print('native lib load:', m)

    # Field references
    for f in dex.iter_field_refs():
        # f.class_name, f.field_name, f.type_desc
        if f.type_desc == 'J' and 'peer' in f.field_name.lower():
            print('opaque peer field:', f)

    # Class definitions
    for cls in dex.iter_classes():
        # cls.class_name, cls.superclass, cls.access_flags, cls.source_file
        if 'Service' in cls.superclass:
            print('Service subclass:', cls.class_name)
```

### Native libs

```python
# All native libs (entry paths within the APK ZIP)
libs = apk.native_libs()         # all ABIs
libs = apk.native_libs('armeabi-v7a')  # filter to one ABI

# Extract a specific lib (returns destination path)
dest = apk.extract_native_lib('lib/armeabi-v7a/libfoo.so', Path('/tmp/out/'))
```

### AXML binary format notes

Android binary XML uses a chunk-based layout. The critical offset fix: in
`ResXMLTree_attrExt`, the `attributeStart` field is relative to the start of
the `ResXMLTree_attrExt` struct (which begins at `body+8`), not relative to
the chunk body start. Using `attr_base = body + _attr_start` instead of
`attr_base = body + 8 + _attr_start` silently reads garbage attribute data.

---

## DexAnalyzer

**File:** `ablation/analyzers/dex_analyzer.py`

Security scanner over DEX string pool and method reference table. Runs on the
full APK (iterates all `classes*.dex` files).

### Usage

```python
from ablation.analyzers.dex_analyzer import DexAnalyzer

with APKParser.from_path('/path/to/app.apk') as apk:
    scanner = DexAnalyzer(apk)
    findings = scanner.scan()
    print(DexAnalyzer.report(findings))

# From path directly
scanner = DexAnalyzer.from_path('/path/to/app.apk')
findings = scanner.scan()
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
| MEDIUM | `secret/hex_key_32` | 64-char hex string |
| LOW | `manifest/permission_N` | dangerous permission count |

### Extending with custom patterns

```python
scanner._secret_patterns.append(
    ('my_api_key', re.compile(r'sk-[A-Za-z0-9]{32}'), HIGH)
)
scanner._dangerous_apis['myDangerousMethod'] = (CRITICAL, "custom/sink", "Description")
```

---

## JniBridgeScanner

**File:** `ablation/analyzers/jni_bridge_scanner.py`

Reconstructs the Java ↔ native boundary from DEX `class_data_item` access flags
and ELF dynsym. Three-way classification: methods confirmed native in both DEX and
ELF (strongly confirmed), methods with `ACC_NATIVE` but no ELF symbol (stripped or
dynamically registered), and ELF `Java_*` symbols with no `ACC_NATIVE` flag (helpers
or dead code).

**DEX side:**
- `iter_native_methods()` over `class_data_item` encoded_method arrays — authoritative
  `ACC_NATIVE` (`0x0100`) flag detection
- `Ljava/lang/System;->loadLibrary` method reference → identifies which classes
  load native libraries
- `FieldRef` with type descriptor `J` (long) and a peer-like name → opaque peer
  pattern (Java object holds native pointer in a `long` field, set by native code
  via `GetFieldID`/`SetLongField`)

**ELF side (native lib dynsym):**
- `JNI_OnLoad` export present → library uses `RegisterNatives` for dynamic
  registration; canonical `Java_*` symbol names will NOT appear; this is the
  harder-to-RE path
- `Java_*` exports → canonical naming; symbol names directly encode the Java
  class and method name

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
| HIGH | `jni/dynamic_registration` | Lib uses `JNI_OnLoad`+`RegisterNatives`; function pointers not in symbol table |
| MEDIUM | `jni/canonical_naming` | Lib exports `Java_*` symbols; naming is recoverable |
| HIGH | `jni/opaque_peer` | Class has `long` field with peer-like name; native holds raw pointer |
| INFO | `jni/load_sites` | Count of `System.loadLibrary` call sites |

### Why JNI_OnLoad matters for RE

The canonical `Java_pkg_ClassName_methodName` naming scheme is automatically
resolved by ART. When a library instead implements `JNI_OnLoad` and calls
`env->RegisterNatives(klass, methods, count)`, the function pointers in the
`JNINativeMethod` array can have arbitrary names — or be stripped entirely.
`ARM32TaintTracker` must start from `JNI_OnLoad` and walk the `RegisterNatives`
call's third argument (the array) to recover the Java↔native mapping.

---

## BinderScanner

**File:** `ablation/analyzers/binder_scanner.py`

Maps the exported Binder service surface from DEX class definitions and the
manifest. Binder is Android's primary IPC mechanism; exported services are the
first-hop attack surface for privilege escalation and authentication bypass.

### What it detects

**Service subclasses** — Any class extending `android.app.Service` or
`android.app.IntentService` is a potential Binder server if it implements
`onBind()`. Cross-referenced against the manifest to flag exported=true entries.

**Raw Binder implementations** — Classes directly extending `android.os.Binder`
and overriding `onTransact(int code, Parcel data, Parcel reply, int flags)`.
This is the lowest-level Binder API; `onTransact` receives an integer transaction
code and a raw `Parcel` — missing authentication checks here are critical.

**AIDL Stub classes** — Inner classes named `$Stub` extending `android.os.Binder`
are generated by the AIDL compiler. They dispatch on transaction codes
(starting at `FIRST_CALL_TRANSACTION = 1`). The outer interface name encodes
the service contract.

**Messenger-based IPC** — `android.os.Messenger` wraps a `Handler` behind a
Binder, used for message-passing. Lower attack surface than raw Binder but still
an IPC entry point.

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
| HIGH | `binder/exported_service` | Service exported=true in manifest; accepts binds from other apps |
| HIGH | `binder/raw_transact` | Class overrides `onTransact`; manual dispatch; missing auth check risk |
| MEDIUM | `binder/aidl_stub` | AIDL-generated `$Stub` class; dispatch by integer transaction code |
| MEDIUM | `binder/service_subclass` | Service subclass; potential Binder server |
| INFO | `binder/messenger` | Messenger IPC usage |

### Binder transaction code attack surface

AIDL stubs dispatch on integer transaction codes in `onTransact`. The first
method in the AIDL interface maps to code `1`, second to `2`, etc. Fuzzing
transaction codes (especially codes beyond the defined range) often triggers
unguarded paths. Each `$Stub` class found is a candidate for code enumeration.

---

## android_sweep.py

**File:** `sweeps/android_sweep.py`

Orchestration script that runs the full APK RE pass in one call: manifest
analysis, DexAnalyzer, JniBridgeScanner, BinderScanner, and native lib ELF
security properties.

### Usage

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

XAPK containers are handled transparently — pass the `.xapk` file directly.
All scanner output is printed in order: manifest summary, CRITICAL/HIGH/MEDIUM
findings across all scanners, native lib security summary.

---

## DEXDisasm

**File:** `ablation/analyzers/dex_disasm.py`

Disassembles DEX bytecode to smali-style text. Covers all 17 DEX instruction
formats and annotates every reference with the full descriptor from the DEX flat
tables: method signatures, field types, class names, and string literals.

### Construction

```python
from ablation.core.apk_parser import APKParser
from ablation.analyzers.dex_disasm import DEXDisasm

with APKParser.from_path('/path/to/app.apk') as apk:
    dexes = list(apk.iter_dex())

dd = DEXDisasm(dexes[0])
```

### Disassemble one method

```python
# Both descriptor form and dotted Java form are accepted
smali = dd.disasm_method('Lcom/example/Foo;', 'onCreate')
print(smali)

# Output:
# .method Lcom/example/Foo;->onCreate
#     .registers 4
#
#     0000  const/4 v0, #0
#     0001  invoke-virtual {v1, v0}, Landroid/widget/TextView;->setText(I)V
#     0004  return-void
# .end method
```

### Disassemble a full class

```python
smali = dd.disasm_class('Lcom/example/Foo;')
print(smali)
```

### List methods with code

```python
methods = dd.list_methods('Lcom/example/Foo;')
# Returns sorted list of method names that have a code_item
```

### One-call convenience

```python
smali = DEXDisasm.report(dex, 'Lcom/example/Foo;', 'authenticate')
```

### DEXInstruction fields

| Field | Type | Meaning |
|---|---|---|
| `cu_offset` | int | Code unit offset from start of `insns[]` |
| `opcode` | int | Raw opcode byte |
| `mnemonic` | str | Smali mnemonic (e.g., `invoke-virtual`) |
| `fmt` | str | DEX format string (e.g., `35c`) |
| `regs` | List[int] | Register indices |
| `ref_idx` | int | DEX table index (-1 if none) |
| `literal` | int | Literal value |
| `branch` | int | Branch offset in code units (relative) |

### Low-level: decode a code_item directly

```python
from ablation.analyzers.dex_disasm import decode_code_item

registers, ins_size, outs_size, instrs = decode_code_item(dex, code_off)
for ins in instrs:
    print(f"{ins.cu_offset:04x}  {ins.smali(dex)}")
```

### Instruction formats decoded

All 17 DEX formats: `10x`, `10t`, `11x`, `11n`, `12x`, `20t`, `21c`, `21h`,
`21s`, `21t`, `22b`, `22c`, `22s`, `22t`, `22x`, `23x`, `30t`, `31c`, `31i`,
`31t`, `32x`, `35c`, `3rc`, `45cc`, `4rcc`, `51l`. Unknown opcodes emit
`data-XX` and advance one code unit so decoding continues past data payloads.

### Limitations

- `fill-array-data`, `packed-switch`, and `sparse-switch` payloads are data
  blocks embedded in the instruction stream. The disassembler skips their
  content but prints the branch target label correctly.
- Try/catch blocks and annotation tables are not rendered (code_item header
  fields `tries_size` and `debug_info_off` are parsed but not displayed).

---

## DEXLifter

**File:** `ablation/analyzers/dex_lifter.py`

Lifts DEX bytecode to pseudo-Java IR. Produces readable Java-like source from
the instruction stream without external dependencies or SSA construction.

### Construction

```python
from ablation.core.apk_parser import APKParser
from ablation.analyzers.dex_lifter import DEXLifter

with APKParser.from_path('/path/to/app.apk') as apk:
    dexes = list(apk.iter_dex())

lifter = DEXLifter(dexes[0])
```

### Lift one method

```python
pseudo_java = lifter.lift_method('Lcom/thingclips/smart/sdk/ThingNfcPlugin;', 'findDeviceKeys')
print(pseudo_java)
```

Output (abbreviated):
```java
// com.thingclips.smart.sdk.ThingNfcPlugin.findDeviceKeys
DeviceKeys findDeviceKeys(String p1, String p2) {
    // registers=5  params=3  outs=3
    Intrinsics.checkNotNullParameter(p1, "uid");
    Intrinsics.checkNotNullParameter(p2, "devId");
    qbdqpqq v1 = this.getManagerOrThrow();
    DeviceKeys p1 = v1.findDeviceKeys(p1, p2);
    return p1;
}
```

### Lift a whole class

```python
pseudo_java = lifter.lift_class('Lcom/example/Foo;')
```

### One-call convenience

```python
pseudo_java = DEXLifter.report(dex, 'Lcom/example/Foo;', 'methodName')
```

### What the lifter translates

| DEX bytecode | Pseudo-Java output |
|---|---|
| `const-string v0, "uid"` | `String v0 = "uid";` |
| `iget-object v0, v1, Lf/Bar;->mField:Ljava/lang/String;` | `String v0 = v1.mField;` |
| `invoke-virtual {v0, v1}, Landroid/widget/TV;->setText(I)V` | `v0.setText(v1);` |
| `invoke-static + move-result-object vA` | `RetType vA = ClassName.method(args);` |
| `new-instance v0, Ljava/lang/StringBuilder;` | `StringBuilder v0;  // <init> call follows` |
| `if-eqz v0, :L000a` | `if (v0 == null) goto :L000a;` |
| backward `goto :L0000` | `// ↑ back-edge → :L0000  (loop end)` |
| `check-cast v0, Ljava/util/Map;` | `Map v0 = (Map) v0;` |
| `sget-object v0, Lfoo/Bar;->TAG:Ljava/lang/String;` | `String v0 = Bar.TAG;` |

### Limitations

- No full SSA or dominator-tree analysis — if/else blocks show as `if (cond) goto :Lxxx`
  labels rather than structured braces. Sufficient for reading control flow.
- `new-instance` + `invoke-direct <init>` is shown as two lines; constructor
  arguments appear on the `<init>` call comment line, not on the `new T()` line.
- Switch tables (`packed-switch`, `sparse-switch`) show the switch expression
  and a reference to the payload offset but not the individual case values.
- Try/catch blocks and exception handlers are not structurally represented
  (exception registers still appear via `move-exception`).
- Obfuscator instrumentation (e.g. ByteDance `Tz.a()/Tz.b()` anti-tamper
  calls) is rendered as-is — which is itself a finding: heavy wrapping around
  simple logic is a pattern signature for the ByteDance runtime protection.
