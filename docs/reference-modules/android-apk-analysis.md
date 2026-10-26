# Android / APK Analysis

Parse APK containers, decode Android binary XML manifests (AXML), iterate DEX class/method tables, enumerate `ACC_NATIVE` methods and bundled native libraries, then scan all DEX string pools and method reference tables for hardcoded secrets, dangerous API usage, weak cryptography, cleartext traffic, and unprotected exported components: with no external dependencies.

---

## Why this exists

1. **Android apps ship as ZIP containers with binary-encoded manifests and multi-DEX class databases.** The `AndroidManifest.xml` inside an APK is not text, it is AXML Android Binary XML, chunk type `0x0003` with a separate string pool, resource map, and compact attribute encoding. DEX files use ULEB128-encoded method, field, and class tables. Without a dedicated parser, analysts use `aapt`, `apktool`, or `jadx`: tools not available in automated pipelines and not integrated with the ablation scanner chain.

2. **Hardcoded credentials, API keys, and weak cipher choices live in DEX string pools and are not visible from manifest inspection alone.** The DEX string pool contains every string constant from the Java source: AWS `AKIA*` access keys, Firebase API keys, Tuya `appKey`/`appSecret`, JWT bearer tokens, PEM-encoded private keys, and hardcoded 16/32-byte hex keys all appear as strings. `DexAnalyzer` scans all `classes*.dex` string pools in a single pass and matches 12 secret patterns plus a database of dangerous class and method references.

3. **Native method inventory from DEX is the prerequisite for JNI bridge reconstruction.** `ACC_NATIVE` methods in DEX (`code_off == 0` in `class_data_item`) declare the JNI bridge boundary: Java code declares them, native `.so` files implement them. Identifying all native method declarations, the libraries they load (`System.loadLibrary`), and any opaque peer pointer fields (`long` fields with names matching `_PEER_NAMES`) feeds directly into `JniBridgeScanner` for the ELF-side analysis.

---

## How it works

```mermaid
flowchart TD
    A(["APKParser.from_path(apk_path)"]):::input --> B["Open APK as ZIP\n(zipfile.ZipFile)"]:::primary
    B:::primary --> C["parse_manifest(): read 'AndroidManifest.xml'\n_parse_axml(): chunk walk\nSTRING_POOL (0x0001) → string table UTF-8/UTF-16LE\nSTART_ELEMENT (0x0102) → attr name+value decode\nReturns XML element tree"]:::secondary
    C:::secondary --> D(["_build_manifest(tree) → ManifestInfo:\npackage, version_name/code, min_sdk, target_sdk\npermissions[], declared_permissions[]\ncomponents[]: activity/service/receiver/provider\ndebugable, allowBackup, usesCleartextTraffic"]):::output
    B:::primary --> E["iter_dex(): yield DEXFile for each classes*.dex\n_parse_dex(): header at offset 0\nendian check: 0x12345678\nParse 7 ID/def tables at fixed header offsets"]:::tertiary
    E:::tertiary --> F["DEXFile tables:\nstring_ids (u32[N] offsets) + ULEB128 strings\ntype_ids (u32[N] string_idx)\nproto_ids (u32[3] per entry: shorty, return_type, params)\nmethod_ids (u16 class_idx, u16 proto_idx, u32 name_idx)\nfield_ids (u16 class_idx, u16 type_idx, u32 name_idx)\nclass_defs (8×u32 per entry)"]:::tertiary
    F:::tertiary --> G(["iter_native_methods():\nFor each ClassDef with class_data_off != 0:\n_parse_class_data(): ULEB128 field counts\nDirect methods: running_idx reset to 0\nVirtual methods: running_idx reset to 0\nFor each method: idx_diff + flags + code_off\nACC_NATIVE (0x0100) + code_off==0 → yield NativeMethod"]):::output
    B:::primary --> H(["native_libs(abi='') → List[str]\nList 'lib/**/*.so' entries from ZIP\nFilter by ABI prefix: armeabi-v7a / arm64-v8a / x86 / x86_64"]):::output
    A2(["DexAnalyzer.from_path(apk_path)"]):::input --> I(["scan():\n1. _scan_manifest(mf): debuggable, cleartext, backup,\n   exported components (android:exported=True OR has intent-filter),\n   dangerous permissions, dangerous permission combos\n2. _scan_dex_strings(dex): all strings vs _SECRET_PATTERNS + _WEAK_CRYPTO_STRINGS\n3. _scan_dex_apis(dex): all method refs vs _DANGEROUS_CLASSES + _DANGEROUS_METHODS\nSort by _SEVERITY_RANK"]):::output
    classDef input     fill:#0d47a1,stroke:#1565c0,color:#fff
    classDef primary   fill:#e65100,stroke:#bf360c,color:#fff
    classDef secondary fill:#004d40,stroke:#00695c,color:#fff
    classDef tertiary  fill:#4a148c,stroke:#6a1b9a,color:#fff
    classDef neutral   fill:#37474f,stroke:#546e7a,color:#fff
    classDef output    fill:#1b5e20,stroke:#2e7d32,color:#fff
    linkStyle 0 stroke:#bf360c,stroke-width:2px
    linkStyle 1 stroke:#00695c,stroke-width:2px
    linkStyle 2 stroke:#2e7d32,stroke-width:3px
    linkStyle 3 stroke:#6a1b9a,stroke-width:2px
    linkStyle 4 stroke:#6a1b9a,stroke-width:2px
    linkStyle 5 stroke:#2e7d32,stroke-width:3px
    linkStyle 6 stroke:#2e7d32,stroke-width:3px
    linkStyle 7 stroke:#2e7d32,stroke-width:3px
```

### Dangerous class/method targets selected

| Class / Method | Category | Severity |
|---|---|---|
| `Ldalvik/system/InMemoryDexClassLoader;` | `dyn_load` | CRITICAL |
| `addJavascriptInterface` | `webview/js_bridge` | CRITICAL |
| `wipeData` | `device_admin/wipe` | CRITICAL |
| `SSLv3` string | `tls/SSLv3` | CRITICAL |
| `Ljava/lang/Runtime;` | `exec/Runtime` | HIGH |
| `Ljava/lang/ProcessBuilder;` | `exec/ProcessBuilder` | HIGH |
| `setJavaScriptEnabled` | `webview/js_enabled` | HIGH |
| AES/ECB string | `weak_mode/AES-ECB` | HIGH |
| `Landroid/webkit/WebView;` | `webview` | MEDIUM |
| `Ljava/lang/reflect/Method;` | `reflection` | MEDIUM |

### Secret patterns 12 entries, selected

| Pattern | Category |
|---|---|
| `AKIA[0-9A-Z]{16}` | `aws_access_key` |
| `AIza[0-9A-Za-z\-_]{35}` | `google_api_key` |
| `eyJ...eyJ...[sig]` | `jwt_bearer` |
| `-----BEGIN [RSA/EC] PRIVATE KEY-----` | `private_key_pem` |
| Tuya `appKey`/`appSecret` patterns | `tuya_app_key` / `tuya_app_secret` |
| `[0-9a-fA-F]{64}` 32-byte hex | `hex_key_32` |
| `secret=|password=|api_key=...{16,}` | `generic_secret` |

---

## Usage

```python
from ablation.core.apk_parser import APKParser
from ablation.analyzers.dex_analyzer import DexAnalyzer

# Manifest + component analysis
with APKParser.from_path('/tmp/TargetApp.apk') as apk:
    mf = apk.parse_manifest()
    print(f"Package: {mf.package}  ver={mf.version_name}  sdk={mf.min_sdk}–{mf.target_sdk}")
    print(f"Debuggable: {mf.debuggable}  AllowBackup: {mf.allow_backup}")
    print(f"Permissions: {len(mf.permissions)}  dangerous: {mf.dangerous_permissions()}")
    for comp in mf.exported_components():
        print(f"  EXPORTED {comp.tag}: {comp.name}  perm={comp.permission}")

    # Native library inventory
    libs = apk.native_libs()
    print(f"Native libs ({len(libs)}): {libs}")
    # Extract ARM64 libraries for BinaryContext load
    for lib in apk.native_libs(abi='arm64-v8a'):
        out = apk.extract_native_lib(lib, Path('/tmp/extracted/'))
        print(f"  Extracted: {out}")

    # DEX analysis: all classes and native methods
    for dex in apk.iter_dex():
        print(f"\n{dex.filename}: {dex.class_count} classes, {dex.method_count} methods")
        for nm in dex.iter_native_methods():
            print(f"  NATIVE: {nm.class_name}->{nm.method_name}({nm.proto_shorty})")
        # Crypto class references
        for ref in dex.iter_method_refs():
            if 'Cipher' in ref.class_name or 'KeySpec' in ref.class_name:
                print(f"  CRYPTO: {ref}")

# Full security scan
scanner = DexAnalyzer.from_path('/tmp/TargetApp.apk')
findings = scanner.scan()
print(DexAnalyzer.report(findings))

# Filter to critical findings only
critical = [f for f in findings if f.severity == 'CRITICAL']
for f in critical:
    print(f.fmt())
```

---

## Example output

```
Package: com.vendor.mobileconfig  ver=3.2.1  sdk=21–33
Debuggable: False  AllowBackup: True
Permissions: 18  dangerous: ['android.permission.READ_SMS', 'android.permission.ACCESS_FINE_LOCATION']
  EXPORTED activity: com.vendor.mobileconfig.DeepLinkActivity  perm=None
  EXPORTED receiver: com.vendor.mobileconfig.BootReceiver     perm=None

Native libs (4): ['lib/arm64-v8a/libnative.so', 'lib/arm64-v8a/libencode.so', ...]

classes.dex: 847 classes, 6241 methods
  NATIVE: Lcom/vendor/sdk/NativeSession;->init(Ljava/lang/String;)Z
  NATIVE: Lcom/vendor/sdk/NativeSession;->encrypt([B)[B

DexAnalyzer Findings:
[CRITICAL] dyn_load/InMemoryDexClassLoader: InMemoryDexClassLoader detected
  source:   dex:classes2.dex
  evidence: Ldalvik/system/InMemoryDexClassLoader;->(...

[CRITICAL] manifest/secret: AWS access key found in DEX string pool
  source:   dex:classes.dex
  evidence: AKIAIOSFODNN7EXAMPLE

[HIGH    ] manifest/debug: Application is debuggable
  source:   manifest
  detail:   android:debuggable=true allows ADB debugging on any device

[HIGH    ] webview/js_enabled: setJavaScriptEnabled called
  source:   dex:classes.dex

[HIGH    ] weak_cipher/DES: DES string found in DEX
  source:   dex:classes.dex  evidence: DES

Summary: CRITICAL=2, HIGH=5, MEDIUM=3, LOW=2, INFO=8
```

---

## False positives

**`allowBackup=True` finding on apps targeting API 31+.** As of Android 12 (API 31), `allowBackup=true` is the default but automatic cloud backup requires explicit `BackupAgent` configuration. On apps with `targetSdk >= 31` that do not implement `BackupAgent`, `adb backup` is blocked by default even with `allowBackup=true`. The finding is still accurate as a configuration observation: evaluate it in context of the `targetSdk` value.

**`generic_secret` matches variable assignments, not literal secret values.** The `generic_secret` pattern matches strings like `"secret=changeMe"` and `"api_key=YOUR_KEY_HERE"`: placeholder values from developer templates that are not actual credentials. Inspect the `evidence` field: any value under 16 characters or containing obvious placeholder text is not a real credential. Set the pattern minimum match length or add an entropy filter for production analysis.

**DEX string pool includes documentation and error messages.** DES, MD5, and SHA1 strings appear in crypto provider diagnostic strings, documentation comments compiled into the DEX, and error message templates. `weak_cipher/DES` and `weak_hash/MD5` findings require verification that the string appears in an API call argument, not a log message. Use `iter_method_refs()` to confirm the corresponding `Ljavax/crypto/Cipher;->getInstance()` call is present with that algorithm string.

---

## Pipeline position

**Before this module:** Confirm the file is a valid APK (ZIP magic at offset 0: `PK\x03\x04`). For APKs with split DEX multi-dex apps, `iter_dex()` automatically covers all `classes*.dex` files, no special handling needed.

**After this module:** Extract native libraries via `native_libs()` + `extract_native_lib()`, then run `JniBridgeScanner.from_path()` on the APK to correlate DEX `ACC_NATIVE` declarations with ELF JNI exports. For `InMemoryDexClassLoader` findings: capture the DEX bytes passed to the loader at runtime dynamic analysis: the loaded DEX is not present in the APK at static analysis time.

---

## Reading findings

| Field | Content |
|:---|:---|
| `mf.debuggable` | `True` = `android:debuggable` set in manifest |
| `mf.dangerous_permissions()` | Permissions matching the 28-entry dangerous-permissions set |
| `comp.is_exported_or_implicit()` | `True` if `android:exported=True` OR has `<intent-filter>` with no permission guard |
| `DexFinding.severity` | `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFO` |
| `DexFinding.category` | Dotted path: `manifest/debug`, `dyn_load/InMemoryDexClassLoader`, `tls/SSLv3`, etc. |
| `DexFinding.evidence` | The raw string, class reference, or component name that triggered the finding |
| `NativeMethod.has_code` | `True` = anomaly native + DEX code present: possible decompiler artifact |

---

## See also

- [JNI Bridge Reconstruction](jni-bridge-reconstruction.md): ELF-side JNI surface for native methods identified here
- [Architectural Risk Detection](architectural-risk-detection.md): source-level equivalent for server-side Java/Kotlin APIs
- [Android Binder Surface](android-binder-surface.md): Binder IPC attack surface complementary to exported component analysis
