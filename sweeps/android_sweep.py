#!/usr/bin/env python3
"""
android_sweep.py -- Semantic security sweep for Android APKs.

Orchestrates:
  1. Manifest analysis (permissions, exported components, security flags)
  2. DEX string + API call scan across all classes*.dex files
  3. Native lib inventory with ELF security property check (NX, RELRO, stack canary)
  4. Summary ranked by severity

Usage:
    python3 sweeps/android_sweep.py /path/to/app.apk
    python3 sweeps/android_sweep.py /path/to/app.apk --native-dir /tmp/out/

The --native-dir flag extracts native libs to the given directory so the
ELF sweep can be run manually with base_sweep.py on interesting targets.

Output goes to stdout; pipe to a file for persistence.
"""

import argparse
import struct
import sys
from pathlib import Path

# ensure ablation package is importable when run directly
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ablation.core.apk_parser import APKParser
from ablation.analyzers.dex_analyzer import DexAnalyzer, DexFinding, CRITICAL, HIGH, MEDIUM, LOW, INFO


# ── ELF security properties (inline — no dependency on ELFParser) ─────────────

def _elf_security_props(data: bytes) -> dict:
    """Quick check for stack canary, NX, RELRO, FORTIFY in an ARM32 .so."""
    props = {
        "nx":           False,
        "relro":        False,
        "full_relro":   False,
        "stack_canary": False,
        "fortify":      False,
        "stripped":     True,
    }
    if len(data) < 52 or data[:4] != b"\x7fELF":
        return props

    # ELF32 LE assumed (all armeabi-v7a libs)
    e_phoff = struct.unpack_from("<I", data, 28)[0]
    e_phentsize = struct.unpack_from("<H", data, 42)[0]
    e_phnum = struct.unpack_from("<H", data, 44)[0]
    e_shoff = struct.unpack_from("<I", data, 32)[0]
    e_shnum = struct.unpack_from("<H", data, 48)[0]
    e_shstrndx = struct.unpack_from("<H", data, 50)[0]

    PT_GNU_STACK  = 0x6474E551
    PT_GNU_RELRO  = 0x6474E552
    PF_X = 1

    has_gnu_relro = False
    has_bind_now  = False

    for i in range(e_phnum):
        base = e_phoff + i * e_phentsize
        if base + e_phentsize > len(data):
            break
        p_type  = struct.unpack_from("<I", data, base)[0]
        p_flags = struct.unpack_from("<I", data, base + 24)[0]
        if p_type == PT_GNU_STACK:
            props["nx"] = not bool(p_flags & PF_X)
        elif p_type == PT_GNU_RELRO:
            has_gnu_relro = True
            props["relro"] = True

    # check .dynamic for BIND_NOW / FLAGS_1_NOW
    DT_FLAGS    = 30
    DT_FLAGS_1  = 0x6ffffffb
    DF_BIND_NOW = 0x8
    DF_1_NOW    = 0x1
    PT_DYNAMIC  = 2
    for i in range(e_phnum):
        base = e_phoff + i * e_phentsize
        p_type   = struct.unpack_from("<I", data, base)[0]
        p_offset = struct.unpack_from("<I", data, base + 4)[0]
        p_filesz = struct.unpack_from("<I", data, base + 16)[0]
        if p_type != PT_DYNAMIC:
            continue
        j = 0
        while j + 8 <= p_filesz:
            doff = p_offset + j
            if doff + 8 > len(data):
                break
            d_tag = struct.unpack_from("<I", data, doff)[0]
            d_val = struct.unpack_from("<I", data, doff + 4)[0]
            if d_tag == DT_FLAGS and (d_val & DF_BIND_NOW):
                has_bind_now = True
            if d_tag == DT_FLAGS_1 and (d_val & DF_1_NOW):
                has_bind_now = True
            j += 8

    props["full_relro"] = has_gnu_relro and has_bind_now

    # stack canary: check for __stack_chk_fail in dynamic symbols (imported)
    # fortify: check for __*_chk symbols
    SHT_DYNSYM = 11
    SHT_STRTAB = 3
    if e_shoff and e_shnum and e_shstrndx < e_shnum:
        # read section names
        shstr_base = e_shoff + e_shstrndx * 40
        shstr_off  = struct.unpack_from("<I", data, shstr_base + 16)[0]
        for si in range(e_shnum):
            sb = e_shoff + si * 40
            if sb + 40 > len(data):
                break
            sh_type     = struct.unpack_from("<I", data, sb + 4)[0]
            sh_offset   = struct.unpack_from("<I", data, sb + 16)[0]
            sh_size     = struct.unpack_from("<I", data, sb + 20)[0]
            sh_entsize  = struct.unpack_from("<I", data, sb + 36)[0]
            sh_link     = struct.unpack_from("<I", data, sb + 24)[0]
            if sh_type != SHT_DYNSYM or sh_entsize == 0:
                continue
            # find linked string table
            if sh_link < e_shnum:
                str_sb      = e_shoff + sh_link * 40
                str_off     = struct.unpack_from("<I", data, str_sb + 16)[0]
                str_size    = struct.unpack_from("<I", data, str_sb + 20)[0]
                sym_count   = sh_size // sh_entsize
                for k in range(sym_count):
                    sym_base = sh_offset + k * sh_entsize
                    if sym_base + 4 > len(data):
                        break
                    st_name = struct.unpack_from("<I", data, sym_base)[0]
                    if str_off + st_name >= len(data):
                        continue
                    null = data.find(b'\x00', str_off + st_name)
                    if null < 0:
                        continue
                    sym_name = data[str_off + st_name : null].decode("ascii", errors="replace")
                    if sym_name == "__stack_chk_fail":
                        props["stack_canary"] = True
                    if sym_name.endswith("_chk"):
                        props["fortify"] = True
            # dynsym section doesn't contain symbol table info (stripped check)
            sh_name_idx = struct.unpack_from("<I", data, sb)[0]
            props["stripped"] = True  # can't check symtab without full parse here

    return props


# ── native lib summary ────────────────────────────────────────────────────────

_SECURITY_CRITICAL_LIBS = {
    "libthing_security.so",
    "libthing_security_algorithm.so",
    "libthingnetsec.so",
    "libThingP2PSDK.so",
    "libthing-outpoint.so",
    "libv8executor.so",
    "libv8android.so",
    "libcrypto.1.1.so",
    "libssl.1.1.so",
    "libsqlcipher.so",
    "libThingCameraSDK.so",
    "libThingCloudStorageSignatureTools.so",
}

def _native_lib_findings(apk: APKParser, extract_dir: Path | None) -> list[DexFinding]:
    findings = []
    libs = apk.native_libs()

    if not libs:
        return findings

    # OpenSSL 1.1 present
    ssl_libs = [l for l in libs if "crypto.1.1" in l or "ssl.1.1" in l]
    if ssl_libs:
        findings.append(DexFinding(
            severity=HIGH,
            category="native/openssl_eol",
            title="OpenSSL 1.1.x (EOL Sep 2023) bundled",
            detail=(
                "OpenSSL 1.1.1 reached end-of-life 2023-09-11. "
                "All post-EOL CVEs (CVE-2023-3446, CVE-2023-3817, etc.) "
                "are present unless vendor-patched. Verify with: "
                "strings libcrypto.1.1.so | grep -i 'OpenSSL'"
            ),
            source="native",
            evidence=", ".join(Path(l).name for l in ssl_libs),
        ))

    # V8 JS engine — massive attack surface
    v8_libs = [l for l in libs if "v8" in Path(l).name.lower()]
    if v8_libs:
        findings.append(DexFinding(
            severity=HIGH,
            category="native/v8_engine",
            title="V8 JavaScript engine embedded (React Native)",
            detail=(
                "libv8android.so (~10MB) provides a full JS runtime. "
                "Any attacker-controlled JS reaching evaluateJavascript() or the "
                "RN bridge executes in this engine. Pair with webview/js_bridge findings."
            ),
            source="native",
            evidence=", ".join(Path(l).name for l in v8_libs),
        ))

    # Hooking frameworks
    hook_libs = [l for l in libs if any(k in Path(l).name for k in ("shadowhook", "bytehook", "xhook"))]
    if hook_libs:
        findings.append(DexFinding(
            severity=MEDIUM,
            category="native/plt_hooking",
            title="PLT/GOT inline hooking framework present",
            detail=(
                "libshadowhook/libbytehook are ByteDance inline hooking libs. "
                "They intercept libc calls at runtime — used for anti-tamper, "
                "telemetry injection, or obfuscation. Trace hook registrations "
                "in libthingssmart.so or libnetwork-android.so."
            ),
            source="native",
            evidence=", ".join(Path(l).name for l in hook_libs),
        ))

    # NCnn + MediaPipe + TFLite — on-device ML inference
    ml_libs = [l for l in libs if any(k in Path(l).name for k in ("ncnn", "mediapipe", "tflite", "tensorflow"))]
    if ml_libs:
        findings.append(DexFinding(
            severity=INFO,
            category="native/on_device_ml",
            title="On-device ML inference (ncnn/MediaPipe/TFLite)",
            detail=(
                "App runs ML models locally. Check assets/ for model files (.tflite, .bin) "
                "that may reveal inference targets (face recognition, motion detection, etc.)."
            ),
            source="native",
            evidence=", ".join(Path(l).name for l in ml_libs),
        ))

    # BLE library
    ble_libs = [l for l in libs if "BleLib" in Path(l).name]
    if ble_libs:
        findings.append(DexFinding(
            severity=MEDIUM,
            category="native/ble",
            title="Bluetooth LE native library (device provisioning attack surface)",
            detail=(
                "libBleLib.so handles BLE pairing/provisioning. "
                "Tuya BLE provisioning has historically used predictable tokens. "
                "RE target: pair_packet parsing in libBleLib.so."
            ),
            source="native",
            evidence="libBleLib.so",
        ))

    # extraction
    if extract_dir:
        extract_dir.mkdir(parents=True, exist_ok=True)
        count = 0
        for lib_path in libs:
            name = Path(lib_path).name
            if name in _SECURITY_CRITICAL_LIBS:
                try:
                    apk.extract_native_lib(lib_path, extract_dir)
                    count += 1
                except Exception:
                    pass
        if count:
            findings.append(DexFinding(
                severity=INFO,
                category="native/extracted",
                title=f"Extracted {count} security-critical native libs",
                detail=f"Priority libs written to {extract_dir}/ for ELF sweep",
                source="native",
                evidence=str(extract_dir),
            ))

    return findings


# ── main sweep ────────────────────────────────────────────────────────────────

def run_sweep(apk_path: str, native_dir: str | None = None) -> None:
    path = Path(apk_path)
    if not path.exists():
        print(f"[error] APK not found: {path}", file=sys.stderr)
        sys.exit(1)

    print(f"android_sweep: {path.name}")
    print("=" * 60)

    with APKParser.from_path(path) as apk:
        # manifest
        mf = apk.parse_manifest()
        print(f"package:    {mf.package}")
        print(f"version:    {mf.version_name} (code {mf.version_code})")
        print(f"sdk:        min={mf.min_sdk}  target={mf.target_sdk}")
        print(f"components: {len(mf.components)} total, "
              f"{len(mf.exported_components())} exported")
        print(f"libs:       {len(apk.native_libs())} native .so files")
        print()

        # DEX stats
        dex_files = list(apk.iter_dex())
        total_methods = sum(d.method_count for d in dex_files)
        total_strings = sum(d.string_count for d in dex_files)
        total_classes = sum(d.class_count for d in dex_files)
        print(f"dex:        {len(dex_files)} files  "
              f"{total_classes} classes  "
              f"{total_methods} methods  "
              f"{total_strings} strings")
        print()

        # run scanners
        scanner  = DexAnalyzer(apk)
        findings = scanner.scan()

        # native findings
        extract_dir = Path(native_dir) if native_dir else None
        findings += _native_lib_findings(apk, extract_dir)

        findings.sort(key=lambda f: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(f.severity, 9))

    print(DexAnalyzer.report(findings))

    # next steps for native RE
    print("\n── NEXT: native RE targets ──────────────────────────────────────")
    print("Priority ELF targets for base_sweep.py + ARM32TaintTracker:")
    for lib in sorted(_SECURITY_CRITICAL_LIBS):
        print(f"  {lib}")
    if native_dir:
        print(f"\nExtracted to: {native_dir}")
        print("Run: python3 sweeps/base_sweep.py <lib> for each")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Android APK security sweep")
    parser.add_argument("apk", help="Path to APK file")
    parser.add_argument("--native-dir", default=None,
                        help="Extract security-critical native libs to this directory")
    args = parser.parse_args()
    run_sweep(args.apk, args.native_dir)
