#!/usr/bin/env python3
"""
jni_bridge_scanner.py -- JNI bridge surface scanner for Android APKs.

Reconstructs the Java<->native boundary using two orthogonal signals:

  DEX side:
    - System.loadLibrary call sites (MethodRef scan)
    - Opaque peer pattern: FieldRef type='J' with peer-like name
      (Java object holds native pointer set via GetFieldID/SetLongField)

  ELF side (native lib dynsym):
    - JNI_OnLoad exported  -> RegisterNatives dynamic registration
      (function pointers arbitrary; canonical Java_* names absent)
    - Java_* prefix exports -> canonical naming; class+method recoverable

Usage:
    from ablation.analyzers.jni_bridge_scanner import JniBridgeScanner

    scanner = JniBridgeScanner.from_path('/path/to/app.apk')
    findings = scanner.scan()
    print(JniBridgeScanner.report(findings))
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Set

from ablation.core.apk_parser import APKParser


# ── Severity constants ────────────────────────────────────────────────────────

HIGH   = "HIGH"
MEDIUM = "MEDIUM"
INFO   = "INFO"


# ── Peer field name heuristics ────────────────────────────────────────────────

_PEER_NAMES: Set[str] = {
    "peer", "mNativePtr", "mNativePeer", "nativeHandle", "nativePtr",
    "nativeObj", "mPtr", "mHandle", "mNativeContext", "nativeContext",
    "mNativeSurface", "nativeWindow", "mNativeWindow",
}


# ── JNI ELF dynsym scanner ────────────────────────────────────────────────────

def _scan_elf_jni(data: bytes) -> dict:
    """
    Inspect an ELF .so's dynamic symbol table for JNI registration signals.
    Returns dict with:
      jni_on_load: bool    - JNI_OnLoad export present
      java_exports: list   - Java_* exported symbol names
    """
    result: dict = {"jni_on_load": False, "java_exports": []}

    if len(data) < 52 or data[:4] != b"\x7fELF":
        return result

    ei_class = data[4]  # 1=ELF32, 2=ELF64
    ei_data  = data[5]  # 1=LE, 2=BE
    endian   = "<" if ei_data == 1 else ">"

    if ei_class == 1:  # ELF32
        e_shoff    = struct.unpack_from(endian + "I", data, 32)[0]
        e_shnum    = struct.unpack_from(endian + "H", data, 48)[0]
        e_shstrndx = struct.unpack_from(endian + "H", data, 50)[0]
        e_shentsize = struct.unpack_from(endian + "H", data, 46)[0]
        _parse_elf32_dynsym(data, endian, e_shoff, e_shnum, e_shstrndx, e_shentsize, result)
    elif ei_class == 2:  # ELF64
        e_shoff    = struct.unpack_from(endian + "Q", data, 40)[0]
        e_shnum    = struct.unpack_from(endian + "H", data, 60)[0]
        e_shstrndx = struct.unpack_from(endian + "H", data, 62)[0]
        e_shentsize = struct.unpack_from(endian + "H", data, 58)[0]
        _parse_elf64_dynsym(data, endian, e_shoff, e_shnum, e_shstrndx, e_shentsize, result)

    return result


def _read_sym_name(data: bytes, strtab_off: int, st_name: int) -> str:
    pos = strtab_off + st_name
    if pos >= len(data):
        return ""
    end = data.find(b'\x00', pos)
    if end < 0:
        return ""
    return data[pos:end].decode("ascii", errors="replace")


def _parse_elf32_dynsym(data, endian, shoff, shnum, shstrndx, shentsize, result):
    SHT_DYNSYM = 11
    for i in range(shnum):
        sb = shoff + i * shentsize
        if sb + shentsize > len(data):
            break
        sh_type   = struct.unpack_from(endian + "I", data, sb + 4)[0]
        sh_offset = struct.unpack_from(endian + "I", data, sb + 16)[0]
        sh_size   = struct.unpack_from(endian + "I", data, sb + 20)[0]
        sh_entsize = struct.unpack_from(endian + "I", data, sb + 36)[0]
        sh_link   = struct.unpack_from(endian + "I", data, sb + 24)[0]
        if sh_type != SHT_DYNSYM or sh_entsize == 0:
            continue
        if sh_link >= shnum:
            continue
        str_sb  = shoff + sh_link * shentsize
        str_off = struct.unpack_from(endian + "I", data, str_sb + 16)[0]
        count   = sh_size // sh_entsize
        for k in range(count):
            sym_base = sh_offset + k * sh_entsize
            if sym_base + 4 > len(data):
                break
            st_name = struct.unpack_from(endian + "I", data, sym_base)[0]
            name = _read_sym_name(data, str_off, st_name)
            _classify_jni_sym(name, result)


def _parse_elf64_dynsym(data, endian, shoff, shnum, shstrndx, shentsize, result):
    SHT_DYNSYM = 11
    for i in range(shnum):
        sb = shoff + i * shentsize
        if sb + shentsize > len(data):
            break
        sh_type   = struct.unpack_from(endian + "I", data, sb + 4)[0]
        sh_offset = struct.unpack_from(endian + "Q", data, sb + 24)[0]
        sh_size   = struct.unpack_from(endian + "Q", data, sb + 32)[0]
        sh_entsize = struct.unpack_from(endian + "Q", data, sb + 56)[0]
        sh_link   = struct.unpack_from(endian + "I", data, sb + 40)[0]
        if sh_type != SHT_DYNSYM or sh_entsize == 0:
            continue
        if sh_link >= shnum:
            continue
        str_sb  = shoff + sh_link * shentsize
        str_off = struct.unpack_from(endian + "Q", data, str_sb + 24)[0]
        count   = int(sh_size // sh_entsize) if sh_entsize else 0
        for k in range(count):
            sym_base = sh_offset + k * sh_entsize
            if sym_base + 4 > len(data):
                break
            st_name = struct.unpack_from(endian + "I", data, sym_base)[0]
            name = _read_sym_name(data, str_off, st_name)
            _classify_jni_sym(name, result)


def _classify_jni_sym(name: str, result: dict) -> None:
    if name == "JNI_OnLoad":
        result["jni_on_load"] = True
    elif name.startswith("Java_"):
        result["java_exports"].append(name)


# ── Finding dataclass ─────────────────────────────────────────────────────────

@dataclass
class JniBridgeFinding:
    severity: str
    category: str
    title: str
    detail: str
    source: str
    evidence: str


# ── Scanner ───────────────────────────────────────────────────────────────────

class JniBridgeScanner:
    """JNI bridge surface scanner for Android APKs."""

    def __init__(self, apk: APKParser) -> None:
        self._apk = apk

    @classmethod
    def from_path(cls, path) -> "JniBridgeScanner":
        return cls(APKParser.from_path(str(path)))

    def scan(self) -> List[JniBridgeFinding]:
        findings: List[JniBridgeFinding] = []

        # DEX side: collect native methods (authoritative — from class_data_item)
        dex_native_methods: Dict[str, List[str]] = {}  # class_name -> [method_name]
        load_classes: Set[str] = set()
        peer_classes: Dict[str, List[str]] = {}
        load_site_count = 0

        for dex in self._apk.iter_dex():
            # Authoritative native method scan via class_data_item ACC_NATIVE
            for nm in dex.iter_native_methods():
                if nm.class_name not in dex_native_methods:
                    dex_native_methods[nm.class_name] = []
                dex_native_methods[nm.class_name].append(nm.method_name)

            # loadLibrary call sites (MethodRef scan)
            for m in dex.iter_method_refs():
                if (m.class_name == "Ljava/lang/System;"
                        and m.method_name in ("loadLibrary", "load")):
                    load_classes.add(m.class_name)
                    load_site_count += 1

            # opaque peer: long field with peer-like name
            for f in dex.iter_field_refs():
                if f.type_desc == "J" and f.field_name in _PEER_NAMES:
                    cls_name = f.class_name
                    if cls_name not in peer_classes:
                        peer_classes[cls_name] = []
                    peer_classes[cls_name].append(f.field_name)

        # Report DEX-declared native method classes
        if dex_native_methods:
            total_native = sum(len(v) for v in dex_native_methods.values())
            top_classes = sorted(dex_native_methods.items(), key=lambda x: -len(x[1]))[:5]
            top_str = "; ".join(
                f"{c.lstrip('L').rstrip(';').split('/')[-1]}({len(m)})"
                for c, m in top_classes
            )
            findings.append(JniBridgeFinding(
                severity=HIGH,
                category="jni/dex_native_methods",
                title=f"{total_native} ACC_NATIVE method(s) across {len(dex_native_methods)} class(es)",
                detail=(
                    "Methods flagged ACC_NATIVE in class_data_item.encoded_method.access_flags. "
                    "These are authoritative DEX-declared native methods with code_off=0 — "
                    "they MUST be backed by a JNI implementation at runtime or the app crashes. "
                    "Cross-reference with ELF dynsym findings below to classify each as "
                    "canonical (Java_* symbol) or dynamic registration (JNI_OnLoad path)."
                ),
                source="dex/class_data_item",
                evidence=top_str + (f" (+{len(dex_native_methods)-5} more classes)" if len(dex_native_methods) > 5 else ""),
            ))

        if load_site_count:
            findings.append(JniBridgeFinding(
                severity=INFO,
                category="jni/load_sites",
                title=f"System.loadLibrary called {load_site_count} time(s)",
                detail=(
                    "Native libraries are loaded at runtime via System.loadLibrary / System.load. "
                    "Each load site is a potential JNI bridge entry. "
                    "Pair with ELF dynsym scan to determine registration style."
                ),
                source="dex",
                evidence=f"{load_site_count} loadLibrary/load call sites across all DEX files",
            ))

        for cls_name, fields in peer_classes.items():
            findings.append(JniBridgeFinding(
                severity=HIGH,
                category="jni/opaque_peer",
                title="Opaque native peer (long field holding raw pointer)",
                detail=(
                    f"Class '{cls_name}' has field(s) of type 'J' (long) with peer-like names. "
                    "This is the canonical pattern where ART holds a raw native pointer opaque to Java. "
                    "The native side writes via env->SetLongField(); direct integer arithmetic on this "
                    "value or missing bounds checking in the native accessor is the attack surface. "
                    "RE target: loadLibrary'd .so — find GetFieldID('J') usage in JNI_OnLoad or "
                    "Java_* functions, trace what native memory the pointer addresses."
                ),
                source=cls_name,
                evidence=", ".join(fields),
            ))

        # ELF side: scan dynsym in each native lib
        findings += self._scan_native_libs()

        return findings

    def _scan_native_libs(self) -> List[JniBridgeFinding]:
        findings: List[JniBridgeFinding] = []
        dynamic_libs: List[str] = []
        canonical_libs: Dict[str, List[str]] = {}

        for lib_path in self._apk.native_libs():
            lib_name = Path(lib_path).name
            try:
                data = self._apk._zip.read(lib_path)
            except Exception:
                continue
            info = _scan_elf_jni(data)
            if info["jni_on_load"]:
                dynamic_libs.append(lib_name)
            if info["java_exports"]:
                canonical_libs[lib_name] = info["java_exports"]

        if dynamic_libs:
            findings.append(JniBridgeFinding(
                severity=HIGH,
                category="jni/dynamic_registration",
                title=f"{len(dynamic_libs)} lib(s) use RegisterNatives (JNI_OnLoad present)",
                detail=(
                    "These libraries export JNI_OnLoad and register methods via env->RegisterNatives(). "
                    "Function pointers in the JNINativeMethod array can have any symbol name — or none if "
                    "the binary is stripped. Canonical Java_* names will NOT appear in the symbol table. "
                    "RE approach: find JNI_OnLoad in the .so, trace the RegisterNatives call, parse the "
                    "JNINativeMethod[] array to recover the Java class/method → native function mapping. "
                    "Use ARM32TaintTracker with JNI_OnLoad as entry point."
                ),
                source="native",
                evidence=", ".join(sorted(dynamic_libs)),
            ))

        for lib_name, syms in canonical_libs.items():
            top = syms[:5]
            rest = len(syms) - 5
            sym_str = ", ".join(top) + (f" (+{rest} more)" if rest > 0 else "")
            findings.append(JniBridgeFinding(
                severity=MEDIUM,
                category="jni/canonical_naming",
                title=f"{lib_name}: {len(syms)} canonical Java_* export(s)",
                detail=(
                    "Canonical JNI naming: Java_<pkg_underscored>_<Class>_<method>. "
                    "Class and method names are directly recoverable from symbol names even in stripped binaries. "
                    "Each exported symbol is a direct Java method binding — no RegisterNatives traversal needed."
                ),
                source=lib_name,
                evidence=sym_str,
            ))

        return findings

    @staticmethod
    def report(findings: List[JniBridgeFinding], max_info: int = 10) -> str:
        if not findings:
            return "JniBridgeScanner: no findings.\n"

        sev_order = {HIGH: 0, MEDIUM: 1, INFO: 2}
        findings = sorted(findings, key=lambda f: sev_order.get(f.severity, 9))

        lines = ["── JNI Bridge Scanner ────────────────────────────────────────"]
        info_count = 0
        for f in findings:
            if f.severity == INFO:
                info_count += 1
                if info_count > max_info:
                    continue
            lines.append(f"[{f.severity}] {f.category}")
            lines.append(f"  {f.title}")
            lines.append(f"  src: {f.source}")
            lines.append(f"  evidence: {f.evidence}")
            lines.append(f"  {f.detail}")
            lines.append("")

        skipped = info_count - max_info
        if skipped > 0:
            lines.append(f"  ... {skipped} INFO findings omitted (pass max_info= to show all)")
        return "\n".join(lines)
