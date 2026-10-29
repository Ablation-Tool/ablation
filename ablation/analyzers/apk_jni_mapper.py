"""Map DEX native declarations to JNI exports and registration tables."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

from ablation.core.android_package import AndroidPackage, NativeLibrary
from ablation.core.apk_parser import DEXFile
from ablation.analyzers.dex_decompiler import DEXDecompiler, DEXMethod
from ablation.analyzers.elf_disassembler import ELFDisassembler


@dataclass
class JNIBinding:
    method_idx: int
    java_method: str
    library: str
    library_entry: str
    native_address: int
    native_name: str
    binding_kind: str
    confidence: str
    table_address: Optional[int] = None
    thumb: bool = False

    def to_dict(self) -> dict:
        result = asdict(self)
        result["native_address"] = self.native_address
        return result


@dataclass
class JavaNativeEdge:
    caller: str
    native_method: str
    library: str
    native_address: int
    cu_offset: int


@dataclass
class NativeEdge:
    source_address: int
    source_name: str
    target_address: int
    target_name: str
    library: str
    site: int


@dataclass
class JNIGraph:
    bindings: List[JNIBinding] = field(default_factory=list)
    java_edges: List[JavaNativeEdge] = field(default_factory=list)
    native_edges: List[NativeEdge] = field(default_factory=list)
    unresolved_native_methods: List[str] = field(default_factory=list)
    ambiguous_registrations: List[dict] = field(default_factory=list)
    library_loads: List[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "bindings": [asdict(binding) for binding in self.bindings],
            "java_to_native_edges": [asdict(edge) for edge in self.java_edges],
            "native_call_edges": [asdict(edge) for edge in self.native_edges],
            "unresolved_native_methods": self.unresolved_native_methods,
            "ambiguous_registrations": self.ambiguous_registrations,
            "library_loads": self.library_loads,
            "summary": {
                "bindings": len(self.bindings),
                "java_to_native_edges": len(self.java_edges),
                "native_call_edges": len(self.native_edges),
                "unresolved": len(self.unresolved_native_methods),
                "ambiguous": len(self.ambiguous_registrations),
            },
        }


def _jni_escape(value: str) -> str:
    result: List[str] = []
    for char in value:
        if char == "/":
            result.append("_")
        elif char == "_":
            result.append("_1")
        elif char == ";":
            result.append("_2")
        elif char == "[":
            result.append("_3")
        elif char.isalnum():
            result.append(char)
        else:
            result.append(f"_0{ord(char):04x}")
    return "".join(result)


def canonical_jni_names(method: DEXMethod) -> Tuple[str, str]:
    class_name = method.class_name[1:-1] if method.class_name.startswith("L") else method.class_name
    prefix = f"Java_{_jni_escape(class_name)}_{_jni_escape(method.name)}"
    overloaded = prefix + "__" + _jni_escape("".join(method.param_types))
    return prefix, overloaded


def _valid_descriptor(descriptor: str, position: int) -> int:
    while position < len(descriptor) and descriptor[position] == "[":
        position += 1
    if position >= len(descriptor):
        return -1
    if descriptor[position] in "ZBCSIFJDV":
        return position + 1
    if descriptor[position] == "L":
        end = descriptor.find(";", position + 1)
        return end + 1 if end > position + 1 else -1
    return -1


def valid_method_signature(signature: str) -> bool:
    if not signature.startswith("("):
        return False
    position = 1
    while position < len(signature) and signature[position] != ")":
        position = _valid_descriptor(signature, position)
        if position < 0:
            return False
    if position >= len(signature) or signature[position] != ")":
        return False
    return _valid_descriptor(signature, position + 1) == len(signature)


class APKJNIMapper:
    """Reconstruct static and dynamically registered JNI bridges in APK/XAPK files."""

    def __init__(self, package: AndroidPackage) -> None:
        self.package = package
        self.decompilers: List[DEXDecompiler] = []
        self.methods: Dict[int, DEXMethod] = {}
        self.libraries: Dict[str, ELFDisassembler] = {}
        self.library_entries: Dict[str, str] = {}
        self.class_loads: Dict[str, set] = {}
        self.graph = JNIGraph()

    @classmethod
    def from_path(cls, path: str | Path) -> "APKJNIMapper":
        return cls(AndroidPackage.from_path(path))

    def close(self) -> None:
        self.package.close()

    def __enter__(self) -> "APKJNIMapper":
        return self

    def __exit__(self, *_) -> None:
        self.close()

    def _load_dex(self) -> None:
        dex_files: List[DEXFile] = []
        for apk in self.package.iter_apks():
            try:
                dex_files.extend(apk.iter_dex())
            finally:
                apk.close()
        if len(dex_files) > 1:
            raise ValueError(
                "APKJNIMapper supports exactly one DEX per package; "
                f"found {len(dex_files)}. Multi-DEX method indices are not globally unique."
            )
        for dex in dex_files:
            decompiler = DEXDecompiler(dex)
            self.decompilers.append(decompiler)
            for method in decompiler.iter_native_methods():
                self.methods[method.method_idx] = method

    def _load_libraries(self) -> None:
        for native in self.package.iter_native_libraries():
            self.libraries[native.name] = ELFDisassembler(native.data, native.name)
            self.library_entries[native.name] = f"{native.apk_name}!/{native.entry_path}"

    def _record_library_loads(self) -> None:
        for decompiler in self.decompilers:
            for method in decompiler.iter_methods():
                if not method.code_off:
                    continue
                strings: Dict[int, str] = {}
                for insn in decompiler.instructions(method)[3]:
                    if insn.opcode in (0x1A, 0x1B) and insn.regs:
                        strings[insn.regs[0]] = decompiler.dex.string_at(insn.ref_idx)
                    elif insn.opcode in range(0x01, 0x0A) and len(insn.regs) >= 2 and insn.regs[1] in strings:
                        strings[insn.regs[0]] = strings[insn.regs[1]]
                    elif insn.opcode in (0x71, 0x77) and 0 <= insn.ref_idx < len(decompiler.dex._method_ids):
                        class_idx, _, name_idx = decompiler.dex._method_ids[insn.ref_idx]
                        if decompiler.dex.type_name(class_idx) != "Ljava/lang/System;":
                            continue
                        load_kind = decompiler.dex.string_at(name_idx)
                        if load_kind not in ("load", "loadLibrary") or not insn.regs:
                            continue
                        value = strings.get(insn.regs[0])
                        if not value:
                            continue
                        library = Path(value).name if load_kind == "load" else f"lib{value}.so"
                        self.class_loads.setdefault(method.class_name, set()).add(library)
                        self.graph.library_loads.append({
                            "caller": method.descriptor,
                            "library": library,
                            "argument": value,
                            "cu_offset": insn.cu_offset,
                        })

    def _bind_canonical(self, bound: Dict[Tuple[str, int], JNIBinding]) -> None:
        exports = [
            (library, symbol, address)
            for library in self.libraries.values()
            for symbol, address in library.exports().items()
            if symbol.startswith("Java_")
        ]
        for method in self.methods.values():
            names = canonical_jni_names(method)
            matches = [(library, symbol, address) for library, symbol, address in exports if symbol in names]
            if not matches:
                continue
            if len(matches) > 1:
                self.graph.ambiguous_registrations.append({
                    "kind": "canonical",
                    "java_method": method.descriptor,
                    "candidates": [
                        {"library": library.name, "symbol": symbol, "native_address": address}
                        for library, symbol, address in matches
                    ],
                })
                continue
            library, symbol, address = matches[0]
            binding = JNIBinding(
                method_idx=method.method_idx,
                java_method=method.descriptor,
                library=library.name,
                library_entry=self.library_entries[library.name],
                native_address=address,
                native_name=symbol,
                binding_kind="canonical",
                confidence="exact" if symbol == names[1] else "name-only",
            )
            bound[(library.name, method.method_idx)] = binding
            self.graph.bindings.append(binding)

    def _registration_records(self, library: ELFDisassembler) -> Iterator[Tuple[int, str, str, int, bool]]:
        pointer_size = library.bits // 8
        record_size = pointer_size * 3
        byte_order = "little" if library.endian == "<" else "big"
        executable = [
            (segment["p_vaddr"], segment["p_vaddr"] + segment["p_memsz"])
            for segment in library.elf.iter_segments()
            if segment["p_type"] == "PT_LOAD" and segment["p_flags"] & 1
        ]
        for section in library.elf.iter_sections():
            if section.name not in (".rodata", ".data.rel.ro", ".data") or not section["sh_size"]:
                continue
            base = section["sh_addr"]
            data = section.data()
            for offset in range(0, len(data) - record_size + 1, pointer_size):
                name_ptr = int.from_bytes(data[offset:offset + pointer_size], byte_order)
                signature_ptr = int.from_bytes(data[offset + pointer_size:offset + 2 * pointer_size], byte_order)
                function_ptr = int.from_bytes(data[offset + 2 * pointer_size:offset + 3 * pointer_size], byte_order)
                thumb = library.machine == "EM_ARM" and bool(function_ptr & 1)
                function_address = function_ptr & ~1 if library.machine == "EM_ARM" else function_ptr
                if not any(start <= function_address < end for start, end in executable):
                    continue
                try:
                    name = library.cstring_at_va(name_ptr, 256)
                    signature = library.cstring_at_va(signature_ptr, 512)
                except (ValueError, UnicodeDecodeError):
                    continue
                if not re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", name):
                    continue
                if valid_method_signature(signature):
                    yield base + offset, name, signature, function_address, thumb

    def _bind_dynamic(self, bound: Dict[Tuple[str, int], JNIBinding]) -> None:
        by_signature: Dict[str, List[DEXMethod]] = {}
        for method in self.methods.values():
            key = f"{method.name}({''.join(method.param_types)}){method.return_type}"
            by_signature.setdefault(key, []).append(method)
        for library in self.libraries.values():
            for table_address, name, signature, function_address, thumb in self._registration_records(library):
                candidates = by_signature.get(f"{name}{signature}", [])
                loaded = [method for method in candidates if library.name in self.class_loads.get(method.class_name, set())]
                if loaded:
                    candidates = loaded
                if len(candidates) != 1:
                    self.graph.ambiguous_registrations.append({
                        "library": library.name,
                        "table_address": table_address,
                        "name": name,
                        "signature": signature,
                        "native_address": function_address,
                        "candidates": [method.descriptor for method in candidates],
                    })
                    continue
                method = candidates[0]
                key = (library.name, method.method_idx)
                if key in bound:
                    continue
                binding = JNIBinding(
                    method_idx=method.method_idx,
                    java_method=method.descriptor,
                    library=library.name,
                    library_entry=self.library_entries[library.name],
                    native_address=function_address,
                    native_name=f"sub_{function_address:x}",
                    binding_kind="JNINativeMethod",
                    confidence="exact-signature+loader" if loaded else "unique-signature",
                    table_address=table_address,
                    thumb=thumb,
                )
                bound[key] = binding
                self.graph.bindings.append(binding)

    def _build_edges(self) -> None:
        bindings_by_method: Dict[int, List[JNIBinding]] = {}
        for binding in self.graph.bindings:
            bindings_by_method.setdefault(binding.method_idx, []).append(binding)
        for decompiler in self.decompilers:
            for method in decompiler.iter_methods():
                if not method.code_off:
                    continue
                for call in decompiler.calls(method):
                    for binding in bindings_by_method.get(call.target_idx, []):
                        self.graph.java_edges.append(JavaNativeEdge(
                            caller=method.descriptor,
                            native_method=binding.java_method,
                            library=binding.library,
                            native_address=binding.native_address,
                            cu_offset=call.cu_offset,
                        ))
        for binding in self.graph.bindings:
            library = self.libraries[binding.library]
            for call in library.direct_calls(library.disassemble_function(binding.native_address, thumb=binding.thumb)):
                self.graph.native_edges.append(NativeEdge(
                    source_address=binding.native_address,
                    source_name=binding.native_name,
                    target_address=call.target,
                    target_name=call.target_name,
                    library=binding.library,
                    site=call.site,
                ))

    def analyze(self) -> JNIGraph:
        self.decompilers = []
        self.methods = {}
        self.libraries = {}
        self.library_entries = {}
        self.class_loads = {}
        self.graph = JNIGraph()
        self._load_dex()
        self._load_libraries()
        self._record_library_loads()
        bound: Dict[Tuple[str, int], JNIBinding] = {}
        self._bind_canonical(bound)
        self._bind_dynamic(bound)
        bound_methods = {binding.method_idx for binding in self.graph.bindings}
        self.graph.unresolved_native_methods = [
            method.descriptor for method in self.methods.values()
            if method.method_idx not in bound_methods
        ]
        self.graph.bindings.sort(key=lambda binding: (binding.library, binding.native_address, binding.java_method))
        self._build_edges()
        return self.graph
