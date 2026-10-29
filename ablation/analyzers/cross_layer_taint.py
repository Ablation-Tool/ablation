"""Fixed-point DEX taint analysis with JNI-to-native sink propagation."""

from __future__ import annotations

from collections import deque
from dataclasses import asdict, dataclass, field
from typing import Dict, Iterator, List, Optional, Set, Tuple

import capstone

from ablation.analyzers.apk_jni_mapper import APKJNIMapper, JNIBinding
from ablation.analyzers.dex_decompiler import DEXDecompiler, DEXMethod
from ablation.analyzers.elf_disassembler import ELFDisassembler, ELFInstruction


@dataclass
class Origin:
    identifier: str
    kind: str
    method_idx: int
    method: str
    cu_offset: int


@dataclass
class DexCallTaint:
    caller_idx: int
    target_idx: int
    target: str
    cu_offset: int
    argument_origins: List[Set[str]]
    receiver_origins: Set[str]
    argument_regs: List[int]


@dataclass
class DexSinkTaint:
    caller_idx: int
    target_idx: int
    target: str
    kind: str
    cu_offset: int
    origins: Set[str]


@dataclass
class DexMethodFacts:
    returns: Set[str] = field(default_factory=set)
    calls: List[DexCallTaint] = field(default_factory=list)
    sinks: List[DexSinkTaint] = field(default_factory=list)


@dataclass
class CrossLayerFinding:
    source_kind: str
    source: str
    sink_kind: str
    sink: str
    java_path: List[str]
    native_path: List[str]
    confidence: str = "static-taint-candidate"


@dataclass
class CrossLayerReport:
    findings: List[CrossLayerFinding] = field(default_factory=list)
    native_entry_flows: List[dict] = field(default_factory=list)
    native_sink_surface: List[dict] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "findings": [asdict(finding) for finding in self.findings],
            "native_entry_flows": self.native_entry_flows,
            "native_sink_surface": self.native_sink_surface,
            "warnings": self.warnings,
            "summary": {
                "source_to_sink_candidates": len(self.findings),
                "native_entry_flows": len(self.native_entry_flows),
                "native_sink_surface": len(self.native_sink_surface),
            },
        }


_ENTRY_SOURCES = {
    "onReceive": (1, "ipc"),
    "onTransact": (1, "ipc"),
    "onActivityResult": (2, "ipc"),
    "onNewIntent": (0, "ipc"),
    "onImageAvailable": (0, "camera"),
    "onAuthenticationSucceeded": (0, "biometric"),
}

_SOURCE_METHODS = {
    "Ljava/io/InputStream;": (("read",), "network"),
    "Ljava/net/URLConnection;": (("getInputStream",), "network"),
    "Lokhttp3/ResponseBody;": (("bytes", "string", "byteStream"), "network"),
    "Lokhttp3/Response;": (("body",), "network"),
    "Landroid/media/ImageReader;": (("acquireLatestImage", "acquireNextImage"), "camera"),
    "Landroid/media/Image;": (("getPlanes",), "camera"),
    "Landroidx/camera/core/ImageProxy;": (("getPlanes", "getImage"), "camera"),
    "Landroid/hardware/biometrics/BiometricPrompt$AuthenticationResult;": (("getCryptoObject",), "biometric"),
    "Landroidx/biometric/BiometricPrompt$AuthenticationResult;": (("getCryptoObject",), "biometric"),
    "Landroid/os/Parcel;": (("read",), "ipc"),
}

_SINK_METHODS = {
    "Ljava/lang/Runtime;": (("exec",), "command"),
    "Ljava/lang/ProcessBuilder;": (("<init>",), "command"),
    "Ljavax/crypto/Cipher;": (("doFinal",), "crypto"),
    "Ljavax/crypto/Mac;": (("doFinal",), "crypto"),
    "Ljava/security/MessageDigest;": (("digest",), "crypto"),
    "Ljava/lang/System;": (("arraycopy",), "memory"),
    "Ljava/nio/ByteBuffer;": (("put",), "memory"),
    "Ljava/io/OutputStream;": (("write",), "network"),
}

_NATIVE_SINKS = {
    "system": "command",
    "popen": "command",
    "execve": "command",
    "execl": "command",
    "execlp": "command",
    "execvp": "command",
    "memcpy": "memory",
    "memmove": "memory",
    "memset": "memory",
    "strcpy": "memory",
    "strncpy": "memory",
    "strcat": "memory",
    "sprintf": "memory",
    "snprintf": "memory",
    "vsprintf": "memory",
    "__aeabi_memcpy": "memory",
    "__aeabi_memmove": "memory",
    "__memcpy_chk": "memory",
    "__memmove_chk": "memory",
    "__strcpy_chk": "memory",
    "__strncpy_chk2": "memory",
}


class CrossLayerTaintAnalyzer:
    """Propagate source tags through DEX calls and bound ARM JNI functions."""

    def __init__(self, mapper: APKJNIMapper, max_iterations: int = 6, native_depth: int = 3) -> None:
        self.mapper = mapper
        self.max_iterations = max_iterations
        self.native_depth = native_depth
        self.methods: Dict[int, DEXMethod] = {}
        self.decompilers: List[DEXDecompiler] = []
        self.origins: Dict[str, Origin] = {}
        self.param_origins: Dict[int, List[Set[str]]] = {}
        self.return_origins: Dict[int, Set[str]] = {}
        self.facts: Dict[int, DexMethodFacts] = {}
        self.bindings: Dict[int, List[JNIBinding]] = {}
        self.adjacency: Dict[int, Set[int]] = {}
        self.report = CrossLayerReport()

    @classmethod
    def from_path(cls, path: str) -> "CrossLayerTaintAnalyzer":
        return cls(APKJNIMapper.from_path(path))

    def close(self) -> None:
        self.mapper.close()

    def __enter__(self) -> "CrossLayerTaintAnalyzer":
        return self

    def __exit__(self, *_) -> None:
        self.close()

    def _origin(self, kind: str, method: DEXMethod, cu_offset: int, suffix: str = "") -> str:
        identifier = f"{kind}:{method.method_idx}:{cu_offset}{suffix}"
        self.origins[identifier] = Origin(identifier, kind, method.method_idx, method.descriptor, cu_offset)
        return identifier

    def _initialize(self) -> None:
        self.decompilers = self.mapper.decompilers
        for decompiler in self.decompilers:
            for method in decompiler.iter_methods():
                self.methods[method.method_idx] = method
                self.param_origins[method.method_idx] = [set() for _ in method.param_types]
                self.return_origins[method.method_idx] = set()
                if method.name in _ENTRY_SOURCES:
                    index, kind = _ENTRY_SOURCES[method.name]
                    if index < len(method.param_types):
                        self.param_origins[method.method_idx][index].add(self._origin(kind, method, 0, f":param{index}"))
                if method.code_off:
                    for call in decompiler.calls(method):
                        self.adjacency.setdefault(method.method_idx, set()).add(call.target_idx)
        for binding in self.mapper.graph.bindings:
            self.bindings.setdefault(binding.method_idx, []).append(binding)

    def _method_ref_parts(self, decompiler: DEXDecompiler, method_idx: int) -> Tuple[str, str]:
        if not 0 <= method_idx < len(decompiler.dex._method_ids):
            return "", ""
        class_idx, _, name_idx = decompiler.dex._method_ids[method_idx]
        return decompiler.dex.type_name(class_idx), decompiler.dex.string_at(name_idx)

    def _source_for(self, class_name: str, method_name: str) -> Optional[str]:
        methods = _SOURCE_METHODS.get(class_name)
        if methods and any(method_name == name or method_name.startswith(name) for name in methods[0]):
            return methods[1]
        if class_name in ("Landroid/content/Intent;", "Landroid/os/Bundle;") and method_name.startswith("get"):
            return "ipc"
        return None

    def _sink_for(self, class_name: str, method_name: str) -> Optional[str]:
        methods = _SINK_METHODS.get(class_name)
        if methods and any(method_name == name or method_name.startswith(name) for name in methods[0]):
            return methods[1]
        return None

    def _analyze_method(self, decompiler: DEXDecompiler, method: DEXMethod) -> DexMethodFacts:
        facts = DexMethodFacts()
        registers, ins_size, _, instructions = decompiler.instructions(method)
        params_start = registers - ins_size
        state: Dict[int, Set[str]] = {}
        for index, origins in enumerate(self.param_origins[method.method_idx]):
            register = params_start + index + (0 if method.is_static else 1)
            state[register] = set(origins)
        pending: Set[str] = set()
        invoke_ops = (0x6E, 0x6F, 0x70, 0x71, 0x72, 0x74, 0x75, 0x76, 0x77, 0x78)
        for insn in instructions:
            op = insn.opcode
            if op in (0x0A, 0x0B, 0x0C):
                if insn.regs:
                    state[insn.regs[0]] = set(pending)
                pending = set()
                continue
            if op not in (0x0A, 0x0B, 0x0C):
                pending = set()
            if op in range(0x01, 0x0A) and len(insn.regs) >= 2:
                state[insn.regs[0]] = set(state.get(insn.regs[1], set()))
            elif 0x12 <= op <= 0x1C and insn.regs:
                state[insn.regs[0]] = set()
            elif op == 0x0D and insn.regs:
                state[insn.regs[0]] = set()
            elif op in (0x0F, 0x10, 0x11) and insn.regs:
                facts.returns.update(state.get(insn.regs[0], set()))
            elif op in range(0x20, 0x24) and insn.regs:
                sources = [state.get(reg, set()) for reg in insn.regs[1:]]
                state[insn.regs[0]] = set().union(*sources) if sources else set()
            elif op in range(0x44, 0x4B) and len(insn.regs) >= 3:
                state[insn.regs[0]] = set(state.get(insn.regs[1], set())) | set(state.get(insn.regs[2], set()))
            elif op in range(0x52, 0x59) and len(insn.regs) >= 2:
                state[insn.regs[0]] = set(state.get(insn.regs[1], set()))
            elif op in range(0x60, 0x67) and insn.regs:
                state[insn.regs[0]] = set()
            elif 0x7B <= op <= 0xE2 and insn.regs:
                sources = [state.get(reg, set()) for reg in insn.regs[1:]]
                if op in range(0xB0, 0xD0):
                    sources.insert(0, state.get(insn.regs[0], set()))
                state[insn.regs[0]] = set().union(*sources) if sources else set()
            elif op in invoke_ops:
                class_name, method_name = self._method_ref_parts(decompiler, insn.ref_idx)
                is_static = op in (0x71, 0x77)
                receiver_regs = [] if is_static else insn.regs[:1]
                argument_regs = list(insn.regs if is_static else insn.regs[1:])
                receiver_origins = set().union(*(state.get(reg, set()) for reg in receiver_regs)) if receiver_regs else set()
                argument_origins = [set(state.get(reg, set())) for reg in argument_regs]
                all_origins = set(receiver_origins).union(*argument_origins) if argument_origins else set(receiver_origins)
                facts.calls.append(DexCallTaint(
                    caller_idx=method.method_idx,
                    target_idx=insn.ref_idx,
                    target=decompiler.method_ref(insn.ref_idx),
                    cu_offset=insn.cu_offset,
                    argument_origins=argument_origins,
                    receiver_origins=receiver_origins,
                    argument_regs=argument_regs,
                ))
                source_kind = self._source_for(class_name, method_name)
                pending = set(self.return_origins.get(insn.ref_idx, set()))
                if source_kind:
                    source = self._origin(source_kind, method, insn.cu_offset)
                    pending.add(source)
                    if class_name == "Ljava/io/InputStream;" and argument_regs:
                        state[argument_regs[0]] = set(state.get(argument_regs[0], set())) | {source}
                sink_kind = self._sink_for(class_name, method_name)
                if insn.ref_idx in self.bindings:
                    sink_kind = "jni"
                argument_only = set().union(*argument_origins) if argument_origins else set()
                if sink_kind and argument_only:
                    facts.sinks.append(DexSinkTaint(
                        caller_idx=method.method_idx,
                        target_idx=insn.ref_idx,
                        target=decompiler.method_ref(insn.ref_idx),
                        kind=sink_kind,
                        cu_offset=insn.cu_offset,
                        origins=argument_only,
                    ))
                if method_name == "<init>" and receiver_regs and argument_only:
                    state[receiver_regs[0]] = set(state.get(receiver_regs[0], set())) | argument_only
        return facts

    def _propagate_dex(self) -> None:
        for iteration in range(self.max_iterations):
            new_facts: Dict[int, DexMethodFacts] = {}
            param_additions: Dict[int, List[Set[str]]] = {
                method_idx: [set() for _ in method.param_types]
                for method_idx, method in self.methods.items()
            }
            return_additions: Dict[int, Set[str]] = {}
            for decompiler in self.decompilers:
                for method in decompiler.iter_methods():
                    if not method.code_off:
                        continue
                    facts = self._analyze_method(decompiler, method)
                    new_facts[method.method_idx] = facts
                    return_additions[method.method_idx] = set(facts.returns)
                    for call in facts.calls:
                        if call.target_idx not in self.methods:
                            continue
                        for index, origins in enumerate(call.argument_origins):
                            if index < len(param_additions[call.target_idx]):
                                param_additions[call.target_idx][index].update(origins)
            changed = False
            for method_idx, additions in param_additions.items():
                for index, origins in enumerate(additions):
                    before = len(self.param_origins[method_idx][index])
                    self.param_origins[method_idx][index].update(origins)
                    changed |= len(self.param_origins[method_idx][index]) != before
            for method_idx, origins in return_additions.items():
                before = len(self.return_origins[method_idx])
                self.return_origins[method_idx].update(origins)
                changed |= len(self.return_origins[method_idx]) != before
            self.facts = new_facts
            if not changed:
                return
            if iteration == self.max_iterations - 1:
                self.report.warnings.append(f"DEX taint reached the {self.max_iterations}-iteration limit")

    def _java_path(self, source_idx: int, sink_idx: int, max_depth: int = 8) -> List[str]:
        if source_idx == sink_idx:
            return [self.methods[source_idx].descriptor]
        queue = deque([(source_idx, [source_idx], 0)])
        seen = {source_idx}
        while queue:
            current, path, depth = queue.popleft()
            if depth >= max_depth:
                continue
            for target in self.adjacency.get(current, set()):
                if target in seen or target not in self.methods:
                    continue
                next_path = path + [target]
                if target == sink_idx:
                    return [self.methods[index].descriptor for index in next_path]
                seen.add(target)
                queue.append((target, next_path, depth + 1))
        return [self.methods[source_idx].descriptor, "... unresolved intermediate calls ...", self.methods[sink_idx].descriptor]

    def _findings_from_dex(self) -> None:
        for facts in self.facts.values():
            for sink in facts.sinks:
                if sink.kind == "jni":
                    continue
                for identifier in sorted(sink.origins):
                    origin = self.origins[identifier]
                    self.report.findings.append(CrossLayerFinding(
                        source_kind=origin.kind,
                        source=f"{origin.method}@{origin.cu_offset:#x}",
                        sink_kind=sink.kind,
                        sink=f"{self.methods[sink.caller_idx].descriptor} -> {sink.target}@{sink.cu_offset:#x}",
                        java_path=self._java_path(origin.method_idx, sink.caller_idx),
                        native_path=[],
                    ))

    def _native_entry_flows(self) -> Dict[Tuple[str, int], Dict[int, Set[str]]]:
        entries: Dict[Tuple[str, int], Dict[int, Set[str]]] = {}
        for facts in self.facts.values():
            for call in facts.calls:
                for binding in self.bindings.get(call.target_idx, []):
                    tainted = {index: origins for index, origins in enumerate(call.argument_origins) if origins}
                    if not tainted:
                        continue
                    key = (binding.library, binding.method_idx)
                    entries.setdefault(key, {})
                    for index, origins in tainted.items():
                        entries[key].setdefault(index, set()).update(origins)
                        for identifier in sorted(origins):
                            origin = self.origins[identifier]
                            self.report.native_entry_flows.append({
                                "source_kind": origin.kind,
                                "source": f"{origin.method}@{origin.cu_offset:#x}",
                                "caller": self.methods[call.caller_idx].descriptor,
                                "native_method": binding.java_method,
                                "library": binding.library,
                                "native_address": binding.native_address,
                                "java_argument": index,
                                "java_path": self._java_path(origin.method_idx, call.caller_idx),
                            })
        return entries

    def _native_sink_kind(self, name: str) -> Optional[str]:
        base = name.split("@", 1)[0]
        if base in _NATIVE_SINKS:
            return _NATIVE_SINKS[base]
        upper = base.upper()
        if upper.startswith(("EVP_", "AES_", "DES_", "MD5", "SHA", "RSA_")):
            return "crypto"
        return None

    def _trace_native(
        self,
        library: ELFDisassembler,
        address: int,
        thumb: bool,
        initial: Dict[int, Set[str]],
        java_path: List[str],
        depth: int = 0,
    ) -> List[CrossLayerFinding]:
        findings: List[CrossLayerFinding] = []
        instructions = library.disassemble_function(address, max_size=0x4000, thumb=thumb)
        direct = {call.site: call for call in library.direct_calls(instructions)}
        registers: Dict[int, Set[str]] = {index: set(origins) for index, origins in initial.items()}
        stack: Dict[int, Set[str]] = {}
        for wrapped in instructions:
            raw = next(library._engine_for(wrapped.thumb).disasm(wrapped.data, wrapped.address), None)
            if raw is None:
                continue
            call = direct.get(wrapped.address)
            if call:
                call_origins = set().union(*(registers.get(index, set()) for index in range(4)))
                sink_kind = self._native_sink_kind(call.target_name)
                if sink_kind and call_origins:
                    for identifier in sorted(call_origins):
                        origin = self.origins[identifier]
                        findings.append(CrossLayerFinding(
                            source_kind=origin.kind,
                            source=f"{origin.method}@{origin.cu_offset:#x}",
                            sink_kind=sink_kind,
                            sink=f"{library.name}!{call.target_name}@0x{call.site:x}",
                            java_path=java_path,
                            native_path=[f"{library.name}!sub_{address:x}", f"{call.target_name}@0x{call.site:x}"],
                        ))
                elif depth < self.native_depth and not sink_kind and call.target_name.startswith("sub_"):
                    nested_initial = {index: set(registers.get(index, set())) for index in range(4) if registers.get(index)}
                    if nested_initial:
                        findings.extend(self._trace_native(library, call.target, thumb, nested_initial, java_path, depth + 1))
                continue
            if library.machine != "EM_ARM":
                continue
            operands = raw.operands
            if raw.mnemonic.startswith("str") and len(operands) >= 2 and operands[0].type == capstone.arm.ARM_OP_REG and operands[1].type == capstone.arm.ARM_OP_MEM:
                base = raw.reg_name(operands[1].mem.base)
                if base == "sp":
                    stack[operands[1].mem.disp] = set(registers.get(operands[0].reg, set()))
                continue
            if raw.mnemonic.startswith("ldr") and len(operands) >= 2 and operands[0].type == capstone.arm.ARM_OP_REG and operands[1].type == capstone.arm.ARM_OP_MEM:
                base = raw.reg_name(operands[1].mem.base)
                if base == "sp" and operands[1].mem.disp in stack:
                    registers[operands[0].reg] = set(stack[operands[1].mem.disp])
                    continue
            try:
                read, written = raw.regs_access()
            except capstone.CsError:
                continue
            read_origins = set().union(*(registers.get(reg, set()) for reg in read)) if read else set()
            for reg in written:
                if raw.reg_name(reg) not in ("sp", "lr", "pc"):
                    registers[reg] = set(read_origins)
        return findings

    def _analyze_native(self, entries: Dict[Tuple[str, int], Dict[int, Set[str]]]) -> None:
        for binding in self.mapper.graph.bindings:
            library = self.mapper.libraries[binding.library]
            for edge in self.mapper.graph.native_edges:
                if edge.library != binding.library or edge.source_address != binding.native_address:
                    continue
                kind = self._native_sink_kind(edge.target_name)
                if kind:
                    self.report.native_sink_surface.append({
                        "library": binding.library,
                        "java_method": binding.java_method,
                        "native_address": binding.native_address,
                        "sink_kind": kind,
                        "sink": edge.target_name,
                        "site": edge.site,
                    })
            arguments = entries.get((binding.library, binding.method_idx), {})
            if not arguments or library.machine != "EM_ARM":
                continue
            initial: Dict[int, Set[str]] = {}
            register = 2
            method = self.methods[binding.method_idx]
            java_path: List[str] = []
            for index, param_type in enumerate(method.param_types):
                origins = arguments.get(index, set())
                if origins and register <= 3:
                    initial[register] = set(origins)
                    if not java_path:
                        origin = self.origins[sorted(origins)[0]]
                        java_path = self._java_path(origin.method_idx, binding.method_idx)
                if origins and register > 3:
                    self.report.warnings.append(f"Stack-passed JNI argument {index} not modeled for {binding.java_method}")
                register += 2 if param_type in ("J", "D") else 1
            if initial:
                self.report.findings.extend(self._trace_native(
                    library,
                    binding.native_address,
                    binding.thumb,
                    initial,
                    java_path or [binding.java_method],
                ))

    def analyze(self) -> CrossLayerReport:
        if not self.mapper.graph.bindings:
            self.mapper.analyze()
        self._initialize()
        self._propagate_dex()
        self._findings_from_dex()
        entries = self._native_entry_flows()
        self._analyze_native(entries)
        unique = {(finding.source, finding.sink): finding for finding in self.report.findings}
        self.report.findings = list(unique.values())
        return self.report
