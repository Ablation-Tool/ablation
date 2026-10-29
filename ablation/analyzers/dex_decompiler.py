"""Overload-aware DEX class model and Java-like decompiler."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional, Tuple

from ablation.core.apk_parser import DEXFile, _uleb128
from ablation.analyzers.dex_disasm import (
    DEXDisasm,
    DEXInstruction,
    _proto_str,
    decode_code_item,
)
from ablation.analyzers.dex_lifter import DEXLifter, _split_proto_params, jtype


_ACCESS_FLAGS = (
    (0x0001, "public"),
    (0x0002, "private"),
    (0x0004, "protected"),
    (0x0008, "static"),
    (0x0010, "final"),
    (0x0020, "synchronized"),
    (0x0040, "bridge"),
    (0x0080, "varargs"),
    (0x0100, "native"),
    (0x0400, "abstract"),
    (0x0800, "strictfp"),
    (0x1000, "synthetic"),
)


def access_string(flags: int) -> str:
    return " ".join(name for bit, name in _ACCESS_FLAGS if flags & bit)


@dataclass
class DEXField:
    field_idx: int
    class_name: str
    name: str
    type_desc: str
    access_flags: int
    is_static: bool

    def declaration(self, dex: DEXFile) -> str:
        flags = access_string(self.access_flags)
        return f"{flags + ' ' if flags else ''}{jtype(self.type_desc)} {self.name};"


@dataclass
class DEXMethod:
    dex_name: str
    method_idx: int
    class_name: str
    name: str
    access_flags: int
    code_off: int
    param_types: Tuple[str, ...]
    return_type: str
    is_direct: bool

    @property
    def descriptor(self) -> str:
        return f"{self.class_name}->{self.name}({''.join(self.param_types)}){self.return_type}"

    @property
    def is_native(self) -> bool:
        return bool(self.access_flags & 0x0100)

    @property
    def is_abstract(self) -> bool:
        return bool(self.access_flags & 0x0400)

    @property
    def is_static(self) -> bool:
        return bool(self.access_flags & 0x0008)

    def declaration(self) -> str:
        flags = access_string(self.access_flags)
        params = ", ".join(f"{jtype(desc)} p{i}" for i, desc in enumerate(self.param_types))
        name = self.class_name[1:-1].split("/")[-1] if self.name == "<init>" else self.name
        returns = "" if self.name == "<init>" else jtype(self.return_type) + " "
        return f"{flags + ' ' if flags else ''}{returns}{name}({params})"


@dataclass
class DEXClass:
    class_name: str
    access_flags: int
    superclass: str
    source_file: str
    fields: List[DEXField] = field(default_factory=list)
    methods: List[DEXMethod] = field(default_factory=list)


@dataclass
class DEXCall:
    caller_idx: int
    target_idx: int
    cu_offset: int
    opcode: int
    argument_regs: Tuple[int, ...]
    target: str


class DEXDecompiler:
    """Parse class definitions and emit Java-like source for exact DEX methods."""

    def __init__(self, dex: DEXFile) -> None:
        self.dex = dex
        self.classes: Dict[str, DEXClass] = {}
        self.methods: Dict[int, DEXMethod] = {}
        self._disasm = DEXDisasm(dex)
        self._lifter = DEXLifter(dex, self._disasm)
        self._instruction_cache: Dict[int, Tuple[int, int, int, List[DEXInstruction]]] = {}
        self._parse_classes()

    @classmethod
    def from_apk(cls, path: str, dex_name: str = "classes.dex") -> "DEXDecompiler":
        from ablation.core.apk_parser import APKParser

        with APKParser.from_path(path) as apk:
            return cls(apk.read_dex(dex_name))

    def _proto(self, method_idx: int) -> Tuple[Tuple[str, ...], str]:
        _, proto_idx, _ = self.dex._method_ids[method_idx]
        params, returns = _proto_str(self.dex, proto_idx)
        return tuple(_split_proto_params(params)), returns

    def _parse_classes(self) -> None:
        data = self.dex._data
        for row in self.dex._class_defs_raw:
            class_idx, flags, super_idx, _, source_idx, _, class_data_off, _ = row
            class_name = self.dex.type_name(class_idx)
            dex_class = DEXClass(
                class_name=class_name,
                access_flags=flags,
                superclass=self.dex.type_name(super_idx),
                source_file=self.dex.string_at(source_idx) if source_idx != 0xFFFFFFFF else "",
            )
            self.classes[class_name] = dex_class
            if not class_data_off:
                continue
            off = class_data_off
            static_count, off = _uleb128(data, off)
            instance_count, off = _uleb128(data, off)
            direct_count, off = _uleb128(data, off)
            virtual_count, off = _uleb128(data, off)
            for is_static, count in ((True, static_count), (False, instance_count)):
                field_idx = 0
                for _ in range(count):
                    diff, off = _uleb128(data, off)
                    field_flags, off = _uleb128(data, off)
                    field_idx += diff
                    _, type_idx, name_idx = self.dex._field_ids[field_idx]
                    dex_class.fields.append(DEXField(
                        field_idx=field_idx,
                        class_name=class_name,
                        name=self.dex.string_at(name_idx),
                        type_desc=self.dex.type_name(type_idx),
                        access_flags=field_flags,
                        is_static=is_static,
                    ))
            for is_direct, count in ((True, direct_count), (False, virtual_count)):
                method_idx = 0
                for _ in range(count):
                    diff, off = _uleb128(data, off)
                    method_flags, off = _uleb128(data, off)
                    code_off, off = _uleb128(data, off)
                    method_idx += diff
                    _, _, name_idx = self.dex._method_ids[method_idx]
                    params, returns = self._proto(method_idx)
                    method = DEXMethod(
                        dex_name=self.dex.filename,
                        method_idx=method_idx,
                        class_name=class_name,
                        name=self.dex.string_at(name_idx),
                        access_flags=method_flags,
                        code_off=code_off,
                        param_types=params,
                        return_type=returns,
                        is_direct=is_direct,
                    )
                    dex_class.methods.append(method)
                    self.methods[method_idx] = method

    def iter_methods(self) -> Iterator[DEXMethod]:
        yield from self.methods.values()

    def iter_native_methods(self) -> Iterator[DEXMethod]:
        for method in self.methods.values():
            if method.is_native:
                yield method

    def method_ref(self, method_idx: int) -> str:
        if method_idx in self.methods:
            return self.methods[method_idx].descriptor
        if not 0 <= method_idx < len(self.dex._method_ids):
            return f"method@{method_idx}"
        class_idx, proto_idx, name_idx = self.dex._method_ids[method_idx]
        params, returns = _proto_str(self.dex, proto_idx)
        return f"{self.dex.type_name(class_idx)}->{self.dex.string_at(name_idx)}({params}){returns}"

    def instructions(self, method: DEXMethod | int) -> Tuple[int, int, int, List[DEXInstruction]]:
        method_idx = method if isinstance(method, int) else method.method_idx
        if method_idx not in self._instruction_cache:
            encoded = self.methods[method_idx]
            if not encoded.code_off:
                return 0, 0, 0, []
            self._instruction_cache[method_idx] = decode_code_item(self.dex, encoded.code_off)
        return self._instruction_cache[method_idx]

    def calls(self, method: DEXMethod | int) -> Iterator[DEXCall]:
        encoded = self.methods[method if isinstance(method, int) else method.method_idx]
        for insn in self.instructions(encoded)[3]:
            if insn.opcode not in (0x6E, 0x6F, 0x70, 0x71, 0x72, 0x74, 0x75, 0x76, 0x77, 0x78):
                continue
            yield DEXCall(
                caller_idx=encoded.method_idx,
                target_idx=insn.ref_idx,
                cu_offset=insn.cu_offset,
                opcode=insn.opcode,
                argument_regs=tuple(insn.regs),
                target=self.method_ref(insn.ref_idx),
            )

    def decompile_method(self, method: DEXMethod | int) -> str:
        encoded = self.methods[method if isinstance(method, int) else method.method_idx]
        declaration = encoded.declaration()
        if encoded.is_native:
            return declaration + ";"
        if encoded.is_abstract or not encoded.code_off:
            return declaration + ";"
        return self._lifter.lift_method(
            encoded.class_name,
            encoded.name,
            method_idx=encoded.method_idx,
            code_off=encoded.code_off,
            access_flags=encoded.access_flags,
        )

    def decompile_class(self, class_name: str) -> str:
        if not class_name.startswith("L"):
            class_name = "L" + class_name.replace(".", "/") + ";"
        if class_name not in self.classes:
            raise KeyError(class_name)
        dex_class = self.classes[class_name]
        package = class_name[1:-1].rsplit("/", 1)[0].replace("/", ".") if "/" in class_name[1:-1] else ""
        simple_name = class_name[1:-1].split("/")[-1].replace("$", ".")
        lines = [f"package {package};", ""] if package else []
        class_flags = access_string(dex_class.access_flags & ~0x0200)
        kind = "interface" if dex_class.access_flags & 0x0200 else "class"
        extends = ""
        if dex_class.superclass not in ("", "Ljava/lang/Object;", "<no_type>"):
            extends = f" extends {jtype(dex_class.superclass)}"
        lines.append(f"{class_flags + ' ' if class_flags else ''}{kind} {simple_name}{extends} {{")
        for dex_field in dex_class.fields:
            lines.append(f"    {dex_field.declaration(self.dex)}")
        for method in dex_class.methods:
            body = self.decompile_method(method)
            lines.extend("    " + line if line else "" for line in body.splitlines())
            lines.append("")
        lines.append("}")
        return "\n".join(lines)

    def decompile_all(self) -> Iterator[str]:
        for class_name in self.classes:
            yield self.decompile_class(class_name)
