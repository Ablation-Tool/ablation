"""
abc_parser.py -- HarmonyOS/ArkTS Ark Bytecode (ABC) file parser.

Parses the binary format defined by ArkCompiler's libpandafile (file.h).
Covers ABC versions 9–13; handles the v12.0.6.0 literal-array header boundary.

Two ABC dialects exist in the wild:
  DYNAMIC  -- ECMAScript/ArkTS runtime (e.g. wechat.abc, HAP modules.abc)
              method access_flags encoded as ULEB128
  STATIC   -- Typed ArkTS (older or compiled differently)
              method access_flags encoded as u32

This parser detects the dialect per-file and parses accordingly.

Usage:
    from ablation.analyzers.abc_parser import ABCParser

    with ABCParser.from_path("/path/to/modules.abc") as p:
        print(p.summary())
        for method in p.iter_methods():
            code = p.get_code(method)
            if code:
                print(method.fqn, code.code_size)
        for method in p.find_native_methods():
            print("native:", method.fqn)
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

# ── Binary constants ──────────────────────────────────────────────────────────

_MAGIC         = b"PANDA\x00\x00\x00"
_HEADER_SIZE   = 60  # 8 magic + 13 × uint32_t (verified from file.h struct Header)
_ENTITY_ID_MIN = _HEADER_SIZE  # EntityId.IsValid(): offset > sizeof(Header)

# Last version where num_literalarrays/literalarray_idx_off live in the fixed header.
# v13+ stores literal arrays only in the index section.
_LAST_LITARR_IN_HDR = (12, 0, 6, 0)

# ── Access flag constants (from modifiers.h) ──────────────────────────────────

ACC_PUBLIC    = 0x0001
ACC_PRIVATE   = 0x0002
ACC_PROTECTED = 0x0004
ACC_STATIC    = 0x0008
ACC_FINAL     = 0x0010
ACC_NATIVE    = 0x0100
ACC_ABSTRACT  = 0x0400

# ── ClassTag values (from abcclass/class_tag.py + C++ class_data_accessor) ───

_CTAG_NOTHING              = 0
_CTAG_INTERFACES           = 1
_CTAG_SOURCE_LANG          = 2
_CTAG_RUNTIME_ANNOTATION   = 3
_CTAG_ANNOTATION           = 4
_CTAG_RUNTIME_TYPE_ANNOT   = 5
_CTAG_TYPE_ANNOTATION      = 6
_CTAG_SOURCE_FILE          = 7

# ── FieldTag values ───────────────────────────────────────────────────────────

_FTAG_NOTHING              = 0
_FTAG_INT_VALUE            = 1   # payload: sleb128
_FTAG_VALUE                = 2   # payload: u32
_FTAG_RUNTIME_ANNOTATIONS  = 3   # payload: u32 offset (TODO: full decode)
_FTAG_ANNOTATIONS          = 4   # payload: u32 offset
_FTAG_RUNTIME_TYPE_ANNOT   = 5   # payload: u32 offset
_FTAG_TYPE_ANNOTATION      = 6   # payload: u32 offset

# ── MethodTag values (empirically verified + dayu method_tag.py) ─────────────

_MTAG_NOTHING              = 0
_MTAG_CODE                 = 1   # payload: u32 code_off
_MTAG_SOURCE_LANG          = 2   # payload: u8
_MTAG_RUNTIME_ANNOTATION   = 3   # payload: u32 offset
_MTAG_RUNTIME_PARAM_ANNOT  = 4   # payload: u32 offset
_MTAG_DEBUG_INFO           = 5   # payload: u32 offset
_MTAG_ANNOTATIONS          = 6   # payload: u32 offset
_MTAG_PARAM_ANNOTATION     = 7   # payload: u32 offset
_MTAG_TYPE_ANNOTATION      = 8   # payload: u32 offset
_MTAG_RUNTIME_TYPE_ANNOT   = 9   # payload: u32 offset

# Tags whose payload is exactly u32 (skip when not processing them)
_MTAG_U32_PAYLOAD = frozenset({
    _MTAG_CODE,
    _MTAG_RUNTIME_ANNOTATION, _MTAG_RUNTIME_PARAM_ANNOT,
    _MTAG_DEBUG_INFO, _MTAG_ANNOTATIONS, _MTAG_PARAM_ANNOTATION,
    _MTAG_TYPE_ANNOTATION, _MTAG_RUNTIME_TYPE_ANNOT,
})

# ── ULEB128 / SLEB128 decoders ────────────────────────────────────────────────

def _uleb128(data: bytes, pos: int) -> Tuple[int, int]:
    """Return (value, bytes_consumed).  Max 5 bytes (covers u32)."""
    result, shift, n = 0, 0, 0
    while n < 5:
        b = data[pos + n]
        result |= (b & 0x7f) << shift
        n += 1
        if not (b & 0x80):
            break
        shift += 7
    return result, n


def _sleb128(data: bytes, pos: int) -> Tuple[int, int]:
    """Return (signed_value, bytes_consumed)."""
    result, shift, n = 0, 0, 0
    b = 0
    while n < 5:
        b = data[pos + n]
        result |= (b & 0x7f) << shift
        n += 1
        shift += 7
        if not (b & 0x80):
            break
    if b & 0x40:
        result |= -(1 << shift)
    return result, n


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class ABCHeader:
    magic: bytes
    checksum: int
    version: Tuple[int, int, int, int]   # (major, minor, feat, build)
    file_size: int
    foreign_off: int
    foreign_size: int
    num_classes: int
    class_idx_off: int
    num_lnps: int
    lnp_idx_off: int
    num_literalarrays: int
    literalarray_idx_off: int
    num_indexes: int
    index_section_off: int

    @property
    def version_tuple(self) -> Tuple[int, int, int, int]:
        return self.version

    def has_literal_in_header(self) -> bool:
        """True for versions <= 12.0.6.0 which embed literalarray index in header."""
        return self.version <= _LAST_LITARR_IN_HDR


@dataclass
class ABCIndexHeader:
    """One region in the index section (IndexHeader in file.h)."""
    start: int
    end: int
    class_idx_size: int
    class_idx_off: int
    method_idx_size: int
    method_idx_off: int
    field_idx_size: int
    field_idx_off: int
    proto_idx_size: int
    proto_idx_off: int


@dataclass
class MethodInfo:
    entity_id: int        # file offset of method item (= position of class_idx field)
    class_name: str       # decoded class name string
    method_name: str      # decoded method name string
    class_idx: int        # u16 in the method item
    proto_idx: int        # u16 in the method item (0xffff = no prototype)
    access_flags: int     # decoded ULEB128 value
    code_off: int         # file offset of CodeItem; 0 = abstract/native (no bytecode)
    source_lang: int      # 0 = ECMAScript/ArkTS, 1 = Java; -1 = not present

    @property
    def fqn(self) -> str:
        """Fully-qualified name: ClassName.methodName"""
        return f"{self.class_name}.{self.method_name}"

    @property
    def is_native(self) -> bool:
        return bool(self.access_flags & ACC_NATIVE)

    @property
    def is_abstract(self) -> bool:
        return bool(self.access_flags & ACC_ABSTRACT)

    @property
    def is_static(self) -> bool:
        return bool(self.access_flags & ACC_STATIC)

    @property
    def has_code(self) -> bool:
        return self.code_off > _ENTITY_ID_MIN


@dataclass
class CodeItem:
    offset: int               # absolute file offset of this code item
    register_count: int       # total virtual registers (includes args)
    parameter_count: int      # argument count
    code_size: int            # bytecode byte count
    exception_handler_count: int
    bytecode: bytes           # raw bytecode[code_size]

    # Aliases for callers that used the old names
    @property
    def num_vregs(self) -> int:
        return self.register_count

    @property
    def num_args(self) -> int:
        return self.parameter_count


@dataclass
class FieldInfo:
    class_name: str
    field_name: str
    class_idx: int
    type_idx: int
    name_off: int


@dataclass
class ClassInfo:
    entity_id: int
    name: str
    access_flags: int
    num_fields: int
    num_methods: int
    source_lang: int    # from CLASS tagged values
    source_file: str    # from CLASS tagged values


# ── Parser ────────────────────────────────────────────────────────────────────

class ABCParser:
    """
    Zero-copy ABC file parser. Operates on the raw bytes buffer.

    Call from_path() or __init__(bytes) then use the public API.
    Acts as a context manager (no-op __exit__; provided for symmetry with
    other Ablation parsers).
    """

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._hdr  = self._parse_header()
        self._idx_headers: List[ABCIndexHeader] = self._load_index_headers()
        # Lazily populated on first access
        self._class_names: Optional[Dict[int, str]] = None   # entity_id → class name
        self._methods: Optional[List[MethodInfo]]   = None

    # ── Factory / context manager ─────────────────────────────────────────────

    @classmethod
    def from_path(cls, path: "str | Path") -> "ABCParser":
        return cls(Path(path).read_bytes())

    def __enter__(self) -> "ABCParser":
        return self

    def __exit__(self, *_) -> None:
        pass

    # ── Public header accessors ───────────────────────────────────────────────

    @property
    def header(self) -> ABCHeader:
        return self._hdr

    @property
    def version(self) -> Tuple[int, int, int, int]:
        return self._hdr.version

    def is_valid(self) -> bool:
        return self._data[:8] == _MAGIC and len(self._data) >= _HEADER_SIZE

    # ── Class names ───────────────────────────────────────────────────────────

    def _ensure_class_names(self) -> None:
        if self._class_names is not None:
            return
        self._class_names = {}
        for i in range(self._hdr.num_classes):
            eid = self._read_u32(self._hdr.class_idx_off + i * 4)
            if eid < _ENTITY_ID_MIN or eid >= len(self._data):
                continue
            name, _ = self._read_string(eid)
            self._class_names[eid] = name

    def get_class_name(self, entity_id: int) -> str:
        self._ensure_class_names()
        return self._class_names.get(entity_id, "")

    def iter_class_names(self) -> Iterator[Tuple[int, str]]:
        """Yield (entity_id, class_name) for all classes in the file."""
        self._ensure_class_names()
        yield from self._class_names.items()

    # ── String decoding ───────────────────────────────────────────────────────

    def get_string(self, offset: int) -> str:
        """Decode the MUTF-8 string at *offset* in the file."""
        if offset < _ENTITY_ID_MIN or offset >= len(self._data):
            return ""
        name, _ = self._read_string(offset)
        return name

    def resolve_class_idx(self, n: int, region: int = 0) -> str:
        """
        Resolve a class/string index N from IndexHeader[region].class_idx.

        In dynamic ABC, bytecode instruction operands of kind 'd' (entity ID)
        are NOT raw file offsets — they are INDICES into the per-region
        class_idx array.  E.g. lda.str N → class_idx[N] → entity_id → string.

        Returns the decoded string, or "" if N is out of range.
        """
        if region >= len(self._idx_headers):
            return ""
        ih = self._idx_headers[region]
        if n < 0 or n >= ih.class_idx_size:
            return ""
        eid = self._read_u32(ih.class_idx_off + n * 4)
        return self.get_string(eid)

    def resolve_method_idx(self, n: int, region: int = 0) -> str:
        """
        Resolve a property/global name index N from IndexHeader[region].method_idx.

        Property-access instructions (ldobjbyname, stobjbyname, tryldglobalbyname,
        stglobalvar, etc.) encode their 'd'-kind operand as an INDEX into the
        per-region method_idx array, which is separate from class_idx.
        method_idx[N] → entity_id → string offset → decoded name.

        Returns the decoded string, or "" if N is out of range.
        """
        if region >= len(self._idx_headers):
            return ""
        ih = self._idx_headers[region]
        if n < 0 or n >= ih.method_idx_size:
            return ""
        eid = self._read_u32(ih.method_idx_off + n * 4)
        return self.get_string(eid)

    def _read_string(self, off: int) -> Tuple[str, int]:
        """
        Returns (decoded_str, end_pos_after_null).
        String layout: uleb128(utf16_len) + bytes[utf16_len>>1] + 0x00
        char_count = utf16_len >> 1
        is_ascii   = utf16_len & 1
        """
        utf16_len, n = _uleb128(self._data, off)
        char_count = utf16_len >> 1
        pos = off + n
        raw = self._data[pos: pos + char_count]
        end = pos + char_count + 1  # +1 for null terminator
        try:
            return raw.decode("utf-8", errors="replace"), end
        except Exception:
            return raw.decode("latin-1", errors="replace"), end

    # ── Method iteration (primary API) ────────────────────────────────────────

    def iter_methods(self) -> Iterator[MethodInfo]:
        """
        Yield every MethodInfo in the file by walking all class bodies.

        Method items are stored inline in class bodies (after field items).
        Each method item:  class_idx(u16) + proto_idx(u16) + name_off(u32)
                           + access_flags(uleb128) + MethodTaggedValues
        """
        self._ensure_class_names()
        for eid in self._iter_class_entity_ids():
            yield from self._parse_class_methods(eid)

    def get_all_methods(self) -> List[MethodInfo]:
        """Return all MethodInfo objects, caching after first call."""
        if self._methods is None:
            self._methods = list(self.iter_methods())
        return self._methods

    # ── Code item ─────────────────────────────────────────────────────────────

    def get_code(self, method: "MethodInfo | int") -> Optional[CodeItem]:
        """
        Return the CodeItem for *method* (MethodInfo or raw code_off).
        Returns None if no code exists (abstract, native, or invalid offset).

        CodeItem layout (all ULEB128 — confirmed from ark-rs bytecode.rs):
          register_count(uleb) + parameter_count(uleb) + code_size(uleb)
          + exception_handler_count(uleb) + bytecode[code_size]
          + exception_handler_records[exception_handler_count]
        """
        code_off = method.code_off if isinstance(method, MethodInfo) else method
        if code_off < _ENTITY_ID_MIN or code_off >= len(self._data):
            return None
        d = self._data
        pos = code_off
        try:
            register_count, n = _uleb128(d, pos); pos += n
            parameter_count, n = _uleb128(d, pos); pos += n
            code_size, n       = _uleb128(d, pos); pos += n
            exc_count, n       = _uleb128(d, pos); pos += n
        except (IndexError, struct.error):
            return None
        end = pos + code_size
        if end > len(d):
            return None
        return CodeItem(
            offset=code_off,
            register_count=register_count,
            parameter_count=parameter_count,
            code_size=code_size,
            exception_handler_count=exc_count,
            bytecode=d[pos:end],
        )

    # ── Security-oriented query methods ──────────────────────────────────────

    def find_native_methods(self) -> List[MethodInfo]:
        """Return methods declared with ACC_NATIVE (no bytecode, FFI boundary)."""
        return [m for m in self.get_all_methods() if m.is_native]

    def find_methods_by_name(self, name_substr: str) -> List[MethodInfo]:
        """Return methods whose name contains *name_substr* (case-sensitive)."""
        return [m for m in self.get_all_methods() if name_substr in m.method_name]

    def find_methods_in_class(self, class_substr: str) -> List[MethodInfo]:
        """Return methods whose class name contains *class_substr*."""
        return [m for m in self.get_all_methods() if class_substr in m.class_name]

    def find_string_refs_in_code(self, pattern: str) -> List[Tuple[MethodInfo, str]]:
        """
        Scan all string literals reachable from literal arrays and method code
        for strings containing *pattern*.  Returns [(method, matched_string), ...].

        This is a best-effort scan based on string entity IDs embedded in code.
        A full implementation requires the disassembler (abc_disasm.py) to resolve
        lda.str/lda.const operands.
        """
        matches: List[Tuple[MethodInfo, str]] = []
        for method in self.get_all_methods():
            code = self.get_code(method)
            if not code:
                continue
            for s in self._scan_string_refs_in_bytecode(code.bytecode,
                                                         code.offset + 10):
                if pattern in s:
                    matches.append((method, s))
        return matches

    def iter_class_info(self) -> Iterator[ClassInfo]:
        """Yield ClassInfo for each class (metadata only, no methods/fields)."""
        self._ensure_class_names()
        for eid in self._iter_class_entity_ids():
            info = self._parse_class_info(eid)
            if info:
                yield info

    # ── Summary ───────────────────────────────────────────────────────────────

    def summary(self) -> Dict:
        """Return a dict suitable for Ablation's finding schema."""
        methods = self.get_all_methods()
        with_code = [m for m in methods if m.has_code]
        native    = [m for m in methods if m.is_native]
        return {
            "format": "ABC",
            "version": ".".join(str(v) for v in self._hdr.version),
            "file_size": self._hdr.file_size,
            "num_classes": self._hdr.num_classes,
            "num_literalarrays": self._hdr.num_literalarrays,
            "num_methods_total": len(methods),
            "num_methods_with_code": len(with_code),
            "num_native_methods": len(native),
            "num_index_regions": self._hdr.num_indexes,
        }

    # ── Internal: header / index parsing ─────────────────────────────────────

    def _parse_header(self) -> ABCHeader:
        d = self._data
        if len(d) < _HEADER_SIZE:
            raise ValueError(f"ABC data too short ({len(d)} < {_HEADER_SIZE})")
        if d[:8] != _MAGIC:
            raise ValueError(f"Bad ABC magic: {d[:8]!r}")
        (checksum,) = struct.unpack_from("<I", d, 8)
        ver_bytes   = d[12:16]
        ver         = (ver_bytes[0], ver_bytes[1], ver_bytes[2], ver_bytes[3])
        (
            file_size, foreign_off, foreign_size,
            num_classes, class_idx_off,
            num_lnps, lnp_idx_off,
            num_lits, litarr_idx_off,
            num_idx, idx_section_off,
        ) = struct.unpack_from("<11I", d, 16)
        return ABCHeader(
            magic=d[:8],
            checksum=checksum,
            version=ver,
            file_size=file_size,
            foreign_off=foreign_off,
            foreign_size=foreign_size,
            num_classes=num_classes,
            class_idx_off=class_idx_off,
            num_lnps=num_lnps,
            lnp_idx_off=lnp_idx_off,
            num_literalarrays=num_lits,
            literalarray_idx_off=litarr_idx_off,
            num_indexes=num_idx,
            index_section_off=idx_section_off,
        )

    def _load_index_headers(self) -> List[ABCIndexHeader]:
        out = []
        off = self._hdr.index_section_off
        for _ in range(self._hdr.num_indexes):
            if off + 40 > len(self._data):
                break
            fields = struct.unpack_from("<10I", self._data, off)
            out.append(ABCIndexHeader(*fields))
            off += 40
        return out

    # ── Internal: class walking ───────────────────────────────────────────────

    def _iter_class_entity_ids(self) -> Iterator[int]:
        hdr = self._hdr
        for i in range(hdr.num_classes):
            eid = self._read_u32(hdr.class_idx_off + i * 4)
            if eid >= _ENTITY_ID_MIN and eid < len(self._data):
                yield eid

    def _parse_class_info(self, eid: int) -> Optional[ClassInfo]:
        """Parse class metadata without descending into fields/methods."""
        try:
            pos = eid
            name, pos = self._read_string(pos)
            reserved  = self._read_u32(pos); pos += 4
            acc, n    = _uleb128(self._data, pos); pos += n
            nf,  n    = _uleb128(self._data, pos); pos += n
            nm,  n    = _uleb128(self._data, pos); pos += n
            src_lang = -1
            src_file = ""
            # ClassTaggedValues
            while pos < len(self._data):
                tag = self._data[pos]; pos += 1
                if tag == _CTAG_NOTHING:
                    break
                elif tag == _CTAG_SOURCE_LANG:
                    src_lang = self._data[pos]; pos += 1
                elif tag == _CTAG_SOURCE_FILE:
                    src_file = self.get_string(self._read_u32(pos))
                    pos += 4
                elif tag == _CTAG_INTERFACES:
                    n_iface, n = _uleb128(self._data, pos); pos += n
                    pos += n_iface * 2
                elif tag in (_CTAG_RUNTIME_ANNOTATION, _CTAG_ANNOTATION,
                             _CTAG_RUNTIME_TYPE_ANNOT, _CTAG_TYPE_ANNOTATION):
                    pos += 4  # skip u32 offset
                else:
                    break  # unknown tag, bail
            return ClassInfo(
                entity_id=eid, name=name, access_flags=acc,
                num_fields=nf, num_methods=nm,
                source_lang=src_lang, source_file=src_file,
            )
        except (IndexError, struct.error):
            return None

    def _parse_class_methods(self, eid: int) -> Iterator[MethodInfo]:
        """
        Walk one class body, skipping over fields, then parse each method item.
        Yields MethodInfo for every method in this class.
        """
        try:
            pos = eid
            # 1. class name (consume the string to advance pos)
            class_name, pos = self._read_string(pos)
            # 2. reserved u32
            pos += 4
            # 3. access_flags uleb
            _, n = _uleb128(self._data, pos); pos += n
            # 4. num_fields uleb
            num_fields, n = _uleb128(self._data, pos); pos += n
            # 5. num_methods uleb
            num_methods, n = _uleb128(self._data, pos); pos += n
            # 6. ClassTaggedValues
            pos = self._skip_class_tags(pos)
            # 7. Field items × num_fields
            pos = self._skip_fields(pos, num_fields)
            # 8. Method items × num_methods
            for _ in range(num_methods):
                m, pos = self._parse_one_method(pos, class_name)
                if m:
                    yield m
        except (IndexError, struct.error):
            return

    def _skip_class_tags(self, pos: int) -> int:
        d = self._data
        while pos < len(d):
            tag = d[pos]; pos += 1
            if tag == _CTAG_NOTHING:
                break
            elif tag == _CTAG_SOURCE_LANG:
                pos += 1
            elif tag == _CTAG_SOURCE_FILE:
                pos += 4
            elif tag == _CTAG_INTERFACES:
                n_iface, n = _uleb128(d, pos); pos += n
                pos += n_iface * 2
            elif tag in (_CTAG_RUNTIME_ANNOTATION, _CTAG_ANNOTATION,
                         _CTAG_RUNTIME_TYPE_ANNOT, _CTAG_TYPE_ANNOTATION):
                pos += 4
            else:
                break
        return pos

    def _skip_fields(self, pos: int, count: int) -> int:
        """
        Skip *count* FieldItems.
        Field12 layout: class_idx(u16) + type_idx(u16) + name_off(u32)
                        + reserved(uleb128) + FieldTaggedValues
        """
        d = self._data
        for _ in range(count):
            pos += 8  # class_idx(2) + type_idx(2) + name_off(4)
            _, n = _uleb128(d, pos); pos += n  # reserved
            # FieldTaggedValues until NOTHING
            while pos < len(d):
                tag = d[pos]; pos += 1
                if tag == _FTAG_NOTHING:
                    break
                elif tag == _FTAG_INT_VALUE:
                    _, n = _sleb128(d, pos); pos += n
                elif tag == _FTAG_VALUE:
                    pos += 4
                elif tag in (_FTAG_RUNTIME_ANNOTATIONS, _FTAG_ANNOTATIONS,
                             _FTAG_RUNTIME_TYPE_ANNOT, _FTAG_TYPE_ANNOTATION):
                    pos += 4
                else:
                    break
        return pos

    def _parse_one_method(self, pos: int,
                          class_name: str) -> Tuple[Optional[MethodInfo], int]:
        """
        Parse one MethodItem inline in the class body at *pos*.

        Layout: class_idx(u16) + proto_idx(u16) + name_off(u32)
                + access_flags(uleb128) + MethodTaggedValues
        """
        d = self._data
        start = pos
        class_idx = self._read_u16(pos); pos += 2
        proto_idx  = self._read_u16(pos); pos += 2
        name_off   = self._read_u32(pos); pos += 4
        access_flags, n = _uleb128(d, pos); pos += n

        method_name = self.get_string(name_off)

        code_off   = 0
        source_lang = -1

        while pos < len(d):
            tag = d[pos]; pos += 1
            if tag == _MTAG_NOTHING:
                break
            elif tag == _MTAG_CODE:
                code_off = self._read_u32(pos); pos += 4
            elif tag == _MTAG_SOURCE_LANG:
                source_lang = d[pos]; pos += 1
            elif tag in _MTAG_U32_PAYLOAD:
                pos += 4  # skip annotation/debug-info offsets
            else:
                # Unknown tag: bail out of this method's tag list.
                # Roll back one byte so the outer loop sees a sane position.
                pos -= 1
                break

        info = MethodInfo(
            entity_id=start,
            class_name=class_name,
            method_name=method_name,
            class_idx=class_idx,
            proto_idx=proto_idx,
            access_flags=access_flags,
            code_off=code_off,
            source_lang=source_lang,
        )
        return info, pos

    # ── Internal: string scanning in bytecode ─────────────────────────────────

    def _scan_string_refs_in_bytecode(self,
                                       bytecode: bytes,
                                       base_offset: int) -> Iterator[str]:
        """
        Best-effort string-ref scan: walks the raw bytes looking for
        u32 values that fall within the file's string-storage region
        and resolve to printable strings.  Used by find_string_refs_in_code().

        A proper implementation belongs in abc_disasm.py (opcode-aware scan).
        This approximation catches the majority of string literals.
        """
        file_len = len(self._data)
        # String region: everything above header and below literalarray_idx_off
        # (where all the string data lives in practice)
        str_lo = _ENTITY_ID_MIN
        str_hi = min(self._hdr.file_size, file_len)

        i = 0
        while i + 4 <= len(bytecode):
            candidate = struct.unpack_from("<I", bytecode, i)[0]
            if str_lo <= candidate < str_hi:
                try:
                    s, _ = self._read_string(candidate)
                    # Filter: keep printable ASCII strings >= 4 chars
                    if len(s) >= 4 and all(0x20 <= ord(c) < 0x7f for c in s):
                        yield s
                except (IndexError, UnicodeDecodeError):
                    pass
            i += 1

    # ── Internal: raw read helpers ────────────────────────────────────────────

    def _read_u16(self, off: int) -> int:
        return struct.unpack_from("<H", self._data, off)[0]

    def _read_u32(self, off: int) -> int:
        return struct.unpack_from("<I", self._data, off)[0]
