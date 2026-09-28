#!/usr/bin/env python3
"""
apk_parser.py -- Zero-dependency APK, AXML, and DEX format parser.

Covers:
  APK  — ZIP container; manifest, DEX files, native lib inventory, assets
  AXML — Android binary XML (chunk type 0x0003); used in AndroidManifest.xml
  DEX  — Dalvik Executable format (magic dex\\n035\\0 through dex\\n041\\0)

No external dependencies beyond Python stdlib (zipfile, struct, dataclasses).

Usage:
    from ablation.core.apk_parser import APKParser

    apk = APKParser.from_path('/path/to/app.apk')
    mf  = apk.parse_manifest()
    print(mf.package, mf.version_name)
    for p in mf.permissions:
        print(p)

    for dx in apk.iter_dex():
        print(dx.filename, dx.method_count, 'methods')
        for m in dx.iter_method_refs():
            if 'crypto' in m.class_name.lower():
                print(m)
"""

from __future__ import annotations

import re
import struct
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Generator, Iterator, List, Optional, Tuple


# ── AXML constants ────────────────────────────────────────────────────────────

_CHUNK_STRING_POOL   = 0x0001
_CHUNK_XML           = 0x0003
_CHUNK_RESOURCE_MAP  = 0x0180
_CHUNK_XML_START_NS  = 0x0100
_CHUNK_XML_END_NS    = 0x0101
_CHUNK_XML_START_ELM = 0x0102
_CHUNK_XML_END_ELM   = 0x0103
_CHUNK_XML_TEXT      = 0x0104

_FLAG_UTF8           = 0x00000100  # string pool uses UTF-8 instead of UTF-16LE

# Attribute value types
_AVAL_NULL      = 0x00
_AVAL_REFERENCE = 0x01
_AVAL_ATTRIBUTE = 0x02
_AVAL_STRING    = 0x03
_AVAL_FLOAT     = 0x04
_AVAL_INT_DEC   = 0x10
_AVAL_INT_HEX   = 0x11
_AVAL_BOOLEAN   = 0x12

# DEX constants
_DEX_MAGIC_PREFIX = b"dex\n"
_DEX_ENDIAN_CONST = 0x12345678

# Access flag masks (shared DEX / AXML uses-permission flags)
_ACC_PUBLIC    = 0x0001
_ACC_PRIVATE   = 0x0002
_ACC_PROTECTED = 0x0004
_ACC_STATIC    = 0x0008
_ACC_FINAL     = 0x0010
_ACC_NATIVE    = 0x0100  # method-level: declared native (no DEX code_item)
_ACC_INTERFACE = 0x0200
_ACC_ABSTRACT  = 0x0400
_ACC_SYNTHETIC = 0x1000
_ACC_ANNOTATION= 0x2000
_ACC_ENUM      = 0x4000


# ── Manifest dataclasses ──────────────────────────────────────────────────────

@dataclass
class ComponentInfo:
    tag: str                   # activity / service / receiver / provider
    name: str
    exported: Optional[bool]
    permission: Optional[str]
    intent_filters: List[str] = field(default_factory=list)

    def is_exported_or_implicit(self) -> bool:
        if self.exported is True:
            return True
        if self.exported is None and self.intent_filters:
            return True
        return False


@dataclass
class ManifestInfo:
    package: str
    version_name: str
    version_code: int
    min_sdk: int
    target_sdk: int
    permissions: List[str] = field(default_factory=list)
    declared_permissions: List[str] = field(default_factory=list)
    components: List[ComponentInfo] = field(default_factory=list)
    network_security_config: Optional[str] = None
    debuggable: bool = False
    allow_backup: bool = True
    uses_cleartext_traffic: bool = False

    def exported_components(self) -> List[ComponentInfo]:
        return [c for c in self.components if c.is_exported_or_implicit()]

    def dangerous_permissions(self) -> List[str]:
        danger = {
            "android.permission.READ_CONTACTS",
            "android.permission.WRITE_CONTACTS",
            "android.permission.READ_CALL_LOG",
            "android.permission.WRITE_CALL_LOG",
            "android.permission.PROCESS_OUTGOING_CALLS",
            "android.permission.READ_SMS",
            "android.permission.SEND_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.RECEIVE_WAP_PUSH",
            "android.permission.RECEIVE_MMS",
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.WRITE_EXTERNAL_STORAGE",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.ACCESS_BACKGROUND_LOCATION",
            "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO",
            "android.permission.READ_PHONE_STATE",
            "android.permission.CALL_PHONE",
            "android.permission.GET_ACCOUNTS",
            "android.permission.BODY_SENSORS",
            "android.permission.BLUETOOTH_SCAN",
            "android.permission.BLUETOOTH_CONNECT",
            "android.permission.UWB_RANGING",
            "android.permission.MANAGE_EXTERNAL_STORAGE",
            "android.permission.INSTALL_PACKAGES",
            "android.permission.DELETE_PACKAGES",
            "android.permission.CHANGE_WIFI_STATE",
            "android.permission.READ_PRIVILEGED_PHONE_STATE",
        }
        return [p for p in self.permissions if p in danger]


# ── DEX dataclasses ───────────────────────────────────────────────────────────

@dataclass
class NativeMethod:
    """A method declared native (ACC_NATIVE) in class_data_item."""
    class_name: str
    method_name: str
    proto_shorty: str
    method_idx: int
    is_abstract: bool
    has_code: bool   # code_off != 0; native methods have code_off==0


@dataclass
class MethodRef:
    class_name: str    # e.g. "Landroid/util/Log;"  (descriptor form)
    method_name: str
    proto_shorty: str  # e.g. "VLjava/lang/String;"

    def __str__(self) -> str:
        return f"{self.class_name}->{self.method_name}({self.proto_shorty})"


@dataclass
class FieldRef:
    class_name: str
    field_name: str
    type_desc: str


@dataclass
class ClassDef:
    class_name: str
    access_flags: int
    superclass: str
    source_file: str

    def access_str(self) -> str:
        parts = []
        if self.access_flags & _ACC_PUBLIC:    parts.append("public")
        if self.access_flags & _ACC_PRIVATE:   parts.append("private")
        if self.access_flags & _ACC_ABSTRACT:  parts.append("abstract")
        if self.access_flags & _ACC_INTERFACE: parts.append("interface")
        if self.access_flags & _ACC_FINAL:     parts.append("final")
        if self.access_flags & _ACC_ENUM:      parts.append("enum")
        return " ".join(parts)


@dataclass
class DEXFile:
    filename: str
    version: str           # e.g. "035"
    file_size: int
    string_count: int
    type_count: int
    method_count: int
    field_count: int
    class_count: int
    _data: bytes = field(repr=False)
    _str_offsets: List[int] = field(repr=False, default_factory=list)
    _type_ids: List[int] = field(repr=False, default_factory=list)
    _proto_ids: List[Tuple[int,int,int]] = field(repr=False, default_factory=list)
    _method_ids: List[Tuple[int,int,int]] = field(repr=False, default_factory=list)
    _field_ids: List[Tuple[int,int,int]] = field(repr=False, default_factory=list)
    _class_defs_raw: List[Tuple] = field(repr=False, default_factory=list)

    # ── string access ──────────────────────────────────────────────────────

    def string_at(self, idx: int) -> str:
        if idx < 0 or idx >= len(self._str_offsets):
            return f"<str#{idx}>"
        return _dex_read_string(self._data, self._str_offsets[idx])

    def iter_strings(self) -> Iterator[str]:
        for off in self._str_offsets:
            yield _dex_read_string(self._data, off)

    # ── type / class name ──────────────────────────────────────────────────

    def type_name(self, idx: int) -> str:
        if idx == 0xFFFFFFFF or idx >= len(self._type_ids):
            return "<no_type>"
        return self.string_at(self._type_ids[idx])

    # ── method / field iteration ───────────────────────────────────────────

    def iter_method_refs(self) -> Iterator[MethodRef]:
        for class_idx, proto_idx, name_idx in self._method_ids:
            class_name  = self.type_name(class_idx)
            method_name = self.string_at(name_idx)
            shorty      = self.string_at(self._proto_ids[proto_idx][0]) if proto_idx < len(self._proto_ids) else ""
            yield MethodRef(class_name, method_name, shorty)

    def iter_field_refs(self) -> Iterator[FieldRef]:
        for class_idx, type_idx, name_idx in self._field_ids:
            yield FieldRef(
                class_name = self.type_name(class_idx),
                field_name = self.string_at(name_idx),
                type_desc  = self.type_name(type_idx),
            )

    def iter_classes(self) -> Iterator[ClassDef]:
        for row in self._class_defs_raw:
            (class_idx, access_flags, super_idx,
             _ifaces_off, src_idx, _ann_off, _data_off, _sv_off) = row
            yield ClassDef(
                class_name   = self.type_name(class_idx),
                access_flags = access_flags,
                superclass   = self.type_name(super_idx),
                source_file  = self.string_at(src_idx) if src_idx != 0xFFFFFFFF else "",
            )

    def iter_native_methods(self) -> Iterator[NativeMethod]:
        """
        Parse class_data_item for each ClassDef and yield methods with ACC_NATIVE set.

        Parses the encoded_method ULEB128 triples (method_idx_diff, access_flags, code_off)
        for both direct and virtual method arrays. Skips classes with class_data_off == 0.
        """
        for row in self._class_defs_raw:
            (class_idx, _cls_flags, _super_idx,
             _ifaces_off, _src_idx, _ann_off, data_off, _sv_off) = row
            if not data_off:
                continue
            class_name = self.type_name(class_idx)
            try:
                yield from self._parse_class_data(data_off, class_name)
            except Exception:
                pass

    def _parse_class_data(self, off: int, class_name: str) -> Iterator[NativeMethod]:
        data = self._data
        # four ULEB128 counts
        sf_size, off  = _uleb128(data, off)
        if_size, off  = _uleb128(data, off)
        dm_size, off  = _uleb128(data, off)
        vm_size, off  = _uleb128(data, off)

        # skip encoded_field arrays (field_idx_diff + access_flags each)
        for _ in range(sf_size + if_size):
            _, off = _uleb128(data, off)  # field_idx_diff
            _, off = _uleb128(data, off)  # access_flags

        # direct_methods and virtual_methods each use method_idx_diff relative
        # to the previous entry WITHIN their own array (not across the boundary).
        # The running index MUST reset to 0 between the two arrays.
        for dm_count in (dm_size, vm_size):
            running_idx = 0
            for _ in range(dm_count):
                idx_diff, off = _uleb128(data, off)
                flags, off    = _uleb128(data, off)
                code_off, off = _uleb128(data, off)
                running_idx += idx_diff
                if flags & _ACC_NATIVE:
                    method_name, shorty = self._method_info(running_idx)
                    yield NativeMethod(
                        class_name   = class_name,
                        method_name  = method_name,
                        proto_shorty = shorty,
                        method_idx   = running_idx,
                        is_abstract  = bool(flags & _ACC_ABSTRACT),
                        has_code     = code_off != 0,
                    )

    def _method_info(self, method_idx: int) -> Tuple[str, str]:
        if method_idx >= len(self._method_ids):
            return (f"<method#{method_idx}>", "")
        _class_idx, proto_idx, name_idx = self._method_ids[method_idx]
        name   = self.string_at(name_idx)
        shorty = self.string_at(self._proto_ids[proto_idx][0]) if proto_idx < len(self._proto_ids) else ""
        return name, shorty


# ── AXML parser internals ─────────────────────────────────────────────────────

def _sp_read_utf8(data: bytes, off: int) -> str:
    """Read one UTF-8 string from a UTF-8 string pool at given offset."""
    # Two ULEB128 lengths: first = char_count (utf16), second = byte_count (utf8)
    _char_len, off = _uleb128(data, off)
    byte_len, off  = _uleb128(data, off)
    raw = data[off : off + byte_len]
    return raw.decode("utf-8", errors="replace")


def _sp_read_utf16(data: bytes, off: int) -> str:
    """Read one UTF-16LE string from a UTF-16 string pool at given offset."""
    length = struct.unpack_from("<H", data, off)[0]
    off += 2
    raw = data[off : off + length * 2]
    return raw.decode("utf-16-le", errors="replace")


def _axml_read_string_pool(data: bytes, base: int) -> Tuple[List[str], int]:
    """
    Parse a STRING_POOL chunk starting at base.
    Returns (strings_list, chunk_end_offset).
    """
    # chunk header: type(2) + header_size(2) + chunk_size(4) + string_count(4) + ...
    header_size = struct.unpack_from("<H", data, base + 2)[0]
    chunk_size  = struct.unpack_from("<I", data, base + 4)[0]

    string_count  = struct.unpack_from("<I", data, base +  8)[0]
    _style_count  = struct.unpack_from("<I", data, base + 12)[0]
    flags         = struct.unpack_from("<I", data, base + 16)[0]
    strings_start = struct.unpack_from("<I", data, base + 20)[0]

    offsets_base = base + header_size
    strings_base = base + strings_start  # relative to chunk start, not file start
    # Actually strings_start is relative to the string pool header start
    strings_base = base + 8 + strings_start  # after the fixed ResStringPool_header
    # Per AOSP: strings_start is offset from beginning of the chunk body (after the u16 type/header_size/chunk_size trio)
    # Correct: strings_start is from start of the ResStringPool_header (which starts at base)
    strings_base = base + strings_start

    utf8 = bool(flags & _FLAG_UTF8)
    strings: List[str] = []

    for i in range(string_count):
        off_idx = offsets_base + i * 4
        if off_idx + 4 > len(data):
            strings.append("")
            continue
        rel_off = struct.unpack_from("<I", data, off_idx)[0]
        abs_off = strings_base + rel_off
        if abs_off >= len(data):
            strings.append("")
            continue
        if utf8:
            strings.append(_sp_read_utf8(data, abs_off))
        else:
            strings.append(_sp_read_utf16(data, abs_off))

    return strings, base + chunk_size


def _aval_to_str(val_type: int, val_data: int, strings: List[str]) -> str:
    if val_type == _AVAL_STRING:
        return strings[val_data] if val_data < len(strings) else f"<str#{val_data}>"
    if val_type == _AVAL_BOOLEAN:
        return "true" if val_data else "false"
    if val_type == _AVAL_INT_DEC:
        return str(val_data)
    if val_type == _AVAL_INT_HEX:
        return hex(val_data)
    if val_type in (_AVAL_REFERENCE, _AVAL_ATTRIBUTE):
        return f"@{val_data:#010x}"
    if val_type == _AVAL_NULL:
        return ""
    return f"[type={val_type:#x} data={val_data:#010x}]"


def _parse_axml(data: bytes) -> Dict:
    """
    Parse a complete binary AXML buffer.
    Returns a tree of dicts: {"tag": name, "attrs": {}, "children": [...]}
    Raises ValueError on invalid magic.
    """
    if len(data) < 8:
        raise ValueError("AXML too short")
    chunk_type = struct.unpack_from("<H", data, 0)[0]
    if chunk_type != _CHUNK_XML:
        raise ValueError(f"Not an XML chunk: {chunk_type:#x}")

    strings: List[str] = []
    pos = 8  # skip outer XML chunk header (type + header_size + chunk_size)

    # --- scan chunks ---
    root: Optional[Dict] = None
    stack: List[Dict]    = []

    while pos < len(data) - 7:
        ctype = struct.unpack_from("<H", data, pos)[0]
        cheader = struct.unpack_from("<H", data, pos + 2)[0]
        csize  = struct.unpack_from("<I", data, pos + 4)[0]
        if csize < 8 or pos + csize > len(data):
            break

        if ctype == _CHUNK_STRING_POOL:
            strings, _ = _axml_read_string_pool(data, pos)

        elif ctype in (_CHUNK_XML_START_NS, _CHUNK_XML_END_NS):
            pass  # namespace mapping not needed for manifest parsing

        elif ctype == _CHUNK_XML_START_ELM:
            # body starts after 8-byte chunk header
            body = pos + 8
            _line  = struct.unpack_from("<I", data, body)[0]
            _comm  = struct.unpack_from("<I", data, body + 4)[0]
            ns_idx = struct.unpack_from("<I", data, body + 8)[0]
            nm_idx = struct.unpack_from("<I", data, body + 12)[0]

            _attr_start = struct.unpack_from("<H", data, body + 16)[0]
            _attr_size  = struct.unpack_from("<H", data, body + 18)[0]
            attr_count  = struct.unpack_from("<H", data, body + 20)[0]

            tag_name = strings[nm_idx] if nm_idx < len(strings) else f"<tag#{nm_idx}>"
            node: Dict = {"tag": tag_name, "attrs": {}, "children": []}

            # ResXMLTree_attrExt starts at body+8; attributeStart is relative to it
            attr_base = body + 8 + _attr_start
            for i in range(attr_count):
                ap = attr_base + i * 20
                if ap + 20 > len(data):
                    break
                _a_ns     = struct.unpack_from("<I", data, ap)[0]
                a_name_i  = struct.unpack_from("<I", data, ap + 4)[0]
                _a_raw    = struct.unpack_from("<I", data, ap + 8)[0]
                a_val_sz  = struct.unpack_from("<H", data, ap + 12)[0]
                _a_res0   = data[ap + 14]
                a_val_typ = data[ap + 15]
                a_val_dat = struct.unpack_from("<I", data, ap + 16)[0]

                attr_name = strings[a_name_i] if a_name_i < len(strings) else f"<attr#{a_name_i}>"
                attr_val  = _aval_to_str(a_val_typ, a_val_dat, strings)
                node["attrs"][attr_name] = attr_val

            if stack:
                stack[-1]["children"].append(node)
            else:
                root = node
            stack.append(node)

        elif ctype == _CHUNK_XML_END_ELM:
            if stack:
                stack.pop()

        pos += csize

    return root or {}


# ── Manifest builder from AXML tree ─────────────────────────────────────────

def _attr(node: Dict, *names: str, default: str = "") -> str:
    for n in names:
        v = node["attrs"].get(n)
        if v is not None:
            return v
    return default


def _build_manifest(tree: Dict) -> ManifestInfo:
    mf = ManifestInfo(
        package      = _attr(tree, "package"),
        version_name = _attr(tree, "versionName"),
        version_code = int(_attr(tree, "versionCode", default="0") or "0"),
        min_sdk      = 0,
        target_sdk   = 0,
    )

    def walk(node: Dict, parent_tag: str = "") -> None:
        tag = node.get("tag", "")
        attrs = node.get("attrs", {})

        if tag == "uses-permission":
            name = _attr(node, "name")
            if name:
                mf.permissions.append(name)

        elif tag == "permission":
            name = _attr(node, "name")
            if name:
                mf.declared_permissions.append(name)

        elif tag == "uses-sdk":
            min_v = _attr(node, "minSdkVersion")
            tgt_v = _attr(node, "targetSdkVersion")
            if min_v.lstrip("-").isdigit():
                mf.min_sdk = int(min_v)
            if tgt_v.lstrip("-").isdigit():
                mf.target_sdk = int(tgt_v)

        elif tag == "application":
            dbg = _attr(node, "debuggable")
            mf.debuggable = dbg == "true"
            bak = _attr(node, "allowBackup", default="true")
            mf.allow_backup = bak != "false"
            clr = _attr(node, "usesCleartextTraffic")
            mf.uses_cleartext_traffic = clr == "true"

        elif tag in ("activity", "service", "receiver", "provider"):
            name = _attr(node, "name")
            exp_str = attrs.get("exported")
            exported: Optional[bool] = None
            if exp_str == "true":
                exported = True
            elif exp_str == "false":
                exported = False

            perm = _attr(node, "permission") or None
            comp = ComponentInfo(tag=tag, name=name, exported=exported, permission=perm)

            # collect intent filter actions
            for child in node.get("children", []):
                if child.get("tag") == "intent-filter":
                    for sub in child.get("children", []):
                        if sub.get("tag") == "action":
                            act = _attr(sub, "name")
                            if act:
                                comp.intent_filters.append(act)

            mf.components.append(comp)

        for child in node.get("children", []):
            walk(child, tag)

    walk(tree)
    return mf


# ── DEX parser internals ─────────────────────────────────────────────────────

def _uleb128(data: bytes, off: int) -> Tuple[int, int]:
    """Read a ULEB128 integer from data at offset. Returns (value, next_offset)."""
    result = 0
    shift  = 0
    while True:
        b = data[off]
        off += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
    return result, off


def _dex_read_string(data: bytes, off: int) -> str:
    """Read a DEX string (ULEB128 utf16_len + UTF-8 bytes + null)."""
    _utf16_len, off = _uleb128(data, off)
    end = data.index(b'\x00', off)
    raw = data[off:end]
    return raw.decode("utf-8", errors="replace")


def _parse_dex(data: bytes, filename: str = "classes.dex") -> DEXFile:
    """
    Parse a single DEX file buffer.
    Raises ValueError on bad magic or unsupported endianness.
    """
    if not data.startswith(_DEX_MAGIC_PREFIX):
        raise ValueError(f"Not a DEX file: {data[:8]!r}")
    version = data[4:7].decode("ascii", errors="replace")

    endian = struct.unpack_from("<I", data, 40)[0]
    if endian != _DEX_ENDIAN_CONST:
        raise ValueError(f"Big-endian or corrupt DEX not supported: {endian:#010x}")

    file_size        = struct.unpack_from("<I", data, 32)[0]
    string_ids_size  = struct.unpack_from("<I", data, 56)[0]
    string_ids_off   = struct.unpack_from("<I", data, 60)[0]
    type_ids_size    = struct.unpack_from("<I", data, 64)[0]
    type_ids_off     = struct.unpack_from("<I", data, 68)[0]
    proto_ids_size   = struct.unpack_from("<I", data, 72)[0]
    proto_ids_off    = struct.unpack_from("<I", data, 76)[0]
    field_ids_size   = struct.unpack_from("<I", data, 80)[0]
    field_ids_off    = struct.unpack_from("<I", data, 84)[0]
    method_ids_size  = struct.unpack_from("<I", data, 88)[0]
    method_ids_off   = struct.unpack_from("<I", data, 92)[0]
    class_defs_size  = struct.unpack_from("<I", data, 96)[0]
    class_defs_off   = struct.unpack_from("<I", data, 100)[0]

    # String IDs: array of u32 data offsets
    str_offsets: List[int] = list(
        struct.unpack_from(f"<{string_ids_size}I", data, string_ids_off)
    ) if string_ids_size else []

    # Type IDs: array of u32 string_idx
    type_ids: List[int] = list(
        struct.unpack_from(f"<{type_ids_size}I", data, type_ids_off)
    ) if type_ids_size else []

    # Proto IDs: array of {shorty_idx(u32), return_type_idx(u32), params_off(u32)}
    proto_ids: List[Tuple[int,int,int]] = []
    for i in range(proto_ids_size):
        base = proto_ids_off + i * 12
        proto_ids.append(struct.unpack_from("<III", data, base))

    # Method IDs: array of {class_idx(u16), proto_idx(u16), name_idx(u32)}
    method_ids: List[Tuple[int,int,int]] = []
    for i in range(method_ids_size):
        base = method_ids_off + i * 8
        ci, pi = struct.unpack_from("<HH", data, base)
        ni,    = struct.unpack_from("<I",  data, base + 4)
        method_ids.append((ci, pi, ni))

    # Field IDs: array of {class_idx(u16), type_idx(u16), name_idx(u32)}
    field_ids: List[Tuple[int,int,int]] = []
    for i in range(field_ids_size):
        base = field_ids_off + i * 8
        ci, ti = struct.unpack_from("<HH", data, base)
        ni,    = struct.unpack_from("<I",  data, base + 4)
        field_ids.append((ci, ti, ni))

    # Class defs: 8 x u32 per entry
    class_defs_raw: List[Tuple] = []
    for i in range(class_defs_size):
        base = class_defs_off + i * 32
        class_defs_raw.append(struct.unpack_from("<8I", data, base))

    return DEXFile(
        filename         = filename,
        version          = version,
        file_size        = file_size,
        string_count     = string_ids_size,
        type_count       = type_ids_size,
        method_count     = method_ids_size,
        field_count      = field_ids_size,
        class_count      = class_defs_size,
        _data            = data,
        _str_offsets     = str_offsets,
        _type_ids        = type_ids,
        _proto_ids       = proto_ids,
        _method_ids      = method_ids,
        _field_ids       = field_ids,
        _class_defs_raw  = class_defs_raw,
    )


# ── APKParser public API ──────────────────────────────────────────────────────

class APKParser:
    """
    Zero-dependency APK parser.

    Reads the APK ZIP container and exposes:
      - parse_manifest() -> ManifestInfo
      - iter_dex()       -> Iterator[DEXFile]
      - native_libs()    -> List[str]
      - list_assets()    -> List[str]
    """

    def __init__(self, path: Path) -> None:
        self._path = path
        self._zf: Optional[zipfile.ZipFile] = None

    @classmethod
    def from_path(cls, path: str | Path) -> "APKParser":
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"APK not found: {p}")
        inst = cls(p)
        inst._zf = zipfile.ZipFile(p, "r")
        return inst

    def close(self) -> None:
        if self._zf:
            self._zf.close()

    def __enter__(self) -> "APKParser":
        return self

    def __exit__(self, *_) -> None:
        self.close()

    # ── manifest ──────────────────────────────────────────────────────────────

    def parse_manifest(self) -> ManifestInfo:
        """Parse AndroidManifest.xml and return a ManifestInfo."""
        raw = self._zf.read("AndroidManifest.xml")
        tree = _parse_axml(raw)
        return _build_manifest(tree)

    # ── DEX ───────────────────────────────────────────────────────────────────

    def iter_dex(self) -> Iterator[DEXFile]:
        """Yield a DEXFile for each classes*.dex in the APK."""
        names = sorted(
            n for n in self._zf.namelist()
            if re.match(r"^classes\d*\.dex$", n)
        )
        for name in names:
            data = self._zf.read(name)
            yield _parse_dex(data, filename=name)

    def read_dex(self, name: str = "classes.dex") -> DEXFile:
        """Read a specific DEX file by name."""
        data = self._zf.read(name)
        return _parse_dex(data, filename=name)

    # ── native libs ───────────────────────────────────────────────────────────

    def native_libs(self, abi: str = "") -> List[str]:
        """
        Return paths to bundled .so files.
        Optionally filter by ABI prefix (e.g. abi='armeabi-v7a').
        """
        prefix = f"lib/{abi}" if abi else "lib/"
        return [
            n for n in self._zf.namelist()
            if n.startswith(prefix) and n.endswith(".so")
        ]

    def extract_native_lib(self, entry_path: str, dest: Path) -> Path:
        """Extract a native lib by its in-APK path to dest directory."""
        dest.mkdir(parents=True, exist_ok=True)
        out = dest / Path(entry_path).name
        out.write_bytes(self._zf.read(entry_path))
        return out

    # ── assets / misc ─────────────────────────────────────────────────────────

    def list_assets(self) -> List[str]:
        return [n for n in self._zf.namelist() if n.startswith("assets/")]

    def read_file(self, name: str) -> bytes:
        return self._zf.read(name)

    def namelist(self) -> List[str]:
        return self._zf.namelist()
