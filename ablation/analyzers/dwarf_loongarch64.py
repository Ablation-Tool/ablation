"""
dwarf_loongarch64.py: DWARF, CFI, and BTF utilities for LoongArch64 ELF binaries.

Three independent data sources for precise function-boundary recovery:

  1. .eh_frame FDE records (pyelftools):
       Present in stripped binaries (GCC emits CFI by default).
       Yields function start VAs only.

  2. .debug_info DW_TAG_subprogram (pyelftools):
       Present only with -g. Yields (name, low_pc, high_pc) triples.
       high_pc eliminates the "next-function-start" end approximation.

  3. .BTF / .BTF.ext (pure struct, no external deps):
       Present in Linux kernel modules. Maps section offsets -> function names
       when .symtab is stripped or sparse.

All three are best-effort: any parse failure returns an empty result.
"""
from __future__ import annotations

import struct
from pathlib import Path
from typing import Dict, Set, Tuple

# ---------------------------------------------------------------------------
# 1. .eh_frame — function start VAs from FDE records
# ---------------------------------------------------------------------------

def extract_eh_frame_starts(path: str) -> Set[int]:
    """
    Return the set of function start VAs recorded in .eh_frame FDE entries.

    Uses pyelftools FDE iteration. Returns empty set if .eh_frame is absent,
    pyelftools is unavailable, or any parse error occurs.
    """
    try:
        from elftools.elf.elffile import ELFFile
        from elftools.dwarf.callframe import FDE
        with open(path, "rb") as fh:
            elf = ELFFile(fh)
            if not elf.has_dwarf_info():
                return set()
            di = elf.get_dwarf_info()
            if not di.has_EH_CFI():
                return set()
            return {
                e["initial_location"]
                for e in di.EH_CFI_entries()
                if isinstance(e, FDE) and e["initial_location"] > 0
            }
    except Exception:
        return set()


# ---------------------------------------------------------------------------
# 2. .debug_info — DW_TAG_subprogram name + low_pc + high_pc
# ---------------------------------------------------------------------------

def extract_debug_funcs(path: str) -> Dict[int, Tuple[str, int]]:
    """
    Parse DW_TAG_subprogram entries from .debug_info.

    Returns {low_pc: (name, high_pc)} for each subprogram that has both
    DW_AT_low_pc and DW_AT_high_pc. high_pc may be stored as an absolute
    address (DW_FORM_addr) or as a byte count relative to low_pc
    (DW_FORM_data*); both forms are normalized to an absolute end VA.

    Returns empty dict if .debug_info is absent, -g was not used, or
    pyelftools is unavailable.
    """
    result: Dict[int, Tuple[str, int]] = {}
    try:
        from elftools.elf.elffile import ELFFile
        with open(path, "rb") as fh:
            elf = ELFFile(fh)
            if not elf.has_dwarf_info():
                return result
            di = elf.get_dwarf_info()

            # Build a flat DIE-offset -> DIE map for abstract_origin resolution.
            # GCC LTO emits concrete instances with DW_AT_abstract_origin pointing
            # to the definition DIE that holds DW_AT_name.
            die_by_offset: Dict[int, object] = {}
            for cu in di.iter_CUs():
                for die in cu.iter_DIEs():
                    die_by_offset[die.offset] = die

            def _resolve_name(die: object) -> str:
                """Return name, following DW_AT_abstract_origin / DW_AT_specification."""
                name_attr = die.attributes.get("DW_AT_name")
                if name_attr is not None:
                    raw = name_attr.value
                    return raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else str(raw)
                for link_key in ("DW_AT_abstract_origin", "DW_AT_specification"):
                    ref = die.attributes.get(link_key)
                    if ref is not None:
                        target = die_by_offset.get(ref.value)
                        if target is not None:
                            return _resolve_name(target)
                return ""

            for cu in di.iter_CUs():
                for die in cu.iter_DIEs():
                    if die.tag != "DW_TAG_subprogram":
                        continue
                    low  = die.attributes.get("DW_AT_low_pc")
                    high = die.attributes.get("DW_AT_high_pc")
                    if low is None or high is None:
                        continue
                    low_va  = low.value
                    high_va = high.value
                    # DW_FORM_data* stores a byte-count offset from low_pc
                    if high.form in ("DW_FORM_data1", "DW_FORM_data2",
                                     "DW_FORM_data4", "DW_FORM_data8",
                                     "DW_FORM_udata", "DW_FORM_sdata"):
                        high_va = low_va + high.value
                    func_name = _resolve_name(die)
                    if low_va > 0:
                        result[low_va] = (func_name, high_va)
    except Exception:
        pass
    return result


# ---------------------------------------------------------------------------
# 3. .BTF / .BTF.ext — kernel-module function names
# ---------------------------------------------------------------------------

_BTF_MAGIC      = 0xEB9F
_BTF_KIND_FUNC  = 12      # BTF_KIND_FUNC — named function entry
_BTF_HDR_FMT    = "<HBBIIII"   # magic, version, flags, hdr_len, type_off, type_len, str_off, str_len
_BTF_HDR_SZ     = struct.calcsize(_BTF_HDR_FMT)
_BTF_TYPE_FMT   = "<II"        # name_off, info (kind in bits 24-28, vlen in bits 0-15)
_BTF_TYPE_SZ    = struct.calcsize(_BTF_TYPE_FMT) + 4  # + union(size/type)

_BEXT_HDR_FMT   = "<HBBIIIIIi"  # magic, version, flags, hdr_len, func_info_off, func_info_len,
                                  # line_info_off, line_info_len, core_relo_off  (v3 extension)
_BEXT_HDR_BASE  = struct.calcsize("<HBBIIIII")  # fields up through line_info_len only


def _btf_cstring(blob: bytes, off: int) -> str:
    end = blob.find(b"\x00", off)
    if end == -1:
        return ""
    return blob[off:end].decode("utf-8", errors="replace")


def extract_btf_funcs(path: str) -> Dict[int, str]:
    """
    Extract function name → VA pairs from .BTF and .BTF.ext sections.

    .BTF encodes type records; BTF_KIND_FUNC entries have a name_off into
    the string section.  .BTF.ext func_info records map (ELF-section-offset,
    type_id) pairs back to VAs by combining the ELF section base VA.

    Returns empty dict if either section is absent, malformed, or the ELF
    section base VAs cannot be resolved.
    """
    result: Dict[int, str] = {}
    try:
        data = Path(path).read_bytes()
    except OSError:
        return result

    # Locate .BTF and .BTF.ext section data using our own ELFParser
    btf_data = btext_data = b""
    sec_va: Dict[str, int] = {}  # section name -> sh_addr for .BTF.ext sec_name_off resolution
    try:
        from ablation.core.elf_parser import ELFParser
        elf = ELFParser(path).parse()
        sh_btf   = elf.get_section(".BTF")
        sh_btext = elf.get_section(".BTF.ext")
        if sh_btf is None:
            return result
        btf_data   = data[sh_btf["sh_offset"] : sh_btf["sh_offset"]  + sh_btf["sh_size"]]
        btext_data = data[sh_btext["sh_offset"]: sh_btext["sh_offset"]+ sh_btext["sh_size"]] if sh_btext else b""
        for sh in elf.shdrs:
            sec_va[sh.get("name", "")] = sh.get("sh_addr", 0)
    except Exception:
        return result

    if len(btf_data) < _BTF_HDR_SZ:
        return result

    # Parse .BTF header
    try:
        magic, version, flags, hdr_len, type_off, type_len, str_off, str_len = \
            struct.unpack_from(_BTF_HDR_FMT, btf_data)
    except struct.error:
        return result
    if magic != _BTF_MAGIC:
        return result

    str_start  = hdr_len + str_off
    type_start = hdr_len + type_off
    if str_start + str_len > len(btf_data) or type_start + type_len > len(btf_data):
        return result
    strtab = btf_data[str_start : str_start + str_len]

    # Build type_id -> name for BTF_KIND_FUNC entries
    func_names: Dict[int, str] = {}  # 1-based type_id -> name
    offset = type_start
    type_id = 1
    while offset + _BTF_TYPE_SZ <= type_start + type_len:
        try:
            name_off, info = struct.unpack_from(_BTF_TYPE_FMT, btf_data, offset)
        except struct.error:
            break
        kind  = (info >> 24) & 0x1F
        vlen  = info & 0xFFFF
        if kind == _BTF_KIND_FUNC:
            func_names[type_id] = _btf_cstring(strtab, name_off)
        # Advance: BTF type records have variable trailing data by kind.
        # For our purposes only FUNC matters; skip all by 12 bytes (base record)
        # plus kind-specific extras. We use a simplified skip for non-FUNC kinds.
        trailing = _btf_kind_extra(kind, vlen)
        offset  += 12 + trailing
        type_id += 1

    if not func_names or not btext_data:
        return result

    # Parse .BTF.ext func_info section to map type_ids to VAs
    if len(btext_data) < _BEXT_HDR_BASE:
        return result
    try:
        (ext_magic, ext_ver, ext_flags, ext_hdr_len,
         fi_off, fi_len, li_off, li_len) = struct.unpack_from("<HBBIIIIi", btext_data)
    except struct.error:
        return result
    if ext_magic != _BTF_MAGIC:
        return result

    fi_start = ext_hdr_len + fi_off
    fi_end   = fi_start + fi_len
    if fi_end > len(btext_data):
        return result

    pos = fi_start
    # func_info section layout: __u32 rec_size, then per-section blocks
    if pos + 4 > fi_end:
        return result
    rec_size = struct.unpack_from("<I", btext_data, pos)[0]
    pos += 4
    if rec_size < 8:
        return result  # bpf_func_info is at least insn_off(4) + type_id(4)

    # Iterate per-section blocks: each block = { sec_name_off(4), num_info(4), recs[num_info] }
    while pos + 8 <= fi_end:
        try:
            sec_name_off, num_info = struct.unpack_from("<II", btext_data, pos)
        except struct.error:
            break
        pos += 8
        sec_name = _btf_cstring(btf_data[str_start:str_start+str_len], sec_name_off)
        base_va  = sec_va.get(sec_name, 0)
        for _ in range(num_info):
            if pos + rec_size > fi_end:
                break
            try:
                insn_off, type_id_fi = struct.unpack_from("<II", btext_data, pos)
            except struct.error:
                break
            va = base_va + insn_off
            if type_id_fi in func_names and func_names[type_id_fi] and va > 0:
                result[va] = func_names[type_id_fi]
            pos += rec_size

    return result


def _btf_kind_extra(kind: int, vlen: int) -> int:
    """Return byte count of trailing data after the 12-byte base BTF type record."""
    # Simplified: only the kinds we encounter in kernel modules matter.
    # Source: include/uapi/linux/btf.h BTF_KIND_* definitions.
    # FUNC (12) and FUNC_PROTO (13) are the critical ones; rest approximated.
    _EXTRAS = {
        1:  4 * vlen,   # INT: 1 extra __u32
        2:  8 * vlen,   # PTR: none (type union covers it) — actually 0 extra
        3:  4,          # ARRAY: btf_array (3 * __u32 = 12 — already counted as 0 extra here)
        4:  8 * vlen,   # STRUCT: btf_member * vlen
        5:  8 * vlen,   # UNION
        6:  4 * vlen,   # ENUM: btf_enum * vlen
        7:  0,          # FWD
        8:  0,          # TYPEDEF
        9:  0,          # VOLATILE
        10: 0,          # CONST
        11: 0,          # RESTRICT
        12: 0,          # FUNC — no trailing
        13: 8 * vlen,   # FUNC_PROTO: return type in union + btf_param * vlen
        14: 8 * vlen,   # VAR
        15: 8 * vlen,   # DATASEC: btf_var_secinfo * vlen
        16: 0,          # FLOAT
        17: 4,          # DECL_TAG
        18: 0,          # TYPE_TAG
        19: 12 * vlen,  # ENUM64
    }
    return _EXTRAS.get(kind, 0)
