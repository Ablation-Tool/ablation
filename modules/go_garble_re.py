#!/usr/bin/env python3
"""
Go Garble Binary RE Module
Handles garble-obfuscated Go ELF binaries: correct VA->file-offset mapping,
Go runtime bootstrap tracing, HTTP handler pattern detection, pclntab location.

Sources: Go internals (runtime/asm_amd64.s, cmd/link/internal/ld),
         "Practical Binary Analysis" ch5, mvdan/garble source.
"""

import struct
import re
import sys
from pathlib import Path

try:
    from capstone import *
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False

# ---------------------------------------------------------------------------
# ELF helpers
# ---------------------------------------------------------------------------

ELF_MAGIC = b"\x7fELF"
PT_LOAD = 1


def _parse_elf_phdrs(data: bytes):
    """Return list of LOAD program headers with p_vaddr, p_offset, p_filesz."""
    if data[:4] != ELF_MAGIC:
        raise ValueError("Not an ELF file")
    bits = 64 if data[4] == 2 else 32
    if bits != 64:
        raise ValueError("Only ELF64 supported")

    e_entry = struct.unpack_from("<Q", data, 0x18)[0]
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", data, 0x36)[0]
    e_phnum = struct.unpack_from("<H", data, 0x38)[0]

    phdrs = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type = struct.unpack_from("<I", data, off)[0]
        p_flags = struct.unpack_from("<I", data, off + 4)[0]
        p_offset = struct.unpack_from("<Q", data, off + 8)[0]
        p_vaddr = struct.unpack_from("<Q", data, off + 0x10)[0]
        p_filesz = struct.unpack_from("<Q", data, off + 0x20)[0]
        p_memsz = struct.unpack_from("<Q", data, off + 0x28)[0]
        phdrs.append({
            "p_type": p_type, "p_flags": p_flags, "p_offset": p_offset,
            "p_vaddr": p_vaddr, "p_filesz": p_filesz, "p_memsz": p_memsz,
        })

    load_segs = [p for p in phdrs if p["p_type"] == PT_LOAD]
    return e_entry, load_segs


def va_to_file_offset(va: int, load_segs: list) -> int:
    """Convert virtual address to file offset using LOAD segments."""
    for seg in load_segs:
        vstart = seg["p_vaddr"]
        vend = vstart + seg["p_filesz"]
        if vstart <= va < vend:
            return va - vstart + seg["p_offset"]
    raise ValueError(f"VA 0x{va:x} not in any LOAD segment")


# ---------------------------------------------------------------------------
# pclntab detection
# ---------------------------------------------------------------------------

# go1.2-1.15: 0xFFFFFAFF | go1.16: 0xFFFFFAF0 | go1.18-1.19: 0xFFFFFAF1 | go1.20+: 0xFFFFFAF2
# All little-endian for amd64. Previous values (\xff\xfb\xff\xff, \xfb\xff\xff\xff) were wrong.
GO120_MAGIC = b"\xf2\xfa\xff\xff"  # go1.20+
GO118_MAGIC = b"\xf1\xfa\xff\xff"  # go1.18-1.19
GO116_MAGIC = b"\xf0\xfa\xff\xff"  # go1.16-1.17
GO112_MAGIC = b"\xff\xfa\xff\xff"  # go1.2-1.15

PCLNTAB_MAGICS = [GO120_MAGIC, GO118_MAGIC, GO116_MAGIC, GO112_MAGIC]


def find_pclntab(data: bytes) -> tuple:
    """Scan binary for pclntab magic. Returns (file_offset, magic_bytes) or (None, None).

    Validates quantum==1 and ptrsize==8 (amd64) to reject false positive matches
    in code/data sections. Returns the first valid match.
    """
    for magic in PCLNTAB_MAGICS:
        start = 0
        while True:
            idx = data.find(magic, start)
            if idx == -1:
                break
            if len(data) >= idx + 8:
                quantum = data[idx + 6]
                ptrsize = data[idx + 7]
                if quantum == 1 and ptrsize == 8:
                    return idx, magic
            start = idx + 1
    return None, None


def parse_pclntab_header(data: bytes, offset: int) -> dict:
    """Parse pclntab header and extract function names for go1.18+ binaries.

    go1.18+ layout (all uint64, little-endian):
      [0]  magic(4) + pad(2) + quantum(1) + ptrsize(1)
      [8]  nfunc
      [16] nfiles
      [24] textStart
      [32] funcnametab_offset, funcnametab_len
      [48] cutab_offset, cutab_len
      [64] filetab_offset, filetab_len
      [80] pctab_offset, pctab_len
      [96] pclntab_offset, pclntab_len
      [112] funcdata_offset, funcdata_len
      [128] ftab array (nfunc+1) * [entryOff:uint32, funcOff:uint32]
    """
    if len(data) < offset + 16:
        return {}
    magic = data[offset:offset+4]
    quantum = data[offset + 6]
    ptrsize = data[offset + 7]

    is_go118 = magic in (b"\xf1\xfa\xff\xff", b"\xf2\xfa\xff\xff")
    is_go116 = magic == b"\xf0\xfa\xff\xff"

    if ptrsize == 8:
        nfunc = struct.unpack_from("<Q", data, offset + 8)[0]
    else:
        nfunc = struct.unpack_from("<I", data, offset + 8)[0]

    result = {
        "magic": magic.hex(),
        "quantum": quantum,
        "ptrsize": ptrsize,
        "nfunc": nfunc,
        "file_offset": offset,
        "func_names": [],
    }

    if not is_go118 or ptrsize != 8 or len(data) < offset + 144:
        return result

    # go1.18+: extract funcnametab to get function names
    nfiles = struct.unpack_from("<Q", data, offset + 16)[0]
    textstart = struct.unpack_from("<Q", data, offset + 24)[0]
    funcnametab_off = struct.unpack_from("<Q", data, offset + 32)[0]
    funcnametab_len = struct.unpack_from("<Q", data, offset + 40)[0]

    result["nfiles"] = nfiles
    result["textStart"] = hex(textstart)
    result["funcnametab_off"] = funcnametab_off

    # funcnametab is relative to start of pclntab in memory (not file offset)
    name_start = offset + funcnametab_off
    name_end = name_start + funcnametab_len
    if name_end > len(data):
        return result

    namedata = data[name_start:name_end]
    names = []
    for raw in namedata.split(b'\x00'):
        try:
            s = raw.decode('utf-8')
            if s and (s.startswith('golang.cisco') or s.startswith('main.') or
                      s.startswith('aci-github') or '/' in s):
                names.append(s)
        except UnicodeDecodeError:
            continue

    result["func_names"] = sorted(set(names))
    return result


# ---------------------------------------------------------------------------
# Go bootstrap tracing
# ---------------------------------------------------------------------------

def disasm_at(data: bytes, file_offset: int, va_base: int, count: int = 30) -> list:
    """Disassemble `count` instructions at file_offset, treating va_base as load VA."""
    if not HAS_CAPSTONE:
        return []
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    chunk = data[file_offset: file_offset + count * 15]
    load_va = file_offset - (file_offset % 0x1000) + va_base  # approximate
    insns = []
    for insn in md.disasm(chunk, file_offset + 0x400000 - 0):
        insns.append({
            "va": insn.address,
            "mnemonic": insn.mnemonic,
            "op_str": insn.op_str,
            "bytes": insn.bytes.hex(),
        })
        if len(insns) >= count:
            break
    return insns


def disasm_at_va(data: bytes, va: int, load_segs: list, count: int = 30) -> list:
    """Disassemble at a virtual address."""
    if not HAS_CAPSTONE:
        return []
    try:
        fo = va_to_file_offset(va, load_segs)
    except ValueError:
        return []
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    chunk = data[fo: fo + count * 15]
    insns = []
    for insn in md.disasm(chunk, va):
        insns.append({
            "va": f"0x{insn.address:x}",
            "fo": f"0x{fo + (insn.address - va):x}",
            "mnemonic": insn.mnemonic,
            "op_str": insn.op_str,
            "bytes": insn.bytes.hex(),
        })
        if len(insns) >= count:
            break
    return insns


def trace_go_bootstrap(data: bytes, entry_va: int, load_segs: list) -> dict:
    """
    Trace Go bootstrap call chain from entry point.
    Go bootstrap: _rt0_amd64_linux -> _rt0_amd64 -> runtime.rt0_go -> runtime.main -> main.main
    Returns dict with each stage's first instructions and called addresses.
    """
    result = {"entry_va": f"0x{entry_va:x}", "stages": []}

    va = entry_va
    visited = set()

    for stage_num in range(8):
        if va in visited:
            break
        visited.add(va)

        insns = disasm_at_va(data, va, load_segs, count=20)
        if not insns:
            break

        stage = {"stage": stage_num, "va": f"0x{va:x}", "instructions": insns[:8]}
        result["stages"].append(stage)

        # Find first JMP or CALL to follow
        next_va = None
        for insn in insns:
            m = insn["mnemonic"]
            op = insn["op_str"]
            if m in ("jmp", "call") and op.startswith("0x"):
                try:
                    next_va = int(op, 16)
                    break
                except ValueError:
                    pass

        if next_va is None or next_va == va:
            break
        va = next_va

    return result


# ---------------------------------------------------------------------------
# HTTP handler pattern detection
# ---------------------------------------------------------------------------

# In net/http ServeMux, routes are stored as strings in a map.
# Garble encrypts them, but the mux registration calls follow a pattern:
# - LEA rax, [string_addr]   ; load string pointer
# - MOV rdx, len             ; string length
# - CALL mux_handle           ; register handler
# We look for sequences that match this pattern.

def find_call_sequences(data: bytes, load_segs: list, search_va_start: int,
                         search_va_end: int, stride: int = 16) -> list:
    """
    Scan a VA range for CALL instructions and return targets.
    Used to find repeated calls (route registration loops).
    """
    if not HAS_CAPSTONE:
        return []
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    try:
        fo_start = va_to_file_offset(search_va_start, load_segs)
        fo_end = va_to_file_offset(search_va_end, load_segs)
    except ValueError:
        return []

    chunk = data[fo_start:fo_end]
    calls = []
    for insn in md.disasm(chunk, search_va_start):
        if insn.mnemonic == "call":
            op = insn.op_str
            if op.startswith("0x"):
                try:
                    target = int(op, 16)
                    calls.append({"va": f"0x{insn.address:x}", "target": f"0x{target:x}"})
                except ValueError:
                    pass
    return calls


# ---------------------------------------------------------------------------
# String anchor analysis
# ---------------------------------------------------------------------------

def find_string_xrefs(data: bytes, string_file_offset: int, load_segs: list,
                       search_radius: int = 0x200000) -> list:
    """
    Find all LEA instructions that reference a string at string_file_offset.
    The string VA = string_file_offset + base_va_offset (from load segment).
    Returns list of instruction VAs that load this address.
    """
    # Convert string file offset to VA
    for seg in load_segs:
        end_fo = seg["p_offset"] + seg["p_filesz"]
        if seg["p_offset"] <= string_file_offset < end_fo:
            string_va = string_file_offset - seg["p_offset"] + seg["p_vaddr"]
            break
    else:
        return []

    # x86-64 LEA uses RIP-relative addressing: LEA reg, [RIP + disp32]
    # We need to find all places where RIP + disp32 == string_va
    # Scan executable LOAD segments for LEA opcodes
    results = []
    for seg in load_segs:
        if not (seg["p_flags"] & 0x1):  # not executable
            continue
        fo = seg["p_offset"]
        seg_va = seg["p_vaddr"]
        seg_data = data[fo: fo + seg["p_filesz"]]

        # LEA r64, [RIP+disp32]: opcodes 48 8D xx xx xx xx xx (ModRM 05)
        # More precisely: REX.W=1 (48), 8D, ModRM where mod=00, rm=101 (RIP-rel)
        # ModRM low 3 bits = 101 (5), mod bits = 00 -> byte & 0xC7 == 0x05
        i = 0
        while i < len(seg_data) - 7:
            b = seg_data[i]
            # REX prefix 48 or 4C (REX.W + REX.R)
            if b in (0x48, 0x4C, 0x49, 0x4D):
                if i + 6 < len(seg_data) and seg_data[i+1] == 0x8D:
                    modrm = seg_data[i+2]
                    if (modrm & 0xC7) == 0x05:  # RIP-relative
                        disp = struct.unpack_from("<i", seg_data, i+3)[0]
                        insn_va = seg_va + i
                        next_insn_va = insn_va + 7
                        target_va = next_insn_va + disp
                        if target_va == string_va:
                            results.append({
                                "insn_va": f"0x{insn_va:x}",
                                "target_va": f"0x{target_va:x}",
                                "string_va": f"0x{string_va:x}",
                            })
            i += 1

    return results


# ---------------------------------------------------------------------------
# Garble decryption stub detection
# ---------------------------------------------------------------------------

def find_garble_decrypt_stubs(data: bytes, load_segs: list) -> list:
    """
    Garble encrypts string constants and inserts XOR/decrypt loops.
    Pattern: small function (<50 bytes) with XOR loop, called many times.
    Find candidate decrypt stubs by looking for frequently-called short functions.
    """
    if not HAS_CAPSTONE:
        return []

    call_targets = {}
    md = Cs(CS_ARCH_X86, CS_MODE_64)

    for seg in load_segs:
        if not (seg["p_flags"] & 0x1):
            continue
        fo = seg["p_offset"]
        seg_va = seg["p_vaddr"]
        chunk = data[fo: fo + min(seg["p_filesz"], 0x800000)]

        for insn in md.disasm(chunk, seg_va):
            if insn.mnemonic == "call" and insn.op_str.startswith("0x"):
                try:
                    t = int(insn.op_str, 16)
                    call_targets[t] = call_targets.get(t, 0) + 1
                except ValueError:
                    pass

    # Candidates: called >= 10 times
    candidates = [(va, cnt) for va, cnt in call_targets.items() if cnt >= 10]
    candidates.sort(key=lambda x: -x[1])

    results = []
    for va, cnt in candidates[:20]:
        try:
            fo = va_to_file_offset(va, load_segs)
            chunk = data[fo: fo + 64]
            insns = []
            has_xor = False
            for insn in md.disasm(chunk, va):
                insns.append(f"0x{insn.address:x}: {insn.mnemonic} {insn.op_str}")
                if insn.mnemonic in ("xor", "xorps", "xorpd", "vpxor", "pxor"):
                    has_xor = True
                if len(insns) >= 8:
                    break
            results.append({
                "va": f"0x{va:x}",
                "call_count": cnt,
                "has_xor": has_xor,
                "preview": insns[:4],
            })
        except ValueError:
            pass

    return results


# ---------------------------------------------------------------------------
# Main analysis entrypoint
# ---------------------------------------------------------------------------

def analyze_go_garble_binary(binary_path: str) -> dict:
    """
    Full analysis of a garble-obfuscated Go ELF binary.
    Returns structured findings dict.
    """
    path = Path(binary_path)
    data = path.read_bytes()
    file_size = len(data)

    result = {
        "binary": str(path),
        "file_size": f"0x{file_size:x} ({file_size // 1024 // 1024}MB)",
        "errors": [],
        "elf": {},
        "pclntab": {},
        "bootstrap": {},
        "string_xrefs": {},
        "decrypt_stubs": [],
        "findings": [],
    }

    # Parse ELF
    try:
        entry_va, load_segs = _parse_elf_phdrs(data)
        result["elf"] = {
            "entry_va": f"0x{entry_va:x}",
            "load_segments": [
                {
                    "p_vaddr": f"0x{s['p_vaddr']:x}",
                    "p_offset": f"0x{s['p_offset']:x}",
                    "p_filesz": f"0x{s['p_filesz']:x}",
                    "flags": f"{'R' if s['p_flags']&4 else '-'}{'W' if s['p_flags']&2 else '-'}{'X' if s['p_flags']&1 else '-'}",
                }
                for s in load_segs
            ],
        }
        try:
            entry_fo = va_to_file_offset(entry_va, load_segs)
            result["elf"]["entry_file_offset"] = f"0x{entry_fo:x}"
        except ValueError as e:
            result["errors"].append(f"entry VA mapping: {e}")
    except Exception as e:
        result["errors"].append(f"ELF parse: {e}")
        return result

    # pclntab
    pclntab_fo, pclntab_magic = find_pclntab(data)
    if pclntab_fo is not None:
        hdr = parse_pclntab_header(data, pclntab_fo)
        result["pclntab"] = hdr
        result["findings"].append(f"pclntab at 0x{pclntab_fo:x} (magic {pclntab_magic.hex()}), nfunc={hdr.get('nfunc','?')}")
    else:
        result["pclntab"] = {"status": "not found — garble may have removed it"}
        result["findings"].append("WARNING: pclntab not found — full garble or non-Go binary")

    if not HAS_CAPSTONE:
        result["errors"].append("capstone not installed — skipping disassembly")
        return result

    # Bootstrap tracing
    try:
        result["bootstrap"] = trace_go_bootstrap(data, entry_va, load_segs)
    except Exception as e:
        result["errors"].append(f"bootstrap trace: {e}")

    # String anchor: find "8897" (port string) xrefs
    # Previously found at file offset 0x78b51f
    PORT_STRING_FO = 0x78b51f
    try:
        xrefs = find_string_xrefs(data, PORT_STRING_FO, load_segs)
        result["string_xrefs"]["port_8897"] = {
            "file_offset": f"0x{PORT_STRING_FO:x}",
            "xref_count": len(xrefs),
            "xrefs": xrefs[:10],
        }
        if xrefs:
            result["findings"].append(f"Port 8897 string referenced from {len(xrefs)} locations")
    except Exception as e:
        result["errors"].append(f"port xref scan: {e}")

    # Decrypt stub candidates (garble string decryption)
    try:
        result["decrypt_stubs"] = find_garble_decrypt_stubs(data, load_segs)
        high_call = [s for s in result["decrypt_stubs"] if s["call_count"] >= 50]
        xor_stubs = [s for s in result["decrypt_stubs"] if s["has_xor"]]
        result["findings"].append(
            f"Frequently-called functions: {len(result['decrypt_stubs'])} candidates, "
            f"{len(high_call)} with >=50 calls, {len(xor_stubs)} with XOR (garble decrypt candidates)"
        )
    except Exception as e:
        result["errors"].append(f"decrypt stub scan: {e}")

    return result


if __name__ == "__main__":
    import json
    if len(sys.argv) < 2:
        print("Usage: go_garble_re.py <binary>")
        sys.exit(1)
    result = analyze_go_garble_binary(sys.argv[1])
    print(json.dumps(result, indent=2))
