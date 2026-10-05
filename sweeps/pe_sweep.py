#!/usr/bin/env python3
"""
sweeps/pe_sweep.py — Windows PE (i386 and AMD64) binary vulnerability sweep.

Adapted from fortinet_sweep.py for Windows PE targets. Key differences:
  - Import Address Table (IAT) replaces PLT for call resolution
  - i386: CS_MODE_32; AMD64: CS_MODE_64 with RIP-relative IAT resolution
  - i386 prologue: 55 8B EC / 55 89 E5 (PUSH EBP; MOV EBP,ESP)
  - AMD64 prologue: 48 83 EC (SUB RSP,imm8) / 55 48 89 E5 (PUSH RBP; MOV RBP,RSP)
  - PE section boundaries from lief.PE.Binary
  - No XRefGraph (ELF-only); inline .rdata string index instead
  - Taint analysis skipped (all taint trackers are ELF-only); semantic sweep only

Pipeline
--------
Phase 0 (directory mode): filter files to PE i386 or AMD64.

Phase 1 (every PE binary): IAT build + prologue scan + SemanticSearcher.
         Runs base VULN_PROFILES + PE_WIN_PROFILES (Windows/QuickTime-specific).

Phase 2: SinkArgClassifier skipped (x86-64 ELF only).
         String reference index built from .rdata section.

Usage
-----
Single binary:
    python3 sweeps/pe_sweep.py /path/to/target.exe --vendor apple --product quicktime --version 7.0

Directory scan (.exe and .dll):
    python3 sweeps/pe_sweep.py /path/to/dir/ --vendor apple --product quicktime --version 7.0

Output:
    reports/sweep_pe_<vendor>_<product>_<version>_<ts>.md
"""
from __future__ import annotations

import argparse
import re
import struct
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np

# ── IAT indirect call patterns ────────────────────────────────────────────────
# Capstone 32-bit: call dword ptr [0x4XXXXX] → op_str = "dword ptr [0x4xxxxx]"
# Some Capstone builds include a segment prefix: "dword ptr ds:[0x4xxxxx]"
_IAT_PTR_RE = re.compile(r'dword ptr (?:[a-z]{2}:)?\[0x([0-9a-f]+)\]', re.I)
_DIRECT_CALL_RE = re.compile(r'^0x([0-9a-f]+)$')

# Capstone 64-bit: call qword ptr [rip + 0xNNNNN]  (Capstone never resolves RIP)
# IAT slot VA = insn.address + insn.size + offset
_IAT_RIP_RE = re.compile(r'qword ptr \[rip \+ 0x([0-9a-f]+)\]', re.I)
_IAT_RIP_NEG_RE = re.compile(r'qword ptr \[rip - 0x([0-9a-f]+)\]', re.I)

# x64 string refs: lea reg, [rip + offset]  →  str VA = insn.address + insn.size + offset
_LEA_RIP_RE = re.compile(r'\[rip \+ 0x([0-9a-f]+)\]', re.I)
_LEA_RIP_NEG_RE = re.compile(r'\[rip - 0x([0-9a-f]+)\]', re.I)


# ── PE32 vulnerability profiles (Windows/QuickTime-specific) ──────────────────

PE_WIN_PROFILES: List[Tuple[str, str]] = [
    # QuickTime movie atom heap overflow — size field from file header controls malloc
    ("qt_heap_atom_parse",
     "FUNC | calls: malloc GlobalAlloc HeapAlloc LocalAlloc | "
     "vuln: QuickTime movie atom or chunk size field read from file without upper bound "
     "check before allocation; attacker-controlled size in .mov/.qt file header wraps "
     "on 32-bit integer arithmetic causing small allocation then heap overflow; "
     "atom type 'mdat' 'trak' 'moov' parsed in loop"),

    # RTSP streaming recv into fixed-size buffer
    ("qt_rtsp_recv_overflow",
     "FUNC | calls: recv WSARecv recvfrom | "
     "vuln: QuickTime RTSP or RTP streaming protocol recv into fixed-size stack or heap "
     "buffer with no length validation; attacker-controlled packet length field bypasses "
     "bounds check; port 554 or dynamic RTP port; pre-authentication network exposure"),

    # Registry path → LoadLibrary plugin loading
    ("qt_registry_plugin_load",
     "FUNC | calls: RegQueryValueExA RegQueryValueExW LoadLibraryA LoadLibraryW | "
     "vuln: QuickTime reads plugin or codec path from registry value without length "
     "limit on the registry data buffer; value written by low-priv user then passed "
     "to LoadLibraryA; planting a DLL in user-writable path achieves code execution"),

    # Unsafe string copy on file/URL path from user input (drag-drop, CLI, URL)
    ("qt_path_string_overflow",
     "FUNC | calls: lstrcpyA lstrcatA strcpy strcat wsprintfA | "
     "vuln: file path or movie URL received via DragQueryFileA, command line, or "
     "URL argument copied into fixed-size stack buffer without length check; "
     "QuickTime URL scheme handler or file association attack vector"),

    # WinExec or CreateProcess with user-controlled command string
    ("win_cmd_exec",
     "FUNC | calls: WinExec CreateProcessA CreateProcessW ShellExecuteA ShellExecuteExA | "
     "vuln: command or executable path built from user-controlled input (file name, "
     "URL parameter, registry value) without sanitization; attacker-crafted movie file "
     "or URL triggers command execution via QuickTime association handler"),

    # wsprintf/sprintf format string in QuickTime logging or UI path
    ("win_format_string",
     "FUNC | calls: wsprintfA wsprintfW sprintfA sprintf | "
     "vuln: user-controlled string (filename, URL, metadata tag from movie file) passed "
     "as format string argument to wsprintf or sprintf without format specifier; "
     "stack disclosure or overwrite in QuickTime UI or error reporting path"),

    # Integer overflow before allocation in codec stream parsing
    ("qt_codec_intovf",
     "FUNC | calls: malloc GlobalAlloc HeapAlloc | "
     "vuln: codec stream width * height * bytes_per_pixel computed in 32-bit integer "
     "arithmetic without overflow check; large dimensions in specially crafted media "
     "file cause wrap to small allocation size then heap overflow during frame decode"),

    # OLE/COM media handler with untrusted IStream data
    ("qt_com_stream_overflow",
     "FUNC | calls: IStream::Read CoTaskMemAlloc CoTaskMemRealloc | "
     "vuln: QuickTime ActiveX or COM IStream consumer reads length field from stream "
     "data without validation; IStream::Read into fixed buffer controlled by attacker "
     "through crafted container or malicious web page embedding ActiveX control"),
]


def _build_win_profiles() -> List[Tuple[str, str]]:
    """Merge base VULN_PROFILES with Windows PE profiles (no duplicates)."""
    from sweeps.base_sweep import VULN_PROFILES as BASE
    seen = {name for name, _ in BASE}
    extra = [(n, q) for n, q in PE_WIN_PROFILES if n not in seen]
    return list(BASE) + extra


# ── PE format helpers ─────────────────────────────────────────────────────────

def _is_pe(path: str) -> bool:
    """Return True if file starts with PE magic (MZ header + PE signature)."""
    try:
        with open(path, "rb") as f:
            mz = f.read(2)
            if mz != b"MZ":
                return False
            f.seek(0x3C)
            pe_offset = struct.unpack("<I", f.read(4))[0]
            f.seek(pe_offset)
            return f.read(4) == b"PE\x00\x00"
    except OSError:
        return False


def _detect_pe_arch(path: str) -> Tuple[Optional[str], bool]:
    """
    Return (arch_str, is_64bit) for a PE binary.
    arch_str: "ARCH.I386" | "ARCH.AMD64" | "ARCH.ARM" | "ARCH.ARM64" | None
    """
    try:
        import lief
        pe = lief.parse(path)
        if pe is None:
            return None, False
        machine = str(pe.header.machine)
        if "I386" in machine:
            return "ARCH.I386", False
        if "AMD64" in machine or "X86_64" in machine:
            return "ARCH.AMD64", True
        if "ARM64" in machine or "AARCH64" in machine:
            return "ARCH.ARM64", True
        if "ARM" in machine:
            return "ARCH.ARM", False
        return f"ARCH.{machine}", False
    except Exception:
        return None, False


def _build_iat(pe) -> Dict[int, str]:
    """
    Build Import Address Table: {absolute_va: "DLL!FuncName"}.

    iat_address from lief is an RVA; absolute = imagebase + iat_address.
    Ordinal-only imports (no name) are skipped.
    """
    iat: Dict[int, str] = {}
    try:
        imagebase = pe.optional_header.imagebase
        for lib in pe.imports:
            dll = lib.name.lower()
            for entry in lib.entries:
                if not entry.name:
                    continue
                abs_va = imagebase + entry.iat_address
                iat[abs_va] = f"{dll}!{entry.name}"
    except Exception as e:
        print(f"  [!] _build_iat partial failure: {e} — IAT may be incomplete")
    return iat


def _pe_text_range(pe) -> Tuple[int, int]:
    """
    Return (text_start_abs, text_end_abs) for the .text section.
    Falls back to first executable section if .text is absent.
    Absolute VAs = imagebase + section.virtual_address.
    """
    imagebase = pe.optional_header.imagebase
    for section in pe.sections:
        if section.name.strip("\x00").lower() == ".text" and section.size > 0:
            start = imagebase + section.virtual_address
            return start, start + section.size
    # Fallback: first executable section
    for section in pe.sections:
        flags = section.characteristics
        # IMAGE_SCN_MEM_EXECUTE = 0x20000000
        if flags & 0x20000000 and section.size > 0:
            start = imagebase + section.virtual_address
            return start, start + section.size
    return 0, 0


def _build_rdata_strings(pe, data: bytes) -> Dict[int, str]:
    """
    Build {abs_va: string} from printable null-terminated strings in .rdata.
    Only strings >= 5 characters are indexed. Restricted to .rdata only
    (writable .data segment contains structs/pointers that produce noise).
    """
    strings: Dict[int, str] = {}
    imagebase = pe.optional_header.imagebase
    for section in pe.sections:
        if section.name.strip("\x00").lower() != ".rdata":
            continue
        va = imagebase + section.virtual_address
        offset = section.offset
        size = section.size
        chunk = data[offset: offset + size]
        i = 0
        while i < len(chunk):
            j = i
            while j < len(chunk) and 0x20 <= chunk[j] < 0x7F:
                j += 1
            if j - i >= 5 and j < len(chunk) and chunk[j] == 0:
                strings[va + i] = chunk[i:j].decode("ascii", errors="replace")
            i = j + 1
    return strings


# ── i386 prologue detection ───────────────────────────────────────────────────

def _find_prologue_starts_x86_32(data: bytes, start_offset: int, end_offset: int) -> List[int]:
    """
    Return file offsets of likely x86-32 function starts.

    Detects two common prologues:
      MSVC: 55 8B EC  (push ebp; mov ebp,esp — MOV r32,r/m32 form)
      GCC:  55 89 E5  (push ebp; mov ebp,esp — MOV r/m32,r32 form)

    start_offset / end_offset are byte offsets into data (not VAs).
    """
    hits = []
    end = min(end_offset, len(data) - 3)
    i = start_offset
    while i < end:
        if data[i] == 0x55:
            b12 = data[i + 1: i + 3]
            if b12 == b"\x8B\xEC" or b12 == b"\x89\xE5":
                hits.append(i)
        i += 1
    return hits


# ── AMD64 prologue detection ──────────────────────────────────────────────────

def _find_prologue_starts_x86_64(data: bytes, start_offset: int, end_offset: int) -> List[int]:
    """
    Return file offsets of likely x86-64 function starts.

    Detects three common x64 prologues:
      55 48 89 E5    PUSH RBP; MOV RBP,RSP  (GCC/Clang frame pointer)
      48 83 EC XX    SUB RSP, imm8          (MSVC typical; most common)
      48 89 5C 24    MOV [RSP+N], RBX       (MSVC callee-save preamble)

    start_offset / end_offset are byte offsets into data (not VAs).
    """
    hits: set = set()
    # end = len(data) - 4 guarantees data[i+3] is always a safe read inside the loop
    end = min(end_offset, len(data) - 4)
    i = start_offset
    while i < end:
        b = data[i]
        if b == 0x55 and data[i + 1] == 0x48 and data[i + 2] == 0x89 and data[i + 3] == 0xE5:
            hits.add(i)
        elif b == 0x48 and data[i + 1] == 0x83 and data[i + 2] == 0xEC:
            hits.add(i)
        elif b == 0x48 and data[i + 1] == 0x89 and data[i + 2] == 0x5C and data[i + 3] == 0x24:
            hits.add(i)
        i += 1
    return sorted(hits)


# ── FPO call-target recovery ──────────────────────────────────────────────────

def _find_fpo_call_targets_x86_32(
    data: bytes,
    text_file_offset: int,
    text_size: int,
    text_section_va: int,
    imagebase: int,
) -> set:
    """
    Recover function starts missed by prologue detection (FPO-compiled code).

    Scans the .text section for direct call rel32 instructions (opcode 0xe8)
    and returns the set of VA targets that land within .text.  Any such target
    is a function entry point regardless of whether it has a frame-pointer
    prologue.

    Returns a set of file offsets (not VAs) of recovered function starts.
    """
    text_start_va = imagebase + text_section_va
    text_end_va   = text_start_va + text_size
    recovered: set = set()

    end = text_file_offset + text_size - 4
    for i in range(text_file_offset, end):
        if data[i] == 0xe8:
            rel32 = int.from_bytes(data[i + 1: i + 5], "little", signed=True)
            # call rel32 target = address of next instruction + rel32
            insn_va = imagebase + text_section_va + (i - text_file_offset)
            target_va = insn_va + 5 + rel32
            if text_start_va <= target_va < text_end_va:
                target_offset = text_file_offset + (target_va - text_start_va)
                recovered.add(target_offset)
    return recovered


# ── call target resolution ────────────────────────────────────────────────────

def _resolve_call_target(op_str: str, iat: Dict[int, str]) -> str:
    """
    Resolve a Capstone x86-32 call operand to a human-readable name.

    Handles:
      - Indirect via IAT:  "dword ptr [0x4XXXXX]"
      - Direct call:       "0x4XXXXX"
    Falls back to raw op_str when no IAT entry matches.
    """
    m = _IAT_PTR_RE.search(op_str)
    if m:
        addr = int(m.group(1), 16)
        return iat.get(addr, op_str)
    m = _DIRECT_CALL_RE.match(op_str.strip())
    if m:
        addr = int(m.group(1), 16)
        return iat.get(addr, op_str)
    return op_str


def _resolve_call_target_x64(
    op_str: str, insn_va: int, insn_size: int, iat: Dict[int, str]
) -> str:
    """
    Resolve a Capstone x86-64 call operand to a human-readable name.

    Capstone does not resolve RIP-relative addresses; we compute:
      IAT slot VA = insn_va + insn_size + signed_offset

    Handles:
      - RIP-relative IAT:  "qword ptr [rip + 0xNNNNN]"
      - RIP-relative IAT:  "qword ptr [rip - 0xNNNNN]"
      - Direct call:       "0x1400XXXXX"
    Falls back to raw op_str when no IAT entry matches.
    """
    m = _IAT_RIP_RE.search(op_str)
    if m:
        offset = int(m.group(1), 16)
        return iat.get(insn_va + insn_size + offset, op_str)
    m = _IAT_RIP_NEG_RE.search(op_str)
    if m:
        offset = int(m.group(1), 16)
        return iat.get(insn_va + insn_size - offset, op_str)
    m = _DIRECT_CALL_RE.match(op_str.strip())
    if m:
        addr = int(m.group(1), 16)
        return iat.get(addr, op_str)
    return op_str


# ── function extraction (PE / i386 + AMD64) ──────────────────────────────────

def _extract_functions_pe(
    binary_path: str,
    pe,
    iat: Dict[int, str],
    rdata_strings: Dict[int, str],
    data: Optional[bytes] = None,
    max_bytes: int = 2048,
    is_64: bool = False,
) -> List[dict]:
    """
    Disassemble PE32/PE32+ binary and return function dicts:
        {'va': int, 'desc': str, 'calls': list[str], 'strings': list[str]}

    i386: CS_MODE_32, prologue 55 8B EC / 55 89 E5, string refs via push imm.
    AMD64: CS_MODE_64, prologues 48 83 EC / 55 48 89 E5, string refs via lea+RIP,
           call resolution via RIP-relative slot computation.
    """
    import capstone
    from ablation.analyzers import describe_function

    if data is None:
        data = Path(binary_path).read_bytes()
    imagebase = pe.optional_header.imagebase
    text_start_abs, text_end_abs = _pe_text_range(pe)

    if text_start_abs == 0:
        print(f"  [!] No executable section found in {binary_path}")
        return []

    # File offset of .text section start
    text_section = None
    for section in pe.sections:
        abs_va = imagebase + section.virtual_address
        if abs_va == text_start_abs:
            text_section = section
            break

    if text_section is None:
        print(f"  [!] Cannot locate .text file offset for {binary_path}")
        return []

    text_file_offset = text_section.offset
    text_size = text_section.size

    # Guard: offset=0 means section is memory-only (packed/virtual PE) — skip
    if text_file_offset == 0:
        print(f"  [!] .text file offset is 0 — packed or virtual-only PE, skipping")
        return []

    # Prologue detection (arch-specific)
    if is_64:
        prologue_offsets = _find_prologue_starts_x86_64(
            data, text_file_offset, text_file_offset + text_size
        )
    else:
        prologue_offsets = _find_prologue_starts_x86_32(
            data, text_file_offset, text_file_offset + text_size
        )

    # FPO recovery: E8 rel32 direct-call scanning — same opcode for i386 and AMD64
    fpo_offsets = _find_fpo_call_targets_x86_32(
        data, text_file_offset, text_size,
        text_section.virtual_address, imagebase,
    )
    prologue_set = set(prologue_offsets)
    fpo_only = sorted(fpo_offsets - prologue_set)
    all_offsets = sorted(prologue_set | fpo_offsets)

    if not all_offsets:
        arch_tag = "x64" if is_64 else "x86-32"
        print(f"  [!] No {arch_tag} functions found in .text section (prologue+FPO)")
        return []

    fpo_count = len(fpo_only)
    if fpo_count:
        print(f"  [*] FPO recovery: +{fpo_count} call-target functions "
              f"(total {len(all_offsets)} incl. {len(prologue_set)} prologue)")

    cs_mode = capstone.CS_MODE_64 if is_64 else capstone.CS_MODE_32
    md = capstone.Cs(capstone.CS_ARCH_X86, cs_mode)
    md.detail = False

    funcs = []
    for file_offset in all_offsets:
        is_fpo = file_offset not in prologue_set
        # Absolute VA of this function
        va = imagebase + (file_offset - text_file_offset) + text_section.virtual_address

        chunk = data[file_offset: file_offset + max_bytes]
        lines, calls, str_refs = [], [], []

        for insn in md.disasm(chunk, va):
            text = f"{insn.mnemonic} {insn.op_str}".strip()
            lines.append(text)

            if insn.mnemonic == "call":
                if is_64:
                    resolved = _resolve_call_target_x64(insn.op_str, insn.address, insn.size, iat)
                else:
                    resolved = _resolve_call_target(insn.op_str, iat)
                calls.append(resolved)
            elif not is_64 and insn.mnemonic == "push" and insn.op_str.startswith("0x"):
                # x86-32: string refs via push immediate (string VA as imm)
                try:
                    pushed_va = int(insn.op_str, 16)
                    s = rdata_strings.get(pushed_va)
                    if s:
                        str_refs.append(s)
                except ValueError:
                    pass
            elif is_64 and insn.mnemonic == "lea":
                # x64: string refs via lea reg, [rip + offset]
                m = _LEA_RIP_RE.search(insn.op_str)
                if m:
                    str_va = insn.address + insn.size + int(m.group(1), 16)
                    s = rdata_strings.get(str_va)
                    if s:
                        str_refs.append(s)
                else:
                    m = _LEA_RIP_NEG_RE.search(insn.op_str)
                    if m:
                        str_va = insn.address + insn.size - int(m.group(1), 16)
                        s = rdata_strings.get(str_va)
                        if s:
                            str_refs.append(s)

            if insn.mnemonic in ("ret", "retn"):
                break

        if len(lines) < 5:
            continue

        role = "FPO" if is_fpo else "FUNC"
        desc = describe_function(
            name=f"func_{va:08x}",
            role=role,
            call_targets=calls,
            strings=str_refs,
            asm_lines=lines,
        )
        funcs.append({
            "va": va,
            "desc": desc,
            "calls": calls,
            "strings": str_refs,
            "fpo": is_fpo,
        })
    return funcs


# ── semantic sweep ────────────────────────────────────────────────────────────

def _semantic_sweep_pe(
    funcs: List[dict],
    model,
    profiles: List[Tuple[str, str]],
    top_k: int = 5,
) -> Dict[str, List[Tuple[float, int, List[str], str]]]:
    """
    Run semantic similarity sweep against all profiles for pre-extracted functions.

    Returns {profile_name: [(score, va, calls, desc), ...]} top_k per profile.
    model must already be loaded.
    """
    from ablation.analyzers import FindingRegistry

    registry = FindingRegistry()

    if not funcs:
        registry.close()
        return {}

    print(f"  [*] {len(funcs)} functions; encoding ...")
    corpus = model.encode(
        [f["desc"] for f in funcs],
        normalize_embeddings=True,
        batch_size=128,
        show_progress_bar=False,
    ).astype(np.float32)

    # Augment with prior confirmed findings from registry
    all_profiles = list(profiles)
    prior = registry.prior_queries(top_n=15)
    for i, desc in enumerate(prior):
        label = (
            f"prior:{i:02d}:{desc[:35].replace(' ', '_').replace('|', '').strip('_')}"
        )
        all_profiles.append((label, desc))
    if prior:
        print(f"  [*] +{len(prior)} prior-finding queries from registry")

    n_built = registry.build_embeddings(model)
    if n_built:
        print(f"  [*] Built {n_built} registry embeddings")

    results: Dict = {}
    for name, query in all_profiles:
        qvec = model.encode(query, normalize_embeddings=True).astype(np.float32)
        scores = corpus @ qvec
        top = np.argsort(scores)[::-1][:top_k]
        results[name] = [
            (float(scores[i]), funcs[i]["va"], funcs[i]["calls"], funcs[i]["desc"])
            for i in top
        ]

    registry.close()
    return results


# ── per-binary sweep orchestrator ─────────────────────────────────────────────

def _sweep_pe_one(
    binary_path: str,
    model,
    profiles: List[Tuple[str, str]],
    top_k: int,
) -> dict:
    """
    Run semantic sweep against a single PE32 binary.

    Returns result dict:
        {
          'path': str,
          'arch': str,
          'is_64': bool,
          'functions_found': int,
          'iat_size': int,
          'semantic': {profile: [(score, va, calls, desc)]},
          'error': str or None,
        }
    """
    import lief

    name = Path(binary_path).name
    arch_str, is_64 = _detect_pe_arch(binary_path)
    print(f"\n[{name}] arch={arch_str or 'unknown'}  64bit={is_64}")

    result: dict = {
        "path": binary_path,
        "arch": arch_str or "unknown",
        "is_64": is_64,
        "functions_found": 0,
        "iat_size": 0,
        "semantic": {},
        "error": None,
    }

    try:
        pe = lief.parse(binary_path)
        if pe is None:
            result["error"] = "lief.parse returned None"
            return result
    except Exception as e:
        result["error"] = f"lief.parse failed: {e}"
        return result

    # IAT build
    iat = _build_iat(pe)
    result["iat_size"] = len(iat)
    print(f"  [*] IAT: {len(iat)} entries")

    # Read file once; pass bytes to both string indexer and function extractor
    data = Path(binary_path).read_bytes()

    # .rdata string index
    rdata_strings = _build_rdata_strings(pe, data)
    print(f"  [*] .rdata strings: {len(rdata_strings)} indexed")

    # Function extraction
    try:
        funcs = _extract_functions_pe(binary_path, pe, iat, rdata_strings, data=data, is_64=is_64)
        result["functions_found"] = len(funcs)
        print(f"  [*] Functions extracted: {len(funcs)}")
    except Exception as e:
        result["error"] = f"function extraction: {e}\n{traceback.format_exc()}"
        print(f"  [!] Extraction failed: {e}")
        return result

    if not funcs:
        print(f"  [!] No functions extracted — skipping semantic sweep")
        return result

    # Semantic sweep
    try:
        print(f"  [*] Semantic sweep ({len(profiles)} profiles) ...")
        result["semantic"] = _semantic_sweep_pe(funcs, model, profiles, top_k=top_k)
    except Exception as e:
        result["error"] = f"semantic: {e}\n{traceback.format_exc()}"
        print(f"  [!] Semantic sweep failed: {e}")

    return result


# ── report generation ─────────────────────────────────────────────────────────

def _render_report(
    results: List[dict],
    vendor: str,
    product: str,
    version: str,
    top_k: int,
) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines: List[str] = [
        "# PE Sweep Report",
        "",
        f"**Vendor:** {vendor}  **Product:** {product}  **Version:** {version}",
        f"**Generated:** {ts}  **Targets:** {len(results)} binaries",
        "",
    ]

    for r in results:
        name = Path(r["path"]).name
        lines += [
            "---",
            "",
            f"## {name}",
            "",
            f"**Path:** `{r['path']}`  **Arch:** `{r['arch']}`  "
            f"**IAT entries:** {r['iat_size']}  "
            f"**Functions found:** {r['functions_found']}",
            "",
        ]

        if r.get("error"):
            lines += [f"**ERROR:** {r['error']}", ""]
            continue

        if r["semantic"]:
            lines += ["### Semantic Sweep", ""]
            for profile_name, hits in r["semantic"].items():
                if not hits:
                    continue
                top = hits[0]
                score, va, calls, desc = top
                if score < 0.30:
                    continue
                lines.append(
                    f"**{profile_name}** — top score `{score:.4f}` @ `{va:#010x}`"
                )
                calls_str = ", ".join(c for c in calls[:6] if not c.startswith("0x")) or "none"
                lines.append(f"  calls: {calls_str}")
                lines.append("")
        else:
            lines += ["*No semantic results.*", ""]

    return "\n".join(lines)


# ── directory sweep ───────────────────────────────────────────────────────────

def sweep_directory_pe(
    directory: str,
    model,
    profiles: List[Tuple[str, str]],
    top_k: int,
) -> List[dict]:
    """
    Scan all .exe and .dll files in directory for PE i386 or AMD64 binaries,
    then run _sweep_pe_one on each.
    """
    dir_path = Path(directory)
    candidates = sorted(
        p for p in dir_path.iterdir()
        if p.is_file()
        and p.suffix.lower() in (".exe", ".dll", ".ocx", ".ax")
        and _is_pe(str(p))
    )

    if not candidates:
        # Also try any file without extension that looks like PE
        candidates = sorted(
            p for p in dir_path.iterdir()
            if p.is_file() and _is_pe(str(p))
        )

    print(f"[Phase 0] {len(candidates)} PE file(s) found in {directory}")

    _SUPPORTED_ARCHS = {"ARCH.I386", "ARCH.AMD64"}

    results: List[dict] = []
    for p in candidates:
        arch_str, _ = _detect_pe_arch(str(p))
        if arch_str not in _SUPPORTED_ARCHS:
            print(f"  [~] SKIP {p.name}: arch={arch_str} (PE sweep handles i386/AMD64 only)")
            continue
        try:
            r = _sweep_pe_one(str(p), model, profiles, top_k)
            results.append(r)
        except Exception as e:
            print(f"  [!] SKIP {p.name}: {e}")
            results.append({
                "path": str(p), "arch": "unknown", "is_64": False,
                "functions_found": 0, "iat_size": 0, "semantic": {}, "error": str(e),
            })
    return results


# ── main / CLI ────────────────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser(
        description="Windows PE (i386 and AMD64) binary vulnerability sweep",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("target", help="Path to PE32 binary OR directory")
    ap.add_argument("--vendor",  default="",        help="Vendor name (e.g. apple)")
    ap.add_argument("--product", default="",        help="Product name (e.g. quicktime)")
    ap.add_argument("--version", default="",        help="Version string (e.g. 7.0)")
    ap.add_argument("--top",     type=int, default=5,
                    help="Candidates per semantic profile (default 5)")
    ap.add_argument("--report",  default="",
                    help="Write report to this .md path (default: auto-named in reports/)")
    args = ap.parse_args()

    target = Path(args.target)
    if not target.exists():
        print(f"[!] Target not found: {target}")
        sys.exit(1)

    print("[*] Loading sentence transformer (all-MiniLM-L6-v2) ...")
    from sentence_transformers import SentenceTransformer
    model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2", device="cpu")
    print("[*] Model loaded")

    profiles = _build_win_profiles()
    print(f"[*] Profiles: {len(profiles)} (base + {len(PE_WIN_PROFILES)} PE/Win-specific)")

    if target.is_dir():
        results = sweep_directory_pe(str(target), model, profiles, args.top)
    else:
        if not _is_pe(str(target)):
            print(f"[!] {target} does not look like a PE binary")
            sys.exit(1)
        arch_str, _ = _detect_pe_arch(str(target))
        if arch_str not in ("ARCH.I386", "ARCH.AMD64"):
            print(f"[!] {target} is {arch_str} — PE sweep handles i386 and AMD64 only")
            sys.exit(1)
        results = [_sweep_pe_one(str(target), model, profiles, args.top)]

    # Write report
    if args.report:
        report_path = Path(args.report)
    else:
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M")
        slug = "_".join(filter(None, ["pe", args.vendor, args.product, args.version, ts]))
        report_path = Path("reports") / f"sweep_{slug}.md"

    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_md = _render_report(
        results,
        vendor=args.vendor,
        product=args.product,
        version=args.version,
        top_k=args.top,
    )
    report_path.write_text(report_md, encoding="utf-8")
    print(f"\n[*] Report written to {report_path}")

    n_hits = sum(
        1 for r in results
        for hits in r["semantic"].values()
        if hits and hits[0][0] >= 0.30
    )
    print(f"[*] Summary: {len(results)} binary(ies) swept, {n_hits} semantic hit(s) >= 0.30")


if __name__ == "__main__":
    main()
