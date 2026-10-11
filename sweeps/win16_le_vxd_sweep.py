#!/usr/bin/env python3
"""
sweeps/win16_le_vxd_sweep.py — Windows 3.x LE (Linear Executable) VxD vulnerability sweep.

Fills GAP-F: no prior Ablation loader handled the LE/VxD format.

LE format is the ring-0 executable container used for Windows 3.x Virtual Device
Drivers (VxDs). LIEF and standard PE parsers reject it (wrong magic). Key
differences from NE/PE:

  - Magic: 'LE' (0x4c45) at the offset stored in MZ header field 0x3c
  - 32-bit protected-mode code (CS_MODE_32), not 16-bit
  - VMM service calls via INT 0x20 + DWORD service ID (no IAT — VxDs have 0 imports)
  - Object page table uses big-endian 3-byte page numbers (1-indexed) + 1-byte flags
  - Data pages base = le_off + obj_table_off + loader_size + fixup_size

Targets here are ring-0 network stack components: the only bounds checking that
separates them from user-mode TCP/IP packets is whatever they implement themselves.

Pipeline
--------
Phase 1: Detect LE magic and parse header fields.
Phase 2: Build flat code map by reading pages from the data section.
Phase 3: Find function starts via 32-bit prologue scan + E8 call-target recovery.
Phase 4: Scan for VxD DDB (Device Descriptor Block) to name entry-point functions.
Phase 5: Disassemble with Capstone CS_MODE_32; resolve VMM INT-20 service calls.
Phase 6: Semantic sweep (same MiniLM-L6-v2 model as pe_sweep.py and win16_ne_sweep.py).

Usage
-----
Single .386/.vxd binary:
    python3 sweeps/win16_le_vxd_sweep.py VIP.386 --vendor microsoft --product tcpip32 --version 3.11a

Directory scan (scans .386, .vxd, .drv files with LE magic):
    python3 sweeps/win16_le_vxd_sweep.py /path/to/vxd_dir/ --vendor microsoft --product tcpip32 --version 3.11a

Output:
    reports/sweep_le_<vendor>_<product>_<version>_<ts>.md
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

# ── VMM service ID → name (WfW 3.11 + Win 3.1 DDK) ──────────────────────────
# Service IDs are 32-bit DWORDs following INT 20h.
# Format: device_id (high 16 bits) + service_index (low 16 bits)
# Device 0x0001 = VMM (Virtual Machine Manager)

_VMM_SERVICES: Dict[int, str] = {
    # VMM device 0x0001 core services (most common in TCP/IP VxDs)
    0x00010000: "VMM!Get_VMM_Version",
    0x00010001: "VMM!Get_Cur_VM_Handle",
    0x00010002: "VMM!Test_Cur_VM_Handle",
    0x00010003: "VMM!Get_Sys_VM_Handle",
    0x00010004: "VMM!Test_Sys_VM_Handle",
    0x00010005: "VMM!Validate_VM_Handle",
    0x00010006: "VMM!Get_Last_Updated_System_Time",
    0x00010007: "VMM!Get_Last_Updated_VM_Exec_Time",
    0x00010008: "VMM!Update_System_Clock",
    0x00010009: "VMM!Test_DBCS_Lead_Byte",
    0x0001000a: "VMM!Get_Set_HMA_Info",
    0x0001000b: "VMM!Set_System_Exit_Code",
    0x0001000c: "VMM!Fatal_Error_Handler",
    0x0001000d: "VMM!Fatal_Memory_Error",
    0x0001001d: "VMM!Allocate_LDT_Selector",
    0x0001001e: "VMM!Free_LDT_Selector",
    0x0001001f: "VMM!Allocate_GDT_Selector",
    0x00010020: "VMM!Free_GDT_Selector",
    0x00010025: "VMM!Map_Lin_To_VM_Addr",
    0x00010026: "VMM!Adjust_Execution_Priority",
    0x00010027: "VMM!Begin_Critical_Section",
    0x00010028: "VMM!End_Critical_Section",
    0x00010029: "VMM!End_Crit_And_Suspend",
    0x0001002a: "VMM!Claim_Critical_Section",
    0x0001002b: "VMM!Release_Critical_Section",
    0x0001002c: "VMM!Call_When_Not_Critical",
    0x0001002d: "VMM!Create_Semaphore",
    0x0001002e: "VMM!Destroy_Semaphore",
    0x0001002f: "VMM!Wait_Semaphore",
    0x00010030: "VMM!Signal_Semaphore",
    0x00010031: "VMM!Get_Crit_Section_Status",
    0x00010032: "VMM!Call_When_Task_Switched",
    0x00010033: "VMM!Suspend_VM",
    0x00010034: "VMM!Resume_VM",
    0x00010035: "VMM!No_Fail_Resume_VM",
    0x00010036: "VMM!Nuke_VM",
    0x00010037: "VMM!Crash_Cur_VM",
    0x00010038: "VMM!Get_Execution_Focus",
    0x00010039: "VMM!Set_Execution_Focus",
    0x0001003a: "VMM!Get_Time_Slice_Priority",
    0x0001003b: "VMM!Set_Time_Slice_Priority",
    0x0001003c: "VMM!Get_Time_Slice_Granularity",
    0x0001003d: "VMM!Set_Time_Slice_Granularity",
    0x0001003e: "VMM!Get_Time_Slice_Info",
    0x0001003f: "VMM!Adjust_Execution_Time",
    0x00010040: "VMM!Release_Time_Slice",
    0x00010041: "VMM!Wake_Up_VM",
    0x00010042: "VMM!Call_When_Idle",
    0x00010043: "VMM!Get_Next_VM_Handle",
    0x00010044: "VMM!Set_Global_Time_Out",
    0x00010045: "VMM!Set_VM_Time_Out",
    0x00010046: "VMM!Cancel_Time_Out",
    0x00010047: "VMM!Get_System_Time",
    0x00010048: "VMM!Get_VM_Exec_Time",
    0x00010049: "VMM!Hook_V86_Int_Chain",
    0x0001004a: "VMM!Get_V86_Int_Vector",
    0x0001004b: "VMM!Set_V86_Int_Vector",
    0x0001004c: "VMM!Get_PM_Int_Vector",
    0x0001004d: "VMM!Set_PM_Int_Vector",
    0x0001004e: "VMM!Simulate_Int",
    0x0001004f: "VMM!Simulate_Iret",
    0x00010050: "VMM!Simulate_Far_Call",
    0x00010051: "VMM!Simulate_Far_Jmp",
    0x00010052: "VMM!Simulate_Far_Ret",
    0x00010053: "VMM!Simulate_Far_Ret_N",
    0x00010054: "VMM!Build_Int_Stack_Frame",
    0x00010055: "VMM!Simulate_Push",
    0x00010056: "VMM!Simulate_Pop",
    # Memory allocation services
    0x00010063: "VMM!HeapAllocate",
    0x00010064: "VMM!HeapReAllocate",
    0x00010065: "VMM!HeapFree",
    0x00010066: "VMM!HeapGetSize",
    0x0001006b: "VMM!PageAllocate",
    0x0001006c: "VMM!PageReAllocate",
    0x0001006d: "VMM!PageFree",
    0x0001006e: "VMM!PageLock",
    0x0001006f: "VMM!PageUnLock",
    0x00010070: "VMM!PageGetSizeAddr",
    0x00010071: "VMM!PageGetAllocInfo",
    0x00010072: "VMM!GetFirstV86Page",
    0x00010073: "VMM!MapIntoV86",
    0x00010074: "VMM!PhysIntoV86",
    0x00010075: "VMM!TestGlobalV86Mem",
    0x00010076: "VMM!ModifyPageBits",
    0x00010077: "VMM!CopyPageTable",
    0x00010078: "VMM!MapLinearToPhys",
    0x00010079: "VMM!GetFreePageCount",
    0x0001007a: "VMM!GetSysPageCount",
    0x0001007b: "VMM!GetVM_PageCount",
    0x0001007c: "VMM!QueryFreePages",
    0x0001007d: "VMM!PhysPageAllocate",
    0x0001007e: "VMM!PhysPageFree",
    0x0001007f: "VMM!PhysPageLock",
    # String operations (important for overflow analysis)
    0x000100c0: "VMM!lstrlen",
    0x000100c1: "VMM!lstrcpy",
    0x000100c2: "VMM!lstrcat",
    0x000100c3: "VMM!lstrcmp",
    # VPICD (programmable interrupt controller)
    0x00030000: "VPICD!Get_Version",
    0x00030001: "VPICD!Virtualize_IRQ",
    0x00030002: "VPICD!Set_Int_Request",
    0x00030003: "VPICD!Clear_Int_Request",
    0x00030004: "VPICD!Phys_EOI",
    0x00030005: "VPICD!Get_Complete_Status",
    0x00030006: "VPICD!Get_Status",
    0x00030007: "VPICD!Test_Phys_Request",
    0x00030008: "VPICD!Acknowledge_Clone",
    0x00030009: "VPICD!Get_Virtualized_Mask",
    0x0003000a: "VPICD!Get_IRQ_Complete_Status",
    0x0003000b: "VPICD!Remove_Virtualization",
    0x0003000c: "VPICD!Set_Auto_Masking",
    0x0003000d: "VPICD!Get_IRQ_Number",
    # VTDI (Timer Device)
    0x00180000: "VTDI!Get_Version",
    0x00180001: "VTDI!Begin_Min_Int_Period",
    0x00180002: "VTDI!End_Min_Int_Period",
    0x00180003: "VTDI!Disable_Trapping",
    0x00180004: "VTDI!Enable_Trapping",
}


def _vmm_service_name(svc_id: int) -> str:
    known = _VMM_SERVICES.get(svc_id)
    if known:
        return known
    dev = (svc_id >> 16) & 0xFFFF
    svc = svc_id & 0xFFFF
    return f"VxD_Dev{dev:04X}!svc_{svc:04X}"


# ── VxD-specific vulnerability profiles ───────────────────────────────────────

VXD_LE_PROFILES: List[Tuple[str, str]] = [
    ("vxd_ring0_recv_overflow",
     "FUNC | calls: VMM!HeapAllocate VMM!PageAllocate rep movsd rep movsb | "
     "vuln: ring-0 VxD copies network packet data from user-mode V86 memory or "
     "VTCP/VUDP receive buffer into heap buffer without checking received length "
     "against allocation size; attacker-controlled packet length field overflows "
     "kernel heap (VMM heap, ring-0 address space, no guard pages); INT 20h "
     "VMM!HeapAllocate called with fixed size before recv loop"),

    ("vxd_netbios_name_overflow",
     "FUNC | calls: VMM!lstrcpy VMM!lstrcat rep movsb | "
     "vuln: NetBIOS or TCP/IP hostname string from incoming packet (NBT name "
     "registration, WINS registration, DHCP hostname option 12) copied into "
     "fixed-size ring-0 kernel buffer without bounds check; source length from "
     "network packet header; VNBT.386 or VDHCP.386 name handler"),

    ("vxd_heap_alloc_intovf",
     "FUNC | calls: VMM!HeapAllocate VMM!PageAllocate | "
     "vuln: ring-0 allocation size computed from 32-bit arithmetic on network-"
     "derived value (packet count * packet_size, or length field from header) "
     "without overflow check; 32-bit wrap causes small allocation; subsequent "
     "fill overflows kernel heap with no ring-3 boundary to stop it"),

    ("vxd_v86_param_nocopy",
     "FUNC | calls: VMM!Map_Lin_To_VM_Addr VMM!Simulate_Push | "
     "vuln: VxD PM API handler reads pointer from V86 or protected-mode API call "
     "parameters and dereferences it as a kernel-mode pointer without copying "
     "to a private buffer first; attacker changes the V86-mode data between "
     "the validation check and the use (TOCTTOU), or the pointer is never "
     "validated at all"),

    ("vxd_format_string_ring0",
     "FUNC | calls: wsprintfA sprintfA _sprintf wsprintf | "
     "vuln: format string argument to wsprintf or sprintf in ring-0 VxD code "
     "derived from network packet or V86 API parameter without validation; "
     "no ring-3 exception handler in ring-0 context so stack corruption causes "
     "immediate system crash (BSOD equivalent for Windows 3.x)"),
]


def _build_le_profiles() -> List[Tuple[str, str]]:
    """Merge base VULN_PROFILES + Win16 NE profiles + LE VxD-specific profiles."""
    try:
        from sweeps.base_sweep import VULN_PROFILES as BASE
    except ImportError:
        BASE = []
    try:
        from sweeps.win16_ne_sweep import WIN16_NE_PROFILES
    except ImportError:
        WIN16_NE_PROFILES = []
    seen = {name for name, _ in BASE}
    extra_ne = [(n, q) for n, q in WIN16_NE_PROFILES if n not in seen]
    seen.update(n for n, _ in extra_ne)
    extra_le = [(n, q) for n, q in VXD_LE_PROFILES if n not in seen]
    return list(BASE) + extra_ne + extra_le


# ── LE format detection ────────────────────────────────────────────────────────

def _is_le_vxd(path: str) -> bool:
    """Return True if file is a Windows 3.x LE binary (VxD)."""
    try:
        with open(path, "rb") as f:
            mz = f.read(2)
            if mz != b"MZ":
                return False
            f.seek(0x3C)
            le_off_bytes = f.read(4)
            if len(le_off_bytes) < 4:
                return False
            le_off = struct.unpack("<I", le_off_bytes)[0]
            f.seek(le_off)
            magic = f.read(2)
            return magic == b"LE"
    except OSError:
        return False


# ── LE binary parser ──────────────────────────────────────────────────────────

class LEBinary:
    """
    Parsed Windows 3.x LE (Linear Executable) VxD binary.

    Windows VxD LE header layout (distinct from IBM OS/2 LX by a 4-byte shift
    in the page/fixup/loader size field group):

        LE+0x00  magic 'LE'
        LE+0x04  format_level
        LE+0x08  cpu_type (WORD)
        LE+0x0a  os_type  (WORD)
        LE+0x0c  module_version
        LE+0x10  module_flags
        LE+0x14  num_pages
        LE+0x18  eip_object, LE+0x1c eip_offset
        LE+0x20  esp_object, LE+0x24 esp_offset
        LE+0x28  page_size (0x1000)
        LE+0x2c  bytes_on_last_page
        LE+0x30  fixup_section_size
        LE+0x34  fixup_section_checksum
        LE+0x38  loader_section_size
        LE+0x3c  loader_section_checksum
        LE+0x40  obj_table_offset  (from LE header; also = fixed header size)
        LE+0x44  num_objects
        LE+0x48  obj_page_table_offset  (from LE header)
        ...
        LE+0x68  fixup_page_table_offset
        LE+0x70  imported_modules_offset
        LE+0x78  imported_procs_offset / per_page_checksum_offset

    Data pages base (file-absolute):
        data_base = le_off + obj_table_off + loader_size + fixup_size

    Object page table entry (4 bytes):
        bytes[0..2] big-endian: 1-indexed page number
        bytes[3]: flags (0=normal, 1=iterated/compressed, 2=invalid, 3=zeroed)
        page data at: data_base + (page_num - 1) * page_size
    """

    def __init__(self, path: str):
        self.path = path
        self.data = Path(path).read_bytes()
        self._parse()

    def _parse(self):
        d = self.data
        if d[:2] != b"MZ":
            raise ValueError("Not an MZ binary")
        self.le_off: int = struct.unpack_from('<I', d, 0x3c)[0]
        if d[self.le_off:self.le_off + 2] != b'LE':
            raise ValueError(f"LE magic missing at 0x{self.le_off:x}: "
                             f"got {d[self.le_off:self.le_off+2].hex()}")

        off = self.le_off
        self.num_pages           = struct.unpack_from('<I', d, off + 0x14)[0]
        self.page_size           = struct.unpack_from('<I', d, off + 0x28)[0] or 0x1000
        self.bytes_on_last_page  = struct.unpack_from('<I', d, off + 0x2c)[0]
        self.fixup_size          = struct.unpack_from('<I', d, off + 0x30)[0]
        self.loader_size         = struct.unpack_from('<I', d, off + 0x38)[0]
        self.obj_table_off       = struct.unpack_from('<I', d, off + 0x40)[0]
        self.num_objects         = struct.unpack_from('<I', d, off + 0x44)[0]
        self.obj_page_table_off  = struct.unpack_from('<I', d, off + 0x48)[0]

        # Data pages start immediately after fixed header + loader section + fixup section
        # obj_table_off == fixed header size (object table is first table after fixed header)
        self.data_base: int = (self.le_off + self.obj_table_off
                               + self.loader_size + self.fixup_size)

        if self.num_objects < 1 or self.num_objects > 32:
            raise ValueError(f"Implausible num_objects={self.num_objects}")
        if self.data_base >= len(d):
            raise ValueError(f"data_base 0x{self.data_base:x} >= file size 0x{len(d):x}")

        # Parse object descriptors (24 bytes each)
        self.objects: List[dict] = []
        base = self.le_off + self.obj_table_off
        for i in range(self.num_objects):
            b = base + i * 24
            vsize, vbase, flags, mapsize, itermap = struct.unpack_from('<IIIII', d, b)
            self.objects.append({
                'index':   i,
                'vsize':   vsize,
                'vbase':   vbase,
                'flags':   flags,
                'mapsize': mapsize,
                'itermap': itermap,  # 1-based index into page map for first page
            })

    def _page_file_offset(self, pte_idx: int) -> Optional[int]:
        """Return file offset of page data for 0-based PTE index."""
        entry_off = self.le_off + self.obj_page_table_off + pte_idx * 4
        if entry_off + 4 > len(self.data):
            return None
        b = self.data[entry_off: entry_off + 4]
        # Big-endian 3-byte page number (1-indexed) + 1-byte flags
        page_num = (b[0] << 16) | (b[1] << 8) | b[2]
        flags = b[3]
        if page_num == 0 or flags in (2, 3):  # invalid or zeroed
            return None
        file_off = self.data_base + (page_num - 1) * self.page_size
        if file_off >= len(self.data):
            return None
        return file_off

    def code_objects(self) -> List[dict]:
        """Return executable objects with assembled code bytes."""
        result = []
        for obj in self.objects:
            # LE object flags: bit 2 = EXECUTABLE, bit 0 = READABLE
            if not (obj['flags'] & 0x4):
                continue
            pages = []
            for p in range(obj['mapsize']):
                pte_idx = obj['itermap'] - 1 + p  # itermap is 1-based
                file_off = self._page_file_offset(pte_idx)
                if file_off is None:
                    pages.append(b'\xcc' * self.page_size)  # INT3 pad for missing pages
                    continue
                end = file_off + self.page_size
                chunk = self.data[file_off: min(end, len(self.data))]
                if len(chunk) < self.page_size:
                    chunk = chunk + b'\xcc' * (self.page_size - len(chunk))
                pages.append(chunk)

            code_bytes = b''.join(pages)

            # Trim last page to actual bytes on last page (if this is the last object)
            if obj['index'] == self.num_objects - 1 and self.bytes_on_last_page:
                trim = (obj['mapsize'] - 1) * self.page_size + self.bytes_on_last_page
                code_bytes = code_bytes[:trim]

            result.append({
                'obj_index': obj['index'],
                'vbase':     obj['vbase'],   # base VA (0 for VMM-relocated VxDs)
                'vsize':     obj['vsize'],
                'bytes':     code_bytes,
            })
        return result

    def scan_ddb(self, code_bytes: bytes) -> Optional[dict]:
        """
        Scan code bytes for VxD Device Descriptor Block.

        The DDB starts with 4 null bytes (DDB_Next=0) followed by SDK version
        word 0x030A (WfW 3.11) or 0x030B. Returns extracted entry point offsets.
        """
        pattern_a = b'\x00\x00\x00\x00\x0a\x03'  # SDK ver 0x030A
        pattern_b = b'\x00\x00\x00\x00\x0b\x03'  # SDK ver 0x030B
        pattern_c = b'\x00\x00\x00\x00\x0a\x04'  # Win 4.0 DDK
        for pat in (pattern_a, pattern_b, pattern_c):
            idx = code_bytes.find(pat)
            if idx == -1:
                continue
            if idx + 0x20 > len(code_bytes):
                continue
            try:
                sdk_ver  = struct.unpack_from('<H', code_bytes, idx + 4)[0]
                dev_num  = struct.unpack_from('<H', code_bytes, idx + 6)[0]
                dev_maj  = code_bytes[idx + 8]
                dev_min  = code_bytes[idx + 9]
                # DDB_Name at offset 12, 8 bytes
                dev_name = code_bytes[idx + 12: idx + 20].rstrip(b'\x00 ').decode('ascii', 'replace')
                # DDB_Init_Order at offset 20 (DWORD)
                # DDB_Control_Proc at offset 24, DDB_V86_API_Proc at offset 28, ...
                ctrl_proc   = struct.unpack_from('<I', code_bytes, idx + 24)[0]
                v86_api     = struct.unpack_from('<I', code_bytes, idx + 28)[0]
                pm_api      = struct.unpack_from('<I', code_bytes, idx + 32)[0]
                return {
                    'ddb_off':    idx,
                    'sdk_ver':    sdk_ver,
                    'dev_num':    dev_num,
                    'dev_name':   dev_name,
                    'ctrl_proc':  ctrl_proc,
                    'v86_api_proc': v86_api,
                    'pm_api_proc':  pm_api,
                }
            except Exception:
                continue
        return None


# ── 32-bit function start detection ───────────────────────────────────────────

def _find_prologue_starts_x86_32(data: bytes, start: int, end: int) -> List[int]:
    """
    Return byte offsets (within data) of 32-bit function starts.

    Detects:
      55 8b ec  — push ebp; mov ebp, esp  (MSVC standard)
      55 89 e5  — push ebp; mov ebp, esp  (GCC/Watcom form)
      53 55 89  — push ebx; push ebp; mov... (frame + saved reg)
      c8 ?? ?? 00 — enter imm16, 0  (rare but present; found in WfW FTP.EXE)
    """
    hits = []
    stop = min(end, len(data) - 4)
    i = start
    while i < stop:
        b = data[i]
        if b == 0x55:
            b12 = data[i+1:i+3]
            if b12 == b"\x8b\xec" or b12 == b"\x89\xe5":
                hits.append(i)
        elif b == 0xc8 and i + 3 < len(data) and data[i+3] == 0x00:
            hits.append(i)
        elif b == 0x53 and i + 2 < len(data) and data[i+1] == 0x55 and data[i+2] == 0x89:
            hits.append(i)
        i += 1
    return hits


def _find_call_targets_x86_32(data: bytes, start: int, end: int) -> set:
    """
    Recover function starts via E8 rel32 (CALL near) and FF-prefixed indirect calls.

    Returns offsets within data of called targets that land in [start, end).
    """
    recovered: set = set()
    stop = min(end - 4, len(data) - 4)
    for i in range(start, stop):
        if data[i] == 0xE8:
            rel32 = struct.unpack_from('<i', data, i + 1)[0]
            target = (i + 5 + rel32)
            if start <= target < end:
                recovered.add(target)
    return recovered


# ── INT 20h service call extraction ───────────────────────────────────────────

def _extract_vmm_calls(data: bytes, start: int, end: int) -> List[str]:
    """
    Scan a code range for INT 20h + DWORD service ID sequences.

    INT 20h in VxDs is followed by a 4-byte DWORD service ID (VMM call gate).
    This is the ring-0 equivalent of an IAT import call.
    """
    calls = []
    stop = min(end - 5, len(data) - 5)
    for i in range(start, stop):
        if data[i] == 0xcd and data[i+1] == 0x20:  # INT 20h
            svc_id = struct.unpack_from('<I', data, i + 2)[0]
            calls.append(_vmm_service_name(svc_id))
    return calls


# ── function extraction (LE/VxD, x86-32) ─────────────────────────────────────

def _extract_functions_le(
    le: LEBinary,
    max_bytes: int = 512,
) -> Tuple[List[dict], Optional[dict]]:
    """
    Disassemble all executable code objects; return (function dicts, ddb_info).

    Function dicts match the schema used by win16_ne_sweep.py and pe_sweep.py.
    ddb_info is from scan_ddb() or None.
    """
    import capstone
    from ablation.analyzers import describe_function

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = False

    funcs = []
    ddb_info = None

    for obj in le.code_objects():
        code = obj['bytes']
        vbase = obj['vbase']
        obj_idx = obj['obj_index']

        if not ddb_info:
            ddb_info = le.scan_ddb(code)

        prologue_offs = _find_prologue_starts_x86_32(code, 0, len(code))
        call_offs = _find_call_targets_x86_32(code, 0, len(code))
        prologue_set = set(prologue_offs)
        all_offs = sorted(prologue_set | call_offs)

        if not all_offs:
            print(f"  [*] Obj {obj_idx}: 0 functions found")
            continue

        fpo_count = len(call_offs - prologue_set)
        if fpo_count:
            print(f"  [*] Obj {obj_idx}: +{fpo_count} call-target functions "
                  f"(total {len(all_offs)} incl. {len(prologue_set)} prologue)")
        else:
            print(f"  [*] Obj {obj_idx}: {len(all_offs)} functions")

        # Label DDB entry points
        ddb_vas: Dict[int, str] = {}
        if ddb_info:
            for ep_name, ep_key in (
                ('control_proc', 'ctrl_proc'),
                ('v86_api_proc', 'v86_api_proc'),
                ('pm_api_proc',  'pm_api_proc'),
            ):
                ep_va = ddb_info.get(ep_key, 0)
                if ep_va:
                    ddb_vas[ep_va] = ep_name

        for code_off in all_offs:
            is_fpo = code_off not in prologue_set
            # VA = vbase + code_off  (vbase = 0 for VMM-relocated VxDs)
            va = vbase + code_off

            chunk = code[code_off: code_off + max_bytes]
            lines, calls, str_refs = [], [], []

            for insn in md.disasm(chunk, va or code_off):
                text = f"{insn.mnemonic} {insn.op_str}".strip()
                lines.append(text)

                if insn.mnemonic in ('call', 'lcall'):
                    calls.append(insn.op_str)

                # INT 20h = VMM service call; the next 4 bytes are the service ID
                if insn.mnemonic == 'int' and insn.op_str.strip() == '0x20':
                    # Service ID is the 4 bytes immediately following the INT instruction
                    insn_offset = insn.address - (va or code_off) + code_off
                    if insn_offset + 2 + 4 <= len(code):
                        svc_id = struct.unpack_from('<I', code, insn_offset + 2)[0]
                        svc_name = _vmm_service_name(svc_id)
                        calls.append(svc_name)
                        lines.append(f"  ; VMM service: {svc_name}")

                if insn.mnemonic in ('ret', 'retf', 'retn', 'iret'):
                    break

            if len(lines) < 4:
                continue

            ddb_label = ddb_vas.get(va, '')
            role = "FPO" if is_fpo else "FUNC"
            desc = describe_function(
                name=f"vxd_{ddb_label or f'va{va:08x}'}",
                role=role,
                call_targets=calls,
                strings=str_refs,
                asm_lines=lines,
            )
            funcs.append({
                'va':      va,
                'code_off': code_off,
                'desc':    desc,
                'calls':   calls,
                'strings': str_refs,
                'fpo':     is_fpo,
                'obj':     obj_idx,
                'ddb_ep':  ddb_label,
            })

    return funcs, ddb_info


# ── semantic sweep ─────────────────────────────────────────────────────────────

def _semantic_sweep_le(
    funcs: List[dict],
    model,
    profiles: List[Tuple[str, str]],
    top_k: int = 5,
) -> Dict[str, List[Tuple[float, int, List[str], str]]]:
    from ablation.analyzers import FindingRegistry

    registry = FindingRegistry()
    try:
        if not funcs:
            return {}

        print(f"  [*] {len(funcs)} functions; encoding ...")
        corpus = model.encode(
            [f['desc'] for f in funcs],
            normalize_embeddings=True,
            batch_size=128,
            show_progress_bar=False,
        ).astype(np.float32)

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
            print(f"  [*] Registry embeddings: {n_built} entries cached")

        results: Dict = {}
        for name, query in all_profiles:
            qvec = model.encode(query, normalize_embeddings=True).astype(np.float32)
            scores = corpus @ qvec
            top = np.argsort(scores)[::-1][:top_k]
            results[name] = [
                (float(scores[i]), funcs[i]['va'], funcs[i]['calls'], funcs[i]['desc'])
                for i in top
            ]
        return results
    finally:
        registry.close()


# ── per-binary sweep orchestrator ─────────────────────────────────────────────

def _sweep_le_one(
    binary_path: str,
    model,
    profiles: List[Tuple[str, str]],
    top_k: int,
) -> dict:
    name = Path(binary_path).name
    print(f"\n[{name}] Win16 LE VxD (ring-0)")

    result: dict = {
        'path':       binary_path,
        'arch':       'Win16 LE VxD i386 ring-0',
        'name':       name,
        'error':      None,
        'functions':  0,
        'sweep':      {},
        'ddb_info':   None,
    }

    try:
        le = LEBinary(binary_path)
        print(f"  [*] LE: {le.num_objects} objects, {le.num_pages} pages, "
              f"page_size={le.page_size:#x}, data_base={le.data_base:#x}")

        for obj in le.objects:
            exe_flag = "exec" if (obj['flags'] & 0x4) else "data"
            print(f"  [*]   obj[{obj['index']}]: va={obj['vbase']:#010x} "
                  f"size={obj['vsize']:#x} pages={obj['mapsize']} iter={obj['itermap']} "
                  f"({exe_flag})")

        funcs, ddb_info = _extract_functions_le(le, max_bytes=512)
        result['functions'] = len(funcs)
        result['ddb_info']  = ddb_info

        if ddb_info:
            print(f"  [*] DDB found: dev={ddb_info.get('dev_name','?')!r} "
                  f"sdk_ver={ddb_info.get('sdk_ver', 0):#06x} "
                  f"ctrl_proc={ddb_info.get('ctrl_proc', 0):#010x}")

        if not funcs:
            print(f"  [!] No functions extracted — check LE header parsing")
            return result

        result['sweep'] = _semantic_sweep_le(funcs, model, profiles, top_k)

    except Exception as e:
        result['error'] = str(e)
        print(f"  [!] Error: {e}")
        traceback.print_exc()

    return result


# ── report formatter ──────────────────────────────────────────────────────────

def _format_va_le(va: int, ddb_info: Optional[dict]) -> str:
    """Format a VA for display. If vbase=0 (VMM-relocated), show as hex offset."""
    return f"0x{va:08x}"


def _write_report(
    results: List[dict],
    vendor: str,
    product: str,
    version: str,
    out_dir: Path,
    top_k: int,
    threshold: float,
) -> Path:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M")
    safe_product = re.sub(r'[^a-z0-9_-]', '-', product.lower())
    fname = f"sweep_le_{vendor}_{safe_product}_{version}_{ts}.md"
    out_path = out_dir / fname

    lines = [
        "# Win16 LE VxD Sweep Report",
        "",
        f"**Vendor:** {vendor}  **Product:** {product}  **Version:** {version}",
        f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"
        f"  **Targets:** {len(results)} binaries",
        "",
        "---",
        "",
    ]

    for r in results:
        name  = r['name']
        arch  = r['arch']
        nfunc = r['functions']
        ddb   = r.get('ddb_info')
        err   = r['error']

        lines.append(f"## {name}")
        lines.append("")
        lines.append(f"**Path:** `{r['path']}`  **Arch:** `{arch}`  "
                     f"**Functions found:** {nfunc}")

        if ddb:
            dev_name = ddb.get('dev_name', '?')
            sdk_ver  = ddb.get('sdk_ver', 0)
            ctrl     = ddb.get('ctrl_proc', 0)
            v86      = ddb.get('v86_api_proc', 0)
            pm_api   = ddb.get('pm_api_proc', 0)
            lines.append(f"**VxD DDB:** device=`{dev_name}` sdk_ver=`{sdk_ver:#06x}` "
                         f"ctrl_proc=`{ctrl:#010x}` v86_api=`{v86:#010x}` "
                         f"pm_api=`{pm_api:#010x}`")

        if err:
            lines.append(f"**Error:** {err}")
            lines.append("")
            continue

        lines.append("")
        lines.append("### Semantic Sweep")
        lines.append("")

        sweep = r['sweep']
        if not sweep:
            lines.append("*(no results)*")
            lines.append("")
            continue

        printed = False
        for profile_name, hits in sorted(sweep.items()):
            best = hits[0] if hits else None
            if not best:
                continue
            score, va, calls, desc = best
            if score < threshold:
                continue
            printed = True
            call_str = ', '.join(calls[:6]) if calls else ''
            lines.append(f"**{profile_name}** — top score `{score:.4f}` @ `{_format_va_le(va, ddb)}`")
            if call_str:
                lines.append(f"  calls: {call_str}")
            lines.append("")

        if not printed:
            lines.append(f"*(no hits above {threshold:.2f})*")
            lines.append("")

        hit_count = sum(
            1 for hits in sweep.values()
            if hits and hits[0][0] >= threshold
        )
        lines.append(f"---")
        lines.append("")
        lines.append(f"*[*] Summary: {len(results)} binary(ies) swept, "
                     f"{hit_count} semantic hit(s) >= {threshold}*")
        lines.append("")

    out_path.write_text("\n".join(lines))
    return out_path


# ── entry point ──────────────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser(description="Win16 LE VxD semantic sweep")
    ap.add_argument("target", help="Path to .386/.vxd file or directory")
    ap.add_argument("--vendor",   required=True)
    ap.add_argument("--product",  required=True)
    ap.add_argument("--version",  required=True)
    ap.add_argument("--top-k",    type=int,   default=5,   dest="top_k")
    ap.add_argument("--threshold",type=float, default=0.30, dest="threshold")
    ap.add_argument("--out-dir",  default=None, dest="out_dir")
    args = ap.parse_args()

    target = Path(args.target)
    if args.out_dir:
        out_dir = Path(args.out_dir)
    else:
        out_dir = Path(__file__).parent.parent / "reports"
    out_dir.mkdir(parents=True, exist_ok=True)

    # Collect targets
    _VXD_EXTS = {'.386', '.vxd', '.drv', '.sys'}
    if target.is_dir():
        candidates = []
        for ext in _VXD_EXTS:
            candidates.extend(target.glob(f"*{ext}"))
            candidates.extend(target.glob(f"*{ext.upper()}"))
        binaries = sorted({str(p) for p in candidates if _is_le_vxd(str(p))})
        if not binaries:
            # Fall back: scan all files for LE magic
            binaries = sorted({
                str(p) for p in target.iterdir()
                if p.is_file() and _is_le_vxd(str(p))
            })
    else:
        binaries = [str(target)]

    if not binaries:
        print("[!] No LE VxD binaries found")
        sys.exit(1)

    print(f"[*] Loading MiniLM-L6-v2 ...")
    from sentence_transformers import SentenceTransformer
    model = SentenceTransformer("all-MiniLM-L6-v2")

    profiles = _build_le_profiles()
    print(f"[*] {len(profiles)} vulnerability profiles loaded")
    print(f"[*] Sweeping {len(binaries)} LE VxD binary(ies)")

    results = []
    for bp in binaries:
        results.append(_sweep_le_one(bp, model, profiles, args.top_k))

    out_path = _write_report(
        results, args.vendor, args.product, args.version,
        out_dir, args.top_k, args.threshold,
    )
    print(f"\n[*] Report: {out_path}")

    # Print summary
    total_funcs  = sum(r['functions'] for r in results)
    total_errors = sum(1 for r in results if r['error'])
    total_hits   = sum(
        1 for r in results
        for hits in r['sweep'].values()
        if hits and hits[0][0] >= args.threshold
    )
    print(f"[*] {len(results)} binary(ies): {total_funcs} functions, "
          f"{total_hits} semantic hits >= {args.threshold:.2f}, "
          f"{total_errors} error(s)")


if __name__ == "__main__":
    main()
