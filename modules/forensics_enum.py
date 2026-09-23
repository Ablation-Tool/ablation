#!/usr/bin/env python3
"""
Forensics enumeration: SEH chain, SSDT hooks, DPC/timer abuse, Windows artifacts.
Synthesized from: Practical Reverse Engineering (Dang/Gazet/Bachaalany, ch1 + ch3)

Covers:
  - SEH chain corruption / exploit patterns (FS:0, POPAD+JMP eggscan, VEH)
  - SSDT/kernel hook indicators (KeServiceDescriptorTable, KiFastCallEntry,
    PsSetLoadImageNotifyRoutine, ObRegisterCallbacks, CmRegisterCallback)
  - DPC and timer abuse patterns (KeInitializeDpc, KeSetTimerEx, IoQueueWorkItem)
  - Windows forensic artifact detection ($MFT, LNK, Prefetch, EVTX)
"""

import re
import struct
import os
from typing import List, Dict


# ---------------------------------------------------------------------------
# 1. SEH chain corruption / exploit patterns
# ---------------------------------------------------------------------------

def detect_seh_chain_corruption(binary_data: bytes) -> List[Dict]:
    """
    Scan binary_data for SEH chain manipulation patterns.

    Patterns detected:
      - FS:[0] read (x86 SEH head access): bytes 64 A1 00 00 / 64 8B 00 (MOV EAX, FS:[EAX])
      - POPAD + short/near JMP within 8 bytes: eggscan / SEH exploit chain
      - RtlAddVectoredExceptionHandler: VEH installation
      - RtlDispatchException / ntdll_RtlDispatchException: custom handler chaining

    Returns list of finding dicts {severity, title, detail, host, port}.
    """
    findings: List[Dict] = []

    # FS:[0] read patterns — 32-bit SEH chain head access
    # 64 A1 00 00 00 00 = MOV EAX, FS:[0x00000000]  (SEH head)
    # 64 8B 18          = MOV EBX, FS:[EAX]  (common variant)
    seh_head_patterns = [
        (b"\x64\xa1\x00\x00\x00\x00", "MOV EAX, FS:[0] — 32-bit SEH head read"),
        (b"\x64\xa1\x00\x00",         "MOV EAX, FS:[0] (short) — SEH chain accessed"),
        (b"\x64\x8b\x18",             "MOV EBX, FS:[EAX] — FS-relative dereference"),
    ]
    for pattern, description in seh_head_patterns:
        if pattern in binary_data:
            findings.append({
                "severity": "HIGH",
                "title":    "SEH_CHAIN_ACCESSED",
                "detail":   f"{description}; rootkit or exploit reads the SEH linked list",
                "host":     "localhost",
                "port":     0,
            })
            break  # one HIGH per pattern class

    # POPAD + short JMP (EB xx) or near JMP (E9 xx xx xx xx) within 8 bytes
    # Classic Windows SEH exploit: POPAD restores registers, JMP skips 4-byte nSEH field
    popad = b"\x61"
    pos = 0
    hit = False
    while not hit and pos < len(binary_data) - 2:
        idx = binary_data.find(popad, pos)
        if idx == -1:
            break
        window = binary_data[idx + 1 : idx + 9]
        # short JMP = EB; near JMP = E9
        for jmp_byte in (b"\xeb", b"\xe9"):
            if jmp_byte in window:
                findings.append({
                    "severity": "CRITICAL",
                    "title":    "POPAD_JMP_EGGSCAN",
                    "detail":   (
                        f"POPAD (0x61) followed by JMP (0x{jmp_byte[0]:02x}) within 8 bytes "
                        f"at offset 0x{idx:x} — eggscan / SEH exploit chain signature"
                    ),
                    "host":     "localhost",
                    "port":     0,
                })
                hit = True
                break
        pos = idx + 1

    # RtlAddVectoredExceptionHandler — VEH installation (bypasses SEH entirely)
    veh_markers = [
        b"RtlAddVectoredExceptionHandler",
        b"RtlAddVectoredExceptionHandler\x00",
    ]
    for marker in veh_markers:
        if marker in binary_data:
            findings.append({
                "severity": "MEDIUM",
                "title":    "VECTORED_EXCEPTION_HANDLER_INSTALLED",
                "detail":   (
                    "RtlAddVectoredExceptionHandler reference — VEH registration intercepts "
                    "exceptions before the SEH chain; used by exploits and anti-debug stubs"
                ),
                "host":     "localhost",
                "port":     0,
            })
            break

    # RtlDispatchException / ntdll!RtlDispatchException — non-standard handler chain
    dispatch_markers = [
        b"RtlDispatchException",
        b"ntdll!RtlDispatchException",
        b"KiUserExceptionDispatcher",
    ]
    for marker in dispatch_markers:
        if marker in binary_data:
            findings.append({
                "severity": "HIGH",
                "title":    "CUSTOM_EXCEPTION_HANDLER",
                "detail":   (
                    f"{marker.decode(errors='replace')} reference — "
                    "direct manipulation of the exception dispatch path; "
                    "rootkits patch this to intercept or swallow exceptions"
                ),
                "host":     "localhost",
                "port":     0,
            })
            break

    return findings


# ---------------------------------------------------------------------------
# 2. SSDT / kernel hook indicators
# ---------------------------------------------------------------------------

def detect_ssdt_hook_indicators(binary_data: bytes) -> List[Dict]:
    """
    Scan binary_data for SSDT and kernel callback hook patterns.

    Patterns detected:
      - KeServiceDescriptorTable: direct SSDT access — hook setup or rootkit
      - KiSystemServiceStart / KiFastCallEntry: syscall entry point patching
      - PsSetLoadImageNotifyRoutine: image-load notification callback
      - ObRegisterCallbacks / CmRegisterCallback: object/registry callbacks
      - PsSetCreateProcessNotifyRoutine: process creation notification

    Returns list of finding dicts {severity, title, detail, host, port}.
    """
    findings: List[Dict] = []

    checks = [
        (
            [b"KeServiceDescriptorTable\x00", b"KeServiceDescriptorTable"],
            "HIGH",
            "SSDT_ACCESSED",
            "KeServiceDescriptorTable reference — direct SSDT access; "
            "classic rootkit hook pivot to redirect system call dispatch",
        ),
        (
            [b"KiSystemServiceStart\x00", b"KiSystemServiceStart",
             b"KiFastCallEntry\x00",      b"KiFastCallEntry"],
            "CRITICAL",
            "SYSCALL_ENTRY_PATCHED",
            "KiSystemServiceStart / KiFastCallEntry reference — "
            "undocumented syscall entry points; inline-patching these "
            "intercepts every system call before dispatch",
        ),
        (
            [b"PsSetLoadImageNotifyRoutine\x00", b"PsSetLoadImageNotifyRoutine"],
            "HIGH",
            "IMAGE_LOAD_CALLBACK_REGISTERED",
            "PsSetLoadImageNotifyRoutine reference — "
            "callback fires on every DLL/EXE load; used by EDR and rootkits "
            "to inspect or tamper with loaded images",
        ),
        (
            [b"ObRegisterCallbacks\x00", b"ObRegisterCallbacks",
             b"CmRegisterCallback\x00",  b"CmRegisterCallback"],
            "HIGH",
            "OBJECT_MANAGER_CALLBACK",
            "ObRegisterCallbacks / CmRegisterCallback reference — "
            "object manager or registry callback registration; "
            "intercepts handle creation and registry operations kernel-side",
        ),
        (
            [b"PsSetCreateProcessNotifyRoutine\x00",
             b"PsSetCreateProcessNotifyRoutine",
             b"PsSetCreateProcessNotifyRoutineEx\x00",
             b"PsSetCreateProcessNotifyRoutineEx"],
            "MEDIUM",
            "PROCESS_NOTIFY_CALLBACK",
            "PsSetCreateProcessNotifyRoutine reference — "
            "process creation/termination notification; legitimate EDR hook, "
            "also used by rootkits to maintain persistence lists",
        ),
    ]

    for markers, severity, title, detail in checks:
        for marker in markers:
            if marker in binary_data:
                findings.append({
                    "severity": severity,
                    "title":    title,
                    "detail":   detail,
                    "host":     "localhost",
                    "port":     0,
                })
                break  # one finding per pattern class

    return findings


# ---------------------------------------------------------------------------
# 3. DPC and timer abuse patterns
# ---------------------------------------------------------------------------

def detect_dpc_timer_abuse(binary_data: bytes) -> List[Dict]:
    """
    Scan binary_data for DPC (Deferred Procedure Call) and timer abuse patterns.

    Patterns detected:
      - KeInitializeDpc / KeInsertQueueDpc: async kernel execution via DPC queue
      - KeSetTimerEx: high-frequency timer (look for very short intervals in context)
      - IoQueueWorkItem: work-item queued with kernel function pointer
      - KeDelayExecutionThread: sleep inside driver code — timing evasion

    Returns list of finding dicts {severity, title, detail, host, port}.
    """
    findings: List[Dict] = []

    # DPC initialisation and queuing
    dpc_markers = [
        b"KeInitializeDpc\x00",
        b"KeInitializeDpc",
        b"KeInsertQueueDpc\x00",
        b"KeInsertQueueDpc",
    ]
    for marker in dpc_markers:
        if marker in binary_data:
            findings.append({
                "severity": "HIGH",
                "title":    "DPC_QUEUED",
                "detail":   (
                    f"{marker.rstrip(b'\\x00').decode(errors='replace')} reference — "
                    "DPC queued for async kernel execution outside normal thread context; "
                    "used by rootkits to defer work to DISPATCH_LEVEL, evading some hooks"
                ),
                "host":     "localhost",
                "port":     0,
            })
            break

    # KeSetTimerEx — high-frequency timer; heuristic: immediate finding on reference,
    # severity reflects potential for <100 ms evasion timing loops
    timer_markers = [
        b"KeSetTimerEx\x00",
        b"KeSetTimerEx",
        b"KeSetTimer\x00",
        b"KeSetTimer",
    ]
    for marker in timer_markers:
        if marker in binary_data:
            findings.append({
                "severity": "HIGH",
                "title":    "HIGH_FREQUENCY_TIMER",
                "detail":   (
                    f"{marker.rstrip(b'\\x00').decode(errors='replace')} reference — "
                    "kernel timer registration; short-interval usage (<100 ms) is a "
                    "common evasion timing pattern to poll for analysis environment signals"
                ),
                "host":     "localhost",
                "port":     0,
            })
            break

    # IoQueueWorkItem — work item with kernel function pointer (MEDIUM)
    work_markers = [
        b"IoQueueWorkItem\x00",
        b"IoQueueWorkItem",
        b"IoAllocateWorkItem\x00",
        b"IoAllocateWorkItem",
    ]
    for marker in work_markers:
        if marker in binary_data:
            findings.append({
                "severity": "MEDIUM",
                "title":    "WORK_ITEM_QUEUED",
                "detail":   (
                    f"{marker.rstrip(b'\\x00').decode(errors='replace')} reference — "
                    "I/O work item queued with a kernel function pointer; "
                    "used to execute arbitrary kernel code outside DPC constraints"
                ),
                "host":     "localhost",
                "port":     0,
            })
            break

    # KeDelayExecutionThread — driver sleep loop for timing evasion
    delay_markers = [
        b"KeDelayExecutionThread\x00",
        b"KeDelayExecutionThread",
    ]
    for marker in delay_markers:
        if marker in binary_data:
            findings.append({
                "severity": "MEDIUM",
                "title":    "DRIVER_SLEEP_LOOP",
                "detail":   (
                    "KeDelayExecutionThread reference — "
                    "explicit sleep inside driver/kernel code; "
                    "used for timing evasion (sandbox timeout bypass) or "
                    "rate-limited polling loops"
                ),
                "host":     "localhost",
                "port":     0,
            })
            break

    return findings


# ---------------------------------------------------------------------------
# 4. Windows forensic artifact detection
# ---------------------------------------------------------------------------

def detect_windows_forensic_artifacts(scan_path: str = "/") -> List[Dict]:
    """
    Walk scan_path looking for Windows forensic artifact files and magic bytes.

    Artifacts detected:
      - $MFT  : NTFS master file table — full filesystem timeline available
      - .lnk  : shell link files outside AppData — execution evidence
      - Prefetch (.pf): program execution trace (magic 0x53 0x43 0x43 0x41)
      - .evtx : Windows event log (magic 45 6C 66 4C 67 00)

    Returns list of finding dicts {severity, title, detail, host, port}.
    """
    findings: List[Dict] = []

    # --- $MFT: NTFS master file table ---
    mft_path = os.path.join(scan_path, "$MFT")
    if os.path.exists(mft_path):
        try:
            size = os.path.getsize(mft_path)
            findings.append({
                "severity": "HIGH",
                "title":    "NTFS_MFT_ACCESSIBLE",
                "detail":   (
                    f"$MFT found at {mft_path} ({size} bytes) — "
                    "NTFS master file table is readable; provides full filesystem "
                    "timeline including deleted files and MAC timestamps"
                ),
                "host":     "localhost",
                "port":     0,
            })
        except OSError:
            pass

    # Magic byte constants
    LNK_MAGIC      = b"\x4c\x00\x00\x00"   # Shell Link header CLSID prefix
    PREFETCH_MAGIC  = b"\x53\x43\x43\x41"   # "SCCA" — Prefetch file signature
    EVTX_MAGIC      = b"\x45\x6c\x66\x4c\x67\x00"  # "ElfLg\0" — EVTX file magic

    # Track counts to avoid one finding per file; report once per artifact class
    lnk_hits:      List[str] = []
    prefetch_hits:  List[str] = []
    evtx_hits:      List[str] = []

    try:
        for dirpath, dirnames, filenames in os.walk(scan_path, followlinks=False):
            # Skip known-legitimate LNK locations
            low_dir = dirpath.lower()
            in_appdata = "appdata" in low_dir or "application data" in low_dir

            for fname in filenames:
                fpath = os.path.join(dirpath, fname)
                flower = fname.lower()

                # LNK files outside AppData
                if flower.endswith(".lnk") and not in_appdata:
                    try:
                        with open(fpath, "rb") as fh:
                            header = fh.read(4)
                        if header == LNK_MAGIC:
                            lnk_hits.append(fpath)
                    except OSError:
                        pass

                # Prefetch files (.pf) — Windows\Prefetch
                elif flower.endswith(".pf"):
                    try:
                        with open(fpath, "rb") as fh:
                            header = fh.read(8)
                        # Prefetch SCCA at offset 4 in some versions, 0 in others
                        if PREFETCH_MAGIC in header:
                            prefetch_hits.append(fpath)
                    except OSError:
                        pass

                # Windows event logs (.evtx)
                elif flower.endswith(".evtx"):
                    try:
                        with open(fpath, "rb") as fh:
                            header = fh.read(8)
                        if header[:6] == EVTX_MAGIC:
                            evtx_hits.append(fpath)
                    except OSError:
                        pass

    except OSError:
        pass

    if lnk_hits:
        sample = lnk_hits[:5]
        findings.append({
            "severity": "MEDIUM",
            "title":    "LNK_FILE_FOUND",
            "detail":   (
                f"{len(lnk_hits)} .lnk file(s) with valid Shell Link magic found "
                f"outside AppData — execution evidence; "
                f"sample: {', '.join(sample)}"
            ),
            "host":     "localhost",
            "port":     0,
        })

    if prefetch_hits:
        sample = prefetch_hits[:5]
        findings.append({
            "severity": "MEDIUM",
            "title":    "PREFETCH_FILE_FOUND",
            "detail":   (
                f"{len(prefetch_hits)} Prefetch file(s) with SCCA magic found — "
                f"program execution trace; reveals run count and last execution time; "
                f"sample: {', '.join(sample)}"
            ),
            "host":     "localhost",
            "port":     0,
        })

    if evtx_hits:
        sample = evtx_hits[:5]
        findings.append({
            "severity": "MEDIUM",
            "title":    "WINDOWS_EVENT_LOG_FOUND",
            "detail":   (
                f"{len(evtx_hits)} .evtx file(s) with ElfLg magic found — "
                f"Windows event log; may contain logon, process, and security events; "
                f"sample: {', '.join(sample)}"
            ),
            "host":     "localhost",
            "port":     0,
        })

    return findings


# ---------------------------------------------------------------------------
# 5. PE file header structural analysis
# ---------------------------------------------------------------------------

def analyze_pe_file(pe_data: bytes) -> List[Dict]:
    """
    Analyse raw PE bytes for structural malware indicators.

    Source: Practical Malware Analysis ch.1 (Portable Executable File Format,
    The PE File Headers and Sections, Linked Libraries and Functions) and
    ch.14 (Combining Dynamic and Static Analysis Techniques).

    Checks:
      - MZ header (0x4D 0x5A) and PE signature at e_lfanew offset
      - COFF TimeDateStamp in 2000-2020 range  -> possible backdated compile
      - NumberOfSections > 10                  -> packer/protector indicator
      - Section with SizeOfRawData=0 but       -> UPX/MPRESS packed section
        VirtualSize>0
      - IAT containing only LoadLibrary* +     -> reflective loading pattern
        GetProcAddress with no other imports
      - Rich header present but DanS marker    -> forged linker provenance
        not recoverable with stated XOR key

    Returns list of {severity, title, detail, host='localhost', port=0}.
    """
    findings: List[Dict] = []
    data = pe_data

    # ---- MZ header ----
    if len(data) < 64 or data[0:2] != b'\x4d\x5a':
        return findings

    # ---- PE signature at e_lfanew ----
    e_lfanew = struct.unpack_from('<I', data, 0x3c)[0]
    if e_lfanew + 4 > len(data) or data[e_lfanew:e_lfanew + 4] != b'PE\x00\x00':
        return findings

    # ---- IMAGE_FILE_HEADER (20 bytes) ----
    # Machine(H) NumSections(H) TimeDateStamp(I) PtrSymTbl(I) NumSym(I)
    # SizeOfOptHdr(H) Characteristics(H)
    coff_off = e_lfanew + 4
    if coff_off + 20 > len(data):
        return findings
    machine, num_sections, timestamp, _ptr_sym, _num_sym, size_opt_hdr, _chars = \
        struct.unpack_from('<HHIIIHH', data, coff_off)

    # ---- TimeDateStamp: 2000-01-01 (946684800) to 2020-01-01 (1577836800) ----
    _TS_2000 = 946684800
    _TS_2020 = 1577836800
    if _TS_2000 <= timestamp < _TS_2020:
        # Approximate year without importing datetime
        _approx_year = 1970 + timestamp // 31_536_000
        findings.append({
            'severity': 'MEDIUM',
            'title':    'PE_OLD_TIMESTAMP',
            'detail':   (
                f'COFF TimeDateStamp 0x{timestamp:08x} (~{_approx_year}) '
                'falls in the 2000-2020 range — possible backdated compile time; '
                'malware authors backdate PE headers to suggest file age and '
                'evade timeline-based triage'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # ---- Section count > 10 ----
    if num_sections > 10:
        findings.append({
            'severity': 'MEDIUM',
            'title':    'EXCESSIVE_PE_SECTIONS',
            'detail':   (
                f'NumberOfSections={num_sections} exceeds 10 — '
                'atypical for legitimate builds (3-6 is normal); '
                'common indicator of packers, protectors, or overlay segmentation'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # ---- Optional header magic -> data directory base ----
    opt_off = coff_off + 20
    if opt_off + 2 > len(data):
        return findings
    magic = struct.unpack_from('<H', data, opt_off)[0]
    if magic == 0x010B:      # PE32
        dd_off = opt_off + 96
    elif magic == 0x020B:    # PE32+
        dd_off = opt_off + 112
    else:
        return findings      # unknown optional header format

    # ---- Section table (IMAGE_SECTION_HEADER, 40 bytes each) ----
    # Name(8s) VirtualSize(I) VirtualAddress(I) SizeOfRawData(I) PointerToRawData(I)
    secs_base = opt_off + size_opt_hdr
    sections: List = []
    for idx in range(num_sections):
        sh = secs_base + idx * 40
        if sh + 24 > len(data):
            break
        name_b, vsize, vaddr, raw_size, raw_off = struct.unpack_from('<8sIIII', data, sh)
        sections.append((
            name_b.rstrip(b'\x00').decode('ascii', errors='replace'),
            vsize, vaddr, raw_size, raw_off,
        ))

    def _rva_to_off(rva: int) -> int:
        """Convert RVA to file offset using section table. Returns -1 on failure."""
        for _n, vs, va, rs, ro in sections:
            if va <= rva < va + max(vs, rs):
                return ro + (rva - va)
        return -1

    # ---- Zero-raw-size section -> packed executable ----
    for sec_name, vsize, _va, raw_size, _ro in sections:
        if raw_size == 0 and vsize > 0:
            findings.append({
                'severity': 'HIGH',
                'title':    'ZERO_RAW_SIZE_SECTION',
                'detail':   (
                    f"Section '{sec_name}': SizeOfRawData=0 but "
                    f'VirtualSize=0x{vsize:x} — packed executable pattern (UPX, MPRESS); '
                    'packer stub decompresses code at runtime into the '
                    'pre-allocated virtual region; on-disk section carries no code'
                ),
                'host': 'localhost',
                'port': 0,
            })
            break  # one finding per file

    # ---- Import directory: dynamic-only import check ----
    # Data directory index 1 (Import Table) at dd_off + 8
    if dd_off + 16 <= len(data):
        imp_rva, _ = struct.unpack_from('<II', data, dd_off + 8)
        if imp_rva:
            imp_off = _rva_to_off(imp_rva)
            if imp_off >= 0:
                all_fns: List[str] = []
                desc = imp_off
                while desc + 20 <= len(data):
                    # IMAGE_IMPORT_DESCRIPTOR: ILT_RVA(I) TS(I) Fwd(I) DLL_Name_RVA(I) IAT_RVA(I)
                    ilt_rva, _ts2, _fwd, dll_rva, iat_rva = \
                        struct.unpack_from('<IIIII', data, desc)
                    if ilt_rva == 0 and dll_rva == 0:
                        break
                    thunk_rva = ilt_rva or iat_rva
                    ptr_sz = 8 if magic == 0x020B else 4
                    if thunk_rva:
                        t = _rva_to_off(thunk_rva)
                        if t >= 0:
                            while t + ptr_sz <= len(data):
                                entry = (
                                    struct.unpack_from('<Q', data, t)[0]
                                    if ptr_sz == 8
                                    else struct.unpack_from('<I', data, t)[0]
                                )
                                if entry == 0:
                                    break
                                ord_bit = (1 << 63) if ptr_sz == 8 else (1 << 31)
                                if not (entry & ord_bit):
                                    # RVA to IMAGE_IMPORT_BY_NAME: skip 2-byte hint, read name
                                    hint_rva = int(entry & (ord_bit - 1))
                                    h = _rva_to_off(hint_rva)
                                    if h >= 0 and h + 2 < len(data):
                                        fn_end = data.find(b'\x00', h + 2)
                                        if 0 < fn_end - h - 2 < 256:
                                            all_fns.append(
                                                data[h + 2:fn_end].decode(
                                                    'ascii', errors='replace'))
                                t += ptr_sz
                    desc += 20

                _LOADERS = {
                    'LoadLibraryA', 'LoadLibraryW',
                    'LoadLibraryExA', 'LoadLibraryExW',
                    'GetProcAddress',
                }
                fn_set = set(all_fns)
                _has_load = bool({'LoadLibraryA', 'LoadLibraryW',
                                  'LoadLibraryExA', 'LoadLibraryExW'} & fn_set)
                _has_gpa  = 'GetProcAddress' in fn_set
                _only_ldr = all(f in _LOADERS for f in all_fns)
                if _has_load and _has_gpa and _only_ldr and all_fns:
                    findings.append({
                        'severity': 'HIGH',
                        'title':    'DYNAMIC_IMPORT_ONLY',
                        'detail':   (
                            'IAT contains only LoadLibrary*/GetProcAddress with no other '
                            'static imports — all remaining API calls resolved at runtime; '
                            'reflective DLL loading / shellcode injection pattern; '
                            'static import analysis will not surface actual API surface'
                        ),
                        'host': 'localhost',
                        'port': 0,
                    })

    # ---- Rich header anomaly ----
    # Rich header sits in DOS stub (between 0x40 and e_lfanew):
    # [DanS XOR key][padding][CompId/Count pairs XOR key]...[Rich][key]
    search_cap = min(e_lfanew, len(data))
    rich_pos = data.find(b'Rich', 4, search_cap)
    if rich_pos != -1 and rich_pos + 8 <= search_cap:
        xor_key = struct.unpack_from('<I', data, rich_pos + 4)[0]
        # DanS (0x44614e53) appears XOR'd with the key at the block start
        dans_enc = struct.pack('<I', 0x44614e53 ^ xor_key)
        if data.find(dans_enc, 0x40, rich_pos) == -1:
            findings.append({
                'severity': 'MEDIUM',
                'title':    'RICH_HEADER_ANOMALY',
                'detail':   (
                    f'Rich header at offset 0x{rich_pos:x} with XOR key 0x{xor_key:08x} '
                    '— DanS marker not recoverable; '
                    'Rich header may be forged, stripped, or hand-crafted; '
                    'linker toolchain provenance and version data are unreliable'
                ),
                'host': 'localhost',
                'port': 0,
            })

    return findings


# ---------------------------------------------------------------------------
# 6. PE resource directory analysis
# ---------------------------------------------------------------------------

def analyze_pe_resources(pe_data: bytes) -> List[Dict]:
    """
    Parse the PE resource directory (.rsrc) for malware-relevant patterns.

    Source: Practical Malware Analysis ch.1 (The PE File Headers and Sections —
    Viewing the Resource Section with Resource Hacker) and ch.14 / ch.19
    (shellcode embedded in media/resource sections).

    Checks:
      - Any resource blob starting with MZ header   -> CRITICAL dropper pattern
        (embedded PE executable)
      - RT_MANIFEST (type 24) requesting admin       -> HIGH UAC elevation intent
        elevation level
      - RT_VERSION (type 16) naming 'Microsoft' in  -> HIGH fake Microsoft identity
        CompanyName or ProductName strings
      - Resource section > 90% of total file size   -> HIGH data-hiding pattern

    Returns list of {severity, title, detail, host='localhost', port=0}.
    """
    findings: List[Dict] = []
    data = pe_data

    # ---- Basic PE validity (duplicate of analyze_pe_file intentionally; standalone) ----
    if len(data) < 64 or data[0:2] != b'\x4d\x5a':
        return findings
    e_lfanew = struct.unpack_from('<I', data, 0x3c)[0]
    if e_lfanew + 4 > len(data) or data[e_lfanew:e_lfanew + 4] != b'PE\x00\x00':
        return findings
    coff_off = e_lfanew + 4
    if coff_off + 20 > len(data):
        return findings
    _mach, num_sections, _ts, _ps, _ns, size_opt_hdr, _ch = \
        struct.unpack_from('<HHIIIHH', data, coff_off)
    opt_off = coff_off + 20
    if opt_off + 2 > len(data):
        return findings
    magic = struct.unpack_from('<H', data, opt_off)[0]
    if magic == 0x010B:
        dd_off = opt_off + 96
    elif magic == 0x020B:
        dd_off = opt_off + 112
    else:
        return findings

    secs_base = opt_off + size_opt_hdr
    sections: List = []
    for idx in range(num_sections):
        sh = secs_base + idx * 40
        if sh + 24 > len(data):
            break
        name_b, vsize, vaddr, raw_size, raw_off = struct.unpack_from('<8sIIII', data, sh)
        sections.append((
            name_b.rstrip(b'\x00').decode('ascii', errors='replace'),
            vsize, vaddr, raw_size, raw_off,
        ))

    def _rva_to_off(rva: int) -> int:
        for _n, vs, va, rs, ro in sections:
            if va <= rva < va + max(vs, rs):
                return ro + (rva - va)
        return -1

    # ---- Resource-heavy PE check ----
    # Data directory index 2 (Resource Table) at dd_off + 16
    total_sz = len(data)
    if dd_off + 24 <= len(data):
        res_rva_chk, _ = struct.unpack_from('<II', data, dd_off + 16)
        if res_rva_chk and total_sz > 0:
            for _sn, vs, va, rs, _ro in sections:
                if va <= res_rva_chk < va + max(vs, rs):
                    sec_bytes = max(vs, rs)
                    if sec_bytes / total_sz > 0.90:
                        findings.append({
                            'severity': 'HIGH',
                            'title':    'RESOURCE_HEAVY_PE',
                            'detail':   (
                                f'Resource section is {sec_bytes}/{total_sz} bytes '
                                f'({100 * sec_bytes // total_sz}% of file) — '
                                'executable or encrypted payload may be hidden inside '
                                'resources; common dropper technique to evade '
                                'size-based static heuristics'
                            ),
                            'host': 'localhost',
                            'port': 0,
                        })
                    break

    # ---- Resolve resource directory base ----
    if dd_off + 24 > len(data):
        return findings
    res_rva, _ = struct.unpack_from('<II', data, dd_off + 16)
    if not res_rva:
        return findings
    res_base = _rva_to_off(res_rva)
    if res_base < 0 or res_base >= len(data):
        return findings

    # ---- Resource tree helpers ----
    def _rsrc_entries(dir_off: int):
        """
        Yield (type_id_or_None, is_named, is_subdir, ptr) entries from an
        IMAGE_RESOURCE_DIRECTORY at section-relative offset dir_off.
        IMAGE_RESOURCE_DIRECTORY layout (16 bytes):
          Characteristics(I) TimeDateStamp(I) Major(H) Minor(H)
          NumberOfNamedEntries(H) NumberOfIdEntries(H)
        Each IMAGE_RESOURCE_DIRECTORY_ENTRY is 8 bytes: NameOrId(I) DataOrSubdir(I).
        High bit of NameOrId: 1=name string, 0=integer ID.
        High bit of DataOrSubdir: 1=subdirectory offset, 0=data entry offset.
        All offsets are relative to the start of the resource section.
        """
        abs_off = res_base + dir_off
        if abs_off + 16 > len(data):
            return
        _, _, _, _, num_named, num_id = struct.unpack_from('<IIHHHH', data, abs_off)
        ent_base = abs_off + 16
        for i in range(num_named + num_id):
            ep = ent_base + i * 8
            if ep + 8 > len(data):
                break
            nid, ptr = struct.unpack_from('<II', data, ep)
            is_named = bool(nid & 0x80000000)
            is_sub   = bool(ptr & 0x80000000)
            yield (None if is_named else nid, is_named, is_sub, ptr & 0x7FFFFFFF)

    def _get_blobs(type_id: int):
        """
        Walk root (type) -> name -> language resource tree for the given type_id
        and yield raw bytes for each leaf IMAGE_RESOURCE_DATA_ENTRY.
        IMAGE_RESOURCE_DATA_ENTRY: DataRVA(I) Size(I) CodePage(I) Reserved(I).
        """
        for tid, _, is_sub1, ptr1 in _rsrc_entries(0):
            if tid != type_id or not is_sub1:
                continue
            for _, _, is_sub2, ptr2 in _rsrc_entries(ptr1):
                if not is_sub2:
                    continue
                for _, _, is_sub3, ptr3 in _rsrc_entries(ptr2):
                    if is_sub3:
                        continue
                    de = res_base + ptr3
                    if de + 8 > len(data):
                        continue
                    d_rva, d_sz = struct.unpack_from('<II', data, de)
                    d_off = _rva_to_off(d_rva)
                    if d_off >= 0 and d_off + d_sz <= len(data) and d_sz > 0:
                        yield data[d_off:d_off + d_sz]

    # ---- Embedded PE in any resource: scan all leaves ----
    found_pe = False
    for tid, _, is_sub1, ptr1 in _rsrc_entries(0):
        if not is_sub1 or found_pe:
            break
        for _, _, is_sub2, ptr2 in _rsrc_entries(ptr1):
            if not is_sub2 or found_pe:
                break
            for _, _, is_sub3, ptr3 in _rsrc_entries(ptr2):
                if is_sub3:
                    continue
                de = res_base + ptr3
                if de + 8 > len(data):
                    continue
                d_rva, d_sz = struct.unpack_from('<II', data, de)
                d_off = _rva_to_off(d_rva)
                if d_off >= 0 and d_off + 2 <= len(data) \
                        and data[d_off:d_off + 2] == b'\x4d\x5a':
                    type_label = f'type={tid}' if tid is not None else 'named-type'
                    findings.append({
                        'severity': 'CRITICAL',
                        'title':    'PE_IN_RESOURCE',
                        'detail':   (
                            f'MZ signature at byte 0 of resource ({type_label}) — '
                            'embedded PE executable in .rsrc section; '
                            'dropper pattern: payload extracted and executed at runtime '
                            'via WriteFile/CreateProcess or LoadLibrary'
                        ),
                        'host': 'localhost',
                        'port': 0,
                    })
                    found_pe = True
                    break

    # ---- RT_MANIFEST (type 24): requireAdministrator elevation ----
    for blob in _get_blobs(24):
        try:
            text = blob.decode('utf-8', errors='replace')
        except Exception:
            text = ''
        if 'requireAdministrator' in text:
            findings.append({
                'severity': 'HIGH',
                'title':    'UAC_ELEVATION_MANIFEST',
                'detail':   (
                    'RT_MANIFEST contains '
                    'requestedExecutionLevel level="requireAdministrator" — '
                    'PE requests full UAC elevation at launch; '
                    'expected in legitimate admin tools; '
                    'in malware context signals deliberate privilege escalation'
                ),
                'host': 'localhost',
                'port': 0,
            })
            break

    # ---- RT_VERSION (type 16): fake Microsoft version strings ----
    # VS_VERSIONINFO stores strings as UTF-16LE; match both encodings
    _ms_re = re.compile(
        rb'M\x00i\x00c\x00r\x00o\x00s\x00o\x00f\x00t|Microsoft',
        re.IGNORECASE,
    )
    for blob in _get_blobs(16):
        if _ms_re.search(blob):
            findings.append({
                'severity': 'HIGH',
                'title':    'FAKE_MICROSOFT_VERSIONINFO',
                'detail':   (
                    'RT_VERSION resource contains "Microsoft" in '
                    'CompanyName or ProductName — '
                    'version strings claim Microsoft origin; '
                    'verify Authenticode certificate chain; '
                    'unsigned or third-party-signed PE with Microsoft '
                    'version strings is a common binary masquerading technique'
                ),
                'host': 'localhost',
                'port': 0,
            })
            break

    return findings


# ---------------------------------------------------------------------------
# 7. Mutex artifact detection
# ---------------------------------------------------------------------------

def detect_mutex_artifacts(binary_data: bytes) -> list:
    """Detect mutex-related Windows API usage indicating single-instance or C2
    synchronization patterns.

    Source: Practical Malware Analysis, Appendix A (CreateMutex / OpenMutex
    entries) -- fixed mutex names are host-based IOCs for malware reinstall
    prevention and C2 coordination.
    """
    findings: list = []

    # ---- CreateMutex / CreateMutexA / CreateMutexW presence ----
    _create_re = re.compile(rb'CreateMutex[AW]?\x00', re.IGNORECASE)
    create_matches = _create_re.findall(binary_data)

    if create_matches:
        findings.append({
            'severity': 'MEDIUM',
            'title':    'MUTEX_CREATION',
            'detail':   (
                f'CreateMutex/CreateMutexA/CreateMutexW import string detected '
                f'({len(create_matches)} occurrence(s)) -- '
                'single-instance malware or C2 synchronization sentinel; '
                'malware uses fixed mutex names as host-based indicators; '
                'extract mutex name argument for threat actor attribution'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # ---- Multiple CreateMutex (>3) = complex multi-component persistence ----
    if len(create_matches) > 3:
        findings.append({
            'severity': 'HIGH',
            'title':    'MULTIPLE_MUTEX_CREATION',
            'detail':   (
                f'{len(create_matches)} CreateMutex string references detected -- '
                'complex persistence mechanism; '
                'multiple mutexes guard separate malware components or parallel '
                'C2 channels; enumerate all mutex name arguments for full IOC set'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # ---- Suspicious mutex name: Global\ or Local\ namespace prefix ----
    # In PE string tables these appear as literal ASCII/UTF-16LE bytes
    _global_re = re.compile(
        rb'(?:Global|Local)\\[A-Za-z0-9_\-\.]{3,}',
        re.IGNORECASE,
    )
    gm = _global_re.search(binary_data)
    if gm:
        findings.append({
            'severity': 'HIGH',
            'title':    'SUSPICIOUS_MUTEX_NAME',
            'detail':   (
                f'Mutex name with Global\\ or Local\\ namespace prefix found '
                f'(sample: {gm.group(0)[:48].decode("latin-1", errors="replace")!r}) -- '
                'named kernel mutex characteristic of malware anti-reinstall logic '
                'or C2 synchronization; '
                'fixed name is a reliable host-based indicator; '
                'cross-reference against known malware mutex IOC databases'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # ---- OpenMutex without CreateMutex = existence check only ----
    _open_re = re.compile(rb'OpenMutex[AW]?\x00', re.IGNORECASE)
    if _open_re.search(binary_data) and not create_matches:
        findings.append({
            'severity': 'HIGH',
            'title':    'MUTEX_EXISTENCE_CHECK',
            'detail':   (
                'OpenMutex detected without corresponding CreateMutex -- '
                'malware checking if already installed before executing second stage; '
                'common anti-reinstall sentinel: if mutex exists, sample exits silently; '
                'mutex name is the host-based indicator -- extract from call argument'
            ),
            'host': 'localhost',
            'port': 0,
        })

    return findings


# ---------------------------------------------------------------------------
# 8. Clipboard monitor / hijack detection
# ---------------------------------------------------------------------------

def detect_clipboard_monitor(binary_data: bytes) -> list:
    """Detect Windows clipboard API usage indicating monitoring or hijacking.

    Source: Practical Malware Analysis, Appendix A (SetWindowsHookEx /
    GetAsyncKeyState / credential stealer chapter) -- clipboard interception
    is a common infostealer and crypto-hijack primitive.
    """
    findings: list = []

    # ---- SetClipboardViewer / AddClipboardFormatListener = persistent monitor ----
    _viewer_re = re.compile(
        rb'(?:SetClipboardViewer|AddClipboardFormatListener)\x00',
        re.IGNORECASE,
    )
    if _viewer_re.search(binary_data):
        findings.append({
            'severity': 'CRITICAL',
            'title':    'CLIPBOARD_MONITOR',
            'detail':   (
                'SetClipboardViewer or AddClipboardFormatListener import detected -- '
                'process registers as a system-wide clipboard change listener; '
                'receives WM_DRAWCLIPBOARD / WM_CLIPBOARDUPDATE on every clipboard '
                'write; keystroke/data theft vector used by banking trojans, '
                'RATs, and credential stealers to intercept copied passwords and tokens'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # ---- Presence flags for hijack triplet ----
    _open_re  = re.compile(rb'OpenClipboard\x00',    re.IGNORECASE)
    _get_re   = re.compile(rb'GetClipboardData\x00', re.IGNORECASE)
    _set_re   = re.compile(rb'SetClipboardData\x00', re.IGNORECASE)
    has_open  = bool(_open_re.search(binary_data))
    has_get   = bool(_get_re.search(binary_data))
    has_set   = bool(_set_re.search(binary_data))

    # ---- OpenClipboard + GetClipboardData + SetClipboardData = MITC hijack ----
    if has_open and has_get and has_set:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'CLIPBOARD_HIJACK',
            'detail':   (
                'OpenClipboard + GetClipboardData + SetClipboardData all present -- '
                'man-in-the-clipboard (MITC) pattern: reads clipboard content then '
                'overwrites with attacker-controlled data before user pastes; '
                'primary cryptocurrency address substitution vector; '
                'also used to inject malicious commands into terminal paste workflows'
            ),
            'host': 'localhost',
            'port': 0,
        })
    elif has_get:
        # ---- GetClipboardData alone = read-only credential interception ----
        findings.append({
            'severity': 'HIGH',
            'title':    'CLIPBOARD_READ',
            'detail':   (
                'GetClipboardData detected (no SetClipboardData) -- '
                'read-only clipboard interception; '
                'credential/data theft: copies clipboard contents for exfiltration; '
                'common in infostealers targeting copied passwords, API keys, '
                'and session tokens; correlate with network send primitives '
                'to confirm exfiltration channel'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # ---- CF_TEXT / CF_UNICODETEXT format constant strings ----
    _fmt_re = re.compile(rb'CF_(?:UNICODETEXT|TEXT)\x00', re.IGNORECASE)
    if _fmt_re.search(binary_data):
        findings.append({
            'severity': 'MEDIUM',
            'title':    'CLIPBOARD_TEXT_FORMAT',
            'detail':   (
                'CF_TEXT or CF_UNICODETEXT clipboard format constant detected '
                'as string in binary -- '
                'malware explicitly requests text-format clipboard data; '
                'targets copied plaintext: passwords, wallet addresses, session tokens; '
                'correlate with GetClipboardData and network exfiltration imports'
            ),
            'host': 'localhost',
            'port': 0,
        })

    return findings


def detect_rootkit_hiding_indicators(binary_data: bytes) -> list:
    """Detect kernel and user-mode rootkit API patterns indicating process, file,
    registry, and memory hiding techniques.

    Grounded in PMA ch10 (rootkits): SSDT hooking routes through
    NtQuerySystemInformation/SystemProcessInformation to conceal processes;
    ZwQueryDirectoryFile / NtQueryDirectoryFile is the directory-enum intercept
    point for file hiding; PsLookupProcessByProcessId is the kernel primitive for
    DKOM (Direct Kernel Object Manipulation) process unlinking; MmMapIoSpace /
    MmGetPhysicalAddress give raw physical-memory access below the OS page-table
    layer, bypassing all virtual-address-space visibility; NtQueryKey +
    NtEnumerateValueKey together form the registry enumeration pair targeted by
    kernel registry-hiding hooks.
    """
    import re

    findings = []

    # ---- PROCESS_HIDING_API: NtQuerySystemInformation + SystemProcessInformation ----
    _nqsi_re  = re.compile(rb'NtQuerySystemInformation\x00', re.IGNORECASE)
    _spi_re   = re.compile(rb'SystemProcessInformation\x00', re.IGNORECASE)
    has_nqsi  = bool(_nqsi_re.search(binary_data))
    has_spi   = bool(_spi_re.search(binary_data))

    if has_nqsi and has_spi:
        findings.append({
            'severity': 'HIGH',
            'title':    'PROCESS_HIDING_API',
            'detail':   (
                'NtQuerySystemInformation + SystemProcessInformation both present -- '
                'rootkit process enumeration bypass: hooking NtQuerySystemInformation '
                'with class SystemProcessInformation (0x05) is the canonical SSDT-hook '
                'technique for hiding processes from Task Manager and Process Explorer; '
                'hook filters SYSTEM_PROCESS_INFORMATION linked list before returning '
                'to caller, removing entries for protected PIDs; '
                'correlate with SSDT-hook installation primitives (KeServiceDescriptorTable, '
                'MmGetSystemRoutineAddress) and driver load artifacts'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # ---- FILE_HIDING_API: ZwQueryDirectoryFile or NtQueryDirectoryFile ----
    _zqdf_re = re.compile(rb'(?:Zw|Nt)QueryDirectoryFile\x00', re.IGNORECASE)
    if _zqdf_re.search(binary_data):
        findings.append({
            'severity': 'HIGH',
            'title':    'FILE_HIDING_API',
            'detail':   (
                'ZwQueryDirectoryFile or NtQueryDirectoryFile detected -- '
                'rootkit directory enumeration bypass: hooking this syscall allows '
                'the rootkit to intercept directory listings and strip FILE_DIRECTORY_INFORMATION '
                'entries for hidden files before the buffer is returned to user space; '
                'used in conjunction with NtCreateFile hooks to achieve full file invisibility; '
                'classic technique demonstrated in PMA lab rootkit samples; '
                'presence in a driver binary is a strong indicator of file-hiding intent'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # ---- KERNEL_PROCESS_LOOKUP: PsLookupProcessByProcessId (DKOM) ----
    _pslookup_re = re.compile(rb'PsLookupProcessByProcessId\x00', re.IGNORECASE)
    if _pslookup_re.search(binary_data):
        findings.append({
            'severity': 'CRITICAL',
            'title':    'KERNEL_PROCESS_LOOKUP',
            'detail':   (
                'PsLookupProcessByProcessId detected -- '
                'DKOM (Direct Kernel Object Manipulation) rootkit technique: '
                'this kernel export resolves an EPROCESS pointer from a PID, '
                'enabling the rootkit to directly manipulate the EPROCESS doubly-linked list '
                '(ActiveProcessLinks) to unlink a process entry, rendering it invisible '
                'to all enumeration paths that walk this list (Task Manager, Process32Next, '
                'NtQuerySystemInformation); DKOM is harder to detect than SSDT hooking '
                'because no system call is modified -- the data structure itself is corrupted; '
                'presence in kernel driver code is a critical indicator of process-cloaking capability'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # ---- PHYSICAL_MEMORY_MAP: MmMapIoSpace or MmGetPhysicalAddress ----
    _phys_re = re.compile(rb'Mm(?:MapIoSpace|GetPhysicalAddress)\x00', re.IGNORECASE)
    if _phys_re.search(binary_data):
        findings.append({
            'severity': 'CRITICAL',
            'title':    'PHYSICAL_MEMORY_MAP',
            'detail':   (
                'MmMapIoSpace or MmGetPhysicalAddress detected -- '
                'hardware-level hiding via direct physical memory access: '
                'MmMapIoSpace maps a physical address range into kernel virtual address space, '
                'bypassing OS page-table and virtual memory abstractions; '
                'MmGetPhysicalAddress translates a virtual address to its physical counterpart; '
                'used by advanced rootkits to read/write physical memory directly, '
                'hiding artifacts below the OS memory manager visibility layer; '
                'also used to patch MBR or firmware regions from kernel mode; '
                'legitimate drivers (hardware HALs) use these -- cross-correlate with '
                'absence of hardware PnP identifiers and presence of hiding-related imports'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # ---- REGISTRY_HIDING_API: NtQueryKey + NtEnumerateValueKey ----
    _ntqk_re  = re.compile(rb'NtQueryKey\x00', re.IGNORECASE)
    _ntevk_re = re.compile(rb'NtEnumerateValueKey\x00', re.IGNORECASE)
    has_ntqk  = bool(_ntqk_re.search(binary_data))
    has_ntevk = bool(_ntevk_re.search(binary_data))

    if has_ntqk and has_ntevk:
        findings.append({
            'severity': 'HIGH',
            'title':    'REGISTRY_HIDING_API',
            'detail':   (
                'NtQueryKey + NtEnumerateValueKey both present -- '
                'registry entry concealment: hooking these two syscalls enables '
                'a rootkit to intercept registry enumeration and strip key/value entries '
                'from the returned buffer before it reaches user-space callers; '
                'NtQueryKey retrieves metadata about a key (subkey count, class) '
                'and NtEnumerateValueKey walks value entries -- both must be hooked '
                'to achieve complete registry invisibility for persistence keys; '
                'correlate with SSDT hook installation primitives and known persistence paths '
                '(Run, Services, Winlogon)'
            ),
            'host': 'localhost',
            'port': 0,
        })

    return findings


def detect_bootkit_indicators(binary_data: bytes) -> list:
    """Detect bootkit and MBR/VBR manipulation indicators in binary data.

    Covers raw disk device access strings targeting physical drive paths,
    MBR boot signature (0x55 0xAA at byte offset 510), disk geometry DeviceIoControl
    patterns used for MBR analysis, and VBR-like JMP-short opcode clusters at
    file start consistent with boot sector code headers.
    """
    import re
    import struct

    findings = []

    # ---- RAW_DISK_ACCESS: PhysicalDrive0 or GLOBALROOT HarddiskVolume paths ----
    _rawdisk_re = re.compile(
        rb'\\\\\.\\\\?(?:PhysicalDrive\d|GLOBALROOT\\Device\\Harddisk)',
        re.IGNORECASE,
    )
    if _rawdisk_re.search(binary_data):
        findings.append({
            'severity': 'HIGH',
            'title':    'RAW_DISK_ACCESS',
            'detail':   (
                r'\\.\PhysicalDrive0 or \\.\GLOBALROOT\Device\HarddiskVolume path '
                'string detected in binary -- '
                'MBR/bootkit manipulation vector: opening a PhysicalDrive handle '
                'with CreateFile bypasses the filesystem layer and grants direct '
                'read/write access to raw disk sectors including the MBR (LBA 0); '
                'bootkits use this path to overwrite the MBR with malicious bootstrap '
                'code that executes before the OS loader, persisting below OS visibility; '
                'GLOBALROOT device paths are used to access volume boot records (VBR) '
                'on specific partitions; legitimate disk utilities also use these paths -- '
                'correlate with WriteFile calls and absence of forensic/backup imports'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # ---- MBR_CONTENT: 0x55 0xAA boot signature at byte offset 510 ----
    if len(binary_data) >= 512:
        sig = struct.unpack_from('<H', binary_data, 510)[0]
        if sig == 0xAA55:
            findings.append({
                'severity': 'HIGH',
                'title':    'MBR_CONTENT',
                'detail':   (
                    'MBR boot signature 0x55 0xAA found at byte offset 510-511 -- '
                    'boot sector code embedded in binary: the master boot record '
                    'signature marks valid MBR content; presence inside a PE or '
                    'data binary indicates an embedded boot sector payload; '
                    'bootkits carry MBR replacement code as a blob within the dropper, '
                    'which is then written to LBA 0 via a raw disk handle; '
                    'the original MBR is typically relocated to another sector by the bootkit '
                    'to preserve chainloading while intercepting the boot sequence; '
                    'inspect surrounding 512-byte block for INT 13h calls and partition table structure'
                ),
                'host': 'localhost',
                'port': 0,
            })

    # ---- DISK_GEOMETRY_QUERY: DeviceIoControl + IOCTL_DISK_GET_DRIVE_GEOMETRY ----
    _devio_re     = re.compile(rb'DeviceIoControl\x00', re.IGNORECASE)
    _ioctl_str_re = re.compile(rb'IOCTL_DISK_GET_DRIVE_GEOMETRY\x00', re.IGNORECASE)
    # Also match the literal IOCTL code 0x00070000 as a 4-byte LE constant in data
    _ioctl_hex_re = re.compile(rb'\x00\x00\x07\x00', re.DOTALL)
    has_devio     = bool(_devio_re.search(binary_data))
    has_ioctl_s   = bool(_ioctl_str_re.search(binary_data))
    has_ioctl_b   = bool(_ioctl_hex_re.search(binary_data))

    if has_devio and (has_ioctl_s or has_ioctl_b):
        findings.append({
            'severity': 'HIGH',
            'title':    'DISK_GEOMETRY_QUERY',
            'detail':   (
                'DeviceIoControl + IOCTL_DISK_GET_DRIVE_GEOMETRY (0x00070000) detected -- '
                'MBR analysis preparation: querying disk geometry (cylinders, tracks, '
                'sectors per track, bytes per sector) is a prerequisite step for '
                'bootkit code that must calculate absolute LBA addresses for MBR '
                'and VBR sectors before patching; returned geometry values are used '
                'to construct the DISK_GEOMETRY structure needed for subsequent '
                'raw sector reads/writes via IOCTL_DISK_READ_ABSOLUTE or direct '
                'WriteFile to a PhysicalDrive handle; '
                'correlate with raw disk access paths (PhysicalDrive0) and WriteFile imports'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # ---- VBR_LIKE_HEADER: multiple JMP short (0xEB) opcodes at file start ----
    # Volume Boot Records begin with a JMP short + NOP (0xEB xx 0x90) sequence;
    # two or more 0xEB bytes in the first 16 bytes of the file is a strong VBR marker.
    if len(binary_data) >= 16:
        header_slice = binary_data[:16]
        jmp_short_count = header_slice.count(b'\xEB')
        if jmp_short_count >= 2:
            findings.append({
                'severity': 'MEDIUM',
                'title':    'VBR_LIKE_HEADER',
                'detail':   (
                    f'JMP short opcode (0xEB) found {jmp_short_count} times in first 16 bytes -- '
                    'VBR-like header pattern: BIOS Parameter Block (BPB) layout in FAT/NTFS '
                    'Volume Boot Records begins with JMP SHORT + NOP (EB xx 90) to skip '
                    'the BPB data block; multiple 0xEB bytes at file start are consistent '
                    'with boot sector code structure; standalone boot sector blobs embedded '
                    'in droppers exhibit this pattern before they are written to a VBR partition; '
                    'low-confidence standalone indicator -- combine with MBR_CONTENT, '
                    'RAW_DISK_ACCESS, or DISK_GEOMETRY_QUERY to elevate confidence'
                ),
                'host': 'localhost',
                'port': 0,
            })

    return findings


def detect_office_macro_indicators(binary_data: bytes) -> list:
    """
    Detect Office document macro malware indicators in raw binary data.
    Covers OLE2 container format, VBA project presence, auto-executing macros,
    shell execution primitives, and macro-embedded URLs (downloader pattern).
    Source: Practical Malware Analysis (Sikorski/Honig) -- malware behavior and
    basic static techniques applied to document-format delivery vectors.
    """
    findings = []

    # ---- OLE2_DOCUMENT: OLE2 compound document magic bytes ----
    OLE2_MAGIC = b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1'
    if binary_data[:8] == OLE2_MAGIC:
        findings.append({
            'severity': 'MEDIUM',
            'title':    'OLE2_DOCUMENT',
            'detail':   (
                'OLE2 compound document magic (D0 CF 11 E0 A1 B1 1A E1) detected at offset 0 -- '
                'Structured Storage / Compound File Binary Format container; used by all pre-OOXML '
                'Office formats (.doc/.xls/.ppt) and some hybrid .docm/.xlsm files; '
                'OLE2 is the outer container for VBA macro storage streams (VBA Storage -> '
                'VBA/dir, VBA/_VBA_PROJECT, VBA/Module streams); '
                'malicious macros always live inside an OLE2 container regardless of '
                'file extension; correlate with VBA_MACRO_PRESENT'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # ---- VBA_MACRO_PRESENT: VBA project stream signature ----
    has_vba = b'VBA' in binary_data or b'VBAProject' in binary_data
    if has_vba:
        findings.append({
            'severity': 'HIGH',
            'title':    'VBA_MACRO_PRESENT',
            'detail':   (
                'VBA or VBAProject string found in document binary -- '
                'Office macro detected: VBA stream presence confirms an embedded '
                'Visual Basic for Applications macro project; the VBA storage stream '
                '(_VBA_PROJECT) contains compiled p-code and the compressed source; '
                'macro code is the primary delivery mechanism for malware in phishing '
                'campaigns; malicious macros range from simple downloaders to full '
                'implant installers; static extraction of VBA source requires '
                'decompression of the module stream (RLE compression, offset from dir stream); '
                'correlate with AUTO_EXEC_MACRO and MACRO_SHELL_EXEC'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # ---- AUTO_EXEC_MACRO: auto-executing macro entry points ----
    auto_exec_triggers = [b'AutoOpen', b'Auto_Open', b'Document_Open', b'Workbook_Open']
    found_auto = [t.decode() for t in auto_exec_triggers if t in binary_data]
    if found_auto:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'AUTO_EXEC_MACRO',
            'detail':   (
                f'Auto-executing macro trigger(s) found: {", ".join(found_auto)} -- '
                'macro executes automatically on document open without user interaction; '
                'AutoOpen / Auto_Open fire when a Word/Excel document is opened; '
                'Document_Open is the modern Word event handler (Workbook_Open for Excel); '
                'attackers rely on these entry points to bypass the need for the victim '
                'to manually run a macro; combined with social engineering that disables '
                'the macro security prompt, these triggers achieve zero-click execution '
                'from a phishing attachment; '
                'this is the primary delivery mechanism in most commodity malware campaigns'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # ---- MACRO_SHELL_EXEC: shell execution primitives near VBA content ----
    # Windowed search: shell strings within 64KB of any VBA marker indicate
    # macro-context shell execution (vs. incidental PE import strings elsewhere).
    _WINDOW = 65536
    shell_indicators = [b'Shell', b'WScript.Shell', b'CreateObject']

    vba_positions = []
    for marker in (b'VBA', b'VBAProject'):
        pos = 0
        while True:
            idx = binary_data.find(marker, pos)
            if idx == -1:
                break
            vba_positions.append(idx)
            pos = idx + 1

    found_shell = []
    if vba_positions:
        for si in shell_indicators:
            pos = 0
            while True:
                idx = binary_data.find(si, pos)
                if idx == -1:
                    break
                if any(abs(idx - vp) <= _WINDOW for vp in vba_positions):
                    found_shell.append(si.decode())
                    break
                pos = idx + 1

    if found_shell:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'MACRO_SHELL_EXEC',
            'detail':   (
                f'Shell execution primitive(s) near VBA content: {", ".join(found_shell)} -- '
                'macro-based shell execution: Shell() is a VBA built-in that spawns a process; '
                'WScript.Shell is a COM object (CreateObject("WScript.Shell")) giving access '
                'to Run(), Exec(), and RegWrite(); CreateObject is the generic COM '
                'instantiation call used to access WScript.Shell, ADODB.Stream, '
                'and other automation objects; these are the standard primitives for '
                'macro-based command execution, file writes, and registry modification; '
                'attacker pattern: macro downloads payload via URLDownloadToFile or '
                'ADODB.Stream, writes to %TEMP%, then launches via Shell or WScript.Shell.Run; '
                'presence near VBA content indicates execution capability within macro context'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # ---- MACRO_URL_PRESENT: http/https URLs in macro region (downloader pattern) ----
    url_indicators = [b'http://', b'https://']
    found_urls = []
    if vba_positions:
        for ui in url_indicators:
            pos = 0
            while True:
                idx = binary_data.find(ui, pos)
                if idx == -1:
                    break
                if any(abs(idx - vp) <= _WINDOW for vp in vba_positions):
                    end = min(idx + 80, len(binary_data))
                    snippet = re.sub(rb'[^\x20-\x7e]', b'?', binary_data[idx:end])
                    found_urls.append(snippet.decode('ascii', errors='replace'))
                    break
                pos = idx + 1

    if found_urls:
        findings.append({
            'severity': 'HIGH',
            'title':    'MACRO_URL_PRESENT',
            'detail':   (
                f'URL string(s) found near VBA macro content: {"; ".join(found_urls[:3])} -- '
                'macro contains URL indicating downloader behavior: embedded URLs in macro '
                'code are the primary mechanism for stage-1 payload retrieval; '
                'macro calls URLDownloadToFile, XMLHTTP, or WinHttp to fetch a binary '
                'from the attacker C2, writes it to disk, and executes via Shell or WScript; '
                'URL may be obfuscated via string concatenation or Chr() calls but '
                'static reconstruction is possible by tracing assignments; '
                'network indicator: pivot on the domain/IP for C2 infrastructure mapping'
            ),
            'host': 'localhost',
            'port': 0,
        })

    return findings


def detect_pdf_exploit_indicators(binary_data: bytes) -> list:
    """
    Detect PDF-based exploit and malware delivery indicators in raw binary data.
    Covers PDF format identification, JavaScript presence, launch actions,
    auto-executing JavaScript, large stream payloads, and embedded files.
    Source: Practical Malware Analysis (Sikorski/Honig) -- document-format
    delivery vectors and static analysis of non-PE malware carriers.
    """
    findings = []

    # ---- PDF_DOCUMENT: PDF magic signature ----
    if binary_data[:4] == b'%PDF':
        findings.append({
            'severity': 'MEDIUM',
            'title':    'PDF_DOCUMENT',
            'detail':   (
                'PDF magic (%PDF-) detected at offset 0 -- '
                'Portable Document Format: cross-platform document container; '
                'PDF is structured as objects (indirect: "N 0 obj ... endobj") '
                'connected by a cross-reference table (xref) and trailer; '
                'the format supports JavaScript execution, file launching, embedded '
                'files, and form submission -- all have been weaponized; '
                'version string (e.g. %PDF-1.6) constrains feature set available to attacker; '
                'correlate with PDF_JAVASCRIPT, PDF_LAUNCH_ACTION, PDF_AUTO_EXEC_JS'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # ---- PDF_JAVASCRIPT: /JavaScript or /JS action dictionary key ----
    has_js = b'/JavaScript' in binary_data or b'/JS' in binary_data
    if has_js:
        findings.append({
            'severity': 'HIGH',
            'title':    'PDF_JAVASCRIPT',
            'detail':   (
                '/JavaScript or /JS key found in PDF structure -- '
                'PDF contains JavaScript: Acrobat/Reader exposes a JavaScript engine '
                '(Acrobat DOM) that can manipulate PDF objects, spawn subprocesses '
                '(via app.launchURL with "launch"), access the clipboard, and exploit '
                'engine vulnerabilities (heap spray, type confusion); '
                'malicious PDF JS commonly implements heap spray shellcode delivery, '
                'NOP sled construction, and shellcode execution via memory corruption; '
                'CVE-2008-2992, CVE-2009-4324, CVE-2010-0188 are canonical JS-triggered PDFs; '
                'static JS extraction: locate stream after /JS key, decompress (FlateDecode), '
                'decode (ASCIIHexDecode/ASCII85), deobfuscate; '
                'correlate with PDF_AUTO_EXEC_JS for weaponized variant'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # ---- PDF_LAUNCH_ACTION: /Launch action key ----
    if b'/Launch' in binary_data:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'PDF_LAUNCH_ACTION',
            'detail':   (
                '/Launch action key found in PDF -- '
                'PDF can execute arbitrary commands: the /Launch action dictionary '
                '(/Type /Action /S /Launch /F ...) executes a file or command when '
                'activated; attackers embed /Launch in annotations or OpenAction to '
                'spawn cmd.exe, PowerShell, or a dropped binary; '
                'Acrobat presents a security dialog but social engineering text in the PDF '
                'instructs victims to click Allow; '
                'the /F key specifies the target file path -- may reference an embedded '
                'file extracted by the reader or an absolute path; '
                'no JavaScript required: pure PDF object structure achieves code execution; '
                'correlate with PDF_EMBEDDED_FILE for self-contained dropper variants'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # ---- PDF_AUTO_EXEC_JS: /OpenAction + /JavaScript (JS fires on open, no interaction) ----
    has_open_action = b'/OpenAction' in binary_data
    if has_open_action and has_js:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'PDF_AUTO_EXEC_JS',
            'detail':   (
                '/OpenAction + /JavaScript both present -- '
                'JavaScript executes automatically when PDF is opened: /OpenAction '
                'is the document-level action triggered on open without any user '
                'interaction; when combined with a /JavaScript action, the JS payload '
                'runs immediately on load; '
                'this is the dominant PDF exploit delivery pattern (CVE-2009-4324 / '
                'util.printf heap spray, CVE-2010-0188 TIFF LibTIFF): JS performs '
                'heap spray, triggers the vulnerability, jumps to shellcode; '
                'zero-click from victim perspective -- opening the PDF in a vulnerable '
                'reader triggers full exploitation chain; '
                'static analysis path: extract /OpenAction target -> resolve /JavaScript '
                'stream -> decompress -> deobfuscate -> identify spray/NOP/shellcode pattern'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # ---- LARGE_PDF_STREAM: stream/endstream blocks > 100KB (embedded payload indicator) ----
    _STREAM_MARKER    = b'stream'
    _ENDSTREAM_MARKER = b'endstream'
    _LARGE_THRESHOLD  = 100 * 1024  # 100KB

    large_stream_count   = 0
    largest_stream_bytes = 0
    stream_pos = 0
    while True:
        s_idx = binary_data.find(_STREAM_MARKER, stream_pos)
        if s_idx == -1:
            break
        # Skip 'endstream' occurrences (9-char prefix check)
        if binary_data[s_idx:s_idx + 9] == b'endstream':
            stream_pos = s_idx + 1
            continue
        e_idx = binary_data.find(_ENDSTREAM_MARKER, s_idx + len(_STREAM_MARKER))
        if e_idx == -1:
            break
        stream_size = e_idx - (s_idx + len(_STREAM_MARKER))
        if stream_size > _LARGE_THRESHOLD:
            large_stream_count += 1
            if stream_size > largest_stream_bytes:
                largest_stream_bytes = stream_size
        stream_pos = e_idx + len(_ENDSTREAM_MARKER)

    if large_stream_count > 0:
        findings.append({
            'severity': 'HIGH',
            'title':    'LARGE_PDF_STREAM',
            'detail':   (
                f'{large_stream_count} stream object(s) > 100KB detected '
                f'(largest: {largest_stream_bytes // 1024}KB) -- '
                'possible embedded payload: legitimate PDF streams (fonts, images, content) '
                'rarely exceed 100KB; large streams are consistent with embedded executables, '
                'shellcode blobs, or secondary document payloads; '
                'heap spray PDFs embed large repetitive blocks (0x0C0C0C0C NOP sleds) '
                'inflating stream sizes; '
                'stream content is typically compressed (FlateDecode) and possibly '
                'additionally encoded (ASCIIHexDecode, ASCII85Decode, LZWDecode); '
                'decompress via zlib.decompress() after stripping the stream header; '
                'look for MZ/PE headers, shellcode patterns (GetPC stubs, LoadLibrary hashes), '
                'or embedded OLE2 containers inside the decompressed stream data'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # ---- PDF_EMBEDDED_FILE: /EmbeddedFile key ----
    if b'/EmbeddedFile' in binary_data:
        findings.append({
            'severity': 'HIGH',
            'title':    'PDF_EMBEDDED_FILE',
            'detail':   (
                '/EmbeddedFile key found in PDF structure -- '
                'file embedded in PDF: /EmbeddedFile is a file attachment specification '
                '(/Type /EmbeddedFile, /F -> file specification, /EF -> embedded file stream); '
                'PDF can embed arbitrary file types (executables, Office documents, scripts); '
                'when combined with /Launch, the PDF drops and executes the embedded file; '
                'a common attack pattern: PDF drops an embedded .exe or .doc to a temp '
                'directory and launches it via a /Launch action on open; '
                'extraction: locate /EmbeddedFile stream, read /Length, decompress, '
                'write raw bytes -- the result is the embedded payload in its native format; '
                'pivot on embedded file hash for threat intelligence correlation'
            ),
            'host': 'localhost',
            'port': 0,
        })

    return findings


def detect_keylogger_artifacts(binary_data: bytes) -> list:
    """
    Detect keylogger patterns in raw binary data.
    Source: Practical Malware Analysis (Sikorski/Honig) Ch.11 -- credential stealers,
    keystroke logging via SetWindowsHookEx hooking and GetAsyncKeyState polling.
    Covers hook-based keyloggers (WH_KEYBOARD, WH_KEYBOARD_LL), polling-based keyloggers,
    hotkey registration, and window-title-capture for credential context logging.
    """
    findings = []

    # --- KEYLOGGER_HOOK_INSTALL: SetWindowsHookEx + WH_KEYBOARD (2) or WH_KEYBOARD_LL (13) ---
    if b'SetWindowsHookEx' in binary_data:
        # WH_KEYBOARD = 2 (0x02), WH_KEYBOARD_LL = 13 (0x0D) as little-endian DWORD push immediates
        has_wh_keyboard = (
            b'\x02\x00\x00\x00' in binary_data or  # WH_KEYBOARD DWORD constant
            b'\x0d\x00\x00\x00' in binary_data or  # WH_KEYBOARD_LL DWORD constant
            binary_data.count(b'\x02') > 0           # single-byte push 0x02 (WH_KEYBOARD)
        )
        if has_wh_keyboard:
            findings.append({
                'severity': 'CRITICAL',
                'title':    'KEYLOGGER_HOOK_INSTALL',
                'detail':   (
                    'SetWindowsHookEx present with WH_KEYBOARD (2) or WH_KEYBOARD_LL (13) constant -- '
                    'keyboard hook for keylogging: SetWindowsHookEx installs a system-wide or '
                    'thread-local hook procedure intercepting keyboard messages before they reach '
                    'the target application; WH_KEYBOARD (2) hooks keyboard input in the calling '
                    'thread message queue; WH_KEYBOARD_LL (13) hooks all keyboard input at the '
                    'system level via a low-level hook proc receiving KBDLLHOOKSTRUCT events '
                    '(vkCode, scanCode, flags, time, dwExtraInfo); '
                    'pattern from PMA Ch.11: hooking keyloggers package a DLL with the hook '
                    'callback that gets mapped into every process automatically via SetWindowsHookEx; '
                    'the call signature: SetWindowsHookEx(idHook, lpfn callback, hMod DLL handle, '
                    'dwThreadId=0 for global scope); '
                    'WH_KEYBOARD_LL requires the hooking process to maintain a message pump '
                    '(GetMessage loop) to receive hook notifications; '
                    'locate cross-references to SetWindowsHookEx, examine lpfn callback for '
                    'GetAsyncKeyState/ToAscii/MapVirtualKey/WriteFile patterns; '
                    'unhook indicator: look for UnhookWindowsHookEx in the same binary'
                ),
                'host': 'localhost',
                'port': 0,
            })

    # --- ASYNC_KEY_STATE_POLL: GetAsyncKeyState with multiple occurrences (loop context) ---
    count = binary_data.count(b'GetAsyncKeyState')
    if count >= 2:
        findings.append({
            'severity': 'HIGH',
            'title':    'ASYNC_KEY_STATE_POLL',
            'detail':   (
                f'GetAsyncKeyState appears {count} time(s) -- polling-based keylogger: '
                'polling keyloggers call GetAsyncKeyState in a tight loop iterating through '
                'virtual key codes (VK_0 through VK_Z, VK_SPACE, function keys); '
                'GetAsyncKeyState(vKey) returns high-bit set (0x8000) if key is currently pressed, '
                'low-bit set if pressed since the last call; '
                'pattern from PMA Ch.11: inner loop increments EBX through an array of ~92 VK '
                'codes checking each key per iteration at high frequency; '
                'typically paired with GetForegroundWindow (context logging) and Sleep (CPU throttle); '
                'multiple occurrences indicate a loop structure or multiple key-polling call sites; '
                'GetAsyncKeyState requires no message pump, making it simpler to embed in a '
                'worker thread than hook-based keyloggers; '
                'also check for GetKeyState (synchronous) used to test modifier keys -- '
                'SHIFT=0x10, CAPS LOCK=0x14, CTRL=0x11 -- to correctly reconstruct typed text; '
                'string artifact: keyloggers logging special keys embed bracket strings such as '
                '[Up], [Num Lock], [PageDown] to represent non-printable key events'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # --- HOTKEY_REGISTER: RegisterHotKey ---
    if b'RegisterHotKey' in binary_data:
        findings.append({
            'severity': 'MEDIUM',
            'title':    'HOTKEY_REGISTER',
            'detail':   (
                'RegisterHotKey present -- hotkey registration (potential keylogger trigger): '
                'RegisterHotKey(hWnd, id, fsModifiers, vk) registers a system-wide hotkey that '
                'posts WM_HOTKEY to the registering window regardless of input focus; '
                'used by keyloggers to toggle logging on/off, exfiltrate captured data on demand, '
                'or trigger secondary payload execution via a specific key combination; '
                'also used by spyware to monitor specific combos (screenshot capture, clipboard dump) '
                'rather than logging all keystrokes; '
                'fsModifiers: MOD_ALT=0x0001, MOD_CONTROL=0x0002, MOD_SHIFT=0x0004, MOD_WIN=0x0008; '
                'requires a message loop (GetMessage/PeekMessage) to receive WM_HOTKEY events; '
                'elevate severity to HIGH if combined with file-write or network-send API imports'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # --- WINDOW_TITLE_CAPTURE: GetForegroundWindow + GetWindowText in proximity ---
    if b'GetForegroundWindow' in binary_data and b'GetWindowText' in binary_data:
        _PROX = 4096
        gfw_positions = [m.start() for m in re.finditer(b'GetForegroundWindow', binary_data)]
        gwt_positions = [m.start() for m in re.finditer(b'GetWindowText', binary_data)]
        close = any(
            abs(gfw - gwt) <= _PROX
            for gfw in gfw_positions
            for gwt in gwt_positions
        )
        if close:
            findings.append({
                'severity': 'HIGH',
                'title':    'WINDOW_TITLE_CAPTURE',
                'detail':   (
                    'GetForegroundWindow and GetWindowText found within 4096 bytes of each other -- '
                    'foreground window title captured (credential context logging): '
                    'pattern from PMA Ch.11: polling keylogger outer loop calls GetForegroundWindow '
                    'before and after the inner key-poll loop to track the active application; '
                    'GetWindowText(hWnd, lpString, nMaxCount) retrieves the window caption string '
                    'used to log which application received the captured keystrokes '
                    '(e.g., browser login dialog, Outlook compose window, VPN client); '
                    'window title logging disambiguates captured keystrokes: passwords typed in a '
                    'browser are separated from text typed in Notepad; '
                    'targeted credential stealers trigger on specific window titles (bank names, '
                    'email clients, VPN clients) to selectively exfiltrate relevant keystrokes; '
                    'also see: GetWindowTextA (ANSI) and GetWindowTextW (Unicode) variants; '
                    'if GetWindowText output is compared against a hardcoded string list, the '
                    'malware is performing targeted credential harvesting rather than bulk logging'
                ),
                'host': 'localhost',
                'port': 0,
            })

    return findings


def detect_backdoor_artifacts(binary_data: bytes) -> list:
    """
    Detect backdoor and downloader patterns in raw binary data.
    Source: Practical Malware Analysis (Sikorski/Honig) Ch.11 -- backdoors (reverse shells,
    bind shells, RATs) and downloaders/launchers (HTTP, URLDownloadToFile, FTP).
    Covers socket-based shell patterns, HTTP C2 triads, and direct file-download APIs.
    """
    findings = []

    # --- REVERSE_SHELL_PATTERN: WSASocket + cmd.exe in proximity ---
    if b'WSASocket' in binary_data and re.search(rb'cmd\.exe', binary_data, re.IGNORECASE):
        _PROX = 8192
        wsa_positions = [m.start() for m in re.finditer(b'WSASocket', binary_data)]
        cmd_positions = [m.start() for m in re.finditer(rb'cmd\.exe', binary_data, re.IGNORECASE)]
        close = any(
            abs(wsa - cmd) <= _PROX
            for wsa in wsa_positions
            for cmd in cmd_positions
        )
        if close:
            findings.append({
                'severity': 'CRITICAL',
                'title':    'REVERSE_SHELL_PATTERN',
                'detail':   (
                    'WSASocket and cmd.exe found within 8192 bytes of each other -- '
                    'socket connected to cmd.exe (classic reverse shell): '
                    'pattern from PMA Ch.11: Windows reverse shell ties cmd.exe '
                    'stdin/stdout/stderr directly to a connected socket via STARTUPINFO '
                    'manipulation in CreateProcess; WSASocket creates a socket handle passed '
                    'as hStdInput/hStdOutput/hStdError in the STARTUPINFO structure; '
                    'CreateProcess("cmd.exe") with STARTF_USESTDHANDLES (0x00000100) flag '
                    'redirects shell I/O over the outbound socket connection; '
                    'the reverse connection originates from the victim, bypassing inbound firewall '
                    'rules; multithreaded variant: CreatePipe + CreateThread pairs relay between '
                    'the socket and cmd.exe pipes, allowing in-transit data encoding; '
                    'additional indicators: connect() called before CreateProcess, '
                    'SW_HIDE in STARTUPINFO.wShowWindow to suppress the cmd window; '
                    'network indicator: outbound TCP on common ports (80, 443, 4444, 1337) '
                    'to C2 IP; also check for CreateThread pairs (multithreaded shell variant)'
                ),
                'host': 'localhost',
                'port': 0,
            })

    # --- BIND_SHELL_PATTERN: bind + listen + accept + cmd.exe all present ---
    has_bind   = b'bind' in binary_data
    has_listen = b'listen' in binary_data
    has_accept = b'accept' in binary_data
    has_cmd    = bool(re.search(rb'cmd\.exe', binary_data, re.IGNORECASE))
    if has_bind and has_listen and has_accept and has_cmd:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'BIND_SHELL_PATTERN',
            'detail':   (
                'bind + listen + accept socket triad with cmd.exe all present -- '
                'local socket listener with shell: '
                'bind shell sequence: socket() -> bind(sockaddr with local port) -> listen() '
                '-> accept() -> spawn cmd.exe with stdio redirected to the accepted socket; '
                'attacker connects inbound to the victim on the bound port to receive a shell; '
                'requires inbound firewall rule or no perimeter firewall to reach the listener; '
                'pattern from PMA Ch.11: bind shells appear in post-exploitation tools targeting '
                'internal network segments where outbound egress filtering is strict; '
                'also used in RAT server components -- PMA Ch.11 RAT server runs on victim and '
                'listens for the RAT client operated by the attacker on port 80 or 443; '
                'detection on live host: netstat -anp shows LISTENING on unexpected port; '
                'look for hardcoded port WORD/DWORD constant in htons() call near bind() site; '
                'WSASocket variant uses WSA_FLAG_OVERLAPPED for async I/O'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # --- HTTP_DOWNLOADER: InternetOpen + InternetConnect + HttpOpenRequest triad ---
    if (b'InternetOpen' in binary_data
            and b'InternetConnect' in binary_data
            and b'HttpOpenRequest' in binary_data):
        findings.append({
            'severity': 'HIGH',
            'title':    'HTTP_DOWNLOADER',
            'detail':   (
                'InternetOpen + InternetConnect + HttpOpenRequest triad present -- '
                'HTTP-based payload retrieval: '
                'WinINet HTTP sequence: InternetOpen(user-agent) -> '
                'InternetConnect(host, port, INTERNET_SERVICE_HTTP) -> '
                'HttpOpenRequest(GET/POST, path) -> HttpSendRequest() -> '
                'InternetReadFile(buffer) loop -> write to disk; '
                'pattern from PMA Ch.11: backdoors use port 80 HTTP to blend with legitimate '
                'traffic; C2 communications use HTTP POST to exfiltrate collected data and '
                'receive next-stage payloads in the response body; '
                'user-agent string in InternetOpen is often hardcoded and distinctive -- '
                'extract from .rdata; blank or custom user-agent is a C2 indicator; '
                'also check HttpAddRequestHeaders for custom C2 beacon headers; '
                'InternetConnect host parameter is the C2 domain/IP -- pivot to threat intel; '
                'this triad gives finer control over headers and chunked reads versus '
                'URLDownloadToFile, indicating a purpose-built C2 client'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # --- URL_DOWNLOAD_TO_FILE: URLDownloadToFile ---
    if b'URLDownloadToFile' in binary_data:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'URL_DOWNLOAD_TO_FILE',
            'detail':   (
                'URLDownloadToFile present -- direct URL download (common dropper): '
                'pattern from PMA Ch.11: simplest downloader pattern -- '
                'URLDownloadToFileA(NULL, url, local_path, 0, NULL) followed by '
                'WinExec(local_path) or ShellExecute() to execute the dropped payload; '
                'URLDownloadToFile is a single-call HTTP GET that writes the response body '
                'directly to disk; requires only urlmon.dll, zero additional WinINet setup; '
                'commonly used in first-stage droppers and exploit payloads for its simplicity; '
                'C2 URL and drop path are typically hardcoded strings in .rdata or .data; '
                'anti-analysis: URL may be XOR or RC4 obfuscated in .data, decrypted at runtime; '
                'variants: URLDownloadToCacheFile, DeleteUrlCacheEntry to erase download evidence; '
                'the dropped file commonly lands in %TEMP%, %APPDATA%, or System32 to blend in; '
                'pivot: extract URL host from strings and query threat intel for C2 attribution'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # --- FTP_DOWNLOADER: FtpGetFile or FtpOpenFile ---
    has_ftpget  = b'FtpGetFile'  in binary_data
    has_ftpopen = b'FtpOpenFile' in binary_data
    if has_ftpget or has_ftpopen:
        indicator = 'FtpGetFile' if has_ftpget else 'FtpOpenFile'
        findings.append({
            'severity': 'HIGH',
            'title':    'FTP_DOWNLOADER',
            'detail':   (
                f'{indicator} present -- FTP-based payload retrieval: '
                'FTP download chain: InternetOpen() -> InternetConnect(host, port=21, '
                'INTERNET_SERVICE_FTP, user, password) -> FtpGetFile(remote_path, local_path) '
                'or FtpOpenFile() + InternetReadFile() loop; '
                'FTP credentials (username/password) passed to InternetConnect are typically '
                'hardcoded -- extract from strings to identify C2 FTP server and credentials; '
                'FtpGetFile performs a direct file transfer analogous to URLDownloadToFile but '
                'over FTP (port 21 control, passive-mode ephemeral data port); '
                'FtpOpenFile opens a remote file handle for byte-level reading, giving the '
                'malware resume support and partial-download control; '
                'passive mode indicator: INTERNET_FLAG_PASSIVE flag in FtpOpenFile/FtpGetFile '
                'call -- passive FTP is more firewall-friendly for outbound data connections; '
                'FTP-based downloaders appear in targeted malware where the operator controls '
                'a staging FTP server; less common than HTTP but harder to block without '
                'deep-packet inspection on port 21'
            ),
            'host': 'localhost',
            'port': 0,
        })

    return findings


def detect_dll_sideloading_artifacts(binary_data: bytes) -> list:
    """
    Detect DLL side-loading and phantom DLL hijacking artifacts in raw binary data.
    Source: Practical Malware Analysis (Sikorski/Honig) Ch.12 -- covert malware launching,
    launcher techniques, DLL injection via search-order manipulation.
    DLL side-loading: placing a malicious DLL alongside a trusted, signed executable causes
    the OS DLL search order to load the attacker-controlled copy before the System32 copy,
    executing malicious DllMain under the trusted process identity.
    Phantom DLL hijacking: targeting DLLs legitimately imported by an app but absent from
    its directory so the attacker-placed file wins the search-order race.
    """
    findings = []

    # LoadLibrary family present anywhere in the binary (IAT import or dynamic call string)
    has_loadlib = bool(re.search(
        rb'LoadLibrary(?:A|W|ExA|ExW)',
        binary_data
    ))

    # --- DLL_RELATIVE_PATH_LOAD: LoadLibrary with a relative/bare path (no drive root) ---
    # A bare DLL name like "version.dll\x00" or ".\evil.dll\x00" between null bytes signals
    # LoadLibrary is being called without a full absolute path, triggering the OS search order.
    if has_loadlib:
        bare_dll = re.search(
            rb'\x00(\.{0,2}\\?[A-Za-z][A-Za-z0-9_\-]{0,47}\.dll)\x00',
            binary_data, re.IGNORECASE
        )
        if bare_dll:
            findings.append({
                'severity': 'HIGH',
                'title':    'DLL_RELATIVE_PATH_LOAD',
                'detail':   (
                    'LoadLibrary present with bare or relative DLL path (no absolute drive root) -- '
                    'DLL side-loading risk: '
                    'pattern from PMA Ch.12: when LoadLibrary is called with a bare filename '
                    '(e.g. "version.dll") or a relative path (e.g. ".\\evil.dll"), Windows resolves '
                    'it using the DLL search order: (1) application directory, (2) system directory, '
                    '(3) Windows directory, (4) current working directory, (5) PATH entries; '
                    'malware places a malicious DLL with the target name in the application '
                    'directory of a trusted, signed executable -- the OS loads the attacker copy '
                    'before checking System32; the trusted process executes the malicious DllMain '
                    'under its own signed identity, bypassing process reputation checks; '
                    'bare DLL candidate in binary: ' + bare_dll.group(1).decode(errors='replace') + '; '
                    'pivot: check app directories for unexpected DLL files matching system names '
                    '(version.dll, dwmapi.dll, WINMM.dll, cryptbase.dll); '
                    'verify: Process Monitor filter on LoadImage events to trace the resolved path; '
                    'mitigations: use absolute paths in LoadLibrary, call SetDllDirectory("") to '
                    'remove the app dir from search order, enable DLL Safe Search Mode'
                ),
                'host': 'localhost',
                'port': 0,
            })

    # --- DLL_SIDELOAD_PATTERN: bare DLL load + known legitimate app name in same binary ---
    # The launcher binary references a known trusted executable alongside a bare DLL name --
    # the classic pattern where a dropper installs both a legit app and a malicious DLL
    # in the same directory, then invokes the legit app to trigger the side-load.
    if has_loadlib:
        known_app_targets = [
            b'chrome.exe', b'firefox.exe', b'explorer.exe', b'svchost.exe',
            b'regsvr32.exe', b'rundll32.exe', b'msiexec.exe', b'wscript.exe',
            b'cscript.exe', b'notepad.exe', b'calc.exe', b'mspaint.exe',
        ]
        app_hit = any(
            re.search(t, binary_data, re.IGNORECASE) for t in known_app_targets
        )
        bare_dll2 = re.search(
            rb'\x00([A-Za-z][A-Za-z0-9_\-]{0,47}\.dll)\x00',
            binary_data, re.IGNORECASE
        )
        # Full-path indicator: a DLL string with a drive letter and backslash
        has_fullpath = bool(re.search(
            rb'[A-Za-z]:\\[A-Za-z0-9_\-\\]{4,}\.dll',
            binary_data, re.IGNORECASE
        ))
        if app_hit and bare_dll2 and not has_fullpath:
            matched_app = next(
                t.decode() for t in known_app_targets
                if re.search(t, binary_data, re.IGNORECASE)
            )
            findings.append({
                'severity': 'HIGH',
                'title':    'DLL_SIDELOAD_PATTERN',
                'detail':   (
                    'LoadLibrary without full path present alongside known legitimate executable name '
                    '(' + matched_app + ') -- DLL load without full path (side-loading into trusted process): '
                    'pattern from PMA Ch.12: side-loading exploits the DLL search order by packaging '
                    'a malicious DLL with the same name as a DLL legitimately imported by the host app; '
                    'the dropper installs both the trusted app binary and the malicious DLL to the '
                    'same directory, then invokes the trusted app; the OS loads the malicious DLL '
                    'from the app directory before checking System32 because app dir is position 1 '
                    'in the default search order; '
                    'the host process (' + matched_app + ') is trusted by AV/EDR so the injected '
                    'DllMain executes with the host\'s reputation and integrity level; '
                    'no process injection API (VirtualAllocEx, WriteProcessMemory) is needed -- '
                    'the OS loader performs the injection transparently; '
                    'live detection: Sysinternals Process Explorer highlights unsigned DLLs loaded '
                    'by signed processes; compare loaded module paths against System32 baseline; '
                    'on-disk check: look for unexpected .dll files in app installation directories '
                    'matching system DLL names'
                ),
                'host': 'localhost',
                'port': 0,
            })

    # --- DLL_SEARCH_ORDER_MOD: SetDllDirectory API reference present ---
    # SetDllDirectory("") removes the app dir from search order (defensive use);
    # SetDllDirectory("C:\attacker\") inserts an attacker-controlled dir at position 2,
    # ahead of System32, redirecting all subsequent LoadLibrary calls to attacker copies.
    if b'SetDllDirectory' in binary_data:
        findings.append({
            'severity': 'HIGH',
            'title':    'DLL_SEARCH_ORDER_MOD',
            'detail':   (
                'SetDllDirectory present in binary -- '
                'DLL search order manipulated via SetDllDirectory: '
                'pattern from PMA Ch.12: SetDllDirectory inserts a caller-controlled directory '
                'at position 2 of the Windows DLL search order (immediately after the '
                'application directory, before System32 and Windows directory); '
                'attacker use: SetDllDirectory("C:\\attacker\\") causes all subsequent '
                'LoadLibrary calls in the process to resolve from the attacker directory first, '
                'allowing replacement of any system DLL without modifying System32 or the '
                'application\'s import table; '
                'this affects all LoadLibrary calls for the lifetime of the process thread '
                'until SetDllDirectory is called again with a different path; '
                'defensive use: SetDllDirectory("") removes the application directory from '
                'the search order entirely, preventing DLL planting in the app dir -- '
                'presence in a malware binary with a non-empty argument indicates offensive use; '
                'analysis: disassemble calls to SetDllDirectory to extract the path argument '
                'pushed onto the stack (or passed in RCX on x64) immediately before the call; '
                'Windows Vista+: KB2533623 added AddDllDirectory for more granular control; '
                'related: SetCurrentDirectory can also redirect relative paths before the '
                'search-order walk begins'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # --- KNOWN_HIJACKABLE_DLL: presence of well-known phantom DLL hijacking target names ---
    # These DLLs are commonly imported by legitimate applications but absent from app directories,
    # making them classic phantom DLL hijacking targets (place malicious copy in app dir to win
    # the search-order race before System32 is checked).
    hijackable_dlls = [
        (
            rb'version\.dll',
            'version.dll',
            'version-info API (GetFileVersionInfo/VerQueryValue); imported by many executables '
            'for version checking; absent from most app directories; '
            'classic phantom DLL target documented in multiple APT campaigns (MITRE T1574.001); '
            'place malicious version.dll alongside any app that imports it to capture execution'
        ),
        (
            rb'WINMM\.dll',
            'WINMM.dll',
            'Windows Multimedia API (mciSendString, waveOutOpen etc.); imported by multimedia '
            'and game applications; absent from app dirs in most installs; '
            'phantom hijack: place malicious WINMM.dll alongside target app; '
            'the OS loads it from app dir before checking System32 in the default search order'
        ),
        (
            rb'dwmapi\.dll',
            'dwmapi.dll',
            'Desktop Window Manager API; not always present in app directories; '
            'phantom DLL hijack vector in installer packages and apps that import dwmapi.dll '
            'without verifying the load path; '
            'attacker places malicious dwmapi.dll alongside a signed installer, '
            'which loads it during startup before System32 is checked'
        ),
        (
            rb'cryptbase\.dll',
            'cryptbase.dll',
            'Base cryptographic functions; historically loaded by lsass.exe and many apps '
            'under older Windows versions; exploited in UAC bypass DLL hijacking chains; '
            'in Windows 7 era: cryptbase.dll loaded from app dir before System32 in some '
            'elevated contexts, allowing privilege escalation via DLL substitution; '
            'still a high-signal indicator of DLL hijacking awareness in the binary author'
        ),
    ]
    for pattern, dll_name, dll_desc in hijackable_dlls:
        if re.search(pattern, binary_data, re.IGNORECASE):
            findings.append({
                'severity': 'CRITICAL',
                'title':    'KNOWN_HIJACKABLE_DLL',
                'detail':   (
                    dll_name + ' name present in binary -- '
                    'known DLL hijacking target name present: '
                    + dll_desc + '; '
                    'pattern from PMA Ch.12: phantom DLL hijacking targets DLLs that are '
                    'legitimately imported by a trusted application but do not exist in the '
                    'application directory -- the attacker places a malicious DLL with the exact '
                    'name in the application directory; Windows loads it from position 1 '
                    '(app dir) in the search order before checking System32; the trusted '
                    'process loads the phantom DLL without error and DllMain executes with '
                    'full host-process privileges and identity; '
                    'live response: enumerate loaded modules per process and flag any '
                    'module whose path is not under System32 or SysWOW64 -- '
                    'PowerShell: Get-Process | ForEach-Object { $_.Modules } | '
                    'Where-Object { $_.FileName -notmatch "System32|SysWOW64" }'
                ),
                'host': 'localhost',
                'port': 0,
            })

    return findings


def detect_memory_only_malware_indicators(binary_data: bytes) -> list:
    """
    Detect fileless and memory-resident malware execution patterns in raw binary data.
    Source: Practical Malware Analysis (Sikorski/Honig) Ch.12 -- covert malware launching,
    direct injection (shellcode injection without disk staging), process replacement, and
    the general pattern of executing code that never touches the filesystem.
    Memory-only execution leaves no file artifact for file-based AV/EDR to scan; the payload
    exists only in process memory, making forensic recovery dependent on memory acquisition.
    Covers: PowerShell IEX download cradles, reflective DLL injection (ReflectiveLoader),
    .NET in-memory assembly loading (Assembly.Load), and shellcode injection without disk write.
    """
    findings = []

    # --- POWERSHELL_IEX_DOWNLOAD: Invoke-Expression combined with a download primitive ---
    # The canonical fileless PowerShell execution chain: download script text as a string
    # entirely into memory, then execute it via IEX without writing a file to disk.
    iex_present = (
        bool(re.search(rb'\bIEX\b', binary_data, re.IGNORECASE)) or
        bool(re.search(rb'Invoke-Expression', binary_data, re.IGNORECASE))
    )
    download_present = bool(re.search(
        rb'(?:DownloadString|DownloadData|Net\.WebClient|New-Object\s+Net\.|'
        rb'Invoke-WebRequest|\biwr\b|Start-BitsTransfer)',
        binary_data, re.IGNORECASE
    ))
    if iex_present and download_present:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'POWERSHELL_IEX_DOWNLOAD',
            'detail':   (
                'PowerShell Invoke-Expression (IEX) combined with network download primitive '
                'present -- PowerShell Invoke-Expression with download (fileless execution): '
                'pattern from PMA Ch.12: the IEX download cradle is the canonical fileless '
                'execution chain -- (New-Object Net.WebClient).DownloadString(url) retrieves '
                'a PowerShell script as an in-memory string; IEX then compiles and executes '
                'that string without writing a file to disk; no disk artifact is created beyond '
                'the initial launcher; the payload exists only in PowerShell process memory '
                'for the duration of execution; '
                'common obfuscation: IEX split into char codes, base64, or reverse string -- '
                'look for [Convert]::FromBase64String, [System.Text.Encoding]::Unicode.GetString; '
                'AMSI bypass often precedes IEX cradle: [Ref].Assembly.GetType patterns or '
                'direct AMSI.dll patching via VirtualProtect + byte-patch of AmsiScanBuffer; '
                'defender pivot: enable PowerShell Script Block Logging '
                '(HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging); '
                'event 4104 in Microsoft-Windows-PowerShell/Operational captures decoded IEX '
                'content even when -EncodedCommand is used; '
                'process indicators: powershell.exe spawned with -WindowStyle Hidden, '
                '-NonInteractive, -NoProfile, or -EncodedCommand flags is high-signal'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # --- REFLECTIVE_DLL_INJECT: ReflectiveLoader export name or LoadLibraryR API ---
    # A DLL containing a ReflectiveLoader export carries its own PE loader -- it can load
    # itself from a raw memory buffer without calling the OS loader, leaving no LDR entry.
    reflective_indicators = [s for s in
        [b'ReflectiveLoader', b'LoadLibraryR', b'ReflectiveDLLInjection']
        if s in binary_data]
    if reflective_indicators:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'REFLECTIVE_DLL_INJECT',
            'detail':   (
                'ReflectiveLoader or LoadLibraryR present -- '
                'ReflectiveLoader present (fileless DLL injection technique): '
                'indicators found: ' + ', '.join(i.decode(errors='replace') for i in reflective_indicators) + '; '
                'pattern from PMA Ch.12: a DLL containing a ReflectiveLoader export carries '
                'its own PE loader; when the injector writes the DLL bytes into a remote '
                'process via VirtualAllocEx + WriteProcessMemory and jumps to the '
                'ReflectiveLoader offset (not DllMain), the DLL loads itself entirely from '
                'memory without calling LdrLoadDll or LoadLibrary; '
                'no LoadLibrary call is made, no LDR_DATA_TABLE_ENTRY is created in the '
                'module list (the DLL is invisible to EnumProcessModules), no file on disk '
                'is required after injection -- the DLL is genuinely memory-only; '
                'the DLL relocates itself, resolves imports via PEB walk '
                '(InLoadOrderModuleList) rather than GetProcAddress, then calls DllMain '
                'after self-loading; '
                'used by Metasploit meterpreter, Cobalt Strike beacons, and custom implants; '
                'memory forensics: scan for MZ/PE headers (4D 5A) in executable but non-image '
                'VAD regions -- Volatility malfind plugin detects anonymous executable pages; '
                'live: Process Hacker -> process -> memory tab shows RWX regions without '
                'backing file paths; YARA: MZ header in PAGE_EXECUTE_READWRITE allocation'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # --- DOTNET_ASSEMBLY_LOAD_MEMORY: Assembly.Load from byte array (no file path required) ---
    # Assembly.Load(byte[]) loads a .NET PE image from a raw byte array into the current
    # AppDomain entirely in memory -- no file path is opened, no disk artifact created.
    has_assembly_load = bool(re.search(rb'Assembly\.Load\b', binary_data, re.IGNORECASE))
    has_byte_source = bool(re.search(
        rb'(?:Convert\.FromBase64String|ReadAllBytes|DownloadData|'
        rb'\bGetBytes\b|byte\[\])',
        binary_data, re.IGNORECASE
    ))
    if has_assembly_load and has_byte_source:
        findings.append({
            'severity': 'HIGH',
            'title':    'DOTNET_ASSEMBLY_LOAD_MEMORY',
            'detail':   (
                'Assembly.Load combined with byte array source primitive present -- '
                '.NET assembly loaded from byte array (memory-only execution): '
                'pattern from PMA Ch.12 / .NET reflection: Assembly.Load(byte[]) accepts a '
                'raw PE image as a byte array and loads it into the current AppDomain entirely '
                'in memory -- no file path is required, no file handle is opened, and no '
                'disk artifact is created beyond the byte source (which may itself be '
                'an embedded resource or network download); '
                'attack chain: download payload bytes via WebClient.DownloadData(url) or '
                'decode from embedded base64 blob via Convert.FromBase64String -> '
                'Assembly.Load(bytes) -> Activator.CreateInstance or MethodInfo.Invoke '
                'to execute the entry point; the loaded assembly executes as a normal .NET '
                'DLL in the host AppDomain with full access to managed and unmanaged APIs; '
                'anti-analysis: the byte array is commonly AES-CBC or XOR encrypted, '
                'decrypted at runtime immediately before Assembly.Load -- look for symmetric '
                'key material hardcoded in .data or derived from environment values; '
                'forensic detection: ETW provider Microsoft-Windows-DotNETRuntime event '
                'AssemblyLoad where ModulePath is empty or references a non-existent path; '
                'PowerShell variant: [Reflection.Assembly]::Load([Convert]::FromBase64String(...))'
            ),
            'host': 'localhost',
            'port': 0,
        })

    # --- SHELLCODE_INJECT_NO_DISK: VirtualAllocEx + WriteProcessMemory without CreateFile ---
    # The direct-injection chain from PMA Ch.12: allocate executable memory in a remote
    # process, write shellcode bytes directly from an in-memory buffer (no staging file),
    # then trigger execution via CreateRemoteThread or QueueUserAPC.
    # Absence of CreateFile indicates the payload is embedded or received over the network
    # directly into a buffer rather than staged to disk first.
    has_virtalloc  = b'VirtualAllocEx' in binary_data
    has_write_pm   = b'WriteProcessMemory' in binary_data
    has_createfile = bool(re.search(rb'CreateFile[AW]?\x00', binary_data))
    if has_virtalloc and has_write_pm and not has_createfile:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'SHELLCODE_INJECT_NO_DISK',
            'detail':   (
                'VirtualAllocEx + WriteProcessMemory present without CreateFile -- '
                'shellcode injection with no disk artifact: '
                'pattern from PMA Ch.12 direct injection: the canonical shellcode injection '
                'chain is VirtualAllocEx (allocate RWX region in remote process) -> '
                'WriteProcessMemory (copy shellcode bytes from local buffer into remote region) '
                '-> CreateRemoteThread or QueueUserAPC (trigger remote execution); '
                'absence of CreateFile indicates the payload bytes are embedded in the binary '
                'itself or received over the network directly into a heap/stack buffer -- '
                'no staging file is written to disk before injection; '
                'file-based AV cannot scan the payload because it never exists as a file; '
                'PMA Ch.12: direct-injection shellcode must be position-independent (PIC) '
                'and resolve its own imports via PEB walk (InLoadOrderModuleList) since '
                'normal .idata import table structures are absent from a raw injected buffer; '
                'additional indicators: VirtualProtectEx changing region from RW to RX '
                'post-write signals W^X-aware staged shellcode; '
                'OpenProcess + VirtualAllocEx + WriteProcessMemory + CreateRemoteThread '
                'is the full injection quad -- check for OpenProcess and CreateRemoteThread '
                'alongside these to confirm the complete chain; '
                'memory forensics: Volatility malfind detects VAD nodes tagged executable '
                'that have no backing file object (anonymous executable pages); '
                'YARA: match VirtualAllocEx + WriteProcessMemory import strings + MZ '
                'magic in the same binary section for high-confidence detection'
            ),
            'host': 'localhost',
            'port': 0,
        })

    return findings


# ---------------------------------------------------------------------------
# ELF binary security indicator analysis
# Ref: Learning Linux Binary Analysis ch.2 (ELF Binary Format)
# ---------------------------------------------------------------------------

def analyze_elf_binary_indicators(binary_data: bytes, host: str = '', port: int = 0) -> list:
    """Parse ELF binary for security-relevant indicators: NX stack, RELRO, PIE,
    stack canary, stripped section headers, DT_DEBUG, and dangerous/dynamic imports.
    Ref: Learning Linux Binary Analysis ch.2 (ELF Binary Format).
    """
    findings = []
    if len(binary_data) < 64 or binary_data[:4] != b'\x7fELF':
        return []

    try:
        ei_class = binary_data[4]   # 1=32-bit, 2=64-bit
        ei_data  = binary_data[5]   # 1=LE, 2=BE
        if ei_class not in (1, 2):
            return []
        is64   = (ei_class == 2)
        endian = '>' if ei_data == 2 else '<'

        # ELF header field offsets differ for 32 vs 64-bit
        e_type = struct.unpack_from(endian + 'H', binary_data, 16)[0]
        if not is64:
            # Elf32_Ehdr layout
            e_phoff     = struct.unpack_from(endian + 'I', binary_data, 28)[0]
            e_shoff     = struct.unpack_from(endian + 'I', binary_data, 32)[0]
            e_phentsize = struct.unpack_from(endian + 'H', binary_data, 42)[0]
            e_phnum     = struct.unpack_from(endian + 'H', binary_data, 44)[0]
            e_shentsize = struct.unpack_from(endian + 'H', binary_data, 46)[0]
            e_shnum     = struct.unpack_from(endian + 'H', binary_data, 48)[0]
            e_shstrndx  = struct.unpack_from(endian + 'H', binary_data, 50)[0]
        else:
            # Elf64_Ehdr layout
            e_phoff     = struct.unpack_from(endian + 'Q', binary_data, 32)[0]
            e_shoff     = struct.unpack_from(endian + 'Q', binary_data, 40)[0]
            e_phentsize = struct.unpack_from(endian + 'H', binary_data, 54)[0]
            e_phnum     = struct.unpack_from(endian + 'H', binary_data, 56)[0]
            e_shentsize = struct.unpack_from(endian + 'H', binary_data, 58)[0]
            e_shnum     = struct.unpack_from(endian + 'H', binary_data, 60)[0]
            e_shstrndx  = struct.unpack_from(endian + 'H', binary_data, 62)[0]

        if e_phnum > 256 or e_shnum > 4096:
            return []

        # Program header segment type constants
        PT_DYNAMIC   = 2
        PT_INTERP    = 3
        PT_GNU_STACK = 0x6474e551
        PT_GNU_RELRO = 0x6474e552
        PF_X         = 0x1

        has_relro  = False
        has_interp = False
        exec_stack = False

        for i in range(e_phnum):
            ph_off = e_phoff + i * e_phentsize
            if ph_off + 4 > len(binary_data):
                break
            p_type = struct.unpack_from(endian + 'I', binary_data, ph_off)[0]
            # p_flags offset: Elf64_Phdr has flags at +4; Elf32_Phdr has flags at +24
            flags_off = ph_off + (4 if is64 else 24)
            p_flags = (struct.unpack_from(endian + 'I', binary_data, flags_off)[0]
                       if flags_off + 4 <= len(binary_data) else 0)

            if p_type == PT_GNU_STACK and (p_flags & PF_X):
                exec_stack = True
            elif p_type == PT_GNU_RELRO:
                has_relro = True
            elif p_type == PT_INTERP:
                has_interp = True

        if exec_stack:
            findings.append({
                'severity': 'CRITICAL',
                'title': 'ELF_EXECUTABLE_STACK',
                'detail': (
                    'PT_GNU_STACK segment (0x6474e551) has PF_X (execute) flag set -- NX '
                    'disabled for stack: the p_flags field in the GNU_STACK program header '
                    'controls whether the kernel marks the process stack mapping executable '
                    'at load time; PF_X bypasses hardware NX/XD protection entirely without '
                    'heap sprays or ROP chains -- shellcode pushed directly to the stack can '
                    'be jumped to; common causes: -z execstack linker flag, inline asm '
                    'trampolines, legacy code without -z noexecstack; exploit chain: stack '
                    'buffer overflow -> shellcode on stack -> rip/eip redirected to stack '
                    'address -> direct code execution; ref: ELF spec PT_GNU_STACK, kernel '
                    'arch/x86/mm/mmap.c read_implies_exec(), '
                    'learning-linux-binary-analysis ch.2 program headers'
                ),
                'host': host,
                'port': port,
            })

        # RELRO: absent header on an executable or shared lib = no protection
        if not has_relro and e_type in (2, 3):
            findings.append({
                'severity': 'HIGH',
                'title': 'ELF_NO_RELRO',
                'detail': (
                    'PT_GNU_RELRO program header (0x6474e552) absent -- no RELRO hardening: '
                    'RELRO marks the GOT, .dynamic, and other initially-writable ELF sections '
                    'read-only after the dynamic linker finishes symbol resolution; without it, '
                    '.got.plt remains writable for the entire process lifetime -- a single '
                    'write-primitive exploit overwrites a GOT function pointer to redirect the '
                    'next PLT call to attacker-controlled code; full RELRO also requires '
                    'DT_BIND_NOW/LD_BIND_NOW for eager resolution before locking; partial RELRO '
                    '(header present, no DT_BIND_NOW) still leaves .got.plt writable; absent '
                    'header = zero protection; ref: binutils ld -z relro, glibc dl-reloc.c, '
                    'learning-linux-binary-analysis ch.2 .got.plt section and dynamic linking'
                ),
                'host': host,
                'port': port,
            })

        # PIE check: ET_EXEC (2) = fixed load address regardless of ASLR kernel setting
        # PIE = ET_DYN (3) + PT_INTERP present (shared lib with interpreter = PIE executable)
        if e_type == 2:
            findings.append({
                'severity': 'HIGH',
                'title': 'ELF_NO_PIE',
                'detail': (
                    'ELF e_type=ET_EXEC (2) -- binary compiled without PIE: ET_EXEC loads at '
                    'a fixed virtual address (x86_64: 0x400000; x86: 0x8048000) regardless of '
                    'the kernel ASLR setting; an attacker who knows any one symbol address can '
                    'compute all gadget offsets from ABI convention alone with no leak primitive '
                    'required; PIE (ET_DYN + PT_INTERP) randomizes the load base on each '
                    'execve() and is a prerequisite for ASLR to raise ROP chain cost; '
                    'compile with: gcc -fpie -pie (or -fPIE -pie); '
                    'ref: learning-linux-binary-analysis ch.2 ELF file types (ET_EXEC/ET_DYN), '
                    'kernel load_elf_binary() in fs/binfmt_elf.c'
                ),
                'host': host,
                'port': port,
            })

        # e_shnum == 0: section header table stripped -- anti-analysis / size reduction
        if e_shnum == 0:
            findings.append({
                'severity': 'INFO',
                'title': 'ELF_STRIPPED_BINARY',
                'detail': (
                    'ELF e_shnum == 0 -- section header table absent (stripped): section '
                    'headers are not required for program execution (only program headers are '
                    'needed by the kernel loader); stripping removes .symtab, .strtab, and '
                    'all section boundary metadata, disabling gdb symbol lookups and objdump '
                    'section views; indicates deliberate anti-analysis hardening or release '
                    'build size reduction; a skilled reverser can partially reconstruct the '
                    'section header table from PT_DYNAMIC DT_STRTAB/DT_SYMTAB virtual '
                    'addresses and PT_LOAD segment boundaries; '
                    'ref: learning-linux-binary-analysis ch.2 section headers, ch.8 ECFS '
                    'reconstruction; readelf -S yields no output on stripped binary'
                ),
                'host': host,
                'port': port,
            })

        # Stack canary: GCC inserts __stack_chk_fail import when -fstack-protector is active
        if b'__stack_chk_fail' not in binary_data and e_type in (2, 3):
            findings.append({
                'severity': 'HIGH',
                'title': 'ELF_NO_STACK_CANARY',
                'detail': (
                    '__stack_chk_fail symbol absent -- stack canary not detected: GCC '
                    '-fstack-protector / -fstack-protector-strong inserts a random canary '
                    'value between local variables and the saved return address on function '
                    'entry and checks it on epilogue by calling __stack_chk_fail if modified; '
                    'absence indicates compilation without stack protection or full inlining of '
                    'canary-protected functions; stack buffer overflows can directly overwrite '
                    'the return address without triggering an abort; '
                    'recommend: gcc -fstack-protector-strong (GCC >= 4.9) or '
                    '-fstack-protector-all for complete function coverage'
                ),
                'host': host,
                'port': port,
            })

        # DT_DEBUG with non-zero d_val in the .dynamic segment
        # 32-bit Elf32_Dyn: d_tag I4 + d_val I4 = 8 bytes
        # 64-bit Elf64_Dyn: d_tag Q8 + d_val Q8 = 16 bytes
        DT_DEBUG      = 0x15
        DT_NULL       = 0
        dyn_esz       = 16 if is64 else 8
        dyn_tag_fmt   = endian + ('Q' if is64 else 'I')
        dyn_tag_bytes = 8 if is64 else 4

        for i in range(e_phnum):
            ph_off = e_phoff + i * e_phentsize
            if ph_off + 4 > len(binary_data):
                break
            if struct.unpack_from(endian + 'I', binary_data, ph_off)[0] != PT_DYNAMIC:
                continue
            if is64:
                p_offset = struct.unpack_from(endian + 'Q', binary_data, ph_off + 8)[0]
                p_filesz = struct.unpack_from(endian + 'Q', binary_data, ph_off + 32)[0]
            else:
                p_offset = struct.unpack_from(endian + 'I', binary_data, ph_off + 4)[0]
                p_filesz = struct.unpack_from(endian + 'I', binary_data, ph_off + 16)[0]
            dyn_end = min(p_offset + p_filesz, len(binary_data))
            j = p_offset
            while j + dyn_esz <= dyn_end:
                d_tag = struct.unpack_from(dyn_tag_fmt, binary_data, j)[0]
                d_val = struct.unpack_from(dyn_tag_fmt, binary_data, j + dyn_tag_bytes)[0]
                if d_tag == DT_DEBUG and d_val != 0:
                    findings.append({
                        'severity': 'INFO',
                        'title': 'ELF_DEBUG_INFO_PRESENT',
                        'detail': (
                            f'DT_DEBUG (tag=0x15) in .dynamic with non-zero d_val=0x{d_val:x} '
                            '-- debug information embedded in dynamic segment: the dynamic '
                            'linker writes a pointer to its r_debug struct into DT_DEBUG at '
                            'runtime so debuggers can walk the link_map chain of loaded DSOs; '
                            'a hardcoded non-zero d_val in the on-disk binary indicates a debug '
                            'build or manually patched binary; exposes internal linker state to '
                            'attached debuggers via r_debug.r_map linked list; '
                            'ref: glibc sysdeps/generic/ldsodefs.h r_debug struct, '
                            'learning-linux-binary-analysis ch.2 PT_DYNAMIC / DT_DEBUG tag'
                        ),
                        'host': host,
                        'port': port,
                    })
                if d_tag == DT_NULL:
                    break
                j += dyn_esz
            break  # only one PT_DYNAMIC segment

        # Import scanning via .dynstr section; fall back to raw binary scan if stripped
        dangerous_imports = {b'system', b'popen', b'execve', b'ptrace', b'mmap', b'mprotect'}
        dynamic_loaders   = {b'dlopen', b'dl_open', b'dlsym'}

        dynstr_data = b''
        if e_shnum > 0 and 0 < e_shstrndx < e_shnum and e_shoff > 0:
            shstr_sh_off = e_shoff + e_shstrndx * e_shentsize
            if shstr_sh_off + e_shentsize <= len(binary_data):
                if is64:
                    shstr_foff = struct.unpack_from(endian + 'Q', binary_data, shstr_sh_off + 24)[0]
                    shstr_size = struct.unpack_from(endian + 'Q', binary_data, shstr_sh_off + 32)[0]
                else:
                    shstr_foff = struct.unpack_from(endian + 'I', binary_data, shstr_sh_off + 16)[0]
                    shstr_size = struct.unpack_from(endian + 'I', binary_data, shstr_sh_off + 20)[0]
                if 0 < shstr_foff and shstr_foff + shstr_size <= len(binary_data):
                    shstrtab = binary_data[shstr_foff:shstr_foff + shstr_size]
                    for s in range(e_shnum):
                        sh_off = e_shoff + s * e_shentsize
                        if sh_off + e_shentsize > len(binary_data):
                            break
                        sh_name_idx = struct.unpack_from(endian + 'I', binary_data, sh_off)[0]
                        if sh_name_idx >= len(shstrtab):
                            continue
                        nm_end = shstrtab.find(b'\x00', sh_name_idx)
                        if nm_end == -1:
                            continue
                        if shstrtab[sh_name_idx:nm_end] == b'.dynstr':
                            if is64:
                                ds_off  = struct.unpack_from(endian + 'Q', binary_data, sh_off + 24)[0]
                                ds_size = struct.unpack_from(endian + 'Q', binary_data, sh_off + 32)[0]
                            else:
                                ds_off  = struct.unpack_from(endian + 'I', binary_data, sh_off + 16)[0]
                                ds_size = struct.unpack_from(endian + 'I', binary_data, sh_off + 20)[0]
                            if 0 < ds_off and ds_off + ds_size <= len(binary_data):
                                dynstr_data = binary_data[ds_off:ds_off + ds_size]
                            break

        scan_target = dynstr_data if dynstr_data else binary_data

        found_dangerous = sorted({
            sym.decode('ascii', errors='replace')
            for sym in dangerous_imports
            if (sym + b'\x00') in scan_target
        })
        found_loaders = sorted({
            sym.decode('ascii', errors='replace')
            for sym in dynamic_loaders
            if (sym + b'\x00') in scan_target
        })

        if found_dangerous:
            findings.append({
                'severity': 'HIGH',
                'title': 'ELF_DANGEROUS_IMPORTS',
                'detail': (
                    f'Dangerous function imports in ELF dynamic string table: '
                    f'{found_dangerous}; '
                    'system()/popen() execute arbitrary shell commands from a string -- any '
                    'format-string or overflow reaching these calls = OS command injection; '
                    'execve() replaces the process image by path+argv -- writable path or argv '
                    '= arbitrary program execution; ptrace() enables PTRACE_POKETEXT writes '
                    'into any attached process address space (see ch.3 code injection); '
                    'mmap()+mprotect() together create RWX pages: mmap(PROT_RW) -> write '
                    'shellcode -> mprotect(PROT_RX) bypasses W^X enforcement; '
                    'ref: learning-linux-binary-analysis ch.2 .dynstr section, '
                    'ch.3 ptrace and code injection with PTRACE_POKETEXT'
                ),
                'host': host,
                'port': port,
            })

        if found_loaders:
            findings.append({
                'severity': 'MEDIUM',
                'title': 'ELF_DYNAMIC_LOADING',
                'detail': (
                    f'Dynamic loading functions in ELF imports: {found_loaders}; '
                    'dlopen() opens a shared library by path string at runtime -- if the path '
                    'is user-controlled or derived from env vars (LD_LIBRARY_PATH, relative '
                    'DT_RUNPATH), an attacker can substitute a malicious .so; dlsym() resolves '
                    'a symbol by name from a dlopen() handle, enabling runtime plugin execution '
                    'that bypasses static import analysis; this mechanism is also used by '
                    'LD_PRELOAD injection and GOT/PLT hooking frameworks to intercept library '
                    'calls at the symbol resolution layer; '
                    'ref: learning-linux-binary-analysis ch.2 ELF dynamic linking, '
                    'DT_NEEDED / DT_RUNPATH tags, dlopen(3)'
                ),
                'host': host,
                'port': port,
            })

    except (struct.error, IndexError, ValueError):
        pass

    return findings


# ---------------------------------------------------------------------------
# ELF runtime injection and hooking technique detection
# Ref: Learning Linux Binary Analysis ch.2-3 (ELF format + process tracing)
# ---------------------------------------------------------------------------

def detect_elf_runtime_injection_techniques(binary_data: bytes, host: str = '', port: int = 0) -> list:
    """Detect ELF runtime injection and hooking techniques: LD_PRELOAD/LD_AUDIT
    references, PLT/GOT hook surface, ptrace abuse, suspicious DT_NEEDED paths,
    IRELATIVE/IFUNC misuse, and parasitic entry points outside .text.
    Ref: Learning Linux Binary Analysis ch.2-3.
    """
    findings = []
    if len(binary_data) < 64 or binary_data[:4] != b'\x7fELF':
        return []

    try:
        ei_class = binary_data[4]
        ei_data  = binary_data[5]
        if ei_class not in (1, 2):
            return []
        is64   = (ei_class == 2)
        endian = '>' if ei_data == 2 else '<'

        e_type = struct.unpack_from(endian + 'H', binary_data, 16)[0]
        if not is64:
            e_entry     = struct.unpack_from(endian + 'I', binary_data, 24)[0]
            e_phoff     = struct.unpack_from(endian + 'I', binary_data, 28)[0]
            e_shoff     = struct.unpack_from(endian + 'I', binary_data, 32)[0]
            e_phentsize = struct.unpack_from(endian + 'H', binary_data, 42)[0]
            e_phnum     = struct.unpack_from(endian + 'H', binary_data, 44)[0]
            e_shentsize = struct.unpack_from(endian + 'H', binary_data, 46)[0]
            e_shnum     = struct.unpack_from(endian + 'H', binary_data, 48)[0]
            e_shstrndx  = struct.unpack_from(endian + 'H', binary_data, 50)[0]
        else:
            e_entry     = struct.unpack_from(endian + 'Q', binary_data, 24)[0]
            e_phoff     = struct.unpack_from(endian + 'Q', binary_data, 32)[0]
            e_shoff     = struct.unpack_from(endian + 'Q', binary_data, 40)[0]
            e_phentsize = struct.unpack_from(endian + 'H', binary_data, 54)[0]
            e_phnum     = struct.unpack_from(endian + 'H', binary_data, 56)[0]
            e_shentsize = struct.unpack_from(endian + 'H', binary_data, 58)[0]
            e_shnum     = struct.unpack_from(endian + 'H', binary_data, 60)[0]
            e_shstrndx  = struct.unpack_from(endian + 'H', binary_data, 62)[0]

        if e_phnum > 256 or e_shnum > 4096:
            return []

        # LD_PRELOAD: binary reads/sets the dynamic linker preload variable
        if b'LD_PRELOAD' in binary_data:
            findings.append({
                'severity': 'CRITICAL',
                'title': 'ELF_LD_PRELOAD_REFERENCE',
                'detail': (
                    'LD_PRELOAD string embedded in ELF binary -- runtime library injection '
                    'surface: LD_PRELOAD causes ld.so to load a specified .so before all '
                    'others in the link chain, enabling symbol interposition -- any libc '
                    'function can be replaced by the preloaded library\'s same-named export; '
                    'attack chain: LD_PRELOAD=/tmp/evil.so ./target -> linker resolves all '
                    'PLT entries from evil.so first, intercepting open(), read(), getenv(), '
                    'malloc(), and any other libc symbol; presence in binary indicates it '
                    'reads, sets, or propagates LD_PRELOAD to child processes via '
                    'putenv()+execve(); system-wide persistence: writing to /etc/ld.so.preload '
                    'applies LD_PRELOAD to every dynamically linked process on the host; '
                    'ref: ld.so(8) LD_PRELOAD, learning-linux-binary-analysis ch.2 '
                    'dynamic linking, ch.7 PLT/GOT poisoning via preloaded libraries'
                ),
                'host': host,
                'port': port,
            })

        # LD_AUDIT: more powerful than preload -- hooks every symbol binding event
        if b'LD_AUDIT' in binary_data:
            findings.append({
                'severity': 'CRITICAL',
                'title': 'ELF_LD_AUDIT_REFERENCE',
                'detail': (
                    'LD_AUDIT string embedded in ELF binary -- rtld auditing interface '
                    'manipulation: LD_AUDIT loads an audit library implementing rtld-audit(7); '
                    'callbacks la_symbind32/64 fire for every PLT/GOT symbol binding event, '
                    'la_preinit before main(), la_objopen for each DSO load -- complete '
                    'visibility into every dynamic linker resolution event; more capable than '
                    'LD_PRELOAD: audit callbacks receive and can modify the resolved address '
                    'of every symbol without requiring name collision; the audit library runs '
                    'with the full privileges of the target process; presence indicates the '
                    'binary manipulates LD_AUDIT to instrument child processes or hook symbol '
                    'resolution; ref: rtld-audit(7), glibc elf/dl-audit.c, '
                    'ld.so(8) LD_AUDIT environment variable'
                ),
                'host': host,
                'port': port,
            })

        # PLT/GOT hooking surface: .got.plt section name reference combined with mprotect import
        has_gotplt   = b'.got.plt' in binary_data or b'got.plt' in binary_data
        has_mprotect = b'mprotect\x00' in binary_data
        if has_gotplt and has_mprotect:
            findings.append({
                'severity': 'HIGH',
                'title': 'ELF_PLT_HOOK_SURFACE',
                'detail': (
                    '.got.plt reference + mprotect import -- PLT/GOT runtime hooking surface: '
                    'the GOT (.got.plt section) is an array of function pointers patched by '
                    'ld.so at startup; each slot holds the resolved address of a shared library '
                    'function reached via PLT stubs; mprotect() with PROT_WRITE on the .got.plt '
                    'page re-enables writes even under partial RELRO, allowing each GOT slot to '
                    'be overwritten with an attacker trampoline; all subsequent PLT calls '
                    '(printf@PLT, malloc@PLT, etc.) branch to the trampoline instead of the '
                    'legitimate function; a binary embedding the got.plt string and importing '
                    'mprotect is deliberately manipulating GOT page permissions -- hallmark of '
                    'a runtime hooking framework or userland rootkit; '
                    'ref: learning-linux-binary-analysis ch.2 .got.plt section, '
                    'ch.7 PLT/GOT poisoning, mprotect(2)'
                ),
                'host': host,
                'port': port,
            })

        # ptrace usage in a binary with no debugger context strings
        has_ptrace  = b'ptrace\x00' in binary_data or b'ptrace' in binary_data
        is_debugger = any(s in binary_data for s in (b'gdb', b'strace', b'ltrace', b'debugger'))
        if has_ptrace and not is_debugger:
            findings.append({
                'severity': 'HIGH',
                'title': 'ELF_PTRACE_USAGE',
                'detail': (
                    'ptrace reference in non-debugger ELF -- process tracing/injection surface: '
                    'ptrace(2) is the primary Linux mechanism for process observation and '
                    'control; PTRACE_ATTACH/SEIZE attaches to a running process; '
                    'PTRACE_PEEKTEXT/PTRACE_POKETEXT read and write arbitrary process memory '
                    'at word granularity -- sufficient to inject shellcode into any executable '
                    'page; PTRACE_SETREGS redirects RIP/EIP to injected code; PTRACE_TRACEME '
                    'in a __constructor__ function self-traces the process so no external '
                    'debugger can attach (anti-debug trick documented in '
                    'learning-linux-binary-analysis ch.2 .ctors section); without gdb/strace/'
                    'ltrace context, ptrace use signals: runtime code patching, process '
                    'hollowing, or anti-debug self-tracing; '
                    'ref: learning-linux-binary-analysis ch.3 Linux process tracing, '
                    'ptrace(2), PTRACE_POKETEXT code injection technique'
                ),
                'host': host,
                'port': port,
            })

        # DT_NEEDED entries containing suspicious library paths
        # Standard entries are bare names (libc.so.6) resolved via ld.so search paths;
        # absolute /tmp/ paths, relative ./paths, or /home/ paths indicate injection
        PT_DYNAMIC    = 2
        PT_LOAD       = 1
        DT_NULL       = 0
        DT_NEEDED     = 1
        DT_STRTAB     = 5
        dyn_esz       = 16 if is64 else 8
        dyn_tag_fmt   = endian + ('Q' if is64 else 'I')
        dyn_tag_bytes = 8 if is64 else 4
        suspicious_libs = []

        for i in range(e_phnum):
            ph_off = e_phoff + i * e_phentsize
            if ph_off + 4 > len(binary_data):
                break
            if struct.unpack_from(endian + 'I', binary_data, ph_off)[0] != PT_DYNAMIC:
                continue
            if is64:
                p_offset = struct.unpack_from(endian + 'Q', binary_data, ph_off + 8)[0]
                p_filesz = struct.unpack_from(endian + 'Q', binary_data, ph_off + 32)[0]
            else:
                p_offset = struct.unpack_from(endian + 'I', binary_data, ph_off + 4)[0]
                p_filesz = struct.unpack_from(endian + 'I', binary_data, ph_off + 16)[0]
            dyn_end = min(p_offset + p_filesz, len(binary_data))

            # First pass: locate DT_STRTAB virtual address for the dynamic string table
            strtab_vaddr = 0
            j = p_offset
            while j + dyn_esz <= dyn_end:
                d_tag = struct.unpack_from(dyn_tag_fmt, binary_data, j)[0]
                d_val = struct.unpack_from(dyn_tag_fmt, binary_data, j + dyn_tag_bytes)[0]
                if d_tag == DT_STRTAB:
                    strtab_vaddr = d_val
                if d_tag == DT_NULL:
                    break
                j += dyn_esz

            # Convert strtab virtual address to file offset via PT_LOAD segment mapping
            strtab_foff = 0
            if strtab_vaddr:
                for k in range(e_phnum):
                    kph = e_phoff + k * e_phentsize
                    if kph + 4 > len(binary_data):
                        break
                    if struct.unpack_from(endian + 'I', binary_data, kph)[0] != PT_LOAD:
                        continue
                    if is64:
                        kp_off   = struct.unpack_from(endian + 'Q', binary_data, kph + 8)[0]
                        kp_vaddr = struct.unpack_from(endian + 'Q', binary_data, kph + 16)[0]
                        kp_fsz   = struct.unpack_from(endian + 'Q', binary_data, kph + 32)[0]
                    else:
                        kp_off   = struct.unpack_from(endian + 'I', binary_data, kph + 4)[0]
                        kp_vaddr = struct.unpack_from(endian + 'I', binary_data, kph + 8)[0]
                        kp_fsz   = struct.unpack_from(endian + 'I', binary_data, kph + 16)[0]
                    if kp_vaddr <= strtab_vaddr < kp_vaddr + kp_fsz:
                        strtab_foff = kp_off + (strtab_vaddr - kp_vaddr)
                        break

            # Second pass: read DT_NEEDED string values and check for suspicious paths
            if strtab_foff:
                j = p_offset
                while j + dyn_esz <= dyn_end:
                    d_tag = struct.unpack_from(dyn_tag_fmt, binary_data, j)[0]
                    d_val = struct.unpack_from(dyn_tag_fmt, binary_data, j + dyn_tag_bytes)[0]
                    if d_tag == DT_NEEDED:
                        str_off = strtab_foff + d_val
                        if str_off < len(binary_data):
                            null_pos = binary_data.find(b'\x00', str_off)
                            if null_pos != -1:
                                lib = binary_data[str_off:null_pos].decode('ascii', errors='replace')
                                if (lib.startswith('/tmp/') or lib.startswith('/dev/')
                                        or lib.startswith('/proc/')
                                        or lib.startswith('./') or lib.startswith('../')
                                        or '/home/' in lib):
                                    suspicious_libs.append(lib)
                    if d_tag == DT_NULL:
                        break
                    j += dyn_esz
            break  # only one PT_DYNAMIC segment

        if suspicious_libs:
            findings.append({
                'severity': 'CRITICAL',
                'title': 'ELF_SUSPICIOUS_LIBRARY_PATH',
                'detail': (
                    f'DT_NEEDED entries with suspicious library paths: {suspicious_libs}; '
                    'DT_NEEDED in the .dynamic segment lists shared libraries required at '
                    'runtime; standard entries are bare names (libc.so.6) resolved via ld.so '
                    'search paths (/etc/ld.so.cache, DT_RUNPATH, /lib); absolute /tmp/ paths, '
                    'relative ./paths, or /home/ paths indicate: dropped .so persistence in '
                    'world-writable directories, deliberate shared library injection, or '
                    'malicious library substitution; ld.so loads DT_NEEDED entries in order '
                    '-- a /tmp/.evil.so entry executes its .init section before main() runs '
                    'with no additional privileges beyond the target binary\'s effective uid; '
                    'ref: ld.so(8) DT_NEEDED search order, '
                    'learning-linux-binary-analysis ch.2 dynamic segment DT_NEEDED tag'
                ),
                'host': host,
                'port': port,
            })

        # IFUNC / IRELATIVE indicator: string presence in binary
        # R_X86_64_IRELATIVE (37) / R_386_IRELATIVE (42) invoke a resolver at load time
        has_irelative = (b'IRELATIVE' in binary_data
                         or b'STT_GNU_IFUNC' in binary_data
                         or b'ifunc' in binary_data)
        if has_irelative:
            findings.append({
                'severity': 'MEDIUM',
                'title': 'ELF_IRELATIVE_RELOCATION',
                'detail': (
                    'IFUNC / IRELATIVE relocation indicator in ELF binary -- indirect function '
                    'resolution execution surface: R_X86_64_IRELATIVE (type 37) and '
                    'R_386_IRELATIVE (type 42) relocations invoke an IFUNC resolver function '
                    'at the addend address during dl_relocate_object() before main() executes; '
                    'designed for CPU feature dispatch (selecting AVX vs SSE memcpy) but '
                    'exploitable: a patched binary can add an IRELATIVE entry pointing to '
                    'injected code that runs before any debugger attach point and before '
                    'main(); the resolver executes with full process context and can perform '
                    'arbitrary actions then return a legitimate address to evade post-init '
                    'memory inspection; '
                    'ref: ELF spec STT_GNU_IFUNC, binutils ld IRELATIVE generation, '
                    'glibc elf/dl-machine.h elf_machine_rela() IRELATIVE handling'
                ),
                'host': host,
                'port': port,
            })

        # Parasitic entry point: e_entry outside the .text section address range
        # Requires section headers to be present for .text address lookup
        if e_shnum > 0 and 0 < e_shstrndx < e_shnum and e_shoff > 0 and e_entry > 0:
            shstr_sh = e_shoff + e_shstrndx * e_shentsize
            if shstr_sh + e_shentsize <= len(binary_data):
                if is64:
                    shstr_foff = struct.unpack_from(endian + 'Q', binary_data, shstr_sh + 24)[0]
                    shstr_size = struct.unpack_from(endian + 'Q', binary_data, shstr_sh + 32)[0]
                else:
                    shstr_foff = struct.unpack_from(endian + 'I', binary_data, shstr_sh + 16)[0]
                    shstr_size = struct.unpack_from(endian + 'I', binary_data, shstr_sh + 20)[0]
                if 0 < shstr_foff and shstr_foff + shstr_size <= len(binary_data):
                    shstrtab   = binary_data[shstr_foff:shstr_foff + shstr_size]
                    text_start = 0
                    text_end   = 0
                    for s in range(e_shnum):
                        sh_off = e_shoff + s * e_shentsize
                        if sh_off + e_shentsize > len(binary_data):
                            break
                        nm_idx = struct.unpack_from(endian + 'I', binary_data, sh_off)[0]
                        if nm_idx >= len(shstrtab):
                            continue
                        nm_end = shstrtab.find(b'\x00', nm_idx)
                        if nm_end == -1:
                            continue
                        if shstrtab[nm_idx:nm_end] == b'.text':
                            if is64:
                                text_start = struct.unpack_from(endian + 'Q', binary_data, sh_off + 16)[0]
                                text_sz    = struct.unpack_from(endian + 'Q', binary_data, sh_off + 32)[0]
                            else:
                                text_start = struct.unpack_from(endian + 'I', binary_data, sh_off + 12)[0]
                                text_sz    = struct.unpack_from(endian + 'I', binary_data, sh_off + 20)[0]
                            text_end = text_start + text_sz
                            break
                    if text_start and text_end and not (text_start <= e_entry < text_end):
                        findings.append({
                            'severity': 'HIGH',
                            'title': 'ELF_ENTRY_OUTSIDE_TEXT',
                            'detail': (
                                f'ELF e_entry=0x{e_entry:x} outside .text section '
                                f'[0x{text_start:x}-0x{text_end:x}] -- parasitic entry point: '
                                'e_entry in the ELF file header specifies the first instruction '
                                'executed after kernel load; normally this is inside .text at '
                                'the _start symbol or CRT entry; an entry outside .text '
                                'indicates: ELF virus infection that appended a shellcode stub '
                                'to a PT_LOAD extension and redirected e_entry, binary patching '
                                'that placed injected code in a NOTE/PT_NOTE segment, or '
                                'deliberate anti-analysis obfuscation; classic Linux parasite: '
                                'extend the last PT_LOAD segment by shellcode size, set e_entry '
                                'to the appended code, shellcode saves registers and transfers '
                                'control back to the original entry after executing payload; '
                                'ref: learning-linux-binary-analysis ch.2 ELF header e_entry, '
                                'Ryan O\'Neill parasite infection technique ch.2-4'
                            ),
                            'host': host,
                            'port': port,
                        })

    except (struct.error, IndexError, ValueError):
        pass

    return findings


# ---------------------------------------------------------------------------
# Binary obfuscation and PEB manipulation detection
# Ref: Practical Binary Analysis (Dennis Andriesse, 2019) Ch.1-3
# ---------------------------------------------------------------------------

def detect_binary_obfuscation_patterns(binary_data: bytes, host: str = '', port: int = 0) -> list:
    """
    Detect binary obfuscation and protection techniques.
    Source: 'Practical Binary Analysis' (Dennis Andriesse, 2019) Ch.1-3 -- binary anatomy,
    ELF/PE format internals, stripped binaries, section structure, and import tables.
    Covers UPX packing, high-entropy (packed/encrypted) sections, stripped debug symbols,
    PE overlay data (appended content after last section), non-standard PE section names,
    and minimal PE import tables indicative of dynamic API resolution.
    """
    import math

    findings = []
    data = binary_data

    # --- UPX_PACKED_BINARY: UPX packer signature ---
    # UPX writes 'UPX!' as a 4-byte marker; packed section names are 'UPX0' and 'UPX1'.
    # PBA Ch.1: in a UPX binary the .text section stores compressed code; the decompressor
    # stub runs first, decompresses to a freshly allocated RWX region, then jumps to OEP.
    if b'UPX!' in data or b'UPX0\x00' in data or b'UPX1\x00' in data:
        findings.append({
            'severity': 'HIGH',
            'title':    'UPX_PACKED_BINARY',
            'detail':   (
                'UPX packer signature detected (UPX! marker or UPX0/UPX1 section names): '
                'the binary is packed and the .text section contains compressed code rather than '
                'directly executable instructions; static disassembly produces garbage output '
                'until the stub decompresses the original code at runtime; '
                'PBA Ch.1: UPX stub decompresses the payload to a freshly allocated RWX region '
                'then jumps to the original entry point (OEP); '
                'remediation: unpack with "upx -d <binary>" before analysis; '
                'packed binaries evade signature-based AV since the actual code bytes are not '
                'visible in the on-disk representation; '
                'dynamic analysis (process dump after OEP execution) recovers the original binary'
            ),
            'host': host,
            'port': port,
        })

    # --- HIGH_ENTROPY_SECTIONS: Entropy analysis for packed/encrypted code ---
    # PBA Ch.1: packed or encrypted sections have near-uniform byte distributions.
    # Shannon entropy H = -sum(p_i * log2(p_i)) approaches 8.0 for random/encrypted data.
    # Split into 256-byte chunks; > 30% of chunks above 7.2 bits signals packing/encryption.
    CHUNK_SZ = 256
    ENTROPY_THRESH = 7.2
    HIGH_RATIO = 0.30
    total_chunks = 0
    high_entropy_chunks = 0
    for i in range(0, len(data), CHUNK_SZ):
        chunk = data[i:i + CHUNK_SZ]
        if len(chunk) < 32:
            continue
        total_chunks += 1
        freq = [0] * 256
        for b in chunk:
            freq[b] += 1
        n = len(chunk)
        entropy = sum(-(c / n) * math.log2(c / n) for c in freq if c > 0)
        if entropy > ENTROPY_THRESH:
            high_entropy_chunks += 1

    if total_chunks > 0 and (high_entropy_chunks / total_chunks) > HIGH_RATIO:
        pct = int(high_entropy_chunks / total_chunks * 100)
        findings.append({
            'severity': 'HIGH',
            'title':    'HIGH_ENTROPY_SECTIONS',
            'detail':   (
                f'{high_entropy_chunks}/{total_chunks} ({pct}%) 256-byte chunks exceed '
                f'{ENTROPY_THRESH} bits/byte Shannon entropy (threshold >{int(HIGH_RATIO*100)}%): '
                'likely packed or encrypted payload -- PBA Ch.1: in a packed binary the .text '
                'section stores compressed/XOR-encrypted code; the stub decompresses at runtime; '
                'high-entropy sections are a reliable packing indicator even when packer '
                'signatures are absent; encrypted overlay data (appended after PE sections) '
                'also exhibits high entropy; entropy > 7.5 across the whole binary strongly '
                'suggests encryption; '
                'analysis approach: identify the decompressor stub (low-entropy section executed '
                'first), set breakpoint at OEP transfer, dump process memory post-decompression'
            ),
            'host': host,
            'port': port,
        })

    # --- DEBUG_INFO_STRIPPED: Absence of debug information markers ---
    # PBA Ch.1: 'strip --strip-all' removes .symtab/.strtab and DWARF debug sections,
    # eliminating function name symbols and source-line mappings; stripped binaries force
    # reverse engineers to reconstruct function boundaries through heuristics rather than
    # reading symbol names. Absence of DWARF markers in a large binary signals stripping.
    DEBUG_MARKERS = [b'DWARF', b'__debug_info', b'.debug_line', b'__debug_abbrev',
                     b'.debug_info', b'DW_AT_', b'.debug_str']
    has_debug = any(m in data for m in DEBUG_MARKERS)
    if not has_debug and len(data) > 4096:
        findings.append({
            'severity': 'MEDIUM',
            'title':    'DEBUG_INFO_STRIPPED',
            'detail':   (
                'No DWARF debug section markers found in binary of significant size; '
                'binary appears stripped of debug information: '
                'PBA Ch.1: stripped binaries (strip --strip-all) lose .symtab, .strtab, and '
                'DWARF sections, eliminating function symbols and source-line mappings; '
                'readelf --syms shows only .dynsym entries (dynamic linking symbols that '
                'cannot be stripped without breaking dynamic loading); '
                'stripped binaries force reconstruction of function boundaries via heuristics '
                '(epilogue/prologue patterns, call-graph reconstruction); '
                'all production malware and most commercial software ships stripped; '
                'IDA Pro / Ghidra apply FLIRT / function-signature matching to recover '
                'standard library function names even in stripped binaries'
            ),
            'host': host,
            'port': port,
        })

    # PE-specific checks: overlay data, section names, minimal imports
    # Require MZ magic and valid e_lfanew (PBA Ch.3: every PE starts with MS-DOS MZ header)
    if len(data) < 0x40 or data[:2] != b'MZ':
        return findings

    try:
        pe_off = struct.unpack_from('<I', data, 0x3C)[0]
    except struct.error:
        return findings

    if pe_off + 24 >= len(data) or data[pe_off:pe_off + 4] != b'PE\x00\x00':
        return findings

    try:
        num_sections = struct.unpack_from('<H', data, pe_off + 6)[0]
        size_opt = struct.unpack_from('<H', data, pe_off + 20)[0]
    except struct.error:
        return findings

    opt_hdr_off = pe_off + 24       # 4-byte PE sig + 20-byte IMAGE_FILE_HEADER
    sec_tbl_off = opt_hdr_off + size_opt

    # PBA Ch.3: standard PE section names from the PE/COFF specification
    STANDARD_NAMES = {
        b'.text', b'.data', b'.rdata', b'.bss', b'.rsrc', b'.reloc',
        b'.idata', b'.edata', b'.pdata', b'.tls', b'.debug', b'.xdata',
        b'.sdata', b'.sbss', b'CODE', b'DATA', b'BSS',
    }

    sections_pe = []    # (name, vaddr, vsize, raw_off, raw_size)
    non_standard = []
    last_raw_end = 0

    for i in range(min(num_sections, 96)):
        off = sec_tbl_off + i * 40
        if off + 40 > len(data):
            break
        name     = data[off:off + 8].rstrip(b'\x00')
        vsize    = struct.unpack_from('<I', data, off + 8)[0]
        vaddr    = struct.unpack_from('<I', data, off + 12)[0]
        raw_size = struct.unpack_from('<I', data, off + 16)[0]
        raw_off  = struct.unpack_from('<I', data, off + 20)[0]
        sections_pe.append((name, vaddr, vsize, raw_off, raw_size))

        if raw_off > 0 and raw_size > 0:
            raw_end = raw_off + raw_size
            if raw_end > last_raw_end:
                last_raw_end = raw_end

        if name and name not in STANDARD_NAMES:
            non_standard.append(name.decode('ascii', errors='replace'))

    def _pe_rva_to_off(rva):
        for (sn, va, vsz, ro, rs) in sections_pe:
            span = max(vsz, rs)
            if span > 0 and va <= rva < va + span:
                return ro + (rva - va)
        return None

    # --- BINARY_OVERLAY_DATA: Data appended after last PE section ---
    # PBA Ch.3: PointerToRawData + SizeOfRawData marks the legitimate end of PE content;
    # data beyond this boundary is not described by any section header ("overlay data");
    # used by malware to store encrypted configs, second-stage payloads, or RC4-keyed shellcode.
    if last_raw_end > 0 and len(data) > last_raw_end + 512:
        overlay_size = len(data) - last_raw_end
        findings.append({
            'severity': 'HIGH',
            'title':    'BINARY_OVERLAY_DATA',
            'detail':   (
                f'PE binary has {overlay_size} bytes of data after the last declared section '
                f'(file offset {last_raw_end:#010x}): '
                'PBA Ch.3: the PE format defines end-of-content as PointerToRawData + '
                'SizeOfRawData of the last section; data appended beyond this boundary is '
                'overlay data -- not described by any section header; '
                'malware uses overlay data to store encrypted C2 URLs, RC4 keys, or '
                'second-stage payloads decoded at runtime; '
                'self-extracting installers (NSIS, WinRAR SFX) also append overlay data legitimately; '
                'differentiate: overlay entropy > 7.0 suggests encryption; '
                'overlay starting with PK (0x504B) is a ZIP archive; '
                'overlay starting with MZ is a nested PE binary; '
                'extraction: carve bytes from last_section_end to EOF for separate analysis'
            ),
            'host': host,
            'port': port,
        })

    # --- NON_STANDARD_SECTION_NAMES: Obfuscated or packer-generated section names ---
    # PBA Ch.2/3: standard section names (.text, .data, etc.) are PE/COFF convention;
    # packers and obfuscators rename sections or use non-printable names to confuse tools.
    if non_standard:
        findings.append({
            'severity': 'MEDIUM',
            'title':    'NON_STANDARD_SECTION_NAMES',
            'detail':   (
                f'PE section name(s) not matching PE/COFF standard conventions: {non_standard}; '
                'PBA Ch.2: section names are stored in the 8-byte Name field of '
                'IMAGE_SECTION_HEADER; standard names (.text, .data, .rdata, .bss, .rsrc, '
                '.reloc, .idata, .edata, .pdata, .tls) are PE/COFF spec conventions; '
                'packers frequently rename sections (UPX0/UPX1, .petite, .nsp*, .MPRESS*) '
                'or use non-printable bytes to confuse section-name-based detection; '
                'custom names alone are low-signal (Delphi and .NET compilers produce '
                'non-standard names legitimately); combined with high entropy or minimal '
                'imports this indicator is HIGH confidence'
            ),
            'host': host,
            'port': port,
        })

    # --- MINIMAL_IMPORT_TABLE: Very few imports indicating dynamic API resolution ---
    # PBA Ch.3: the PE Import Directory (DataDirectory[1]) describes statically declared
    # DLL/function dependencies; malware using GetProcAddress+LoadLibrary or PEB
    # InLoadOrderModuleList walk can reduce the visible IAT to 1-2 entries to defeat
    # static import analysis by AV/EDR.
    if size_opt >= 4 and opt_hdr_off + size_opt <= len(data):
        try:
            opt_magic = struct.unpack_from('<H', data, opt_hdr_off)[0]
            # DataDirectory starts at opt_hdr_off + 0x60 (PE32) or +0x70 (PE32+)
            # PBA Ch.3 optional header layout: PE32 has BaseOfData (4B) that PE32+ omits;
            # PE32+ has 8B ImageBase/stack/heap fields vs 4B in PE32 (+16B total offset)
            if opt_magic == 0x10b:    # PE32
                dd_off = opt_hdr_off + 0x60
                thunk_size = 4
                ordinal_flag = 0x80000000
            elif opt_magic == 0x20b:  # PE32+ (64-bit)
                dd_off = opt_hdr_off + 0x70
                thunk_size = 8
                ordinal_flag = 0x8000000000000000
            else:
                dd_off = None

            if dd_off and dd_off + 16 <= len(data):
                # DataDirectory[1] = Import Directory (each DD entry: 4B RVA + 4B Size)
                import_rva = struct.unpack_from('<I', data, dd_off + 8)[0]
                import_sz  = struct.unpack_from('<I', data, dd_off + 12)[0]

                if import_rva and import_sz:
                    imp_tbl_off = _pe_rva_to_off(import_rva)
                    total_named_imports = 0

                    if imp_tbl_off and imp_tbl_off + 20 <= len(data):
                        # Walk IMAGE_IMPORT_DESCRIPTORs (20 bytes each); all-zero = sentinel
                        for desc_idx in range(200):
                            desc = imp_tbl_off + desc_idx * 20
                            if desc + 20 > len(data):
                                break
                            orig_ft, _ts, _fc, name_rva, first_thunk = struct.unpack_from(
                                '<IIIII', data, desc
                            )
                            if orig_ft == 0 and name_rva == 0 and first_thunk == 0:
                                break
                            thunk_rva = orig_ft if orig_ft else first_thunk
                            thunk_file = _pe_rva_to_off(thunk_rva)
                            if thunk_file:
                                for k in range(2000):
                                    t_off = thunk_file + k * thunk_size
                                    if t_off + thunk_size > len(data):
                                        break
                                    if thunk_size == 4:
                                        val = struct.unpack_from('<I', data, t_off)[0]
                                    else:
                                        val = struct.unpack_from('<Q', data, t_off)[0]
                                    if val == 0:
                                        break
                                    if not (val & ordinal_flag):
                                        total_named_imports += 1

                    if 0 < total_named_imports < 3 and len(data) > 10240:
                        findings.append({
                            'severity': 'HIGH',
                            'title':    'MINIMAL_IMPORT_TABLE',
                            'detail':   (
                                f'PE binary statically imports only {total_named_imports} named '
                                'function(s) from the Import Directory (IAT): '
                                'PBA Ch.3: the Import Address Table lists all statically declared '
                                'library dependencies; malware using dynamic API resolution '
                                '(GetProcAddress / LoadLibrary, or PEB walk to '
                                'InLoadOrderModuleList) reduces the visible IAT to 1-2 entries '
                                'to defeat static function-import analysis by AV/EDR; '
                                'a legitimate binary of this size would typically import 10-100+ '
                                'functions; presence of "LoadLibrary" and "GetProcAddress" in '
                                'the minimal import set confirms runtime resolution; '
                                'remediation: dynamic analysis (API monitoring) or sandbox '
                                'captures the true import set at runtime'
                            ),
                            'host': host,
                            'port': port,
                        })
        except (struct.error, TypeError, ValueError):
            pass

    return findings


def detect_pe_peb_manipulation(binary_data: bytes, host: str = '', port: int = 0) -> list:
    """
    Detect PEB (Process Environment Block) manipulation and anti-analysis techniques.
    Source: 'Practical Binary Analysis' (Dennis Andriesse, 2019) Ch.1-3 -- PE load process,
    dynamic-linking internals, and the Windows loader's PEB population sequence.
    The PEB is populated by ntdll (LdrpInitializeProcess) before the entry point executes
    (PBA Ch.3); it contains the module list (InLoadOrderModuleList), debug flags
    (BeingDebugged, NtGlobalFlag), and heap metadata -- structures widely abused by
    malware for anti-debug detection, module hiding, and PPID spoofing.
    """
    findings = []
    data = binary_data

    # --- PEB_DEBUGGER_CHECK: NtQueryInformationProcess + IsDebuggerPresent ---
    # IsDebuggerPresent reads PEB.BeingDebugged (PEB+0x02); NtQueryInformationProcess
    # (ProcessDebugPort) returns non-zero when debugged via WaitForDebugEvent.
    # Combining both provides redundancy: patching PEB.BeingDebugged=0 fails if
    # NtQueryInformationProcess check remains active.
    has_ntqip = b'NtQueryInformationProcess' in data
    has_idbp  = b'IsDebuggerPresent' in data
    if has_ntqip and has_idbp:
        findings.append({
            'severity': 'HIGH',
            'title':    'PEB_DEBUGGER_CHECK',
            'detail':   (
                'NtQueryInformationProcess + IsDebuggerPresent both present: '
                'combined PEB-based debugger detection; IsDebuggerPresent reads PEB+0x02 '
                '(BeingDebugged byte) set to 1 by the Windows loader when a debugger is '
                'attached; NtQueryInformationProcess(ProcessDebugPort) returns non-zero '
                'when debugged via WaitForDebugEvent; '
                'malware uses both to cross-validate: a single-point bypass (patching '
                'PEB.BeingDebugged=0) fails if NtQueryInformationProcess check remains; '
                'bypass: zero PEB.BeingDebugged at PEB+0x02 AND intercept the '
                'NtQueryInformationProcess syscall to return 0 for ProcessDebugPort; '
                'PBA Ch.3: the Windows loader (ntdll LdrpInitializeProcess) populates the '
                'PEB including the debug flag before transferring control to AddressOfEntryPoint'
            ),
            'host': host,
            'port': port,
        })

    # --- PEB_NTGlobalFlag_CHECK: HeapFlags / NtGlobalFlag anti-debug ---
    # PEB.NtGlobalFlag at 32-bit offset 0x68 / 64-bit offset 0xBC is set to 0x70 by the
    # Windows loader when the process is created under a debugger
    # (FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS);
    # HeapFlags and ForceFlags in the heap header are similarly non-zero under a debugger.
    has_ntgf       = b'NtGlobalFlag' in data
    has_heap_flags = b'HeapFlags' in data
    if has_ntgf or has_heap_flags:
        findings.append({
            'severity': 'HIGH',
            'title':    'PEB_NTGlobalFlag_CHECK',
            'detail':   (
                'NtGlobalFlag or HeapFlags reference detected: '
                'PEB.NtGlobalFlag (32-bit: PEB+0x68, 64-bit: PEB+0xBC) is set to 0x70 '
                '(FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | '
                'FLG_HEAP_VALIDATE_PARAMETERS) by the Windows loader when the process is '
                'started under a debugger; malware reads this field to detect debugging '
                'even after PEB.BeingDebugged has been patched to 0; '
                'HeapBase.ForceFlags (heap+0x18 on 32-bit, heap+0x74 on 64-bit) is also '
                'non-zero under a debugger; '
                'bypass: patch PEB.NtGlobalFlag to 0 and zero HeapBase.ForceFlags; '
                'PBA Ch.3: PEB fields are populated by ntdll before entry point execution'
            ),
            'host': host,
            'port': port,
        })

    # --- DIRECT_PEB_ACCESS: Inline PEB walk via FS:[0x30] or GS:[0x60] ---
    # Direct segment-register access bypasses hookable API wrappers:
    #   32-bit: FS -> TEB; PEB at TEB+0x30 -> FS:[0x30]
    #     bytes: 64 A1 30 00 00 00 = MOV EAX, FS:[30h]
    #            64 8B 40 30       = MOV EAX, FS:[EAX+30h]
    #   64-bit: GS -> TEB; PEB at TEB+0x60 -> GS:[0x60]
    #     bytes: 65 48 8B 04 25 60 00 00 00 = MOV RAX, GS:[60h]
    peb_32  = b'\x64\x8b\x40\x30' in data
    peb_64  = b'\x65\x48\x8b\x04\x25\x60\x00\x00\x00' in data
    peb_alt = b'\x64\xa1\x30\x00\x00\x00' in data
    if peb_32 or peb_64 or peb_alt:
        variants = []
        if peb_32:
            variants.append('FS:[EAX+30h] (32-bit MOV EAX, 64 8B 40 30)')
        if peb_64:
            variants.append('GS:[60h] (64-bit MOV RAX, 65 48 8B 04 25 60 00 00 00)')
        if peb_alt:
            variants.append('FS:[30h] (32-bit MOV EAX direct, 64 A1 30 00 00 00)')
        findings.append({
            'severity': 'CRITICAL',
            'title':    'DIRECT_PEB_ACCESS',
            'detail':   (
                f'Inline PEB access via segment register detected: {", ".join(variants)}; '
                'direct segment-register access to PEB bypasses hookable API wrappers such '
                'as IsDebuggerPresent() (hooking at function boundary by AV/EDR) by reading '
                'PEB fields directly using the TEB base in FS/GS; '
                '32-bit: FS points to TEB; PEB pointer at TEB+0x30; '
                '64-bit: GS points to TEB; PEB pointer at TEB+0x60; '
                'once PEB base is in a register, malware walks InLoadOrderModuleList to '
                'resolve kernel32/ntdll without calling LoadLibrary (PEB-walk shellcode); '
                'also used to read BeingDebugged (PEB+0x02), NtGlobalFlag (PEB+0x68 / 0xBC), '
                'and ProcessHeap (PEB+0x18 / 0x30) for anti-debug; '
                'PBA Ch.3: PEB structure is populated by ntdll LdrpInitializeProcess during '
                'the PE loading sequence before AddressOfEntryPoint executes'
            ),
            'host': host,
            'port': port,
        })

    # --- LOADER_LOCK_MANIPULATION: LdrLockLoaderLock / LdrpLoaderLock references ---
    # The loader lock serializes DLL_PROCESS_ATTACH notifications and InLoadOrderModuleList
    # modifications; malware acquiring it can prevent AV/EDR DLLs from loading during injection.
    has_lock = (b'LdrLockLoaderLock' in data or
                b'_LdrpLoaderLock' in data or
                b'LdrpLoaderLock' in data or
                b'LdrUnlockLoaderLock' in data)
    if has_lock:
        findings.append({
            'severity': 'HIGH',
            'title':    'LOADER_LOCK_MANIPULATION',
            'detail':   (
                'LdrLockLoaderLock / LdrpLoaderLock reference detected: '
                'the Windows loader lock (ntdll!LdrpLoaderLock) is a critical section that '
                'serializes DLL_PROCESS_ATTACH/DETACH notifications and InLoadOrderModuleList '
                'modifications; malware acquires this lock to: (1) prevent AV/EDR DLLs from '
                'loading during injection windows, (2) safely modify the PEB module list, '
                '(3) detect debugging via lock contention timing patterns; '
                'DllMain reentrancy attacks call LoadLibrary from DLL_PROCESS_ATTACH while '
                'holding the loader lock, causing deadlocks; '
                'PBA Ch.3: the PE loader (ntdll LdrpInitializeProcess) uses this lock when '
                'walking InLoadOrderModuleList to resolve imports at load time -- the same '
                'structures malware traverses for PEB-walk API resolution'
            ),
            'host': host,
            'port': port,
        })

    # --- PEB_MODULE_UNLINK: RemoveEntryList + InLoadOrderLinks module hiding ---
    # Malware unlinks its LDR_DATA_TABLE_ENTRY from all three PEB module lists
    # (InLoadOrderModuleList, InMemoryOrderModuleList, InInitializationOrderModuleList)
    # to hide the loaded module from EnumProcessModules and forensic tools.
    has_remove     = b'RemoveEntryList' in data
    has_load_order = (b'InLoadOrderLinks' in data or
                      b'InLoadOrderModuleList' in data or
                      b'InMemoryOrderLinks' in data)
    if has_remove and has_load_order:
        findings.append({
            'severity': 'CRITICAL',
            'title':    'PEB_MODULE_UNLINK',
            'detail':   (
                'RemoveEntryList + InLoadOrderLinks/InLoadOrderModuleList detected: '
                'PEB module list unlinking: after a DLL is loaded (via LoadLibrary or '
                'manual mapping), its LDR_DATA_TABLE_ENTRY is present in three doubly-linked '
                'lists in PEB.Ldr: InLoadOrderModuleList, InMemoryOrderModuleList, '
                'InInitializationOrderModuleList; '
                'RemoveEntryList on each Flink/Blink removes the entry, making the module '
                'invisible to EnumProcessModules, Process Hacker, and Volatility ldrmodules '
                '(which enumerates these same PEB lists); '
                'detection: compare VAD-mapped executable pages to PEB module list -- '
                'hidden DLLs have VAD entries without LDR entries; '
                'Volatility: "dlllist" exposes gaps; "malfind" finds executable VAD regions '
                'without backing file objects; '
                'PBA Ch.3: InLoadOrderModuleList is populated by the Windows loader during '
                'import resolution -- the same structure used for lazy-binding IAT patching'
            ),
            'host': host,
            'port': port,
        })

    # --- PPID_SPOOFING_TECHNIQUE: UpdateProcThreadAttribute parent process override ---
    # PPID spoofing via PROC_THREAD_ATTRIBUTE_PARENT_PROCESS creates a child process with
    # a forged parent PID so process-tree telemetry attributes the child to a legitimate
    # process (e.g., explorer.exe), bypassing parent-child correlation in EDRs.
    has_upta = b'UpdateProcThreadAttribute' in data
    has_ppid = (b'PROC_THREAD_ATTRIBUTE_PARENT_PROCESS' in data or
                b'ProcThreadAttributeParentProcess' in data)
    if has_upta or has_ppid:
        findings.append({
            'severity': 'HIGH',
            'title':    'PPID_SPOOFING_TECHNIQUE',
            'detail':   (
                'UpdateProcThreadAttribute / PROC_THREAD_ATTRIBUTE_PARENT_PROCESS detected: '
                'PPID spoofing: PROC_THREAD_ATTRIBUTE_PARENT_PROCESS passed to '
                'UpdateProcThreadAttribute before CreateProcess overrides the child\'s recorded '
                'parent PID in the kernel EPROCESS structure; '
                'supplying a handle to a different process (e.g., explorer.exe) as the parent '
                'handle makes the child\'s process-tree telemetry reflect the spoofed parent; '
                'bypasses EDR behavioral rules that flag "cmd.exe spawned by Word.exe" since '
                'the recorded parent is now explorer.exe; '
                'detection: correlate ETW process-creation events with CreateProcess caller '
                'vs. recorded parent; Sysmon EventID 1 parent image field shows spoofed parent; '
                'PBA Ch.3: the PE loading process records parent relationship in PEB fields '
                'initialized by ntdll before entry point receives control'
            ),
            'host': host,
            'port': port,
        })

    # --- TEB_DIRECT_ACCESS: Thread Environment Block inline access via FS:[0x18] ---
    # FS:[0x18] (32-bit) reads the TEB self-pointer; used as entry point for inline
    # PEB/TEB field access without calling hookable API wrappers; NtCurrentTeb() is an
    # NTDLL intrinsic that compiles to the same FS/GS read.
    has_teb_fs = (
        b'\x64\xa1\x18\x00\x00\x00' in data or      # MOV EAX, FS:[18h]
        b'\x64\x8b\x0d\x18\x00\x00\x00' in data or  # MOV ECX, FS:[18h]
        b'\x64\x8b\x40\x18' in data                  # MOV EAX, FS:[EAX+18h]
    )
    has_ntcurteb = b'NtCurrentTeb' in data
    if has_teb_fs or has_ntcurteb:
        findings.append({
            'severity': 'MEDIUM',
            'title':    'TEB_DIRECT_ACCESS',
            'detail':   (
                'Direct TEB access via FS:[0x18] or NtCurrentTeb() detected: '
                'FS:[0x18] (32-bit) reads the TEB self-pointer -- a pointer to the start of '
                'the Thread Environment Block for the current thread; '
                'used as entry point for inline PEB/TEB field access without calling hookable '
                'Windows API functions: TEB+0x30 = PEB pointer, TEB+0x24 = ThreadId, '
                'TEB+0x34 = LastErrorValue; '
                'NtCurrentTeb() is an NTDLL intrinsic that compiles to the same FS/GS read; '
                'this pattern precedes PEB walks, anti-debug checks, and thread-ID enumeration '
                'in shellcode and position-independent code that resolves APIs without an IAT; '
                'PBA Ch.3: TEB/PEB structures are populated by ntdll LdrpInitializeProcess '
                'during the PE loading sequence before entry point execution'
            ),
            'host': host,
            'port': port,
        })

    return findings


# ---------------------------------------------------------------------------
# Linux /proc memory forensic artifact detection
# Ref: Art of Memory Forensics Ch.19 (Linux Memory Acquisition), Ch.21
# (Processes and Process Memory), Ch.23 (Kernel Memory Artifacts)
# ---------------------------------------------------------------------------

def detect_linux_memory_artifacts() -> list:
    """
    Analyze /proc filesystem for memory-based forensic indicators.
    Grounded in Art of Memory Forensics Ch.19-21: Linux memory acquisition,
    process structures (task_struct/vm_area_struct), and kernel artifacts
    (/proc/kcore, /dev/mem, /proc/kmem, memfd_create fileless execution).
    No args; scans the live /proc filesystem.
    Returns List[dict] with severity/title/detail/host/port.
    """
    import errno as _errno
    import base64 as _b64

    findings = []
    host = ''
    port = 0

    # /proc/kcore: exposes full kernel virtual address space as ELF core image
    kcore = '/proc/kcore'
    if os.path.exists(kcore):
        try:
            sz = os.path.getsize(kcore)
        except OSError:
            sz = 0
        findings.append({
            'severity': 'HIGH',
            'title': 'KERNEL_CORE_ACCESSIBLE',
            'detail': (
                f'/proc/kcore present (size {sz} bytes): exposes the full kernel virtual '
                'address space as an ELF core image; readable by root or CAP_SYS_RAWIO; '
                'memory forensics acquisition tool (e.g. LiME) can harvest RAM through '
                'this interface without loading a kernel module; '
                'AMF Ch.19: /proc/kcore is one of three legacy memory acquisition '
                'interfaces (kcore, /dev/mem, /proc/kmem) now restricted in hardened '
                'kernels but still present as a dump surface when accessible; '
                'presence confirms the kernel was not built with STRICT_DEVMEM restrictions'
            ),
            'host': host,
            'port': port,
        })

    # /proc/kmem writable: direct kernel virtual memory write surface
    kmem = '/proc/kmem'
    if os.path.exists(kmem):
        try:
            mode = os.stat(kmem).st_mode
            is_writable = bool(mode & 0o222)
        except OSError:
            is_writable = False
        sev = 'CRITICAL' if is_writable else 'HIGH'
        findings.append({
            'severity': sev,
            'title': 'KERNEL_MEM_WRITABLE',
            'detail': (
                f'/proc/kmem present (writable={is_writable}): provides a character-device '
                'interface to kernel virtual memory; writes at an offset corresponding to '
                'a kernel function or global variable can overwrite kernel code/data '
                'structures without loading a signed kernel module; '
                'rootkits use this to patch the system call table, bypassing '
                'module-signing enforcement (Secure Boot + GRUB lockdown); '
                'AMF Ch.23: kernel artifacts accessible via /proc/kmem include '
                'task_struct chains, module list, and call tables; presence on a '
                'hardened host indicates a misconfigured or deliberately re-enabled '
                'kernel memory interface'
            ),
            'host': host,
            'port': port,
        })

    # /proc/sysrq-trigger writable: kernel crash / reboot on demand
    sysrq = '/proc/sysrq-trigger'
    if os.path.exists(sysrq):
        try:
            mode = os.stat(sysrq).st_mode
            writable = bool(mode & 0o222)
        except OSError:
            writable = False
        if writable:
            findings.append({
                'severity': 'HIGH',
                'title': 'SYSRQ_TRIGGER_WRITABLE',
                'detail': (
                    '/proc/sysrq-trigger is writable by non-root: a single-byte write '
                    '("c") triggers immediate kernel panic/crash dump; "b" = instant '
                    'reboot without sync; "s" = emergency sync; '
                    'attacker with filesystem write access can crash the kernel to '
                    'trigger a kdump that exposes full memory contents on reboot, '
                    'or force a hard reboot to bypass disk-encryption unlock prompts; '
                    'AMF Ch.23: kernel debug interfaces in /proc expose physical memory '
                    'maps and live kernel state; sysrq-trigger is a DoS and crash-dump '
                    'facilitation surface when accessible to non-privileged writers'
                ),
                'host': host,
                'port': port,
            })

    # Enumerate live PIDs from /proc
    try:
        pids = [p for p in os.listdir('/proc') if p.isdigit()]
    except OSError:
        pids = []

    # Anonymous RWX mmaps: shellcode injection staging area
    for pid in pids:
        maps_path = f'/proc/{pid}/maps'
        try:
            with open(maps_path, 'r', errors='replace') as fh:
                for line in fh:
                    parts = line.split()
                    if len(parts) < 5:
                        continue
                    perms = parts[1] if len(parts) > 1 else ''
                    if 'rwx' not in perms:
                        continue
                    inode = parts[4] if len(parts) > 4 else '0'
                    pathname = parts[5] if len(parts) > 5 else ''
                    is_anon = (inode == '0' and pathname == '')
                    is_anon_labeled = '[anon' in pathname
                    if is_anon or is_anon_labeled:
                        findings.append({
                            'severity': 'CRITICAL',
                            'title': 'RWX_ANON_MMAP_REGION',
                            'detail': (
                                f'PID {pid}: anonymous rwx memory region at {parts[0]}: '
                                'read-write-execute anonymous mapping with no backing file; '
                                'classic shellcode injection staging area -- attacker '
                                'mprotect()s a heap/stack region to rwx then copies '
                                'shellcode before jumping into it, or uses mmap(PROT_RWX) '
                                'directly; '
                                'AMF Ch.8: malfind detects injected code by scanning the '
                                'VAD tree for committed, executable, non-image-backed '
                                'regions containing MZ/PE or shellcode prologs; '
                                'AMF Ch.21: Linux /proc/*/maps exposes the same signal '
                                'via anonymous rwx vm_area_struct entries'
                            ),
                            'host': host,
                            'port': port,
                        })
        except (OSError, PermissionError):
            continue

    # Deleted executables still running: fileless post-cleanup indicator
    for pid in pids:
        exe_path = f'/proc/{pid}/exe'
        try:
            target = os.readlink(exe_path)
        except (OSError, PermissionError):
            continue
        if '(deleted)' in target:
            try:
                comm = open(f'/proc/{pid}/comm', 'r').read().strip()
            except OSError:
                comm = pid
            findings.append({
                'severity': 'HIGH',
                'title': 'DELETED_EXECUTABLE_RUNNING',
                'detail': (
                    f'PID {pid} ({comm}): executable deleted from disk while process '
                    f'runs -- exe link: {target}: '
                    'common indicator of fileless malware or attacker cleanup after '
                    'dropping a dropper/loader that erases itself post-exec; '
                    'the inode remains allocated as long as the process holds an open '
                    'file descriptor; full ELF image recoverable via /proc/<pid>/exe '
                    'or by reading /proc/<pid>/mem at the text segment; '
                    'AMF Ch.21: process memory internals -- the vm_area_struct for '
                    'the text segment retains a reference to the inode even after '
                    'filesystem unlink; AMF Ch.8: process dump recovers full PE/ELF '
                    'from memory even when on-disk file is gone'
                ),
                'host': host,
                'port': port,
            })

    # /dev/shm-backed executable regions: tmpfs payload staging
    for pid in pids:
        maps_path = f'/proc/{pid}/maps'
        try:
            with open(maps_path, 'r', errors='replace') as fh:
                for line in fh:
                    parts = line.split()
                    if len(parts) < 6:
                        continue
                    perms = parts[1]
                    pathname = parts[5]
                    if 'x' in perms and '/dev/shm' in pathname:
                        findings.append({
                            'severity': 'HIGH',
                            'title': 'SHARED_MEM_EXEC_REGION',
                            'detail': (
                                f'PID {pid}: executable mapping from /dev/shm '
                                f'({pathname}) at {parts[0]}: '
                                '/dev/shm is a tmpfs mount; shared-memory objects created '
                                'with shm_open()/mmap() are executable and persist across '
                                'process boundaries; attacker drops payload into /dev/shm, '
                                'mmap()s it executable, executes, then shm_unlink()s the '
                                'object -- no on-disk artifact remains; '
                                'AMF Ch.21: vm_area_struct entries with vma->vm_file '
                                'pointing to tmpfs inodes are the Linux equivalent of '
                                'Windows VAD nodes containing injected PE images without '
                                'a file-backed section object'
                            ),
                            'host': host,
                            'port': port,
                        })
        except (OSError, PermissionError):
            continue

    # Interpreter process with anonymous rwx region: JIT/FFI injection
    interpreters = {'python', 'python3', 'ruby', 'perl', 'php', 'node', 'java', 'bash', 'sh'}
    for pid in pids:
        try:
            comm = open(f'/proc/{pid}/comm', 'r').read().strip().lower()
        except OSError:
            continue
        if not any(interp in comm for interp in interpreters):
            continue
        maps_path = f'/proc/{pid}/maps'
        try:
            with open(maps_path, 'r', errors='replace') as fh:
                for line in fh:
                    parts = line.split()
                    if len(parts) < 5:
                        continue
                    perms = parts[1]
                    inode = parts[4]
                    pathname = parts[5] if len(parts) > 5 else ''
                    if 'rwx' in perms and inode == '0' and pathname == '':
                        findings.append({
                            'severity': 'CRITICAL',
                            'title': 'INTERPRETER_MEMORY_INJECTION',
                            'detail': (
                                f'PID {pid} ({comm}): interpreter has anonymous rwx '
                                f'region at {parts[0]}: '
                                'script interpreters (Python/Ruby/Node/Perl/Java) with '
                                'anonymous rwx pages indicate JIT trampoline injection '
                                'or shellcode staged via ctypes/cffi/Inline::C/FFI; '
                                'attacker loads interpreter, uses its FFI to mmap an '
                                'rwx region, copies shellcode, and executes within the '
                                'interpreter address space -- avoids exec() and presents '
                                'a legitimate-looking process name in ps/top; '
                                'AMF Ch.8: malfind targets exactly this pattern -- '
                                'executable non-image VAD nodes inside high-trust '
                                'interpreter contexts'
                            ),
                            'host': host,
                            'port': port,
                        })
                        break
        except (OSError, PermissionError):
            continue

    # Process with /proc/<pid> dir but no exe symlink: rootkit hiding indicator
    for pid in pids:
        exe_path = f'/proc/{pid}/exe'
        proc_dir = f'/proc/{pid}'
        if not os.path.isdir(proc_dir):
            continue
        try:
            os.readlink(exe_path)
        except OSError as e:
            if e.errno == _errno.ENOENT:
                findings.append({
                    'severity': 'HIGH',
                    'title': 'HIDDEN_PROCESS_NO_EXE',
                    'detail': (
                        f'PID {pid}: /proc/{pid} directory exists but '
                        f'/proc/{pid}/exe symlink is absent (ENOENT): '
                        'rootkits that hook the proc filesystem VFS operations '
                        '(proc_iops, proc_root_readdir) can hide the exe symlink '
                        'while leaving the process directory visible in listings; '
                        'AMF Ch.13: DKOM (direct kernel object manipulation) '
                        'rootkits unlink _EPROCESS / task_struct from '
                        'PsActiveProcessHead / init_task list but leave vm_area_struct '
                        'mappings in memory; cross-reference /proc enumeration '
                        'against a kernel task_struct walk to surface hidden pids; '
                        'AMF Ch.23: kernel module analysis reveals rootkit drivers '
                        'that install this hook'
                    ),
                    'host': host,
                    'port': port,
                })

    # Base64-padded strings in cmdline: obfuscated argument passing
    b64_pat = re.compile(rb'[A-Za-z0-9+/]{40,}={0,2}')
    for pid in pids:
        cmdline_path = f'/proc/{pid}/cmdline'
        try:
            raw = open(cmdline_path, 'rb').read()
        except (OSError, PermissionError):
            continue
        for m in b64_pat.finditer(raw):
            candidate = m.group(0)
            if len(candidate) % 4 != 0 and not candidate.endswith(b'='):
                continue
            try:
                decoded = _b64.b64decode(candidate)
            except Exception:
                continue
            if len(decoded) > 20:
                findings.append({
                    'severity': 'HIGH',
                    'title': 'BASE64_IN_PROCESS_ARGS',
                    'detail': (
                        f'PID {pid}: base64 string in cmdline '
                        f'({len(candidate)} chars -> {len(decoded)} decoded bytes): '
                        'base64-encoded command arguments are a common obfuscation '
                        'technique for passing shellcode, scripts, or C2 configuration '
                        'to a child process without leaving readable strings in '
                        '/proc/<pid>/cmdline; '
                        'on Linux: bash -c "$(echo <b64> | base64 -d)" or '
                        'python3 -c "import base64,exec; exec(base64.b64decode(...))"; '
                        'AMF Ch.8: command-line recovery from PEB/process memory is a '
                        'primary triage step for identifying obfuscated invocations; '
                        '/proc cmdline equivalent for Linux forensics'
                    ),
                    'host': host,
                    'port': port,
                })
                break

    # memfd_create: fileless ELF loaded into anonymous fd
    for pid in pids:
        fd_dir = f'/proc/{pid}/fd'
        try:
            fd_entries = os.listdir(fd_dir)
        except (OSError, PermissionError):
            continue
        for fd in fd_entries:
            fd_link = f'{fd_dir}/{fd}'
            try:
                target = os.readlink(fd_link)
            except (OSError, PermissionError):
                continue
            if target.startswith('/memfd:') or 'memfd:' in target:
                findings.append({
                    'severity': 'CRITICAL',
                    'title': 'MEMFD_EXECUTION',
                    'detail': (
                        f'PID {pid}: fd/{fd} -> {target}: '
                        'memfd_create() produces an anonymous file descriptor with no '
                        'filesystem path; attacker writes ELF payload into the memfd, '
                        'optionally seals it with F_SEAL_WRITE, then executes via '
                        'fexecve(memfd_fd, argv, envp) or /proc/self/fd/<n>; '
                        'the running binary never touches disk and leaves no inode '
                        'in any mounted filesystem -- invisible to find/ls/stat; '
                        'AMF Ch.19: LiME-style physical acquisition captures memfd '
                        'contents in RAM; runtime detection requires scanning '
                        '/proc/*/fd/ for memfd: symlink targets; '
                        'first documented as a primary vector in DDexec and '
                        'memfd-based fileless loader chains (2020+)'
                    ),
                    'host': host,
                    'port': port,
                })
                break  # one finding per pid is sufficient

    return findings


# ---------------------------------------------------------------------------
# Memory dump / process image forensic artifact analysis
# Ref: Art of Memory Forensics Ch.8 (Hunting Malware in Process Memory),
# Ch.13 (Kernel Forensics and Rootkits)
# ---------------------------------------------------------------------------

def detect_memory_forensic_artifacts(binary_data: bytes, host: str = '', port: int = 0) -> list:
    """
    Analyze binary data (memory dump or process image) for forensic artifacts.
    Grounded in Art of Memory Forensics Ch.8 (string extraction from heap/stack,
    VAD-based injected-PE detection, reflective DLL indicators) and Ch.13
    (kernel rootkit artifacts, embedded PE structures in driver memory).
    Signature: fn(binary_data: bytes, host='', port=0) -> list.
    Returns List[dict] with severity/title/detail/host/port.
    """
    import base64 as _b64

    findings = []
    data = binary_data

    # URL patterns in memory (IPv4-literal and hostname forms)
    url_pat = re.compile(
        rb'https?://'
        rb'(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)'
        rb'(?::\d{1,5})?(?:/[^\x00-\x1f\x7f ]{0,128})?'
        rb'|https?://[a-zA-Z0-9\-]{1,63}(?:\.[a-zA-Z0-9\-]{1,63}){1,5}'
        rb'(?::\d{1,5})?(?:/[^\x00-\x1f\x7f ]{0,128})?'
    )
    url_count = 0
    for m in url_pat.finditer(data):
        if url_count >= 5:
            break
        findings.append({
            'severity': 'HIGH',
            'title': 'URL_IN_MEMORY',
            'detail': (
                f'URL at offset 0x{m.start():x}: {m.group(0)[:120]!r}: '
                'embedded URLs in process memory or dump images indicate C2 '
                'beaconing targets, download-stager destinations, or exfiltration '
                'endpoints hardcoded in malware; '
                'AMF Ch.8: heap scanning for URL strings is a primary tactic in '
                'manual process memory analysis; Volatility yarascan and dumpfiles '
                'recover these from live or acquired memory images; '
                'strings that survive heap reuse are often configuration constants '
                'written before the first beacon and retained through the session'
            ),
            'host': host,
            'port': port,
        })
        url_count += 1

    # Windows registry paths in memory
    reg_pat = re.compile(
        rb'(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKLM|HKCU)'
        rb'[\\][^\x00-\x1f\x7f]{4,128}',
        re.IGNORECASE
    )
    seen_reg = set()
    for m in reg_pat.finditer(data):
        key = bytes(m.group(0)[:80])
        if key in seen_reg:
            continue
        seen_reg.add(key)
        findings.append({
            'severity': 'MEDIUM',
            'title': 'REGISTRY_PATH_IN_MEMORY',
            'detail': (
                f'Windows registry path at offset 0x{m.start():x}: {key!r}: '
                'registry paths embedded in memory indicate persistence keys '
                '(Run/RunOnce), COM object hijacking targets, or service config; '
                'AMF Ch.10: registry-in-memory analysis recovers hive data and '
                'cached key/value pairs from the registry cache manager (CM); '
                'Volatility printkey / hivedump surfaces these from live images; '
                'presence in a Linux dump or cross-platform memory image indicates '
                'Wine, a Windows VM guest, or emulation layer artifacts'
            ),
            'host': host,
            'port': port,
        })
        if len(seen_reg) >= 3:
            break

    # Malware mutex patterns: named mutex indicators
    mutex_patterns = [
        rb'Global\\[A-Za-z0-9_\-]{8,32}',
        rb'[{(][0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}[})]',
        rb'(?:mutex|Mutex|MUTEX)[A-Za-z0-9_\-]{4,32}',
        rb'(?:ZoneIdAttribute|NtControlPipe\d+|RasPbFile)',
        rb'(?:TermServReadyEvent|Global\\TermSrv)',
    ]
    for pat_bytes in mutex_patterns:
        try:
            pat = re.compile(pat_bytes)
        except re.error:
            continue
        m = pat.search(data)
        if m:
            findings.append({
                'severity': 'HIGH',
                'title': 'MALWARE_MUTEX_PATTERN',
                'detail': (
                    f'Mutex pattern at offset 0x{m.start():x}: {m.group(0)!r}: '
                    'mutex names are a primary malware family indicator; RATs and '
                    'botnets create named mutexes to prevent double-execution; '
                    'AMF Ch.8: Volatility mutantscan enumerates KMUTANT objects '
                    'in kernel pool memory; global mutexes persist in the kernel '
                    'object namespace and survive process termination until the '
                    'last handle is closed; GUID-format mutexes are common in '
                    'commodity malware loaders (Hancitor, Emotet, Trickbot)'
                ),
                'host': host,
                'port': port,
            })

    # Base64-encoded PE (MZ header after decode): reflective injection staging
    b64_long = re.compile(rb'[A-Za-z0-9+/]{200,}={0,2}')
    for m in b64_long.finditer(data):
        candidate = m.group(0)
        pad = (4 - len(candidate) % 4) % 4
        padded = candidate + b'=' * pad
        try:
            decoded = _b64.b64decode(padded)
        except Exception:
            continue
        if decoded[:2] == b'MZ':
            findings.append({
                'severity': 'CRITICAL',
                'title': 'BASE64_PE_IN_MEMORY',
                'detail': (
                    f'Base64-encoded PE (MZ) at offset 0x{m.start():x}, '
                    f'decoded size {len(decoded)} bytes: '
                    'base64-encoded PE payloads in memory indicate reflective '
                    'injection staging or script-based dropper loading; '
                    'attacker base64-encodes a DLL/EXE, stores it as a string '
                    'resource or in a C2 response, decodes in-process, and '
                    'reflectively maps it without touching disk; '
                    'AMF Ch.8: reflective DLL injection leaves the PE in a VAD '
                    'region without a corresponding file object; malfind detects '
                    'by checking for MZ at the VAD base without an associated '
                    'file-backed section; AMF Ch.13: kernel modules delivered '
                    'via base64-in-memory are also recoverable by this method'
                ),
                'host': host,
                'port': port,
            })
            break

    # XOR-decoded PE: single-byte XOR obfuscation of next-stage payload
    if len(data) >= 2:
        sample = data[:64]
        for xor_key in range(1, 256):
            xored_0 = sample[0] ^ xor_key
            xored_1 = sample[1] ^ xor_key
            if xored_0 == ord('M') and xored_1 == ord('Z'):
                findings.append({
                    'severity': 'CRITICAL',
                    'title': 'XOR_PE_IN_MEMORY',
                    'detail': (
                        f'Single-byte XOR key 0x{xor_key:02x} decodes start of data '
                        'to PE (MZ) header: '
                        'common in shellcode droppers and stager payloads that '
                        'XOR-encode the next-stage PE to evade static string '
                        'scanning; the XOR loop decodes at runtime into an rwx '
                        'allocation then jumps to the PE entry point or reflective '
                        'loader stub; '
                        'AMF Ch.8: after decoding, the PE leaves detectable '
                        'artifacts -- MZ at the VAD base, PE headers in pool '
                        'memory, export directory strings, and section names; '
                        'AMF Ch.13: kernel rootkits use the same XOR encoding '
                        'to deliver the driver payload from userspace'
                    ),
                    'host': host,
                    'port': port,
                })
                break

    # Shell execution strings in memory: command-interpreter invocation
    shell_patterns = [
        (rb'/bin/sh\s+-c\s+', 'POSIX /bin/sh -c execution'),
        (rb'/bin/bash\s+-c\s+', 'POSIX /bin/bash -c execution'),
        (rb'cmd\.exe\s+/[cCkK]\s+', 'Windows cmd.exe /c execution'),
        (rb'powershell(?:\.exe)?\s+-[Ee]nc(?:odedCommand)?\s+',
         'PowerShell EncodedCommand execution'),
        (rb'powershell(?:\.exe)?\s+-[Ww]indow[Ss]tyle\s+[Hh]idden',
         'PowerShell hidden-window execution'),
    ]
    for pat_bytes, desc in shell_patterns:
        try:
            pat = re.compile(pat_bytes, re.IGNORECASE)
        except re.error:
            continue
        m = pat.search(data)
        if m:
            findings.append({
                'severity': 'HIGH',
                'title': 'SHELL_EXEC_IN_MEMORY',
                'detail': (
                    f'Shell invocation at offset 0x{m.start():x} ({desc}): '
                    f'{m.group(0)!r}: '
                    'shell execution strings embedded in process memory or a dump '
                    'indicate a parent process spawning a command interpreter; '
                    'common in web shells, macro droppers, and C2 implants that '
                    'relay operator commands to the OS shell at runtime; '
                    'AMF Ch.8: process command-line analysis via PEB/cmdline and '
                    'environment-variable scanning are standard triage steps for '
                    'identifying shell-spawning malware in memory images'
                ),
                'host': host,
                'port': port,
            })

    # Credential patterns in memory: plaintext key/value pairs
    cred_pat = re.compile(
        rb'(?:password|passwd|apikey|api_key|token|secret|Authorization)'
        rb'\s*[=:]\s*([^\x00\x0a\x0d\x20]{4,64})',
        re.IGNORECASE
    )
    seen_creds = 0
    for m in cred_pat.finditer(data):
        if seen_creds >= 3:
            break
        findings.append({
            'severity': 'CRITICAL',
            'title': 'CREDENTIAL_PATTERN_IN_MEMORY',
            'detail': (
                f'Credential pattern at offset 0x{m.start():x}: '
                f'{m.group(0)[:60]!r}: '
                'cleartext credential strings in process memory are a primary '
                'target of memory-scraping malware and forensic investigators; '
                'languages without secure string handling leave passwords on the '
                'heap long after the application logic has finished with them; '
                'AMF Ch.8: heap dump + string analysis recovers credentials typed '
                'into a process; Volatility hashdump / lsadump / cachedump plugins '
                'use the same heap-resident string technique against LSASS; '
                'API keys and tokens recovered from heap are immediately actionable '
                'for lateral movement without cracking'
            ),
            'host': host,
            'port': port,
        })
        seen_creds += 1

    # C2 IP:port pairs in memory: beacon configuration indicators
    ip_port_pat = re.compile(
        rb'((?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
        rb'(?:25[0-5]|2[0-4]\d|[01]?\d\d?))'
        rb'[:\x00](\d{4,5})'
    )
    seen_c2 = set()
    for m in ip_port_pat.finditer(data):
        ip_b = m.group(1)
        port_b = m.group(2)
        try:
            port_n = int(port_b)
        except ValueError:
            continue
        if not (1024 <= port_n <= 65535):
            continue
        ip_str = ip_b.decode('ascii', errors='replace')
        if ip_str.startswith('127.') or ip_str.startswith('0.') or ip_str == '255.255.255.255':
            continue
        key = (ip_str, port_n)
        if key in seen_c2:
            continue
        seen_c2.add(key)
        findings.append({
            'severity': 'HIGH',
            'title': 'C2_IP_PORT_IN_MEMORY',
            'detail': (
                f'IP:port at offset 0x{m.start():x}: {ip_str}:{port_n}: '
                'hardcoded IP:port pairs in process memory are C2 beacon '
                'configuration indicators; malware families embed C2 addresses '
                'in plaintext or lightly obfuscated form in the .data section '
                'or on the heap after runtime XOR/RC4 decoding; '
                'AMF Ch.11: network artifact analysis (connections, sockets, '
                'netscan) in memory images identifies active C2 channels; '
                'offline strings scan recovers configured but not-yet-contacted '
                'C2 addresses that netscan cannot see'
            ),
            'host': host,
            'port': port,
        })
        if len(seen_c2) >= 5:
            break

    # YARA-style embedded PE: MZ + valid e_lfanew -> PE\x00\x00 signature
    mz_pat = re.compile(rb'MZ')
    for m in mz_pat.finditer(data):
        off = m.start()
        if off == 0:
            continue  # skip outer container header
        if off + 64 > len(data):
            continue
        try:
            e_lfanew = struct.unpack_from('<I', data, off + 60)[0]
        except struct.error:
            continue
        pe_off = off + e_lfanew
        if pe_off + 4 > len(data):
            continue
        if data[pe_off:pe_off + 4] == b'PE\x00\x00':
            findings.append({
                'severity': 'HIGH',
                'title': 'EMBEDDED_PE_HEADER',
                'detail': (
                    f'Valid embedded PE at offset 0x{off:x} '
                    f'(PE sig at 0x{pe_off:x}, e_lfanew=0x{e_lfanew:x}): '
                    'MZ + DOS header with e_lfanew pointing to a valid PE\\x00\\x00 '
                    'signature at the computed offset; indicates a PE file embedded '
                    'inside a memory dump, another PE, or a data stream; '
                    'patterns: reflective loader staging area (injected PE in a '
                    'carved allocation), process hollowing second-stage, packed '
                    'inner payload awaiting decompression; '
                    'AMF Ch.13: kernel module analysis uses the same PE structure '
                    'walk to enumerate loaded drivers from PsLoadedModuleList; '
                    'AMF Ch.8: malfind identifies PE artifacts in VAD regions '
                    'using the MZ/PE header as the primary locator, then disassembles '
                    'entry point to confirm executable code'
                ),
                'host': host,
                'port': port,
            })
            break  # one embedded PE finding per image is the signal

    return findings

