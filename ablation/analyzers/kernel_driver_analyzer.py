#!/usr/bin/env python3
"""
Windows Kernel Driver Analyzer.

Sources: Windows Internals Part 1 & 2 (Yosifovich/Russinovich), Rootkits:
Subverting the Windows Kernel (Hoglund/Butler), Practical Reverse Engineering
(Dang/Gazet/Bachaalany), The Art of Software Security Assessment (Dowd et al.).

Extends PEParser with kernel-mode RE:
- WDM vs KMDF vs minifilter classification
- DriverEntry + MajorFunction dispatch table recovery
- IOCTL code extraction and decoding
- Kernel API surface audit (phys-mem, pool, probes, DKOM, callbacks)
- PDB path extraction (RSDS debug directory)
- Authenticode signature presence check
- Pool operation / tag extraction
- Dangerous byte-pattern scan (MSR access, CR4/CR0 manipulation, HLT)

Usage:
    from ablation.analyzers.kernel_driver_analyzer import KernelDriverAnalyzer
    kda = KernelDriverAnalyzer.from_path('/path/to/driver.sys')
    report = kda.analyze()
    print(report.fmt())

    # IOCTL code decoder standalone:
    from ablation.analyzers.kernel_driver_analyzer import decode_ioctl_code
    ic = decode_ioctl_code(0x222003, site_va=0)
    print(ic.fmt())
"""

import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    import capstone
    import capstone.x86
    _HAS_CAPSTONE = True
except ImportError:
    _HAS_CAPSTONE = False

from ablation.core.pe_parser import PEParser


# ---------------------------------------------------------------------------
# IOCTL code
# ---------------------------------------------------------------------------

@dataclass
class IoctlCode:
    """
    Decoded Windows IOCTL code (CTL_CODE macro output).

    Layout (32-bit value):
      [31:16] DeviceType   -- 0x0001..0x7FFF system, 0x8000..0xFFFF user-defined
      [15:14] Access       -- FILE_ANY_ACCESS=0, FILE_READ_ACCESS=1,
                              FILE_WRITE_ACCESS=2, FILE_READ+WRITE=3
      [13:2]  Function     -- 0x000..0x7FF system, 0x800..0xFFF user-defined
      [1:0]   Method       -- METHOD_BUFFERED=0, METHOD_IN_DIRECT=1,
                              METHOD_OUT_DIRECT=2, METHOD_NEITHER=3

    METHOD_NEITHER is the most dangerous: no buffer copy, raw user pointer
    passed directly into the driver dispatch handler.
    """
    raw: int
    device_type: int
    function: int
    method: int
    access: int
    site_va: int

    _METHOD_NAMES = {
        0: 'METHOD_BUFFERED',
        1: 'METHOD_IN_DIRECT',
        2: 'METHOD_OUT_DIRECT',
        3: 'METHOD_NEITHER',    # raw user pointer -- highest risk
    }
    _ACCESS_NAMES = {
        0: 'FILE_ANY_ACCESS',
        1: 'FILE_READ_ACCESS',
        2: 'FILE_WRITE_ACCESS',
        3: 'FILE_READ+WRITE',
    }

    def method_name(self) -> str:
        return self._METHOD_NAMES.get(self.method, f'unknown({self.method})')

    def access_name(self) -> str:
        return self._ACCESS_NAMES.get(self.access, f'unknown({self.access})')

    def is_neither(self) -> bool:
        """METHOD_NEITHER handlers receive raw user-mode pointers."""
        return self.method == 3

    def is_user_defined(self) -> bool:
        """Function >= 0x800 or DeviceType >= 0x8000 indicates user-defined."""
        return self.function >= 0x800 or self.device_type >= 0x8000

    def fmt(self) -> str:
        risk = ' *** NEITHER (raw user ptr)' if self.is_neither() else ''
        ud   = ' [user-defined]' if self.is_user_defined() else ''
        return (
            f"0x{self.raw:08x}  DevType=0x{self.device_type:04x}{ud}  "
            f"Func=0x{self.function:03x}  {self.method_name():<22}  "
            f"{self.access_name()}{risk}"
        )


def decode_ioctl_code(value: int, site_va: int = 0) -> Optional['IoctlCode']:
    """
    Decode a 32-bit value as a Windows IOCTL CTL_CODE. Returns None if the
    value does not pass heuristic plausibility checks.
    """
    value = value & 0xFFFFFFFF
    device_type = (value >> 16) & 0xFFFF
    access      = (value >> 14) & 0x3
    function    = (value >>  2) & 0xFFF
    method      = value & 0x3

    if device_type == 0:
        return None
    # Reject suspiciously high or obviously-data values
    if value in (0xFFFFFFFF, 0x80000000, 0x00000000):
        return None
    # Common false-positive: values < 0x10000 are just 16-bit quantities
    if value < 0x10000:
        return None

    return IoctlCode(
        raw=value,
        device_type=device_type,
        function=function,
        method=method,
        access=access,
        site_va=site_va,
    )


# ---------------------------------------------------------------------------
# Kernel API finding
# ---------------------------------------------------------------------------

@dataclass
class KernelApiFinding:
    api: str
    dll: str
    severity: str
    category: str

    def fmt(self) -> str:
        return (
            f"[{self.severity:<8}] {self.api:<45} "
            f"({self.category})  from {self.dll}"
        )


# ---------------------------------------------------------------------------
# Callback registration
# ---------------------------------------------------------------------------

@dataclass
class CallbackRegistration:
    api: str
    severity: str
    description: str
    risk_class: str   # 'edr_like', 'rootkit_risk', 'info'

    def fmt(self) -> str:
        return (
            f"[{self.severity:<8}] {self.api:<45} "
            f"{self.description}  [{self.risk_class}]"
        )


# ---------------------------------------------------------------------------
# Pool operation
# ---------------------------------------------------------------------------

@dataclass
class PoolOperation:
    api: str
    tag: Optional[str]   # 4-char ASCII pool tag if extractable
    file_offset: int
    notes: str

    def fmt(self) -> str:
        tag_str = f"tag={self.tag!r}" if self.tag else "tag=?"
        return f"0x{self.file_offset:08x}  {self.api:<35} {tag_str:<14}  {self.notes}"


# ---------------------------------------------------------------------------
# Major function (IRP dispatch slot)
# ---------------------------------------------------------------------------

@dataclass
class MajorFunction:
    index: int
    handler_rva: int    # 0 = detected via slot write, VA not tracked

    _IRP_NAMES = {
        0x00: 'IRP_MJ_CREATE',
        0x01: 'IRP_MJ_CREATE_NAMED_PIPE',
        0x02: 'IRP_MJ_CLOSE',
        0x03: 'IRP_MJ_READ',
        0x04: 'IRP_MJ_WRITE',
        0x05: 'IRP_MJ_QUERY_INFORMATION',
        0x06: 'IRP_MJ_SET_INFORMATION',
        0x07: 'IRP_MJ_QUERY_EA',
        0x08: 'IRP_MJ_SET_EA',
        0x09: 'IRP_MJ_FLUSH_BUFFERS',
        0x0a: 'IRP_MJ_QUERY_VOLUME_INFORMATION',
        0x0b: 'IRP_MJ_SET_VOLUME_INFORMATION',
        0x0c: 'IRP_MJ_DIRECTORY_CONTROL',
        0x0d: 'IRP_MJ_FILE_SYSTEM_CONTROL',
        0x0e: 'IRP_MJ_DEVICE_CONTROL',       # primary IOCTL attack surface
        0x0f: 'IRP_MJ_INTERNAL_DEVICE_CONTROL',
        0x10: 'IRP_MJ_SHUTDOWN',
        0x11: 'IRP_MJ_LOCK_CONTROL',
        0x12: 'IRP_MJ_CLEANUP',
        0x13: 'IRP_MJ_CREATE_MAILSLOT',
        0x14: 'IRP_MJ_QUERY_SECURITY',
        0x15: 'IRP_MJ_SET_SECURITY',
        0x16: 'IRP_MJ_POWER',
        0x17: 'IRP_MJ_SYSTEM_CONTROL',
        0x18: 'IRP_MJ_DEVICE_CHANGE',
        0x19: 'IRP_MJ_QUERY_QUOTA',
        0x1a: 'IRP_MJ_SET_QUOTA',
        0x1b: 'IRP_MJ_PNP',
    }

    def irp_name(self) -> str:
        return self._IRP_NAMES.get(self.index, f'IRP_MJ_UNKNOWN_0x{self.index:02x}')

    def fmt(self) -> str:
        rva_str = f"handler_rva=0x{self.handler_rva:08x}" if self.handler_rva else "handler_rva=detected"
        return f"[{self.index:#04x}] {self.irp_name():<35} {rva_str}"


# ---------------------------------------------------------------------------
# Dangerous pattern
# ---------------------------------------------------------------------------

@dataclass
class DangerousPattern:
    pattern: str
    offset: int
    description: str
    severity: str

    def fmt(self) -> str:
        return (
            f"[{self.severity:<8}] {self.pattern:<35} "
            f"@0x{self.offset:08x}  {self.description}"
        )


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def _subsystem_name(n: int) -> str:
    return {
        1:  'IMAGE_SUBSYSTEM_NATIVE',
        2:  'IMAGE_SUBSYSTEM_WINDOWS_GUI',
        3:  'IMAGE_SUBSYSTEM_WINDOWS_CUI',
        11: 'IMAGE_SUBSYSTEM_NATIVE_WINDOWS',  # ELAM / secure drivers
    }.get(n, f'unknown({n})')


@dataclass
class KernelDriverReport:
    path: str
    driver_type: str        # 'WDM', 'KMDF', 'minifilter', 'unknown'
    subsystem: int
    entry_point_rva: int
    image_base: int
    pdb_path: Optional[str]
    is_signed: bool
    major_functions: list = field(default_factory=list)
    ioctl_codes: list = field(default_factory=list)
    kernel_api_findings: list = field(default_factory=list)
    callback_registrations: list = field(default_factory=list)
    pool_operations: list = field(default_factory=list)
    dangerous_patterns: list = field(default_factory=list)
    error: Optional[str] = None

    def fmt(self) -> str:
        lines = ['=' * 72]
        lines.append(f"KERNEL DRIVER ANALYSIS: {Path(self.path).name}")
        lines.append('=' * 72)
        lines.append(f"Type:        {self.driver_type}")
        lines.append(f"Subsystem:   {self.subsystem} ({_subsystem_name(self.subsystem)})")
        lines.append(f"EP RVA:      0x{self.entry_point_rva:08x}  "
                     f"ImageBase: 0x{self.image_base:016x}")
        lines.append(f"PDB:         {self.pdb_path or '(not found)'}")
        lines.append(f"Signed:      {'YES' if self.is_signed else 'NO -- unsigned or stripped'}")

        if self.error:
            lines.append(f"\nERROR: {self.error}")
            return '\n'.join(lines)

        if self.major_functions:
            lines.append(f"\nMajorFunction handlers ({len(self.major_functions)}):")
            for mf in sorted(self.major_functions, key=lambda x: x.index):
                lines.append(f"  {mf.fmt()}")

        if self.ioctl_codes:
            neither = [ic for ic in self.ioctl_codes if ic.is_neither()]
            lines.append(
                f"\nIOCTL codes ({len(self.ioctl_codes)}, "
                f"{len(neither)} METHOD_NEITHER):"
            )
            for ic in sorted(self.ioctl_codes, key=lambda x: x.raw):
                lines.append(f"  {ic.fmt()}")

        if self.kernel_api_findings:
            crit = sum(1 for f in self.kernel_api_findings if f.severity == 'CRITICAL')
            high = sum(1 for f in self.kernel_api_findings if f.severity == 'HIGH')
            med  = sum(1 for f in self.kernel_api_findings if f.severity == 'MEDIUM')
            lines.append(
                f"\nKernel API surface ({len(self.kernel_api_findings)}: "
                f"{crit} CRIT / {high} HIGH / {med} MED):"
            )
            for f in self.kernel_api_findings:
                lines.append(f"  {f.fmt()}")

        if self.callback_registrations:
            lines.append(f"\nCallback registrations ({len(self.callback_registrations)}):")
            for cb in self.callback_registrations:
                lines.append(f"  {cb.fmt()}")

        if self.pool_operations:
            lines.append(f"\nPool operations ({len(self.pool_operations)}):")
            for po in self.pool_operations:
                lines.append(f"  {po.fmt()}")

        if self.dangerous_patterns:
            lines.append(f"\nDangerous patterns ({len(self.dangerous_patterns)}):")
            for dp in self.dangerous_patterns:
                lines.append(f"  {dp.fmt()}")

        return '\n'.join(lines)

    def summary(self) -> dict:
        return {
            'driver_type':      self.driver_type,
            'is_signed':        self.is_signed,
            'pdb_path':         self.pdb_path,
            'subsystem':        self.subsystem,
            'major_functions':  len(self.major_functions),
            'ioctl_codes':      len(self.ioctl_codes),
            'ioctl_neither':    sum(1 for ic in self.ioctl_codes if ic.is_neither()),
            'kernel_api_crit':  sum(1 for f in self.kernel_api_findings if f.severity == 'CRITICAL'),
            'kernel_api_high':  sum(1 for f in self.kernel_api_findings if f.severity == 'HIGH'),
            'callbacks':        len(self.callback_registrations),
            'pool_ops':         len(self.pool_operations),
            'dangerous':        len(self.dangerous_patterns),
        }


# ---------------------------------------------------------------------------
# Main analyzer
# ---------------------------------------------------------------------------

class KernelDriverAnalyzer:
    """
    Windows kernel driver static analyzer.

    Built on PEParser; does not require BinaryContext (which is ELF-centric).
    Uses capstone for disassembly when available; import-only analysis runs
    without it.

    Workflow integration with TaintTracker:
        Configure custom sinks for kernel buffer APIs:
        tt = TaintTracker(path, custom_sinks={
            'ExAllocatePoolWithTag': [1],   # NumberOfBytes = arg2 (rdx)
            'RtlCopyMemory':         [2],   # Length = arg3 (r8)
            'memcpy':                [2],
        })
        Then seed with arg indices from the IOCTL handler's IRP stack location
        read: Parameters.DeviceIoControl.InputBufferLength is at
        IO_STACK_LOCATION + 0x10 (varies by IRP_MJ type).
    """

    def __init__(self, data: bytes, path: str = '<unknown>'):
        self.data = data
        self.path = path
        self._pe = PEParser(data)
        self._cs: Optional[object] = None
        if _HAS_CAPSTONE:
            cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            cs.detail = True
            self._cs = cs

    @classmethod
    def from_path(cls, path: str) -> 'KernelDriverAnalyzer':
        with open(path, 'rb') as fh:
            data = fh.read()
        return cls(data, path)

    # -----------------------------------------------------------------------
    # Public entry point
    # -----------------------------------------------------------------------

    def analyze(self) -> KernelDriverReport:
        pe = self._pe
        if not pe.valid:
            return KernelDriverReport(
                path=self.path, driver_type='unknown', subsystem=0,
                entry_point_rva=0, image_base=0, pdb_path=None,
                is_signed=False, error='Not a valid PE file',
            )

        report = KernelDriverReport(
            path=self.path,
            driver_type=self._classify_driver(),
            subsystem=self._get_subsystem(),
            entry_point_rva=pe.entry_point_rva,
            image_base=pe.image_base,
            pdb_path=self._extract_pdb_path(),
            is_signed=self._check_signature(),
        )
        report.major_functions        = self._extract_major_functions()
        report.ioctl_codes            = self._extract_ioctl_codes()
        report.kernel_api_findings    = self._scan_kernel_apis()
        report.callback_registrations = self._scan_callbacks()
        report.pool_operations        = self._scan_pool_operations()
        report.dangerous_patterns     = self._scan_dangerous_patterns()
        return report

    # -----------------------------------------------------------------------
    # Driver classification
    # -----------------------------------------------------------------------

    def _classify_driver(self) -> str:
        """
        WDM: imports directly from ntoskrnl.exe / hal.dll, no WDF*
        KMDF: WdfDriverCreate present (wdf01000.sys)
        minifilter: FltRegisterFilter present (fltmgr.sys)
        """
        imports = self._pe.imports
        all_fns: set = set()
        for funcs in imports.values():
            all_fns.update(f.lower() for f in funcs)

        if 'fltregisterfilter' in all_fns or 'wdffiltercreate' in all_fns:
            return 'minifilter'
        if 'wdfdrivercreate' in all_fns or 'wdfdevicecreate' in all_fns:
            return 'KMDF'
        # WDM: any imports from ntoskrnl family
        kernel_dlls = {'ntoskrnl.exe', 'ntkrnlmp.exe', 'ntkrpamp.exe', 'ntkrnlpa.exe'}
        if any(dll in kernel_dlls for dll in imports):
            return 'WDM'
        return 'unknown'

    def _get_subsystem(self) -> int:
        """
        Read IMAGE_OPTIONAL_HEADER.Subsystem.
        Kernel drivers use IMAGE_SUBSYSTEM_NATIVE (1).
        ELAM (Early Launch Anti-Malware) drivers use type 1 with special cert policy.
        """
        pe = self._pe
        # Optional header starts at pe_offset + 4 (PE sig) + 20 (COFF header)
        oh_off = pe.pe_offset + 4 + 20
        # Subsystem field is at offset 68 within IMAGE_OPTIONAL_HEADER for both PE32 and PE32+
        if oh_off + 70 > len(self.data):
            return 0
        try:
            return struct.unpack_from('<H', self.data, oh_off + 68)[0]
        except struct.error:
            return 0

    # -----------------------------------------------------------------------
    # PDB path extraction (RSDS / NB10 debug directory)
    # -----------------------------------------------------------------------

    def _extract_pdb_path(self) -> Optional[str]:
        """
        Parse IMAGE_DIRECTORY_ENTRY_DEBUG (data directory index 6).
        CodeView RSDS record: 'RSDS' + 16-byte GUID + 4-byte age + NUL-terminated path.
        NB10 record (older PDB 2.0): 'NB10' + 4-byte offset + 4-byte sig + 4-byte age + path.

        The PDB path leaks the internal build tree (e.g.
        C:\\Users\\dev\\projects\\rootkit\\x64\\Release\\driver.pdb) which is
        useful for attribution and product identification.
        """
        pe = self._pe
        if len(pe._data_dirs) <= 6:
            return None
        debug_rva, debug_size = pe._data_dirs[6]
        if not debug_rva or not debug_size:
            return None
        off = pe._rva_to_offset(debug_rva)
        if off is None:
            return None

        num_entries = debug_size // 28
        for i in range(min(num_entries, 16)):
            entry_off = off + i * 28
            if entry_off + 28 > len(self.data):
                break
            try:
                # IMAGE_DEBUG_DIRECTORY:
                # Characteristics(4), TimeDateStamp(4), MajorVersion(2), MinorVersion(2),
                # Type(4), SizeOfData(4), AddressOfRawData(4), PointerToRawData(4)
                (_, _, _, _, debug_type, _, _, ptr_to_raw
                ) = struct.unpack_from('<IIHHIII', self.data, entry_off)
            except struct.error:
                break

            if debug_type != 2:   # IMAGE_DEBUG_TYPE_CODEVIEW
                continue
            if ptr_to_raw + 4 > len(self.data):
                continue

            sig = self.data[ptr_to_raw: ptr_to_raw + 4]
            if sig == b'RSDS':
                # 4 sig + 16 GUID + 4 age = 24 bytes before path
                path_start = ptr_to_raw + 24
            elif sig == b'NB10':
                # 4 sig + 4 offset + 4 sig + 4 age = 16 bytes before path
                path_start = ptr_to_raw + 16
            else:
                continue

            end = self.data.find(b'\x00', path_start)
            if end == -1 or end - path_start > 512:
                end = path_start + 512
            try:
                return self.data[path_start:end].decode('ascii', errors='replace').strip()
            except Exception:
                return None
        return None

    # -----------------------------------------------------------------------
    # Authenticode signature presence
    # -----------------------------------------------------------------------

    def _check_signature(self) -> bool:
        """
        Check IMAGE_DIRECTORY_ENTRY_SECURITY (data directory index 4).
        Unlike other entries this stores a FILE OFFSET, not an RVA.
        Presence means an Authenticode WIN_CERTIFICATE table exists.
        Kernel drivers on Win10+ require a valid WHQL, EV, or cross-cert
        signature; unsigned drivers require test-signing mode.
        """
        pe = self._pe
        if len(pe._data_dirs) <= 4:
            return False
        cert_offset, cert_size = pe._data_dirs[4]
        return cert_offset != 0 and cert_size != 0

    # -----------------------------------------------------------------------
    # MajorFunction table recovery via DriverEntry disassembly
    # -----------------------------------------------------------------------

    def _extract_major_functions(self) -> list:
        """
        Disassemble DriverEntry (PE entry point for WDM drivers) and recover
        IRP major function slot assignments.

        DRIVER_OBJECT layout (x64 Windows 10+):
          +0x00  Type                CSHORT
          +0x02  Size                CSHORT
          +0x08  DeviceObject        PDEVICE_OBJECT
          +0x10  Flags               ULONG
          +0x18  DriverStart         PVOID
          +0x20  DriverSize          ULONG
          +0x28  DriverSection       PVOID
          +0x30  DriverExtension     PDRIVER_EXTENSION
          +0x38  DriverName          UNICODE_STRING
          +0x48  HardwareDatabase    PUNICODE_STRING
          +0x50  FastIoDispatch      PFAST_IO_DISPATCH
          +0x58  DriverInit          PDRIVER_INITIALIZE
          +0x60  DriverStartIo       PDRIVER_STARTIO
          +0x68  DriverUnload        PDRIVER_UNLOAD
          +0x70  MajorFunction[28]   PDRIVER_DISPATCH  <- 28 slots x 8 bytes each

        So MajorFunction[n] = DriverObject + 0x70 + n*8.
        IRP_MJ_DEVICE_CONTROL (0x0E): DriverObject + 0x70 + 0x70 = DriverObject + 0xE0.

        Pattern: MOV [RCX+disp], reg  where disp in [0x70, 0x210)
        Some compilers alias DriverObject to RBX/RSI before the loop.
        """
        if not _HAS_CAPSTONE:
            return []

        pe = self._pe
        ep_off = pe._rva_to_offset(pe.entry_point_rva)
        if ep_off is None:
            return []

        ep_va   = pe.image_base + pe.entry_point_rva
        window  = min(8192, len(self.data) - ep_off)
        code    = self.data[ep_off: ep_off + window]

        MF_BASE  = 0x70
        MF_SLOTS = 28
        MF_END   = MF_BASE + MF_SLOTS * 8   # 0x210

        found: dict = {}
        for insn in self._cs.disasm(code, ep_va):
            if insn.mnemonic != 'mov':
                continue
            try:
                op0, op1 = insn.operands[0], insn.operands[1]
            except (IndexError, AttributeError):
                continue
            # MOV QWORD PTR [reg+disp], reg  -> writing a function pointer
            if op0.type != capstone.x86.X86_OP_MEM:
                continue
            disp = op0.mem.disp
            if MF_BASE <= disp < MF_END and (disp - MF_BASE) % 8 == 0:
                slot = (disp - MF_BASE) // 8
                if slot not in found:
                    # Try to capture the handler VA if the source is an immediate
                    handler_rva = 0
                    if op1.type == capstone.x86.X86_OP_IMM:
                        handler_va = op1.imm
                        if handler_va > pe.image_base:
                            handler_rva = handler_va - pe.image_base
                    found[slot] = MajorFunction(index=slot, handler_rva=handler_rva)

        return list(found.values())

    # -----------------------------------------------------------------------
    # IOCTL code extraction
    # -----------------------------------------------------------------------

    def _extract_ioctl_codes(self) -> list:
        """
        Scan executable sections for 32-bit immediate operands in CMP/MOV
        instructions that decode as plausible IOCTL CTL_CODE values.

        IOCTL dispatch handler structure (compiled from switch statement):
            IoControlCode = IoGetCurrentIrpStackLocation(Irp)
                            ->Parameters.DeviceIoControl.IoControlCode
            switch (IoControlCode) {
                case MY_IOCTL_1: ...  // becomes CMP reg, 0xNNNNNNNN
            }

        METHOD_NEITHER IOCTLs warrant immediate attention: the driver receives
        Type3InputBuffer (a raw user-mode pointer) with no kernel copy, making
        any dereference without ProbeForRead an arbitrary kernel read primitive.
        """
        if not _HAS_CAPSTONE:
            return []

        pe       = self._pe
        ioctls   = []
        seen: set = set()

        for section in pe.sections:
            if not section['executable']:
                continue
            raw_off = section['raw_offset']
            raw_sz  = section['raw_size']
            sec_va  = pe.image_base + section['vaddr']
            code    = self.data[raw_off: raw_off + raw_sz]

            for insn in self._cs.disasm(code, sec_va):
                if insn.mnemonic not in ('cmp', 'mov', 'sub', 'test'):
                    continue
                try:
                    ops = insn.operands
                except AttributeError:
                    continue
                for op in ops:
                    if op.type != capstone.x86.X86_OP_IMM:
                        continue
                    val = op.imm & 0xFFFFFFFF
                    if val in seen:
                        continue
                    ic = decode_ioctl_code(val, site_va=insn.address)
                    if ic is not None:
                        seen.add(val)
                        ioctls.append(ic)

        return sorted(ioctls, key=lambda x: x.raw)

    # -----------------------------------------------------------------------
    # Kernel API surface audit
    # -----------------------------------------------------------------------

    def _scan_kernel_apis(self) -> list:
        """
        Classify imported kernel APIs by vulnerability category.

        This is distinct from PEParser.scan_malware_apis() which covers
        userland injection/persistence. Kernel drivers import from ntoskrnl.exe,
        hal.dll, and various kernel support DLLs (fltmgr.sys, wdf01000.sys).

        Severity rationale:
        - CRITICAL: direct kernel arbitrary-read/write primitive, or enables
          bypassing security features (SMEP, WP, signing)
        - HIGH: required for common exploit primitives; misuse = ring-0 code exec
        - MEDIUM: attack surface, but requires chaining with another primitive
        """
        # (api_name -> (severity, category))
        # Kernel-mode only; userland equivalents handled by pe_parser.py
        KERNEL_APIS = {
            # --- Physical memory --- (arbitrary kernel r/w if phys addr is attacker-controlled)
            'MmMapIoSpace':                    ('CRITICAL', 'phys_mem'),
            'MmMapIoSpaceEx':                  ('CRITICAL', 'phys_mem'),
            'MmCopyMemory':                    ('CRITICAL', 'phys_mem'),
            'MmMapLockedPages':                ('CRITICAL', 'phys_mem'),
            'MmMapLockedPagesSpecifyCache':    ('CRITICAL', 'phys_mem'),
            'MmUnmapIoSpace':                  ('MEDIUM',   'phys_mem'),
            'MmGetPhysicalAddress':            ('HIGH',     'phys_mem'),
            'MmAllocateContiguousMemory':      ('HIGH',     'phys_mem'),
            'MmFreeContiguousMemory':          ('MEDIUM',   'phys_mem'),
            'MmProbeAndLockPages':             ('HIGH',     'phys_mem'),

            # --- User-mode buffer validation --- (absent = arbitrary kernel r/w)
            # ProbeForRead/Write validate that the pointer falls in user-mode
            # address space and the buffer is readable/writable. Absence of these
            # before a kernel copy from a user-supplied pointer = trivial kernel arb-r/w.
            'ProbeForRead':                    ('HIGH',  'userland_probe'),
            'ProbeForWrite':                   ('HIGH',  'userland_probe'),

            # --- Pool allocation --- (UAF and pool overflow attack surface)
            # ExAllocatePool (no tag) deprecated since Win10 2004; still accepted
            # ExAllocatePoolWithTag: (PoolType, NumberOfBytes, Tag)
            #   NumberOfBytes in RDX; integer overflow here -> undersized alloc
            'ExAllocatePoolWithTag':           ('HIGH',  'pool_alloc'),
            'ExAllocatePool2':                 ('HIGH',  'pool_alloc'),  # Win10 20H1+
            'ExAllocatePool3':                 ('HIGH',  'pool_alloc'),  # Win11+
            'ExAllocatePool':                  ('HIGH',  'pool_alloc'),  # deprecated
            'ExFreePoolWithTag':               ('MEDIUM','pool_alloc'),
            'ExFreePool':                      ('MEDIUM','pool_alloc'),  # deprecated
            'ExAllocatePoolWithQuotaTag':      ('HIGH',  'pool_alloc'),

            # --- DKOM (Direct Kernel Object Manipulation) ---
            # PsLookupProcessByProcessId returns PEPROCESS; attacker can then
            # modify ActiveProcessLinks to hide processes (EPROCESS list unlink)
            'PsLookupProcessByProcessId':      ('CRITICAL', 'dkom'),
            'PsLookupThreadByThreadId':        ('CRITICAL', 'dkom'),
            'PsGetCurrentProcess':             ('MEDIUM',   'dkom'),
            'PsGetCurrentProcessId':           ('MEDIUM',   'dkom'),
            'ObReferenceObjectByHandle':       ('HIGH',     'dkom'),
            'ObReferenceObjectByPointer':      ('HIGH',     'dkom'),
            'ObDereferenceObject':             ('MEDIUM',   'dkom'),
            'ObOpenObjectByPointer':           ('HIGH',     'dkom'),

            # --- Device I/O setup ---
            'IoCreateDevice':                  ('MEDIUM', 'device_io'),
            'IoDeleteDevice':                  ('MEDIUM', 'device_io'),
            'IoCreateSymbolicLink':            ('MEDIUM', 'device_io'),
            'IoDeleteSymbolicLink':            ('MEDIUM', 'device_io'),
            'IoGetCurrentIrpStackLocation':    ('MEDIUM', 'device_io'),
            'IoCompleteRequest':               ('MEDIUM', 'device_io'),
            'IoCreateDeviceSecure':            ('MEDIUM', 'device_io'),

            # --- MDL (Memory Descriptor List) ---
            # Misuse of MDLs enables mapping arbitrary kernel pages to user space
            'IoAllocateMdl':                   ('HIGH',     'mdl'),
            'MmBuildMdlForNonPagedPool':       ('HIGH',     'mdl'),
            'MmGetSystemAddressForMdlSafe':    ('HIGH',     'mdl'),
            'IoBuildPartialMdl':               ('HIGH',     'mdl'),
            'MmMapLockedPagesWithReservedMapping': ('CRITICAL', 'mdl'),

            # --- System information ---
            'ZwQuerySystemInformation':        ('HIGH',     'system_info'),
            'NtQuerySystemInformation':        ('HIGH',     'system_info'),
            'ZwSetSystemInformation':          ('CRITICAL', 'system_info'),  # can load driver

            # --- Privilege / token manipulation ---
            'SePrivilegeCheck':                ('HIGH',  'privilege'),
            'SeSinglePrivilegeCheck':          ('HIGH',  'privilege'),
            'SeAccessCheck':                   ('HIGH',  'privilege'),
            'SeTokenIsAdmin':                  ('HIGH',  'privilege'),

            # --- Driver loading from kernel ---
            'ZwLoadDriver':                    ('CRITICAL', 'driver_load'),
            'NtLoadDriver':                    ('CRITICAL', 'driver_load'),

            # --- SSDT hooking (rootkit indicator) ---
            # ntoskrnl exports KeServiceDescriptorTable; accessing it directly
            # is the prerequisite for SSDT hook installation
            'KeServiceDescriptorTable':        ('CRITICAL', 'ssdt_hook'),

            # --- Registry ---
            'ZwCreateKey':                     ('HIGH',   'registry'),
            'ZwSetValueKey':                   ('HIGH',   'registry'),
            'ZwOpenKey':                       ('MEDIUM', 'registry'),
            'ZwQueryValueKey':                 ('MEDIUM', 'registry'),
            'CmRegisterCallback':              ('HIGH',   'registry'),
            'CmRegisterCallbackEx':            ('HIGH',   'registry'),

            # --- Kernel memory copy ---
            # RtlCopyMemory without bounds check is a common overflow primitive
            'RtlCopyMemory':                   ('HIGH',   'mem_copy'),
            'RtlMoveMemory':                   ('HIGH',   'mem_copy'),
            'RtlZeroMemory':                   ('MEDIUM', 'mem_copy'),
            'memcpy':                          ('HIGH',   'mem_copy'),
            'memmove':                         ('HIGH',   'mem_copy'),
        }

        findings = []
        seen: set = set()
        for dll, funcs in self._pe.imports.items():
            for fn in funcs:
                if fn in KERNEL_APIS and fn not in seen:
                    seen.add(fn)
                    severity, category = KERNEL_APIS[fn]
                    findings.append(KernelApiFinding(
                        api=fn, dll=dll,
                        severity=severity, category=category,
                    ))

        order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        findings.sort(key=lambda x: order.get(x.severity, 9))
        return findings

    # -----------------------------------------------------------------------
    # Callback registration scan
    # -----------------------------------------------------------------------

    def _scan_callbacks(self) -> list:
        """
        Detect kernel notification callback registrations.

        These are used by both legitimate AV/EDR drivers and rootkits.
        The risk class distinguishes them:
        - 'edr_like': legitimate security product behavior pattern
        - 'rootkit_risk': misuse enables process/file hiding or code injection
        - 'info': general driver lifecycle notifications

        ObRegisterCallbacks is the most powerful: it can intercept and DENY
        handle operations on any kernel object (process, thread, desktop).
        Legitimate use requires PROCESS_VM_READ access check; rootkits suppress it.
        """
        CALLBACKS = {
            # Process / thread / image notifications
            'PsSetCreateProcessNotifyRoutine':
                ('HIGH',     'notified on every process create/exit', 'edr_like'),
            'PsSetCreateProcessNotifyRoutineEx':
                ('HIGH',     'notified on every process create/exit (Ex)', 'edr_like'),
            'PsSetCreateProcessNotifyRoutineEx2':
                ('HIGH',     'notified on every process create/exit (Ex2)', 'edr_like'),
            'PsSetCreateThreadNotifyRoutine':
                ('HIGH',     'notified on every thread create/exit', 'edr_like'),
            'PsSetCreateThreadNotifyRoutineEx':
                ('HIGH',     'notified on every thread create/exit (Ex)', 'edr_like'),
            'PsSetLoadImageNotifyRoutine':
                ('HIGH',     'notified on every DLL / PE load', 'edr_like'),
            'PsSetLoadImageNotifyRoutineEx':
                ('HIGH',     'notified on every DLL / PE load (Ex)', 'edr_like'),
            # Handle interception
            'ObRegisterCallbacks':
                ('CRITICAL', 'intercepts/denies handle ops on any kernel object', 'rootkit_risk'),
            'ObUnRegisterCallbacks':
                ('MEDIUM',   'removes handle operation callback', 'rootkit_risk'),
            # Registry interception
            'CmRegisterCallback':
                ('HIGH',     'intercepts all registry operations', 'rootkit_risk'),
            'CmRegisterCallbackEx':
                ('HIGH',     'intercepts all registry operations (Ex)', 'rootkit_risk'),
            'CmUnRegisterCallback':
                ('MEDIUM',   'removes registry callback', 'info'),
            # Image verification (used by WDAC/AppLocker; also abused to bypass)
            'SeRegisterImageVerificationCallback':
                ('CRITICAL', 'intercepts image verification (WDAC/AppLocker surface)', 'rootkit_risk'),
            # Minifilter (file I/O interception)
            'FltRegisterFilter':
                ('HIGH',     'intercepts all file I/O via minifilter', 'edr_like'),
            'FltUnregisterFilter':
                ('MEDIUM',   'unregisters minifilter', 'info'),
            'FltStartFiltering':
                ('MEDIUM',   'activates minifilter filtering', 'edr_like'),
            # Shutdown / bugcheck
            'IoRegisterShutdownNotification':
                ('MEDIUM',   'shutdown notification', 'info'),
            'KeRegisterBugCheckCallback':
                ('MEDIUM',   'bugcheck callback; can persist malicious state across crashes', 'rootkit_risk'),
            'KeRegisterBugCheckReasonCallback':
                ('MEDIUM',   'extended bugcheck callback', 'rootkit_risk'),
            # NMI
            'KeRegisterNmiCallback':
                ('HIGH',     'NMI handler; executes at highest interrupt priority', 'rootkit_risk'),
        }

        findings = []
        seen: set = set()
        all_imports: dict = {}
        for dll, funcs in self._pe.imports.items():
            for fn in funcs:
                all_imports[fn] = dll

        for fn, (severity, desc, risk_class) in CALLBACKS.items():
            if fn in all_imports and fn not in seen:
                seen.add(fn)
                findings.append(CallbackRegistration(
                    api=fn, severity=severity,
                    description=desc, risk_class=risk_class,
                ))
        return findings

    # -----------------------------------------------------------------------
    # Pool operation scan (pool tag extraction)
    # -----------------------------------------------------------------------

    def _scan_pool_operations(self) -> list:
        """
        Scan for ExAllocatePoolWithTag call sites and extract pool tags.

        x64 Windows calling convention for ExAllocatePoolWithTag:
          RCX = PoolType   (NonPagedPool=0, PagedPool=1, NonPagedPoolNx=512)
          RDX = NumberOfBytes  <- integer overflow here -> undersized allocation
          R8  = Tag           <- 4-byte ASCII pool tag (e.g. b'Devi')
          [RSP+0x20 shadow home]

        Encoding for MOV R8D, imm32 (sets tag in 32-bit form):
          41 B8 <tag_byte0> <tag_byte1> <tag_byte2> <tag_byte3>

        Encoding for MOV R8, imm64:
          49 B8 <tag_byte0..3> 00 00 00 00

        Pool tags are 4 ASCII chars, conventionally stored little-endian
        (b'kniL' displayed as 'Link'). printable chars only.
        """
        ops = []
        seen_off: set = set()

        for off in range(len(self.data) - 6):
            # MOV R8D, imm32  (41 B8 <4 bytes>)
            if self.data[off] == 0x41 and self.data[off + 1] == 0xB8:
                tag = self.data[off + 2: off + 6]
                if all(0x20 <= b < 0x7F for b in tag) and off not in seen_off:
                    seen_off.add(off)
                    ops.append(PoolOperation(
                        api='ExAllocatePoolWithTag (candidate)',
                        tag=tag.decode('ascii'),
                        file_offset=off,
                        notes='tag in R8D (41 B8)',
                    ))
            # MOV R8, imm64 with upper 32 bits zero  (49 B8 <4 bytes> 00 00 00 00)
            elif (off + 10 <= len(self.data)
                  and self.data[off] == 0x49 and self.data[off + 1] == 0xB8
                  and self.data[off + 6: off + 10] == b'\x00\x00\x00\x00'):
                tag = self.data[off + 2: off + 6]
                if all(0x20 <= b < 0x7F for b in tag) and off not in seen_off:
                    seen_off.add(off)
                    ops.append(PoolOperation(
                        api='ExAllocatePoolWithTag (candidate)',
                        tag=tag.decode('ascii'),
                        file_offset=off,
                        notes='tag in R8 (49 B8, upper zero)',
                    ))

        # Limit output; tag sites are plentiful in complex drivers
        return ops[:64]

    # -----------------------------------------------------------------------
    # Dangerous byte-pattern scan
    # -----------------------------------------------------------------------

    def _scan_dangerous_patterns(self) -> list:
        """
        Scan raw binary bytes for dangerous kernel instruction patterns.

        Sources: Practical Reverse Engineering (ch6 Windows kernel),
        Rootkits: Subverting the Windows Kernel (Hoglund/Butler ch3/ch4).
        """
        findings = []

        # RDMSR (0F 32): reads MSR indexed by ECX.
        # If ECX is attacker-controlled (e.g. from user IOCTL input without
        # bounds check), reading MSR_LSTAR (0xC0000082) reveals kernel base.
        for m in re.finditer(rb'\x0f\x32', self.data):
            findings.append(DangerousPattern(
                pattern='RDMSR',
                offset=m.start(),
                description='reads MSR[ECX]; if ECX is IOCTL-tainted = kernel info leak',
                severity='CRITICAL',
            ))

        # WRMSR (0F 30): writes MSR indexed by ECX with EDX:EAX value.
        # Writing MSR_LSTAR (0xC0000082) redirects syscall handler = full ring-0 takeover.
        for m in re.finditer(rb'\x0f\x30', self.data):
            findings.append(DangerousPattern(
                pattern='WRMSR',
                offset=m.start(),
                description='writes MSR[ECX]=EDX:EAX; MSR_LSTAR write = syscall hijack',
                severity='CRITICAL',
            ))

        # MOV CR4, reg (0F 22 E0..E7): CR4 bit 20 = SMEP, bit 21 = SMAP.
        # Clearing SMEP allows ring-0 execution of user-mode pages (classic LPE chain).
        for m in re.finditer(rb'\x0f\x22[\xe0-\xe7]', self.data):
            findings.append(DangerousPattern(
                pattern='MOV_CR4',
                offset=m.start(),
                description='writes CR4; clearing bit 20 (SMEP) enables user-page execution',
                severity='CRITICAL',
            ))

        # MOV CR0, reg (0F 22 C0..C7): CR0 bit 16 = WP (Write Protect).
        # Clearing WP disables write protection on read-only kernel pages,
        # enabling direct patching of SSDT or kernel .text.
        for m in re.finditer(rb'\x0f\x22[\xc0-\xc7]', self.data):
            findings.append(DangerousPattern(
                pattern='MOV_CR0',
                offset=m.start(),
                description='writes CR0; clearing bit 16 (WP) enables kernel .text patching',
                severity='CRITICAL',
            ))

        # Combined CR0 WP-disable sequence: canonical SSDT hook prerequisite.
        # Source: Rootkits: Subverting the Windows Kernel (Hoglund/Butler ch3).
        # Pattern: MOV RAX,CR0 (0F 20 C0) + AND RAX,~WP (48 25 FF FF FE FF) + MOV CR0,RAX (0F 22 C0)
        # This 12-byte sequence appears in virtually every x64 SSDT-hooking rootkit.
        # Any driver with this pattern + KeServiceDescriptorTable = unambiguous SSDT hook.
        for m in re.finditer(rb'\x0f\x20\xc0.{0,8}\x0f\x22\xc0', self.data, re.DOTALL):
            findings.append(DangerousPattern(
                pattern='SSDT_HOOK_CR0_SEQUENCE',
                offset=m.start(),
                description='MOV CR0 read-modify-write; canonical SSDT hook WP-disable sequence',
                severity='CRITICAL',
            ))

        # Combined CR4 SMEP-disable: CLI + MOV CR4 read-modify-write.
        # Source: Windows Internals Part 1 (memory management, kernel mitigations).
        # Full sequence: FA (CLI) + 0F 20 E0 (MOV RAX,CR4) + AND + 0F 22 E0 (MOV CR4,RAX)
        # Bit 20 clear = SMEP disabled = kernel can execute user-mode pages directly.
        for m in re.finditer(rb'\x0f\x20\xe0.{0,8}\x0f\x22\xe0', self.data, re.DOTALL):
            findings.append(DangerousPattern(
                pattern='SMEP_DISABLE_CR4_SEQUENCE',
                offset=m.start(),
                description='MOV CR4 read-modify-write; SMEP/SMAP bypass sequence',
                severity='CRITICAL',
            ))

        # CLI (FA): disables hardware interrupts.
        # On its own: DoS risk. Paired with CR0/CR4 write: interrupt-safe SMEP bypass.
        # Legitimate use: extremely rare in modern kernel drivers.
        for m in re.finditer(rb'\xfa', self.data):
            findings.append(DangerousPattern(
                pattern='CLI',
                offset=m.start(),
                description='disables interrupts; expected only in HAL/ACPI; unusual in driver',
                severity='MEDIUM',
            ))

        # STI (FB): re-enables interrupts. Usually paired with CLI.
        for m in re.finditer(rb'\xfb', self.data):
            findings.append(DangerousPattern(
                pattern='STI',
                offset=m.start(),
                description='re-enables interrupts; usually paired with CLI sequence',
                severity='LOW',
            ))

        # HLT (F4): halts the CPU until next interrupt.
        # If reachable from an IOCTL handler without privilege check = kernel DoS.
        for m in re.finditer(rb'\xf4', self.data):
            findings.append(DangerousPattern(
                pattern='HLT',
                offset=m.start(),
                description='CPU halt instruction; DoS if reachable from user-mode IOCTL',
                severity='HIGH',
            ))

        # SWAPGS (0F 01 F8): swaps GS base between user/kernel.
        # Presence in a driver (not ntoskrnl) is unusual and worth investigating.
        for m in re.finditer(rb'\x0f\x01\xf8', self.data):
            findings.append(DangerousPattern(
                pattern='SWAPGS',
                offset=m.start(),
                description='SWAPGS in driver (expected only in syscall/interrupt stubs)',
                severity='HIGH',
            ))

        # IRETQ (48 CF): return from interrupt / exception handler.
        for m in re.finditer(rb'\x48\xcf', self.data):
            findings.append(DangerousPattern(
                pattern='IRETQ',
                offset=m.start(),
                description='IRETQ in driver; unusual outside ntoskrnl interrupt dispatch',
                severity='HIGH',
            ))

        # IN/OUT port instructions (EC/ED/EE/EF): direct I/O port access.
        # Legitimate in HAL. In a third-party driver: MMIO bypass / hardware backdoor.
        for m in re.finditer(rb'[\xec\xed\xee\xef]', self.data):
            findings.append(DangerousPattern(
                pattern='IO_PORT',
                offset=m.start(),
                description='direct I/O port IN/OUT; hardware access or HAL bypass',
                severity='MEDIUM',
            ))

        # VMware I/O backdoor magic (0x564D5868 = 'VMXh')
        for m in re.finditer(rb'VMXh', self.data):
            findings.append(DangerousPattern(
                pattern='VMWARE_BACKDOOR',
                offset=m.start(),
                description='VMware magic "VMXh"; anti-VM I/O port detection',
                severity='MEDIUM',
            ))

        # UTF-16LE wide-string scan for L"KeServiceDescriptorTable".
        # Source: Windows Internals Part 1 (I/O system, SSDT structure), Rootkits ch4.
        # On x64, ntoskrnl does NOT export KeServiceDescriptorTable -- drivers cannot
        # import it via the IAT. The only static indicator is this wide string passed
        # to MmGetSystemRoutineAddress. Combined with SSDT_HOOK_CR0_SEQUENCE = confirmed hook.
        kssdt_wide = b'K\x00e\x00S\x00e\x00r\x00v\x00i\x00c\x00e\x00D\x00e\x00s\x00c\x00r\x00i\x00p\x00t\x00o\x00r\x00T\x00a\x00b\x00l\x00e\x00'
        if kssdt_wide in self.data:
            findings.append(DangerousPattern(
                pattern='KSERVDESCRIPTORTABLE_WIDE',
                offset=self.data.index(kssdt_wide),
                description='wide string L"KeServiceDescriptorTable"; dynamic SSDT lookup via MmGetSystemRoutineAddress',
                severity='CRITICAL',
            ))

        # ExFreePool without tag: deprecated, pool header type mismatch = BSoD
        imports_flat = {
            fn for funcs in self._pe.imports.values() for fn in funcs
        }
        if 'ExFreePool' in imports_flat:
            findings.append(DangerousPattern(
                pattern='ExFreePool_NOTAG',
                offset=0,
                description='ExFreePool (no tag) deprecated; tag mismatch = pool corruption',
                severity='MEDIUM',
            ))

        # ExAllocatePool (no tag variant) implies NonPagedPool type 0.
        # On Win7/Win8, NonPagedPool was executable -- this is an executable kernel heap alloc.
        # On Win10+, NonPagedPool maps to NonPagedPoolNx (non-execute). But on older targets:
        # shellcode in NonPagedPool + control flow redirect = full kernel code exec.
        if 'ExAllocatePool' in imports_flat:
            findings.append(DangerousPattern(
                pattern='ExAllocatePool_NONPAGEDPOOL',
                offset=0,
                description='ExAllocatePool implies PoolType=0 (NonPagedPool); exec on Win7/Win8; deprecated since Win10 2004',
                severity='HIGH',
            ))

        return findings


# ---------------------------------------------------------------------------
# Convenience function
# ---------------------------------------------------------------------------

def analyze_driver(path: str) -> KernelDriverReport:
    """One-call shortcut. Returns KernelDriverReport."""
    return KernelDriverAnalyzer.from_path(path).analyze()


if __name__ == '__main__':
    import sys

    if len(sys.argv) < 2:
        print(f'Usage: {sys.argv[0]} <driver.sys>')
        sys.exit(1)

    report = analyze_driver(sys.argv[1])
    if report.error:
        print(f'ERROR: {report.error}', file=sys.stderr)
        sys.exit(1)
    print(report.fmt())
    print()
    import json
    print(json.dumps(report.summary(), indent=2))
