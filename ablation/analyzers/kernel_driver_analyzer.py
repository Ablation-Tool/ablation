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
      [31:16] DeviceType  : 0x0001..0x7FFF system, 0x8000..0xFFFF user-defined
      [15:14] Access      : FILE_ANY_ACCESS=0, FILE_READ_ACCESS=1,
                              FILE_WRITE_ACCESS=2, FILE_READ+WRITE=3
      [13:2]  Function    : 0x000..0x7FF system, 0x800..0xFFF user-defined
      [1:0]   Method      : METHOD_BUFFERED=0, METHOD_IN_DIRECT=1,
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
        3: 'METHOD_NEITHER',    # raw user pointer: highest risk
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
    # Reject values where every byte is printable ASCII (0x20-0x7E).
    # ASCII debug strings embedded in .text produce DWORD patterns that pass all
    # other checks — e.g. "acid" (0x64696361) decodes as DevType=0x6469 Func=0x18D.
    # A real CTL_CODE cannot have all four bytes in the printable range because the
    # high word encodes a device-type constant (0x0001-0xFFFF) and the low word
    # encodes method/access/function fields that routinely exceed 0x7E.
    if all(0x20 <= (value >> (i * 8)) & 0xFF <= 0x7E for i in range(4)):
        return None  # printable ASCII string literal, not a CTL_CODE

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
        lines.append(f"Signed:      {'YES' if self.is_signed else 'NO: unsigned or stripped'}")

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
# IOCTL cascade decoder
# ---------------------------------------------------------------------------

class IoctlCascadeDecoder:
    """
    Decode IOCTL codes from SUB/JE dispatch cascades in WDM driver IOCTL handlers.

    WDM drivers compiled from switch(IoControlCode) emit cascades like:

        MOV  ECX, EAX                  ; ECX = IoControlCode
        SUB  ECX, 0x1a2504             ; subtract group base
        JE   handler_0                  ; ECX_orig == 0x1a2504
        PUSH 4
        POP  EAX                        ; load stride 4 into EAX
        SUB  ECX, EAX                   ; ECX_orig - 0x1a2508
        JE   handler_1                  ; ECX_orig == 0x1a2508
        SUB  ECX, EAX                   ; ECX_orig - 0x1a250c
        JE   handler_2                  ; ECX_orig == 0x1a250c

    The stride may be an immediate (SUB reg, 4) or loaded via PUSH/POP or MOV
    into a separate register. This decoder tracks stride registers to handle
    the MSVC-generated PUSH imm; POP reg pattern.
    """

    def __init__(self, cs, image_base: int):
        self._cs         = cs
        self._image_base = image_base

    def decode_section(self, code: bytes, base_va: int) -> list:
        """
        Scan one executable section for SUB/JE cascade patterns.
        Returns list of IoctlCode instances.
        """
        if not _HAS_CAPSTONE or self._cs is None:
            return []
        results  = []
        seen_raw = set()
        insns    = list(self._cs.disasm(code, base_va))

        for i, insn in enumerate(insns):
            if insn.mnemonic != 'sub':
                continue
            try:
                ops = insn.operands
            except AttributeError:
                continue
            if len(ops) != 2:
                continue
            if ops[0].type != capstone.x86.X86_OP_REG:
                continue
            if ops[1].type != capstone.x86.X86_OP_IMM:
                continue

            base_val = ops[1].imm & 0xFFFFFFFF
            base_ic  = decode_ioctl_code(base_val, site_va=insn.address)
            if base_ic is None:
                continue
            # Require a JE/JZ immediately after to confirm dispatch branch
            if i + 1 >= len(insns):
                continue
            if insns[i + 1].mnemonic not in ('je', 'jz'):
                continue

            if base_val not in seen_raw:
                seen_raw.add(base_val)
                results.append(base_ic)

            # Trace derived codes. Strides may be:
            #   immediate:  SUB reg, 4
            #   via register: PUSH 4; POP eax; SUB reg, eax  (MSVC optimizer)
            reg         = ops[0].reg
            accum       = base_val
            stride_regs: dict = {}   # reg_id -> small imm value
            j           = i + 2
            while j < len(insns):
                cur = insns[j]

                # PUSH imm; POP reg — stride register loader
                if cur.mnemonic == 'push':
                    try:
                        push_ops = cur.operands
                        if (len(push_ops) == 1
                                and push_ops[0].type == capstone.x86.X86_OP_IMM
                                and j + 1 < len(insns)
                                and insns[j + 1].mnemonic == 'pop'):
                            pop_ops = insns[j + 1].operands
                            if (len(pop_ops) == 1
                                    and pop_ops[0].type == capstone.x86.X86_OP_REG):
                                sv = push_ops[0].imm & 0xFFFF
                                if 0 < sv <= 0x100:
                                    stride_regs[pop_ops[0].reg] = sv
                            j += 2
                            continue
                    except AttributeError:
                        pass
                    break

                # MOV reg, imm — alternative stride loader
                if cur.mnemonic == 'mov':
                    try:
                        mv_ops = cur.operands
                        if (len(mv_ops) == 2
                                and mv_ops[0].type == capstone.x86.X86_OP_REG
                                and mv_ops[1].type == capstone.x86.X86_OP_IMM):
                            sv = mv_ops[1].imm & 0xFFFF
                            if 0 < sv <= 0x100:
                                stride_regs[mv_ops[0].reg] = sv
                            j += 1
                            continue
                    except AttributeError:
                        pass
                    break

                if cur.mnemonic != 'sub':
                    break
                try:
                    sub_ops = cur.operands
                except AttributeError:
                    break
                if len(sub_ops) != 2:
                    break
                if (sub_ops[0].type != capstone.x86.X86_OP_REG
                        or sub_ops[0].reg != reg):
                    break

                # Determine stride: immediate or via stride register
                if sub_ops[1].type == capstone.x86.X86_OP_IMM:
                    stride = sub_ops[1].imm & 0xFFFF
                elif sub_ops[1].type == capstone.x86.X86_OP_REG:
                    stride = stride_regs.get(sub_ops[1].reg)
                    if stride is None:
                        break
                else:
                    break

                if stride == 0 or stride > 0x100:
                    break
                if j + 1 >= len(insns) or insns[j + 1].mnemonic not in ('je', 'jz'):
                    break
                accum += stride
                derived = decode_ioctl_code(accum, site_va=cur.address)
                if derived is not None and accum not in seen_raw:
                    seen_raw.add(accum)
                    results.append(derived)
                j += 2

        return results


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
        self._machine = self._read_machine()
        self._cs: Optional[object] = None
        if _HAS_CAPSTONE:
            mode = capstone.CS_MODE_32 if self._machine == 0x014c else capstone.CS_MODE_64
            cs = capstone.Cs(capstone.CS_ARCH_X86, mode)
            cs.detail = True
            self._cs = cs

    @classmethod
    def from_path(cls, path: str) -> 'KernelDriverAnalyzer':
        with open(path, 'rb') as fh:
            data = fh.read()
        return cls(data, path)

    # -----------------------------------------------------------------------
    # Architecture helpers
    # -----------------------------------------------------------------------

    def _read_machine(self) -> int:
        """Read IMAGE_FILE_MACHINE from COFF header. 0x014c=i386, 0x8664=AMD64."""
        try:
            return struct.unpack_from('<H', self.data, self._pe.pe_offset + 4)[0]
        except (struct.error, AttributeError):
            return 0x8664

    def _pdata_code_ranges(self) -> list:
        """
        Parse IMAGE_DIRECTORY_ENTRY_EXCEPTION (.pdata) for x64 binaries.
        Each RUNTIME_FUNCTION: BeginAddress(4) EndAddress(4) UnwindInfoAddress(4).
        Returns sorted list of (begin_rva, end_rva) pairs covering actual function code.
        Used by _disasm_exec_sections to exclude UNWIND_INFO data embedded in .text.
        """
        pe = self._pe
        if len(pe._data_dirs) <= 3:
            return []
        pdata_rva, pdata_size = pe._data_dirs[3]
        if not pdata_rva or not pdata_size:
            return []
        off = pe._rva_to_offset(pdata_rva)
        if off is None:
            return []
        ranges = []
        n = pdata_size // 12
        for i in range(n):
            o = off + i * 12
            if o + 12 > len(self.data):
                break
            try:
                begin, end, _ = struct.unpack_from('<III', self.data, o)
            except struct.error:
                break
            if 0 < begin < end < 0x10000000:
                ranges.append((begin, end))
        return sorted(ranges)

    def _disasm_exec_sections(self):
        """
        Yield Capstone instructions from executable sections using boundary-safe disassembly.

        x86 (CS_MODE_32): prologue-seeded. Finds 55 8B EC (PUSH EBP; MOV EBP, ESP)
        function starts and disassembles only from those offsets. WDM x86 .text and INIT
        sections begin with function pointer tables (not code); linear disassembly from
        offset 0 desynchronises there and produces false HLT/RDMSR hits.

        x64 (CS_MODE_64): .pdata-bounded. Parses RUNTIME_FUNCTION entries and disassembles
        only within [BeginAddress, EndAddress) ranges, excluding UNWIND_INFO data blocks
        that the linker embeds at the end of .text and that cause spurious RDMSR reports.
        """
        if not _HAS_CAPSTONE or self._cs is None:
            return

        pe = self._pe

        if self._machine == 0x014c:
            for section in pe.sections:
                if not section['executable']:
                    continue
                raw_off = section['raw_offset']
                raw_sz  = section['raw_size']
                sec_va  = pe.image_base + section['vaddr']
                code    = self.data[raw_off: raw_off + raw_sz]
                # Find 55 8B EC (PUSH EBP; MOV EBP, ESP) prologues
                starts = [i for i in range(len(code) - 2)
                          if code[i] == 0x55 and code[i+1] == 0x8B and code[i+2] == 0xEC]
                if not starts:
                    continue
                starts.append(len(code))
                for i in range(len(starts) - 1):
                    chunk = code[starts[i]: starts[i + 1]]
                    yield from self._cs.disasm(chunk, sec_va + starts[i])
        else:
            code_ranges = self._pdata_code_ranges()
            for section in pe.sections:
                if not section['executable']:
                    continue
                raw_off  = section['raw_offset']
                raw_sz   = section['raw_size']
                sec_va   = pe.image_base + section['vaddr']
                sec_vend = sec_va + raw_sz
                code     = self.data[raw_off: raw_off + raw_sz]
                if code_ranges:
                    for begin_rva, end_rva in code_ranges:
                        begin_va = pe.image_base + begin_rva
                        end_va   = pe.image_base + end_rva
                        if end_va <= sec_va or begin_va >= sec_vend:
                            continue
                        rel_s = max(begin_va - sec_va, 0)
                        rel_e = min(end_va   - sec_va, raw_sz)
                        if rel_s >= rel_e:
                            continue
                        yield from self._cs.disasm(code[rel_s:rel_e], sec_va + rel_s)
                else:
                    yield from self._cs.disasm(code, sec_va)

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
        report.dangerous_patterns    += self._check_neither_probe_absence(report.ioctl_codes)
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
                ) = struct.unpack_from('<IIHHIIII', self.data, entry_off)
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

        if self._machine == 0x014c:   # x86: DRIVER_OBJECT.MajorFunction at +0x38, 4-byte slots
            MF_BASE = 0x38; slot_sz = 4
        else:                          # x64: DRIVER_OBJECT.MajorFunction at +0x70, 8-byte slots
            MF_BASE = 0x70; slot_sz = 8
        MF_END = MF_BASE + 28 * slot_sz

        found: dict = {}
        for insn in self._cs.disasm(code, ep_va):
            if insn.mnemonic != 'mov':
                continue
            try:
                op0, op1 = insn.operands[0], insn.operands[1]
            except (IndexError, AttributeError):
                continue
            if op0.type != capstone.x86.X86_OP_MEM:
                continue
            disp = op0.mem.disp
            if MF_BASE <= disp < MF_END and (disp - MF_BASE) % slot_sz == 0:
                slot = (disp - MF_BASE) // slot_sz
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

        # x86 WDM drivers place function pointer tables at the start of .text and INIT
        # sections. Capstone CS_MODE_32 stops generating instructions when it hits the
        # address-size prefix byte (0x67) used as a ModRM byte in those tables.
        # Use the same prologue-seeded chunks as _disasm_exec_sections so disassembly
        # always starts at a known 55 8B EC (PUSH EBP; MOV EBP, ESP) function entry.
        is_x86 = (self._machine == 0x014c)

        def _iter_code_chunks():
            for section in pe.sections:
                if not section['executable']:
                    continue
                raw_off = section['raw_offset']
                raw_sz  = section['raw_size']
                sec_va  = pe.image_base + section['vaddr']
                code    = self.data[raw_off: raw_off + raw_sz]
                if is_x86:
                    starts = [i for i in range(len(code) - 2)
                              if code[i] == 0x55 and code[i+1] == 0x8B and code[i+2] == 0xEC]
                    if not starts:
                        continue
                    starts.append(len(code))
                    for k in range(len(starts) - 1):
                        yield code[starts[k]: starts[k+1]], sec_va + starts[k]
                else:
                    yield code, sec_va

        # Pass 1: SUB/JE cascade decoder — handles compiled switch(IoControlCode) dispatchers
        # that use register-relative subtraction (incl. push imm; pop reg; sub reg, reg stride).
        cascade = IoctlCascadeDecoder(self._cs, pe.image_base)
        for chunk, chunk_va in _iter_code_chunks():
            for ic in cascade.decode_section(chunk, chunk_va):
                if ic.raw not in seen:
                    seen.add(ic.raw)
                    ioctls.append(ic)

        # Pass 2: CMP/SUB/TEST immediate scan — catches table-driven or hand-coded dispatch.
        # MOV excluded: DriverEntry MOV [DRIVER_OBJECT+disp], handler_va produces handler VAs
        # that pass decode_ioctl_code plausibility checks and create false positives.
        for chunk, chunk_va in _iter_code_chunks():
            for insn in self._cs.disasm(chunk, chunk_va):
                if insn.mnemonic not in ('cmp', 'sub', 'test'):
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
            # Token stealing: PsInitialSystemProcess = EPROCESS for pid 4 (System).
            # Attacker copies System token to arbitrary process -> SYSTEM privileges.
            # Classic LPE primitive; DKOM write to EPROCESS+0x4b8 (Win10 offset).
            'PsInitialSystemProcess':          ('CRITICAL', 'privilege'),
            'PsReferencePrimaryToken':         ('HIGH',   'privilege'),
            'SeQueryInformationToken':         ('HIGH',   'privilege'),
            'PsDereferencePrimaryToken':       ('MEDIUM', 'privilege'),

            # --- Kernel APC injection ---
            # KeInsertQueueApc queues a kernel-mode APC to an arbitrary thread.
            # Chain: OpenThread -> KeInitializeApc -> KeInsertQueueApc -> arbitrary
            # kernel code executed in target thread context at APC_LEVEL.
            # Rootkits use this for stealthy code injection without remote thread APIs.
            'KeInitializeApc':                 ('CRITICAL', 'apc_inject'),
            'KeInsertQueueApc':                ('CRITICAL', 'apc_inject'),
            'PsGetCurrentThreadApcDisable':    ('MEDIUM',   'apc_inject'),

            # --- Process attachment ---
            # KeStackAttachProcess switches the current thread to run in the
            # virtual address space of an arbitrary process (PEPROCESS).
            # Used with PsLookupProcessByProcessId for arbitrary process VA access.
            'KeStackAttachProcess':            ('CRITICAL', 'dkom'),
            'KeUnstackDetachProcess':          ('MEDIUM',   'dkom'),
            'PsGetProcessPeb':                 ('HIGH',     'dkom'),

            # --- Virtual memory manipulation ---
            # ZwAllocateVirtualMemory / NtProtectVirtualMemory from kernel =
            # arbitrary RWX pages in target process without standard userland APIs.
            'ZwAllocateVirtualMemory':         ('CRITICAL', 'mem_copy'),
            'ZwFreeVirtualMemory':             ('MEDIUM',   'mem_copy'),
            'ZwProtectVirtualMemory':          ('CRITICAL', 'mem_copy'),
            'NtProtectVirtualMemory':          ('CRITICAL', 'mem_copy'),
            'ZwWriteVirtualMemory':            ('CRITICAL', 'mem_copy'),

            # --- Driver loading from kernel ---
            'ZwLoadDriver':                    ('CRITICAL', 'driver_load'),
            'NtLoadDriver':                    ('CRITICAL', 'driver_load'),

            # --- SSDT hooking (rootkit indicator) ---
            # ntoskrnl exports KeServiceDescriptorTable; accessing it directly
            # is the prerequisite for SSDT hook installation
            'KeServiceDescriptorTable':        ('CRITICAL', 'ssdt_hook'),
            # MmGetSystemRoutineAddress resolves kernel symbols by Unicode name at runtime.
            # Rootkits use this to locate KeServiceDescriptorTable without a static import,
            # bypassing the trivial import-scan detection above.
            'MmGetSystemRoutineAddress':       ('CRITICAL', 'ssdt_hook'),

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

        # Zero-IAT fallback: some WDM drivers (especially XP-era eGalaxTouch-style
        # drivers) set import_directory_rva=0 and resolve every kernel API at runtime
        # via MmGetSystemRoutineAddress(L"ApiName").  The import table is empty, so the
        # IAT scan above returns nothing.  We recover the API surface by searching the
        # binary for the UTF-16LE names of all known dangerous APIs — these must be
        # present as string literals in .data or .rdata to be passed to MmGetSystemRoutineAddress.
        #
        # This fires only when no IAT findings were produced, avoiding double-reporting
        # on normal drivers that happen to also contain a wide string for some reason.
        if not findings:
            for api_name, (severity, category) in KERNEL_APIS.items():
                if api_name in seen:
                    continue
                wide = api_name.encode('utf-16-le')
                if wide in self.data:
                    seen.add(api_name)
                    findings.append(KernelApiFinding(
                        api=api_name,
                        dll='[dynamic-resolve]',
                        severity=severity,
                        category=category,
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

        # For instruction-boundary-sensitive patterns (HLT, RDMSR, WRMSR, MOV_CR0, MOV_CR4)
        # use _disasm_exec_sections() which avoids false positives from function pointer tables
        # and UNWIND_INFO data embedded in executable sections. Raw byte scan kept as
        # fallback (marked [UNVERIFIED]) when Capstone is unavailable.
        if _HAS_CAPSTONE and self._cs is not None:
            pe = self._pe
            for insn in self._disasm_exec_sections():
                mn   = insn.mnemonic
                ops  = insn.op_str
                # Convert VA → file offset (consistent with raw-byte fallback path).
                rva  = insn.address - pe.image_base
                foff = pe._rva_to_offset(rva) or rva

                if mn == 'hlt':
                    findings.append(DangerousPattern(
                        pattern='HLT',
                        offset=foff,
                        description='CPU halt instruction; DoS if reachable from user-mode IOCTL',
                        severity='HIGH',
                    ))

                elif mn == 'rdmsr':
                    findings.append(DangerousPattern(
                        pattern='RDMSR',
                        offset=foff,
                        description='reads MSR[ECX]; if ECX is IOCTL-tainted = kernel info leak',
                        severity='CRITICAL',
                    ))

                elif mn == 'wrmsr':
                    findings.append(DangerousPattern(
                        pattern='WRMSR',
                        offset=foff,
                        description='writes MSR[ECX]=EDX:EAX; MSR_LSTAR write = syscall hijack',
                        severity='CRITICAL',
                    ))

                elif mn == 'mov' and ops.startswith('cr0'):
                    findings.append(DangerousPattern(
                        pattern='MOV_CR0',
                        offset=foff,
                        description='writes CR0; clearing bit 16 (WP) enables kernel .text patching',
                        severity='CRITICAL',
                    ))

                elif mn == 'mov' and ops.startswith('cr4'):
                    findings.append(DangerousPattern(
                        pattern='MOV_CR4',
                        offset=foff,
                        description='writes CR4; clearing bit 20 (SMEP) enables user-page execution',
                        severity='CRITICAL',
                    ))

        else:
            # Capstone unavailable: raw byte fallback. Offset is file offset, not RVA.
            for m in re.finditer(rb'\x0f\x32', self.data):
                findings.append(DangerousPattern(
                    pattern='RDMSR',
                    offset=m.start(),
                    description='reads MSR[ECX]; if ECX is IOCTL-tainted = kernel info leak [UNVERIFIED]',
                    severity='CRITICAL',
                ))

            for m in re.finditer(rb'\x0f\x30', self.data):
                findings.append(DangerousPattern(
                    pattern='WRMSR',
                    offset=m.start(),
                    description='writes MSR[ECX]=EDX:EAX; MSR_LSTAR write = syscall hijack [UNVERIFIED]',
                    severity='CRITICAL',
                ))

            for m in re.finditer(rb'\x0f\x22[\xe0-\xe7]', self.data):
                findings.append(DangerousPattern(
                    pattern='MOV_CR4',
                    offset=m.start(),
                    description='writes CR4; clearing bit 20 (SMEP) enables user-page execution [UNVERIFIED]',
                    severity='CRITICAL',
                ))

            for m in re.finditer(rb'\x0f\x22[\xc0-\xc7]', self.data):
                findings.append(DangerousPattern(
                    pattern='MOV_CR0',
                    offset=m.start(),
                    description='writes CR0; clearing bit 16 (WP) enables kernel .text patching [UNVERIFIED]',
                    severity='CRITICAL',
                ))

            for m in re.finditer(rb'\xf4', self.data):
                findings.append(DangerousPattern(
                    pattern='HLT',
                    offset=m.start(),
                    description='CPU halt instruction; DoS if reachable from user-mode IOCTL [UNVERIFIED]',
                    severity='HIGH',
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

        # MSR_LSTAR (0xC0000082) targeted access.
        # LSTAR = IA32_LSTAR = syscall entry point (nt!KiSystemCall64 on x64 Windows).
        # MOV ECX, 0xC0000082 (B9 82 00 00 C0) immediately before RDMSR/WRMSR:
        #   RDMSR at LSTAR leaks kernel .text base (KiSystemCall64 VA, trivial KASLR defeat).
        #   WRMSR at LSTAR replaces the syscall handler = full ring-0 code execution.
        # Source: Windows Internals Part 1 (syscall dispatch via LSTAR MSR).
        for m in re.finditer(rb'\xb9\x82\x00\x00\xc0', self.data):
            window = self.data[m.start(): m.start() + 13]
            if b'\x0f\x32' in window:
                op, sev = 'RDMSR(LSTAR): reads KiSystemCall64 VA (KASLR defeat)', 'CRITICAL'
            elif b'\x0f\x30' in window:
                op, sev = 'WRMSR(LSTAR): overwrites syscall handler (full ring-0)', 'CRITICAL'
            else:
                op, sev = 'ECX=LSTAR index loaded (MSR access likely follows)', 'HIGH'
            findings.append(DangerousPattern(
                pattern='MSR_LSTAR_ACCESS',
                offset=m.start(),
                description=op,
                severity=sev,
            ))

        # UTF-16LE wide-string scan for L"KeServiceDescriptorTable".
        # Source: Windows Internals Part 1 (I/O system, SSDT structure), Rootkits ch4.
        # On x64, ntoskrnl does NOT export KeServiceDescriptorTable: drivers cannot
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
        # On Win7/Win8, NonPagedPool was executable: this is an executable kernel heap alloc.
        # On Win10+, NonPagedPool maps to NonPagedPoolNx (non-execute). But on older targets:
        # shellcode in NonPagedPool + control flow redirect = full kernel code exec.
        if 'ExAllocatePool' in imports_flat:
            findings.append(DangerousPattern(
                pattern='ExAllocatePool_NONPAGEDPOOL',
                offset=0,
                description='ExAllocatePool implies PoolType=0 (NonPagedPool); exec on Win7/Win8; deprecated since Win10 2004',
                severity='HIGH',
            ))

        # Writable vtable scan: look for vtable candidates in writable PE sections.
        #
        # Normal C++ drivers store vtables in .rdata (read-only data).  A vtable in
        # .data is mutable at runtime — any kernel write primitive that reaches .data
        # can overwrite a vtable slot and redirect the next IRP dispatch call.  On x86
        # drivers, dispatch runs at IRQL PASSIVE/APC level, so a vtable overwrite is a
        # reliable privilege-escalation primitive.
        #
        # Detection: scan each writable PE section for runs of ≥3 consecutive
        # pointer-size-aligned values that fall inside an executable section.
        # This is the same heuristic CppVtableReconstructorAnalyzer uses for ELF.
        findings.extend(self._scan_writable_vtables())

        return findings

    def _scan_writable_vtables(self) -> list:
        """
        Scan writable PE sections for runs of code pointers (probable vtables).

        Returns DangerousPattern entries for each run of ≥3 consecutive aligned
        pointers into executable sections found inside a writable data section.
        A vtable in .data is mutable at runtime; any kernel write primitive that
        reaches it converts to an IRP dispatch hijack.
        """
        pe = self._pe
        ptr_size = 8 if pe.is_64bit else 4

        # Build executable VA ranges from all exec sections.
        exec_ranges: list = []
        for sec in pe.sections:
            if sec['executable'] and sec['raw_size'] > 0:
                base = pe.image_base + sec['vaddr']
                exec_ranges.append((base, base + sec['vsize']))

        if not exec_ranges:
            return []

        def _points_into_exec(va: int) -> bool:
            return any(lo <= va < hi for lo, hi in exec_ranges)

        findings = []
        fmt = '<Q' if pe.is_64bit else '<I'

        for sec in pe.sections:
            if not sec['writable'] or sec['executable']:
                continue  # skip .rdata and any W^X sections
            if sec['raw_size'] < ptr_size * 3:
                continue

            raw_off = sec['raw_offset']
            raw_end = raw_off + sec['raw_size']
            sec_va  = pe.image_base + sec['vaddr']
            data    = self.data[raw_off:raw_end]

            run_start_off = None
            run_count     = 0

            i = 0
            stride = ptr_size
            while i + ptr_size <= len(data):
                val = struct.unpack_from(fmt, data, i)[0]
                if _points_into_exec(val):
                    if run_start_off is None:
                        run_start_off = i
                    run_count += 1
                else:
                    if run_count >= 3:
                        abs_off = raw_off + run_start_off
                        vtable_va = sec_va + run_start_off
                        findings.append(DangerousPattern(
                            pattern='WRITABLE_VTABLE_IN_DATA',
                            offset=abs_off,
                            description=(
                                f'vtable candidate @ VA 0x{vtable_va:08x} in writable section '
                                f'"{sec.get("name","?")}" ({run_count} slots); '
                                f'any kernel write primitive reaching .data converts to IRP dispatch hijack'
                            ),
                            severity='HIGH',
                        ))
                    run_start_off = None
                    run_count = 0
                i += stride

            # Flush trailing run
            if run_count >= 3:
                abs_off = raw_off + run_start_off
                vtable_va = sec_va + run_start_off
                findings.append(DangerousPattern(
                    pattern='WRITABLE_VTABLE_IN_DATA',
                    offset=abs_off,
                    description=(
                        f'vtable candidate @ VA 0x{vtable_va:08x} in writable section '
                        f'"{sec.get("name","?")}" ({run_count} slots); '
                        f'any kernel write primitive reaching .data converts to IRP dispatch hijack'
                    ),
                    severity='HIGH',
                ))

        return findings

    def _check_neither_probe_absence(self, ioctl_codes: list) -> list:
        """
        For each METHOD_NEITHER IOCTL, check whether ProbeForRead or ProbeForWrite
        appear anywhere in the driver — either in the IAT or as UTF-16LE strings
        passed to MmGetSystemRoutineAddress.

        METHOD_NEITHER passes Type3InputBuffer (a raw user-mode pointer) directly
        to the dispatch handler.  Safe drivers call ProbeForRead/ProbeForWrite before
        any dereference.  A driver with METHOD_NEITHER IOCTLs that never mentions
        ProbeForRead or ProbeForWrite anywhere in the binary has no probe at all:
        every dereference of Type3InputBuffer is an unvalidated kernel read/write path.

        Returns a DangerousPattern entry when METHOD_NEITHER IOCTLs exist and
        ProbeForRead + ProbeForWrite are both absent from the entire binary.
        """
        neither_codes = [ic for ic in ioctl_codes if ic.method == 3]
        if not neither_codes:
            return []

        all_imports: set = set()
        for funcs in self._pe.imports.values():
            all_imports.update(funcs)

        def _probe_present(name: str) -> bool:
            if name in all_imports:
                return True
            return name.encode('utf-16-le') in self.data

        if _probe_present('ProbeForRead') or _probe_present('ProbeForWrite'):
            return []

        codes_fmt = ', '.join(f'0x{ic.raw:08x}' for ic in neither_codes[:6])
        if len(neither_codes) > 6:
            codes_fmt += f' ... (+{len(neither_codes) - 6} more)'

        return [DangerousPattern(
            pattern='NEITHER_IOCTL_NO_PROBE',
            offset=0,
            description=(
                f'{len(neither_codes)} METHOD_NEITHER IOCTL(s) ({codes_fmt}) with no '
                f'ProbeForRead or ProbeForWrite anywhere in the binary; '
                f'Type3InputBuffer dereferences are unvalidated kernel arb-read primitives (CWE-822)'
            ),
            severity='HIGH',
        )]


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
