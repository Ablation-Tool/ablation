"""
com_attack_surface_mapper.py — COM attack surface analysis for Windows PE binaries.

COM is a dominant inter-process and privilege-boundary crossing mechanism on Windows.
Security tools, browsers, AV products, and OS services all expose COM interfaces.
Attack surface here includes:

  1. Self-registering COM servers (DllRegisterServer / DllGetClassObject) — the binary
     is itself a COM server. Any CLSID it registers is an activation target.
  2. CoCreateInstance call sites — the binary activates other COM objects. If the CLSID
     resolves to a machine-writable registry key, an attacker can hijack it (COM hijacking).
  3. COM object marshaling — IDispatch usage (Invoke) combined with CoCreateInstance is
     a common DCOM lateral movement pattern.
  4. Registered CLSID / ProgID strings found in the binary's .rdata/.data that match
     the GUID pattern {xxxxxxxx-...} — inventory of COM identifiers referenced at rest.

Usage:
    from ablation.analyzers.com_attack_surface_mapper import COMAttackSurfaceMapper

    mapper = COMAttackSurfaceMapper.from_path('shdocvw.dll')
    findings = mapper.scan()
    print(COMAttackSurfaceMapper.report(findings))

    for clsid in mapper.referenced_clsids():
        print(clsid)
"""

from __future__ import annotations

import re
import struct
import uuid as _uuid_mod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    import lief
    _LIEF_OK = True
except ImportError:
    _LIEF_OK = False

try:
    import capstone
    import capstone.x86
    _CS_OK = True
except ImportError:
    _CS_OK = False


# IAT functions this module monitors
_COM_CREATE_FUNS = frozenset({
    'CoCreateInstance', 'CoCreateInstanceEx',
    'CoGetClassObject', 'CoGetInstanceFromFile',
})
_COM_SERVER_FUNS = frozenset({
    'DllGetClassObject', 'DllRegisterServer', 'DllUnregisterServer',
    'DllCanUnloadNow',
})
_COM_MARSHAL_FUNS = frozenset({
    'CoMarshalInterface', 'CoUnmarshalInterface',
    'CoMarshalInterThreadInterfaceInStream',
})
_IDISPATCH_FUNS = frozenset({'Invoke', 'GetIDsOfNames'})

# Regex for GUID pattern in string data: {8-4-4-4-12} hex
_GUID_RE = re.compile(
    rb'\{([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\}'
)


@dataclass
class COMFinding:
    """A single COM attack surface finding."""
    severity: str       # HIGH, MEDIUM, LOW, INFO
    category: str       # com_server | com_create | com_hijack_risk | com_marshal |
                        # clsid_inventory | idispatch
    title: str
    location: str
    description: str
    va: int = 0
    cwe: str = ""


class COMAttackSurfaceMapper:
    """COM attack surface analysis for Windows PE binaries.

    Maps COM server registration, CoCreateInstance activation targets, COM hijacking
    risk (CLSID references + HKCU-writable activation paths), marshaling exposure,
    and IDispatch usage.
    """

    def __init__(self, pe: 'lief.PE.Binary', path: str, raw: bytes) -> None:
        self._pe = pe
        self._path = path
        self._raw = raw
        self._imagebase = pe.optional_header.imagebase
        self._arch = 64 if pe.header.machine == lief.PE.MACHINE_TYPES.AMD64 else 32
        self._iat: dict[str, int] = {}
        self._build_iat()

    @classmethod
    def from_path(cls, path: str) -> 'COMAttackSurfaceMapper':
        if not _LIEF_OK:
            raise ImportError("lief required: pip install lief>=0.14.0")
        raw = Path(path).read_bytes()
        pe = lief.parse(str(path))
        if pe is None or not isinstance(pe, lief.PE.Binary):
            raise ValueError(f"COMAttackSurfaceMapper: not a PE binary: {path}")
        return cls(pe, str(path), raw)

    # ── IAT ───────────────────────────────────────────────────────────────────

    def _build_iat(self) -> None:
        if not self._pe.has_imports:
            return
        all_funs = _COM_CREATE_FUNS | _COM_MARSHAL_FUNS | _IDISPATCH_FUNS
        for imp in self._pe.imports:
            for entry in imp.entries:
                name = entry.name or ''
                if name in all_funs:
                    self._iat[name] = self._imagebase + entry.iat_address

    # ── CLSID extraction from data sections ──────────────────────────────────

    def referenced_clsids(self) -> list[str]:
        """Extract GUID strings in {XXXXXXXX-...} format from read-only data."""
        results: list[str] = []
        seen: set[str] = set()
        for section in self._pe.sections:
            # .rdata, .data, .rsrc — not code (.text)
            if section.characteristics & 0x20000000:
                continue
            offset = section.offset
            size = min(section.size, section.virtual_size or section.size)
            chunk = self._raw[offset:offset + size]
            for m in _GUID_RE.finditer(chunk):
                guid_bytes = m.group(1)
                try:
                    guid_str = '{' + guid_bytes.decode('ascii').upper() + '}'
                    if guid_str not in seen:
                        seen.add(guid_str)
                        results.append(guid_str)
                except Exception:
                    pass
        return results

    # ── COM server detection ──────────────────────────────────────────────────

    def is_com_server(self) -> bool:
        """Return True if the binary exports DllGetClassObject."""
        if not self._pe.has_exports:
            return False
        for exp in self._pe.get_export().entries:
            if exp.name in _COM_SERVER_FUNS:
                return True
        return False

    def com_server_exports(self) -> list[str]:
        """Return names of COM server export functions found."""
        if not self._pe.has_exports:
            return []
        return [e.name for e in self._pe.get_export().entries if e.name in _COM_SERVER_FUNS]

    # ── CoCreateInstance call sites ───────────────────────────────────────────

    def cocreate_sites(self) -> list[tuple[int, Optional[str]]]:
        """Return (call_va, clsid_string_or_None) for each CoCreateInstance call site."""
        create_iat_vas = {v for k, v in self._iat.items() if k in _COM_CREATE_FUNS}
        if not create_iat_vas or not _CS_OK:
            return []

        cs_mode = capstone.CS_MODE_64 if self._arch == 64 else capstone.CS_MODE_32
        md = capstone.Cs(capstone.CS_ARCH_X86, cs_mode)
        md.detail = True
        results: list[tuple[int, Optional[str]]] = []

        for section in self._pe.sections:
            if not (section.characteristics & 0x20000000):
                continue
            offset = section.offset
            size = min(section.size, section.virtual_size or section.size)
            va_base = self._imagebase + section.virtual_address
            code = self._raw[offset:offset + size]
            insns = list(md.disasm(code, va_base))

            for idx, insn in enumerate(insns):
                if insn.id != capstone.x86.X86_INS_CALL or not insn.operands:
                    continue
                op = insn.operands[0]
                callee = None
                if op.type == capstone.x86.X86_OP_IMM:
                    callee = op.imm
                elif op.type == capstone.x86.X86_OP_MEM and op.mem.base == 0:
                    callee = op.mem.disp
                if callee not in create_iat_vas:
                    continue

                # First argument: pointer to CLSID (16 bytes)
                clsid_va = self._extract_first_arg(insns, idx, cs_mode)
                clsid_str: Optional[str] = None
                if clsid_va is not None:
                    clsid_str = self._read_guid_string(clsid_va)
                results.append((insn.address, clsid_str))

        return results

    def _extract_first_arg(self, insns: list, call_idx: int, cs_mode: int) -> Optional[int]:
        window = insns[max(0, call_idx - 12):call_idx]
        if cs_mode == capstone.CS_MODE_64:
            for insn in reversed(window):
                if insn.id == capstone.x86.X86_INS_LEA and insn.operands:
                    if insn.operands[0].reg == capstone.x86.X86_REG_RCX:
                        if insn.operands[1].type == capstone.x86.X86_OP_MEM:
                            return insn.operands[1].mem.disp + insn.address + insn.size
                if insn.id == capstone.x86.X86_INS_MOV and insn.operands:
                    if (insn.operands[0].type == capstone.x86.X86_OP_REG and
                            insn.operands[0].reg == capstone.x86.X86_REG_RCX and
                            insn.operands[1].type == capstone.x86.X86_OP_IMM):
                        return insn.operands[1].imm
        else:
            for insn in reversed(window):
                if insn.id == capstone.x86.X86_INS_PUSH and insn.operands:
                    if insn.operands[0].type == capstone.x86.X86_OP_IMM:
                        return insn.operands[0].imm
        return None

    def _read_guid_string(self, va: int) -> Optional[str]:
        offset = self._va_to_offset(va)
        if offset is None or offset + 16 > len(self._raw):
            return None
        data = self._raw[offset:offset + 16]
        try:
            u = _uuid_mod.UUID(bytes_le=data)
            return str(u)
        except Exception:
            return None

    # ── Scan ─────────────────────────────────────────────────────────────────

    def scan(self) -> list[COMFinding]:
        findings: list[COMFinding] = []
        name = Path(self._path).name

        # COM server detection
        if self.is_com_server():
            server_exports = self.com_server_exports()
            clsids = self.referenced_clsids()
            findings.append(COMFinding(
                severity='INFO',
                category='com_server',
                title=f'COM server: exports {", ".join(server_exports)}',
                location=name,
                description=(
                    f'The binary is a COM server (exports {server_exports}). '
                    f'{len(clsids)} CLSID string(s) found in data sections. '
                    f'Each registered CLSID is an activation target — look for '
                    f'HKCU\\Software\\Classes\\CLSID overrides (COM hijacking risk).'
                ),
            ))
            if clsids:
                findings.append(COMFinding(
                    severity='MEDIUM',
                    category='com_hijack_risk',
                    title=f'COM server with {len(clsids)} CLSID reference(s) — hijacking surface',
                    location=name,
                    description=(
                        f'A COM server DLL with CLSID references may be vulnerable to COM hijacking '
                        f'if its CLSID is registered under HKCU (user-writable) rather than HKLM. '
                        f'CLSIDs: ' + ', '.join(clsids[:5]) +
                        (f' (+{len(clsids)-5} more)' if len(clsids) > 5 else '')
                    ),
                    cwe='CWE-426',
                ))

        # CoCreateInstance sites
        sites = self.cocreate_sites()
        if sites:
            resolved = [(va, g) for va, g in sites if g is not None]
            unresolved = [(va, g) for va, g in sites if g is None]
            desc = (
                f'{len(sites)} CoCreateInstance call site(s): '
                f'{len(resolved)} with resolved CLSIDs, {len(unresolved)} unresolved. '
            )
            if resolved:
                desc += 'Resolved CLSIDs: ' + ', '.join(g for _, g in resolved[:5])
                if len(resolved) > 5:
                    desc += f' (+{len(resolved)-5} more)'
            findings.append(COMFinding(
                severity='INFO',
                category='com_create',
                title=f'{len(sites)} CoCreateInstance call site(s)',
                location=name,
                description=desc,
            ))

        # COM marshaling
        marshal_imports = [k for k in self._iat if k in _COM_MARSHAL_FUNS]
        if marshal_imports:
            findings.append(COMFinding(
                severity='MEDIUM',
                category='com_marshal',
                title=f'COM marshaling used: {", ".join(marshal_imports)}',
                location=name,
                description=(
                    f'The binary imports {marshal_imports}. '
                    'COM marshaling crosses apartment boundaries and trust contexts — '
                    'if marshaled data is attacker-influenced, this can lead to '
                    'cross-process exploitation via IMoniker/IStream deserialization.'
                ),
                cwe='CWE-502',
            ))

        # IDispatch usage
        idispatch_imports = [k for k in self._iat if k in _IDISPATCH_FUNS]
        if idispatch_imports:
            findings.append(COMFinding(
                severity='INFO',
                category='idispatch',
                title=f'IDispatch automation interface used',
                location=name,
                description=(
                    f'IDispatch methods {idispatch_imports} are imported. '
                    'IDispatch is the OLE automation interface — any object exposed '
                    'through it is scriptable via VBScript/JScript and reachable from '
                    'DCOM clients over the network if DCOM is enabled.'
                ),
            ))

        # CLSID inventory (non-server case)
        if not self.is_com_server():
            clsids = self.referenced_clsids()
            if clsids:
                findings.append(COMFinding(
                    severity='INFO',
                    category='clsid_inventory',
                    title=f'{len(clsids)} CLSID string(s) in binary data',
                    location=name,
                    description=(
                        'CLSID references in .rdata/.data: ' +
                        ', '.join(clsids[:8]) +
                        (f' (+{len(clsids)-8} more)' if len(clsids) > 8 else '')
                    ),
                ))

        if not findings:
            findings.append(COMFinding(
                severity='INFO',
                category='no_com',
                title='No COM surface found',
                location=name,
                description='No COM server exports, CoCreateInstance imports, or CLSID references found.',
            ))

        return findings

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _va_to_offset(self, va: int) -> Optional[int]:
        rva = va - self._imagebase
        for section in self._pe.sections:
            s_rva = section.virtual_address
            s_size = max(section.virtual_size, section.size)
            if s_rva <= rva < s_rva + s_size:
                return section.offset + (rva - s_rva)
        return None

    @staticmethod
    def report(findings: list[COMFinding]) -> str:
        if not findings:
            return 'COMAttackSurfaceMapper: no findings.'
        n_med = sum(1 for f in findings if f.severity in ('CRITICAL', 'HIGH', 'MEDIUM'))
        lines = [f'COMAttackSurfaceMapper: {len(findings)} finding(s)  ({n_med} MEDIUM+)', '']
        for f in findings:
            lines.append(f'  [{f.severity}] {f.title}')
            lines.append(f'    location : {f.location}')
            if f.cwe:
                lines.append(f'    cwe      : {f.cwe}')
            lines.append(f'    {f.description}')
            lines.append('')
        return '\n'.join(lines)
