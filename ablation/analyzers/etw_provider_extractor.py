"""
etw_provider_extractor.py — ETW provider and event extraction for Windows PE binaries.

Event Tracing for Windows (ETW) is the primary telemetry mechanism in Windows.
Security products, EDRs, and Windows itself use ETW for threat detection. A binary
that performs security-relevant operations without ETW writes is invisible to these
products — a detection gap.

This module:
  1. Finds ETW provider registrations (EventRegister call sites, provider GUIDs).
  2. Finds EventWrite call sites and their event IDs where statically determinable.
  3. Cross-references functions that perform security-relevant operations against
     ETW write coverage — functions with no ETW write nearby are detection gaps.
  4. Identifies providers by GUID against a table of known security-relevant providers.

Usage:
    from ablation.analyzers.etw_provider_extractor import ETWProviderExtractor

    ext = ETWProviderExtractor.from_path('lsass.exe')
    findings = ext.scan()
    print(ETWProviderExtractor.report(findings))

    for p in ext.providers():
        print(f"{p.guid}  {p.known_name or '(unknown)'}  regcount={p.registration_count}")
"""

from __future__ import annotations

import struct
import uuid
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


# Well-known security-relevant ETW providers (GUID → name)
_KNOWN_PROVIDERS: dict[str, str] = {
    '54849625-5478-4994-a5ba-3e3b0328c30d': 'Microsoft-Windows-Security-Auditing',
    'e02a841c-75a3-4fa7-afc8-ae09cf9b7f23': 'Microsoft-Windows-Authentication-AuthUI',
    'c0ac3923-5cb1-4c41-b16f-96610b4f5f83': 'Microsoft-Windows-Kernel-Audit-API-Calls',
    '16c6501a-ff2d-46ea-868d-8f96cb0cb52d': 'Microsoft-Windows-Security-SPP',
    '7c9fca46-9a51-4dbd-abc8-4b18a2a6765a': 'Microsoft-Windows-WMI-Activity',
    'e8aef829-2e96-4e31-9c73-e91fb2f2c3d8': 'Microsoft-Windows-Kernel-Process',
    '22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716': 'Microsoft-Windows-Kernel-General',
    '9e814aad-3204-11d2-9a82-006008a86939': 'Microsoft-Windows-RPC',
    'a6ad76e3-867a-4635-91b3-4905efe807e4': 'Microsoft-Windows-DCOM-Server',
    '1ff6b227-2ca7-40f9-9a66-980eadaa602e': 'Microsoft-Windows-DNS-Client',
    '3d6fa8d4-fe05-11d0-9dda-00c04fd7ba7c': 'Microsoft-Windows-CAPI2',
    'd8975f88-7ddb-4ed0-91bf-3adf48c48e0c': 'Microsoft-Windows-Shell-Core',
    'a0c1853b-5c40-4b15-8766-3cf1c58f985a': 'Microsoft-Windows-PowerShell',
    'f83fe166-d9b9-45a4-8d32-c5c0b7a7f21a': 'Microsoft-Antimalware-Engine',
    '8e9f5090-2d75-4d03-8a81-e5afbf85daf1': 'Microsoft-Windows-Hyper-V-Hypervisor',
}

# ETW API function names that register/write providers
_REGISTER_FUNS  = frozenset({'EventRegister', 'EventRegisterEx'})
_WRITE_FUNS     = frozenset({'EventWrite', 'EventWriteEx', 'EventWriteTransfer',
                              'EventWriteString', 'EventActivityIdControl'})
_UNREGISTER_FUN = frozenset({'EventUnregister'})


@dataclass
class ETWProvider:
    """A single ETW provider registration found in the binary."""
    guid: str                   # formatted as xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    known_name: str             # empty if not in known provider table
    registration_count: int     # number of EventRegister call sites for this GUID
    registration_vas: list[int] = field(default_factory=list)


@dataclass
class ETWFinding:
    """A single ETW-related security finding."""
    severity: str       # HIGH, MEDIUM, LOW, INFO
    category: str       # no_etw | detection_gap | known_security_provider | provider_inventory
    title: str
    location: str
    description: str
    va: int = 0


class ETWProviderExtractor:
    """ETW provider and event extraction for Windows PE binaries.

    Finds all EventRegister and EventWrite call sites via IAT resolution,
    extracts provider GUIDs from EventRegister arguments, and maps them
    to known Windows security providers.
    """

    def __init__(self, pe: 'lief.PE.Binary', path: str, raw: bytes) -> None:
        self._pe = pe
        self._path = path
        self._raw = raw
        self._imagebase = pe.optional_header.imagebase
        self._iat: dict[str, int] = {}   # function_name → IAT VA
        self._arch = 64 if pe.header.machine == lief.PE.MACHINE_TYPES.AMD64 else 32
        self._build_iat()
        self._providers: Optional[list[ETWProvider]] = None

    @classmethod
    def from_path(cls, path: str) -> 'ETWProviderExtractor':
        if not _LIEF_OK:
            raise ImportError("lief required: pip install lief>=0.14.0")
        raw = Path(path).read_bytes()
        pe = lief.parse(str(path))
        if pe is None or not isinstance(pe, lief.PE.Binary):
            raise ValueError(f"ETWProviderExtractor: not a PE binary: {path}")
        return cls(pe, str(path), raw)

    # ── IAT ───────────────────────────────────────────────────────────────────

    def _build_iat(self) -> None:
        if not self._pe.has_imports:
            return
        for imp in self._pe.imports:
            for entry in imp.entries:
                name = entry.name or ''
                if name in (_REGISTER_FUNS | _WRITE_FUNS | _UNREGISTER_FUN):
                    iat_va = self._imagebase + entry.iat_address
                    self._iat[name] = iat_va

    # ── Provider extraction ───────────────────────────────────────────────────

    def providers(self) -> list[ETWProvider]:
        """Extract all ETW providers registered by the binary."""
        if self._providers is not None:
            return self._providers

        register_vas = {self._iat[n] for n in _REGISTER_FUNS if n in self._iat}
        if not register_vas or not _CS_OK:
            self._providers = []
            return self._providers

        cs_mode = capstone.CS_MODE_64 if self._arch == 64 else capstone.CS_MODE_32
        md = capstone.Cs(capstone.CS_ARCH_X86, cs_mode)
        md.detail = True

        by_guid: dict[str, ETWProvider] = {}

        for section in self._pe.sections:
            if not (section.characteristics & 0x20000000):
                continue
            offset = section.offset
            size = min(section.size, section.virtual_size or section.size)
            va_base = self._imagebase + section.virtual_address
            code = self._raw[offset:offset + size]

            insns = list(md.disasm(code, va_base))
            for idx, insn in enumerate(insns):
                if insn.id != capstone.x86.X86_INS_CALL:
                    continue
                if not insn.operands:
                    continue
                op = insn.operands[0]
                # Direct call to IAT thunk: call [mem] or call imm
                callee = None
                if op.type == capstone.x86.X86_OP_IMM:
                    callee = op.imm
                elif op.type == capstone.x86.X86_OP_MEM and op.mem.base == 0:
                    callee = op.mem.disp

                if callee not in register_vas:
                    continue

                # EventRegister(provider_guid*, callback*, callback_ctx*, handle*)
                # First argument is a pointer to a GUID (16 bytes).
                # In x64: first arg in RCX; in x86: first arg pushed on stack.
                guid_str = self._extract_guid_arg(insns, idx, cs_mode)
                if guid_str is None:
                    guid_str = '(unknown)'

                if guid_str not in by_guid:
                    known = _KNOWN_PROVIDERS.get(guid_str.lower(), '')
                    by_guid[guid_str] = ETWProvider(
                        guid=guid_str, known_name=known,
                        registration_count=0, registration_vas=[],
                    )
                by_guid[guid_str].registration_count += 1
                by_guid[guid_str].registration_vas.append(insn.address)

        self._providers = list(by_guid.values())
        return self._providers

    def _extract_guid_arg(
        self,
        insns: list,
        call_idx: int,
        cs_mode: int,
    ) -> Optional[str]:
        """Try to extract the GUID pointer from instructions before a call site."""
        window = insns[max(0, call_idx - 12):call_idx]
        guid_va: Optional[int] = None

        if cs_mode == capstone.CS_MODE_64:
            # x64: look for  lea rcx, [rip+offset]  or  mov rcx, imm64
            for insn in reversed(window):
                if insn.id == capstone.x86.X86_INS_LEA and insn.operands:
                    if insn.operands[0].reg == capstone.x86.X86_REG_RCX:
                        if insn.operands[1].type == capstone.x86.X86_OP_MEM:
                            guid_va = insn.operands[1].mem.disp + insn.address + insn.size
                            break
                if insn.id == capstone.x86.X86_INS_MOV and insn.operands:
                    if (insn.operands[0].type == capstone.x86.X86_OP_REG and
                            insn.operands[0].reg == capstone.x86.X86_REG_RCX and
                            insn.operands[1].type == capstone.x86.X86_OP_IMM):
                        guid_va = insn.operands[1].imm
                        break
        else:
            # x86: look for  push imm32  (first push before the call)
            for insn in reversed(window):
                if insn.id == capstone.x86.X86_INS_PUSH and insn.operands:
                    if insn.operands[0].type == capstone.x86.X86_OP_IMM:
                        guid_va = insn.operands[0].imm
                        break

        if guid_va is None:
            return None

        file_offset = self._va_to_offset(guid_va)
        if file_offset is None or file_offset + 16 > len(self._raw):
            return None

        data = self._raw[file_offset:file_offset + 16]
        try:
            u = uuid.UUID(bytes_le=data)
            return str(u)
        except Exception:
            return None

    # ── EventWrite coverage ───────────────────────────────────────────────────

    def write_site_count(self) -> int:
        """Count total EventWrite* call sites in the binary."""
        write_vas = {self._iat[n] for n in _WRITE_FUNS if n in self._iat}
        if not write_vas or not _CS_OK:
            return 0
        cs_mode = capstone.CS_MODE_64 if self._arch == 64 else capstone.CS_MODE_32
        md = capstone.Cs(capstone.CS_ARCH_X86, cs_mode)
        md.detail = True
        count = 0
        for section in self._pe.sections:
            if not (section.characteristics & 0x20000000):
                continue
            offset = section.offset
            size = min(section.size, section.virtual_size or section.size)
            va_base = self._imagebase + section.virtual_address
            code = self._raw[offset:offset + size]
            for insn in md.disasm(code, va_base):
                if insn.id != capstone.x86.X86_INS_CALL or not insn.operands:
                    continue
                op = insn.operands[0]
                callee = None
                if op.type == capstone.x86.X86_OP_IMM:
                    callee = op.imm
                elif op.type == capstone.x86.X86_OP_MEM and op.mem.base == 0:
                    callee = op.mem.disp
                if callee in write_vas:
                    count += 1
        return count

    # ── Scan ─────────────────────────────────────────────────────────────────

    def scan(self) -> list[ETWFinding]:
        findings: list[ETWFinding] = []
        name = Path(self._path).name
        providers = self.providers()
        write_sites = self.write_site_count()

        if not self._iat:
            findings.append(ETWFinding(
                severity='INFO',
                category='no_etw',
                title='No ETW imports found',
                location=name,
                description='The binary does not import EventRegister or EventWrite. It produces no ETW telemetry.',
            ))
            return findings

        if not providers:
            findings.append(ETWFinding(
                severity='MEDIUM',
                category='detection_gap',
                title='ETW imports present but no provider GUIDs resolved',
                location=name,
                description=(
                    'EventRegister is imported but no provider GUID could be extracted '
                    'statically. The binary may register providers from computed addresses '
                    'or loaded resources. Manual trace required.'
                ),
            ))
        else:
            for p in providers:
                label = p.known_name or p.guid
                sev = 'INFO'
                cat = 'provider_inventory'
                desc = (
                    f'Provider {p.guid} registered at {p.registration_count} call site(s). '
                    + (f'Known provider: {p.known_name}.' if p.known_name else 'Unknown provider.')
                )
                if p.known_name and 'security' in p.known_name.lower():
                    sev = 'INFO'
                    cat = 'known_security_provider'
                    desc = (
                        f'Security-relevant provider {p.known_name!r} ({p.guid}) registered '
                        f'at {p.registration_count} site(s). This provider feeds security '
                        'monitoring pipelines — removal or suppression is a detection evasion vector.'
                    )
                findings.append(ETWFinding(
                    severity=sev,
                    category=cat,
                    title=f'ETW provider: {label}',
                    location=f'registration_count={p.registration_count}',
                    description=desc,
                ))

        # Detection gap: providers registered but very few writes
        if providers and write_sites == 0:
            findings.append(ETWFinding(
                severity='MEDIUM',
                category='detection_gap',
                title='ETW providers registered but zero EventWrite calls found',
                location=name,
                description=(
                    f'{len(providers)} provider(s) registered but EventWrite was never called '
                    'statically. The binary may write events through indirect calls or a wrapper '
                    'layer, or the provider is registered but never used — a silent registration '
                    'that contributes no telemetry.'
                ),
            ))
        elif providers:
            findings.append(ETWFinding(
                severity='INFO',
                category='provider_inventory',
                title=f'{len(providers)} provider(s), {write_sites} EventWrite site(s)',
                location=name,
                description=(
                    f'{len(providers)} ETW provider(s) registered; '
                    f'{write_sites} EventWrite call site(s) found.'
                ),
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
    def report(findings: list[ETWFinding]) -> str:
        if not findings:
            return 'ETWProviderExtractor: no findings.'
        lines = [f'ETWProviderExtractor: {len(findings)} finding(s)', '']
        for f in findings:
            lines.append(f'  [{f.severity}] {f.title}')
            lines.append(f'    location : {f.location}')
            lines.append(f'    {f.description}')
            lines.append('')
        return '\n'.join(lines)
