"""
rpc_server_analyzer.py — Windows RPC server endpoint analysis for PE binaries.

Windows RPC servers register interfaces with RpcServerRegisterIf(Ex) and bind to
transport endpoints (named pipes, TCP ports, ALPC). The registration call carries
an authentication level — RPC_C_AUTHN_LEVEL_NONE (1) means any caller can reach
the interface without credentials.

This module:
  1. Finds RpcServerRegisterIf / RpcServerRegisterIfEx / RpcServerRegisterIfEx2 callers.
  2. Reads the RPC_SERVER_INTERFACE struct from the first argument to extract the
     interface UUID and transfer syntax.
  3. Extracts the auth level passed to RpcServerRegisterIfEx (second argument).
  4. Finds RpcServerUseProtseqEp call sites to enumerate endpoint strings.
  5. Reports unauthenticated RPC interfaces as HIGH findings.

Usage:
    from ablation.analyzers.rpc_server_analyzer import RPCServerAnalyzer

    ana = RPCServerAnalyzer.from_path('svchost.exe')
    findings = ana.scan()
    print(RPCServerAnalyzer.report(findings))

    for iface in ana.interfaces():
        print(f"{iface.uuid}  auth={iface.auth_level_name}  endpoints={iface.endpoints}")
"""

from __future__ import annotations

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


# RPC authentication levels (rpcnterr.h / rpcndr.h)
_AUTH_LEVEL_NAMES = {
    0: 'RPC_C_AUTHN_LEVEL_DEFAULT',
    1: 'RPC_C_AUTHN_LEVEL_NONE',      # ← unauthenticated
    2: 'RPC_C_AUTHN_LEVEL_CONNECT',
    3: 'RPC_C_AUTHN_LEVEL_CALL',
    4: 'RPC_C_AUTHN_LEVEL_PKT',
    5: 'RPC_C_AUTHN_LEVEL_PKT_INTEGRITY',
    6: 'RPC_C_AUTHN_LEVEL_PKT_PRIVACY',
}

_REGISTER_FUNS = frozenset({
    'RpcServerRegisterIf',
    'RpcServerRegisterIfEx',
    'RpcServerRegisterIfEx2',
    'RpcServerRegisterIf2',
    'RpcServerRegisterIf3',
})

_ENDPOINT_FUNS = frozenset({
    'RpcServerUseProtseqEpA',
    'RpcServerUseProtseqEpW',
    'RpcServerUseProtseqEp',
    'RpcServerUseAllProtseqsIfEx',
})


@dataclass
class RPCInterface:
    """An RPC server interface found in the binary."""
    uuid: str                       # interface UUID string
    transfer_syntax_uuid: str       # transfer syntax UUID (NDR, NDR64)
    auth_level: int                 # auth level passed to RegisterIfEx, or -1 if unknown
    registration_va: int            # VA of the RpcServerRegisterIf* call
    endpoints: list[str] = field(default_factory=list)

    @property
    def auth_level_name(self) -> str:
        return _AUTH_LEVEL_NAMES.get(self.auth_level, f'unknown({self.auth_level})')

    @property
    def unauthenticated(self) -> bool:
        return self.auth_level in (0, 1)


@dataclass
class RPCFinding:
    """A single RPC security finding."""
    severity: str       # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str       # unauthenticated_rpc | rpc_interface | endpoint_inventory
    title: str
    location: str
    description: str
    va: int = 0
    cwe: str = ""


class RPCServerAnalyzer:
    """Windows RPC server endpoint analysis.

    Finds RpcServerRegisterIf* call sites, reads the RPC_SERVER_INTERFACE struct
    to extract interface UUIDs, and extracts auth levels from RegisterIfEx calls.
    """

    def __init__(self, pe: 'lief.PE.Binary', path: str, raw: bytes) -> None:
        self._pe = pe
        self._path = path
        self._raw = raw
        self._imagebase = pe.optional_header.imagebase
        self._arch = 64 if pe.header.machine == lief.PE.MACHINE_TYPES.AMD64 else 32
        self._iat: dict[str, int] = {}
        self._build_iat()
        self._interfaces: Optional[list[RPCInterface]] = None

    @classmethod
    def from_path(cls, path: str) -> 'RPCServerAnalyzer':
        if not _LIEF_OK:
            raise ImportError("lief required: pip install lief>=0.14.0")
        raw = Path(path).read_bytes()
        pe = lief.parse(str(path))
        if pe is None or not isinstance(pe, lief.PE.Binary):
            raise ValueError(f"RPCServerAnalyzer: not a PE binary: {path}")
        return cls(pe, str(path), raw)

    # ── IAT ───────────────────────────────────────────────────────────────────

    def _build_iat(self) -> None:
        if not self._pe.has_imports:
            return
        for imp in self._pe.imports:
            for entry in imp.entries:
                name = entry.name or ''
                if name in (_REGISTER_FUNS | _ENDPOINT_FUNS):
                    self._iat[name] = self._imagebase + entry.iat_address

    # ── RPC_SERVER_INTERFACE parsing ─────────────────────────────────────────

    def _read_guid(self, va: int) -> Optional[str]:
        """Read a 16-byte GUID from the binary at the given VA."""
        offset = self._va_to_offset(va)
        if offset is None or offset + 16 > len(self._raw):
            return None
        data = self._raw[offset:offset + 16]
        try:
            u = _uuid_mod.UUID(bytes_le=data)
            return str(u)
        except Exception:
            return None

    def _read_rpc_server_interface(self, struct_va: int) -> Optional[tuple[str, str]]:
        """Parse RPC_SERVER_INTERFACE at struct_va → (interface_uuid, transfer_uuid).

        Layout (x64):
          +0x00  UINT Length
          +0x04  [pad 4]
          +0x08  RPC_SYNTAX_IDENTIFIER InterfaceId  (GUID 16b + version 4b = 20b)
          +0x1c  [pad 4]
          +0x20  RPC_SYNTAX_IDENTIFIER TransferSyntax
        Layout (x86):
          +0x00  UINT Length
          +0x04  RPC_SYNTAX_IDENTIFIER InterfaceId  (20 bytes)
          +0x18  RPC_SYNTAX_IDENTIFIER TransferSyntax
        """
        offset = self._va_to_offset(struct_va)
        if offset is None:
            return None
        # RPC_SYNTAX_IDENTIFIER: GUID (16 bytes) + WORD MajorVersion + WORD MinorVersion
        if self._arch == 64:
            iface_off = offset + 0x08
            xfer_off  = offset + 0x20
        else:
            iface_off = offset + 0x04
            xfer_off  = offset + 0x18

        if xfer_off + 16 > len(self._raw):
            return None

        try:
            iface_guid = _uuid_mod.UUID(bytes_le=self._raw[iface_off:iface_off + 16])
            xfer_guid  = _uuid_mod.UUID(bytes_le=self._raw[xfer_off:xfer_off + 16])
            return str(iface_guid), str(xfer_guid)
        except Exception:
            return None

    # ── Call site extraction ──────────────────────────────────────────────────

    def interfaces(self) -> list[RPCInterface]:
        """Extract all RPC interfaces registered by the binary."""
        if self._interfaces is not None:
            return self._interfaces

        register_vas = {v for k, v in self._iat.items() if k in _REGISTER_FUNS}
        if not register_vas or not _CS_OK:
            self._interfaces = []
            return self._interfaces

        cs_mode = capstone.CS_MODE_64 if self._arch == 64 else capstone.CS_MODE_32
        md = capstone.Cs(capstone.CS_ARCH_X86, cs_mode)
        md.detail = True
        found: list[RPCInterface] = []

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
                if callee not in register_vas:
                    continue

                # Determine which function name this IAT VA maps to
                fun_name = next(
                    (k for k, v in self._iat.items() if v == callee), ''
                )

                # Extract first argument (RPC_SERVER_INTERFACE*)
                struct_va = self._extract_first_arg(insns, idx, cs_mode)
                guids = None
                if struct_va is not None:
                    guids = self._read_rpc_server_interface(struct_va)
                    if guids is None:
                        # struct_va might be a pointer-to-pointer; dereference once
                        ptr_offset = self._va_to_offset(struct_va)
                        if ptr_offset is not None and ptr_offset + self._arch // 8 <= len(self._raw):
                            ptr_size = 8 if self._arch == 64 else 4
                            fmt = '<Q' if self._arch == 64 else '<I'
                            (deref_va,) = struct.unpack_from(fmt, self._raw, ptr_offset)
                            guids = self._read_rpc_server_interface(deref_va)

                iface_uuid = guids[0] if guids else '(unresolved)'
                xfer_uuid  = guids[1] if guids else '(unresolved)'

                # Auth level: second argument for RegisterIfEx, not present in RegisterIf
                auth_level = -1
                if 'Ex' in fun_name or 'If2' in fun_name or 'If3' in fun_name:
                    auth_level = self._extract_nth_arg(insns, idx, 1, cs_mode) or -1

                found.append(RPCInterface(
                    uuid=iface_uuid,
                    transfer_syntax_uuid=xfer_uuid,
                    auth_level=auth_level,
                    registration_va=insn.address,
                ))

        self._interfaces = found
        return found

    def _extract_first_arg(self, insns: list, call_idx: int, cs_mode: int) -> Optional[int]:
        return self._extract_nth_arg(insns, call_idx, 0, cs_mode)

    def _extract_nth_arg(
        self, insns: list, call_idx: int, n: int, cs_mode: int
    ) -> Optional[int]:
        """Extract the n-th argument value (0-indexed) from the call setup code."""
        window = insns[max(0, call_idx - 16):call_idx]
        if cs_mode == capstone.CS_MODE_64:
            # x64 calling convention: rcx, rdx, r8, r9 for args 0-3
            arg_regs = [
                capstone.x86.X86_REG_RCX,
                capstone.x86.X86_REG_RDX,
                capstone.x86.X86_REG_R8,
                capstone.x86.X86_REG_R9,
            ]
            if n >= len(arg_regs):
                return None
            target_reg = arg_regs[n]
            for insn in reversed(window):
                if insn.id in (capstone.x86.X86_INS_LEA, capstone.x86.X86_INS_MOV):
                    ops = insn.operands
                    if (ops and ops[0].type == capstone.x86.X86_OP_REG and
                            ops[0].reg == target_reg):
                        if len(ops) > 1:
                            src = ops[1]
                            if src.type == capstone.x86.X86_OP_IMM:
                                return src.imm
                            if src.type == capstone.x86.X86_OP_MEM:
                                if insn.id == capstone.x86.X86_INS_LEA:
                                    return src.mem.disp + insn.address + insn.size
        else:
            # x86: args pushed right-to-left; n-th arg is the (total_args - 1 - n)-th push
            # Approximate: count pushes; the n-th from last before the call
            pushes = [
                i for i in window
                if i.id == capstone.x86.X86_INS_PUSH and
                i.operands and i.operands[0].type == capstone.x86.X86_OP_IMM
            ]
            if n < len(pushes):
                return pushes[-(n + 1)].operands[0].imm
        return None

    def endpoint_strings(self) -> list[str]:
        """Find string arguments passed to RpcServerUseProtseqEp* calls."""
        ep_vas = {v for k, v in self._iat.items() if k in _ENDPOINT_FUNS}
        if not ep_vas or not _CS_OK:
            return []
        cs_mode = capstone.CS_MODE_64 if self._arch == 64 else capstone.CS_MODE_32
        md = capstone.Cs(capstone.CS_ARCH_X86, cs_mode)
        md.detail = True
        results: list[str] = []
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
                if callee not in ep_vas:
                    continue
                # Second argument is the endpoint string
                ep_va = self._extract_nth_arg(insns, idx, 1, cs_mode)
                if ep_va is None:
                    continue
                s = self._read_string(ep_va)
                if s:
                    results.append(s)
        return results

    def _read_string(self, va: int, max_len: int = 256) -> str:
        offset = self._va_to_offset(va)
        if offset is None:
            return ''
        end = min(offset + max_len, len(self._raw))
        raw = self._raw[offset:end]
        # Try UTF-16LE first (wide strings), then ASCII
        for enc in ('utf-16-le', 'latin-1'):
            try:
                text = raw.decode(enc)
                term = text.find('\x00')
                if term > 0:
                    return text[:term]
            except Exception:
                pass
        return ''

    # ── Scan ─────────────────────────────────────────────────────────────────

    def scan(self) -> list[RPCFinding]:
        findings: list[RPCFinding] = []
        name = Path(self._path).name

        if not self._iat:
            findings.append(RPCFinding(
                severity='INFO',
                category='no_rpc',
                title='No RPC server imports found',
                location=name,
                description='The binary does not import RpcServerRegisterIf* or RpcServerUseProtseqEp*.',
            ))
            return findings

        interfaces = self.interfaces()
        endpoints  = self.endpoint_strings()

        if not interfaces:
            findings.append(RPCFinding(
                severity='INFO',
                category='rpc_interface',
                title='RPC server imports present but no interfaces resolved statically',
                location=name,
                description='RPC registration functions are imported but call sites could not be resolved. Interface UUIDs may come from loaded resources or indirect dispatch.',
            ))

        for iface in interfaces:
            sev = 'HIGH' if iface.unauthenticated else 'INFO'
            cat = 'unauthenticated_rpc' if iface.unauthenticated else 'rpc_interface'
            auth_str = iface.auth_level_name if iface.auth_level >= 0 else 'not set (RpcServerRegisterIf — uses server default)'
            desc = (
                f'Interface {iface.uuid} registered at 0x{iface.registration_va:x}. '
                f'Auth level: {auth_str}. '
                f'Transfer syntax: {iface.transfer_syntax_uuid}.'
            )
            if iface.unauthenticated:
                desc += (
                    ' Auth level NONE means any network caller can invoke methods on this '
                    'interface without credentials. This is a direct lateral movement vector.'
                )
            findings.append(RPCFinding(
                severity=sev,
                category=cat,
                title=f'RPC interface {"(UNAUTHENTICATED) " if iface.unauthenticated else ""}{iface.uuid}',
                location=f'0x{iface.registration_va:x}',
                description=desc,
                va=iface.registration_va,
                cwe='CWE-306' if iface.unauthenticated else '',
            ))

        if endpoints:
            findings.append(RPCFinding(
                severity='INFO',
                category='endpoint_inventory',
                title=f'{len(endpoints)} RPC endpoint string(s) found',
                location=name,
                description='Endpoints: ' + ', '.join(repr(e) for e in endpoints[:10]),
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
    def report(findings: list[RPCFinding]) -> str:
        if not findings:
            return 'RPCServerAnalyzer: no findings.'
        n_high = sum(1 for f in findings if f.severity in ('CRITICAL', 'HIGH'))
        n_med  = sum(1 for f in findings if f.severity == 'MEDIUM')
        lines  = [
            f'RPCServerAnalyzer: {len(findings)} finding(s)  ({n_high} HIGH  {n_med} MEDIUM)',
            '',
        ]
        for f in findings:
            lines.append(f'  [{f.severity}] {f.title}')
            lines.append(f'    location : {f.location}')
            if f.cwe:
                lines.append(f'    cwe      : {f.cwe}')
            lines.append(f'    {f.description}')
            lines.append('')
        return '\n'.join(lines)
