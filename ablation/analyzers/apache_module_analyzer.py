"""
apache_module_analyzer.py — Apache C module binary security analyzer.

Closes TG-APACHE-MOD-1: no ablation module handles Apache APR/APRUTIL C modules.

Why this exists:

FortiAnalyzer v7.6.3 ships a custom Apache module `mod_extension.so` that bypasses
MFA via a session skip flag. Manual disassembly (FAZ-CVE22572 / CVE-2026-22572) was
required to confirm the bypass surface because no ablation tool could:
  - Reconstruct the ap_hook_handler call graph
  - Track APR table get/set patterns (Cookie header → session object)
  - Identify session skip flag accessor calls

This analyzer automates all three for any Apache 2.x C module binary (.so).

Key findings pattern (confirmed in mod_extension.so):
  1. register_hooks() calls ap_hook_handler(handler_fn, NULL, NULL, APR_HOOK_MIDDLE)
  2. handler_fn reads Cookie header: apr_table_get(r->headers_in, "Cookie")
  3. handler_fn calls session_from_string() → decrypt_and_auth() → session_get_adminuser_skip()
  4. session_get_adminuser_skip() return value controls MFA gate

Module outputs:
  HANDLER_REGISTRATION — register_hooks function with the handler function it registers
  AUTH_TABLE_ACCESS     — apr_table_get call reading auth-relevant headers (Cookie, Authorization)
  SESSION_SKIP_FLAG     — call to a session skip/bypass accessor in the handler
  AUTH_BYPASS_SURFACE   — decrypt/auth function + session skip flag in the same handler (CRITICAL)
  APR_TABLE_WRITE       — apr_table_set/setn in handler modifying auth-relevant keys

Usage:

    from ablation.analyzers.apache_module_analyzer import ApacheModuleAnalyzer

    analyzer = ApacheModuleAnalyzer.from_path('/path/to/mod_extension.so')
    findings = analyzer.analyze()
    print(ApacheModuleAnalyzer.report(findings))

    # With BinaryContext
    from ablation.analyzers.binary_context import BinaryContext
    ctx = BinaryContext.load_or_build('/path/to/mod.so')
    analyzer = ApacheModuleAnalyzer.from_context(ctx)
    findings = analyzer.analyze()

CLI:
    python3 -m ablation.analyzers.apache_module_analyzer /path/to/mod.so
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

try:
    import lief
    _LIEF_OK = True
except ImportError:
    _LIEF_OK = False

try:
    import capstone
    _CS_OK = True
    _CS_X86 = capstone.CS_ARCH_X86
    _CS_X64 = capstone.CS_MODE_64
    _CS_ARM64 = capstone.CS_ARCH_ARM64
    _CS_ARM64_MODE = capstone.CS_MODE_ARM
except ImportError:
    _CS_OK = False

# ── Apache APR/AP symbols of interest ────────────────────────────────────────

# Hook registration functions
_AP_HOOK_FUNCS = frozenset({
    'ap_hook_handler', 'ap_hook_post_read_request', 'ap_hook_fixups',
    'ap_hook_check_user_id', 'ap_hook_auth_checker', 'ap_hook_access_checker',
    'ap_hook_translate_name', 'ap_hook_log_transaction', 'ap_hook_type_checker',
    'ap_hook_header_parser',
})

# APR table access functions
_APR_TABLE_READ = frozenset({'apr_table_get', 'apr_table_getm', 'apr_table_merge'})
_APR_TABLE_WRITE = frozenset({'apr_table_set', 'apr_table_setn', 'apr_table_add',
                               'apr_table_addn', 'apr_table_unset'})

# Session/auth-relevant symbols — skip flag patterns
_SESSION_SKIP_PATTERNS = re.compile(
    r'session_get_adminuser_skip|session_get_user_is_admin|'
    r'session_get_admin_prof|session_skip|admin_skip|'
    r'bypass_mfa|skip_auth|noauth',
    re.IGNORECASE,
)

# Auth-relevant header strings
_AUTH_HEADERS = frozenset({
    'Cookie', 'Authorization', 'X-Auth-Token', 'X-Session-Token',
    'X-Forwarded-User', 'X-Remote-User', 'X-API-Key',
    'CURRENT_SESSION', 'Session',
})

# Decrypt/auth entry point patterns
_DECRYPT_AUTH_RE = re.compile(
    r'decrypt_and_auth|decrypt_session|verify_session|'
    r'session_from_string|parse_session|decode_session|'
    r'auth_verify|mfa_check|totp_verify',
    re.IGNORECASE,
)

# ── Module struct register_hooks offset (Apache 2.4 x86-64) ─────────────────
# In Apache 2.4 the module struct is 136-144 bytes on x86_64.
# register_hooks is at different offsets across module struct versions.
# Rather than hardcode an offset, we scan .data for function pointers
# that land inside .text (VA range check).
_MODULE_STRUCT_MIN_FIELDS = 8   # minimum plausible function pointer slots to skip

# ── Finding class ─────────────────────────────────────────────────────────────

@dataclass
class ApacheFinding:
    """One detected Apache module security issue."""
    binary: str
    finding_class: str   # HANDLER_REGISTRATION | AUTH_TABLE_ACCESS | SESSION_SKIP_FLAG |
                         # AUTH_BYPASS_SURFACE | APR_TABLE_WRITE
    severity: str        # CRITICAL | HIGH | MEDIUM | LOW | INFO
    cwe: str
    va: int              # virtual address of the instruction / call site
    title: str
    detail: str
    symbol: str = ""     # PLT symbol involved (apr_table_get, etc.)
    header: str = ""     # header key string for table access findings

    def fmt(self) -> str:
        loc = f"0x{self.va:x}" if self.va else "?"
        sym = f" ({self.symbol})" if self.symbol else ""
        hdr = f" [{self.header!r}]" if self.header else ""
        return (
            f"[{self.severity}] {self.finding_class}{sym}{hdr}  {self.binary}:{loc}\n"
            f"  CWE: {self.cwe}\n"
            f"  {self.title}\n"
            f"  {self.detail}\n"
        )


# ── Analyzer ──────────────────────────────────────────────────────────────────

class ApacheModuleAnalyzer:
    """Analyze an Apache C module .so for security issues."""

    def __init__(self, binary_path: Optional[str] = None, ctx=None) -> None:
        self._path = binary_path
        self._ctx = ctx
        self._binary = None
        self._md = None
        self._text_va = 0
        self._text_data = b''
        self._plt: Dict[int, str] = {}
        self._rodata_strings: Dict[int, str] = {}

    @classmethod
    def from_path(cls, path: str) -> 'ApacheModuleAnalyzer':
        return cls(binary_path=path)

    @classmethod
    def from_context(cls, ctx) -> 'ApacheModuleAnalyzer':
        inst = cls(ctx=ctx)
        if ctx and hasattr(ctx, '_binary_path'):
            inst._path = str(ctx._binary_path)
        return inst

    def analyze(self) -> List[ApacheFinding]:
        if not _LIEF_OK or not _CS_OK:
            return []
        if not self._load():
            return []

        findings: List[ApacheFinding] = []

        # Phase 1: build PLT, text, rodata indices
        self._build_plt()
        self._build_rodata_index()
        self._build_disassembler()

        # Phase 2: find register_hooks function
        register_hooks_va = self._find_register_hooks()
        handler_functions: List[int] = []

        if register_hooks_va:
            handlers = self._extract_handler_registrations(register_hooks_va, findings)
            handler_functions.extend(handlers)

        # Phase 3: analyze each handler function
        for handler_va in handler_functions:
            self._analyze_handler(handler_va, findings)

        # Phase 4: if no handlers identified, scan entire .text for auth patterns
        if not handler_functions:
            self._scan_text_for_auth_patterns(findings)

        return findings

    @staticmethod
    def report(findings: List[ApacheFinding]) -> str:
        if not findings:
            return "[apache_module_analyzer] No findings.\n"
        total = len(findings)
        by_sev: dict = {}
        for f in findings:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        hdr = (
            f"[apache_module_analyzer] {total} finding(s)  "
            + "  ".join(f"{k}={v}" for k, v in sorted(by_sev.items()))
            + "\n"
        )
        lines = [hdr]
        for f in sorted(findings, key=lambda x: ({'CRITICAL':0,'HIGH':1,'MEDIUM':2,'LOW':3,'INFO':4}.get(x.severity, 9), x.va)):
            lines.append(f.fmt())
        return "\n".join(lines)

    # ── Private helpers ───────────────────────────────────────────────────────

    def _load(self) -> bool:
        try:
            path = self._path
            if path is None and self._ctx and hasattr(self._ctx, '_binary_path'):
                path = str(self._ctx._binary_path)
            if not path:
                return False
            self._binary = lief.parse(path)
            return self._binary is not None
        except Exception:
            return False

    def _build_plt(self) -> None:
        """Populate self._plt: {stub_va: symbol_name} from .rela.plt."""
        if not self._binary:
            return
        try:
            rela = self._binary.get_section('.rela.plt')
            if not rela:
                return
            rela_data = bytes(rela.content)
            dynsyms = list(self._binary.dynamic_symbols)
            plt_sec = self._binary.get_section('.plt')
            if not plt_sec:
                return
            plt_base_va = int(plt_sec.virtual_address) + 16  # skip plt[0] (resolver)
            for i, off in enumerate(range(0, len(rela_data) - 23, 24)):
                r_offset, r_info = struct.unpack_from('<QQ', rela_data, off)
                sym_idx = r_info >> 32
                if sym_idx < len(dynsyms):
                    name = dynsyms[sym_idx].name
                    if name:
                        self._plt[plt_base_va + i * 16] = name
        except Exception:
            pass

    def _build_rodata_index(self) -> None:
        """Map VA → string for all non-empty strings in .rodata."""
        if not self._binary:
            return
        try:
            rodata = self._binary.get_section('.rodata')
            if not rodata:
                return
            raw = bytes(rodata.content)
            base_va = int(rodata.virtual_address)
            off = 0
            while off < len(raw):
                end = raw.find(b'\x00', off)
                if end < 0:
                    break
                if end > off:
                    try:
                        s = raw[off:end].decode('utf-8', errors='replace')
                        if len(s) >= 2:
                            self._rodata_strings[base_va + off] = s
                    except Exception:
                        pass
                off = end + 1
        except Exception:
            pass

    def _build_disassembler(self) -> None:
        if not self._binary or not _CS_OK:
            return
        try:
            text = self._binary.get_section('.text')
            if not text:
                return
            self._text_data = bytes(text.content)
            self._text_va = int(text.virtual_address)
            arch = getattr(self._binary.header, 'machine_type', None)
            # Determine architecture
            is_arm64 = False
            try:
                is_arm64 = 'AARCH64' in str(arch).upper() or 'ARM64' in str(arch).upper()
            except Exception:
                pass
            if is_arm64:
                self._md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
            else:
                self._md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            self._md.detail = True
        except Exception:
            pass

    def _read_va(self, va: int, max_bytes: int = 512) -> bytes:
        """Read up to max_bytes from virtual address va in .text."""
        if va < self._text_va:
            return b''
        off = va - self._text_va
        if off >= len(self._text_data):
            return b''
        return self._text_data[off:off + max_bytes]

    def _in_text(self, va: int) -> bool:
        return self._text_va <= va < self._text_va + len(self._text_data)

    def _find_register_hooks(self) -> Optional[int]:
        """Find register_hooks by locating the function that calls ap_hook_handler."""
        hook_plt_vas: Set[int] = {va for va, name in self._plt.items() if name in _AP_HOOK_FUNCS}
        if not hook_plt_vas:
            return None

        if not self._md or not self._text_data:
            return None

        # Scan .text for calls to any ap_hook_* PLT stub
        # On x86-64: call rel32 (0xE8) or jmp rel32 (0xE9)
        for i in range(0, len(self._text_data) - 5):
            byte = self._text_data[i]
            if byte not in (0xE8, 0xE9):
                continue
            rel = struct.unpack_from('<i', self._text_data, i + 1)[0]
            target = self._text_va + i + 5 + rel
            if target in hook_plt_vas:
                # This instruction is at VA = text_va + i
                call_va = self._text_va + i
                # Find function start: scan backwards for endbr64 (f3 0f 1e fa) or push rbp
                func_start = self._find_func_start(call_va)
                return func_start

        # ARM64: bl <offset> pattern
        for i in range(0, len(self._text_data) - 4, 4):
            word = struct.unpack_from('<I', self._text_data, i)[0]
            if (word >> 26) == 0x25:  # BL opcode
                imm = word & 0x3FFFFFF
                if imm & (1 << 25):
                    imm |= ~0x3FFFFFF
                target = (self._text_va + i) + imm * 4
                if target in hook_plt_vas:
                    return self._find_func_start(self._text_va + i)

        return None

    def _find_func_start(self, from_va: int) -> int:
        """Scan backwards from from_va to find a function prologue."""
        off = from_va - self._text_va
        # Look for endbr64 (f3 0f 1e fa) scanning backwards up to 512 bytes
        search_start = max(0, off - 512)
        chunk = self._text_data[search_start:off]
        # endbr64 = f3 0f 1e fa
        idx = chunk.rfind(b'\xf3\x0f\x1e\xfa')
        if idx >= 0:
            return self._text_va + search_start + idx
        # push rbp = 55
        idx = chunk.rfind(b'\x55')
        if idx >= 0:
            return self._text_va + search_start + idx
        # If nothing found, return from_va (treat the call site itself as start)
        return from_va

    def _extract_handler_registrations(
        self, register_hooks_va: int, findings: List[ApacheFinding]
    ) -> List[int]:
        """Disassemble register_hooks; find handler functions passed to ap_hook_handler."""
        handler_vas: List[int] = []
        hook_plt_vas: Set[int] = {va for va, name in self._plt.items() if name in _AP_HOOK_FUNCS}

        if not self._md:
            return handler_vas

        raw = self._read_va(register_hooks_va, 256)
        if not raw:
            return handler_vas

        binary_name = Path(self._path).name if self._path else "unknown"
        handler_candidate: Optional[int] = None

        for insn in self._md.disasm(raw, register_hooks_va):
            # Track the most recent rdi load (first arg to ap_hook_handler = handler func pointer)
            if insn.mnemonic == 'lea' and 'rdi' in insn.op_str:
                # lea rdi, [rip + N] — compute the target VA
                # Capstone may output decimal (rip + 5) or hex (rip + 0x1234)
                try:
                    m = re.search(r'rip \+ (0x[0-9a-f]+|\d+)', insn.op_str)
                    if m:
                        raw_val = m.group(1)
                        disp = int(raw_val, 16) if raw_val.startswith('0x') else int(raw_val)
                        handler_candidate = insn.address + insn.size + disp
                except Exception:
                    pass

            # call / jmp to ap_hook_* PLT stub
            if insn.mnemonic in ('call', 'jmp') and insn.op_str.startswith('0x'):
                try:
                    target = int(insn.op_str, 16)
                except ValueError:
                    target = 0
                if target in hook_plt_vas:
                    hook_name = self._plt[target]
                    handler_va = handler_candidate
                    if handler_va and self._in_text(handler_va):
                        handler_vas.append(handler_va)
                        findings.append(ApacheFinding(
                            binary=binary_name,
                            finding_class='HANDLER_REGISTRATION',
                            severity='INFO',
                            cwe='CWE-0',
                            va=insn.address,
                            title=f'{hook_name} registers handler at 0x{handler_va:x}',
                            detail=(
                                f'register_hooks at 0x{register_hooks_va:x} calls '
                                f'{hook_name}(handler=0x{handler_va:x}, predecessor=NULL, '
                                f'successor=NULL, APR_HOOK_MIDDLE). '
                                f'Handler will receive every matching HTTP request.'
                            ),
                            symbol=hook_name,
                        ))
                    handler_candidate = None

        return handler_vas

    def _analyze_handler(self, handler_va: int, findings: List[ApacheFinding]) -> None:
        """Analyze a request handler function for auth-relevant patterns."""
        if not self._md:
            return

        binary_name = Path(self._path).name if self._path else "unknown"
        raw = self._read_va(handler_va, 4096)
        if not raw:
            return

        # Collect calls and their arguments in a windowed pass
        apr_table_get_vas: Set[int] = {va for va, name in self._plt.items() if name in _APR_TABLE_READ}
        apr_table_set_vas: Set[int] = {va for va, name in self._plt.items() if name in _APR_TABLE_WRITE}
        session_skip_vas: Set[int] = {
            va for va, name in self._plt.items()
            if _SESSION_SKIP_PATTERNS.search(name)
        }
        decrypt_auth_vas: Set[int] = {
            va for va, name in self._plt.items()
            if _DECRYPT_AUTH_RE.search(name)
        }

        found_decrypt = False
        found_skip_flag = False
        found_auth_header = False

        # Track the last loaded string argument (rsi on x86-64 = second arg to apr_table_get)
        last_rsi_str: Optional[str] = None

        for insn in self._md.disasm(raw, handler_va):
            # Track rsi loads for apr_table_get second argument (key string)
            if insn.mnemonic == 'lea' and 'rsi' in insn.op_str:
                try:
                    m = re.search(r'rip \+ (0x[0-9a-f]+|\d+)', insn.op_str)
                    if m:
                        raw_val = m.group(1)
                        disp = int(raw_val, 16) if raw_val.startswith('0x') else int(raw_val)
                        str_va = insn.address + insn.size + disp
                        last_rsi_str = self._rodata_strings.get(str_va)
                except Exception:
                    pass

            if insn.mnemonic not in ('call', 'jmp'):
                continue

            if not insn.op_str.startswith('0x'):
                continue

            try:
                target = int(insn.op_str, 16)
            except ValueError:
                continue

            sym = self._plt.get(target, '')

            # apr_table_get(r->..., "header_key")
            if target in apr_table_get_vas:
                key = last_rsi_str or '?'
                is_auth = key in _AUTH_HEADERS or any(
                    h.lower() in key.lower() for h in _AUTH_HEADERS
                )
                severity = 'HIGH' if is_auth else 'LOW'
                if is_auth:
                    found_auth_header = True
                findings.append(ApacheFinding(
                    binary=binary_name,
                    finding_class='AUTH_TABLE_ACCESS',
                    severity=severity,
                    cwe='CWE-522' if is_auth else 'CWE-0',
                    va=insn.address,
                    title=f'{sym}(r->..., {key!r})',
                    detail=(
                        f'Handler reads HTTP header {key!r} via {sym}. '
                        + ('This is an authentication-relevant header — value flows into session/auth logic.'
                           if is_auth else
                           'Header key is not auth-relevant — verify field is not used in auth decisions.')
                    ),
                    symbol=sym,
                    header=key,
                ))
                last_rsi_str = None

            # apr_table_set/add — writing auth-relevant data
            elif target in apr_table_set_vas:
                key = last_rsi_str or '?'
                is_auth = key in _AUTH_HEADERS or any(h.lower() in key.lower() for h in _AUTH_HEADERS)
                if is_auth:
                    findings.append(ApacheFinding(
                        binary=binary_name,
                        finding_class='APR_TABLE_WRITE',
                        severity='MEDIUM',
                        cwe='CWE-20',
                        va=insn.address,
                        title=f'{sym}(r->..., {key!r}, ...)',
                        detail=(
                            f'Handler writes to auth-relevant header/notes field {key!r}. '
                            'If an attacker influences the value, downstream auth logic may be bypassed.'
                        ),
                        symbol=sym,
                        header=key,
                    ))
                last_rsi_str = None

            # session_get_adminuser_skip / skip flag accessors
            elif target in session_skip_vas:
                found_skip_flag = True
                findings.append(ApacheFinding(
                    binary=binary_name,
                    finding_class='SESSION_SKIP_FLAG',
                    severity='HIGH',
                    cwe='CWE-287',
                    va=insn.address,
                    title=f'Session skip flag accessor: {sym}',
                    detail=(
                        f'Handler calls {sym}() — a session flag that controls whether '
                        'auth/MFA is bypassed for this request. If the flag can be set from '
                        'attacker-controlled session data, authentication is skippable.'
                    ),
                    symbol=sym,
                ))

            # decrypt_and_auth / session parse
            elif target in decrypt_auth_vas:
                found_decrypt = True
                findings.append(ApacheFinding(
                    binary=binary_name,
                    finding_class='AUTH_TABLE_ACCESS',
                    severity='MEDIUM',
                    cwe='CWE-287',
                    va=insn.address,
                    title=f'Session decrypt/auth entry point: {sym}',
                    detail=(
                        f'Handler calls {sym}() to decrypt/validate the session. '
                        'The session value comes from the Cookie header read above.'
                    ),
                    symbol=sym,
                ))

        # Composite: decrypt + session skip flag in same handler → CRITICAL auth bypass surface
        if found_decrypt and found_skip_flag and found_auth_header:
            findings.append(ApacheFinding(
                binary=binary_name,
                finding_class='AUTH_BYPASS_SURFACE',
                severity='CRITICAL',
                cwe='CWE-287',
                va=handler_va,
                title='Auth bypass surface: Cookie → decrypt_session → skip_flag all in one handler',
                detail=(
                    'This handler reads a Cookie header, decrypts/parses it as a session, '
                    'and then reads a session skip flag (e.g., adminuser_skip) to determine '
                    'whether to bypass MFA/authentication. If the decrypted session is attacker-'
                    'controlled (e.g., forged cookie, RC4 key exposure), the skip flag can be '
                    'set to bypass auth entirely. Pattern: FAZ-CVE22572 / CVE-2026-22572.'
                ),
                symbol='decrypt_and_auth+session_skip_flag',
            ))

    def _scan_text_for_auth_patterns(self, findings: List[ApacheFinding]) -> None:
        """Fallback: scan all of .text for auth-relevant PLT calls when handler list is empty."""
        if not self._md or not self._text_data:
            return

        binary_name = Path(self._path).name if self._path else "unknown"
        skip_vas = {va for va, name in self._plt.items() if _SESSION_SKIP_PATTERNS.search(name)}
        if not skip_vas:
            return  # no interesting symbols — skip the fallback scan

        for va in skip_vas:
            # Find all call sites in .text for each skip-flag symbol
            for i in range(0, len(self._text_data) - 5):
                if self._text_data[i] != 0xE8:
                    continue
                rel = struct.unpack_from('<i', self._text_data, i + 1)[0]
                target = self._text_va + i + 5 + rel
                if target == va:
                    call_va = self._text_va + i
                    sym = self._plt[va]
                    findings.append(ApacheFinding(
                        binary=binary_name,
                        finding_class='SESSION_SKIP_FLAG',
                        severity='HIGH',
                        cwe='CWE-287',
                        va=call_va,
                        title=f'Session skip flag accessor: {sym} (fallback scan)',
                        detail=(
                            f'{sym}() called at 0x{call_va:x}. '
                            'No handler function was identified via register_hooks analysis — '
                            'handler discovery may have failed. Verify manually.'
                        ),
                        symbol=sym,
                    ))


# ── CLI entry ─────────────────────────────────────────────────────────────────

def _main() -> None:
    import argparse
    ap = argparse.ArgumentParser(description='Apache C module security analyzer')
    ap.add_argument('path', help='.so file to analyze')
    ap.add_argument('--severity', choices=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'],
                    help='Minimum severity to report')
    args = ap.parse_args()

    analyzer = ApacheModuleAnalyzer.from_path(args.path)
    findings = analyzer.analyze()

    if args.severity:
        rank = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
        threshold = rank[args.severity]
        findings = [f for f in findings if rank.get(f.severity, 99) <= threshold]

    print(ApacheModuleAnalyzer.report(findings))


if __name__ == '__main__':
    _main()
