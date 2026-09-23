"""
preauth_route_auditor.py -- FortiManager flatui pre-auth route scanner.

Automates the manual 4-step process:
  1. Scan route init function for WorkflowLockWithoutSessionPermit-only routes
  2. Extract handler class names for those routes
  3. Cross-reference handler factories to find GET/POST handler VAs
  4. Run FuncProfiler on each handler to surface sinks

Designed for FortiManager 8.0.0 libfmgd.so but parameterized for other
flatui-based binaries.

Usage:
    from ablation.analyzers.preauth_route_auditor import PreAuthRouteAuditor

    auditor = PreAuthRouteAuditor.from_path('/tmp/fmg800_libs/libfmgd.so')
    results = auditor.run(
        route_init_va=0x27b324,
        route_init_end_va=0x288d50,
        factory_va=0x2a5000,
        factory_end_va=0x2b0000,
    )
    print(results.fmt())
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import capstone
from capstone.x86_const import X86_OP_MEM, X86_REG_RIP

from .binary_context import BinaryContext
from .func_profiler import FuncProfiler, FuncProfile

# flatui route registration call targets (FMG 8.0.0 libfmgd.so defaults)
_ROUTE_URL_REGISTER  = 0x27b12a  # call: route URL or handler name
_METHOD_LIST_INIT    = 0x27b1ca  # call: method list vector init
_MIDDLEWARE_BUILD_A  = 0x25acf0  # call: build middleware string (prefix + suffix)
_MIDDLEWARE_BUILD_B  = 0x251430  # call: append to middleware string
_ROUTE_COPY_CTOR     = 0x260530  # call: RouteResourceConfig copy constructor

# Handler factory registration calls
_GET_REGISTER   = 0x24f900   # call: register GET handler (rdx = handler fn VA)
_POST_REGISTER  = 0x268b50   # call: register POST handler (rdx = handler fn VA)
_PUT_REGISTER   = 0x265720   # placeholder -- update if found
_DEL_REGISTER   = 0x25e5f0   # placeholder -- update if found

WLWSP = 'WorkflowLockWithoutSessionPermit'


@dataclass
class RouteEntry:
    """One route found in the route init scan."""
    url: str = ''
    handler: str = ''
    middleware: str = ''
    method_ids: List[int] = field(default_factory=list)
    url_reg_va: int = 0
    handler_reg_va: int = 0
    middleware_va: int = 0
    is_preauth: bool = False

    def fmt(self) -> str:
        tag = '[PRE-AUTH]' if self.is_preauth else '[AUTH]'
        return (
            f"{tag} {self.url!r:60s}"
            f"  handler={self.handler}  methods={self.method_ids}"
            f"  mw={self.middleware[:60]}"
        )


@dataclass
class HandlerEntry:
    """One handler found in the factory scan."""
    class_name: str = ''
    get_va: int = 0
    post_va: int = 0
    put_va: int = 0
    del_va: int = 0
    get_profile: Optional[FuncProfile] = None
    post_profile: Optional[FuncProfile] = None

    def fmt(self) -> str:
        lines = [f"  Handler: {self.class_name}"]
        for method, va, profile in [
            ('GET',  self.get_va,  self.get_profile),
            ('POST', self.post_va, self.post_profile),
        ]:
            if va:
                sink_str = ''
                if profile and profile.sink_calls:
                    sinks = ', '.join(f"{s.target_name}@0x{s.site_va:x}" for s in profile.sink_calls)
                    sink_str = f"  *** SINKS: {sinks} ***"
                lines.append(f"    {method} @ 0x{va:x}{sink_str}")
        return '\n'.join(lines)


@dataclass
class PreAuthAuditResult:
    routes: List[RouteEntry] = field(default_factory=list)
    preauth_routes: List[RouteEntry] = field(default_factory=list)
    handlers: Dict[str, HandlerEntry] = field(default_factory=dict)

    def fmt(self) -> str:  # noqa: E501
        lines = [
            f"=== PreAuthRouteAuditor Results ===",
            f"  Total routes scanned:  {len(self.routes)}",
            f"  Pre-auth routes found: {len(self.preauth_routes)}",
            '',
        ]
        lines.append("--- Pre-auth routes ---")
        for r in self.preauth_routes:
            lines.append(f"  {r.url!r}")
            lines.append(f"    handler={r.handler}  middleware={r.middleware[:60]}")
            entry = self.handlers.get(r.handler)
            if entry:
                lines.append(entry.fmt())
            lines.append('')
        return '\n'.join(lines)

    def preauth_with_sinks(self) -> List[Tuple[RouteEntry, HandlerEntry]]:  # noqa: E501
        out = []
        for r in self.preauth_routes:
            entry = self.handlers.get(r.handler)
            if entry and (
                (entry.get_profile and entry.get_profile.sink_calls) or
                (entry.post_profile and entry.post_profile.sink_calls)
            ):
                out.append((r, entry))
        return out


class PreAuthRouteAuditor:
    """
    Scans a flatui-based binary for pre-auth routes and profiles their handlers.
    """

    def __init__(self, binary_path: str):
        self.path = binary_path
        self.ctx = BinaryContext.load_or_build(binary_path)
        self.fp = FuncProfiler.from_context(self.ctx, custom_sinks={
            'fm_exec_pipe':  'cmd-exec',
            'fm_exec_cli':   'cmd-exec',
            'system':        'cmd-exec',
            'popen':         'cmd-exec',
            'execv':         'cmd-exec',
            'execvp':        'cmd-exec',
            'unlink':        'filesystem',
            'rename':        'filesystem',
        })
        with open(binary_path, 'rb') as f:
            self.data = f.read()
        self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self.md.detail = True

    @classmethod
    def from_path(cls, binary_path: str) -> 'PreAuthRouteAuditor':
        return cls(binary_path)

    def _get_str(self, va: int) -> str:
        if 0 <= va < len(self.data):
            end = self.data.find(b'\x00', va)
            try:
                return self.data[va:end].decode('utf-8', errors='replace')
            except Exception:
                return ''
        return ''

    def _is_rodata(self, va: int) -> bool:
        return 0x5ec000 <= va <= 0x760000

    def _rip_ref(self, insn) -> Optional[int]:
        for op in insn.operands:
            if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                return insn.address + insn.size + op.mem.disp
        return None

    def scan_routes(
        self,
        route_init_va: int,
        route_init_end_va: int,
        url_register_va: int = _ROUTE_URL_REGISTER,
        method_init_va: int = _METHOD_LIST_INIT,
        mw_build_a: int = _MIDDLEWARE_BUILD_A,
        mw_build_b: int = _MIDDLEWARE_BUILD_B,
        wlwsp_bss_va: Optional[int] = None,
    ) -> List[RouteEntry]:
        """
        Scan the route init function and return all RouteEntry objects.

        Pattern per route block (in order):
          1. LEA rsi -> route URL string + call url_register_va
          2. mov/lea to set up method list + call method_init_va (or copy ctor)
          3. LEA rsi -> handler class name + call url_register_va
          4. LEA rsi -> 'WorkflowLockWithoutSessionPermit,...' + call mw_build_a/b
             OR: mov rsi, r13 (BSS reg holding WLWSP at runtime) + call mw_build_a

        The wlwsp_bss_va parameter identifies the BSS address that holds the
        WorkflowLockWithoutSessionPermit prefix at runtime. When this address
        is used as rsi in a middleware build call, the route is pre-auth.

        If wlwsp_bss_va is None, auto-detect it from the first large-BSS LEA
        in the first 256 bytes of the function (FMG 8.0.0 pattern: r13 at
        function start holds the WLWSP BSS addr).
        """
        data = self.data
        md = self.md

        size = route_init_end_va - route_init_va
        if size <= 0 or size > 4 * 1024 * 1024:
            return []

        # Auto-detect WLWSP BSS variable from function prologue
        # Pattern: lea rXX, [rip + large_offset] where target > 0x1000000 from code
        if wlwsp_bss_va is None:
            bss_regs: Dict[str, int] = {}
            prologue_end = route_init_va + 256
            for insn in md.disasm(data[route_init_va:route_init_va + 256], route_init_va):
                if insn.address >= prologue_end:
                    break
                if insn.mnemonic == 'lea':
                    ref = self._rip_ref(insn)
                    if ref is not None and ref > 0x1000000 and not self._is_rodata(ref):
                        # Extract destination register name
                        dest = insn.op_str.split(',')[0].strip()
                        if dest not in bss_regs:
                            bss_regs[dest] = ref
                            # The FIRST such BSS register is typically the WLWSP prefix
                            if len(bss_regs) == 1:
                                wlwsp_bss_va = ref

        entries: List[RouteEntry] = []
        current = RouteEntry()

        # Track register values for middleware string detection
        last_lea_rsi_str: str = ''
        last_lea_rsi_va:  int  = 0
        pending_methods: List[int] = []
        method_count: int = 0

        # Register aliasing: track which register holds which BSS/string value
        # reg_bss: reg_name -> bss_va
        reg_bss: Dict[str, int] = {}
        # reg_str: reg_name -> rodata string value
        reg_str: Dict[str, str] = {}
        # rsi_from_reg: tracks if rsi was set via mov rsi, rXX
        rsi_from_reg: Optional[str] = None

        insns = list(md.disasm(data[route_init_va:route_init_va + size], route_init_va))

        i = 0
        while i < len(insns):
            insn = insns[i]
            op = insn.op_str

            # Track ALL lea rXX -> BSS or rodata (register aliasing)
            if insn.mnemonic == 'lea':
                ref = self._rip_ref(insn)
                if ref is not None:
                    dest = insn.op_str.split(',')[0].strip()
                    if self._is_rodata(ref):
                        s = self._get_str(ref)
                        reg_str[dest] = s
                        if 'rsi' in dest:
                            last_lea_rsi_str = s
                            last_lea_rsi_va  = insn.address
                            rsi_from_reg = None
                    elif ref > 0x1000000:
                        reg_bss[dest] = ref
                        if 'rsi' in dest:
                            last_lea_rsi_str = ''
                            rsi_from_reg = None

            # Track mov rsi, rXX (register alias -- rsi gets value from another reg)
            if insn.mnemonic == 'mov' and op.startswith('rsi, '):
                src = op.split(', ', 1)[1].strip()
                if not src.startswith('0x') and not src.startswith('[') and 'ptr' not in src:
                    # Src is a plain register name
                    rsi_from_reg = src
                    last_lea_rsi_str = reg_str.get(src, '')

            # Track method ID initializations: mov dword ptr [rsp+N], <id>
            if insn.mnemonic == 'mov' and 'dword ptr' in op and 'rsp' in op:
                # Extract immediate value
                parts = op.split(', ')
                if len(parts) == 2:
                    try:
                        method_id = int(parts[1].strip(), 16 if '0x' in parts[1] else 10)
                        if 0 < method_id < 0x20:
                            pending_methods.append(method_id)
                    except (ValueError, IndexError):
                        pass

            # Track count register for method list: mov edx, N
            if insn.mnemonic == 'mov' and 'edx' in op and not 'ptr' in op:
                try:
                    count = int(op.split(', ')[1], 16 if '0x' in op else 10)
                    if 1 <= count <= 10:
                        method_count = count
                except (ValueError, IndexError):
                    pass

            # Detect call targets
            if insn.mnemonic == 'call' and op.startswith('0x'):
                target = int(op, 16)

                if target == url_register_va:
                    # Could be URL registration or handler name registration
                    s = last_lea_rsi_str
                    if not s:
                        i += 1
                        continue

                    if s.startswith('/'):
                        # It's a URL -- start a new route entry
                        if current.url:
                            # Commit previous entry if it has both URL and handler
                            if current.handler:
                                current.is_preauth = WLWSP in current.middleware
                                entries.append(current)
                        current = RouteEntry(
                            url=s,
                            url_reg_va=insn.address,
                        )
                        pending_methods = []
                        method_count = 0
                    else:
                        # It's a handler class name
                        if current.url and not current.handler:
                            current.handler = s
                            current.handler_reg_va = insn.address
                            if pending_methods:
                                current.method_ids = pending_methods[:method_count or len(pending_methods)]

                elif target == method_init_va:
                    # Method list finalized -- methods already in pending_methods
                    if current.url and not current.handler:
                        current.method_ids = pending_methods[:method_count or len(pending_methods)]

                elif target in (mw_build_a, mw_build_b):
                    # Middleware string build -- rsi may come from a direct LEA
                    # or from a BSS register alias (mov rsi, r13 where r13=WLWSP BSS)
                    if current.url and current.handler:
                        mw_str = last_lea_rsi_str

                        # BSS register aliasing: check if rsi was set via mov rsi, rXX
                        # and rXX holds the WLWSP BSS address
                        if not mw_str and rsi_from_reg is not None:
                            bss_val = reg_bss.get(rsi_from_reg)
                            if wlwsp_bss_va is not None and bss_val == wlwsp_bss_va:
                                mw_str = WLWSP
                            elif rsi_from_reg in reg_str:
                                mw_str = reg_str[rsi_from_reg]

                        if not current.middleware:
                            current.middleware = mw_str
                            current.middleware_va = insn.address
                        else:
                            current.middleware += mw_str

            i += 1

        # Commit last entry
        if current.url and current.handler:
            current.is_preauth = WLWSP in current.middleware
            entries.append(current)

        return entries

    def scan_factory(
        self,
        factory_va: int,
        factory_end_va: int,
        get_reg_va: int = _GET_REGISTER,
        post_reg_va: int = _POST_REGISTER,
    ) -> Dict[str, HandlerEntry]:
        """
        Scan the handler factory region for GET/POST handler registrations.

        Pattern per handler block:
          1. LEA rbp/rsi -> handler class name (rodata)
          2. call allocator + call 0x412ee6 (handler name registration)
          3. LEA rdx -> code VA (handler function)
          4. call get_reg_va  OR  call post_reg_va
        """
        data = self.data
        md = self.md

        size = factory_end_va - factory_va
        if size <= 0 or size > 2 * 1024 * 1024:
            return {}

        handlers: Dict[str, HandlerEntry] = {}
        insns = list(md.disasm(data[factory_va:factory_va + size], factory_va))

        current_name: str = ''
        pending_code_va: int = 0

        for insn in insns:
            op = insn.op_str

            # LEA rdx -> code VA (handler function pointer)
            if insn.mnemonic == 'lea' and 'rdx' in op:
                ref = self._rip_ref(insn)
                if ref is not None and 0x24f000 <= ref <= 0x5ec000:
                    pending_code_va = ref

            # LEA rsi/rbp -> handler class name (rodata string)
            if insn.mnemonic == 'lea' and ('rsi' in op or 'rbp' in op):
                ref = self._rip_ref(insn)
                if ref is not None and self._is_rodata(ref):
                    s = self._get_str(ref)
                    # Handler class names: UpperCamelCase, len > 4, no spaces, no '/'
                    if s and len(s) > 4 and s[0].isupper() and ' ' not in s and '/' not in s and ',' not in s:
                        current_name = s
                        if current_name not in handlers:
                            handlers[current_name] = HandlerEntry(class_name=current_name)

            # call get_reg_va -- register GET handler
            if insn.mnemonic == 'call' and op == f'0x{get_reg_va:x}':
                if current_name and pending_code_va:
                    entry = handlers.setdefault(current_name, HandlerEntry(class_name=current_name))
                    if not entry.get_va:
                        entry.get_va = pending_code_va
                    pending_code_va = 0

            # call post_reg_va -- register POST handler
            if insn.mnemonic == 'call' and op == f'0x{post_reg_va:x}':
                if current_name and pending_code_va:
                    entry = handlers.setdefault(current_name, HandlerEntry(class_name=current_name))
                    if not entry.post_va:
                        entry.post_va = pending_code_va
                    pending_code_va = 0

        return handlers

    def profile_handlers(
        self,
        handlers: Dict[str, HandlerEntry],
        handler_names: Optional[Set[str]] = None,
    ) -> Dict[str, HandlerEntry]:
        """
        Run FuncProfiler on GET/POST VAs for the specified handlers.
        If handler_names is None, profiles all handlers.
        """
        for name, entry in handlers.items():
            if handler_names is not None and name not in handler_names:
                continue
            if entry.get_va:
                try:
                    entry.get_profile = self.fp.profile(va=entry.get_va)
                except Exception:
                    pass
            if entry.post_va:
                try:
                    entry.post_profile = self.fp.profile(va=entry.post_va)
                except Exception:
                    pass
        return handlers

    def run(
        self,
        route_init_va: int,
        route_init_end_va: int,
        factory_va: int,
        factory_end_va: int,
        profile_preauth_only: bool = True,
    ) -> PreAuthAuditResult:
        """
        Full audit: scan routes, find factories, profile handlers.
        """
        result = PreAuthAuditResult()

        # Step 1: scan all routes
        result.routes = self.scan_routes(route_init_va, route_init_end_va)
        result.preauth_routes = [r for r in result.routes if r.is_preauth]

        # Step 2: scan factory for all handlers
        result.handlers = self.scan_factory(factory_va, factory_end_va)

        # Step 3: profile handlers for pre-auth routes only (or all)
        if profile_preauth_only:
            preauth_handler_names = {r.handler for r in result.preauth_routes}
        else:
            preauth_handler_names = None

        self.profile_handlers(result.handlers, preauth_handler_names)

        return result
