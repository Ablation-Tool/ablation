"""
priv_drop_before_exec.py: Detect privilege-drop-before-exec pattern in SETUID binaries.

Why this exists
---------------
Gap discovered during HMC rnvi analysis (session 53, 2026-10-23):
  rnvi (SETUID root) calls setreuid(-1, getuid()) immediately before execv("/bin/vi").
  This is the SAFE pattern for a restricted-editor wrapper: root is dropped before
  the editor is exec'd, so vi runs as the calling user.

  SAC marks the execv path as UNKNOWN because the path is computed at runtime
  (movabs into stack buffer), requiring 15 minutes of manual disasm to confirm
  ELIMINATED.  The privilege-drop signal — setreuid(-1, getuid()) — makes this
  classification trivially automatable.

The pattern
-----------
  Within a single function, in order:
    1. call getuid()               — capture real UID
    2. store result in a stack slot
    3. call setuid/seteuid/setreuid with arg = getuid result  (drops to caller's UID)
    4. call exec*()                — child runs as calling user, NOT root

  Key distinction from SetuidBeforeForkAnalyzer:
    - SetuidBeforeForkAnalyzer looks for setuid(0) → escalation
    - This analyzer looks for setuid(getuid()) → safe drop

  Detection heuristic: scan backwards from setuid/setreuid call site; if the
  edi/rdi argument comes from a register previously loaded with the return
  value of getuid(), classify as privilege-drop.

Verdict: NOT_EXPLOITABLE when the drop immediately precedes exec with no
re-escalation between the drop and the exec.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

import capstone

from ablation.analyzers.binary_context import BinaryContext

_SETUID_FUNCS = {'setuid', 'seteuid', 'setreuid'}
_EXEC_FUNCS   = {'execv', 'execve', 'execvp', 'execvpe', 'execl', 'execlp', 'execle'}
_UID_FUNCS    = {'getuid', 'geteuid'}


@dataclass
class PrivDropFinding:
    func_va: int
    getuid_va: int
    getuid_name: str       # 'getuid' or 'geteuid'
    drop_va: int
    drop_name: str         # 'setuid', 'seteuid', or 'setreuid'
    exec_va: int
    exec_name: str
    reescalation: bool     # True if another setuid(non-getuid-result) appears between drop and exec
    verdict: str           # 'NOT_EXPLOITABLE' or 'PLAUSIBLE_DROP'
    note: str

    def __str__(self) -> str:
        return (
            f"PrivDropFinding({self.verdict}): "
            f"func@{hex(self.func_va)} | "
            f"{self.getuid_name}()@{hex(self.getuid_va)} → "
            f"{self.drop_name}(getuid_result)@{hex(self.drop_va)} → "
            f"{self.exec_name}()@{hex(self.exec_va)}"
        )


class PrivilegeDropBeforeExecAnalyzer:
    """
    Detects SETUID binaries that drop root to the calling user's UID before
    exec, making the exec NOT_EXPLOITABLE for privilege escalation.
    """

    def __init__(self, ctx: BinaryContext) -> None:
        self._ctx  = ctx
        self._data = open(ctx.path, 'rb').read()
        self._base = ctx.base_va
        self._plt: Dict[str, int] = {
            name: va for va, name in ctx.plt.items()
            if name in (*_SETUID_FUNCS, *_EXEC_FUNCS, *_UID_FUNCS)
        }

    @classmethod
    def from_path(cls, path: str) -> PrivilegeDropBeforeExecAnalyzer:
        return cls(BinaryContext.load_or_build(path))

    @classmethod
    def from_context(cls, ctx: BinaryContext) -> PrivilegeDropBeforeExecAnalyzer:
        return cls(ctx)

    def _plt_name(self, va: int) -> Optional[str]:
        for name, plt_va in self._plt.items():
            if plt_va == va:
                return name
        return None

    def _disasm_func(self, func_va: int, max_bytes: int = 2048) -> List:
        arch = self._ctx.arch
        if arch == 'x86_64':
            cs_arch, cs_mode = capstone.CS_ARCH_X86, capstone.CS_MODE_64
        elif arch == 'x86':
            cs_arch, cs_mode = capstone.CS_ARCH_X86, capstone.CS_MODE_32
        else:
            return []
        off = func_va - self._base
        if off < 0 or off >= len(self._data):
            return []
        md = capstone.Cs(cs_arch, cs_mode)
        md.detail = True
        return list(md.disasm(self._data[off:off + max_bytes], func_va))

    def _resolve_call(self, insn) -> Optional[int]:
        try:
            return int(insn.op_str.strip(), 16)
        except ValueError:
            return None

    # x86 register families: writing any member kills all aliases
    _REG_FAM: Dict[str, str] = {
        n: f for f, ns in {
            'a':  ['al','ah','ax','eax','rax'],
            'b':  ['bl','bh','bx','ebx','rbx'],
            'c':  ['cl','ch','cx','ecx','rcx'],
            'd':  ['dl','dh','dx','edx','rdx'],
            'si': ['sil','si','esi','rsi'],
            'di': ['dil','di','edi','rdi'],
            'sp': ['spl','sp','esp','rsp'],
            'bp': ['bpl','bp','ebp','rbp'],
        }.items() for n in ns
    }

    def _arg_is_from_getuid(self, insns: List, uid_idx: int, call_idx: int) -> bool:
        """
        Forward-pass taint tracker from uid_idx to call_idx.

        Starts after the uid call (getuid/geteuid) at uid_idx with 'a' family
        tainted.  On subsequent uid calls, also adds 'a' (they also return a
        uid value).  On all other calls, discards 'a'.

        Returns True if edi/esi/rdi/rsi holds a uid-derived value at call_idx.

        Forward pass is required: a backward scan sees 'mov edi, eax' before
        'mov eax, [struct+0x10]', which would falsely conclude eax still holds
        the getuid result (the hscdc false-positive pattern).
        """
        tainted: Set[str] = {'a'}
        tainted_slots: Set[str] = set()

        for i in range(uid_idx + 1, call_idx):
            pi = insns[i]
            if pi.mnemonic == 'call':
                t = self._resolve_call(pi)
                if t and self._plt_name(t) in _UID_FUNCS:
                    tainted.add('a')     # uid function — eax holds uid result
                else:
                    tainted.discard('a') # other call clobbers rax
                continue
            if pi.mnemonic != 'mov':
                continue
            parts = [p.strip() for p in pi.op_str.split(',')]
            if len(parts) != 2:
                continue
            dst, src = parts

            dst_fam = self._REG_FAM.get(dst)
            src_fam = self._REG_FAM.get(src)

            src_tainted = (
                (src_fam is not None and src_fam in tainted) or
                src in tainted_slots
            )

            if dst_fam is not None:
                if src_tainted:
                    tainted.add(dst_fam)
                else:
                    tainted.discard(dst_fam)
            elif '[' in dst:
                if src_tainted:
                    tainted_slots.add(dst)
                else:
                    tainted_slots.discard(dst)

        return bool(tainted & {'di', 'si'})

    def _scan_func(self, func_va: int) -> List[PrivDropFinding]:
        insns = self._disasm_func(func_va)
        if not insns:
            return []

        findings = []
        # (va, name, insn_idx) — idx needed for forward-pass taint analysis
        getuid_events: List[Tuple[int, str, int]] = []
        drop_events: List[Tuple[int, str, int]] = []   # (va, name, insn_idx)

        for i, insn in enumerate(insns):
            if insn.mnemonic != 'call':
                continue
            target = self._resolve_call(insn)
            if target is None:
                continue
            name = self._plt_name(target)
            if name is None:
                continue

            if name in _UID_FUNCS:
                getuid_events.append((insn.address, name, i))

            elif name in _SETUID_FUNCS and getuid_events:
                # Forward-pass from earliest uid call that could taint edi/esi
                uid_va, uid_name, uid_idx = getuid_events[0]
                if self._arg_is_from_getuid(insns, uid_idx, i):
                    drop_events.append((insn.address, name, i))

            elif name in _EXEC_FUNCS and getuid_events and drop_events:
                # Privilege was dropped (setuid(getuid())) before this exec
                # Check if any re-escalation happened between last drop and exec
                last_drop_va, _, last_drop_idx = drop_events[-1]
                reescalation = False
                for j in range(last_drop_idx + 1, i):
                    pinsn = insns[j]
                    if pinsn.mnemonic != 'call':
                        continue
                    pt = self._resolve_call(pinsn)
                    if pt and self._plt_name(pt) in _SETUID_FUNCS:
                        # Another setuid after the drop — check if it's also a drop
                        uid_va, uid_name, uid_idx = getuid_events[0]
                        if not self._arg_is_from_getuid(insns, uid_idx, j):
                            reescalation = True
                            break

                uid_va, uid_name, _ = getuid_events[-1]
                drop_va, drop_name, _ = drop_events[-1]

                verdict = 'NOT_EXPLOITABLE' if not reescalation else 'PLAUSIBLE_DROP'
                note = (
                    f'{drop_name}(getuid()) before {name}() — exec runs as calling user, not root'
                    if not reescalation else
                    f'{drop_name}(getuid()) seen but re-escalation possible before exec'
                )

                findings.append(PrivDropFinding(
                    func_va=func_va,
                    getuid_va=uid_va,
                    getuid_name=uid_name,
                    drop_va=drop_va,
                    drop_name=drop_name,
                    exec_va=insn.address,
                    exec_name=name,
                    reescalation=reescalation,
                    verdict=verdict,
                    note=note,
                ))

        return findings

    def scan(self) -> List[PrivDropFinding]:
        """
        Scan all functions in the binary for privilege-drop-before-exec.
        """
        if not self._plt:
            return []
        has_uid  = any(n in self._plt for n in _UID_FUNCS)
        has_drop = any(n in self._plt for n in _SETUID_FUNCS)
        has_exec = any(n in self._plt for n in _EXEC_FUNCS)
        if not (has_uid and has_drop and has_exec):
            return []

        all_starts = sorted(self._ctx.func_starts)
        seen: Set[Tuple[int, int, int]] = set()
        results: List[PrivDropFinding] = []

        for va in self._ctx.func_starts:
            for f in self._scan_func(va):
                key = (f.drop_va, f.exec_va)
                if key not in seen:
                    seen.add(key)
                    # Correct func_va to enclosing function
                    for s in all_starts:
                        if s <= f.drop_va:
                            f.func_va = s
                    results.append(f)
        return results
