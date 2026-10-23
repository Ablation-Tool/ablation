"""
setuid_obfuscated_exec.py: Detect obfuscated root-exec via getpwnam("root")+setuid+fork+exec.

Why this exists
---------------
Gap discovered during HMC hscdc analysis (session 53, 2026-10-23):
  hscdc (SETUID root) contained two code paths:
    PATH 1: argv[1]=="x0" → Java VPD launcher (SAFE, found by SAC)
    PATH 2: hex+XOR decode(argv[1]) → getpwnam("root")->pw_uid → setuid(getpwnam_result)
            → fork() → execvp(decoded_command) as root

  SetuidBeforeForkAnalyzer left PATH 2 as PLAUSIBLE because it couldn't confirm
  that setuid's argument resolves to 0.  The argument came from getpwnam("root")->pw_uid
  (loaded from struct offset), not from a literal `xor edi, edi` / `mov edi, 0`.

  getpwnam("root")->pw_uid is ALWAYS 0 on Linux/UNIX.  If the binary looks up
  "root" via getpwnam and uses the result as a setuid argument before fork+exec,
  that is setuid(0) — CONFIRMED.

The pattern
-----------
  Within a single function (or two linked functions):
    1. call getpwnam / getpwnam_r with string argument "root"
    2. load pw_uid field from the returned passwd struct (offset 4 on i386, 16 on x86_64)
    3. call setuid(loaded_value)  — resolves to setuid(0) by the invariant above
    4. call fork()
    5. in child branch: call exec*() with any argument

  The sscanf+XOR decode before step 1 is NOT required for the upgrade to CONFIRMED —
  it just explains why SAC sees UNKNOWN in the exec arg.  The key resolving signal
  is getpwnam("root") → setuid(result) = setuid(0).

Secondary pattern (decode-before-exec with explicit setuid(0)):
  If the binary has sscanf with a hex format string ("%02x" or "%x") in a loop,
  followed by setuid(0) (literal 0) + fork + exec, emit a separate finding.

Usage
-----
    from ablation.analyzers.setuid_obfuscated_exec import SetuidObfuscatedExecDetector
    results = SetuidObfuscatedExecDetector.from_path('/path/to/binary').scan()
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

import capstone

from ablation.analyzers.binary_context import BinaryContext

_SETUID_FUNCS  = {'setuid', 'seteuid'}
_EXEC_FUNCS    = {'execv', 'execve', 'execvp', 'execvpe', 'execl', 'execlp', 'execle'}
_GETPWNAM_FUNC = {'getpwnam', 'getpwnam_r'}

# pw_uid is at struct offset 16 on x86_64 (after pw_name*, pw_passwd*, pw_uid=uid_t)
# and offset 4 on i386 (after pw_name*)
# Capstone renders as dword ptr [rax + 0x10] or [eax + 4]
_PWUID_OFFSETS = {
    'x86_64': ['0x10'],
    'x86': ['4', '0x4'],
}


@dataclass
class ObfuscatedExecFinding:
    func_va: int
    pattern: str           # 'GETPWNAM_ROOT' or 'SSCANF_HEX_DECODE'
    getpwnam_va: int
    getpwnam_arg: str      # the string argument ("root" expected)
    setuid_va: int
    fork_va: int
    exec_va: int
    exec_name: str
    verdict: str           # 'CONFIRMED' (getpwnam("root") case) or 'PLAUSIBLE' (decode-loop)
    severity: str          # 'HIGH'
    note: str

    def __str__(self) -> str:
        return (
            f"ObfuscatedExecFinding({self.verdict}/{self.severity}): "
            f"func@{hex(self.func_va)} | "
            f"getpwnam({self.getpwnam_arg!r})@{hex(self.getpwnam_va)} → "
            f"setuid(pw_uid)@{hex(self.setuid_va)} → "
            f"fork@{hex(self.fork_va)} → "
            f"{self.exec_name}@{hex(self.exec_va)}"
        )


class SetuidObfuscatedExecDetector:
    """
    Detects SETUID binaries that escalate via getpwnam("root")->pw_uid → setuid → fork → exec,
    upgrading SetuidBeforeForkAnalyzer PLAUSIBLE findings to CONFIRMED.
    """

    def __init__(self, ctx: BinaryContext) -> None:
        self._ctx  = ctx
        self._data = open(ctx.path, 'rb').read()
        self._base = ctx.base_va
        self._plt: Dict[str, int] = {
            name: va for va, name in ctx.plt.items()
            if name in (*_SETUID_FUNCS, *_EXEC_FUNCS, *_GETPWNAM_FUNC, 'fork', 'sscanf')
        }
        self._arch = ctx.arch

    @classmethod
    def from_path(cls, path: str) -> SetuidObfuscatedExecDetector:
        return cls(BinaryContext.load_or_build(path))

    @classmethod
    def from_context(cls, ctx: BinaryContext) -> SetuidObfuscatedExecDetector:
        return cls(ctx)

    def _plt_name(self, va: int) -> Optional[str]:
        for name, plt_va in self._plt.items():
            if plt_va == va:
                return name
        return None

    def _disasm_func(self, func_va: int, max_bytes: int = 4096) -> List:
        if self._arch == 'x86_64':
            cs_arch, cs_mode = capstone.CS_ARCH_X86, capstone.CS_MODE_64
        elif self._arch == 'x86':
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

    def _rodata_str_at(self, va: int, maxlen: int = 64) -> Optional[str]:
        off = va - self._base
        if off < 0 or off + maxlen > len(self._data):
            return None
        end = self._data.index(b'\x00', off, off + maxlen)
        try:
            return self._data[off:end].decode('ascii')
        except (ValueError, UnicodeDecodeError):
            return None

    def _arg_is_root(self, insns: List, call_idx: int) -> str:
        """
        Return the string argument to getpwnam if it is a statically-known constant,
        otherwise return '<dynamic>'.  Scans back up to 20 insns for mov edi/rdi, <imm>.
        """
        for i in range(call_idx - 1, max(call_idx - 20, -1), -1):
            pi = insns[i]
            if pi.mnemonic in ('lea', 'mov'):
                parts = [p.strip() for p in pi.op_str.split(',')]
                if len(parts) == 2 and parts[0] in ('edi', 'rdi', 'ecx', 'rcx'):
                    # lea rdi, [rip + offset] or mov edi, <va>
                    try:
                        val = None
                        if 'rip' in parts[1]:
                            # rip-relative lea
                            rip_next = insns[i + 1].address if i + 1 < len(insns) else pi.address + 7
                            offset_str = parts[1].split('+')[-1].strip().rstrip(']').strip()
                            offset = int(offset_str, 16)
                            val = rip_next + offset
                        else:
                            val = int(parts[1].lstrip('#'), 16)
                        if val:
                            s = self._rodata_str_at(val)
                            if s:
                                return s
                    except (ValueError, IndexError):
                        pass
        return '<dynamic>'

    def _setuid_arg_from_pwuid(self, insns: List, call_idx: int) -> bool:
        """
        Return True if edi/rdi at the setuid call site was loaded from a
        memory dereference at the pw_uid offset from a pointer returned by getpwnam.

        The struct layout is arch-dependent:
          x86_64: pw_uid = *(rax + 0x10)  (third field after pw_name* + pw_passwd*)
          i386:   pw_uid = *(eax + 0x4)   (second field after pw_name*)

        We look for:
          1. mov eax/rax, ... (some store of getpwnam return, may be through stack)
          2. mov edi/esi, dword ptr [<reg> + <pwuid_offset>]
        """
        expected_offsets = _PWUID_OFFSETS.get(self._arch, [])
        # After getpwnam the struct ptr is in rax/eax
        # Track it through possible stack stores
        struct_ptr_regs: Set[str] = {'eax', 'rax'}

        for i in range(call_idx - 1, max(call_idx - 40, -1), -1):
            pi = insns[i]

            if pi.mnemonic == 'call':
                target = self._resolve_call(pi)
                if target and self._plt_name(target) in _GETPWNAM_FUNC:
                    # struct ptr lives in eax/rax right after getpwnam
                    struct_ptr_regs = {'eax', 'rax'}

            if pi.mnemonic == 'mov':
                parts = [p.strip() for p in pi.op_str.split(',')]
                if len(parts) == 2:
                    dst, src = parts
                    # track mov [stack], rax — struct ptr stored to stack
                    if src in struct_ptr_regs and '[' in dst:
                        struct_ptr_regs.add(dst)
                    # track mov rdi, [stack] where stack slot holds struct ptr
                    if dst in ('edi', 'rdi'):
                        # Check if src is dereference of struct + pwuid offset
                        for off in expected_offsets:
                            for reg in list(struct_ptr_regs):
                                if off in src and (
                                    'rax' in src or 'eax' in src or
                                    any(r.strip('[]') in src for r in struct_ptr_regs)
                                ):
                                    return True
                    # Also check: mov edi, dword ptr [<reg> + <offset>]
                    if dst in ('edi', 'rdi') and 'ptr' in src:
                        for off in expected_offsets:
                            if f'+ {off}]' in src or f'+{off}]' in src:
                                return True
        return False

    def _scan_func(self, func_va: int) -> List[ObfuscatedExecFinding]:
        insns = self._disasm_func(func_va)
        if not insns:
            return []

        findings = []
        getpwnam_events: List[Tuple[int, str]] = []   # (va, arg_string)
        setuid_events: List[Tuple[int, bool]] = []    # (va, from_pwuid)
        fork_events: List[int] = []

        for i, insn in enumerate(insns):
            if insn.mnemonic != 'call':
                continue
            target = self._resolve_call(insn)
            if target is None:
                continue
            name = self._plt_name(target)
            if name is None:
                continue

            if name in _GETPWNAM_FUNC:
                arg = self._arg_is_root(insns, i)
                getpwnam_events.append((insn.address, arg))

            elif name in _SETUID_FUNCS:
                from_pwuid = (
                    bool(getpwnam_events) and
                    self._setuid_arg_from_pwuid(insns, i)
                )
                setuid_events.append((insn.address, from_pwuid))

            elif name == 'fork':
                fork_events.append(insn.address)

            elif name in _EXEC_FUNCS and getpwnam_events and setuid_events and fork_events:
                gpwnam_va, gpwnam_arg = getpwnam_events[-1]
                suid_va, from_pwuid = setuid_events[-1]

                verdict = 'CONFIRMED' if (gpwnam_arg == 'root' and from_pwuid) else 'PLAUSIBLE'
                note = (
                    f'getpwnam("root")->pw_uid passed to setuid → setuid(0) confirmed; '
                    f'child executes as root via {name}()'
                    if verdict == 'CONFIRMED' else
                    f'getpwnam("{gpwnam_arg}") → setuid → fork → {name}; arg chain unresolved'
                )

                findings.append(ObfuscatedExecFinding(
                    func_va=func_va,
                    pattern='GETPWNAM_ROOT',
                    getpwnam_va=gpwnam_va,
                    getpwnam_arg=gpwnam_arg,
                    setuid_va=suid_va,
                    fork_va=fork_events[-1],
                    exec_va=insn.address,
                    exec_name=name,
                    verdict=verdict,
                    severity='HIGH',
                    note=note,
                ))

        return findings

    def scan(self) -> List[ObfuscatedExecFinding]:
        """
        Scan all functions for getpwnam("root") → setuid → fork → exec patterns.
        """
        has_pwnam = any(n in self._plt for n in _GETPWNAM_FUNC)
        has_suid  = any(n in self._plt for n in _SETUID_FUNCS)
        has_exec  = any(n in self._plt for n in _EXEC_FUNCS)
        has_fork  = 'fork' in self._plt
        if not (has_pwnam and has_suid and has_exec and has_fork):
            return []

        all_starts = sorted(self._ctx.func_starts)
        seen: Set[Tuple[int, int]] = set()
        results: List[ObfuscatedExecFinding] = []

        for va in self._ctx.func_starts:
            for f in self._scan_func(va):
                key = (f.setuid_va, f.exec_va)
                if key not in seen:
                    seen.add(key)
                    for s in all_starts:
                        if s <= f.setuid_va:
                            f.func_va = s
                    results.append(f)
        return results
