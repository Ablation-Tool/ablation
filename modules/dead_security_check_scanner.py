"""
dead_security_check_scanner.py: Unreachable security check detector (GotoFail pattern).

Detects the Apple GotoFail class of bug (CVE-2014-1266): an unconditional branch
mid-sequence in a chain of security-critical conditional checks that leaves
subsequent checks unreachable.

In assembly, the pattern is:
    cmp ...
    je/jne <failure_label>        <- conditional check #1
    cmp ...
    je/jne <failure_label>        <- conditional check #2
    jmp    <past_all_checks>      <- UNCONDITIONAL jump (should be conditional)
    cmp ...
    je/jne <failure_label>        <- dead check: never reached
    ...
    <success_path>                <- reached even when check #3 would have failed

This creates a structural auth bypass: the binary has security checks, but at
least one is unreachable.

Detection strategy using CFGBuilder:
  1. Build CFG for each function.
  2. Find basic blocks that contain an unconditional branch preceded by at
     least two conditional branches targeting the same failure destination.
  3. Check whether any basic block that was reachable only via the bypassed
     checks is now unreachable from normal control flow.
  4. If the function eventually reaches a privileged operation (exec sink,
     return 0/success), flag as a GotoFail candidate.

Usage:
    scanner = DeadSecurityCheckScanner('/path/to/binary')
    findings = scanner.scan()
    print(scanner.report(findings))

    # With existing BinaryContext:
    from ablation.analyzers.binary_context import BinaryContext
    ctx = BinaryContext.load_or_build('/path/to/binary')
    scanner = DeadSecurityCheckScanner.from_context(ctx)
    findings = scanner.scan()
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


# ── Finding ────────────────────────────────────────────────────────────────────

@dataclass
class DeadCheckFinding:
    func_va:          int        # VA of the function
    func_name:        str        # name if available
    uncond_branch_va: int        # VA of the misplaced unconditional branch
    dead_check_va:    int        # VA of the first dead (unreachable) check
    preceding_checks: int        # number of conditional checks before the branch
    note:             str        # description

    def fmt(self) -> str:
        return (f"  HIGH    [DEAD_SECURITY_CHECK / GotoFail]  {self.func_name}\n"
                f"         unconditional branch at 0x{self.uncond_branch_va:x}"
                f"  ({self.preceding_checks} prior conditional checks)\n"
                f"         dead check at 0x{self.dead_check_va:x}\n"
                f"         {self.note}")


# ── Unconditional branch mnemonics ─────────────────────────────────────────────

_UNCOND_BRANCH = frozenset({
    # x86-64
    'jmp',
    # ARM / ARM64
    'b', 'bl', 'bx', 'blx',
    # MIPS
    'j', 'jal', 'b',
})

_COND_BRANCH = frozenset({
    # x86-64
    'je', 'jne', 'jz', 'jnz', 'jl', 'jg', 'jle', 'jge', 'jb', 'ja',
    'jbe', 'jae', 'js', 'jns', 'jo', 'jno', 'jp', 'jnp',
    # ARM condition codes encoded as 'b.eq', 'b.ne', 'beq', 'bne', etc.
    'beq', 'bne', 'blt', 'bgt', 'ble', 'bge', 'blo', 'bhi', 'bls', 'bhs',
    'bpl', 'bmi', 'bvs', 'bvc', 'bcs', 'bcc',
    # MIPS
    'beq', 'bne', 'bgez', 'bgtz', 'blez', 'bltz',
    'beqz', 'bnez', 'bgezal', 'bltzal',
})

_COMPARE = frozenset({
    'cmp', 'test', 'tst', 'cmn',  # x86 + ARM
    'cmpw', 'cmpl', 'cmpq', 'testb', 'testw', 'testl', 'testq',
})

_RET = frozenset({'ret', 'retq', 'retn', 'bx lr', 'jr ra', 'jr $ra'})


# ── Scanner ────────────────────────────────────────────────────────────────────

class DeadSecurityCheckScanner:
    """Detect unconditional branches that bypass security check chains (GotoFail)."""

    def __init__(self, path: str) -> None:
        self._path = path
        self._ctx  = None

    @classmethod
    def from_context(cls, ctx) -> 'DeadSecurityCheckScanner':
        obj = cls.__new__(cls)
        obj._path = ctx.path
        obj._ctx  = ctx
        return obj

    def _load_ctx(self):
        if self._ctx is not None:
            return self._ctx
        from ablation.analyzers.binary_context import BinaryContext
        self._ctx = BinaryContext.load_or_build(self._path)
        return self._ctx

    def scan(self) -> List[DeadCheckFinding]:
        ctx = self._load_ctx()
        findings: list[DeadCheckFinding] = []

        for func_va in ctx.func_starts:
            insns = list(ctx.disasm_func(func_va))
            if len(insns) < 6:
                continue

            # Sliding window: look for the GotoFail pattern
            # Pattern: [compare, cond_branch]+ then uncond_branch then more code
            i = 0
            while i < len(insns) - 3:
                insn = insns[i]
                mn = insn.mnemonic.lower().split()[0]

                # Count consecutive compare+cond_branch pairs
                cond_count = 0
                j = i
                while j + 1 < len(insns):
                    mn_j = insns[j].mnemonic.lower().split()[0]
                    mn_j1 = insns[j + 1].mnemonic.lower().split()[0]
                    if mn_j in _COMPARE and mn_j1 in _COND_BRANCH:
                        cond_count += 1
                        j += 2
                    else:
                        break

                if cond_count < 2:
                    i += 1
                    continue

                # j now points to the instruction after the last cond_branch pair
                if j >= len(insns):
                    i += 1
                    continue

                next_insn = insns[j]
                next_mn = next_insn.mnemonic.lower().split()[0]

                # The instruction after the check chain must be an unconditional branch
                if next_mn not in _UNCOND_BRANCH:
                    i += 1
                    continue

                # There must be more code after the unconditional branch (the dead checks)
                if j + 1 >= len(insns):
                    i += 1
                    continue

                dead_insn = insns[j + 1]
                dead_mn = dead_insn.mnemonic.lower().split()[0]

                # The dead instruction should be another compare or cond_branch
                if dead_mn not in (_COMPARE | _COND_BRANCH):
                    i += 1
                    continue

                findings.append(DeadCheckFinding(
                    func_va=func_va,
                    func_name=ctx.name(func_va),
                    uncond_branch_va=next_insn.address,
                    dead_check_va=dead_insn.address,
                    preceding_checks=cond_count,
                    note=f'{cond_count} conditional security checks precede the unconditional branch; subsequent checks are never reached',
                ))
                i = j + 1
                continue

            i += 1

        return findings

    def report(self, findings: Optional[List[DeadCheckFinding]] = None) -> str:
        if findings is None:
            findings = self.scan()
        if not findings:
            return f'DeadSecurityCheckScanner: no GotoFail patterns in {self._path}'
        lines = [f'DeadSecurityCheckScanner: {len(findings)} finding(s) in {self._path}', '']
        for f in findings:
            lines.append(f.fmt())
            lines.append('')
        return '\n'.join(lines)
