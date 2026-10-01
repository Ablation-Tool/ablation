"""
arm64_fgets_fd_discriminator.py: FILE* provenance discriminator for ARM64TaintTracker.

Classifies fgets-sourced TaintFindingARM64 results by whether the FILE* argument
came from a file (config parsing) or a socket (network input). Reduces false
positives where fgets is used only for local config-file reads.

FD class taxonomy:
  file     — FILE* from fopen/fopen64/freopen/tmpfile, or open/openat fd via fdopen
  network  — FILE* from fdopen(socket/accept(...))
  unknown  — FILE* origin not determinable in this function scope
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple  # noqa: F401 (Tuple used in _CALLER_SAVED_REGS)

from .insn_arm64 import from_capstone
from .taint_tracker_arm64 import ARM64TaintTracker, TaintFindingARM64

# Calls whose return value (x0) is a FILE* with file provenance
_FILE_OPEN_CALLS: Set[str] = {
    "fopen", "fopen64", "freopen", "freopen64", "tmpfile", "tmpfile64",
}
# Calls whose return value (x0) is a raw fd with file provenance
_FILE_FD_CALLS: Set[str] = {
    "open", "open64", "openat", "openat64", "creat", "creat64",
}
# Calls whose return value (x0) is a raw fd with socket provenance
_SOCKET_CALLS: Set[str] = {
    "socket", "accept", "accept4", "socketpair",
}

_FGETS_NAMES: Set[str] = {"fgets", "fgets_unlocked", "fread", "fread_unlocked"}

# Caller-saved AArch64 registers clobbered across a call (x0–x17, x30)
_CALLER_SAVED_REGS: Tuple[str, ...] = tuple(
    [f"x{i}" for i in range(18)] + ["x30"]
)


@dataclass
class FgetsClassifiedFinding:
    """fgets finding with FILE* provenance classification."""
    finding: TaintFindingARM64
    fd_class: str   # "file" | "network" | "unknown"

    @property
    def severity(self) -> str:
        return "LOW" if self.fd_class == "file" else self.finding.severity

    @property
    def source_name(self) -> str:
        return self.finding.source_name

    def __str__(self) -> str:
        return (f"[{self.severity}] fd_class={self.fd_class} "
                f"0x{self.finding.func_va:x} ({self.finding.func_name}): "
                f"fgets -> {self.finding.sink_name} @ 0x{self.finding.sink_va:x}")


class ARM64FgetsFdDiscriminator:
    """
    Post-processor that wraps fgets-sourced TaintFindingARM64 findings with
    FILE* provenance classification.

    Non-fgets findings are wrapped with fd_class="n/a" and original severity.
    """

    def __init__(self, tracker: ARM64TaintTracker) -> None:
        self._tracker = tracker

    def classify(self, findings: List[TaintFindingARM64]) -> List[FgetsClassifiedFinding]:
        out: List[FgetsClassifiedFinding] = []
        for f in findings:
            if any(src in _FGETS_NAMES for src in f.source_name.split(",")):
                fd_class = self._classify_finding(f)
            else:
                fd_class = "n/a"
            out.append(FgetsClassifiedFinding(finding=f, fd_class=fd_class))
        return out

    def _classify_finding(self, f: TaintFindingARM64) -> str:
        insns = self._tracker._insns_for_func(f.func_va, f.sink_va + 4)
        if not insns:
            return "unknown"

        # class_state tracks x0–x18 provenance: "file" | "file_fd" | "socket" | "unknown"
        class_state: Dict[str, str] = {}
        # stack spill map: sp-relative offset → class
        stack_state: Dict[int, str] = {}
        sp_off: int = 0  # conservative: don't track sub/add sp changes

        syms = self._tracker._syms

        for insn in insns:
            if insn.address >= f.sink_va:
                break

            m = insn.mnemonic

            if m == "bl":
                target = insn.imm(0)
                callee = syms.get(target, "") if target else ""
                self._clobber_caller_saved(class_state)
                if callee in _FILE_OPEN_CALLS:
                    class_state["x0"] = "file"
                elif callee in _FILE_FD_CALLS:
                    class_state["x0"] = "file_fd"
                elif callee in _SOCKET_CALLS:
                    class_state["x0"] = "socket"
                elif callee == "fdopen":
                    # x0 = fdopen(fd=x0, mode=x1) — propagate fd's class
                    fd_cls = class_state.get("x0", "unknown")
                    class_state["x0"] = "file" if fd_cls in ("file_fd", "file") else (
                        "network" if fd_cls == "socket" else "unknown"
                    )
                else:
                    class_state["x0"] = "unknown"

            elif m in ("mov", "movz", "movn"):
                dst = self._reg_name(insn, 0)
                src = self._reg_name(insn, 1)
                if dst and src and src in class_state:
                    class_state[dst] = class_state[src]
                elif dst:
                    class_state.pop(dst, None)

            elif m in ("ldr", "ldur", "ldr.w"):
                dst = self._reg_name(insn, 0)
                if dst:
                    off = self._sp_offset(insn)
                    if off is not None:
                        class_state[dst] = stack_state[off] if off in stack_state else "unknown"
                    else:
                        class_state.pop(dst, None)

            elif m in ("str", "stur", "str.w"):
                src = self._reg_name(insn, 0)
                off = self._sp_offset(insn)
                if src is not None and off is not None:
                    cls_val = class_state.get(src)
                    if cls_val is not None:
                        stack_state[off] = cls_val
                    else:
                        stack_state.pop(off, None)

            elif m in ("ldp",):
                dst1 = self._reg_name(insn, 0)
                dst2 = self._reg_name(insn, 1)
                for d in (dst1, dst2):
                    if d:
                        class_state.pop(d, None)

        # At fgets call site: classify x0 (FILE* argument)
        x0_cls = class_state.get("x0")
        if x0_cls is None:
            # x0 not modified in this function → likely global/static FILE* (stdin etc.)
            return "file"
        if x0_cls in ("file", "file_fd"):
            return "file"
        if x0_cls in ("socket", "network"):
            return "network"
        return "unknown"

    def _clobber_caller_saved(self, state: Dict[str, str]) -> None:
        for r in _CALLER_SAVED_REGS:
            state.pop(r, None)

    @staticmethod
    def _reg_name(insn, idx: int) -> Optional[str]:
        # insn.reg() returns a Reg dataclass; .name is already canonical (xN form)
        r = insn.reg(idx)
        return r.name if r is not None else None

    @staticmethod
    def _sp_offset(insn) -> Optional[int]:
        """Return SP-relative offset from a ldr/str [sp, #N] operand, or None."""
        try:
            mem = insn.first_mem()
            if mem is None:
                return None
            if mem.base not in ("sp",):
                return None
            return mem.offset
        except (AttributeError, TypeError):
            return None
