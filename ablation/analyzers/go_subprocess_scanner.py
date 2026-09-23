"""
go_subprocess_scanner.py -- Go os/exec injection surface scanner for Ablation

Given a stripped Go binary + its pclntab function table, finds every call site
that invokes os/exec.Command, os/exec.CommandContext, or exec.Cmd.Start/Run,
resolves the static command-path argument using GoStringResolver, and classifies
each site by path type:

  relative  -- starts with "./" or "../" (exploitable if CWD is attacker-writable)
  path      -- bare name, no slash (resolved via PATH; hijackable via PATH injection)
  absolute  -- starts with "/" (not directly injectable via CWD/PATH)
  dynamic   -- argument not resolvable statically (runtime-built string)

Usage:
    from modules.go_subprocess_scanner import GoSubprocessScanner

    scanner = GoSubprocessScanner(binary_data, segments, func_table)
    results = scanner.scan()
    for r in results:
        print(r['severity'], r['scanner_func'], r['cmd_string'], r['cmd_type'])

    # Or one-shot from binary path
    results = scan_binary(binary_path)
"""

import struct
from dataclasses import dataclass, field
from typing import Optional

try:
    import capstone
    import capstone.x86 as x86
    HAVE_CAPSTONE = True
except ImportError:
    HAVE_CAPSTONE = False

try:
    from .go_string_resolver import GoStringResolver, _init_reg_sets, _RAX_REGS
except ImportError:
    from modules.go_string_resolver import GoStringResolver, _init_reg_sets, _RAX_REGS

# Target function names to hunt (all os/exec entry points that exec a process)
EXEC_TARGETS = frozenset([
    "os/exec.Command",
    "os/exec.CommandContext",
    "os/exec.(*Cmd).Start",
    "os/exec.(*Cmd).Run",
    "os/exec.(*Cmd).Output",
    "os/exec.(*Cmd).CombinedOutput",
])

# Stdlib package prefixes to skip when choosing which functions to scan
_STDLIB_PREFIXES = (
    "runtime.", "runtime/", "reflect.", "sync.", "syscall.", "internal/",
    "encoding/", "fmt.", "strings.", "strconv.", "bytes.", "io.", "os.",
    "net/", "bufio.", "sort.", "math/", "time.", "unicode/", "path/",
    "regexp.", "errors.", "log.", "database/", "context.",
    "crypto/", "hash/", "compress/", "archive/", "text/",
    "html/", "image/", "mime/", "multipart.", "net.",
    "go:", "type.", "gclocals", "abi.", "ssa.", "itab.",
)


@dataclass
class SubprocessSite:
    """One resolved os/exec call site."""
    scanner_func:    str       # caller function name (pclntab)
    scanner_func_va: int       # caller function VA
    call_va:         int       # VA of the CALL instruction
    exec_target:     str       # e.g. "os/exec.Command"
    exec_target_va:  int       # VA of os/exec.Command
    cmd_string:      str       # resolved command string, or "" if dynamic
    cmd_va:          int       # VA of the string literal in .rodata (0 if dynamic)
    cmd_len:         int       # byte length (0 if dynamic)
    cmd_type:        str       # "relative" | "path" | "absolute" | "dynamic"
    severity:        str       # "HIGH" | "MEDIUM" | "LOW" | "INFO"
    note:            str = ""

    def as_dict(self) -> dict:
        return {
            "scanner_func":    self.scanner_func,
            "scanner_func_va": f"0x{self.scanner_func_va:x}",
            "call_va":         f"0x{self.call_va:x}",
            "exec_target":     self.exec_target,
            "exec_target_va":  f"0x{self.exec_target_va:x}",
            "cmd_string":      self.cmd_string,
            "cmd_va":          f"0x{self.cmd_va:x}" if self.cmd_va else "0x0",
            "cmd_len":         self.cmd_len,
            "cmd_type":        self.cmd_type,
            "severity":        self.severity,
            "note":            self.note,
        }


def _classify_cmd(cmd: Optional[str]) -> tuple:
    """Return (cmd_type, severity) for a resolved command string."""
    if cmd is None or cmd == "":
        return ("dynamic", "MEDIUM")
    # Log format strings picked up instead of actual command
    if any(f in cmd for f in ('%s', '%v', '%d', '%w', '%q', '%x')):
        return ("dynamic", "MEDIUM")
    # Very long strings are almost certainly not commands
    if len(cmd) > 80:
        return ("dynamic", "MEDIUM")
    # Spaces in command usually means it's not a binary path
    if ' ' in cmd:
        return ("dynamic", "MEDIUM")
    if cmd.startswith("./") or cmd.startswith("../"):
        return ("relative", "HIGH")
    if "/" not in cmd:
        return ("path", "MEDIUM")
    return ("absolute", "INFO")


class GoSubprocessScanner:
    """
    Scans a Go binary for os/exec call sites and resolves static command args.

    Arguments:
        binary_data: full binary file bytes
        segments:    list of PT_LOAD segment dicts (p_vaddr, p_offset, p_filesz)
        func_table:  GoFuncTable instance (from modules.go_pclntab) OR
                     dict of {VA: name} directly
        max_func_size: disassembly window per function (bytes)
        lookback:      how many instructions before a CALL to search for lea/mov
    """

    def __init__(self, binary_data: bytes, segments: list, func_table,
                 max_func_size: int = 0x4000, lookback: int = 12):
        self.data = binary_data
        self.max_func_size = max_func_size
        self.lookback = lookback
        self.resolver = GoStringResolver(binary_data, segments, fallback_max_len=512)

        # Build VA->name and name->VA maps
        if hasattr(func_table, 'names'):
            self._va_to_name = dict(func_table.names)
        else:
            self._va_to_name = dict(func_table)

        self._name_to_va = {}
        for va, name in self._va_to_name.items():
            self._name_to_va.setdefault(name, []).append(va)

        # Sorted VA list for size estimation
        self._sorted_vas = sorted(self._va_to_name.keys())

        if HAVE_CAPSTONE:
            _init_reg_sets()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _func_size(self, va: int) -> int:
        """Estimate function size as gap to next pclntab entry."""
        idx = self._sorted_vas.index(va) if va in set(self._sorted_vas) else -1
        if idx < 0:
            return self.max_func_size
        if idx + 1 < len(self._sorted_vas):
            gap = self._sorted_vas[idx + 1] - va
            return min(gap, self.max_func_size)
        return self.max_func_size

    def _is_stdlib(self, name: str) -> bool:
        for prefix in _STDLIB_PREFIXES:
            if name.startswith(prefix):
                return True
        return False

    def _disasm_func(self, va: int, size: int) -> list:
        foff = self.resolver.vaddr_to_file_offset(va)
        if foff is None:
            return []
        code = self.data[foff: foff + size]
        if not code:
            return []
        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        cs.detail = True
        return list(cs.disasm(code, va))

    # ------------------------------------------------------------------
    # Main scan
    # ------------------------------------------------------------------

    def scan(self, target_names: Optional[frozenset] = None,
             skip_absolute: bool = False) -> list:
        """
        Scan all non-stdlib functions for calls to exec target functions.

        target_names: set of function names to hunt (default: EXEC_TARGETS)
        skip_absolute: if True, exclude absolute-path findings from results

        Returns list of SubprocessSite objects.
        """
        if not HAVE_CAPSTONE:
            return []

        targets = target_names or EXEC_TARGETS

        # Build set of target VAs from pclntab
        target_va_map = {}  # va -> function_name
        for name in targets:
            for va in self._name_to_va.get(name, []):
                target_va_map[va] = name

        if not target_va_map:
            return []

        target_va_set = set(target_va_map.keys())
        results = []

        # Scan all non-stdlib functions
        for va in self._sorted_vas:
            name = self._va_to_name[va]
            if self._is_stdlib(name):
                continue
            if name in targets:
                continue

            size = self._func_size(va)
            instrs = self._disasm_func(va, size)
            if not instrs:
                continue

            for idx, insn in enumerate(instrs):
                if insn.mnemonic != 'call':
                    continue
                if not hasattr(insn, 'operands') or not insn.operands:
                    continue
                op = insn.operands[0]
                if op.type != x86.X86_OP_IMM:
                    continue
                call_target = op.imm
                if call_target not in target_va_set:
                    continue

                # Found a call to an exec function. Resolve command arg.
                exec_name = target_va_map[call_target]
                resolved = self.resolver.resolve_call_site(instrs, idx, self.lookback)

                if resolved:
                    str_va, cmd_str, cmd_len = resolved
                    cmd_type, severity = _classify_cmd(cmd_str)
                else:
                    str_va, cmd_str, cmd_len = 0, "", 0
                    cmd_type, severity = _classify_cmd(None)

                if skip_absolute and cmd_type == "absolute":
                    continue

                note = _make_note(cmd_type, cmd_str, name)

                results.append(SubprocessSite(
                    scanner_func=name,
                    scanner_func_va=va,
                    call_va=insn.address,
                    exec_target=exec_name,
                    exec_target_va=call_target,
                    cmd_string=cmd_str or "",
                    cmd_va=str_va or 0,
                    cmd_len=cmd_len,
                    cmd_type=cmd_type,
                    severity=severity,
                    note=note,
                ))

        # Sort: HIGH first, then MEDIUM, then others
        _order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
        results.sort(key=lambda r: (_order.get(r.severity, 9), r.scanner_func))
        return results

    def scan_function(self, func_va: int) -> list:
        """Scan a single function by VA."""
        name = self._va_to_name.get(func_va, f"func_{func_va:x}")
        size = self._func_size(func_va)
        instrs = self._disasm_func(func_va, size)
        if not instrs:
            return []

        target_va_map = {}
        for tname in EXEC_TARGETS:
            for va in self._name_to_va.get(tname, []):
                target_va_map[va] = tname

        results = []
        for idx, insn in enumerate(instrs):
            if insn.mnemonic != 'call':
                continue
            if not hasattr(insn, 'operands') or not insn.operands:
                continue
            op = insn.operands[0]
            if op.type != x86.X86_OP_IMM:
                continue
            call_target = op.imm
            if call_target not in target_va_map:
                continue

            exec_name = target_va_map[call_target]
            resolved = self.resolver.resolve_call_site(instrs, idx, self.lookback)
            if resolved:
                str_va, cmd_str, cmd_len = resolved
                cmd_type, severity = _classify_cmd(cmd_str)
            else:
                str_va, cmd_str, cmd_len = 0, "", 0
                cmd_type, severity = _classify_cmd(None)

            results.append(SubprocessSite(
                scanner_func=name,
                scanner_func_va=func_va,
                call_va=insn.address,
                exec_target=exec_name,
                exec_target_va=call_target,
                cmd_string=cmd_str or "",
                cmd_va=str_va or 0,
                cmd_len=cmd_len,
                cmd_type=cmd_type,
                severity=severity,
                note=_make_note(cmd_type, cmd_str, name),
            ))
        return results


# ------------------------------------------------------------------
# Note generation
# ------------------------------------------------------------------

def _make_note(cmd_type: str, cmd_str: str, caller: str) -> str:
    if cmd_type == "relative":
        return (f"Relative path '{cmd_str}' resolved against process CWD. "
                f"Exploitable if CWD is attacker-writable.")
    if cmd_type == "path":
        return (f"Bare command '{cmd_str}' resolved via PATH. "
                f"Exploitable via PATH hijacking in calling environment.")
    if cmd_type == "dynamic":
        return f"Command string not statically resolvable in {caller}. Manual trace required."
    return ""


# ------------------------------------------------------------------
# One-shot convenience function
# ------------------------------------------------------------------

def scan_binary(binary_path: str,
                skip_absolute: bool = True,
                max_func_size: int = 0x4000) -> list:
    """
    Full pipeline: load binary, extract pclntab, build resolver, scan.
    Returns list of SubprocessSite objects.
    """
    try:
        from .go_pclntab import GoFuncTable
    except ImportError:
        from modules.go_pclntab import GoFuncTable

    with open(binary_path, 'rb') as f:
        data = f.read()

    segments = _parse_elf_segments(data)
    ft = GoFuncTable.from_binary(data)
    if ft is None:
        return []

    scanner = GoSubprocessScanner(data, segments, ft, max_func_size=max_func_size)
    return scanner.scan(skip_absolute=skip_absolute)


def _parse_elf_segments(data: bytes) -> list:
    """Minimal ELF PT_LOAD segment extractor (64-bit LE)."""
    if data[:4] != b'\x7fELF':
        return []
    e_phoff = struct.unpack_from('<Q', data, 32)[0]
    e_phentsize = struct.unpack_from('<H', data, 54)[0]
    e_phnum = struct.unpack_from('<H', data, 56)[0]
    segs = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type   = struct.unpack_from('<I', data, off)[0]
        p_offset = struct.unpack_from('<Q', data, off + 8)[0]
        p_vaddr  = struct.unpack_from('<Q', data, off + 16)[0]
        p_filesz = struct.unpack_from('<Q', data, off + 32)[0]
        segs.append({'p_type': p_type, 'p_offset': p_offset,
                     'p_vaddr': p_vaddr, 'p_filesz': p_filesz})
    return segs


# ------------------------------------------------------------------
# Pretty-print table
# ------------------------------------------------------------------

def print_results(sites: list, min_severity: str = "INFO") -> None:
    """Print a table of subprocess injection sites."""
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
    min_ord = order.get(min_severity, 3)
    filtered = [s for s in sites if order.get(s.severity, 9) <= min_ord]
    if not filtered:
        print("No subprocess injection sites found.")
        return
    print(f"\n{'SEV':<7} {'CMD_TYPE':<10} {'CMD_STRING':<40} {'CALLER'}")
    print("-" * 100)
    for s in filtered:
        cmd_display = repr(s.cmd_string)[:38] if s.cmd_string else "(dynamic)"
        print(f"{s.severity:<7} {s.cmd_type:<10} {cmd_display:<40} {s.scanner_func}")
        if s.note:
            print(f"         NOTE: {s.note}")
        print(f"         call=0x{s.call_va:x}  caller=0x{s.scanner_func_va:x}  "
              f"exec={s.exec_target}(0x{s.exec_target_va:x})")
        if s.cmd_va:
            print(f"         string_va=0x{s.cmd_va:x} len={s.cmd_len}")
        print()


# ------------------------------------------------------------------
# CLI entry point
# ------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: go_subprocess_scanner.py <binary_path> [--all]")
        sys.exit(1)
    binary_path = sys.argv[1]
    skip_abs = "--all" not in sys.argv
    print(f"Scanning {binary_path} ...")
    sites = scan_binary(binary_path, skip_absolute=skip_abs)
    print_results(sites, min_severity="INFO")
    print(f"Total sites: {len(sites)}")
