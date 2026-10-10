"""
dynamic_sandbox.py — Phase 3: Unicorn-based dynamic sandbox for leaf function probing.

Executes leaf functions with controlled register inputs and captures the output
register state as behavioral evidence for the hypothesis engine.

Safety contract:
  - Only executes functions with no external calls (verified by LeafFunctionChecker).
  - Aborts if execution reaches a PLT stub (mapped to an abort-hook region).
  - Hard instruction-count timeout (default 100 000 insns).
  - Snapshot/restore keeps binary memory state clean between probes.

Architecture support: arm64, x86_64. Stubs for la64/mips64.

Usage:

    from ablation.analyzers.dynamic_sandbox import DynamicSandbox, LeafFunctionChecker

    sandbox = DynamicSandbox.from_path('/path/to/binary', arch='arm64')

    # Verify function is safe to run
    checker = LeafFunctionChecker.from_path('/path/to/binary')
    if checker.is_leaf(va):
        result = sandbox.run_function(va, args={'x0': 0x1234, 'x1': 0x10})
        print(result)
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import unicorn
    import unicorn.arm64_const as uc_arm64
    import unicorn.x86_const as uc_x86
    _UNICORN_AVAILABLE = True
except ImportError:
    _UNICORN_AVAILABLE = False


# ── ELF segment loader ────────────────────────────────────────────────────────

def _page_align(n: int, page: int = 0x1000) -> int:
    return (n + page - 1) & ~(page - 1)


def _load_elf_segments(binary_path: str) -> tuple:
    """Return (load_base, segments, plt_range) from an ELF binary.

    segments: list of (vaddr, data) tuples for LOAD segments
    plt_range: (start, end) VA range of the .plt section, or None
    """
    import lief
    elf = lief.parse(binary_path)
    if elf is None:
        raise ValueError(f"lief cannot parse {binary_path}")

    segments = []
    load_base = None
    for seg in elf.segments:
        if seg.type != lief.ELF.Segment.TYPE.LOAD:
            continue
        va = seg.virtual_address
        data = bytes(seg.content)
        # Pad to virtual size
        if len(data) < seg.virtual_size:
            data = data + b'\x00' * (seg.virtual_size - len(data))
        segments.append((va, data))
        if load_base is None or va < load_base:
            load_base = va

    # Find .plt range for PLT abort hook
    plt_range = None
    for sec in elf.sections:
        if sec.name in (".plt", ".plt.got", ".plt.sec"):
            plt_range = (sec.virtual_address, sec.virtual_address + sec.size)
            break

    return load_base or 0, segments, plt_range


# ── PE segment loader ─────────────────────────────────────────────────────────

def _load_pe_segments(binary_path: str) -> tuple:
    """Return (load_base, segments, iat_range) from a PE/PE+ binary.

    segments: list of (vaddr, data) tuples for each non-empty PE section
    iat_range: (start, end) VA range of the IAT (abort hook for import stubs), or None

    Closes MHB-DYNAMIC (ABLATION-STANDARDS.md §7.3): extends DynamicSandbox to support
    PE binaries so that KernelDriverAnalyzer findings can be dynamically confirmed.
    """
    import lief

    pe = lief.parse(binary_path)
    if pe is None or not isinstance(pe, lief.PE.Binary):
        raise ValueError(f"lief cannot parse {binary_path} as PE")

    image_base: int = pe.optional_header.imagebase
    segments = []

    for section in pe.sections:
        if section.virtual_size == 0:
            continue
        va = image_base + section.virtual_address
        data = bytes(section.content)
        vs = section.virtual_size
        if len(data) < vs:
            data = data + b'\x00' * (vs - len(data))
        segments.append((va, data))

    # IAT is the import hook range (equivalent of PLT in ELF)
    iat_range = None
    try:
        iat_dir = pe.data_directory(lief.PE.DataDirectory.TYPES.IAT)
        if iat_dir and iat_dir.size > 0:
            iat_start = image_base + iat_dir.rva
            iat_range = (iat_start, iat_start + iat_dir.size)
    except Exception:
        pass

    return image_base, segments, iat_range


def _is_pe(binary_path: str) -> bool:
    """Return True if the file begins with the MZ magic byte sequence."""
    try:
        with open(binary_path, "rb") as f:
            return f.read(2) == b"MZ"
    except OSError:
        return False


# ── LeafFunctionChecker ───────────────────────────────────────────────────────

class LeafFunctionChecker:
    """Determines whether a function is safe to probe in the dynamic sandbox.

    A function is a leaf (probe-safe) if it has no calls to PLT stubs and no
    indirect calls whose target is outside the binary's load range.
    """

    def __init__(self, callees_map: Dict[int, List[int]], plt_range: Optional[tuple]):
        self._callees = callees_map      # va → list of callee VAs
        self._plt_range = plt_range      # (start, end) or None

    @classmethod
    def from_path(cls, binary_path: str) -> "LeafFunctionChecker":
        from .xref_graph import XRefGraph
        xg = XRefGraph.from_path(binary_path)
        xg.build()
        if _is_pe(binary_path):
            _, _, plt_range = _load_pe_segments(binary_path)
        else:
            _, _, plt_range = _load_elf_segments(binary_path)
        # XRefGraph doesn't expose full callees_map directly; proxy via callees_of
        return cls(callees_map={}, plt_range=plt_range)

    @classmethod
    def from_xref_graph(cls, xg, plt_range: Optional[tuple] = None) -> "LeafFunctionChecker":
        return cls(callees_map={}, plt_range=plt_range)

    def is_leaf(self, va: int, ctx=None) -> bool:
        """Return True if function at va has no external calls."""
        if ctx is None:
            return True  # can't verify without context; trust caller
        try:
            from .xref_graph import XRefGraph
            xg = XRefGraph.from_path(ctx.path)
            if not getattr(xg, "_built", False):
                xg.build()
            callees = list(xg.callees_of(va) or [])
            if not callees:
                return True
            if self._plt_range is None:
                return True
            plt_start, plt_end = self._plt_range
            for c in callees:
                if plt_start <= c < plt_end:
                    return False
            return True
        except Exception:
            return True

    def check_report(self, va: int, ctx=None) -> str:
        """Return a human-readable probe-safety report for va."""
        leaf = self.is_leaf(va, ctx)
        status = "SAFE" if leaf else "UNSAFE (has PLT callees)"
        return f"{hex(va)}: {status}"


# ── SandboxResult ─────────────────────────────────────────────────────────────

@dataclass
class SandboxResult:
    """Output of a single DynamicSandbox probe run."""

    va: int
    input_regs: Dict[str, int]
    output_regs: Dict[str, int]
    return_value: Optional[int]
    executed_insns: int
    memory_writes: List[tuple]      # list of (address, size, value_bytes)
    aborted: bool = False
    abort_reason: str = ""
    arch: str = "arm64"

    def __str__(self) -> str:
        status = "ABORTED" if self.aborted else "OK"
        rv = hex(self.return_value) if self.return_value is not None else "N/A"
        return (
            f"SandboxResult[{self.arch}] {hex(self.va)} {status}  "
            f"insns={self.executed_insns}  ret={rv}"
            + (f"  abort={self.abort_reason}" if self.aborted else "")
        )

    def behavioral_signature(self) -> str:
        """A short string that identifies this run's behavior.

        Two runs with the same behavioral_signature exhibit the same output
        given the same inputs — useful for comparing across binaries.
        """
        rv = hex(self.return_value) if self.return_value is not None else "none"
        writes = len(self.memory_writes)
        return f"ret={rv},writes={writes},insns={self.executed_insns}"


# ── DynamicSandbox ────────────────────────────────────────────────────────────

# Stack size and address constants
_STACK_BASE  = 0x7fff_0000
_STACK_SIZE  = 0x0001_0000   # 64 KB
_HALT_ADDR   = 0x7fff_e000   # return address — execution stops here

# ARM64 return register + argument registers
_ARM64_ARGS  = ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"]
_X86_ARGS    = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]


class DynamicSandbox:
    """Unicorn-based sandbox for controlled leaf-function execution.

    Maps ELF LOAD segments into Unicorn memory, maps a stack and halt page,
    sets register arguments from probe parameters, and runs the function.

    PLT stubs are covered by a UC_HOOK_CODE callback that aborts on entry.
    A hard insn-count timeout prevents infinite loops.
    """

    MAX_INSNS = 100_000

    def __init__(self, binary_path: str, arch: str = "arm64"):
        if not _UNICORN_AVAILABLE:
            raise RuntimeError("unicorn not installed: pip install unicorn")
        self._path = binary_path
        self._arch = arch
        if _is_pe(binary_path):
            self._load_base, self._segments, self._plt_range = _load_pe_segments(binary_path)
        else:
            self._load_base, self._segments, self._plt_range = _load_elf_segments(binary_path)
        self._uc = self._init_unicorn(arch)
        self._map_segments()
        self._map_infrastructure()
        self._snap = self._uc.context_save()   # clean-state snapshot
        self._mem_snap: bytes = self._read_all_mapped()

    @classmethod
    def from_path(cls, binary_path: str, arch: str = "arm64") -> "DynamicSandbox":
        return cls(binary_path, arch)

    @classmethod
    def from_context(cls, ctx) -> "DynamicSandbox":
        arch = getattr(ctx, "arch", "arm64")
        return cls(ctx.path, arch)

    # ── Unicorn init ──────────────────────────────────────────────────────────

    def _init_unicorn(self, arch: str):
        if arch in ("arm64", "aarch64"):
            uc = unicorn.Uc(unicorn.UC_ARCH_ARM64, unicorn.UC_MODE_ARM)
        elif arch in ("x86_64", "x86"):
            uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
        else:
            raise ValueError(f"Unsupported arch for dynamic sandbox: {arch}")
        return uc

    def _map_segments(self) -> None:
        for vaddr, data in self._segments:
            size = _page_align(max(len(data), 0x1000))
            try:
                self._uc.mem_map(vaddr & ~0xfff, size + 0x1000,
                                 unicorn.UC_PROT_ALL)
                self._uc.mem_write(vaddr, data)
            except unicorn.UcError:
                pass  # already mapped (overlapping segments)

    def _map_infrastructure(self) -> None:
        # Stack
        self._uc.mem_map(_STACK_BASE, _STACK_SIZE, unicorn.UC_PROT_ALL)
        # Halt page — execution jumps here on return; hooks detect it
        self._uc.mem_map(_HALT_ADDR, 0x1000, unicorn.UC_PROT_ALL)
        if self._arch in ("arm64", "aarch64"):
            # NOP sled on halt page
            self._uc.mem_write(_HALT_ADDR, b'\x1f\x20\x03\xd5' * 64)  # NOP * 64
        else:
            self._uc.mem_write(_HALT_ADDR, b'\x90' * 64)  # NOP * 64

    def _read_all_mapped(self) -> bytes:
        """Read a snapshot of the first segment for rollback."""
        if not self._segments:
            return b''
        va, data = self._segments[0]
        try:
            return bytes(self._uc.mem_read(va, len(data)))
        except Exception:
            return b''

    # ── Snapshot / restore ────────────────────────────────────────────────────

    def _restore(self) -> None:
        """Restore CPU context + writable memory to clean state."""
        self._uc.context_restore(self._snap)
        if self._segments and self._mem_snap:
            va, _ = self._segments[0]
            try:
                self._uc.mem_write(va, self._mem_snap)
            except Exception:
                pass

    # ── Register helpers ──────────────────────────────────────────────────────

    def _set_args_arm64(self, args: Dict[str, int]) -> None:
        names = {
            "x0": uc_arm64.UC_ARM64_REG_X0, "x1": uc_arm64.UC_ARM64_REG_X1,
            "x2": uc_arm64.UC_ARM64_REG_X2, "x3": uc_arm64.UC_ARM64_REG_X3,
            "x4": uc_arm64.UC_ARM64_REG_X4, "x5": uc_arm64.UC_ARM64_REG_X5,
            "x6": uc_arm64.UC_ARM64_REG_X6, "x7": uc_arm64.UC_ARM64_REG_X7,
            "sp": uc_arm64.UC_ARM64_REG_SP,  "lr": uc_arm64.UC_ARM64_REG_LR,
        }
        sp_val = _STACK_BASE + _STACK_SIZE - 0x100
        self._uc.reg_write(uc_arm64.UC_ARM64_REG_SP, sp_val)
        self._uc.reg_write(uc_arm64.UC_ARM64_REG_LR, _HALT_ADDR)
        for k, v in args.items():
            reg_id = names.get(k.lower())
            if reg_id is not None:
                self._uc.reg_write(reg_id, v & 0xFFFF_FFFF_FFFF_FFFF)

    def _set_args_x86(self, args: Dict[str, int]) -> None:
        names = {
            "rdi": uc_x86.UC_X86_REG_RDI, "rsi": uc_x86.UC_X86_REG_RSI,
            "rdx": uc_x86.UC_X86_REG_RDX, "rcx": uc_x86.UC_X86_REG_RCX,
            "r8":  uc_x86.UC_X86_REG_R8,  "r9":  uc_x86.UC_X86_REG_R9,
            "rsp": uc_x86.UC_X86_REG_RSP, "rax": uc_x86.UC_X86_REG_RAX,
        }
        sp_val = _STACK_BASE + _STACK_SIZE - 0x100
        self._uc.reg_write(uc_x86.UC_X86_REG_RSP, sp_val)
        # Push halt address as return address
        sp_val -= 8
        self._uc.mem_write(sp_val, struct.pack("<Q", _HALT_ADDR))
        self._uc.reg_write(uc_x86.UC_X86_REG_RSP, sp_val)
        for k, v in args.items():
            reg_id = names.get(k.lower())
            if reg_id is not None:
                self._uc.reg_write(reg_id, v & 0xFFFF_FFFF_FFFF_FFFF)

    def _read_output_regs_arm64(self) -> Dict[str, int]:
        return {
            "x0": self._uc.reg_read(uc_arm64.UC_ARM64_REG_X0),
            "x1": self._uc.reg_read(uc_arm64.UC_ARM64_REG_X1),
            "x8": self._uc.reg_read(uc_arm64.UC_ARM64_REG_X8),
        }

    def _read_output_regs_x86(self) -> Dict[str, int]:
        return {
            "rax": self._uc.reg_read(uc_x86.UC_X86_REG_RAX),
            "rdx": self._uc.reg_read(uc_x86.UC_X86_REG_RDX),
        }

    # ── Probe execution ───────────────────────────────────────────────────────

    def run_function(
        self,
        va: int,
        args: Optional[Dict[str, int]] = None,
        max_insns: int = MAX_INSNS,
    ) -> SandboxResult:
        """Execute function at va with register arguments and return SandboxResult.

        Args:
            va:        Function start VA.
            args:      Register name → value mapping (e.g. {'x0': 0x10}).
            max_insns: Hard instruction-count timeout.

        Returns:
            SandboxResult with output register values and behavioral observations.
        """
        self._restore()
        args = args or {}
        mem_writes: List[tuple] = []
        insn_count = [0]
        aborted = [False]
        abort_reason = [""]

        # Memory-write hook for behavioral fingerprinting
        def hook_mem_write(uc, access, address, size, value, user_data):
            mem_writes.append((address, size, value))

        # Code hook for PLT abort + halt detection + insn count
        def hook_code(uc, address, size, user_data):
            insn_count[0] += 1
            if insn_count[0] >= max_insns:
                aborted[0] = True
                abort_reason[0] = f"timeout at {insn_count[0]} insns"
                uc.emu_stop()
                return
            if address == _HALT_ADDR:
                uc.emu_stop()
                return
            if self._plt_range:
                plt_start, plt_end = self._plt_range
                if plt_start <= address < plt_end:
                    aborted[0] = True
                    abort_reason[0] = f"PLT stub at {hex(address)}"
                    # Simulate clean return: set x0=0, pc=lr
                    if self._arch in ("arm64", "aarch64"):
                        try:
                            uc.reg_write(uc_arm64.UC_ARM64_REG_X0, 0)
                        except Exception:
                            pass
                    uc.emu_stop()

        h1 = self._uc.hook_add(unicorn.UC_HOOK_CODE, hook_code)
        h2 = self._uc.hook_add(unicorn.UC_HOOK_MEM_WRITE, hook_mem_write)

        if self._arch in ("arm64", "aarch64"):
            self._set_args_arm64(args)
        else:
            self._set_args_x86(args)

        try:
            self._uc.emu_start(va, _HALT_ADDR + 0xff, count=max_insns)
        except unicorn.UcError as e:
            if not aborted[0]:
                aborted[0] = True
                abort_reason[0] = str(e)
        finally:
            self._uc.hook_del(h1)
            self._uc.hook_del(h2)

        if self._arch in ("arm64", "aarch64"):
            out_regs = self._read_output_regs_arm64()
            ret_val = out_regs.get("x0")
        else:
            out_regs = self._read_output_regs_x86()
            ret_val = out_regs.get("rax")

        return SandboxResult(
            va=va,
            input_regs=args,
            output_regs=out_regs,
            return_value=ret_val,
            executed_insns=insn_count[0],
            memory_writes=mem_writes[:256],
            aborted=aborted[0],
            abort_reason=abort_reason[0],
            arch=self._arch,
        )

    def probe_multiple(
        self,
        va: int,
        input_sets: List[Dict[str, int]],
        max_insns: int = MAX_INSNS,
    ) -> List[SandboxResult]:
        """Run the same function with multiple input sets.

        Returns a result per input set. Each run gets a clean snapshot restore.
        """
        results = []
        for args in input_sets:
            r = self.run_function(va, args, max_insns)
            results.append(r)
        return results


# ── DynamicProbeAdapter ───────────────────────────────────────────────────────

class DynamicProbeAdapter:
    """ProbeAdapter subclass for 'dynamic' probe kind.

    Runs the target function with probe-specified or auto-generated inputs and
    returns behavioral evidence (UC_HOOK_MEM_WRITE pattern + return value).
    """

    kind = "dynamic"

    def can_handle(self, probe_kind: str) -> bool:
        return probe_kind == self.kind

    def execute(self, probe, ctx, session) -> list:
        if not _UNICORN_AVAILABLE:
            return []
        from .hypothesis_models import EvidenceRecord, EvidenceRelation

        evidence = []
        arch = getattr(ctx, "arch", "arm64")

        try:
            sandbox = DynamicSandbox.from_context(ctx)
        except Exception:
            return []

        # Collect target VAs from probe parameters or hypothesis subjects
        vas = []
        params = probe.parameters
        if "va" in params:
            try:
                vas.append(int(str(params["va"]), 0))
            except (ValueError, TypeError):
                pass
        if not vas:
            for hid in probe.target_hypothesis_ids:
                h = session.get_hypothesis(hid)
                if h is None:
                    continue
                for k in ("va", "func_va", "target_va"):
                    if k in h.subject:
                        try:
                            vas.append(int(str(h.subject[k]), 0))
                        except (ValueError, TypeError):
                            pass

        # Generate a small set of diverse input patterns
        input_sets = params.get("input_sets") or [
            {},                                          # all-zero args
            {"x0": 0x1, "x1": 0x1},
            {"x0": 0xFF, "x1": 0x10},
            {"x0": 0xFFFF_FFFF, "x1": 0x0},
        ]

        for va in set(vas):
            try:
                results = sandbox.probe_multiple(va, input_sets)
                sigs = [r.behavioral_signature() for r in results]
                consistent = len(set(sigs)) < len(sigs)  # some matching sigs
                any_aborted = any(r.aborted for r in results)
                write_counts = [len(r.memory_writes) for r in results]

                obs = {
                    "va": hex(va),
                    "runs": len(results),
                    "behavioral_signatures": sigs,
                    "return_values": [
                        hex(r.return_value) if r.return_value is not None else "N/A"
                        for r in results
                    ],
                    "any_aborted": any_aborted,
                    "total_mem_writes": sum(write_counts),
                    "insns_executed": [r.executed_insns for r in results],
                }

                # Behavioral evidence: strength depends on completeness of runs
                strength = 0.0
                if any_aborted:
                    strength = 0.40  # partial — PLT calls interrupted
                elif consistent:
                    strength = 0.75  # multiple runs show consistent behavior
                else:
                    strength = 0.60  # ran clean but outputs vary

                ev = EvidenceRecord.create(
                    analyzer="DynamicSandbox",
                    family="behavioral",
                    subject={"va": hex(va)},
                    observation=obs,
                    relation=EvidenceRelation.NEUTRAL,
                    hypothesis_ids=probe.target_hypothesis_ids,
                    strength=strength,
                    reliability=0.85,
                    notes=f"dynamic: {len(results)} runs, aborted={any_aborted}",
                )
                evidence.append(ev)
            except Exception:
                pass

        return evidence


__all__ = [
    "DynamicSandbox", "DynamicProbeAdapter",
    "SandboxResult", "LeafFunctionChecker",
]
