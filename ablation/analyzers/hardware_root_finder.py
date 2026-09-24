"""
hardware_root_finder.py: Hardware root detection via MMIO range access scanning.

Firmware for microcontrollers and SoCs accesses peripherals via Memory-Mapped I/O
(MMIO): hardcoded addresses in known peripheral ranges. Functions that read from
or write to MMIO are "hardware roots": the true entry points for device-specific
behavior (UART, GPIO, DMA, watchdog, crypto accelerators, network MACs).

Strategy:
1. Scan the binary for load/store instructions to hardcoded addresses in known
   MMIO ranges (e.g., 0x40000000-0x5FFFFFFF on STM32/ARM, 0xE0000000 on ARM Cortex-M
   system peripherals).
2. Collect the containing function VA for each hit.
3. From each hardware-root function, walk callers backwards via BinaryContext to
   build the "call spine": who eventually calls into the hardware.

This is the inverse of TaintTracker: instead of following data from network input
to dangerous sinks, we follow code from hardware access upward to protocol parsers.

Usage:
    finder = HardwareRootFinder('/path/to/binary')
    roots = finder.find_roots()
    for r in roots:
        print(r.fmt())

    # With existing BinaryContext:
    ctx = BinaryContext.load_or_build('/path/to/binary')
    finder = HardwareRootFinder.from_context(ctx)
    roots = finder.find_roots(depth=2)  # callers 2 hops back

    # Custom MMIO ranges (e.g., Qualcomm IPQ8064 SoC):
    finder = HardwareRootFinder('/path/to/binary',
        extra_ranges=[(0x16000000, 0x1FFFFFFF, 'Qualcomm-GMAC')])
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


# Known MMIO address ranges indexed by SoC family.
# Format: (start, end_inclusive, label)
_MMIO_RANGES: List[Tuple[int, int, str]] = [
    # ARM Cortex-M system peripherals (architecture-defined)
    (0xE0000000, 0xE00FFFFF, 'ARM-CoreSight'),
    (0xE000E000, 0xE000EFFF, 'ARM-SysTick/NVIC/SCB'),

    # STM32 family
    (0x40000000, 0x5FFFFFFF, 'STM32-APB/AHB'),
    (0x20000000, 0x2001FFFF, 'STM32-SRAM'),

    # ARM Cortex-A / Marvell / MediaTek SoC (common ranges)
    (0xF0000000, 0xFFFFFFFF, 'SoC-HighPeripheral'),
    (0x08000000, 0x0FFFFFFF, 'SoC-MidPeripheral'),

    # Broadcom BCM (used in routers/switches)
    (0x18000000, 0x1AFFFFFF, 'BCM-MMIO'),

    # Qualcomm IPQ / MDM
    (0x16000000, 0x17FFFFFF, 'Qualcomm-GMAC'),
    (0x07800000, 0x07FFFFFF, 'Qualcomm-PCIe'),

    # Cavium/Marvell OCTEON (used in Fortinet chassis blades)
    (0x8001180000000000, 0x8001180FFFFFFFFF, 'Cavium-OCTEON-CSR'),
    (0x8001070000000000, 0x800107FFFFFFFFFF, 'Cavium-OCTEON-L2C'),

    # Intel/Ixia NPU (used in some IPS cards)
    (0xFEC00000, 0xFEFFFFFF, 'Intel-IOAPIC/Local-APIC'),
    (0xFED00000, 0xFED003FF, 'Intel-HPET'),

    # Generic: anything in the top 256MB of 32-bit address space
    (0xFF000000, 0xFFFFFFFF, 'Generic-HighMem32'),
]

# Regex to match RIP-relative or absolute immediate addresses in operands
_IMM_RE = re.compile(r'\b(0x[0-9a-f]{6,16})\b', re.IGNORECASE)

# Mnemonics that perform memory access (load or store)
_MEM_ACCESS_MNEMS = frozenset([
    'mov', 'movzx', 'movsx', 'movsxd', 'movzwl', 'movzbl',
    'lea',
    'cmp', 'test',
    'add', 'sub', 'and', 'or', 'xor',
    'push', 'pop',
    'str', 'ldr', 'strb', 'ldrb', 'strh', 'ldrh',  # ARM
    'sw', 'lw', 'lb', 'lbu', 'sh', 'lhu',           # MIPS
])


@dataclass
class HardwareAccess:
    func_va: int          # function containing the access
    site_va: int          # instruction VA
    mmio_addr: int        # the MMIO address referenced
    mmio_label: str       # range label (e.g. 'STM32-APB/AHB')
    mnemonic: str         # instruction mnemonic
    is_write: bool        # True if this is a store to MMIO

    def fmt(self) -> str:
        direction = 'WRITE' if self.is_write else 'READ '
        return (
            f"0x{self.site_va:x}  {direction}  MMIO=0x{self.mmio_addr:x} "
            f"({self.mmio_label})  func=0x{self.func_va:x}  [{self.mnemonic}]"
        )


@dataclass
class HardwareRoot:
    func_va: int
    accesses: List[HardwareAccess] = field(default_factory=list)
    call_spine: List[List[int]] = field(default_factory=list)  # paths of callers

    @property
    def mmio_labels(self) -> List[str]:
        return list({a.mmio_label for a in self.accesses})

    def fmt(self) -> str:
        lines = [
            f"HardwareRoot func=0x{self.func_va:x}",
            f"  MMIO ranges : {', '.join(self.mmio_labels)}",
            f"  accesses    : {len(self.accesses)}",
        ]
        for a in self.accesses:
            lines.append(f"    {a.fmt()}")
        if self.call_spine:
            lines.append(f"  callers ({len(self.call_spine)} paths):")
            for path in self.call_spine[:5]:
                lines.append('    ' + ' -> '.join(f'0x{v:x}' for v in path))
        return '\n'.join(lines)


class HardwareRootFinder:
    """
    Scan an ELF binary for MMIO-range accesses and build call spines back
    from hardware-access functions to their callers.
    """

    def __init__(
        self,
        binary_path: str,
        ctx=None,
        extra_ranges: Optional[List[Tuple[int, int, str]]] = None,
    ):
        self.binary_path = binary_path
        self._ctx = ctx
        self._ranges = list(_MMIO_RANGES)
        if extra_ranges:
            self._ranges.extend(extra_ranges)

    @classmethod
    def from_context(cls, ctx, extra_ranges=None) -> 'HardwareRootFinder':
        return cls(ctx.path, ctx=ctx, extra_ranges=extra_ranges)

    def _mmio_range(self, addr: int) -> Optional[str]:
        """Return label if addr falls in a known MMIO range, else None."""
        for start, end, label in self._ranges:
            if start <= addr <= end:
                return label
        return None

    def _is_store_mnem(self, mnem: str, ops: str) -> bool:
        """Heuristic: is this instruction storing TO memory (not loading from)?"""
        mnem = mnem.lower()
        # x86-64: 'mov [addr], reg' has '[' in first operand
        if mnem in ('mov', 'movabs', 'add', 'sub', 'and', 'or', 'xor', 'not', 'neg'):
            parts = [p.strip() for p in ops.split(',')]
            if parts and '[' in parts[0]:
                return True
        # ARM store mnemonics
        if mnem.startswith('str'):
            return True
        # MIPS store mnemonics
        if mnem in ('sw', 'sh', 'sb'):
            return True
        return False

    def _scan_accesses(self) -> List[HardwareAccess]:
        try:
            import capstone
            import lief
        except ImportError:
            return []

        binary = lief.parse(self.binary_path)
        if not isinstance(binary, lief.ELF.Binary):
            return []

        text_sec = binary.get_section('.text')
        if not text_sec:
            return []

        text_data = bytes(text_sec.content)
        text_va = text_sec.virtual_address

        # Detect arch
        arch = binary.header.machine_type
        if arch == lief.ELF.ARCH.x86_64:
            cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        elif arch == lief.ELF.ARCH.ARM:
            cs = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
        elif arch == lief.ELF.ARCH.AARCH64:
            cs = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
        elif arch == lief.ELF.ARCH.MIPS:
            cs = capstone.Cs(capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS32)
        else:
            cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        cs.detail = False

        accesses: List[HardwareAccess] = []
        func_va = text_va

        for insn in cs.disasm(text_data, text_va):
            # Update current function VA estimate using endbr64 / function prologues
            if insn.mnemonic.lower() in ('endbr64', 'endbr32'):
                func_va = insn.address
            elif insn.mnemonic.lower() == 'push' and 'rbp' in insn.op_str:
                func_va = insn.address

            if insn.mnemonic.lower() not in _MEM_ACCESS_MNEMS:
                continue

            ops_str = insn.op_str
            for m in _IMM_RE.finditer(ops_str):
                try:
                    addr = int(m.group(1), 16)
                except ValueError:
                    continue
                label = self._mmio_range(addr)
                if label:
                    is_wr = self._is_store_mnem(insn.mnemonic, ops_str)
                    # Use context for better func_va if available
                    fva = func_va
                    if self._ctx:
                        found = self._ctx.func_containing(insn.address)
                        if found:
                            fva = found
                    accesses.append(HardwareAccess(
                        func_va=fva,
                        site_va=insn.address,
                        mmio_addr=addr,
                        mmio_label=label,
                        mnemonic=insn.mnemonic,
                        is_write=is_wr,
                    ))

        return accesses

    def _build_call_spine(self, func_va: int, depth: int) -> List[List[int]]:
        """Walk callers backwards up to depth hops. Returns list of caller paths."""
        if not self._ctx or depth <= 0:
            return []
        visited: Set[int] = set()

        def _walk(va: int, current_path: List[int], d: int) -> List[List[int]]:
            if d == 0 or va in visited:
                return [current_path] if current_path else []
            visited.add(va)
            callers = self._ctx.callers_of(va)
            if not callers:
                return [current_path] if current_path else []
            paths = []
            for caller_va, _ in callers[:5]:  # limit fan-out
                caller_func = self._ctx.func_containing(caller_va) or caller_va
                new_path = current_path + [caller_func]
                paths.extend(_walk(caller_func, new_path, d - 1))
            return paths

        return _walk(func_va, [func_va], depth)

    def find_roots(self, depth: int = 2) -> List[HardwareRoot]:
        """
        Find all functions that directly access MMIO addresses.
        Build call spines `depth` hops back from each hardware root.
        """
        accesses = self._scan_accesses()
        if not accesses:
            return []

        # Group by function VA
        by_func: Dict[int, List[HardwareAccess]] = {}
        for a in accesses:
            by_func.setdefault(a.func_va, []).append(a)

        roots: List[HardwareRoot] = []
        for func_va, func_accesses in sorted(by_func.items()):
            spine = self._build_call_spine(func_va, depth)
            roots.append(HardwareRoot(
                func_va=func_va,
                accesses=func_accesses,
                call_spine=spine,
            ))

        return roots

    def report(self, depth: int = 2) -> str:
        roots = self.find_roots(depth=depth)
        if not roots:
            return 'HardwareRootFinder: no MMIO accesses found\n'
        total_accesses = sum(len(r.accesses) for r in roots)
        lines = [
            f'HardwareRootFinder: {len(roots)} hardware-root functions, '
            f'{total_accesses} MMIO accesses',
            '',
        ]
        for r in roots:
            lines.append(r.fmt())
            lines.append('')
        return '\n'.join(lines)
