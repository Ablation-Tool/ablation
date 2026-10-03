"""
PowerPC 32-bit function discovery for stripped binaries.

Discovers function entry points via:
1. Entry point from ELF header
2. Direct branch targets (bl/bla instructions)
3. Standard prologue patterns:
   - mflr r0; stw r0, <offset>(r1); stwu r1, -<frame>(r1)
   - stwu r1, -<frame>(r1)  (frameless functions)

PowerPC branch instructions:
- bl  target  : 0x48000001 | ((target & 0x03FFFFFC))
- bla target  : 0x48000003 | ((target & 0x03FFFFFC))

Prologue patterns (big-endian):
- 0x7C0802A6: mflr r0
- 0x90010xxx: stw r0, <offset>(r1)
- 0x9421xxxx: stwu r1, -<frame>(r1)
"""

from typing import Set
import struct
import capstone
import lief

class PPC32FuncDiscovery:
    """Discover function entry points in PowerPC 32-bit big-endian binaries."""

    def __init__(self, data: bytes, base_va: int, entry_va: int):
        self.data = data
        self.base_va = base_va
        self.entry_va = entry_va
        self.md = capstone.Cs(capstone.CS_ARCH_PPC, capstone.CS_MODE_BIG_ENDIAN | capstone.CS_MODE_32)
        self.md.detail = True

    @classmethod
    def from_path(cls, path: str) -> "PPC32FuncDiscovery":
        """Load from ELF file - reads main LOAD segment directly."""
        elf = lief.parse(path)
        if not elf:
            raise ValueError(f"Failed to parse ELF: {path}")

        entry_va = elf.header.entrypoint

        # Find LOAD segment containing entry point
        main_seg = None
        for seg in elf.segments:
            seg_type = seg.type
            if hasattr(seg_type, 'value'):
                seg_type = seg_type.value

            if seg_type == 1:  # PT_LOAD
                if seg.virtual_address <= entry_va < (seg.virtual_address + seg.virtual_size):
                    main_seg = seg
                    break

        if not main_seg:
            raise ValueError(f"No LOAD segment found containing entry 0x{entry_va:x}")

        # Read segment data directly from file (lief has issues with no-section binaries)
        with open(path, 'rb') as f:
            f.seek(main_seg.file_offset)
            data = f.read(main_seg.physical_size)

        return cls(data, main_seg.virtual_address, entry_va)

    def discover(self) -> Set[int]:
        """
        Discover all function entry points.

        Returns:
            Set of function start VAs
        """
        func_starts = {self.entry_va}

        # Scan for branch targets and prologue patterns
        branch_targets = self._find_branch_targets()
        prologue_vas = self._find_prologues()

        func_starts.update(branch_targets)
        func_starts.update(prologue_vas)

        return func_starts

    def _find_branch_targets(self) -> Set[int]:
        """Find all direct branch (bl/bla) target addresses."""
        targets = set()

        # Scan every 4-byte boundary for branch instructions
        for offset in range(0, len(self.data) - 3, 4):
            insn_bytes = self.data[offset:offset+4]
            opcode = struct.unpack('>I', insn_bytes)[0]

            # Check for bl (branch and link) - opcode 0x48000001
            if (opcode & 0xFC000003) == 0x48000001:
                # Extract 24-bit signed target offset
                target_offset = (opcode & 0x03FFFFFC)
                if target_offset & 0x02000000:  # Sign extend
                    target_offset |= 0xFC000000
                    target_offset = struct.unpack('>i', struct.pack('>I', target_offset & 0xFFFFFFFF))[0]

                # Calculate absolute target
                va = self.base_va + offset
                target_va = va + target_offset

                # Only add targets within our segment
                if self.base_va <= target_va < (self.base_va + len(self.data)):
                    targets.add(target_va)

            # Check for bla (branch and link absolute) - opcode 0x48000003
            elif (opcode & 0xFC000003) == 0x48000003:
                target_va = (opcode & 0x03FFFFFC)
                if self.base_va <= target_va < (self.base_va + len(self.data)):
                    targets.add(target_va)

        return targets

    def _find_prologues(self) -> Set[int]:
        """Find standard PowerPC function prologues."""
        prologue_vas = set()

        # Common prologue patterns
        MFLR_R0 = 0x7C0802A6      # mflr r0
        STW_R0_PATTERN = 0x9001   # stw r0, <offset>(r1) - upper 16 bits
        STWU_R1_PATTERN = 0x9421  # stwu r1, -<frame>(r1) - upper 16 bits

        for offset in range(0, len(self.data) - 11, 4):
            # Pattern 1: mflr r0; stw r0, X(r1); stwu r1, -Y(r1)
            if offset + 12 <= len(self.data):
                insn1 = struct.unpack('>I', self.data[offset:offset+4])[0]
                insn2 = struct.unpack('>I', self.data[offset+4:offset+8])[0]
                insn3 = struct.unpack('>I', self.data[offset+8:offset+12])[0]

                if (insn1 == MFLR_R0 and
                    (insn2 >> 16) == STW_R0_PATTERN and
                    (insn3 >> 16) == STWU_R1_PATTERN):
                    prologue_vas.add(self.base_va + offset)

            # Pattern 2: stwu r1, -<frame>(r1) alone (frameless or leaf)
            insn = struct.unpack('>I', self.data[offset:offset+4])[0]
            if (insn >> 16) == STWU_R1_PATTERN:
                # Verify reasonable frame size (typically < 4096)
                frame_size = (insn & 0xFFFF)
                if frame_size & 0x8000:  # Negative (two's complement)
                    frame_size = (~frame_size + 1) & 0xFFFF
                    if 16 <= frame_size <= 4096:
                        prologue_vas.add(self.base_va + offset)

        return prologue_vas

    def report(self, func_starts: Set[int]) -> str:
        """Generate discovery report."""
        sorted_funcs = sorted(func_starts)

        lines = [
            f"PowerPC 32-bit Function Discovery Report",
            f"=" * 50,
            f"Binary VA range: 0x{self.base_va:08x} - 0x{self.base_va + len(self.data):08x}",
            f"Entry point: 0x{self.entry_va:08x}",
            f"Total functions discovered: {len(func_starts)}",
            f"",
            f"Function VAs:",
        ]

        for va in sorted_funcs[:50]:  # Show first 50
            lines.append(f"  0x{va:08x}")

        if len(sorted_funcs) > 50:
            lines.append(f"  ... ({len(sorted_funcs) - 50} more)")

        return "\n".join(lines)


def discover_ppc32_functions(elf_path: str) -> Set[int]:
    """
    Convenience function to discover PPC32 functions from an ELF file.

    Args:
        elf_path: Path to PowerPC 32-bit ELF binary

    Returns:
        Set of function start VAs
    """
    disc = PPC32FuncDiscovery.from_path(elf_path)
    return disc.discover()


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 ppc32_func_discovery.py <elf_file>")
        sys.exit(1)

    func_starts = discover_ppc32_functions(sys.argv[1])
    disc = PPC32FuncDiscovery.from_path(sys.argv[1])
    print(disc.report(func_starts))
