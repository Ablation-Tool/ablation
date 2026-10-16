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
import lief

class PPC32FuncDiscovery:
    """Discover function entry points in PowerPC 32-bit big-endian binaries."""

    def __init__(self, data: bytes, base_va: int, entry_va: int):
        self.data = data
        self.base_va = base_va
        self.entry_va = entry_va

    @classmethod
    def from_path(cls, path: str) -> "PPC32FuncDiscovery":
        """Load from ELF file - reads main LOAD segment directly."""
        elf = lief.parse(path)
        if not elf:
            raise ValueError(f"Failed to parse ELF: {path}")

        entry_va = elf.header.entrypoint
        if not entry_va:
            raise ValueError(f"ELF has no entry point (PIE or malformed): {path}")

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
                if target_offset & 0x02000000:  # Sign extend 26-bit value
                    target_offset -= 0x04000000

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

        # Predecessors that indicate a function boundary.
        # Only non-linking branches: blr, bctr, b (LK=0).
        # bl (LK=1) is a call — the instruction after a bl is still inside
        # the caller's body, not a new function entry.
        _BOUNDARY_PREDECESSORS = frozenset({
            0x4E800020,  # blr
            0x4E800420,  # bctr
        })

        for offset in range(0, len(self.data) - 11, 4):
            insn1 = struct.unpack('>I', self.data[offset:offset+4])[0]

            # Pattern 1: mflr r0; stw r0, X(r1); stwu r1, -Y(r1)
            # Only unpack insn2/insn3 when insn1 can possibly match.
            if insn1 == MFLR_R0:
                insn2 = struct.unpack('>I', self.data[offset+4:offset+8])[0]
                insn3 = struct.unpack('>I', self.data[offset+8:offset+12])[0]
                if ((insn2 >> 16) == STW_R0_PATTERN and
                        (insn3 >> 16) == STWU_R1_PATTERN):
                    prologue_vas.add(self.base_va + offset)
                continue

            # Pattern 2: stwu r1, -<frame>(r1) — require a non-linking branch
            # or function-return predecessor to avoid flagging mid-function stwu.
            if (insn1 >> 16) == STWU_R1_PATTERN:
                frame_size = insn1 & 0xFFFF
                if frame_size & 0x8000:  # Negative displacement only
                    frame_size = (~frame_size + 1) & 0xFFFF
                    if 16 <= frame_size <= 4096:
                        if offset >= 4:
                            prev = struct.unpack('>I', self.data[offset-4:offset])[0]
                            # b/ba (opcode 18, LK=0): top 6 bits = 0x48, LK bit = 0
                            is_b_no_link = (prev & 0xFC000001) == 0x48000000
                            # any conditional branch (opcode 16); covers all CR fields
                            is_bc = (prev >> 26) == 16
                            is_boundary = (
                                prev in _BOUNDARY_PREDECESSORS
                                or is_b_no_link
                                or is_bc
                            )
                        else:
                            is_boundary = True  # segment start is always a boundary
                        if is_boundary:
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
    """Convenience wrapper: parse ELF and return all discovered function VAs."""
    return PPC32FuncDiscovery.from_path(elf_path).discover()


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 ppc32_func_discovery.py <elf_file>")
        sys.exit(1)

    disc = PPC32FuncDiscovery.from_path(sys.argv[1])
    func_starts = disc.discover()
    print(disc.report(func_starts))
