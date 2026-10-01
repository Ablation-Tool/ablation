"""
hisi_rv32_ext.py: Correct-size decoder for HiSilicon RV32 custom-3 ISA extension.

HiSilicon WS63 / Hi3863 NearLink SoC firmware uses a proprietary custom-3 RISC-V
extension (opcode 0x7b). Capstone 5.x skipdata mode emits the first 2 bytes as a
raw .byte pair, then misinterprets the next 2 bytes as a valid compressed instruction.
This cascades 2-byte misalignment through the rest of every function that contains
a custom-3 instruction.

Field layout (RISC-V R-type, nML AND-rule grammar):
    image  = {funct7[6:0]} :: {rs2[4:0]} :: {rs1[4:0]} :: {funct3[2:0]} :: {rd[4:0]} :: 0b1111011
    syntax = "hisi.{funct3}.{funct7:02x}  {rd}, {rs1}, {rs2}"
    action = unknown without HiSilicon ISA docs

With ~9000 occurrences across ~8900 unique encodings in WS63-liteos-app, this is a
broad multi-operation extension, not a handful of accelerator calls. funct3 and funct7
distribute uniformly, confirming operand-bearing R-type layout.

See: docs/module-reference/hisi-rv32-ext.md
"""
from __future__ import annotations

import struct
from typing import Generator, Iterator, List, Optional, Tuple

try:
    import capstone
    from capstone import CS_ARCH_RISCV, CS_MODE_RISCV32, CS_MODE_RISCVC
    _HAS_CAPSTONE = True
except ImportError:
    _HAS_CAPSTONE = False


# ---------------------------------------------------------------------------
# ABI register names (RISC-V ilp32 psABI)
# ---------------------------------------------------------------------------

_ABI: List[str] = [
    'zero', 'ra',  'sp',  'gp',  'tp',
    't0',   't1',  't2',
    's0',   's1',
    'a0',   'a1',  'a2',  'a3',  'a4',  'a5',  'a6',  'a7',
    's2',   's3',  's4',  's5',  's6',  's7',  's8',  's9',  's10', 's11',
    't3',   't4',  't5',  't6',
]

_ARG_REGS = frozenset({'a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7'})

# ---------------------------------------------------------------------------
# Decoded instruction result
# ---------------------------------------------------------------------------

class HisiInsn:
    """A decoded HiSilicon custom-3 instruction."""
    __slots__ = ('address', 'size', 'mnemonic', 'op_str',
                 'rd', 'rs1', 'rs2', 'funct3', 'funct7')

    def __init__(
        self,
        address: int,
        rd: int, funct3: int, rs1: int, rs2: int, funct7: int,
        conservative: bool,
    ) -> None:
        self.address = address
        self.size    = 4
        self.funct3  = funct3
        self.funct7  = funct7
        self.rd      = rd
        self.rs1     = rs1
        self.rs2     = rs2
        rd_n  = _ABI[rd]  if rd  < 32 else f'x{rd}'
        rs1_n = _ABI[rs1] if rs1 < 32 else f'x{rs1}'
        rs2_n = _ABI[rs2] if rs2 < 32 else f'x{rs2}'
        self.mnemonic = f'hisi.{funct3}.{funct7:02x}'
        self.op_str   = f'{rd_n}, {rs1_n}, {rs2_n}'

    @property
    def taint_sources(self) -> List[str]:
        """Registers that may carry taint into this instruction."""
        return [_ABI[r] for r in (self.rs1, self.rs2) if r < 32]

    @property
    def taint_dest(self) -> Optional[str]:
        """Register written by this instruction (None if rd == zero)."""
        if self.rd == 0:
            return None
        return _ABI[self.rd] if self.rd < 32 else f'x{self.rd}'

    def as_tuple(self) -> Tuple[int, int, str, str]:
        """(address, size, mnemonic, op_str) — same layout as capstone.disasm_lite."""
        return (self.address, self.size, self.mnemonic, self.op_str)


# ---------------------------------------------------------------------------
# Decoder
# ---------------------------------------------------------------------------

class HiSiliconRV32ExtDecoder:
    """
    Drop-in replacement for capstone.Cs whose disasm_lite() correctly handles
    HiSilicon custom-3 instructions (opcode 0x7b, always 4 bytes).

    Capstone handles everything else; this decoder wraps it transparently.

    Args:
        conservative: if True, treat custom-3 as propagating taint from rs1/rs2
            to rd. If False (default), treat them as opaque with no taint.
    """

    def __init__(self, conservative: bool = False) -> None:
        self._conservative = conservative
        self._cs: Optional['capstone.Cs'] = None
        if _HAS_CAPSTONE:
            self._cs = capstone.Cs(CS_ARCH_RISCV, CS_MODE_RISCV32 | CS_MODE_RISCVC)
            self._cs.skipdata = True
            self._cs.detail   = False

    # ------------------------------------------------------------------
    # Core decode
    # ------------------------------------------------------------------

    @staticmethod
    def decode_custom3(word: int, address: int, conservative: bool) -> HisiInsn:
        """Decode a 32-bit custom-3 word (must have bits[6:0] == 0x7b) as R-type."""
        rd     = (word >>  7) & 0x1f
        funct3 = (word >> 12) & 0x07
        rs1    = (word >> 15) & 0x1f
        rs2    = (word >> 20) & 0x1f
        funct7 = (word >> 25) & 0x7f
        return HisiInsn(address, rd, funct3, rs1, rs2, funct7, conservative)

    # ------------------------------------------------------------------
    # disasm_lite: drop-in for capstone.Cs.disasm_lite
    # ------------------------------------------------------------------

    def disasm_lite(
        self,
        code: bytes,
        offset: int,
    ) -> Iterator[Tuple[int, int, str, str]]:
        """
        Yield (address, size, mnemonic, op_str) for each instruction.

        Custom-3 instructions (opcode 0x7b at 2-byte aligned positions within
        the stream) are decoded as R-type and emitted as 4-byte instructions.
        All other bytes are forwarded to Capstone in contiguous chunks.

        The stream position is tracked at 2-byte granularity matching RISC-V's
        minimum instruction alignment.
        """
        pos = 0
        length = len(code)

        while pos < length - 3:
            va = offset + pos

            # Peek at the opcode byte
            b0 = code[pos]
            b1 = code[pos + 1] if pos + 1 < length else 0xff

            # Custom-3 detection: low 7 bits of byte[0] == 0x7b
            # bits[1:0] == 11 → 4-byte instruction (guaranteed by RISC-V spec)
            if (b0 & 0x7f) == 0x7b and (b0 & 0x80) == 0:
                # Second byte must also align: for a standard R-type custom-3,
                # byte[0] bit[7] = rd[0]. We accept any value of rd[0], but
                # for this specific opcode byte[0]=0x7b rd[0]=0 always.
                if pos + 4 <= length:
                    word = struct.unpack_from('<I', code, pos)[0]
                    insn = self.decode_custom3(word, va, self._conservative)
                    yield insn.as_tuple()
                    pos += 4
                    continue

            # Not custom-3: determine instruction size from bits[1:0]
            # bits[1:0] == 11 → 4-byte; otherwise 2-byte (RVC)
            if (b0 & 0x03) == 0x03:
                insn_size = 4
            else:
                insn_size = 2

            # Collect a contiguous run of non-custom-3 bytes for Capstone.
            # Run until we hit the end, a custom-3 byte, or exhaust the buffer.
            run_start = pos
            run_pos   = pos + insn_size

            while run_pos < length - 3:
                nb0 = code[run_pos]
                if (nb0 & 0x7f) == 0x7b and (nb0 & 0x80) == 0:
                    break  # custom-3 ahead; end the run
                nb_size = 4 if (nb0 & 0x03) == 0x03 else 2
                run_pos += nb_size

            # Clamp run to buffer
            run_end = min(run_pos, length)
            chunk   = code[run_start:run_end]
            chunk_va = offset + run_start

            if self._cs is not None:
                yield from self._cs.disasm_lite(chunk, chunk_va)
            else:
                # Capstone unavailable: emit raw bytes as .byte entries
                for i in range(0, len(chunk), 2):
                    b = chunk[i]
                    sz = 4 if (b & 0x03) == 0x03 else 2
                    chunk_slice = chunk[i:i+sz]
                    if len(chunk_slice) == sz:
                        yield (chunk_va + i, sz, '.byte', ' '.join(f'0x{x:02x}' for x in chunk_slice))

            pos = run_end

        # Tail: fewer than 4 bytes remaining — pass to Capstone
        if pos < length and self._cs is not None:
            tail = code[pos:]
            yield from self._cs.disasm_lite(tail, offset + pos)

    # ------------------------------------------------------------------
    # Convenience: filter for only custom-3 from a full scan
    # ------------------------------------------------------------------

    def scan_custom3(
        self,
        code: bytes,
        base_va: int,
    ) -> List[HisiInsn]:
        """Return all custom-3 instructions found in the code region."""
        results: List[HisiInsn] = []
        for i in range(0, len(code) - 3, 2):
            b0 = code[i]
            if (b0 & 0x7f) == 0x7b and (b0 & 0x80) == 0:
                word = struct.unpack_from('<I', code, i)[0]
                results.append(self.decode_custom3(word, base_va + i, self._conservative))
        return results

    # ------------------------------------------------------------------
    # Opcode frequency report
    # ------------------------------------------------------------------

    def opcode_report(self, code: bytes, base_va: int) -> str:
        """Print top-N (funct3, funct7) pairs by occurrence count."""
        import collections
        counts: collections.Counter = collections.Counter()
        for insn in self.scan_custom3(code, base_va):
            counts[(insn.funct3, insn.funct7)] += 1
        lines = [f"HiSilicon custom-3 opcode frequency ({sum(counts.values())} total, {len(counts)} unique):"]
        for (f3, f7), cnt in counts.most_common(20):
            lines.append(f"  hisi.{f3}.{f7:02x}  x{cnt}")
        return '\n'.join(lines)
