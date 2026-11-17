import io
import os
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from ablation.analyzers.binary_context import BinaryContext
from ablation.analyzers.insn_m88k import M88kDecoder
from ablation.core.coff_m88k_parser import parse as parse_coff
from ablation.core.elf_m88k_parser import parse as parse_elf
from ablation.m88k.cli import main

IBM_RE = Path(os.environ.get("IBM_RE", "/media/cowboy/research/IBM-RE"))
DG_GEN = IBM_RE / "Lotus123/dg_gen"
MOTO_GEN = IBM_RE / "Lotus123/moto_gen"


class M88kDecoderTests(unittest.TestCase):
    def test_bsr_target(self):
        decoder = object.__new__(M88kDecoder)
        instruction = decoder.decode_word(0xCBFFF686, 0x102F10)
        self.assertEqual(instruction.mnemonic, "bsr")
        self.assertEqual(instruction.branch_target, 0x100928)
        self.assertTrue(instruction.is_call)
        instruction = decoder.decode_word(0xCBFFF686, 0x102F28)
        self.assertEqual(instruction.branch_target, 0x100940)

    def test_return_and_unknown(self):
        decoder = object.__new__(M88kDecoder)
        self.assertTrue(decoder.decode_word(0xF400C001, 0x1000).is_return)
        self.assertFalse(decoder.decode_word(0xFFFFFFFF, 0x1000).known)

    def test_invalid_length(self):
        decoder = object.__new__(M88kDecoder)
        with self.assertRaises(ValueError):
            list(decoder.disassemble_bytes(b"\0", 0))


@unittest.skipUnless(DG_GEN.is_file(), "DG/UX corpus unavailable")
class M88kElfTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = parse_elf(DG_GEN)
        cls.decoder = M88kDecoder(cls.binary)

    def test_dynamic_imports(self):
        self.assertEqual(self.binary.entry, 0x100994)
        self.assertEqual(len(self.binary.sections), 21)
        self.assertEqual(len(self.binary.plt), 15)
        self.assertEqual(self.binary.plt[0x100928], "system")
        self.assertEqual(self.binary.plt[0x100940], "gets")
        self.assertEqual(self.binary.needed, ["/usr/dglib/libc.so.1"])

    def test_frame_evidence(self):
        instructions = {item.address: item for item in self.decoder.disassemble_va(0x102C30, 0x170)}
        self.assertEqual(instructions[0x102C30].mnemonic, "subu")
        self.assertEqual(instructions[0x102C30].op_str, " r31,r31,0x170")
        self.assertEqual(instructions[0x102C3C].op_str, " r30,r31,0x30")
        self.assertEqual(instructions[0x102F20].op_str, " r13,r30,0xd0")
        self.assertEqual(instructions[0x102F28].branch_target, 0x100940)
        self.assertEqual(instructions[0x102F10].branch_target, 0x100928)
        buffer_size = 0x110 - 0xD0
        self.assertEqual(buffer_size, 64)
        self.assertEqual(self.binary.va_to_bytes(0x1138B0, 14), b"cat readme.txt")

    def test_complete_text_and_context(self):
        instructions = []
        va = self.binary.text.vaddr
        while self.binary.text.contains_va(va):
            instructions.append(self.decoder.decode_word(self.binary.text.read_word(va), va))
            va += 4
        self.assertEqual(len(instructions), 2468)
        self.assertEqual(sum(not item.known for item in instructions), 0)
        context = BinaryContext.load_or_build(str(DG_GEN), force_rebuild=True)
        self.assertEqual(context.arch, "m88k")
        self.assertEqual(len(context.plt), 15)
        self.assertIn((0x102C30, 0x100928, "system"), context.call_edges)
        self.assertIn((0x102C30, 0x100940, "gets"), context.call_edges)

    def test_cli(self):
        with redirect_stdout(io.StringIO()):
            self.assertEqual(main(["info", str(DG_GEN)]), 0)
            self.assertEqual(main(["disassemble", str(DG_GEN), "0x102f20", "--maximum", "4", "--json"]), 0)
            self.assertEqual(main(["calls", str(DG_GEN), "--json"]), 0)
            self.assertEqual(main(["functions", str(DG_GEN), "--json"]), 0)


@unittest.skipUnless(MOTO_GEN.is_file(), "M88K COFF corpus unavailable")
class M88kCoffTests(unittest.TestCase):
    def test_complete_text(self):
        binary = parse_coff(MOTO_GEN)
        decoder = M88kDecoder(binary)
        instructions = []
        va = binary.text.vaddr
        while binary.text.contains_va(va):
            instructions.append(decoder.decode_word(binary.text.read_word(va), va))
            va += 4
        self.assertEqual(len(instructions), 10000)
        self.assertEqual(sum(not item.known for item in instructions), 0)
        self.assertEqual(len(decoder.function_starts()), 126)
        self.assertEqual(len(decoder.string_refs()), 73)


if __name__ == "__main__":
    unittest.main()
