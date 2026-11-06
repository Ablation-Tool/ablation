import os
import unittest
from pathlib import Path

from ablation.hpux import PaRiscDecoder, read_som


class PaRiscDecoderTests(unittest.TestCase):
    def setUp(self):
        self.decoder = PaRiscDecoder()

    def test_immediate_encoding(self):
        instruction = self.decoder.decode(0x36C10740, 0x2F9C0)
        self.assertEqual(instruction.mnemonic, "ldo")
        self.assertEqual(instruction.operands, " 3a0(r22),r1")
        load = self.decoder.decode(0x4BD73EB9, 0x2F9D4)
        self.assertEqual(load.operands, " -a4(sp),r23")
        store = self.decoder.decode(0x6BC03F99, 0x2F9D8)
        self.assertEqual(store.operands, " r0,-34(sp)")

    def test_branch_and_call(self):
        instruction = self.decoder.decode(0xE85F1DF5, 0x2F9DC)
        self.assertEqual(instruction.mnemonic, "b")
        self.assertEqual(instruction.operands, ",l 0x2f8dc,rp")
        self.assertEqual(instruction.branch_target, 0x2F8DC)
        self.assertTrue(instruction.is_call)
        self.assertEqual(instruction.text(), "0x0002f9dc: e85f1df5  b,l 0x2f8dc,rp")

    def test_copy_nop_and_unknown(self):
        self.assertEqual(self.decoder.decode(0x08000240, 0).mnemonic, "nop")
        copy = self.decoder.decode(0x0819025A, 0x2F9E0)
        self.assertEqual(copy.mnemonic, "copy")
        self.assertEqual(copy.operands, " r25,r26")
        self.assertFalse(self.decoder.decode(0xFFFFFFFF, 0).known)

    def test_byte_order_and_length(self):
        instructions = list(self.decoder.decode_bytes(bytes.fromhex("36c10740e85f1df5"), 0x1000))
        self.assertEqual(len(instructions), 2)
        self.assertEqual(instructions[0].address, 0x1000)
        self.assertEqual(instructions[1].address, 0x1004)
        with self.assertRaises(ValueError):
            list(self.decoder.decode_bytes(b"\0", 0))


@unittest.skipUnless(Path(os.environ.get("IBM_RE", "/media/cowboy/research/IBM-RE") + "/analysis/Lotus123/42bdf512ad55cd70/20261106T195800Z-motif-som/input/123_motif").is_file(), "SOM corpus unavailable")
class PaRiscCorpusTests(unittest.TestCase):
    def test_complete_corpus_decodes(self):
        path = Path(os.environ.get("IBM_RE", "/media/cowboy/research/IBM-RE")) / "analysis/Lotus123/42bdf512ad55cd70/20261106T195800Z-motif-som/input/123_motif"
        image = read_som(path)
        instructions = list(image.instructions(0x19BEC, 0x1419C0, 400000))
        self.assertEqual(len(instructions), 302965)
        self.assertEqual(sum(not item.known for item in instructions), 0)
        self.assertEqual(sum(item.is_call for item in instructions), 28661)


if __name__ == "__main__":
    unittest.main()
