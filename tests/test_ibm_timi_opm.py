import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from ablation.ibm_timi.cli import main
from ablation.ibm_timi.errors import FormatError, UnsupportedFormatError
from ablation.ibm_timi.opm import decode_opm_instruction
from ablation.ibm_timi.program import recover_program

IBM_RE = Path(os.environ.get("IBM_RE", "/media/cowboy/research/IBM-RE"))
RUN = IBM_RE / "analysis/as400-timi/6aa933fd4379d4b8/20261030T003743Z-pgm-segments"


class OpmDecoderTests(unittest.TestCase):
    def test_verified_instructions(self):
        cases = {
            "104200012001": ("CPYNV", (("odt_reference", 1), ("immediate", 1))),
            "3042004c2002": ("CPYNV", (("odt_reference", 76), ("immediate", 2))),
            "10420001bfc9": ("CPYNV", (("odt_reference", 1), ("immediate", -55))),
            "10b200710019": ("CPYBLA", (("odt_reference", 113), ("odt_reference", 25))),
        }
        for encoding, (mnemonic, expected) in cases.items():
            with self.subTest(encoding=encoding):
                result = decode_opm_instruction(bytes.fromhex(encoding))
                self.assertEqual(result["mnemonic"], mnemonic)
                self.assertEqual(result["length"], 6)
                for operand, (kind, value) in zip(result["operands"], expected):
                    self.assertEqual(operand["kind"], kind)
                    self.assertIn(value, operand.values())

    def test_null_and_rejected_forms(self):
        result = decode_opm_instruction(bytes.fromhex("104200000001"))
        self.assertEqual(result["operands"][0]["kind"], "null")
        for encoding in ("213200350036", "104240170025", "324200012001"):
            with self.subTest(encoding=encoding):
                with self.assertRaises(UnsupportedFormatError):
                    decode_opm_instruction(bytes.fromhex(encoding))
        with self.assertRaises(FormatError):
            decode_opm_instruction(bytes.fromhex("10420001"))
        with self.assertRaises(FormatError):
            decode_opm_instruction(bytes.fromhex("104200012001"), 1)


@unittest.skipUnless((RUN / "input/02-QZRDPDSPCL.bin").is_file(), "OPM corpus unavailable")
class OpmRecoveryTests(unittest.TestCase):
    def test_program_components(self):
        cases = {
            "02-QZRDPDSPCL.bin": (4580, 4425, "5081592b2ea4d5b90cb9623b71523ef1fbc9fd6f53ca60a50cbd6a75fed49a32", 492, "ea5b3efd42effabe145f024793d6d6ba4e5c92d5ddfad7f29c1f051bc06bc5ec", 879, "015c3c0afc726de3a2dc98e57e9f42c2fb3eb3f37c7b65acabecc527439086d6"),
            "04-QZRDPEXTCL.bin": (4760, 4227, "9a7e59244b4821e92d924075e9d17020ce129a02db477bb69d4fe26a9c74adf4", 476, "858e1b61af55a3e9cef85c01cf87ad41bd6810febde6e2ac795b67ef30a303c3", 1254, "6306fd46d0ca1ab39ed0d55bb9c30d7f2f2af763ed62b8bbe06bd698cdccad75"),
        }
        for filename, (template_size, end, digest, odv_length, odv_digest, oes_length, oes_digest) in cases.items():
            data = (RUN / "input" / filename).read_bytes()
            with self.subTest(program=filename):
                recovery = recover_program(data)
                self.assertEqual(recovery.object_header.offset, 0x220)
                self.assertEqual(recovery.template_offset, 0xE20)
                self.assertEqual(recovery.template_size, template_size)
                self.assertEqual([section["offset"] for section in recovery.sections], [0x200, 0xE00, 0x2400])
                self.assertEqual([section["type_raw"] for section in recovery.sections], ["0x0181", "0x0581", "0x0281"])
                self.assertEqual((recovery.code_start, recovery.code_end), (0xF20, end))
                self.assertEqual(recovery.code_sha256, digest)
                self.assertEqual([component["name"] for component in recovery.components], ["instruction_stream", "odv", "oes"])
                self.assertEqual([component["length"] for component in recovery.components], [end - 0xF20 + 1, odv_length, oes_length])
                self.assertEqual([component["sha256"] for component in recovery.components], [digest, odv_digest, oes_digest])
                self.assertTrue(all(component["length_includes_prefix"] for component in recovery.components))
                with tempfile.TemporaryDirectory() as temporary:
                    output = recovery.extract(data, Path(temporary) / "out")
                    self.assertEqual((output / "code.bin").read_bytes(), data[0xF20:end + 1])
                    for component, filename in zip(recovery.components[1:], ("odv.bin", "oes.bin")):
                        self.assertEqual((output / filename).read_bytes(), data[component["start"]:component["end_inclusive"] + 1])
                    report = json.loads((output / "program.json").read_text())
                    self.assertEqual(report["layout"], "legacy OPM program template with length-prefixed MI components")

    def test_corpus_instruction_decoding_and_cli(self):
        cases = {
            "02-QZRDPDSPCL.bin": (0xF62, "CPYNV", 76, "value", 1),
            "04-QZRDPEXTCL.bin": (0xF54, "CPYBLA", 102, "index", 101),
        }
        for filename, (offset, mnemonic, first, second_kind, second) in cases.items():
            data = (RUN / "input" / filename).read_bytes()
            with self.subTest(program=filename):
                recovery = recover_program(data)
                result = recovery.decode_at(data, offset)
                self.assertEqual(result["mnemonic"], mnemonic)
                self.assertEqual(result["operands"][0]["index"], first)
                self.assertEqual(result["operands"][1][second_kind], second)
                output = io.StringIO()
                with redirect_stdout(output):
                    self.assertEqual(main(["opm-decode", str(RUN / "input" / filename), hex(offset)]), 0)
                self.assertEqual(json.loads(output.getvalue())["mnemonic"], mnemonic)

    def test_malformed_opm_inputs(self):
        original = (RUN / "input/02-QZRDPDSPCL.bin").read_bytes()
        for offset, value in ((0xF20, 0xFFFFFFFF), (0x114C, 0xFFFFFFFF), (0x133C, 0xFFFFFFFF)):
            data = bytearray(original)
            data[offset:offset + 4] = value.to_bytes(4, "big")
            with self.subTest(corrupt_length=hex(offset)):
                with self.assertRaises(FormatError):
                    recover_program(data)
        data = bytearray(original)
        data[0xE2A] = 0
        with self.assertRaises(FormatError):
            recover_program(data)
        data = bytearray(original)
        data[0xE00:0xE02] = b"\x00\x00"
        with self.assertRaises(UnsupportedFormatError):
            recover_program(data)
        data = bytearray(original)
        data[0x30C] = 0x46
        with self.assertRaises(UnsupportedFormatError):
            recover_program(data)
        recovery = recover_program(original)
        with self.assertRaises(FormatError):
            recovery.decode_at(original, 0xF21)


if __name__ == "__main__":
    unittest.main()
