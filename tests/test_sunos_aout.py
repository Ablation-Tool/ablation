import hashlib
import io
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from contextlib import redirect_stdout

from ablation.sunos import AoutError, parse_aout, read_aout, render_calls, render_dispatch
from ablation.sunos.cli import main


IBM_RE = Path(os.environ.get("IBM_RE", "/media/cowboy/research/IBM-RE"))
SYBASE = IBM_RE / "analysis/Lotus123/88a7ce88f9d1ead0/20261107T001439Z-protocol/input/sybase"


def synthetic_image():
    header = struct.pack(">8I", 0x01030107, 8, 0, 0, 24, 0, 24, 0)
    text = struct.pack(">II", 0x40000000, 0x40000000)
    internal = struct.pack(">III", 0, 0x406, 0x100)
    external = struct.pack(">III", 4, (1 << 8) | 0x86, 0xFFFFFFFC)
    symbols = struct.pack(">IBBhI", 0, 0, 0, 0, 0) + struct.pack(">IBBhI", 1, 1, 0, 0, 0)
    return header + text + internal + external + symbols + b"\0_strlen\0"


def sparc_call(address, target):
    return (1 << 30) | (((target - address) // 4) & 0x3FFFFFFF)


def sparc_mov(value, register=9):
    return (2 << 30) | (register << 25) | (2 << 19) | (1 << 13) | (value & 0x1FFF)


def sparc_branch(address, target, condition, annul=False):
    return (int(annul) << 29) | (condition << 25) | (2 << 22) | (((target - address) // 4) & 0x3FFFFF)


def dispatch_image():
    words = {
        0x2000: sparc_call(0x2000, 0x2100),
        0x2004: sparc_mov(6),
        0x2008: sparc_mov(0),
        0x200C: sparc_call(0x200C, 0x2100),
        0x2010: sparc_branch(0x2010, 0x2020, 1, True),
        0x2014: sparc_mov(0),
        0x2018: sparc_branch(0x2018, 0x2030, 8),
        0x201C: 0x01000000,
        0x2020: sparc_call(0x2020, 0x2100),
        0x2024: 0x90100018,
        0x2028: sparc_call(0x2028, 0x2200),
        0x202C: 0x90100019,
        0x2030: 0x81C7E008,
        0x2034: 0x81E80000,
        0x2200: 0x9DE3BFA0,
        0x2204: sparc_call(0x2204, 0x2100),
        0x2208: sparc_mov(0),
        0x220C: 0x81C7E008,
        0x2210: 0x81E80000,
    }
    text_size = 0x214
    text = b"".join(struct.pack(">I", words.get(0x2000 + offset, 0)) for offset in range(0, text_size, 4))
    header = struct.pack(">8I", 0x01030107, text_size, 0, 0, 0, 0, 0, 0)
    return header + text


class AoutValidationTests(unittest.TestCase):
    def test_internal_external_and_unrelocated_calls(self):
        image = parse_aout(synthetic_image())
        calls = image.calls()
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0].target, 0x2100)
        self.assertEqual(calls[1].external_symbol, "_strlen")
        self.assertIsNone(calls[1].target)
        self.assertEqual(image.header.symbol_size, 24)
        self.assertEqual(len(image.relocations), 2)
        self.assertIn("0x2000 -> 0x2100", render_calls(image))
        self.assertIn("0x2004 -> _strlen", render_calls(image))

    def test_rejects_bad_magic_truncation_and_duplicate_relocations(self):
        with self.assertRaises(AoutError):
            parse_aout(b"")
        with self.assertRaises(AoutError):
            parse_aout(b"\0" * 32)
        with self.assertRaises(AoutError):
            parse_aout(synthetic_image()[:-1])
        raw = bytearray(synthetic_image())
        struct.pack_into(">I", raw, 52, 0)
        with self.assertRaisesRegex(AoutError, "duplicate text relocation"):
            parse_aout(bytes(raw)).calls()

    def test_rejects_invalid_relocation_and_external_symbol(self):
        raw = bytearray(synthetic_image())
        struct.pack_into(">I", raw, 56, 0x402)
        with self.assertRaisesRegex(AoutError, "unsupported direct-call relocation"):
            parse_aout(bytes(raw)).calls()
        raw = bytearray(synthetic_image())
        struct.pack_into(">I", raw, 84, 1)
        with self.assertRaisesRegex(AoutError, "not undefined"):
            parse_aout(bytes(raw)).calls()

    def test_dispatch_argument_provenance(self):
        image = parse_aout(dispatch_image())
        arguments = {item.call_address: item for item in image.dispatch_arguments(0x2100, wrappers=(0x2200,))}
        self.assertEqual(set(arguments), {0x2000, 0x200C, 0x2020, 0x2028, 0x2204})
        self.assertEqual(arguments[0x2000].value, 6)
        self.assertEqual(arguments[0x2000].provenance, "call_delay_slot")
        self.assertEqual(arguments[0x200C].provenance, "preceding_instruction")
        self.assertEqual(arguments[0x2020].provenance, "branch_delay_slot")
        self.assertEqual(arguments[0x2020].branch_address, 0x2010)
        self.assertEqual(arguments[0x2028].provenance, "wrapper")
        self.assertEqual(arguments[0x2028].wrapper_address, 0x2200)
        self.assertEqual(arguments[0x2028].dispatcher_call_address, 0x2204)
        self.assertTrue(all(item.value == 0 for item in arguments.values() if item.call_address != 0x2000))
        rendered = render_dispatch(image, 0x2100, wrappers=(0x2200,))
        self.assertIn("0x2020 -> 0x2100 %o1=0 provenance=branch_delay_slot", rendered)
        self.assertIn("dispatch_calls=5 resolved=5 unresolved=0", rendered)

    def test_dispatch_provenance_remains_conservative(self):
        raw = bytearray(dispatch_image())
        struct.pack_into(">I", raw, 0x20 + 0x18, 0x01000000)
        image = parse_aout(bytes(raw))
        call = next(item for item in image.calls() if item.address == 0x2020)
        self.assertIsNone(image.call_argument(call).value)
        struct.pack_into(">I", raw, 0x24, sparc_mov(-1))
        modified = parse_aout(bytes(raw))
        argument = modified.call_argument(modified.calls()[0])
        self.assertEqual(argument.value, -1)
        with self.assertRaisesRegex(AoutError, "invalid SPARC register"):
            image.call_argument(call, "%o8")

    def test_dispatch_cli_json(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "dispatch"
            path.write_bytes(dispatch_image())
            with redirect_stdout(io.StringIO()) as output:
                self.assertEqual(main(["dispatch", str(path), "--target", "0x2100", "--wrapper", "0x2200", "--json"]), 0)
            arguments = {item["call_address"]: item for item in json.loads(output.getvalue())}
            self.assertEqual(arguments[0x2020]["value"], 0)
            self.assertEqual(arguments[0x2028]["provenance"], "wrapper")

    def test_cli_and_hash(self):
        raw = synthetic_image()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample"
            path.write_bytes(raw)
            with redirect_stdout(io.StringIO()) as output:
                self.assertEqual(main(["info", str(path), "--json"]), 0)
                self.assertEqual(main(["render", str(path)]), 0)
            self.assertIn("0x2000 -> 0x2100", output.getvalue())
        self.assertEqual(hashlib.sha256(raw).hexdigest(), parse_aout(raw).sha256)


@unittest.skipUnless(SYBASE.is_file(), "Sybase corpus unavailable")
class SybaseCorpusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = read_aout(SYBASE)

    def test_real_layout_and_corrected_calls(self):
        self.assertEqual(self.image.sha256, "88a7ce88f9d1ead09508d0b01e636616d14442c98f4c74171d468680e73a5cce")
        self.assertEqual(len(self.image.symbols), 1417)
        self.assertEqual(len(self.image.relocations), 5800)
        calls = {item.address: item for item in self.image.calls()}
        self.assertEqual(calls[0xB1B0].target, 0xF624)
        self.assertEqual(calls[0xB270].target, 0x2998)
        self.assertEqual(calls[0xB31C].target, 0xD0D8)
        self.assertTrue(any(item.external_symbol == "_strlen" for item in calls.values()))
        self.assertTrue(any(item.target == 0xA428 for item in calls.values()))

    def test_real_dispatch_argument_census(self):
        arguments = self.image.dispatch_arguments(0xA428, wrappers=(0xA4C8,))
        self.assertEqual(len(arguments), 12)
        self.assertEqual({item.value for item in arguments}, {0, 6})
        self.assertTrue(all(item.value is not None and item.value >= 0 for item in arguments))
        by_address = {item.call_address: item for item in arguments}
        self.assertEqual(by_address[0x9E90].provenance, "branch_delay_slot")
        self.assertEqual(by_address[0x9E90].setup_address, 0x9EF0)
        self.assertEqual(by_address[0xAEEC].provenance, "branch_delay_slot")
        self.assertEqual(by_address[0xAEEC].setup_address, 0xAEC8)
        self.assertEqual([item.provenance for item in arguments if item.call_address in (0xA3B0, 0xA3D8)], ["wrapper", "wrapper"])

    def test_real_cli_and_render(self):
        with redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main(["info", str(SYBASE), "--json"]), 0)
            self.assertEqual(main(["calls", str(SYBASE), "--target", "0xf624", "--json"]), 0)
            self.assertEqual(main(["render", str(SYBASE), "--target", "0xf624"]), 0)
        self.assertIn("0xb1b0 -> 0xf624", output.getvalue())


if __name__ == "__main__":
    unittest.main()
