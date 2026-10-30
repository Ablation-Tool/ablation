import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from ablation.ibm_timi.catalogue import parse_legacy_catalogue
from ablation.ibm_timi.cli import main
from ablation.ibm_timi.errors import FormatError, UnsupportedFormatError
from ablation.ibm_timi.program import parse_object_header, recover_program
from ablation.ibm_timi.savf import read_savf

IBM_RE = Path(os.environ.get("IBM_RE", "/media/cowboy/research/IBM-RE"))
RUN = IBM_RE / "analysis/as400-timi/6aa933fd4379d4b8/20261030T003743Z-pgm-segments"


@unittest.skipUnless((RUN / "input/qzrdu0mm.sav").is_file(), "TIMI corpus unavailable")
class LegacyCatalogueTests(unittest.TestCase):
    def test_catalogue_entries(self):
        item = next(item for item in read_savf(RUN / "input/qzrdu0mm.sav").items if item.object_type == 0x19DB)
        catalogue = parse_legacy_catalogue(item)
        self.assertEqual(catalogue.command, 2)
        self.assertEqual(catalogue.target_release, 0x34)
        self.assertEqual(catalogue.library, "QZRDPACK")
        self.assertEqual(catalogue.base_object_type, 0x0401)
        self.assertEqual(catalogue.metadata_length, 7936)
        self.assertEqual(len(catalogue.entries), 11)
        self.assertEqual(
            [(entry.name, entry.object_type) for entry in catalogue.entries],
            [
                ("QZRDPACK", 0x0401), ("QZRDPDSP", 0x0201), ("QZRDPDSPCL", 0x0201),
                ("QZRDPEXT", 0x0201), ("QZRDPEXTCL", 0x0201), ("QZRDPACK", 0x0E03),
                ("QDZRDPDSP", 0x1901), ("UNPACK", 0x1901), ("DSPPCKF", 0x1905),
                ("EXTPCKF", 0x1905), ("QHZRDCMD1", 0x1915),
            ],
        )
        self.assertEqual(catalogue.entries[0].owner, "QPGMR")
        self.assertEqual(catalogue.entries[7].owner, "QSECOFR")
        self.assertEqual(catalogue.entries[1].size, 32768)
        with redirect_stdout(io.StringIO()):
            self.assertEqual(main(["catalogue-info", str(RUN / "input/qzrdu0mm.sav")]), 0)

    def test_bad_catalogue_command(self):
        item = next(item for item in read_savf(RUN / "input/qzrdu0mm.sav").items if item.object_type == 0x19DB)
        item.raw = item.raw[:0x300] + b"\x01" + item.raw[0x301:]
        with self.assertRaises(FormatError):
            parse_legacy_catalogue(item)


@unittest.skipUnless((RUN / "input/01-QZRDPDSP.bin").is_file(), "TIMI program corpus unavailable")
class ProgramRecoveryTests(unittest.TestCase):
    def test_non_cl_programs(self):
        cases = {
            "01-QZRDPDSP.bin": ("QZRDPDSP", 1016, 4191, "b6dc209e3c6773f74d8603e83e68addfdb0b59bcf8df444cc9b00ebb431abb8e"),
            "03-QZRDPEXT.bin": ("QZRDPEXT", 1040, 5759, "17ad5d676d357b7b746c9964897b8b282091b13488b82e5f2870f3264ad5cce0"),
        }
        for filename, (name, start, end, digest) in cases.items():
            path = RUN / "input" / filename
            data = path.read_bytes()
            with self.subTest(program=name):
                recovery = recover_program(data)
                self.assertEqual(recovery.object_header.name, name)
                self.assertEqual(recovery.object_header.offset, 0x220)
                self.assertEqual(recovery.object_header.program_header_offset, 0x300)
                self.assertEqual(recovery.object_header.object_type, 0x0201)
                self.assertEqual(recovery.version_table_offset, 0x400)
                self.assertEqual(recovery.target_release, "0x0230")
                self.assertEqual(recovery.created_on_release, "0x0310")
                self.assertEqual(recovery.segment_table_offset, 0x4E0)
                self.assertEqual([entry["segment_use"] for entry in recovery.segments], ["0x02", "0x01"])
                self.assertEqual([entry["declared_page_count"] for entry in recovery.segments], [512, 256])
                self.assertEqual(recovery.activation_header_offset, 0x580)
                self.assertEqual((recovery.code_start, recovery.code_end), (start, end))
                self.assertEqual(recovery.code_sha256, digest)
                with tempfile.TemporaryDirectory() as temporary:
                    output = recovery.extract(data, Path(temporary) / "out")
                    self.assertEqual((output / "code.bin").read_bytes(), data[start:end + 1])
                    report = json.loads((output / "program.json").read_text())
                    self.assertEqual(report["code_region"]["length"], end - start + 1)

    def test_powerpc_as_reference_anchors(self):
        data = (RUN / "input/01-QZRDPDSP.bin").read_bytes()
        anchors = {0x1000: "3007022e", 0x100C: "3007cb03", 0x1010: "3138305e"}
        for offset, encoding in anchors.items():
            with self.subTest(offset=offset):
                self.assertEqual(data[offset:offset + 4].hex(), encoding)

    def test_cl_variants_are_rejected(self):
        for filename in ("02-QZRDPDSPCL.bin", "04-QZRDPEXTCL.bin"):
            with self.subTest(filename=filename):
                with self.assertRaises(UnsupportedFormatError):
                    recover_program((RUN / "input" / filename).read_bytes())

    def test_malformed_headers_and_pointers(self):
        data = bytearray((RUN / "input/01-QZRDPDSP.bin").read_bytes())
        data[0x222:0x224] = b"\x00\x00"
        with self.assertRaises(UnsupportedFormatError):
            parse_object_header(data)
        data = bytearray((RUN / "input/01-QZRDPDSP.bin").read_bytes())
        data[0x224] = 0
        with self.assertRaises(FormatError):
            parse_object_header(data)
        with self.assertRaises(FormatError):
            recover_program(data[:0x300])
        data = bytearray((RUN / "input/01-QZRDPDSP.bin").read_bytes())
        data[0x314] = 0x40
        with self.assertRaises(UnsupportedFormatError):
            recover_program(data)
        data = bytearray((RUN / "input/01-QZRDPDSP.bin").read_bytes())
        data[0x580:0x588] = (0x100000).to_bytes(8, "big")
        with self.assertRaises(FormatError):
            recover_program(data)

    def test_program_cli(self):
        with tempfile.TemporaryDirectory() as temporary:
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main(["program-info", str(RUN / "input/01-QZRDPDSP.bin")]), 0)
                self.assertEqual(main(["program-extract", str(RUN / "input/01-QZRDPDSP.bin"), temporary]), 0)
            self.assertTrue((Path(temporary) / "code.bin").is_file())
            self.assertTrue((Path(temporary) / "program.json").is_file())


if __name__ == "__main__":
    unittest.main()
