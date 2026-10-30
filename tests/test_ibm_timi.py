import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from ablation.ibm_timi.cli import main
from ablation.ibm_timi.errors import FormatError, UnsupportedFormatError
from ablation.ibm_timi.savf import (
    QZRDPACK_MAGIC, logical_to_physical, parse_savf, read_qzrdpack_header,
    read_savf, record_checksum,
)

IBM_RE = Path(os.environ.get("IBM_RE", "/media/cowboy/research/IBM-RE"))
SAVF_CORPUS = IBM_RE / "analysis/as400-timi/6aa933fd4379d4b8/20261029T234341Z-savlib-bootstrap/input/qzrdu0mm.sav"
TIMI_CORPUS = IBM_RE / "analysis/as400-timi/6aa933fd4379d4b8/20261029T234341Z-savlib-bootstrap/input/C05PGM.fil"


def item_bytes(name="TEST", payload=b"data", packed=0):
    descriptor = bytearray(512)
    descriptor[:4] = b"\xff" * 4
    encoded = name.encode("cp500")[:10]
    descriptor[4:14] = encoded + b"\x40" * (10 - len(encoded))
    descriptor[0x22:0x24] = (0x0201).to_bytes(2, "big")
    stored = 512 + ((len(payload) + 511) // 512) * 512
    descriptor[0x48:0x4C] = (stored // 512 - 1).to_bytes(4, "big")
    descriptor[0xCC:0xD0] = (stored // 512).to_bytes(4, "big")
    descriptor[0x170:0x178] = packed.to_bytes(8, "big")
    return bytes(descriptor) + payload + bytes(stored - 512 - len(payload))


def make_savf(items, header_pages=1):
    timestamp = bytes.fromhex("7b342b8ba70000e3")
    header = bytearray(header_pages * 512)
    header[:8] = timestamp
    if header_pages > 1:
        header[0x34:0x38] = (header_pages * 512).to_bytes(4, "big")
    stream = bytearray(header)
    for item in items:
        stream.extend(item)
    count = len(stream) // 512
    stream[8:12] = count.to_bytes(4, "big")
    physical = bytearray()
    for index in range(count):
        payload = bytes(stream[index * 512:(index + 1) * 512])
        physical.extend(payload)
        physical.extend(record_checksum(index + 1, payload, timestamp))
    return bytes(physical)


class ChecksumTests(unittest.TestCase):
    def test_public_vectors_and_coordinate_mapping(self):
        timestamp = bytes.fromhex("af2012d24b4b7f20")
        self.assertEqual(
            record_checksum(2, bytes(512), timestamp).hex(),
            "00000002af2012d24b4b7f2000004000",
        )
        patterned = bytes(range(256)) * 2
        self.assertEqual(
            record_checksum(2, patterned, timestamp).hex(),
            "000000028e43fa214379304d4081df91",
        )
        self.assertEqual(logical_to_physical(0x6D50), 0x70B0)
        self.assertEqual(logical_to_physical(0x6D53), 0x70B3)
        with self.assertRaises(ValueError):
            record_checksum(2, b"short", timestamp)


class SavfTests(unittest.TestCase):
    def test_parse_extract_and_header_length(self):
        save = parse_savf(make_savf([item_bytes(payload=b"payload")], header_pages=2))
        self.assertEqual(save.record_count, 4)
        self.assertEqual(save.checksum_report["failure_count"], 0)
        self.assertEqual(len(save.items), 1)
        item = save.items[0]
        self.assertEqual(item.name, "TEST")
        self.assertEqual(item.offset, 1024)
        self.assertEqual(item.raw[512:519], b"payload")
        self.assertEqual(save.global_checksum["status"], "not_verified")
        with tempfile.TemporaryDirectory() as temporary:
            output = save.extract(Path(temporary) / "out")
            raw = (output / "items" / "00-TEST.bin").read_bytes()
            self.assertEqual(raw, item.raw)
            inventory = json.loads((output / "inventory.json").read_text())
            self.assertTrue(inventory["items"][0]["raw_includes_descriptor"])
            with self.assertRaises(FileExistsError):
                save.extract(output)

    def test_truncation_checksum_and_packed_rejection(self):
        raw = make_savf([item_bytes()])
        with self.assertRaises(FormatError):
            parse_savf(raw[:-1])
        with self.assertRaises(FormatError):
            parse_savf(raw[:100] + bytes([raw[100] ^ 1]) + raw[101:])
        with self.assertRaises(FormatError):
            parse_savf(raw[:8] + (999).to_bytes(4, "big") + raw[12:])
        with self.assertRaises(UnsupportedFormatError):
            parse_savf(make_savf([item_bytes(packed=1)]))
        with self.assertRaises(FormatError):
            parse_savf(b"")

    def test_cli(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "sample.savf"
            path.write_bytes(make_savf([item_bytes()]))
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main(["savf-info", str(path), "--summary"]), 0)
                self.assertEqual(main(["savf-extract", str(path), str(Path(temporary) / "out")]), 0)
            self.assertTrue((Path(temporary) / "out" / "inventory.json").is_file())


@unittest.skipUnless(SAVF_CORPUS.is_file() and TIMI_CORPUS.is_file(), "IBM TIMI corpus unavailable")
class CorpusTests(unittest.TestCase):
    def test_savf_corpus_and_extraction(self):
        save = read_savf(SAVF_CORPUS)
        self.assertEqual(save.record_count, 352)
        self.assertEqual(save.logical_size, 180224)
        self.assertEqual(save.checksum_report["verified_count"], 352)
        self.assertEqual(save.checksum_report["failure_count"], 0)
        self.assertEqual(
            [item.name for item in save.items],
            ["QSRDSSPC.1", "QZRDPDSP", "QZRDPDSPCL", "QZRDPEXT", "QZRDPEXTCL", "QZRDPACK", "QDZRDPDSP", "DSPPCKF", "EXTPCKF", "QHZRDCMD1"],
        )
        self.assertEqual(sum(item.object_type == 0x0201 for item in save.items), 4)
        self.assertEqual(save.items[-1].offset + save.items[-1].stored_length, save.logical_size)
        with tempfile.TemporaryDirectory() as temporary:
            output = save.extract(Path(temporary) / "out")
            for item in save.items:
                matches = list((output / "items").glob(f"{item.index:02d}-*.bin"))
                self.assertEqual(len(matches), 1)
                self.assertEqual(matches[0].read_bytes(), item.raw)

    def test_qzrdpack_headers(self):
        header = read_qzrdpack_header(TIMI_CORPUS)
        self.assertEqual(header["sha256"], "1ee9b76f50ee37559ed63bb836d065c0bc7cb6a1c753753795446531dead7cf7")
        self.assertEqual(header["licensed_program"], "C05MMPGM")
        self.assertEqual(header["library"], "DNLDLIB")
        self.assertEqual(header["context"], "QTEMP")
        self.assertEqual(header["save_command"], "SAVLICPGM")
        self.assertEqual(header["release"], "V3R7M0")
        self.assertEqual(header["status"], "header_only")
        other = read_qzrdpack_header(IBM_RE / "AS400-NC/a0700mm.fil")
        self.assertEqual(other["licensed_program"], "QA0700MM")
        self.assertIsNone(other["library"])
        self.assertEqual(other["release"], "V3R7M0")
        navio = read_qzrdpack_header(IBM_RE / "NC-AS400/navio/b1000mm.fil")
        self.assertEqual(navio["licensed_program"], "QB1000MM")
        self.assertEqual(navio["release"], "V3R2M0")
        with redirect_stdout(io.StringIO()):
            self.assertEqual(main(["qzrd-info", str(TIMI_CORPUS)]), 0)

    def test_bad_qzrdpack_magic(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "bad.bin"
            path.write_bytes(bytes(512))
            with self.assertRaises(FormatError):
                read_qzrdpack_header(path)
        self.assertEqual(QZRDPACK_MAGIC.decode("cp500"), "QZRDPACK")


if __name__ == "__main__":
    unittest.main()
