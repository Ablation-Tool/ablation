import json
import os
import struct
import tempfile
import unittest
from collections import OrderedDict
from pathlib import Path

from ablation.zos_re.cli import main
from ablation.zos_re.errors import FormatError, SafetyError
from ablation.zos_re.functions import decode_cfg, prolog_candidates, recover_functions
from ablation.zos_re.image import LoadImage
from ablation.zos_re.loadmodule import parse_load_image
from ablation.zos_re.netdata import (
    Member, _extract_members, _parse_directory_record, parse_netdata, parse_text_units,
)
from ablation.zos_re.s390 import S390Decoder
from ablation.zos_re.sid import compare_inventories, demangle_ibm_cpp, parse_side_deck


IBM_RE = Path(os.environ.get("IBM_RE", "/media/cowboy/research/IBM-RE"))


def text_unit(key, value, numeric=False):
    if numeric:
        raw = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    elif isinstance(value, bytes):
        raw = value
    else:
        raw = value.encode("cp1140")
    return struct.pack(">HHH", key, 1, len(raw)) + raw


def control(kind, units=b"", number=None):
    body = kind.encode("cp1140")
    if number is not None:
        body += struct.pack(">I", number)
    body += units
    return bytes([len(body) + 2, 0xE0]) + body


def sequential_netdata(payload=b"abc\x00"):
    header = text_unit(0x102F, 1, True)
    descriptor = (
        text_unit(0x1028, "INMCOPY") + text_unit(0x003C, 0x4000, True)
        + text_unit(0x0042, 80, True) + text_unit(0x0049, 0x9000, True)
        + text_unit(0x0002, "TEST.DATA")
    )
    transport = text_unit(0x003C, 0x4000, True) + text_unit(0x0042, 80, True)
    return (
        control("INMR01", header) + control("INMR02", descriptor, 1)
        + control("INMR03", transport) + bytes([len(payload) + 2, 0xC0]) + payload
        + control("INMR06")
    )


def minimal_pds_image():
    name = "CEESTART".encode("cp500")
    cesd_entry = name + b"\x00\x00\x00\x00\x07\x00\x00\x04"
    cesd = b"\x20\x80\x00\x00\x00\x01\x00\x10" + cesd_entry
    idr = b"\x80\x06\x84\x00\x00\x00\x00"
    ccw = b"\x06\x00\x00\x00\x40\x00\x00\x04"
    control_record = b"\x0d\x00\x00\x00\x00\x04\x00\x00" + ccw + b"\x00\x01\x00\x04"
    return cesd + idr + control_record + b"\x07\xfe\x00\x00"


def minimal_program_object():
    data = bytearray(0x1004)
    data[:8] = "IEWPLMH ".encode("cp500")
    struct.pack_into(">I", data, 8, 0x78)
    struct.pack_into(">II", data, 0x10, len(data), 1)
    struct.pack_into(">III", data, 0x18, 7 << 16, 0x1000, 4)
    data[0x1000:] = b"\x07\xfe\x00\x00"
    return bytes(data)


def ppa_image(trampoline=False):
    data = bytearray(256)
    entry = 64
    data[entry:entry + 4] = b"\x47\xf0\xf0\x01"
    data[entry + 4] = 1
    data[entry + 5:entry + 8] = b"\xc3\xc5\xc5"
    struct.pack_into(">I", data, entry + 8, 128)
    struct.pack_into(">i", data, entry + 12, -32)
    data[32] = 4
    struct.pack_into(">H", data, 40, 4)
    data[42:46] = "main".encode("cp500")
    if trampoline:
        data[entry + 3] = 32
        data[entry + 16:entry + 20] = b"\x47\xf0\xf0\x01"
        data[96:100] = b"\x07\xfe\x00\x00"
    else:
        data[80:84] = b"\x07\xfe\x00\x00"
    return LoadImage("synthetic", "", "IEWPLMH", bytes(data), [], [], None, [])


def sid_records(*lines):
    records = []
    for line in lines:
        encoded = line.encode("cp1140")[:80]
        records.append(encoded + b"\x40" * (80 - len(encoded)))
    return b"".join(records)


class NetdataTests(unittest.TestCase):
    def test_text_units_split_dataset_name(self):
        raw = struct.pack(">HHH", 2, 2, 3) + "ABC".encode("cp1140") + struct.pack(">H", 2) + "DE".encode("cp1140")
        units, _ = parse_text_units(raw)
        self.assertEqual(units["INMDSNAM"], "ABC.DE")

    def test_sequential_netdata_and_required_terminator(self):
        parsed = parse_netdata(sequential_netdata())
        self.assertTrue(parsed.terminated)
        self.assertEqual(parsed.datasets["TEST.DATA"].member_bytes("DATA"), b"abc\x00")
        with self.assertRaises(FormatError):
            parse_netdata(sequential_netdata()[:-9])

    def test_pds_directory_alias_and_payload(self):
        entries = bytearray()
        entries.extend("PRIMARY ".encode("cp1140") + b"\x00\x00\x01\x00")
        entries.extend("ALIAS   ".encode("cp1140") + b"\x00\x00\x01\x80")
        entries.extend(b"\xff" * 8)
        record = bytearray(276)
        record[12:20] = "PRIMARY ".encode("cp1140")
        struct.pack_into(">H", record, 20, len(entries) + 2)
        record[22:22 + len(entries)] = entries
        members = OrderedDict()
        self.assertTrue(_parse_directory_record(record, members))
        stream = bytearray(12) + b"payload" + bytearray(12)
        struct.pack_into(">H", stream, 10, 7)
        _extract_members([bytes(stream)], {"container_type": "PDS", "recfm": "U"}, members)
        self.assertEqual(members["PRIMARY"].data, b"payload")
        self.assertEqual(members["ALIAS"].target, "PRIMARY")
        self.assertEqual(members["ALIAS"].data, None)


class LoadImageTests(unittest.TestCase):
    def test_pds_load_image(self):
        image = parse_load_image(minimal_pds_image())
        self.assertEqual(image.format, "PDS_LOAD_MODULE")
        self.assertEqual(image.text, b"\x07\xfe\x00\x00")
        self.assertEqual(image.symbols[0].name, "CEESTART")
        self.assertEqual(image.metadata["text_gap_bytes"], 0)

    def test_program_object_fallback(self):
        image = parse_load_image(minimal_program_object())
        self.assertEqual(image.format, "IEWPLMH")
        self.assertIsNone(image.entry_rva)
        self.assertEqual(image.text, b"\x07\xfe\x00\x00")

    def test_truncated_text_rejected(self):
        data = bytearray(minimal_program_object())
        struct.pack_into(">I", data, 0x1C, len(data) + 1)
        with self.assertRaises(FormatError):
            parse_load_image(data)

    def test_truncated_segment_record_rejected(self):
        data = bytearray(minimal_program_object())
        data.extend(b"\x00" * (0x1030 - len(data)))
        struct.pack_into(">I", data, 0x10, len(data))
        data[0x1000:0x1008] = "IEWPSEGM".encode("cp500")
        with self.assertRaises(FormatError):
            parse_load_image(data)


class S390Tests(unittest.TestCase):
    def setUp(self):
        self.decoder = S390Decoder()

    def test_control_flow_and_operands(self):
        self.assertEqual(self.decoder.decode(bytes.fromhex("07fe")).flow, "return")
        self.assertEqual(self.decoder.decode(bytes.fromhex("a7f40002")).target, 4)
        self.assertEqual(self.decoder.decode(bytes.fromhex("c0f400000002")).target, 4)
        branch = self.decoder.decode(bytes.fromhex("47f00004"))
        self.assertEqual((branch.target, branch.flow), (4, "jump"))
        store = self.decoder.decode(bytes.fromhex("50e0484c"))
        self.assertEqual(store.mnemonic, "st")

    def test_unknown_instruction_preserves_bytes(self):
        instruction = self.decoder.decode(b"\xff" * 6)
        self.assertFalse(instruction.known)
        self.assertEqual(instruction.data, b"\xff" * 6)

    def test_cfg(self):
        instructions, _, _, complete = decode_cfg(bytes.fromhex("a7f4000207fe"), 0, self.decoder)
        self.assertTrue(complete)
        self.assertEqual([item.address for item in instructions], [0, 4])

    def test_ppa_variants(self):
        for trampoline in (False, True):
            recovery = recover_functions(ppa_image(trampoline))
            self.assertEqual(len(recovery.functions), 1)
            function = recovery.functions[0]
            self.assertEqual(function.name, "main")
            self.assertEqual(function.code_rva, 96 if trampoline else 80)
            self.assertEqual(function.kind, "PPA_LE" if trampoline else "PPA_CPP")

    def test_xplink_prolog(self):
        candidates = prolog_candidates(bytes.fromhex("50e0484c07fe"), S390Decoder())
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].kind, "XPLINK_SAVE_STORE")


class SideDeckTests(unittest.TestCase):
    def test_known_demangles(self):
        samples = {
            "__aad__7IStringFPCc": "IString::operator+=(const char*)",
            "__ad__FPCcRC7IString": "operator+(const char*, const IString&)",
            "__ad__7IStringCFPCc": "IString::operator+(const char*) const",
            "__as__14IFullExceptionFRC14IFullException": "IFullException::operator=(const IFullException&)",
            "__ct__7IStringFPCc": "IString::IString(const char*)",
        }
        for symbol, expected in samples.items():
            self.assertEqual(demangle_ibm_cpp(symbol), (expected, "demangled"))

    def test_parse_normalize_and_compare(self):
        first = parse_side_deck(sid_records(
            " IMPORT CODE 'ASCCOLL'  currentPID__12IApplicationFv",
            " IMPORT DATA 'ASCCOLL'  __vft12IApplication",
        ))
        second = parse_side_deck(sid_records(
            " IMPORT CODE 'ASCCOLL'  currentPID__12IApplicationFv",
            " IMPORT CODE,'IOC','__as__14IFullExceptionFRC14IFullException'",
        ))
        self.assertEqual(len(first.statements), 2)
        self.assertEqual(first.statements[0].demangled, "IApplication::currentPID()")
        comparison = compare_inventories(first, second)
        self.assertEqual(comparison["intersection_count"], 1)
        with self.assertRaises(FormatError):
            parse_side_deck(sid_records(" IMPORT CODE,'IOC','unterminated*"))

    def test_continuation(self):
        deck = parse_side_deck(sid_records(
            " IMPORT CODE,'IOC','__als__FRQ2_8IUnicode14EUnicodeBoundsR11IDataStream*",
            "'",
        ))
        self.assertEqual(len(deck.statements), 1)
        self.assertEqual(deck.statements[0].end_record, 2)
        self.assertEqual(deck.statements[0].demangled, "operator<<(IUnicode::EUnicodeBounds&, IDataStream&)")


class OutputSafetyTests(unittest.TestCase):
    def test_existing_symlink_is_not_followed(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "output"
            output.mkdir()
            outside = Path(temporary) / "outside"
            outside.write_bytes(b"unchanged")
            os.symlink(outside, output / "text.bin")
            with self.assertRaises(SafetyError):
                ppa_image().write(output)
            self.assertEqual(outside.read_bytes(), b"unchanged")


class CliTests(unittest.TestCase):
    def test_sequential_cli_pipeline(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "sample.xmit"
            output = Path(temporary) / "out"
            source.write_bytes(sequential_netdata())
            self.assertEqual(main(["pipeline", str(source), str(output)]), 0)
            summary = json.loads((output / "pipeline.json").read_text())
            self.assertEqual(summary["items"][0]["kind"], "uninterpreted")
            self.assertTrue((output / "TEST.DATA" / "DATA.bin").is_file())


@unittest.skipUnless(IBM_RE.is_dir(), "IBM-RE golden corpus is unavailable")
class IbmGoldenTests(unittest.TestCase):
    def test_netdata_golden(self):
        cases = {
            "iocchk.xmit": ("TS56136.IOCCHK", 1, "IOCCHK", "ed15e92b831ea44d61d46ba2d43a3ef1cfdca999c682226a04e27be7964c81a6"),
            "IOC_DLL.sclbdll": ("TSKRIK.SCLBDLL", 7, "CLB3CLAS", "a9996026b0908424b058fb203a42abcd027e4a2f17b98ec6d914d4f29a31c2b9"),
            "IOC_DLL.sclbdll2": ("TSKRIK.SCLBDLL2", 7, "CLBEIOC", "46ccf0c308fc812359823279734685f7d78e80e025b8e1c8e66c40232ff3555b"),
            "IOC_DLL.sclbsid": ("TSKRIK.SCLBSID", 10, "CLBEIOC", "0d6a244d5cd1cef7de7c70f1f5c1a1c58f2c3130eeedd36ea17dd20dd6d8cf0b"),
        }
        import hashlib
        from ablation.zos_re.netdata import read_netdata
        for filename, (dsn, count, member, digest) in cases.items():
            parsed = read_netdata(IBM_RE / "zOS-IOC" / filename)
            self.assertEqual(len(parsed.datasets[dsn].members), count)
            self.assertEqual(hashlib.sha256(parsed.datasets[dsn].member_bytes(member)).hexdigest(), digest)

    def test_load_image_golden(self):
        from ablation.zos_re.loadmodule import read_load_image
        cases = [
            ("analysis/zos-ioc/3b1b5a8d5eba036b/20261029T031210Z-goff-r2/input/iocchk", 72343, 0xAFC),
            ("analysis/zos-ioc/3b1b5a8d5eba036b/20261029T031210Z-goff-r2/input/iocchk-zip", 72431, 0x69C),
            ("analysis/zos-ioc/8c99b4aeb1c27241/20261029T034441Z-netdata-xmi/recovered/IOCCHK.bin", 76002, None),
            ("analysis/zos-ioc/76d992873e0a878a/20261029T054323Z-ioc-dll/recovered/TSKRIK.SCLBDLL/CLB3CLAS.bin", 3778904, None),
            ("analysis/zos-ioc/76d992873e0a878a/20261029T054323Z-ioc-dll/recovered/TSKRIK.SCLBDLL/CLB3MSGE.bin", 5936, None),
            ("analysis/zos-ioc/76d992873e0a878a/20261029T054323Z-ioc-dll/recovered/TSKRIK.SCLBDLL/CLB3MSGT.bin", 128, None),
            ("analysis/zos-ioc/808914d8f458a7f2/20261029T055542Z-ioc-dll2/recovered/TSKRIK.SCLBDLL2/CLBECOLL.bin", 2107923, 0x2FDC0),
            ("analysis/zos-ioc/808914d8f458a7f2/20261029T055542Z-ioc-dll2/recovered/TSKRIK.SCLBDLL2/CLBEIOC.bin", 3551582, 0x7593C),
            ("analysis/zos-ioc/808914d8f458a7f2/20261029T055542Z-ioc-dll2/recovered/TSKRIK.SCLBDLL2/CLEMSGE.bin", 14976, 0x1D88),
            ("analysis/zos-ioc/808914d8f458a7f2/20261029T055542Z-ioc-dll2/recovered/TSKRIK.SCLBDLL2/CLEMSGT.bin", 320, 0x48),
        ]
        for source, size, entry in cases:
            image = read_load_image(IBM_RE / source)
            self.assertEqual(len(image.text), size, source)
            self.assertEqual(image.entry_rva, entry, source)

    def test_function_golden(self):
        from ablation.zos_re.loadmodule import read_load_image
        cases = [
            ("analysis/zos-ioc/3b1b5a8d5eba036b/20261029T031210Z-goff-r2/input/iocchk", "PPA_LE", 89),
            ("analysis/zos-ioc/3b1b5a8d5eba036b/20261029T031210Z-goff-r2/input/iocchk-zip", "PPA_LE", 85),
            ("analysis/zos-ioc/8c99b4aeb1c27241/20261029T034441Z-netdata-xmi/recovered/IOCCHK.bin", "PPA_LE", 85),
            ("analysis/zos-ioc/76d992873e0a878a/20261029T054323Z-ioc-dll/recovered/TSKRIK.SCLBDLL/CLB3CLAS.bin", "PPA_CPP", 5918),
            ("analysis/zos-ioc/808914d8f458a7f2/20261029T055542Z-ioc-dll2/recovered/TSKRIK.SCLBDLL2/CLBEIOC.bin", "XPLINK_SAVE_STORE", 449),
        ]
        for source, kind, count in cases:
            image = read_load_image(IBM_RE / source)
            recovery = recover_functions(image)
            self.assertEqual(sum(function.kind == kind for function in recovery.functions), count, source)

    def test_sid_golden(self):
        from ablation.zos_re.sid import read_side_deck
        total = 0
        inventories = {}
        for name in ("CLB3D003", "CLB3D004", "CLB3D008", "CLBECOLL", "CLBEIOC"):
            deck = read_side_deck(IBM_RE / f"analysis/zos-ioc/5c0751aef203db91/20261029T055542Z-ioc-sid/recovered/TSKRIK.SCLBSID/{name}.txt")
            total += len(deck.statements)
            inventories[name] = {item.symbol for item in deck.statements}
        self.assertEqual(total, 19546)
        self.assertLessEqual(inventories["CLB3D003"], inventories["CLB3D008"])


if __name__ == "__main__":
    unittest.main()
