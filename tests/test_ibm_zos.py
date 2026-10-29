import json
import os
import struct
import tempfile
import unittest
from collections import OrderedDict
from pathlib import Path

from ablation.ibm_zos.callgraph import build_call_graph
from ablation.ibm_zos.cli import main
from ablation.ibm_zos.compare import compare_images, compare_side_decks
from ablation.ibm_zos.decompiler import S390Decompiler, _branch_parts
from ablation.ibm_zos.errors import FormatError, SafetyError
from ablation.ibm_zos.functions import FunctionInfo, Recovery, decode_cfg, prolog_candidates, recover_functions
from ablation.ibm_zos.image import LoadImage, Symbol
from ablation.ibm_zos.inventory import _unknown_key, instruction_inventory
from ablation.ibm_zos.loadmodule import _program_object_symbols, parse_load_image
from ablation.ibm_zos.netdata import (
    Member, _extract_members, _parse_directory_record, parse_netdata, parse_text_units,
)
from ablation.ibm_zos.relocation import parse_rld, relocate_image
from ablation.ibm_zos.s390 import S390Decoder
from ablation.ibm_zos.sid import compare_inventories, demangle_ibm_cpp, parse_side_deck


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

    def test_rxy_signed_displacement(self):
        positive = self.decoder.decode(bytes.fromhex("e30003451250"))
        self.assertEqual((positive.format, positive.operands), ("RXY", "%r0, 0x12345"))
        negative = self.decoder.decode(bytes.fromhex("e3000fffff50"))
        self.assertEqual(negative.operands, "%r0, -0x1")

    def test_extended_opcode_families(self):
        samples = {
            "a5f60000": "nilh", "a7010001": "tmll", "bd71e000": "clm",
            "bf0f400c": "icm", "b2520016": "msr", "b25e0018": "srst",
            "b3050000": "lxdbr", "b3490004": "cxbr", "b90400fe": "lgr", "3604": "axr",
            "c20000000001": "msgfi", "e3e040000024": "stg",
            "51514100": "lae", "7120b040": "ms", "d0b85880c1f4": "trtr",
            "a90e0040": "clcle",
        }
        for encoded, mnemonic in samples.items():
            with self.subTest(mnemonic=mnemonic):
                self.assertEqual(self.decoder.decode(bytes.fromhex(encoded)).mnemonic, mnemonic)
        self.assertEqual(self.decoder.decode(bytes.fromhex("bd71e000")).operands, "%r7, 0x1, 0x0(%r14)")
        self.assertEqual(self.decoder.decode(bytes.fromhex("51514100")).operands, "%r5, 0x100(%r1,%r4)")
        self.assertEqual(self.decoder.decode(bytes.fromhex("a90e0040")).operands, "%r0, %r14, 0x40")
        self.assertEqual(self.decoder.decode(bytes.fromhex("3604")).operands, "%f0, %f4")
        self.assertEqual(self.decoder.decode(bytes.fromhex("b3490004")).operands, "%f0, %f4")
        self.assertEqual(self.decoder.decode(bytes.fromhex("b2520016")).operands, "%r1, %r6")
        self.assertEqual(self.decoder.decode(bytes.fromhex("b90400fe")).operands, "%r15, %r14")
        self.assertEqual(self.decoder.decode(bytes.fromhex("c01000000002")).target, 4)

    def test_bfp_and_atomic_formats(self):
        samples = {
            "ba201004": ("cs", "RS", "%r2, %r0, 0x4(%r1)"),
            "d130482041a2": ("mvn", "SS", "0x820(%r4), 0x1a2(%r4), 0x30"),
            "b3020000": ("ltebr", "RRE", "%f0, %f0"),
            "b3040042": ("ldebr", "RRE", "%f4, %f2"),
            "b3120000": ("ltdbr", "RRE", "%f0, %f0"),
            "b3190004": ("cdbr", "RRE", "%f0, %f4"),
            "b31a0002": ("adbr", "RRE", "%f0, %f2"),
            "b3420000": ("ltxbr", "RRE", "%f0, %f0"),
            "b35f5000": ("fidbr", "RRF-e", "%f0, 0x5, %f0"),
            "b3995060": ("cfdbr", "RRF-e", "%r6, 0x5, %f0"),
            "ed00d2800019": ("cdb", "RXE", "%f0, 0x280(%r13)"),
            "ed00d010001a": ("adb", "RXE", "%f0, 0x10(%r13)"),
            "ed00b000001c": ("mdb", "RXE", "%f0, 0x0(%r11)"),
            "ed00b000001d": ("ddb", "RXE", "%f0, 0x0(%r11)"),
        }
        for encoded, expected in samples.items():
            with self.subTest(encoded=encoded):
                instruction = self.decoder.decode(bytes.fromhex(encoded))
                self.assertEqual((instruction.mnemonic, instruction.format, instruction.operands), expected)
        self.assertFalse(self.decoder.decode(bytes.fromhex("ed00d2800119")).known)
        self.assertFalse(self.decoder.decode(bytes.fromhex("b3995160")).known)

    def test_linkage_and_never_branch_semantics(self):
        self.assertEqual(self.decoder.decode(bytes.fromhex("051e")).flow, "return")
        self.assertEqual(self.decoder.decode(bytes.fromhex("0530")).flow, "next")
        self.assertEqual(self.decoder.decode(bytes.fromhex("0707")).flow, "next")

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

    def test_ppa_code_prolog_is_not_duplicated(self):
        image = ppa_image()
        image.text = image.text[:80] + bytes.fromhex("50e0d004") + image.text[84:]
        self.assertEqual(len(recover_functions(image).functions), 1)

    def test_xplink_prolog(self):
        candidates = prolog_candidates(bytes.fromhex("50e0484c07fe"), S390Decoder())
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].kind, "XPLINK_SAVE_STORE")
        extended = prolog_candidates(bytes.fromhex("e3e04000002407fe"), S390Decoder())
        self.assertEqual(len(extended), 1)
        self.assertEqual(extended[0].kind, "XPLINK_SAVE_STORE")


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

    def test_template_backreference_and_operator_demangles(self):
        samples = {
            "__ct__5IDateFiT1": "IDate::IDate(int, int)",
            "__eq__FRC9IThreadIdT1": "operator==(const IThreadId&, const IThreadId&)",
            "__vc__7IStringCFi": "IString::operator[](int) const",
            "throwIt__14IFullExceptionFUlPCcT1": "IFullException::throwIt(unsigned long, const char*, unsigned long)",
            "AddAntivalence__14IARelationImplFRC14IARelationImplT1":
                "IARelationImpl::AddAntivalence(const IARelationImpl&, const IARelationImpl&)",
            "__dt__16IBagOnKeyBagImplXT21IKeyBagAsHshTableImpl_Fv": "IBagOnKeyBagImpl<IKeyBagAsHshTableImpl>::~IBagOnKeyBagImpl()",
        }
        for symbol, expected in samples.items():
            self.assertEqual(demangle_ibm_cpp(symbol), (expected, "demangled"))
        self.assertEqual(demangle_ibm_cpp("__vtt10IDirectory"), (None, "virtual_table"))
        self.assertEqual(demangle_ibm_cpp("__fsm_tab____ls__Fv"), (None, "static_table"))

    def test_parameter_pack_and_volatile_demangles(self):
        self.assertEqual(demangle_ibm_cpp("__ct__12IDecimalUtilFL"), ("IDecimalUtil::IDecimalUtil(long)", "demangled"))
        self.assertEqual(demangle_ibm_cpp("__ct__12IDecimalUtilFr"), ("IDecimalUtil::IDecimalUtil(long double)", "demangled"))
        self.assertEqual(demangle_ibm_cpp("__ct__12IDecimalUtilFBd"), ("IDecimalUtil::IDecimalUtil(volatile double)", "demangled"))
        self.assertEqual(
            demangle_ibm_cpp("change__7IStringFRC7IStringN21UiT4"),
            ("IString::change(const IString&, const IString&, unsigned int, unsigned int)", "demangled"),
        )
        self.assertEqual(
            demangle_ibm_cpp("indexOfWord__7IStringCFUiN21"),
            ("IString::indexOfWord(unsigned int, unsigned int) const", "demangled"),
        )
        self.assertEqual(demangle_ibm_cpp("change__7IStringFRC7IStringN99Ui"), (None, "unparsed"))

    def test_function_pointer_demangles(self):
        samples = {
            "__ct__7IThreadFPFPv_vPvi": "IThread::IThread(void (*)(void*), void*, int)",
            "__ct__7IThreadFPFUl_vUli": "IThread::IThread(void (*)(unsigned long), unsigned long, int)",
            "AllElementsDo__16IACollectionImplFPFPvT1_iPv":
                "IACollectionImpl::AllElementsDo(int (*)(void*, IACollectionImpl&), void*)",
            "AllElementsDo__16IACollectionImplFPFPvT1_bPv":
                "IACollectionImpl::AllElementsDo(bool (*)(void*, IACollectionImpl&), void*)",
            "callback__FPFi_v": "callback(void (*)(int))",
            "setDecisionFn__21IDecisionFnWrapperhexFM8ITesthexFv_b":
                "IDecisionFnWrapperhex::setDecisionFn(bool (ITesthex::*)())",
            "printf__3iocFPCce": "ioc::printf(const char*, ...)",
            "IExcept__assertParameter__FPCcRC18IExceptionLocation":
                "IExcept__assertParameter(const char*, const IExceptionLocation&)",
            "IsEqual__Q2_27IKeySortedBagOnSequenceImplXT19ISequenceAsListImpl_9PredicateFPCvPv":
                "IKeySortedBagOnSequenceImpl<ISequenceAsListImpl>::Predicate::IsEqual(const void*, void*)",
        }
        for symbol, expected in samples.items():
            self.assertEqual(demangle_ibm_cpp(symbol), (expected, "demangled"))
        self.assertEqual(demangle_ibm_cpp("__ct__7IThreadFPFPvPvi"), (None, "unparsed"))
        self.assertEqual(demangle_ibm_cpp("callback__FPFi"), (None, "unparsed"))
        self.assertEqual(
            demangle_ibm_cpp("Any__16IBagOnKeyBagImplXT25IKeyBagOnKeySortedBagImplXT27IKeySortedBagOnSequenceImplXT19ISequenceAsListImpl___CFv"),
            ("IBagOnKeyBagImpl<IKeyBagOnKeySortedBagImpl<IKeySortedBagOnSequenceImpl<ISequenceAsListImpl>>>::Any() const", "demangled"),
        )

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


class RelocationTests(unittest.TestCase):
    def test_rld_continuation_and_signed_relocation(self):
        symbols = [Symbol("SECTION", 0x100, "SD", symbol_id=1)]
        state = {}
        first = parse_rld(bytes.fromhex("000100010d000018"), symbols, 1, 0x100, state)
        second = parse_rld(bytes.fromhex("0400002c"), symbols, 2, 0x200, state)
        self.assertEqual(len(first), 1)
        self.assertTrue(second[0].repeated)
        self.assertEqual(second[0].target_address, 0x100)
        extended = parse_rld(bytes.fromhex("000100014c000030"), symbols)[0]
        self.assertEqual(extended.length, 8)
        relative = parse_rld(bytes.fromhex("000100013c000034"), symbols)[0]
        self.assertEqual(relative.kind, "RI")
        self.assertFalse(relative.resolved)
        text = bytearray(64)
        text[0x18:0x1C] = bytes.fromhex("fffffffe")
        text[0x2C:0x2E] = bytes.fromhex("0001")
        image = LoadImage(
            "rld", "", "PDS_LOAD_MODULE", bytes(text), symbols, [], None, [],
            {"relocations": [item.to_dict() for item in first + second]},
        )
        unchanged, _ = relocate_image(image)
        self.assertEqual(unchanged, image.text)
        relocated, report = relocate_image(image, 0x1000)
        self.assertEqual(relocated[0x18:0x1C], bytes.fromhex("00000ffe"))
        self.assertEqual(relocated[0x2C:0x2E], bytes.fromhex("1001"))
        self.assertEqual(report["applied_count"], 2)
        with self.assertRaises(ValueError):
            relocate_image(image, -1)
        with self.assertRaises(FormatError):
            parse_rld(b"\0" * 4)


class ProgramObjectNameTests(unittest.TestCase):
    def test_name_inventory_does_not_infer_addresses(self):
        data = bytearray(512)
        signature = "IEWBXLF ".encode("cp500")
        data[100:108] = signature
        struct.pack_into(">II", data, 108, 24, 0x01000000)
        data[116:120] = "NAME".encode("cp500")
        struct.pack_into(">II", data, 120, 1, 400)
        data[400] = 1
        struct.pack_into(">H", data, 401, 4)
        data[403:407] = "TEST".encode("cp500")
        symbols, metadata = _program_object_symbols(data, [{"file_offset": 100, "length": 28}])
        self.assertEqual([symbol.name for symbol in symbols], ["TEST"])
        self.assertEqual(symbols[0].address, -1)
        self.assertIsNone(metadata["program_object_names"][0]["address"])
        self.assertEqual(metadata["program_object_name_errors"], [])


class CallGraphTests(unittest.TestCase):
    def test_base_register_rld_call_resolution(self):
        raw = bytes.fromhex("053058f0301005ef051e")
        instructions = list(S390Decoder().linear(raw))
        function = FunctionInfo(0, 0, "caller", "PPA_CPP", "high", instructions=instructions, complete=True)
        image = LoadImage(
            "calls", "", "PDS_LOAD_MODULE", raw + bytes(0x90 - len(raw)), [Symbol("target", 0x80, "LR")], [], None, [],
            {"relocations": [{"rva": 0x12, "resolved": True, "target_address": 0x80}]},
        )
        graph = build_call_graph(image, Recovery([function], []))
        self.assertEqual(len(graph.edges), 1)
        edge = graph.edges[0]
        self.assertEqual((edge.target_rva, edge.target_name, edge.evidence), (0x80, "target", "rld:0x12"))
        self.assertEqual(graph.unresolved, [])

    def test_interprocedural_return_summary(self):
        target_raw = bytes.fromhex("a7f8008007fe")
        target = FunctionInfo(0x80, 0x80, "target", "PPA_CPP", "high", instructions=list(S390Decoder().linear(target_raw)), complete=True)
        caller_raw = bytes.fromhex("c0e50000004005ef051e")
        caller = FunctionInfo(0, 0, "caller", "PPA_CPP", "high", instructions=list(S390Decoder().linear(caller_raw)), complete=True)
        text = caller_raw + bytes(0x90 - len(caller_raw))
        text = text[:0x80] + target_raw + text[0x80 + len(target_raw):]
        image = LoadImage(
            "summary", "", "PDS_LOAD_MODULE", text,
            [Symbol("caller", 0, "LR"), Symbol("target", 0x80, "LR")], [], None, [],
        )
        graph = build_call_graph(image, Recovery([caller, target], []))
        self.assertEqual(len(graph.edges), 2)
        self.assertEqual(graph.edges[0].evidence, "direct:brasl")
        self.assertEqual(graph.edges[1].evidence, "summary:0x80")
        self.assertEqual(graph.edges[1].target_name, "target")

    def test_rre_return_summary(self):
        target_raw = bytes.fromhex("c01000000040b90400f107fe")
        target = FunctionInfo(0x80, 0x80, "target", "PPA_CPP", "high", instructions=list(S390Decoder().linear(target_raw)), complete=True)
        caller_raw = bytes.fromhex("c0e50000004005ef051e")
        caller = FunctionInfo(0, 0, "caller", "PPA_CPP", "high", instructions=list(S390Decoder().linear(caller_raw)), complete=True)
        text = caller_raw + bytes(0x90 - len(caller_raw))
        text = text[:0x80] + target_raw + text[0x80 + len(target_raw):]
        image = LoadImage(
            "rre_summary", "", "PDS_LOAD_MODULE", text,
            [Symbol("caller", 0, "LR"), Symbol("target", 0x80, "LR")], [], None, [],
        )
        graph = build_call_graph(image, Recovery([caller, target], []))
        self.assertEqual(len(graph.edges), 2)
        self.assertEqual(graph.edges[1].evidence, "summary:0x80")

    def test_unresolved_external_and_binder_links(self):
        raw = bytes.fromhex("053058f0301005ef051e")
        function = FunctionInfo(0, 0, "caller", "PPA_CPP", "high", instructions=list(S390Decoder().linear(raw)), complete=True)
        image = LoadImage(
            "external", "", "PDS_LOAD_MODULE", raw + bytes(0x90 - len(raw)),
            [Symbol("target", 0x80, "LR")], [], None, [],
            {"relocations": [{"rva": 0x12, "resolved": False, "target_name": "target", "target_address": None}]},
        )
        deck = parse_side_deck(sid_records(" IMPORT CODE,'IOC','target'"))
        graph = build_call_graph(image, Recovery([function], []), [deck])
        self.assertEqual(graph.edges, [])
        self.assertEqual(graph.unresolved, [])
        self.assertEqual(len(graph.external_calls), 1)
        self.assertEqual(graph.external_calls[0].target_name, "target")
        self.assertEqual(graph.external_calls[0].evidence, "external_rld:0x12")
        self.assertEqual(len(graph.binder_links), 1)
        self.assertEqual(graph.binder_links[0]["dll"], "IOC")


class DecompilerTests(unittest.TestCase):
    @staticmethod
    def function(raw):
        image = LoadImage("decompile", "", "IEWPLMH", raw, [], [], None, [])
        instructions = list(S390Decoder().linear(raw))
        function = FunctionInfo(0, 0, "test", "PPA_CPP", "high", instructions=instructions, complete=True)
        return image, function

    def test_expression_and_stack_recovery(self):
        image, function = self.function(bytes.fromhex("5810d0044120d0081a1218f107fe"))
        result = S390Decompiler(image).decompile(function)
        self.assertIn("stack_4", result.stack_variables)
        self.assertIn("return (stack_4 + (r13 + 0x8));", result.pseudo_c)

    def test_rre_register_expression(self):
        image, function = self.function(bytes.fromhex("b90400fe07fe"))
        result = S390Decompiler(image).decompile(function)
        self.assertIn("return r14;", result.pseudo_c)

    def test_simple_loop_structuring(self):
        image, function = self.function(bytes.fromhex("a71e0000a7840006a71affffa7f4fffa07fe"))
        result = S390Decompiler(image).decompile(function)
        self.assertEqual(result.structured_loop_count, 1)
        self.assertIn("while", result.pseudo_c)
        self.assertIn("r1 = (r1 + -0x1);", result.pseudo_c)

    def test_if_else_and_multiblock_loop_structuring(self):
        image, function = self.function(bytes.fromhex("a71e0000a7840004a7000001a700000207fe"))
        result = S390Decompiler(image).decompile(function)
        self.assertIn("if ((r1 == 0x0))", result.pseudo_c)
        self.assertIn("} else {", result.pseudo_c)
        image, function = self.function(bytes.fromhex("a71e0000a7840006a71affff1211a7e4fff907fe"))
        result = S390Decompiler(image).decompile(function)
        self.assertGreaterEqual(result.structured_loop_count, 1)
        self.assertIn("for (;;)", result.pseudo_c)
        self.assertIn("continue;", result.pseudo_c)

    def test_structured_labels_are_defined(self):
        for encoded in ("a71e0000a7840004a7000001a700000207fe", "a71e0000a7840006a71affffa7f4fffa07fe"):
            image, function = self.function(bytes.fromhex(encoded))
            result = S390Decompiler(image).decompile(function)
            lines = [line.strip() for line in result.pseudo_c.splitlines()]
            labels = {line[:-1] for line in lines if line.startswith("loc_") and line.endswith(":")}
            targets = {line.split("goto ", 1)[1].rstrip(";") for line in lines if "goto loc_" in line}
            self.assertEqual(targets - labels, set())

    def test_function_pointer_and_width_types(self):
        image, function = self.function(bytes.fromhex("58f0d00405ef051e"))
        result = S390Decompiler(image).decompile(function)
        self.assertEqual(result.return_type, "uint32_t")
        self.assertEqual(result.stack_types["stack_4"], [32])
        self.assertEqual(len(result.function_pointers), 1)
        self.assertEqual(result.function_pointers[0].expression, "stack_4")
        self.assertIn("(*stack_4)(r1);", result.pseudo_c)

    def test_loop_with_external_predecessor_keeps_labels(self):
        image, function = self.function(bytes.fromhex("a7f40002a71e0000a7840006a71affffa7f4fffa07fe"))
        result = S390Decompiler(image).decompile(function)
        self.assertEqual(result.structured_loop_count, 0)
        self.assertIn("loc_4:", result.pseudo_c)

    def test_unknown_operation_is_explicit(self):
        image, function = self.function(b"\xff" * 6)
        result = S390Decompiler(image).decompile(function)
        self.assertEqual(result.unknown_statement_count, 1)
        self.assertIn("UNKNOWN_0xffffffffffff", result.pseudo_c)

    def test_external_branch_and_memcmp_condition(self):
        image, function = self.function(bytes.fromhex("a7f40010"))
        result = S390Decompiler(image).decompile(function)
        self.assertIn("external_branch(0x20);", result.pseudo_c)
        self.assertNotIn("goto loc_20", result.pseudo_c)
        self.assertNotIn("None", _branch_parts(("memcmp", "memcmp(a, b)", None), 4))


class ComparisonAndInventoryTests(unittest.TestCase):
    def test_image_and_side_deck_comparison(self):
        image = ppa_image()
        result = compare_images(image, image)
        self.assertTrue(result["text_identical"])
        self.assertEqual(result["exact_function_match_count"], 1)
        first = parse_side_deck(sid_records(" IMPORT CODE 'ASCCOLL'  currentPID__12IApplicationFv"))
        second = parse_side_deck(sid_records(
            " IMPORT CODE 'ASCCOLL'  currentPID__12IApplicationFv",
            " IMPORT CODE,'IOC','__ct__5IDateFiT1'",
        ))
        comparison = compare_side_decks(first, second)
        self.assertEqual(comparison["semantic"]["intersection_count"], 1)
        self.assertEqual(comparison["semantic"]["right_only_count"], 1)

    def test_instruction_inventory(self):
        result = instruction_inventory(ppa_image())
        self.assertEqual(result["function_count"], 1)
        self.assertEqual(result["unknown_instruction_count"], 0)
        self.assertGreaterEqual(result["known_instruction_count"], 1)
        self.assertEqual(_unknown_key(bytes.fromhex("ed00d2800019")), (0xED, 0, 0x19, 6))


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

    def test_existing_regular_file_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "output"
            output.mkdir()
            existing = output / "text.bin"
            existing.write_bytes(b"unchanged")
            with self.assertRaises(FileExistsError):
                ppa_image().write(output)
            self.assertEqual(existing.read_bytes(), b"unchanged")


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

    def test_analysis_cli_commands(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "program.bin"
            source.write_bytes(minimal_pds_image())
            self.assertEqual(main(["relocate", str(source), str(root / "relocated"), "--base", "0x1000"]), 0)
            self.assertEqual(main(["callgraph", str(source), str(root / "graph")]), 0)
            self.assertEqual(main(["decompile", str(source), str(root / "decompiled")]), 0)
            self.assertEqual(main(["compare", str(source), str(source), str(root / "compare.json")]), 0)
            self.assertEqual(main(["opcode-inventory", str(source), str(root / "inventory.json")]), 0)
            sid = root / "deck.bin"
            sid.write_bytes(sid_records(" IMPORT CODE 'ASCCOLL'  currentPID__12IApplicationFv"))
            self.assertEqual(main(["sid-compare", str(sid), str(sid), str(root / "sid-compare.json")]), 0)
            self.assertTrue((root / "relocated" / "relocated-text.bin").is_file())
            self.assertTrue((root / "graph" / "callgraph.json").is_file())
            self.assertEqual(json.loads((root / "decompiled" / "decompilation.json").read_text())["function_count"], 0)
            self.assertTrue(json.loads((root / "compare.json").read_text())["text_identical"])
            self.assertIn("semantic", json.loads((root / "sid-compare.json").read_text()))


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
        from ablation.ibm_zos.netdata import read_netdata
        for filename, (dsn, count, member, digest) in cases.items():
            parsed = read_netdata(IBM_RE / "zOS-IOC" / filename)
            self.assertEqual(len(parsed.datasets[dsn].members), count)
            self.assertEqual(hashlib.sha256(parsed.datasets[dsn].member_bytes(member)).hexdigest(), digest)

    def test_load_image_golden(self):
        from ablation.ibm_zos.loadmodule import read_load_image
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
        named = read_load_image(IBM_RE / cases[2][0])
        self.assertEqual(len(named.metadata["program_object_names"]), 263)
        self.assertEqual(len(named.metadata["program_object_binary_names"]), 1)
        self.assertEqual(named.metadata["program_object_name_errors"], [])
        clas = read_load_image(IBM_RE / cases[3][0])
        self.assertEqual(clas.metadata["relocation_count"], 40069)
        unchanged, report = relocate_image(clas)
        self.assertEqual(unchanged, clas.text)
        self.assertEqual(report["unchanged_count"], 40039)
        self.assertEqual(report["unresolved_count"], 30)

    def test_function_golden(self):
        from ablation.ibm_zos.loadmodule import read_load_image
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
        from ablation.ibm_zos.sid import read_side_deck
        total = 0
        inventories = {}
        statuses = {}
        for name in ("CLB3D003", "CLB3D004", "CLB3D008", "CLBECOLL", "CLBEIOC"):
            deck = read_side_deck(IBM_RE / f"analysis/zos-ioc/5c0751aef203db91/20261029T055542Z-ioc-sid/recovered/TSKRIK.SCLBSID/{name}.txt")
            total += len(deck.statements)
            inventories[name] = {item.symbol for item in deck.statements}
            for item in deck.statements:
                statuses[item.demangle_status] = statuses.get(item.demangle_status, 0) + 1
        self.assertEqual(total, 19546)
        self.assertEqual(statuses["demangled"], 17675)
        self.assertEqual(statuses["unparsed"], 697)
        self.assertEqual(statuses["static_table"], 27)
        self.assertLessEqual(inventories["CLB3D003"], inventories["CLB3D008"])


if __name__ == "__main__":
    unittest.main()
