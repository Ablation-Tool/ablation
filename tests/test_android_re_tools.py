import struct
from pathlib import Path
from types import SimpleNamespace

import pytest

from ablation.core.apk_parser import _parse_dex
from ablation.analyzers.apk_jni_mapper import JNIBinding, JNIGraph, canonical_jni_names, valid_method_signature
from ablation.analyzers.cross_layer_taint import CrossLayerTaintAnalyzer
from ablation.analyzers.dex_decompiler import DEXDecompiler


def _uleb(value):
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def _sample_dex():
    strings = [
        "LExample;", "Ljava/lang/Object;", "[B", "V", "I",
        "Ljava/io/InputStream;", "VL", "V", "IL", "Example.java",
        "nativeData", "flow", "read",
    ]
    types = [0, 1, 2, 3, 4, 5]
    protos = [(6, 3, 1), (7, 3, 0), (8, 4, 1)]
    methods = [(0, 0, 10), (0, 1, 11), (5, 2, 12)]
    string_count = len(strings)
    header_size = 0x70
    string_off = header_size
    type_off = string_off + string_count * 4
    proto_off = type_off + len(types) * 4
    method_off = proto_off + len(protos) * 12
    class_off = method_off + len(methods) * 8
    data_off = class_off + 32
    data = bytearray()
    string_offsets = []
    for value in strings:
        string_offsets.append(data_off + len(data))
        encoded = value.encode("utf-8")
        data += _uleb(len(value)) + encoded + b"\x00"
    while len(data) % 4:
        data.append(0)
    byte_array_list = data_off + len(data)
    data += struct.pack("<IH", 1, 2) + b"\x00\x00"
    while len(data) % 4:
        data.append(0)
    code_off = data_off + len(data)
    instructions = [
        0x1012, 0x0023, 0x0002,
        0x0122, 0x0005,
        0x206E, 0x0002, 0x0001,
        0x010A,
        0x1071, 0x0000, 0x0000,
        0x000E,
    ]
    data += struct.pack("<HHHHII", 2, 0, 2, 0, 0, len(instructions))
    data += struct.pack("<13H", *instructions)
    class_data_off = data_off + len(data)
    class_data = bytearray(_uleb(0) + _uleb(0) + _uleb(2) + _uleb(0))
    class_data += _uleb(0) + _uleb(0x109) + _uleb(0)
    class_data += _uleb(1) + _uleb(0x9) + _uleb(code_off)
    data += class_data
    file_size = data_off + len(data)
    output = bytearray(file_size)
    output[:8] = b"dex\n035\x00"
    struct.pack_into("<I", output, 32, file_size)
    struct.pack_into("<I", output, 36, 0x70)
    struct.pack_into("<I", output, 40, 0x12345678)
    struct.pack_into("<I", output, 52, data_off)
    struct.pack_into("<I", output, 56, string_count)
    struct.pack_into("<I", output, 60, string_off)
    struct.pack_into("<I", output, 64, len(types))
    struct.pack_into("<I", output, 68, type_off)
    struct.pack_into("<I", output, 72, len(protos))
    struct.pack_into("<I", output, 76, proto_off)
    struct.pack_into("<I", output, 88, len(methods))
    struct.pack_into("<I", output, 92, method_off)
    struct.pack_into("<I", output, 96, 1)
    struct.pack_into("<I", output, 100, class_off)
    struct.pack_into("<I", output, 104, len(data))
    struct.pack_into("<I", output, 108, data_off)
    for index, offset in enumerate(string_offsets):
        struct.pack_into("<I", output, string_off + index * 4, offset)
    for index, string_idx in enumerate(types):
        struct.pack_into("<I", output, type_off + index * 4, string_idx)
    proto_offsets = [byte_array_list, 0, byte_array_list]
    for index, (shorty, returns, _) in enumerate(protos):
        struct.pack_into("<III", output, proto_off + index * 12, shorty, returns, proto_offsets[index])
    for index, (class_idx, proto_idx, name_idx) in enumerate(methods):
        struct.pack_into("<HHI", output, method_off + index * 8, class_idx, proto_idx, name_idx)
    struct.pack_into("<8I", output, class_off, 0, 1, 1, 0, 9, 0, class_data_off, 0)
    output[data_off:] = data
    return bytes(output)


def test_dex_decompiler_models_native_and_code_methods():
    dec = DEXDecompiler(_parse_dex(_sample_dex()))
    methods = {method.name: method for method in dec.iter_methods()}
    assert methods["nativeData"].is_native
    assert methods["flow"].code_off
    assert "nativeData([B)V" in methods["nativeData"].descriptor
    assert "Example.nativeData(v0);" in dec.decompile_method(methods["flow"])
    assert [call.target_idx for call in dec.calls(methods["flow"])] == [2, 0]


def test_cross_layer_dex_taint_reaches_native_declaration():
    dec = DEXDecompiler(_parse_dex(_sample_dex()))
    native = next(dec.iter_native_methods())
    binding = JNIBinding(
        method_idx=native.method_idx,
        java_method=native.descriptor,
        library="libsample.so",
        library_entry="sample.apk!/lib/armeabi-v7a/libsample.so",
        native_address=0x1000,
        native_name="Java_Example_nativeData",
        binding_kind="canonical",
        confidence="exact",
    )
    mapper = SimpleNamespace(
        decompilers=[dec],
        graph=JNIGraph(bindings=[binding]),
        libraries={},
    )
    analyzer = CrossLayerTaintAnalyzer(mapper)
    analyzer._initialize()
    analyzer._propagate_dex()
    entries = analyzer._native_entry_flows()
    flow = analyzer.report.native_entry_flows[0]
    assert flow["source_kind"] == "network"
    assert flow["java_argument"] == 0
    assert entries[("libsample.so", native.method_idx)][0]


def test_jni_name_and_signature_decoding():
    dec = DEXDecompiler(_parse_dex(_sample_dex()))
    native = next(dec.iter_native_methods())
    assert canonical_jni_names(native)[0] == "Java_Example_nativeData"
    assert valid_method_signature("([B)V")
    assert valid_method_signature("(I[[Ljava/lang/String;)J")
    assert not valid_method_signature("([B")
    assert not valid_method_signature("not-a-signature")


def test_byte_backed_elf_disassembler():
    binary = Path("/usr/bin/ls")
    if not binary.exists():
        return
    from ablation.analyzers.elf_disassembler import ELFDisassembler

    elf = ELFDisassembler.from_bytes(binary.read_bytes(), binary.name)
    instructions = elf.disassemble(elf.elf.header["e_entry"], 32)
    assert elf.architecture == "x86_64"
    assert instructions
    assert instructions[0].address == elf.elf.header["e_entry"]


def test_apk_member_and_uleb_limits():
    import io
    import zipfile
    from ablation.core.apk_parser import APKParser, _uleb128

    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("payload.bin", b"12345")
    with APKParser.from_bytes(stream.getvalue()) as apk:
        with pytest.raises(ValueError, match="exceeds the 4-byte limit"):
            apk.read_file("payload.bin", max_size=4)
    with pytest.raises(ValueError, match="exceeds 32 bits"):
        _uleb128(b"\x80\x80\x80\x80\x80\x00", 0)


def test_xapk_member_limit(tmp_path):
    import zipfile
    from ablation.core.android_package import AndroidPackage

    target = tmp_path / "limited.xapk"
    with zipfile.ZipFile(target, "w") as archive:
        archive.writestr("base.apk", b"more-than-four-bytes")
        archive.writestr("manifest.json", '{"split_apks":[{"file":"base.apk","id":"base"}]}')
    with AndroidPackage.from_path(target, max_apk_bytes=4) as package:
        with pytest.raises(ValueError, match="exceeds the 4-byte limit"):
            package.read_apk("base.apk")


def test_jni_mapper_rejects_multidex_and_is_repeatable():
    import io
    import zipfile
    from ablation.core.apk_parser import APKParser
    from ablation.analyzers.apk_jni_mapper import APKJNIMapper

    def apk_bytes(multidex):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("classes.dex", _sample_dex())
            if multidex:
                archive.writestr("classes2.dex", _sample_dex())
        return stream.getvalue()

    class Package:
        def __init__(self, data):
            self.data = data

        def iter_apks(self):
            return iter([APKParser.from_bytes(self.data)])

        def iter_native_libraries(self, abi=""):
            return iter([])

    with pytest.raises(ValueError, match="exactly one DEX"):
        APKJNIMapper(Package(apk_bytes(True))).analyze()
    mapper = APKJNIMapper(Package(apk_bytes(False)))
    first = mapper.analyze()
    second = mapper.analyze()
    assert len(first.unresolved_native_methods) == 1
    assert len(second.unresolved_native_methods) == 1
    assert not second.bindings


def test_android_trace_cli_uses_mapper(monkeypatch, capsys):
    import ablation.cli as cli
    import ablation.core.android_package as package_module
    import ablation.analyzers.apk_jni_mapper as mapper_module
    import ablation.analyzers.cross_layer_taint as taint_module

    class FakePackage:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

    class FakeMapper:
        def __init__(self, package):
            self.package = package

    class FakeAnalyzer:
        def __init__(self, mapper, max_iterations):
            assert isinstance(mapper, FakeMapper)
            assert max_iterations == 6

        def analyze(self):
            return SimpleNamespace(to_dict=lambda: {"summary": {"source_to_sink_candidates": 0}})

    monkeypatch.setattr(cli, "_require_binary", lambda path: Path(path))
    monkeypatch.setattr(package_module.AndroidPackage, "from_path", classmethod(lambda cls, path: FakePackage()))
    monkeypatch.setattr(mapper_module, "APKJNIMapper", FakeMapper)
    monkeypatch.setattr(taint_module, "CrossLayerTaintAnalyzer", FakeAnalyzer)
    cli.cmd_android(SimpleNamespace(android_command="trace", package="sample.xapk", iterations=6, json=None))
    assert '"source_to_sink_candidates": 0' in capsys.readouterr().out


@pytest.mark.integration
def test_bunit_xapk_inventory_and_jni_bindings():
    from ablation.core.android_package import AndroidPackage
    from ablation.analyzers.apk_jni_mapper import APKJNIMapper

    target = Path("/media/cowboy/research/Bloomberg Terminal/binaries-for-re/android-bunit.xapk")
    if not target.exists():
        pytest.skip("B-Unit integration fixture is unavailable")
    with AndroidPackage.from_path(target) as package:
        records = package.inventory()
        assert len(records) == 20
        assert not [record for record in records if record.error]
        xml = package.decode_xml("com.bloomberg.android.bUnit.apk", "res/xml/network_config.xml")
        assert "api.bloomberg.com" in xml
    with APKJNIMapper.from_path(target) as mapper:
        graph = mapper.analyze()
    assert len(graph.bindings) == 25
    assert not graph.unresolved_native_methods
    assert not graph.ambiguous_registrations
