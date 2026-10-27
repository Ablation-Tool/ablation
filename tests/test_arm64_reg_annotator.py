from ablation.analyzers.arm64_reg_annotator import ARM64RegAnnotator
from ablation.analyzers.binary_context import BinaryContext
from ablation.analyzers.func_profiler import FuncProfiler


def _bl(site: int, target: int) -> bytes:
    word = 0x94000000 | (((target - site) >> 2) & 0x03FFFFFF)
    return word.to_bytes(4, "little")


def _wide_move(base: int, rd: int, immediate: int, shift: int = 0) -> bytes:
    word = base | ((shift // 16) << 21) | (immediate << 5) | rd
    return word.to_bytes(4, "little")


def test_recv_call_tracks_entry_argument_and_immediate():
    data = bytearray(0x6014)
    data[0x5FD8:] = bytes.fromhex(
        "f40301aaf55b02a9213c0091ff4301d121ec7c92000040b9ff6321cb640040f9"
        "a4831ff8040080d2f30308aae1030091e20314aa0300805210f0ff97"
    )
    annotator = ARM64RegAnnotator(bytes(data), 0, {}, {0x2050: "recv"})

    result = annotator.annotate_calls(0x5FD8, 0x6014)

    assert len(result.calls) == 1
    call = result.calls[0]
    assert call.target_name == "recv"
    assert call.args["x2"].kind == "copy"
    assert call.args["x2"].chain.chain.kind == "arg"
    assert call.args["x2"].chain.chain.int_val == 1
    assert call.args["x3"].kind == "const"
    assert call.args["x3"].int_val == 0


def test_adrp_add_resolves_rodata_string_argument():
    data = bytearray(0x60B4)
    data[0x60A0:] = bytes.fromhex("000000b0e80316aa00001d91e10315aa7c020094")
    strings = {0x7740: "Failed to receive data: "}
    annotator = ARM64RegAnnotator(bytes(data), 0, strings, {0x6AA0: "build_error"})

    result = annotator.annotate_calls(0x60A0, 0x60B4)

    assert len(result.calls) == 1
    value = result.calls[0].args["x0"]
    assert value.kind == "string"
    assert value.str_val == "Failed to receive data: "


def test_call_clobbers_caller_saved_registers():
    data = _bl(0x1000, 0x2050) + _bl(0x1004, 0x2050)
    annotator = ARM64RegAnnotator(data, 0x1000, {}, {0x2050: "recv"})

    result = annotator.annotate_calls(0x1000, 0x1008)

    assert len(result.calls) == 2
    second = result.calls[1]
    assert second.args["x0"].kind == "ret"
    assert second.args["x0"].str_val == "recv"
    assert second.args["x1"].kind == "unknown"


def test_movz_movk_and_rev_preserve_constant_provenance():
    data = b"".join(
        (
            _wide_move(0xD2800000, 0, 0x1234),
            _wide_move(0xF2800000, 0, 0x5678, 16),
            bytes.fromhex("0008c05a"),
            _bl(0x100C, 0x2050),
        )
    )
    annotator = ARM64RegAnnotator(data, 0x1000, {}, {0x2050: "recv"})

    result = annotator.annotate_calls(0x1000, 0x1010)

    value = result.calls[0].args["x0"]
    assert value.kind == "const"
    assert value.int_val == 0x34127856


def test_load_store_memory_provenance_reaches_call():
    data = bytes.fromhex("e18b00f9e08b40f9") + _bl(0x1008, 0x2050)
    annotator = ARM64RegAnnotator(data, 0x1000, {}, {0x2050: "recv"})

    result = annotator.annotate_calls(0x1000, 0x100C)

    value = result.calls[0].args["x0"]
    assert value.kind == "arg"
    assert value.int_val == 1


def test_blr_resolves_known_target_and_marks_unknown_indirect():
    data = b"".join(
        (
            _wide_move(0xD2800000, 2, 0x2050),
            bytes.fromhex("40003fd6"),
            bytes.fromhex("60003fd6"),
        )
    )
    annotator = ARM64RegAnnotator(data, 0x1000, {}, {0x2050: "recv"})

    result = annotator.annotate_calls(0x1000, 0x100C)

    assert len(result.calls) == 2
    assert result.calls[0].target_name == "recv"
    assert result.calls[0].target_va == 0x2050
    assert result.calls[1].target_name == "blr x3"
    assert result.calls[1].target_va == 0


def test_func_profiler_uses_arm64_backend(tmp_path):
    data = bytearray(0x60B4)
    data[0x60A0:] = bytes.fromhex("000000b0e80316aa00001d91e10315aa7c020094")
    binary = tmp_path / "arm64-sample"
    binary.write_bytes(data)
    ctx = BinaryContext()
    ctx.path = str(binary)
    ctx.arch = "arm64"
    ctx.base_va = 0
    ctx.strings = {0x7740: "Failed to receive data: "}
    ctx.plt = {0x6AA0: "open"}
    ctx.func_starts = [0x60A0, 0x60B4]

    profile = FuncProfiler.from_context(ctx).profile(0x60A0, end_va=0x60B4)

    assert profile.arg_regs == [f"x{i}" for i in range(8)]
    assert len(profile.calls) == 1
    assert profile.has_sink("open")
    formatted = profile.fmt()
    assert "open(x0='Failed to receive data: '" in formatted
    assert "*** SINK (filesystem) ***" in formatted
