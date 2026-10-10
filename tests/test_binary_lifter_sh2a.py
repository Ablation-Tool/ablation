"""Tests for BinaryLifter SH-2A backend (_lift_sh2a + _SH2aState)."""
import struct
import tempfile
import os
import pytest

from ablation.analyzers.binary_lifter import BinaryLifter, _SH2aState, NativeVal
from ablation.analyzers.ecu_sh2a_decoder import EcuSH2aDecoder, SH2aInsn


# ── Helpers ────────────────────────────────────────────────────────────────────

BASE = 0x1000


def _make_sh2a_insn(
    offset=BASE,
    is_32bit=False,
    mnemonic="nop",
    insn_type="MISC",
    raw=b"\x00\x09",
    target=None,
    rd=None,
    rs=None,
    imm=None,
) -> SH2aInsn:
    return SH2aInsn(
        offset=offset,
        is_32bit=is_32bit,
        mnemonic=mnemonic,
        insn_type=insn_type,
        raw=raw,
        target=target,
        rd=rd,
        rs=rs,
        imm=imm,
    )


def _flat_rom(*hw_words: int) -> bytes:
    """Pack big-endian 16-bit words into a flat ROM starting at offset 0."""
    out = bytearray()
    for w in hw_words:
        out += struct.pack(">H", w)
    return bytes(out)


def _lift_rom(rom: bytes, func_va: int = BASE, arch: str = "sh2a") -> str:
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(rom)
        path = f.name
    try:
        return BinaryLifter.from_path(path, arch=arch).lift_function(func_va)
    finally:
        os.unlink(path)


# ── _SH2aState unit tests ──────────────────────────────────────────────────────


class TestSH2aStateInit:
    def test_param_regs_seed(self):
        state = _SH2aState(set(), lambda va: f"fn_{va:x}", {})
        assert state._regs["r4"].expr == "arg0"
        assert state._regs["r5"].expr == "arg1"
        assert state._regs["r6"].expr == "arg2"
        assert state._regs["r7"].expr == "arg3"

    def test_tainted_param(self):
        state = _SH2aState({"r4"}, lambda va: f"fn_{va:x}", {})
        assert state._regs["r4"].tainted is True
        assert state._regs["r5"].tainted is False

    def test_sp_is_pointer(self):
        state = _SH2aState(set(), lambda va: f"fn_{va:x}", {})
        assert state._regs["r15"].is_ptr is True

    def test_r0_is_return_reg(self):
        state = _SH2aState(set(), lambda va: f"fn_{va:x}", {})
        assert state._RETURN == "r0"


class TestSH2aStateEmitReturn:
    def test_basic_return(self):
        state = _SH2aState(set(), lambda va: f"fn_{va:x}", {})
        insn = _make_sh2a_insn(mnemonic="rts", insn_type="RETURN")
        result = state.emit(insn)
        assert result == "return r0;"

    def test_return_after_call_returns_vn(self):
        state = _SH2aState(set(), lambda va: f"fn_{va:x}", {})
        call_insn = _make_sh2a_insn(mnemonic="bsr", insn_type="CALL", target=0x1100)
        state.emit(call_insn)
        ret_insn = _make_sh2a_insn(mnemonic="rts", insn_type="RETURN")
        result = state.emit(ret_insn)
        assert "return v0" in result


class TestSH2aStateEmitLrSaveRestore:
    def test_lr_save_emits_comment(self):
        state = _SH2aState(set(), lambda va: f"fn_{va:x}", {})
        insn = _make_sh2a_insn(mnemonic="sts.l", insn_type="LR_SAVE")
        result = state.emit(insn)
        assert result == "// sts.l"

    def test_lr_restore_emits_comment(self):
        state = _SH2aState(set(), lambda va: f"fn_{va:x}", {})
        insn = _make_sh2a_insn(mnemonic="lds.l", insn_type="LR_RESTORE")
        result = state.emit(insn)
        assert result == "// lds.l"


class TestSH2aStateEmitCall:
    def test_call_with_target(self):
        name_fn = lambda va: "target_fn" if va == 0x2000 else f"fn_{va:x}"
        state = _SH2aState(set(), name_fn, {})
        insn = _make_sh2a_insn(mnemonic="bsr", insn_type="CALL", target=0x2000)
        result = state.emit(insn)
        assert "target_fn(arg0, arg1, arg2, arg3)" in result
        assert "uint32_t v0" in result

    def test_call_via_plt(self):
        plt = {0x3000: "malloc"}
        state = _SH2aState(set(), lambda va: plt.get(va, f"fn_{va:x}"), plt)
        insn = _make_sh2a_insn(mnemonic="bsr", insn_type="CALL", target=0x3000)
        result = state.emit(insn)
        assert "malloc(" in result

    def test_indirect_call_jsr(self):
        state = _SH2aState(set(), lambda va: f"fn_{va:x}", {})
        insn = _make_sh2a_insn(mnemonic="jsr", insn_type="CALL", rs=1)
        result = state.emit(insn)
        assert "*r1(" in result

    def test_call_no_target_no_rs(self):
        state = _SH2aState(set(), lambda va: f"fn_{va:x}", {})
        insn = _make_sh2a_insn(mnemonic="bsr", insn_type="CALL")
        result = state.emit(insn)
        assert "???(arg0" in result

    def test_call_tainted_arg_annotated(self):
        state = _SH2aState({"r4"}, lambda va: f"fn_{va:x}", {})
        insn = _make_sh2a_insn(mnemonic="bsr", insn_type="CALL", target=0x2000)
        result = state.emit(insn)
        assert "TAINTED" in result

    def test_call_return_value_stored_in_r0(self):
        state = _SH2aState(set(), lambda va: f"fn_{va:x}", {})
        insn = _make_sh2a_insn(mnemonic="bsr", insn_type="CALL", target=0x2000)
        state.emit(insn)
        assert state._regs["r0"].expr == "v0"


class TestSH2aStateEmitBranch:
    def test_unconditional_bra(self):
        state = _SH2aState(set(), lambda va: f"fn_{va:x}", {})
        insn = _make_sh2a_insn(mnemonic="bra", insn_type="BRANCH", target=0x1020)
        result = state.emit(insn)
        assert result == "goto loc_1020;"

    def test_conditional_bt(self):
        state = _SH2aState(set(), lambda va: f"fn_{va:x}", {})
        insn = _make_sh2a_insn(mnemonic="bt", insn_type="BRANCH", target=0x1040)
        result = state.emit(insn)
        assert result == "if (T) goto loc_1040;"

    def test_conditional_bf(self):
        state = _SH2aState(set(), lambda va: f"fn_{va:x}", {})
        insn = _make_sh2a_insn(mnemonic="bf", insn_type="BRANCH", target=0x1040)
        result = state.emit(insn)
        assert result == "if (!T) goto loc_1040;"

    def test_conditional_bt_s(self):
        state = _SH2aState(set(), lambda va: f"fn_{va:x}", {})
        insn = _make_sh2a_insn(mnemonic="bt/s", insn_type="BRANCH", target=0x1060)
        result = state.emit(insn)
        assert "if (T) goto loc_1060;" == result

    def test_indirect_branch_jmp(self):
        state = _SH2aState(set(), lambda va: f"fn_{va:x}", {})
        insn = _make_sh2a_insn(mnemonic="jmp", insn_type="BRANCH", rs=2)
        result = state.emit(insn)
        assert "goto *r2" in result

    def test_branch_no_operands(self):
        state = _SH2aState(set(), lambda va: f"fn_{va:x}", {})
        insn = _make_sh2a_insn(mnemonic="bra", insn_type="BRANCH")
        result = state.emit(insn)
        assert "goto *???" in result


class TestSH2aStateEmitLoad:
    def test_load_l_basic(self):
        state = _SH2aState(set(), lambda va: f"fn_{va:x}", {})
        insn = _make_sh2a_insn(mnemonic="mov.l", insn_type="LOAD", rd=1, rs=4)
        result = state.emit(insn)
        assert "uint32_t" in result
        assert "(uint32_t *)" in result
        assert "arg0" in result  # r4 = arg0

    def test_load_w_width(self):
        state = _SH2aState(set(), lambda va: f"fn_{va:x}", {})
        insn = _make_sh2a_insn(mnemonic="mov.w", insn_type="LOAD", rd=0, rs=5)
        result = state.emit(insn)
        assert "uint16_t" in result
        assert "(uint16_t *)" in result

    def test_load_b_width(self):
        state = _SH2aState(set(), lambda va: f"fn_{va:x}", {})
        insn = _make_sh2a_insn(mnemonic="mov.b", insn_type="LOAD", rd=2, rs=6)
        result = state.emit(insn)
        assert "uint8_t" in result

    def test_load_with_displacement(self):
        state = _SH2aState(set(), lambda va: f"fn_{va:x}", {})
        insn = _make_sh2a_insn(mnemonic="mov.l", insn_type="LOAD", rd=1, rs=4, imm=8)
        result = state.emit(insn)
        assert "+ 0x8" in result

    def test_load_tainted_source_propagates(self):
        state = _SH2aState({"r4"}, lambda va: f"fn_{va:x}", {})
        insn = _make_sh2a_insn(mnemonic="mov.l", insn_type="LOAD", rd=1, rs=4)
        result = state.emit(insn)
        assert "TAINTED" in result

    def test_load_missing_operands_returns_comment(self):
        state = _SH2aState(set(), lambda va: f"fn_{va:x}", {})
        insn = _make_sh2a_insn(mnemonic="mov.l", insn_type="LOAD")
        result = state.emit(insn)
        assert result.startswith("// ")


class TestSH2aStateEmitStore:
    def test_store_l_basic(self):
        state = _SH2aState(set(), lambda va: f"fn_{va:x}", {})
        insn = _make_sh2a_insn(mnemonic="mov.l", insn_type="STORE", rd=4, rs=1)
        result = state.emit(insn)
        assert "(uint32_t *)" in result
        assert "= r1;" in result or "= v" in result

    def test_store_w_width(self):
        state = _SH2aState(set(), lambda va: f"fn_{va:x}", {})
        insn = _make_sh2a_insn(mnemonic="mov.w", insn_type="STORE", rd=4, rs=0)
        result = state.emit(insn)
        assert "(uint16_t *)" in result

    def test_store_with_displacement(self):
        state = _SH2aState(set(), lambda va: f"fn_{va:x}", {})
        insn = _make_sh2a_insn(mnemonic="mov.l", insn_type="STORE", rd=4, rs=1, imm=0x10)
        result = state.emit(insn)
        assert "+ 0x10" in result

    def test_store_tainted_src_annotated(self):
        state = _SH2aState({"r4"}, lambda va: f"fn_{va:x}", {})
        # Call through r4 first to taint v0 in r0
        call = _make_sh2a_insn(mnemonic="bsr", insn_type="CALL", target=0x2000)
        state.emit(call)
        # r0 is now tainted (r4 was tainted arg)
        insn = _make_sh2a_insn(mnemonic="mov.l", insn_type="STORE", rd=5, rs=0)
        result = state.emit(insn)
        assert "TAINTED" in result

    def test_store_missing_operands_returns_comment(self):
        state = _SH2aState(set(), lambda va: f"fn_{va:x}", {})
        insn = _make_sh2a_insn(mnemonic="mov.l", insn_type="STORE")
        result = state.emit(insn)
        assert result.startswith("// ")


class TestSH2aStateEmitMisc:
    def test_misc_imm_load(self):
        state = _SH2aState(set(), lambda va: f"fn_{va:x}", {})
        insn = _make_sh2a_insn(mnemonic="mov", insn_type="MISC", rd=0, imm=42)
        result = state.emit(insn)
        assert "42" in result or "0x2a" in result

    def test_misc_reg_to_reg(self):
        state = _SH2aState(set(), lambda va: f"fn_{va:x}", {})
        insn = _make_sh2a_insn(mnemonic="mov", insn_type="MISC", rd=0, rs=4)
        result = state.emit(insn)
        assert "arg0" in result

    def test_misc_no_operands_emits_comment(self):
        state = _SH2aState(set(), lambda va: f"fn_{va:x}", {})
        insn = _make_sh2a_insn(mnemonic="nop", insn_type="MISC")
        result = state.emit(insn)
        assert result == "// nop"


# ── _lift_sh2a integration tests ───────────────────────────────────────────────


class TestLiftSH2aFlatROM:
    def _build_rom(self) -> bytes:
        rom = bytearray(0x2000)
        off = BASE

        # STS.L PR, @-R15 (0x4F22) — prologue
        rom[off:off+2] = b"\x4F\x22"; off += 2
        # BSR to 0x100A: at offset 0x1002, disp=3 => target=0x1002+4+3*2=0x100C wait let me calculate
        # BSR at 0x1002: target = 0x1002 + 4 + disp*2
        # Want target at BASE+0x10 = 0x1010: disp = (0x1010 - 0x1002 - 4) / 2 = (0xA) / 2 = 5
        # BSR disp=5: opcode = 0xB005
        rom[off:off+2] = b"\xB0\x05"; off += 2  # BSR -> 0x1010
        # NOP (delay slot)
        rom[off:off+2] = b"\x00\x09"; off += 2
        # MOV.L @R4, R1 (6 nm 2 — mov.l @Rm,Rn, Rn=1, Rm=4 => 0x6142)
        rom[off:off+2] = b"\x61\x42"; off += 2
        # RTS (0x000B)
        rom[off:off+2] = b"\x00\x0B"; off += 2
        # NOP (delay slot)
        rom[off:off+2] = b"\x00\x09"; off += 2

        return bytes(rom)

    def test_output_contains_function_header(self):
        rom = self._build_rom()
        result = _lift_rom(rom, BASE)
        assert f"// fn_{BASE:x} @ {BASE:#x}" in result

    def test_output_contains_call(self):
        rom = self._build_rom()
        result = _lift_rom(rom, BASE)
        assert "fn_1010(arg0, arg1, arg2, arg3)" in result

    def test_output_contains_return(self):
        rom = self._build_rom()
        result = _lift_rom(rom, BASE)
        assert "return" in result

    def test_output_truncated_at_return(self):
        rom = self._build_rom()
        result = _lift_rom(rom, BASE)
        # Must not contain hundreds of // misc0 lines from zero-padding
        misc_count = result.count("// misc0")
        # At most 2 or so from the actual instructions before RTS
        assert misc_count <= 5

    def test_arch_alias_sh_2a(self):
        rom = self._build_rom()
        a = _lift_rom(rom, BASE, arch="sh2a")
        b = _lift_rom(rom, BASE, arch="sh-2a")
        assert a == b

    def test_arch_alias_sh2(self):
        rom = self._build_rom()
        a = _lift_rom(rom, BASE, arch="sh2a")
        b = _lift_rom(rom, BASE, arch="sh2")
        assert a == b

    def test_empty_rom_no_crash(self):
        result = _lift_rom(b"\x00" * 16, BASE)
        # Returns gracefully — either no instructions or a comment
        assert isinstance(result, str)

    def test_out_of_range_va_no_crash(self):
        # flat ROM of 128 bytes, but VA=0x10000 >> len
        rom = b"\x4F\x22\x00\x0B\x00\x09" + b"\x00" * 122
        result = _lift_rom(rom, 0x10000)
        assert isinstance(result, str)

    def test_lr_save_in_output(self):
        rom = self._build_rom()
        result = _lift_rom(rom, BASE)
        assert "// sts.l" in result


class TestLiftSH2aTaintPropagation:
    def test_tainted_arg_propagates_to_call(self):
        rom = bytearray(0x2000)
        off = BASE
        rom[off:off+2] = b"\xB0\x01"; off += 2  # BSR disp=1 => target=BASE+4+2=BASE+6
        rom[off:off+2] = b"\x00\x09"; off += 2  # NOP
        rom[off:off+2] = b"\x00\x0B"; off += 2  # RTS
        rom[off:off+2] = b"\x00\x09"; off += 2  # NOP
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(bytes(rom))
            path = f.name
        try:
            lifter = BinaryLifter.from_path(path, arch="sh2a")
            lifter._taint_map[BASE] = {"r4"}
            result = lifter.lift_function(BASE)
            assert "TAINTED" in result
        finally:
            os.unlink(path)


class TestLiftSH2aDecoder:
    def test_real_decode_sts_l_pr(self):
        rom = bytes([0x4F, 0x22, 0x00, 0x0B, 0x00, 0x09])
        dec = EcuSH2aDecoder(rom, base_va=BASE)
        insns = dec.disassemble(0, len(rom))
        assert insns[0].insn_type == "LR_SAVE"
        assert insns[1].insn_type == "RETURN"

    def test_real_decode_bsr_target(self):
        # BSR disp=5 at offset 0 -> target = BASE + 4 + 5*2 = BASE+14
        rom = bytes([0xB0, 0x05, 0x00, 0x09, 0x00, 0x0B, 0x00, 0x09])
        dec = EcuSH2aDecoder(rom, base_va=BASE)
        insns = dec.disassemble(0, len(rom))
        bsr = insns[0]
        assert bsr.insn_type == "CALL"
        assert bsr.target == BASE + 4 + 5 * 2
